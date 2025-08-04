package probe

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/odigos-io/runtime-detector/internal/common"
	"github.com/odigos-io/runtime-detector/internal/proc"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64,arm64 -cc clang -cflags $CFLAGS bpf ./ebpf/detector.bpf.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64,arm64 -cc clang -cflags $CFLAGS bpf_no_btf ./ebpf/detector.bpf.c -- -DNO_BTF -DBPF_NO_PRESERVE_ACCESS_INDEX

type Probe struct {
	logger *slog.Logger
	c      *ebpf.Collection
	links  []link.Link
	reader *perf.Reader

	// the consumer of process events supplied by the probe
	consumer common.ProcessesFilter

	envPrefixFilter   string
	openFilesToTrack  []string
	execFilesToFilter map[string]struct{}
	btfDisabled       bool
}

type processEvent struct {
	Type common.EventType
	Pid  uint32
}

const (
	PerfBufferDefaultSizeInPages = 128

	eventsMapName               = "events"
	execveSyscallProgramName    = "tracepoint__syscalls__sys_enter_execve"
	execveSyscallExitProgramName = "tracepoint__syscalls__sys_exit_execve"
	processForkNoBTFProgramName = "tracepoint__sched__sched_process_fork"
	processForkProgramName      = "tracepoint_btf__sched__sched_process_fork"
	processExitProgramName      = "tracepoint__sched__sched_process_exit"
	pidToContainerPIDMapName    = "user_pid_to_container_pid"
	envPrefixMapName            = "env_prefix"

	fileOpenProgramName          = "tracepoint__syscalls__sys_enter_openat"
	openTrackingFilenameMapName  = "files_open_to_track"
	numOpenPathsToTrackConstName = "num_open_paths_to_track"

	execFilesToFilterMapName      = "exec_files_to_filter"
	numExecFilesToIgnoreConstName = "num_exec_paths_to_filter"

	userNamespaceInodeConstName = "configured_pid_ns_inode"
)

type Config struct {
	// EnvPrefixFilter can be used to filter the events based on the environment variables
	// set for the process. If one of the environment variables key matches the prefix,
	// the event will be reported.
	// If the value is empty, no filtering will be done based on the environment variables.
	EnvPrefixFilter string

	// OpenFilesToTrack is a list of files that should be tracked by the probe.
	// For the tracked process, any open operation on these files will be reported.
	OpenFilesToTrack []string

	// ExecFilesToFilter is a list of full paths to executables that should be ignored by the probe.
	// If a process is executed by one of these files, the event will not be reported.
	// removing duplication is in the responsibility of the caller.
	ExecFilesToFilter map[string]struct{}
}

func New(logger *slog.Logger, f common.ProcessesFilter, config Config) *Probe {
	return &Probe{
		logger:            logger,
		consumer:          f,
		envPrefixFilter:   config.EnvPrefixFilter,
		openFilesToTrack:  config.OpenFilesToTrack,
		execFilesToFilter: config.ExecFilesToFilter,
	}
}

func (p *Probe) LoadAndAttach() error {
	// find the PID namespace inode
	pidNS, err := proc.GetCurrentPIDNameSpaceIndoe()
	if err != nil {
		return fmt.Errorf("can't get current PID namespace inode: %w", err)
	}

	if err := p.load(pidNS); err != nil {
		return fmt.Errorf("can't load probe: %w", err)
	}

	if err := p.attach(); err != nil {
		return fmt.Errorf("can't attach probe: %w", err)
	}

	return nil
}

func (p *Probe) setSpecConsts(spec *ebpf.CollectionSpec, ns uint32) error {
	v, ok := spec.Variables[userNamespaceInodeConstName]
	if !ok {
		return fmt.Errorf("constant %s not found", userNamespaceInodeConstName)
	}
	if !v.Constant() {
		return fmt.Errorf("variable %s is not a constant", userNamespaceInodeConstName)
	}
	if err := v.Set(ns); err != nil {
		return fmt.Errorf("rewriting constant %s: %w", userNamespaceInodeConstName, err)
	}

	v, ok = spec.Variables[numOpenPathsToTrackConstName]
	if !ok {
		return fmt.Errorf("constant %s not found", numOpenPathsToTrackConstName)
	}
	if !v.Constant() {
		return fmt.Errorf("variable %s is not a constant", numOpenPathsToTrackConstName)
	}
	if len(p.openFilesToTrack) > math.MaxUint8 {
		return fmt.Errorf("too many files to track: provided %d, max allowed %d", len(p.openFilesToTrack), math.MaxUint8)
	}
	if err := v.Set(uint8(len(p.openFilesToTrack))); err != nil {
		return fmt.Errorf("rewriting constant %s: %w", numOpenPathsToTrackConstName, err)
	}

	v, ok = spec.Variables[numExecFilesToIgnoreConstName]
	if !ok {
		return fmt.Errorf("constant %s not found", numExecFilesToIgnoreConstName)
	}
	if !v.Constant() {
		return fmt.Errorf("variable %s is not a constant", numExecFilesToIgnoreConstName)
	}
	if len(p.execFilesToFilter) > math.MaxUint8 {
		return fmt.Errorf("too many files to track: provided %d, max allowed %d", len(p.execFilesToFilter), math.MaxUint8)
	}
	if err := v.Set(uint8(len(p.execFilesToFilter))); err != nil {
		return fmt.Errorf("rewriting constant %s: %w", numExecFilesToIgnoreConstName, err)
	}

	return nil
}

func (p *Probe) createCollection(spec *ebpf.CollectionSpec, ns uint32) (*ebpf.Collection, error) {
	err := p.setSpecConsts(spec, ns)
	if err != nil {
		return nil, fmt.Errorf("can't rewrite constants: %w", err)
	}

	if len(p.openFilesToTrack) == 0 {
		// if there are no files to track for open, avoid loading the openat program
		delete(spec.Programs, fileOpenProgramName)
	}

	c, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{})
	if err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			fmt.Printf("Verifier log: %-100v\n", ve)
		}
		return nil, err
	}
	return c, nil
}

func (p *Probe) load(ns uint32) error {
	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		return err
	}

	spec, err := loadBpf()
	if err != nil {
		return err
	}

	c, err := p.createCollection(spec, ns)
	if err != nil {
		if !errors.Is(err, ebpf.ErrNotSupported) {
			return fmt.Errorf("can't create eBPF collection: %w", err)
		}

		// BTF is not supported, fallback to eBPF without BTF
		p.logger.Warn("BTF not supported, loading eBPF without BTF, some of the features will be disabled", "error", err)
		p.btfDisabled = true
		spec, err = loadBpf_no_btf()
		if err != nil {
			return err
		}

		c, err = p.createCollection(spec, ns)
		if err != nil {
			return fmt.Errorf("can't create eBPF collection: %w", err)
		}
	}

	p.c = c

	err = p.setEnvPrefixFilter()
	if err != nil {
		return fmt.Errorf("can't set env prefix filter: %w", err)
	}

	err = p.setFilenamesToTrackWhenOpened()
	if err != nil {
		return fmt.Errorf("can't set filenames to track for open: %w", err)
	}

	err = p.setExecFilenamesToIgnore()
	if err != nil {
		return fmt.Errorf("can't set exec filenames to ignore: %w", err)
	}

	p.logger.Info("eBPF probes loaded", "env prefix filter", p.envPrefixFilter)
	return nil
}

func (p *Probe) attach() error {
	if p.c == nil {
		return errors.New("no eBPF collection loaded")
	}

	reader, err := perf.NewReader(p.c.Maps[eventsMapName], PerfBufferDefaultSizeInPages*os.Getpagesize())
	if err != nil {
		return fmt.Errorf("can't create perf reader: %w", err)
	}
	p.reader = reader

	l, err := link.Tracepoint("syscalls", "sys_enter_execve", p.c.Programs[execveSyscallProgramName], nil)
	if err != nil {
		return fmt.Errorf("can't attach probe sys_enter_execve: %w", err)
	}
	p.links = append(p.links, l)

	l, err = link.Tracepoint("syscalls", "sys_exit_execve", p.c.Programs[execveSyscallExitProgramName], nil)
	if err != nil {
		return fmt.Errorf("can't attach probe sys_exit_execve: %w", err)
	}
	p.links = append(p.links, l)

	l, err = link.Tracepoint("sched", "sched_process_exit", p.c.Programs[processExitProgramName], nil)
	if err != nil {
		return fmt.Errorf("can't attach probe sched_process_exit: %w", err)
	}
	p.links = append(p.links, l)

	// attach to sched_process_fork tracepoint, first try the version with BTF
	if prog, ok := p.c.Programs[processForkProgramName]; ok {
		// attach to raw tracepoint (we have BTF)
		l, err = link.AttachRawTracepoint((link.RawTracepointOptions{
			Program: prog,
			Name:    "sched_process_fork",
		}))
		if err != nil {
			return fmt.Errorf("can't attach raw tracepoint sched_process_fork: %w", err)
		}
		p.links = append(p.links, l)
	} else {
		// fallback to tracepoint without BTF
		prog, ok := p.c.Programs[processForkNoBTFProgramName]
		if !ok {
			return errors.New("sched_process_fork program not found")
		}

		l, err = link.Tracepoint("sched", "sched_process_fork", prog, nil)
		if err != nil {
			return fmt.Errorf("can't attach probe sched_process_fork (no BTF): %w", err)
		}
		p.links = append(p.links, l)
	}

	if len(p.openFilesToTrack) > 0 {
		// attach to openat syscall
		l, err = link.Tracepoint("syscalls", "sys_enter_openat", p.c.Programs[fileOpenProgramName], nil)
		if err != nil {
			return fmt.Errorf("can't attach probe sys_enter_openat: %w", err)
		}
		p.links = append(p.links, l)
	}

	return nil
}

func (p *Probe) Close() error {
	var err error

	for _, l := range p.links {
		if e := l.Close(); e != nil {
			err = errors.Join(err, e)
		}
	}

	if p.c != nil {
		p.c.Close()
	}

	if p.reader != nil {
		err = errors.Join(err, p.reader.Close())
	}

	if p.consumer != nil {
		err = errors.Join(err, p.consumer.Close())
	}

	return err
}

func parseProcessEventInto(record *perf.Record, event *processEvent) error {
	if len(record.RawSample) < 8 {
		return errors.New("record.RawSample is too short")
	}

	event.Type = common.EventType(binary.NativeEndian.Uint32(record.RawSample[0:4]))
	event.Pid = binary.NativeEndian.Uint32(record.RawSample[4:8])

	return nil
}

func (p *Probe) GetContainerPID(pid int) (int, error) {
	m := p.c.Maps[pidToContainerPIDMapName]
	var containerPID uint32
	err := m.Lookup(uint32(pid), &containerPID)
	if err != nil {
		return 0, fmt.Errorf("can't lookup container PID: %w", err)
	}

	return int(containerPID), nil
}

func (p *Probe) TrackPIDs(pids []int) error {
	m := p.c.Maps[pidToContainerPIDMapName]
	keys := make([]uint32, len(pids))
	for i, pid := range pids {
		keys[i] = uint32(pid)
	}

	// The values are zeros, as we don't know the container PID at this point, just letting
	// the eBPF program know that we are interested in these PIDs
	_, err := m.BatchUpdate(keys, make([]uint32, len(pids)), &ebpf.BatchOptions{})
	if err != nil {
		if errors.Is(err, ebpf.ErrNotSupported) {
			// Batch update is supported only on kernels >= 5.6
			// Fallback to single updates
			for i := range keys {
				err = m.Update(keys[i], uint32(0), ebpf.MapUpdateFlags(0))
				if err != nil {
					return fmt.Errorf("can't update single entry in PIDs map: %w", err)
				}
			}
		} else {
			return fmt.Errorf("can't batch update PIDs: %w", err)
		}
	}
	return nil
}

func (p *Probe) ReadEvents(ctx context.Context) {
	var record perf.Record
	var event processEvent

LOOP:
	for {
		select {
		case <-ctx.Done():
			p.logger.Info("context cancelled, stopping probe")
			break LOOP
		default:
			err := p.reader.ReadInto(&record)
			if err != nil {
				if errors.Is(err, perf.ErrClosed) {
					p.logger.Info("perf reader closed, no more notifications will be received")
					break LOOP
				}
				p.logger.Error("failed to read record", "error", err)
			}

			if record.LostSamples != 0 {
				p.logger.Error("lost samples", "count", record.LostSamples)
			}

			if len(record.RawSample) < 8 {
				p.logger.Error("record.RawSample is too short", "length", len(record.RawSample))
				continue
			}

			err = parseProcessEventInto(&record, &event)
			if err != nil {
				p.logger.Error("failed to parse event", "error", err)
				continue
			}

			switch event.Type {
			case common.EventTypeExec:
				p.consumer.Add(int(event.Pid), common.EventTypeExec)
			case common.EventTypeFork:
				if !p.btfDisabled {
					// BTF is enabled, we can trust the event is a relevant process being created
					p.consumer.Add(int(event.Pid), common.EventTypeFork)
				} else {
					// BTF is disabled, we need to check if the PID is a process or thread
					isProcess, err := proc.IsProcess(int(event.Pid))
					if err == nil && isProcess {
						p.consumer.Add(int(event.Pid), common.EventTypeFork)
					}
				}
			case common.EventTypeFileOpen:
				if len(p.openFilesToTrack) > 0 {
					p.consumer.Add(int(event.Pid), common.EventTypeFileOpen)
				}
			case common.EventTypeExit:
				p.consumer.Remove(int(event.Pid))
			default:
				p.logger.Error("unknown event type", "type", event.Type)
			}
		}
	}
}

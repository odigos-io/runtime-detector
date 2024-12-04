package probe

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"unsafe"

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

	envPrefixFilter string
}

type processEvent struct {
	Type common.EventType
	Pid  uint32
}

const (
	PerfBufferDefaultSizeInPages = 128

	eventsMapName            = "events"
	processExecProgramName   = "tracepoint__syscalls__sys_enter_execve"
	processForkProgramName  = "tracepoint__sched__sched_process_fork"
	processExitProgramName   = "tracepoint__sched__sched_process_exit"
	pidToContainerPIDMapName = "user_pid_to_container_pid"
	envPrefixMapName         = "env_prefix"
)

type Config struct {
	// EnvPrefixFilter can be used to filter the events based on the environment variables
	// set for the process. If one of the environment variables key matches the prefix,
	// the event will be reported.
	// If the value is empty, no filtering will be done based on the environment variables.
	EnvPrefixFilter string
}

func New(logger *slog.Logger, f common.ProcessesFilter, config Config) *Probe {
	return &Probe{
		logger:          logger,
		consumer:        f,
		envPrefixFilter: config.EnvPrefixFilter,
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

func createCollection(spec *ebpf.CollectionSpec, ns uint32) (*ebpf.Collection, error) {
	err := spec.RewriteConstants(map[string]interface{}{
		"configured_pid_ns_inode": ns,
	})
	if err != nil {
		return nil, fmt.Errorf("can't rewrite constants: %w", err)
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

	c, err := createCollection(spec, ns)
	if err != nil && errors.Is(err, ebpf.ErrNotSupported) {
		p.logger.Warn("BTF not supported, loading eBPF without BTF, some of the features will be disabled")
		spec, err = loadBpf_no_btf()
		if err != nil {
			return err
		}

		c, err = createCollection(spec, ns)
		if err != nil {
			return fmt.Errorf("can't create eBPF collection: %w", err)
		}
	}

	p.c = c
	// set env prefix filter by writing it to the map
	err = p.setEnvPrefixFilter()
	if err != nil {
		return fmt.Errorf("can't set env prefix filter: %w", err)
	}
	p.logger.Info("eBPF probes loaded", "env prefix filter", p.envPrefixFilter)
	return nil
}

const maxEnvPrefixLength = int(unsafe.Sizeof(bpfEnvPrefixT{}.Prefix))

func (p *Probe) setEnvPrefixFilter() error {
	if p.c == nil {
		return errors.New("no eBPF collection loaded")
	}

	m, ok := p.c.Maps[envPrefixMapName]
	if !ok {
		return errors.New("env_prefix map not found")
	}

	prefix := p.envPrefixFilter

	if len(prefix) > maxEnvPrefixLength {
		return fmt.Errorf("env prefix filter is too long: provide length is %d, max allowed length is %d", len(prefix), maxEnvPrefixLength)
	}

	key := uint32(0)
	value := bpfEnvPrefixT{Len: uint64(len(prefix))}
	copy(value.Prefix[:], prefix)

	if err := m.Put(key, value); err != nil {
		return fmt.Errorf("can't put env prefix in map: %w", err)
	}
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

	l, err := link.Tracepoint("syscalls", "sys_enter_execve", p.c.Programs[processExecProgramName], nil)
	if err != nil {
		return fmt.Errorf("can't attach probe sys_enter_execve: %w", err)
	}
	p.links = append(p.links, l)

	l, err = link.Tracepoint("sched", "sched_process_exit", p.c.Programs[processExitProgramName], nil)
	if err != nil {
		return fmt.Errorf("can't attach probe sched_process_exit: %w", err)
	}
	p.links = append(p.links, l)

	l, err = link.Tracepoint("sched", "sched_process_fork", p.c.Programs[processForkProgramName], nil)
	if err != nil {
		return fmt.Errorf("can't attach probe sys_exit_clone: %w", err)
	}
	p.links = append(p.links, l)

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
	_, err := m.BatchUpdate(keys, make([]uint32, len(pids)), &ebpf.BatchOptions{})
	if err != nil {
		return fmt.Errorf("can't batch update PIDs: %w", err)
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
				p.consumer.Add(int(event.Pid))
			case common.EventTypeExit:
				p.consumer.Remove(int(event.Pid))
			default:
				p.logger.Error("unknown event type", "type", event.Type)
			}
		}
	}
}

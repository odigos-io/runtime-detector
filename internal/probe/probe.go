package probe

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/odigos-io/runtime-detector/internal/common"
	"github.com/odigos-io/runtime-detector/internal/proc"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64,arm64 -cc clang -cflags $CFLAGS bpf ./ebpf/detector.bpf.c

type Probe struct {
	logger *slog.Logger
	c      *ebpf.Collection
	links  []link.Link
	reader *perf.Reader

	// the consumer of process events supplied by the probe
	consumer common.ProcessesFilter
}

type processEvent struct {
	Type common.EventType
	Pid  uint32
}

const (
	PerfBufferDefaultSizeInPages = 128

	eventsMapName            = "events"
	processExecProgramName   = "tracepoint__syscalls__sys_enter_execve"
	processExitProgramName   = "tracepoint__sched__sched_process_exit"
	pidToContainerPIDMapName = "user_pid_to_container_pid"
)

func New(logger *slog.Logger, f common.ProcessesFilter) *Probe {
	return &Probe{
		logger:   logger,
		consumer: f,
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

func (p *Probe) load(ns uint32) error {
	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		return err
	}

	spec, err := loadBpf()
	if err != nil {
		return err
	}

	err = spec.RewriteConstants(map[string]interface{}{
		"configured_pid_ns_inode": ns,
	})
	if err != nil {
		return fmt.Errorf("can't rewrite constants: %w", err)
	}

	c, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{})
	if err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			fmt.Printf("Verifier log: %-100v\n", ve)
		}
	}

	p.c = c
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

	return nil
}

func (p *Probe) close() error {
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

func (p *Probe) ReadEvents(ctx context.Context) error {
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

	return p.close()
}

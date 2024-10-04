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
	filter "github.com/odigos-io/runtime-detector/internal/process_filter"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64,arm64 -cc clang -cflags $CFLAGS bpf ./ebpf/detector.bpf.c

type Probe struct {
	logger     *slog.Logger
	bpfObjects *bpfObjects
	links      []link.Link
	reader     *perf.Reader

	// the consumer of process events supplied by the probe
	consumer filter.ProcessesFilter
}

type eventType uint32

const (
	undefined eventType = iota
	exec
	exit
)

func (et eventType) String() string {
	switch et {
	case exec:
		return "exec"
	case exit:
		return "exit"
	default:
		return "undefined"
	}
}

type processEvent struct {
	Type eventType
	Pid  uint32
}

const (
	PerfBufferDefaultSizeInPages = 128
)

func New(logger *slog.Logger, f filter.ProcessesFilter) *Probe {
	return &Probe{
		logger:   logger,
		consumer: f,
	}
}

func (p *Probe) LoadAndAttach() error {
	if err := p.load(); err != nil {
		return fmt.Errorf("can't load probe: %w", err)
	}

	if err := p.attach(); err != nil {
		return fmt.Errorf("can't attach probe: %w", err)
	}

	return nil
}

func (p *Probe) load() error {
	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		return err
	}

	objs := &bpfObjects{}
	// TODO: collect verifier logs only when configured to.
	if err := loadBpfObjects(objs, &ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogLevel:    ebpf.LogLevelInstruction | ebpf.LogLevelStats,
			LogDisabled: false,
		},
	}); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			fmt.Printf("Verifier log: %-100v\n", ve)
		}
		return err
	}

	p.bpfObjects = objs

	return nil
}

func (p *Probe) attach() error {
	if p.bpfObjects == nil {
		return fmt.Errorf("can't attach probe: bpf objects are not loaded")
	}

	reader, err := perf.NewReader(p.bpfObjects.Events, PerfBufferDefaultSizeInPages*os.Getpagesize())
	if err != nil {
		return fmt.Errorf("can't create perf reader: %w", err)
	}
	p.reader = reader

	l, err := link.Tracepoint("syscalls", "sys_enter_execve", p.bpfObjects.TracepointSyscallsSysEnterExecve, nil)
	if err != nil {
		return fmt.Errorf("can't attach probe sys_enter_execve: %w", err)
	}
	p.links = append(p.links, l)

	l, err = link.Tracepoint("sched", "sched_process_exit", p.bpfObjects.TracepointSchedSchedProcessExit, nil)
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

	if p.bpfObjects != nil {
		err = errors.Join(err, p.bpfObjects.Close())
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

	event.Type = eventType(binary.NativeEndian.Uint32(record.RawSample[0:4]))
	event.Pid = binary.NativeEndian.Uint32(record.RawSample[4:8])

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
			case exec:
				p.consumer.Add(int(event.Pid))
			case exit:
				p.consumer.Remove(int(event.Pid))
			default:
				p.logger.Error("unknown event type", "type", event.Type)
			}
		}
	}

	return p.close()
}

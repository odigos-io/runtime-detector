package probe

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"os"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64,arm64 -cc clang -cflags $CFLAGS bpf ./ebpf/detector.bpf.c

type Probe struct {
	logger     *slog.Logger
	bpfObjects *bpfObjects
	links      []link.Link
	reader     *perf.Reader
}

const (
	PerfBufferDefaultSizeInPages = 128
)

func New(logger *slog.Logger) *Probe {
	return &Probe{
		logger: logger,
	}
}

func (p *Probe) Load() error {
	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		return err
	}

	objs := &bpfObjects{}
	if err := loadBpfObjects(objs, nil); err != nil {
		return err
	}

	p.bpfObjects = objs

	return nil
}

func (p *Probe) Attach() error {
	if p.bpfObjects == nil {
		return fmt.Errorf("can't attach probe: bpf objects are not loaded")
	}

	reader, err := perf.NewReader(p.bpfObjects.Events, PerfBufferDefaultSizeInPages * os.Getpagesize())
	if err != nil {
		return fmt.Errorf("can't create perf reader: %w", err)
	}
	p.reader = reader

	l, err := link.Tracepoint("syscalls", "sys_enter_execve", p.bpfObjects.TracepointSyscallsSysEnterExecve, nil)
	if err != nil {
		return fmt.Errorf("can't attach probe sys_enter_execve: %w", err)
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

	err = errors.Join(err, p.bpfObjects.Close())

	return err
}

func (p *Probe) Run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			p.logger.Info("context cancelled, stopping probe")
			p.reader.Close()
			return
		default:
			record, err := p.reader.Read()
			if err != nil {
				if errors.Is(err, perf.ErrClosed) {
					p.logger.Info("perf reader closed, no more notifications will be received")
					return
				}
				p.logger.Error("failed to read record", "error", err)
			}

			if record.LostSamples != 0 {
				p.logger.Error("lost samples", "count", record.LostSamples)
			}
			
			if len(record.RawSample) < 4 {
				p.logger.Error("record.RawSample is too short", "length", len(record.RawSample))
				continue
			}

			pid := binary.NativeEndian.Uint32(record.RawSample)
			p.logger.Info("execve", "pid", pid)
		}
	}
}


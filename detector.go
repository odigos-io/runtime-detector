package detector

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"sync"
	"time"

	duration "github.com/odigos-io/runtime-detector/internal/duration_filter"
	k8sfilter "github.com/odigos-io/runtime-detector/internal/k8s_filter"
	"github.com/odigos-io/runtime-detector/internal/probe"
	"github.com/odigos-io/runtime-detector/internal/proc"
	filter "github.com/odigos-io/runtime-detector/internal/process_filter"
)

const procFSPathEnv = "PROC_FS_PATH"

type Detector struct {
	p       *probe.Probe
	filters []filter.ProcessesFilter
	l       *slog.Logger

	stopMu  sync.Mutex
	stop    context.CancelFunc
	stopped chan struct{}
}

func NewDetector(l *slog.Logger, d time.Duration) *Detector {
	procFS := os.Getenv(procFSPathEnv)
	if len(procFS) > 0 {
		proc.SetProcFS(procFS)
	}

	k8s := k8sfilter.New(l)
	durationFilter := duration.NewDurationFilter(l, d, k8s)
	p := probe.New(l, durationFilter)

	filters := []filter.ProcessesFilter{durationFilter, k8s}

	return &Detector{
		p:       p,
		filters: filters,
		l:       l,
	}
}

func (d *Detector) Run(ctx context.Context) error {
	ctx, err := d.newStop(ctx)
	if err != nil {
		return err
	}

	err = d.p.Load()
	if err != nil {
		return err
	}

	err = d.p.Attach()
	if err != nil {
		return err
	}

	// initial scan of all processes, and send them to the first filter
	pids, err := proc.AllProcesses()
	if err != nil {
		return err
	}
	for _, pid := range pids {
		d.filters[0].Add(pid)
	}

	// start the probe which is the generator of process events
	err = d.p.Run(ctx)
	close(d.stopped)
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return nil
	}
	return err
}

func (d *Detector) newStop(parent context.Context) (context.Context, error) {
	d.stopMu.Lock()
	defer d.stopMu.Unlock()

	if d.stop != nil {
		return parent, errors.New("Detector already running")
	}

	ctx, stop := context.WithCancel(parent)
	d.stop, d.stopped = stop, make(chan struct{})
	return ctx, nil
}

func (d *Detector) Stop() error {
	d.stopMu.Lock()
	defer d.stopMu.Unlock()

	if d.stop != nil {
		d.stop()
		<-d.stopped

		d.stop, d.stopped = nil, nil
	}
	return nil
}

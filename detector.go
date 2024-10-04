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
	"github.com/odigos-io/runtime-detector/internal/lang"
	"github.com/odigos-io/runtime-detector/internal/probe"
	"github.com/odigos-io/runtime-detector/internal/proc"
	filter "github.com/odigos-io/runtime-detector/internal/process_filter"
)

const defaultMinDuration = (1 * time.Second)

type Detector struct {
	p       *probe.Probe
	filters []filter.ProcessesFilter
	l       *slog.Logger
	k8s     k8sfilter.K8sFilter

	stopMu  sync.Mutex
	stop    context.CancelFunc
	stopped chan struct{}
}

type detectorConfig struct {
	logger *slog.Logger
	minDuration time.Duration
}

// DetectorOption applies a configuration option to [Detector].
type DetectorOption interface {
	apply(context.Context, detectorConfig) (detectorConfig, error)
}

type fnOpt func(context.Context, detectorConfig) (detectorConfig, error)


func (o fnOpt) apply(ctx context.Context, c detectorConfig) (detectorConfig, error) { return o(ctx, c) }

func NewDetector(ctx context.Context, opts ...DetectorOption) (*Detector, error) {
	c, err := newConfig(ctx, opts)
	if err != nil {
		return nil, err
	}

	lang := lang.NewLangFilter(c.logger)
	k8s := k8sfilter.NewK8sFilter(c.logger, lang)
	durationFilter := duration.NewDurationFilter(c.logger, c.minDuration, k8s)
	p := probe.New(c.logger, durationFilter)

	filters := []filter.ProcessesFilter{durationFilter, k8s}

	d := &Detector{
		p:       p,
		filters: filters,
		l:       c.logger,
	}

	k8sFilter, ok := k8s.(k8sfilter.K8sFilter)
	if !ok {
		return nil, errors.New("k8s filter not set")
	}

	d.k8s = k8sFilter
	return d, nil
}

func (d *Detector) TrackPodContainers(podUID string, containerNames ...string) error {
	if d.k8s == nil {
		return errors.New("k8s filter not set")
	}

	d.k8s.TrackPodContainers(podUID, containerNames...)
	return nil
}

func (d *Detector) Run(ctx context.Context) error {
	ctx, err := d.newStop(ctx)
	if err != nil {
		return err
	}

	// load and attach the the required eBPF programs
	err = d.p.LoadAndAttach()
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

	// start reading events from eBPF, this call is blocking and will return when the context is canceled
	err = d.p.ReadEvents(ctx)
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

func newDefaultLogger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		AddSource: true,
		Level:    slog.LevelInfo,
	}))
}

func newConfig(ctx context.Context, opts []DetectorOption) (detectorConfig, error) {
	var (
		c   detectorConfig
		err error
	)

	for _, opt := range opts {
		if opt != nil {
			var e error
			c, e = opt.apply(ctx, c)
			err = errors.Join(err, e)
		}
	}

	if c.logger == nil {
		c.logger = newDefaultLogger()
	}

	if c.minDuration == 0 {
		c.minDuration = defaultMinDuration
	}

	return c, err
}

func WithLogger(l *slog.Logger) DetectorOption {
	return fnOpt(func(_ context.Context, c detectorConfig) (detectorConfig, error) {
		c.logger = l
		return c, nil
	})
}

// WithMinDuration returns a [DetectorOption] that configures a [Detector] to use the specified minimum duration
// for a process to be considered active, the default is 1 second. This is used to filter out shot-lived processes.
func WithMinDuration(d time.Duration) DetectorOption {
	return fnOpt(func(_ context.Context, c detectorConfig) (detectorConfig, error) {
		c.minDuration = d
		return c, nil
	})
}

// WithProcFSPath returns a [DetectorOption] that configures a [Detector] to use the specified path to the 'proc' filesystem,
// the default is /proc. In some cases, the 'proc' filesystem is mounted in a different location.
// For example when using Kind, the 'proc' filesystem is that of the container running kind.
func WithProcFSPath(p string) DetectorOption {
	return fnOpt(func(_ context.Context, c detectorConfig) (detectorConfig, error) {
		err := proc.SetProcFS(p)
		return c, err
	})
}

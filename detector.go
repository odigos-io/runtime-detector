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

const defaultMinDuration = (1 * time.Second)

type Detector struct {
	p       *probe.Probe
	filters []filter.ProcessesFilter
	l       *slog.Logger
	pids    chan int
	output  chan<- *Details
	envKeys map[string]struct{}

	stopMu  sync.Mutex
	stop    context.CancelFunc
	stopped chan struct{}
}

type Details struct {
	// ProcessID is the process ID of the detected process
	ProcessID int
	// Name of the executable: (e.g. /usr/bin/bash, /usr/local/bin/node)
	ExeName string
	// Symbolic link to the executable, this can be used to read the binary's metadata
	ExeLink string
	// Command line used to launch the process, including arguments (e.g. java -jar /app/frontend.jar)
	CmdLine string
	// Environment variables set for the process, and the user requested to get their values.
	// If the detector was configured with a given set of environment keys, only those keys will be returned
	// with their values. If a given key is not found, it will not be included in the map.
	Environments map[string]string
	// the PID of the process in the container namespace, if the process is running in a container.
	ContainerProcessID int
}

type detectorConfig struct {
	logger      *slog.Logger
	minDuration time.Duration
	envs        map[string]struct{}
}

// DetectorOption applies a configuration option to [Detector].
type DetectorOption interface {
	apply(context.Context, detectorConfig) (detectorConfig, error)
}

type fnOpt func(context.Context, detectorConfig) (detectorConfig, error)

func (o fnOpt) apply(ctx context.Context, c detectorConfig) (detectorConfig, error) { return o(ctx, c) }

func NewDetector(ctx context.Context, output chan<- *Details, opts ...DetectorOption) (*Detector, error) {
	if output == nil {
		return nil, errors.New("output channel is nil")
	}

	c, err := newConfig(ctx, opts)
	if err != nil {
		return nil, err
	}

	pids := make(chan int)

	// the following steps are used to create the filters chain
	// 1. ebpf probe generating events and doing basic filtering
	// 2. duration filter to filter out short-lived processes
	// 3. k8s filter to check if the process is running in a k8s pod
	k8s := k8sfilter.NewK8sFilter(c.logger, pids)
	durationFilter := duration.NewDurationFilter(c.logger, c.minDuration, k8s)
	p := probe.New(c.logger, durationFilter)

	filters := []filter.ProcessesFilter{durationFilter, k8s}

	d := &Detector{
		p:       p,
		filters: filters,
		l:       c.logger,
		pids:    pids,
		output:  output,
		envKeys: c.envs,
	}

	return d, nil
}

func (d *Detector) detailsForPID(pid int) *Details {
	cmd, err := proc.GetCmdline(pid)
	if err != nil {
		return nil
	}

	env, err := proc.GetEnvironmentVars(pid, d.envKeys)
	if err != nil {
		return nil
	}

	link, exeName := proc.GetExeNameAndLink(pid)

	cPID, err := d.p.GetContainerPID(pid)
	if err != nil {
		d.l.Error("failed to get container PID", "pid", pid, "error", err)
	}

	return &Details{
		ProcessID:          pid,
		ExeName:            exeName,
		ExeLink:            link,
		CmdLine:            cmd,
		Environments:       env,
		ContainerProcessID: cPID,
	}
}

func (d *Detector) eventLoop() {
	for pid := range d.pids {
		details := d.detailsForPID(pid)
		if details != nil {
			d.output <- details
		}

	}
	d.l.Info("Detector event loop stopped")
	close(d.output)
}

func (d *Detector) Run(ctx context.Context) error {
	ctx, err := d.newStop(ctx)
	if err != nil {
		return err
	}

	// read pid events from the filters chain and pass them to the client
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		d.eventLoop()
	}()

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
	wg.Wait()
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
		Level:     slog.LevelInfo,
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

	if c.envs == nil {
		c.envs = make(map[string]struct{})
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

// WithEnvironments returns a [DetectorOption] that configures a [Detector] to include the specified environment
// variables in the output (in case they are set for the process). If no environment keys are provided, no environment
// variables will be included in the output.
func WithEnvironments(envs ...string) DetectorOption {
	return fnOpt(func(_ context.Context, c detectorConfig) (detectorConfig, error) {
		envsMap := make(map[string]struct{})
		for _, e := range envs {
			envsMap[e] = struct{}{}
		}
		c.envs = envsMap
		return c, nil
	})
}

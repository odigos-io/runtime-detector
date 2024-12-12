package detector

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"sync"
	"time"

	cmd "github.com/odigos-io/runtime-detector/internal/cmd_filter"
	"github.com/odigos-io/runtime-detector/internal/common"
	duration "github.com/odigos-io/runtime-detector/internal/duration_filter"
	"github.com/odigos-io/runtime-detector/internal/probe"
	"github.com/odigos-io/runtime-detector/internal/proc"
)

const defaultMinDuration = (1 * time.Second)

type Detector struct {
	p               *probe.Probe
	filters         []common.ProcessesFilter
	l               *slog.Logger
	procEvents      chan common.PIDEvent
	output          chan<- ProcessEvent
	envKeys         map[string]struct{}
	envPrefixFilter string
}

type ProcessEventType int

const (
	ProcessExecEvent ProcessEventType = iota
	ProcessExitEvent
)

type ProcessEvent struct {
	// EventType is the type of the process event
	EventType ProcessEventType
	// PID is the process ID of the process which is the subject of the event
	// This PID is in the PID namespace the user sees: i.e if the process is running in a container,
	// it will be from the container namespace. if the process is running in the host namespace,
	// this PID is the PID of the process in the host namespace.
	PID int
	// ExecDetails is the details of the process execution event, it is only set for the Exec event
	// for other events, it is nil
	ExecDetails *ProcessExecDetails
}

type ProcessExecDetails struct {
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
	// if BTF is not enabled, this value will be invalid, and should not be used.
	ContainerProcessID int
}

type detectorConfig struct {
	logger          *slog.Logger
	minDuration     time.Duration
	envs            map[string]struct{}
	envPrefixFilter string
	cmdsToFilter    []string
}

// DetectorOption applies a configuration option to [Detector].
type DetectorOption interface {
	apply(detectorConfig) (detectorConfig, error)
}

type fnOpt func(detectorConfig) (detectorConfig, error)

func (o fnOpt) apply(c detectorConfig) (detectorConfig, error) { return o(c) }

// NewDetector creates a new [Detector] instance, which can be used to detect process creation and exit events.
// The detector will use the provided output channel to send the detected events.
// Once [Detector.Run] is called, the detector will start monitoring the system for process events.
//
// The detector can be configured using the provided [DetectorOption]s.
//
// The output channel will be closed when the detector stops.
func NewDetector(output chan<- ProcessEvent, opts ...DetectorOption) (*Detector, error) {
	if output == nil {
		return nil, errors.New("output channel is nil")
	}

	c, err := newConfig(opts)
	if err != nil {
		return nil, err
	}

	procEvents := make(chan common.PIDEvent)

	// the following steps are used to create the filters chain
	// 1. ebpf probe generating events and doing basic filtering
	// 2. duration filter to filter out short-lived processes
	// 3. cmdFilter filter to check if the process is running in a cmdFilter pod
	cmdFilter := cmd.NewCmdFilter(c.logger, c.cmdsToFilter, procEvents)
	durationFilter := duration.NewDurationFilter(c.logger, c.minDuration, cmdFilter)
	p := probe.New(c.logger, durationFilter, probe.Config{EnvPrefixFilter: c.envPrefixFilter})

	filters := []common.ProcessesFilter{durationFilter, cmdFilter}

	d := &Detector{
		p:               p,
		filters:         filters,
		l:               c.logger,
		procEvents:      procEvents,
		output:          output,
		envKeys:         c.envs,
		envPrefixFilter: c.envPrefixFilter,
	}

	return d, nil
}

func (d *Detector) processExecDetails(pid int) (*ProcessExecDetails, error) {
	cmd, err := proc.GetCmdline(pid)
	if err != nil {
		return nil, err
	}

	env, err := proc.GetEnvironmentVars(pid, d.envKeys)
	if err != nil {
		return nil, err
	}

	link, exeName := proc.GetExeNameAndLink(pid)

	cPID, err := d.p.GetContainerPID(pid)
	if err != nil {
		// log the error and continue currently not returning an error
		// since this might cause if we have an event which is a result of the initial scan
		// (i.e we missed the exec event)
		d.l.Error("failed to get container PID", "pid", pid, "error", err)
	}

	return &ProcessExecDetails{
		ExeName:            exeName,
		ExeLink:            link,
		CmdLine:            cmd,
		Environments:       env,
		ContainerProcessID: cPID,
	}, nil
}

func (d *Detector) procEventLoop() {
	for e := range d.procEvents {
		pe := ProcessEvent{PID: e.Pid}
		switch e.Type {
		case common.EventTypeExec:
			execDetails, err := d.processExecDetails(e.Pid)
			if err != nil {
				d.l.Error("failed to get process details", "pid", e.Pid, "error", err)
				continue
			}
			pe.ExecDetails = execDetails
			pe.EventType = ProcessExecEvent
			d.output <- pe
		case common.EventTypeExit:
			pe.EventType = ProcessExitEvent
			d.output <- pe
		case common.EventTypeFork:
			// these events should be handled internally by the probe, and should not be seen by the detector
			d.l.Error("unexpected fork event", "pid", e.Pid)
		default:
			d.l.Error("unknown event type", "type", e.Type)
		}
	}

	d.l.Info("Detector event loop stopped")
}

// Run starts the detector, and blocks until the one of the following happens:
// 1. The context is canceled
// 2. An un-recoverable error occurs
//
// The output channel will be closed when the detector stops.
func (d *Detector) Run(ctx context.Context) error {
	defer close(d.output)

	// load and attach the the required eBPF programs
	err := d.p.LoadAndAttach()
	if err != nil {
		return err
	}

	// initial scan of all relevant processes, and send them to the first filter
	pids, err := proc.AllRelevantProcesses(d.envPrefixFilter)
	if err != nil {
		return err
	}

	// let the probe know about the PIDs we are interested in, so we can get exit events for them
	err = d.p.TrackPIDs(pids)
	if err != nil {
		return err
	}
	d.l.Info("initial scan done", "number of relevant processes found", len(pids))

	// read pid events from the filters chain and pass them to the client
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		d.procEventLoop()
	}()

	// feed the PIDs from the initial scan to the first filter
	for _, pid := range pids {
		d.filters[0].Add(pid)
	}

	// start reading events from eBPF, this call is blocking and will return when the context is canceled
	wg.Add(1)
	go func() {
		defer wg.Done()
		d.p.ReadEvents(ctx)
	}()

	// block until the context is canceled
	<-ctx.Done()

	// close the eBPF probe, this should clean all the resources associated with the probes,
	// as well as trigger the closing of the filters chain
	err = d.p.Close()

	wg.Wait()
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return nil
	}
	return err
}

func newDefaultLogger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		AddSource: true,
		Level:     slog.LevelInfo,
	}))
}

func newConfig(opts []DetectorOption) (detectorConfig, error) {
	var (
		c   detectorConfig
		err error
	)

	for _, opt := range opts {
		if opt != nil {
			var e error
			c, e = opt.apply(c)
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
	return fnOpt(func(c detectorConfig) (detectorConfig, error) {
		c.logger = l
		return c, nil
	})
}

// WithMinDuration returns a [DetectorOption] that configures a [Detector] to use the specified minimum duration
// for a process to be considered active, the default is 1 second. This is used to filter out short-lived processes.
func WithMinDuration(d time.Duration) DetectorOption {
	return fnOpt(func(c detectorConfig) (detectorConfig, error) {
		c.minDuration = d
		return c, nil
	})
}

// WithEnvironments returns a [DetectorOption] that configures a [Detector] to include the specified environment
// variables in the output (in case they are set for the process). If no environment keys are provided, no environment
// variables will be included in the output.
func WithEnvironments(envs ...string) DetectorOption {
	return fnOpt(func(c detectorConfig) (detectorConfig, error) {
		envsMap := make(map[string]struct{})
		for _, e := range envs {
			envsMap[e] = struct{}{}
		}
		c.envs = envsMap
		return c, nil
	})
}

// WithEnvPrefixFilter returns a [DetectorOption] that configures a [Detector] to filter process events
// based on the environment variables set for the process. If one of the environment variables key matches the prefix,
// the event will be reported. If the value is empty, no filtering will be done based on the environment variables.
// If the value is not empty, the detector will only report events for processes that have an environment variable
// with the specified prefix.
func WithEnvPrefixFilter(prefix string) DetectorOption {
	return fnOpt(func(c detectorConfig) (detectorConfig, error) {
		c.envPrefixFilter = prefix
		return c, nil
	})
}

// WithCmdsToFilter returns a [DetectorOption] that configures a [Detector] to filter out processes with the specified
// commands. If a process has a command that matches one of the provided commands, it will be filtered out and not reported.
func WithCmdsToFilter(cmds ...string) DetectorOption {
	return fnOpt(func(c detectorConfig) (detectorConfig, error) {
		c.cmdsToFilter = cmds
		return c, nil
	})
}

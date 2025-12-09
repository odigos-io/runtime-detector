package detector

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/odigos-io/runtime-detector/internal/common"
	duration "github.com/odigos-io/runtime-detector/internal/duration_filter"
	"github.com/odigos-io/runtime-detector/internal/probe"
	"github.com/odigos-io/runtime-detector/internal/proc"
)

const defaultMinDuration = (1 * time.Second)

type Detector struct {
	p                *probe.Probe
	filters          []common.ProcessesFilter
	l                *slog.Logger
	procEvents       chan common.PIDEvent
	output           chan<- ProcessEvent
	envKeys          map[string]struct{}
	envPrefixFilter  string
	exePathsToFilter map[string]struct{}

	// before the detector passes the process to the output channel,
	// it will filter out processes based on their details, using the functions in this slice.
	// if one of the functions returns true, the process will be filtered out.
	detailsFilters []detailsFilterFn
	// filteredPIDs is a map of PIDs that were filtered out based on their details,
	// used to filter out their exit events.
	filteredPIDs map[int]struct{}
}

type ProcessEventType int

const (
	ProcessExecEvent     ProcessEventType = ProcessEventType(common.EventTypeExec)
	ProcessExitEvent     ProcessEventType = ProcessEventType(common.EventTypeExit)
	ProcessForkEvent     ProcessEventType = ProcessEventType(common.EventTypeFork)
	ProcessFileOpenEvent ProcessEventType = ProcessEventType(common.EventTypeFileOpen)
)

func (pe ProcessEventType) String() string {
	return common.EventType(pe).String()
}

type detailsFilterFn struct {
	fn  func(int, *ProcessExecDetails) bool
	msg string
}

type ProcessEvent struct {
	// EventType is the type of the process event
	EventType ProcessEventType
	// PID is the process ID of the process which is the subject of the event
	// This PID is in the PID namespace the user sees: i.e if the process is running in a container,
	// it will be from the container namespace. if the process is running in the host namespace,
	// this PID is the PID of the process in the host namespace.
	PID int
	// ExecDetails is the details of the process execution event, it is set for the events:
	// - ProcessExecEvent
	// - ProcessForkEvent
	// - ProcessFileOpenEvent
	// for other events, it is nil
	ExecDetails *ProcessExecDetails
}

func (pe ProcessEvent) String() string {
	if pe.ExecDetails != nil {
		return fmt.Sprintf("%s: PID: %d, ExePath: %s, CmdLine: %s, ContainerPID: %d reported envs: %v",
			pe.EventType,
			pe.PID,
			pe.ExecDetails.ExePath,
			pe.ExecDetails.CmdLine,
			pe.ExecDetails.ContainerProcessID,
			pe.ExecDetails.Environments,
		)
	}
	return fmt.Sprintf("%s: PID: %d", pe.EventType, pe.PID)
}

type ProcessExecDetails struct {
	// Path of the executable: (e.g. /usr/bin/bash, /usr/local/bin/node)
	ExePath string
	// Symbolic link to the executable, this can be used to read the binary's metadata
	ExeLink string
	// Command line used to launch the process, including arguments (e.g. java -jar /app/frontend.jar)
	CmdLine string
	// Environment variables set for the process, and the user requested to get their values.
	// If the detector was configured with a given set of environment keys, only those keys will be returned
	// with their values. If a given key is not found, it will not be included in the map.
	Environments map[string]string
	// the PID of the process in the container namespace, if the process is running in a container.
	// if BTF is not enabled, this value might be invalid, and should not be used.
	// container PID is defined as the inner most PID of the process - i.e the PID in the inner most PID namespace it is running in.
	ContainerProcessID int
}

type detectorConfig struct {
	logger           *slog.Logger
	minDuration      time.Duration
	durationPassed   bool
	envs             map[string]struct{}
	envPrefixFilter  string
	exePathsToFilter map[string]struct{}
	filesOpenTrigger []string
	procFSPath       string
}

var (
	// defaultExcludedExePaths are the executables that we do not want to track
	defaultExcludedExePaths = []string{
		// it is common for the kubelet/container-runtime to run a process with the command "/pause",
		"/pause",
	}
)

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
// The detector can be configured using the provided [DetectorOption] values.
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

	if c.procFSPath != "" {
		proc.SetProcFSPath(c.procFSPath)
	}

	procEvents := make(chan common.PIDEvent, 100)

	// the following steps are used to create the filters chain
	// 1. ebpf probe generating events and doing basic filtering
	// 2. duration filter to filter out short-lived processes
	durationFilter := duration.NewDurationFilter(c.logger, c.minDuration, procEvents)
	p := probe.New(c.logger, durationFilter, probe.Config{
		EnvPrefixFilter:   c.envPrefixFilter,
		OpenFilesToTrack:  c.filesOpenTrigger,
		ExecFilesToFilter: c.exePathsToFilter,
	})

	filters := []common.ProcessesFilter{durationFilter}

	envFilterFn := func(pid int, details *ProcessExecDetails) bool {
		if c.envPrefixFilter == "" {
			return false
		}
		for k := range details.Environments {
			if strings.HasPrefix(k, c.envPrefixFilter) {
				return false
			}
		}
		return true
	}

	exePathFilterFn := func(pid int, details *ProcessExecDetails) bool {
		for p := range c.exePathsToFilter {
			if details.ExePath == p {
				return true
			}
		}
		return false
	}

	d := &Detector{
		p:                p,
		filters:          filters,
		l:                c.logger,
		procEvents:       procEvents,
		output:           output,
		envKeys:          c.envs,
		envPrefixFilter:  c.envPrefixFilter,
		exePathsToFilter: c.exePathsToFilter,
		detailsFilters: []detailsFilterFn{
			{fn: envFilterFn, msg: "no env prefix was found in process envs"},
			{fn: exePathFilterFn, msg: "process exe path is in the excluded list"},
		},
		filteredPIDs: make(map[int]struct{}),
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

	link, exePath := proc.GetExePathAndLink(pid)

	cPID, err := d.p.GetContainerPID(pid)
	if err != nil || cPID == 0 {
		// this might happen if we have an event which is a result of the initial scan
		// (i.e we missed the exec event), try to get the container PID from the /proc file system
		cPID, err = proc.InnerMostPID(pid)
		if err != nil {
			d.l.Error("failed to get container PID", "pid", pid, "error", err)
		}
	}

	return &ProcessExecDetails{
		ExePath:            exePath,
		ExeLink:            link,
		CmdLine:            cmd,
		Environments:       env,
		ContainerProcessID: cPID,
	}, nil
}

func (d *Detector) procEventLoop() {
	var (
		filtered  bool
		filterMsg string
	)

	for e := range d.procEvents {
		pe := ProcessEvent{PID: e.Pid}
		switch e.Type {
		case common.EventTypeExec, common.EventTypeFileOpen, common.EventTypeFork:
			execDetails, err := d.processExecDetails(e.Pid)
			if err != nil {
				d.l.Error("failed to get process details", "pid", e.Pid, "error", err)
				continue
			}

			if e.Type == common.EventTypeExec {
				filtered = false
				filterMsg = ""
				for _, f := range d.detailsFilters {
					if f.fn(e.Pid, execDetails) {
						d.filteredPIDs[e.Pid] = struct{}{}
						filtered = true
						filterMsg = f.msg
					}
				}
				if filtered {
					d.l.Warn("skipping process event due to details filter",
						"pid", e.Pid,
						"reason", filterMsg,
						"cmdLine", execDetails.CmdLine,
						"exePath", execDetails.ExePath,
					)
					continue
				}
			}

			pe.ExecDetails = execDetails
			pe.EventType = ProcessEventType(e.Type)
			d.output <- pe
		case common.EventTypeExit:
			if _, ok := d.filteredPIDs[e.Pid]; ok {
				d.l.Debug("skipping exit event for process filtered by env prefix", "pid", e.Pid)
				delete(d.filteredPIDs, e.Pid)
				continue
			}
			pe.EventType = ProcessExitEvent
			d.output <- pe
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
	pids, err := proc.AllRelevantProcesses(d.envPrefixFilter, d.exePathsToFilter)
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
		d.filters[0].Add(pid, common.EventTypeExec)
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

// TrackProcesses notifies the detector about a list of relevant processes for which the caller wants to
// get events for. Future events can be any of the events reported by the detector expect exec event.
//
// Will return an error if called before the detector is initialized and running.
func (d *Detector) TrackProcesses(pids []int) error {
	if d.p == nil {
		return errors.New("eBPF probes are not initialized yet, can't track processes before the detector is running")
	}

	err := d.p.TrackPIDs(pids)
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

	if !c.durationPassed {
		c.minDuration = defaultMinDuration
	}

	if c.envs == nil {
		c.envs = make(map[string]struct{})
	}

	if c.exePathsToFilter == nil {
		c.exePathsToFilter = make(map[string]struct{}, len(defaultExcludedExePaths))
	}

	// add the default excluded exe paths, and remove duplicates
	for _, path := range defaultExcludedExePaths {
		c.exePathsToFilter[path] = struct{}{}
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
// Passing a zero duration will result in a passthrough filter, which will not filter any processes.
func WithMinDuration(d time.Duration) DetectorOption {
	return fnOpt(func(c detectorConfig) (detectorConfig, error) {
		c.minDuration = d
		c.durationPassed = true
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

// WithExePathsToFilter returns a [DetectorOption] that configures a [Detector] to filter out processes which run
// the specified executable. If a process runs an executable that matches one of the provided paths, it will be filtered out and not reported.
func WithExePathsToFilter(paths ...string) DetectorOption {
	return fnOpt(func(c detectorConfig) (detectorConfig, error) {
		pathsMap := make(map[string]struct{}, len(paths))
		for _, p := range paths {
			pathsMap[p] = struct{}{}
		}

		c.exePathsToFilter = pathsMap
		return c, nil
	})
}

// WithFilesOpenTrigger returns a [DetectorOption] that configures a [Detector] to report events when a process opens one of the specified files.
// If a process opens a file that matches one of the provided paths, an event will be reported.
// This would only trigger an event if the process is tracked according to some other criteria (for example has a relevant environment variable).
func WithFilesOpenTrigger(files ...string) DetectorOption {
	return fnOpt(func(c detectorConfig) (detectorConfig, error) {
		c.filesOpenTrigger = files
		return c, nil
	})
}

// WithProcFSPath returns a [DetectorOption] that configures a [Detector] to use the specified path for the /proc filesystem.
// This is useful for containers that want to avoid sharing the host PID namespace but still inspect the host processes.
// The default value is "/proc", which is the standard location for the proc filesystem on Linux systems.
func WithProcFSPath(path string) DetectorOption {
	return fnOpt(func(c detectorConfig) (detectorConfig, error) {
		if path == "" {
			return c, fmt.Errorf("procFSPath cannot be empty")
		}
		c.procFSPath = path
		return c, nil
	})
}

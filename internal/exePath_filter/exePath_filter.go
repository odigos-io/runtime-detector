package exePathFilter

import (
	"log/slog"

	"github.com/odigos-io/runtime-detector/internal/common"
	"github.com/odigos-io/runtime-detector/internal/proc"
)

var (
	// defaultExcludedExePaths are the executables that we do not want to track
	defaultExcludedExePaths = map[string]struct{}{
		// it is common for the kubelet/container-runtime to run a process with the command "/pause",
		"/pause": {},
	}

	// for testing purposes, we can override these functions
	GetExeNameFunc = proc.GetExeNameAndLink
)

// exePathFilter is a filter that filters processes based on the command they are running.
// TODO: this can be implemented inside eBPF, currently we have it in user space for simplicity, but we can improve this in the future.
type exePathFilter struct {
	l *slog.Logger

	// the consumer of process events supplied by the k8s filter
	output chan<- common.PIDEvent

	// exePaths is a set of commands that we want filter
	exePaths map[string]struct{}

	// filteredPIDs is a set of pids that we have filtered based on the exe name,
	// we need to keep track of these pids, so we know not to report the exit event when the process exits.
	filteredPIDs map[int]struct{}
}

func NewExePathFilter(l *slog.Logger, exePaths []string, output chan<- common.PIDEvent) common.ProcessesFilter {
	exePathsToFilter := make(map[string]struct{})

	for exe := range defaultExcludedExePaths {
		exePathsToFilter[exe] = struct{}{}
	}

	for _, exe := range exePaths {
		exePathsToFilter[exe] = struct{}{}
	}

	return &exePathFilter{
		l:            l,
		output:       output,
		exePaths:     exePathsToFilter,
		filteredPIDs: make(map[int]struct{}),
	}
}

func (k *exePathFilter) Add(pid int) {
	_, exeName := GetExeNameFunc(pid)
	if exeName == "" {
		// this error can happen for 2 reasons:
		// 1. the process has already exited, this is a transient error.
		// 2. the pid reported is invalid, this can happen if BTF is not enabled, and the detector is running inside a container
		//    (KinD fir example), in this case, all the process events will get this error, since the pid reported by eBPF,
		//    is not valid in for user space running in a container.
		k.l.Warn("failed to get exe name, not reporting event", "pid", pid)
		return
	}

	if _, ok := k.exePaths[exeName]; ok {
		k.l.Debug("exe name filter skipping pid",
			"pid", pid,
			"exe name", exeName,
		)
		k.filteredPIDs[pid] = struct{}{}
		return
	}

	k.output <- common.PIDEvent{Pid: pid, Type: common.EventTypeExec}

	k.l.Debug("exe path filter received pid",
		"pid", pid,
		"exe name", exeName,
	)
}

func (k *exePathFilter) Close() error {
	k.l.Info("exe path filter closed")
	close(k.output)
	return nil
}

func (k *exePathFilter) Remove(pid int) {
	_, filtered := k.filteredPIDs[pid]
	if filtered {
		delete(k.filteredPIDs, pid)
		return
	}

	// if the pid was not filtered, we need to report the exit event
	k.output <- common.PIDEvent{Pid: pid, Type: common.EventTypeExit}
}

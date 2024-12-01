package cmdfilter

import (
	"log/slog"

	"github.com/odigos-io/runtime-detector/internal/common"
	"github.com/odigos-io/runtime-detector/internal/proc"
)

var (
	// defaultExcludedCmds are the commands that we do not want to track
	defaultExcludedCmds = map[string]struct{}{
		// it is common for the kubelet/container-runtime to run a process with the command "/pause",
		"/pause": {},
	}

	// for testing purposes, we can override these functions
	GetCmdlineFunc = proc.GetCmdline
)

// cmdProcessesFilter is a filter that filters processes based on the command they are running.
// TODO: this can be implemented inside eBPF, currently we have it in user space for simplicity, but we can improve this in the future.
type cmdProcessesFilter struct {
	l *slog.Logger

	// the consumer of process events supplied by the k8s filter
	output chan<- common.PIDEvent

	// cmds is a set of commands that we want filter
	cmds map[string]struct{}
}

func NewCmdFilter(l *slog.Logger, cmds []string, output chan<- common.PIDEvent) common.ProcessesFilter {
	cmdsToFilter := make(map[string]struct{})

	for cmd := range defaultExcludedCmds {
		cmdsToFilter[cmd] = struct{}{}
	}

	for _, cmd := range cmds {
		cmdsToFilter[cmd] = struct{}{}
	}

	return &cmdProcessesFilter{
		l:      l,
		output: output,
		cmds:   cmdsToFilter,
	}
}

func (k *cmdProcessesFilter) Add(pid int) {
	cmd, err := GetCmdlineFunc(pid)
	if err != nil {
		// this error can happen for 2 reasons:
		// 1. the process has already exited, this is a transient error.
		// 2. the pid reported is invalid, this can happen if BTF is not enabled, and the detector is running inside a container
		//    (KinD fir example), in this case, all the process events will get this error, since the pid reported by eBPF,
		//    is not valid in for user space running in a container.
		k.l.Warn("failed to get cmdline, not reporting event", "pid", pid, "error", err)
		return
	}

	if _, ok := k.cmds[cmd]; ok {
		k.l.Debug("cmd filter skipping pid",
			"pid", pid,
			"cmd", cmd,
		)
		return
	}

	k.output <- common.PIDEvent{Pid: pid, Type: common.EventTypeExec}

	k.l.Debug("cmd filter received pid",
		"pid", pid,
		"cmd", cmd,
	)
}

func (k *cmdProcessesFilter) Close() error {
	k.l.Info("cmd filter closed")
	close(k.output)
	return nil
}

func (k *cmdProcessesFilter) Remove(pid int) {
	k.output <- common.PIDEvent{Pid: pid, Type: common.EventTypeExit}
}

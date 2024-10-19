package k8sfilter

import (
	"errors"
	"log/slog"

	"github.com/odigos-io/runtime-detector/internal/common"
	"github.com/odigos-io/runtime-detector/internal/proc"
)

var (
	// excludedCmds are the commands that we do not want to track
	excludedCmds = []string{
		// it is common for the kubelet/container-runtime to run a process with the command "/pause",
		"/pause",
	}

	// for testing purposes, we can override these functions
	getPodIDContainerNameFunc = proc.GetPodIDContainerName
	GetCmdlineFunc            = proc.GetCmdline
)

type k8sProcessesFilter struct {
	l *slog.Logger

	// the consumer of process events supplied by the k8s filter
	output chan<- common.PIDEvent
}

func NewK8sFilter(l *slog.Logger, output chan<- common.PIDEvent) common.ProcessesFilter {
	return &k8sProcessesFilter{
		l:      l,
		output: output,
	}
}

func excludedCmd(cmd string) bool {
	for _, excludedCmd := range excludedCmds {
		if cmd == excludedCmd {
			return true
		}
	}
	return false
}

func (k *k8sProcessesFilter) Add(pid int) {
	cmd, err := GetCmdlineFunc(pid)
	if err != nil {
		// log an error only if the error is not about not found process
		if !errors.Is(err, proc.ErrorProcessNotFound) {
			k.l.Error("failed to get cmdline", "pid", pid, "error", err)
		}
		return
	}

	if excludedCmd(cmd) {
		return
	}

	// try and find the podID and containerName for this pid
	podID, containerName, err := getPodIDContainerNameFunc(pid)
	if err != nil {
		// log an error only if the error is not about the process not being a k8s process
		if !errors.Is(err, proc.ErrorNotK8sProcess) {
			k.l.Error("failed to get podID and containerName", "pid", pid, "error", err)
		}
		return
	}

	k.output <- common.PIDEvent{Pid: pid, Type: common.EventTypeExec}

	k.l.Debug("k8s filter received pid",
		"pid", pid,
		"cmd", cmd,
		"podID", podID,
		"containerName", containerName,
	)
}

func (k *k8sProcessesFilter) Close() error {
	k.l.Info("k8s filter closed")
	close(k.output)
	return nil
}

func (k *k8sProcessesFilter) Remove(pid int) {
	k.output <- common.PIDEvent{Pid: pid, Type: common.EventTypeExit}
}

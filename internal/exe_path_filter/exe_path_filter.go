package exepathfilter

import (
	"log/slog"
	"sync"

	"github.com/odigos-io/runtime-detector/internal/common"
	"github.com/odigos-io/runtime-detector/internal/proc"
)

// exePathFilter filters process events based on executable paths.
// This is done in addition to similar filtering done in eBPF.
// There are some cases that we can cover here that are not covered by our eBPF program,
// This include a script launched with "./my-script.sh" and the script is interpreted by "/usr/bin/bash"
// if the user wants to filter out all bash processes, we can do that here.
type exePathFilter struct {
	mu               sync.Mutex

	// holds PIDs that have been filtered out based on exe path
	filteredPIDs     map[int]struct{}
	exePathsToFilter map[string]struct{}
	logger           *slog.Logger
	closed           bool

	output chan<- common.PIDEvent
}

func NewExePathFilter(logger *slog.Logger, exePathsToFilter map[string]struct{}, output chan<- common.PIDEvent) common.ProcessesFilter {
	return &exePathFilter{
		filteredPIDs:     make(map[int]struct{}),
		exePathsToFilter: exePathsToFilter,
		logger:           logger,
		output:           output,
	}
}

func (epf *exePathFilter) Add(pid int, eventType common.EventType) {
	epf.mu.Lock()
	defer epf.mu.Unlock()

	if epf.closed {
		epf.logger.Info("cannot add pid, the exe path filter has been closed")
		return
	}

	_, exePath := proc.GetExePathAndLink(pid)

	if _, ok := epf.exePathsToFilter[exePath]; ok {
		epf.logger.Debug("process event filtered out based on exe path",
			"exePath", exePath,
			"event type", eventType,
			"pid", pid,
		)
		// Mark this PID as filtered so we don't send exit events for it
		epf.filteredPIDs[pid] = struct{}{}
		return
	}

	epf.logger.Debug("passing process event to next filter", "pid", pid, "eventType", eventType.String())
	epf.output <- common.PIDEvent{Pid: pid, Type: eventType}
}

func (epf *exePathFilter) Remove(pid int) {
	epf.mu.Lock()
	defer epf.mu.Unlock()

	if _, ok := epf.filteredPIDs[pid]; ok {
		epf.logger.Debug("not sending exit event for filtered PID", "pid", pid)
		delete(epf.filteredPIDs, pid)
		return
	}

	epf.logger.Debug("passing exit event to next filter", "pid", pid)
	epf.output <- common.PIDEvent{Pid: pid, Type: common.EventTypeExit}
}

func (epf *exePathFilter) Close() error {
	epf.mu.Lock()
	defer epf.mu.Unlock()

	epf.filteredPIDs = make(map[int]struct{})

	close(epf.output)

	epf.closed = true
	return nil
}

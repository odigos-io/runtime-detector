package durationfilter

import (
	"log/slog"
	"sync"
	"time"

	"github.com/odigos-io/runtime-detector/internal/common"
)

type process struct {
	t        *time.Timer
}

type durationFilter struct {
	mu           sync.Mutex
	procs        map[int]*process
	logger       *slog.Logger
	liveDuration time.Duration
	consumer     common.ProcessesFilter
	closed       bool
}

func NewDurationFilter(logger *slog.Logger, d time.Duration, consumer common.ProcessesFilter) common.ProcessesFilter {
	return &durationFilter{
		procs:        make(map[int]*process),
		logger:       logger,
		liveDuration: d,
		consumer:     consumer,
	}
}

func (df *durationFilter) launchProcessCountdown(pid int, eventType common.EventType) *process {
	return &process{
		t: time.AfterFunc(df.liveDuration, func() {
			df.logger.Debug("process has been active for the specified duration", "pid", pid)
			// add the pid to the consumer
			df.consumer.Add(pid, eventType)
			// stop tracking the pid
			df.mu.Lock()
			delete(df.procs, pid)
			df.mu.Unlock()
		}),
	}
}

func (df *durationFilter) Add(pid int, eventType common.EventType) {
	df.mu.Lock()
	defer df.mu.Unlock()

	if df.closed {
		df.logger.Info("cannot add pid, the duration filter has been closed")
		return
	}

	if p, ok := df.procs[pid]; ok {
		df.logger.Debug("pid already exists")
		// the pid is already being tracked, we just re-scheduled the output
		// first stop the timer and then re-launce it with the updated eventType
		p.t.Stop()
	}

	df.logger.Debug("adding pid", "number of pids", len(df.procs), "pid", pid)
	df.procs[pid] = df.launchProcessCountdown(pid, eventType)
}

func (df *durationFilter) Remove(pid int) {
	df.mu.Lock()
	stopped := false

	if p, ok := df.procs[pid]; ok {
		stopped = p.t.Stop()
		delete(df.procs, pid)
	}
	df.mu.Unlock()

	if stopped {
		// we successfully stopped the timer, the pid was not added to the consumer
		// so we don't need to notify the consumer about the removal
		return
	}

	// the timer has already fired, we need to notify the consumer about the removal
	df.consumer.Remove(pid)
}

func (df *durationFilter) Close() error {
	df.mu.Lock()
	defer df.mu.Unlock()

	for pid, p := range df.procs {
		p.t.Stop()
		delete(df.procs, pid)
	}

	df.consumer.Close()

	df.closed = true
	return nil
}

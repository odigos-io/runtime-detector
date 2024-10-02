package durationfilter

import (
	"log/slog"
	"sync"
	"time"

	filter "github.com/odigos-io/runtime-detector/internal/process_filter"
)

type process struct {
	t        *time.Timer
}

type durationFilter struct {
	rwLock       sync.RWMutex
	procs        map[int]*process
	logger       *slog.Logger
	liveDuration time.Duration
	consumer     filter.ProcessesFilter
	closed       bool
}

func NewDurationFilter(logger *slog.Logger, d time.Duration, consumer filter.ProcessesFilter) filter.ProcessesFilter {
	df := &durationFilter{
		procs:        make(map[int]*process),
		logger:       logger,
		liveDuration: d,
		consumer:     consumer,
	}
	// set the feedback connection, the consumer can notify this filter about the removal of a pid
	// TODO: if we decide that this filter removes an entry once it passes it to the consumer, we should remove this
	if f, ok := df.consumer.(filter.FeedBackProcessesFilter); ok {
		f.SetProducer(df)
	}
	return df
}

func (df *durationFilter) launchProcessCountdown(pid int) *process {
	return &process{
		t: time.AfterFunc(df.liveDuration, func() {
			df.logger.Debug("process has been active for the specified duration", "pid", pid)
			// add the pid to the consumer
			df.consumer.Add(pid)
			// TODO: should we remove the PID from the duration filter here?
		}),
	}
}

func (df *durationFilter) Add(pid int) {
	df.rwLock.Lock()
	defer df.rwLock.Unlock()

	if df.closed {
		df.logger.Info("cannot add pid, the duration filter has been closed")
		return
	}

	if p, ok := df.procs[pid]; ok {
		df.logger.Debug("pid already exists")
		p.t.Reset(df.liveDuration)
		// the pid is already being tracked, we just re-scheduled the output
		return
	}

	df.logger.Debug("adding pid", "number of pids", len(df.procs), "pid", pid)
	df.procs[pid] = df.launchProcessCountdown(pid)
}

func (df *durationFilter) Remove(pid int) {
	df.rwLock.Lock()
	defer df.rwLock.Unlock()

	if p, ok := df.procs[pid]; ok {
		p.t.Stop()
		delete(df.procs, pid)
		df.consumer.Remove(pid)
	}
}

func (df *durationFilter) Close() error {
	df.rwLock.Lock()
	defer df.rwLock.Unlock()

	for pid, p := range df.procs {
		p.t.Stop()
		delete(df.procs, pid)
	}

	df.consumer.Close()

	df.closed = true
	return nil
}

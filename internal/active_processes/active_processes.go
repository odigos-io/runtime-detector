package activeprocesses

import (
	"log/slog"
	"sync"
	"time"
)

type process struct {
	t *time.Timer
}

type ActiveProcesses struct {
	rwLock sync.RWMutex
	procs map[int]*process
	logger *slog.Logger
	livePeriod time.Duration
}

func New (logger *slog.Logger) *ActiveProcesses {
	return &ActiveProcesses{
		procs: make(map[int]*process),
		logger: logger,
		// TODO: pass this as a parameter
		livePeriod: 1 * time.Second,
	}
}

func (ap *ActiveProcesses) launchProcessCountdown(pid int) *process {
	runOnce := sync.Once{}
	return &process{
		t: time.AfterFunc(ap.livePeriod, func() {
			runOnce.Do(func() {
				ap.logger.Info("process has been inactive for the specified time", "pid", pid)
				ap.Remove(pid)
			})
		}),
	}
}


func (ap *ActiveProcesses) Add(pid int) {
	exists := false
	ap.rwLock.RLock()
	if p, ok := ap.procs[pid]; ok {
		ap.logger.Info("pid already exists")
		p.t.Reset(ap.livePeriod)
		exists = true
	}
	ap.rwLock.RUnlock()

	if exists {
		return
	}

	ap.rwLock.Lock()
	defer ap.rwLock.Unlock()

	ap.logger.Info("adding pid", "number of pids", len(ap.procs), "pid", pid)
	ap.procs[pid] = ap.launchProcessCountdown(pid)
}

func (ap *ActiveProcesses) Remove(pid int) {
	ap.rwLock.Lock()
	defer ap.rwLock.Unlock()

	if p, ok := ap.procs[pid]; ok {
		p.t.Stop()
	}
	delete(ap.procs, pid)
}
package k8sfilter

import (
	"errors"
	"log/slog"
	"sync"

	"github.com/odigos-io/runtime-detector/internal/proc"
	filter "github.com/odigos-io/runtime-detector/internal/process_filter"
)

var (
	excludedCmds = []string{
		"/pause",
	}
)

type podContainerKey struct {
	podID         string
	containerName string
}

type k8sProcessesMap struct {
	mu                 sync.RWMutex
	pidToPodContainer  map[int]podContainerKey
	podContainerToPids map[podContainerKey][]int
}

type k8sProcessesFilter struct {
	l *slog.Logger
	m *k8sProcessesMap
	// the producer which feeds the k8s filter with process events,
	// we can notify the producer about processes which are not related to k8s
	producer filter.ProcessesFilter
}

func (k *k8sProcessesMap) podContainer(pid int) (podContainerKey, bool) {
	k.mu.RLock()
	defer k.mu.RUnlock()

	key, ok := k.pidToPodContainer[pid]
	return key, ok
}

func (k *k8sProcessesMap) add(pid int, podID, containerName string) {
	k.mu.Lock()
	defer k.mu.Unlock()

	key := podContainerKey{podID: podID, containerName: containerName}
	if _, ok := k.pidToPodContainer[pid]; !ok {
		// we are not tracking this pid yet
		k.pidToPodContainer[pid] = key

		if _, ok := k.podContainerToPids[key]; !ok {
			// first time we see this (pod,container) key
			k.podContainerToPids[key] = []int{pid}
		} else {
			// new pid for an existing (pod,container) key
			k.podContainerToPids[key] = append(k.podContainerToPids[key], pid)
		}
	}
}

func removePidFromSlice(pids []int, index int) []int {
	// fast removal, order is not important
	pids[index] = pids[len(pids)-1]
    return pids[:len(pids)-1]
}

func (k *k8sProcessesMap) remove(pid int) {
	k.mu.Lock()
	defer k.mu.Unlock()

	key, ok := k.pidToPodContainer[pid]
	if !ok {
		return
	}

	delete(k.pidToPodContainer, pid)
	pidsInPodContainer := k.podContainerToPids[key]
	for i, p := range pidsInPodContainer {
		if p == pid {
			pidsInPodContainer = removePidFromSlice(pidsInPodContainer, i)
			break
		}
	}

	if len(pidsInPodContainer) == 0 {
		// left with no pids for this (pod,container) key
		delete(k.podContainerToPids, key)
	} else {
		k.podContainerToPids[key] = pidsInPodContainer
	}
}

func New(l *slog.Logger) filter.ProcessesFilter {
	return &k8sProcessesFilter{
		l: l,
		m: &k8sProcessesMap{
			pidToPodContainer:  make(map[int]podContainerKey),
			podContainerToPids: make(map[podContainerKey][]int),
		},
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

func (k *k8sProcessesFilter) notifyProducerAboutUnrelaventProcess(pid int) {
	if k.producer != nil {
		k.producer.Remove(pid)
	}
}

func (k *k8sProcessesFilter) Add(pid int) {
	cmd, err := proc.GetCmdline(pid)
	if err != nil {
		k.l.Error("failed to get cmdline", "pid", pid, "error", err)
		return
	}

	if excludedCmd(cmd) {
		k.notifyProducerAboutUnrelaventProcess(pid)
		return
	}

	_, ok := k.m.podContainer(pid)
	if ok {
		// we already know the podID and containerName for this pid
		// TODO notify the consumer about a potential update
		return
	}

	podID, containerName, err := proc.GetPodIDContainerName(pid)
	if err != nil {
		// log an error only if the error is not about the process not being a k8s process
		if !errors.Is(err, proc.ErrorNotK8sProcess) {
			k.l.Error("failed to get podID and containerName", "pid", pid, "error", err)
		}
		// we could not determine the podID and containerName for this pid, we should not track it
		k.notifyProducerAboutUnrelaventProcess(pid)
		return
	}

	k.m.add(pid, podID, containerName)

	k.l.Info("k8s filter received pid",
		"pid", pid,
		"cmd", cmd,
		"podID", podID,
		"containerName", containerName,
	)
}

func (k *k8sProcessesFilter) Close() error {
	k.l.Info("k8s filter closed")
	return nil
}

func (k *k8sProcessesFilter) Remove(pid int) {
	// we might receive a remove event for a pid that we are not tracking
	// in that case this function is a no-op.
	if _, ok := k.m.podContainer(pid); !ok {
		return
	}

	k.m.remove(pid)
}

var _ filter.FeedBackProcessesFilter = &k8sProcessesFilter{}

func (k *k8sProcessesFilter) SetProducer(p filter.ProcessesFilter) {
	k.producer = p
}

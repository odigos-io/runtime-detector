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

	// for testing purposes, we can override these functions
	getPodIDContainerNameFunc = proc.GetPodIDContainerName
	GetCmdlineFunc = proc.GetCmdline
)

type K8sFilter interface {
	TrackPodContainers(podID string, containerNames ...string)
}

var _ K8sFilter = &k8sProcessesFilter{}

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
	producer              filter.ProcessesFilter

	podContainersMu	      sync.RWMutex
	relevantPodContainers map[podContainerKey]struct{}

	// the consumer of process events supplied by the k8s filter
	consumer              filter.ProcessesFilter
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

func (k *k8sProcessesMap) remove(pid int, podContainer podContainerKey) {
	k.mu.Lock()
	defer k.mu.Unlock()

	delete(k.pidToPodContainer, pid)
	pidsInPodContainer := k.podContainerToPids[podContainer]
	for i, p := range pidsInPodContainer {
		if p == pid {
			pidsInPodContainer = removePidFromSlice(pidsInPodContainer, i)
			break
		}
	}

	if len(pidsInPodContainer) == 0 {
		// left with no pids for this (pod,container) key
		delete(k.podContainerToPids, podContainer)
	} else {
		k.podContainerToPids[podContainer] = pidsInPodContainer
	}
}

func NewK8sFilter(l *slog.Logger, consumer filter.ProcessesFilter) filter.ProcessesFilter {
	return &k8sProcessesFilter{
		l: l,
		m: &k8sProcessesMap{
			pidToPodContainer:  make(map[int]podContainerKey),
			podContainerToPids: make(map[podContainerKey][]int),
		},
		relevantPodContainers: make(map[podContainerKey]struct{}),
		consumer:              consumer,
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

func (k *k8sProcessesFilter) notifyConsumerAboutRelevantProcess(pid int, podContainer podContainerKey) {
	if k.consumer == nil {
		return
	}

	k.podContainersMu.RLock()
	defer k.podContainersMu.RUnlock()

	if _, ok := k.relevantPodContainers[podContainer]; ok {
		k.consumer.Add(pid)
	}
}

func (k *k8sProcessesFilter) Add(pid int) {
	cmd, err := GetCmdlineFunc(pid)
	if err != nil {
		k.l.Error("failed to get cmdline", "pid", pid, "error", err)
		return
	}

	if excludedCmd(cmd) {
		k.notifyProducerAboutUnrelaventProcess(pid)
		return
	}

	podContainer, ok := k.m.podContainer(pid)
	if ok {
		// we already know the podID and containerName for this pid.
		// this case can happen if the a process uses 'execve' without fork (aka 'chain loading')
		// notify the consumer about this pid, which might need to re-evaluate it
		k.notifyConsumerAboutRelevantProcess(pid, podContainer)
		return
	}

	// try and find the podID and containerName for this pid
	podID, containerName, err := getPodIDContainerNameFunc(pid)
	if err != nil {
		// log an error only if the error is not about the process not being a k8s process
		if !errors.Is(err, proc.ErrorNotK8sProcess) {
			k.l.Error("failed to get podID and containerName", "pid", pid, "error", err)
		}
		// we could not determine the podID and containerName for this pid, we tell the producer to not track it
		k.notifyProducerAboutUnrelaventProcess(pid)
		return
	}

	k.m.add(pid, podID, containerName)
	k.notifyConsumerAboutRelevantProcess(pid, podContainerKey{podID: podID, containerName: containerName})

	k.l.Debug("k8s filter received pid",
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
	// we might receive a remove event for a pid that we are not tracking.
	// in that case this function is a no-op.
	podContainer, ok := k.m.podContainer(pid)
	if !ok {
		return
	}
	k.m.remove(pid, podContainer)
	if k.consumer != nil {
		k.consumer.Remove(pid)
	}
}

var _ filter.FeedBackProcessesFilter = &k8sProcessesFilter{}

func (k *k8sProcessesFilter) SetProducer(p filter.ProcessesFilter) {
	k.producer = p
}

func (k *k8sProcessesFilter) TrackPodContainers(podID string, containerNames ...string) {
	k.podContainersMu.Lock()
	defer k.podContainersMu.Unlock()

	key := podContainerKey{podID: podID}
	keys := make([]podContainerKey, len(containerNames))
	for i, containerName := range containerNames {
		key.containerName = containerName
		keys[i] = key
		k.relevantPodContainers[key] = struct{}{}
	}

	// go over the pids for this (pod,container) key and notify the consumer
	k.m.mu.RLock()
	defer k.m.mu.RUnlock()

	for _, key := range keys {
		pids, ok := k.m.podContainerToPids[key]
		if !ok {
			continue
		}
		for _, pid := range pids {
			k.consumer.Add(pid)
		}
	}
}

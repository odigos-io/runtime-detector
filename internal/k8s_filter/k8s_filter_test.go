package k8sfilter

import (
	"fmt"
	"log/slog"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRemove(t *testing.T) {
	m := &k8sProcessesMap{
		pidToPodContainer:  make(map[int]podContainerKey),
		podContainerToPids: make(map[podContainerKey][]int),
		mu:                 sync.RWMutex{},
	}

	filter := &k8sProcessesFilter{
		l:        slog.Default(),
		m:        m,
		producer: nil,
	}

	// Add some PIDs
	m.add(1, "pod1", "container1")
	m.add(2, "pod1", "container1")

	// Case: Remove an existing PID
	filter.Remove(1)
	_, ok := m.podContainer(1)
	assert.False(t, ok)
	assert.Len(t, m.podContainerToPids[podContainerKey{"pod1", "container1"}], 1)
	assert.Contains(t, m.podContainerToPids, podContainerKey{"pod1", "container1"})

	// Case: Remove the last PID for a podContainerKey
	filter.Remove(2)
	_, ok = m.podContainer(2)
	assert.False(t, ok)
	assert.NotContains(t, m.podContainerToPids, podContainerKey{"pod1", "container1"})
}

type dummyProcessesFilter struct {
	added   []int
	removed []int
	closed  bool
}

func (d *dummyProcessesFilter) Add(pid int) {
	d.added = append(d.added, pid)
}

func (d *dummyProcessesFilter) Remove(pid int) {
	d.removed = append(d.removed, pid)
}

func (d *dummyProcessesFilter) Close() error {
	d.closed = true
	return nil
}

func TestTrackPodContainers(t *testing.T) {
	// mock the getPodIDContainerNameFunc
	origPodIdContainerNameFunc := getPodIDContainerNameFunc
	getPodIDContainerNameFunc = func(pid int) (string, string, error) {
		if pid >= 1 && pid <= 10 {
			return "pod1", fmt.Sprintf("container%d", pid%10), nil
		}
		if pid >= 11 && pid <= 20 {
			return "pod2", fmt.Sprintf("container%d", pid%10), nil
		}
		if pid >= 21 && pid <= 30 {
			return "pod3", fmt.Sprintf("container%d", pid%10), nil
		}
		return "", "", fmt.Errorf("pid %d not found", pid)
	}
	t.Cleanup(func() { getPodIDContainerNameFunc = origPodIdContainerNameFunc })

	origGetCmdlineFunc := GetCmdlineFunc
	GetCmdlineFunc = func(pid int) (string, error) {
		return fmt.Sprintf("cmd%d", pid), nil
	}
	t.Cleanup(func() { GetCmdlineFunc = origGetCmdlineFunc })

	m := &k8sProcessesMap{
		pidToPodContainer:  make(map[int]podContainerKey),
		podContainerToPids: make(map[podContainerKey][]int),
		mu:                 sync.RWMutex{},
	}

	dummyConsumer := &dummyProcessesFilter{
		added:   []int{},
		removed: []int{},
		closed:  false,
	}

	filter := &k8sProcessesFilter{
		l:                     slog.Default(),
		m:                     m,
		producer:              nil,
		consumer:              dummyConsumer,
		relevantPodContainers: make(map[podContainerKey]struct{}),
	}

	// Case: Track a new podContainerKey
	filter.TrackPodContainers("pod1", "container1")
	assert.Empty(t, dummyConsumer.added)

	// pod1 container1
	filter.Add(1)
	assert.Equal(t, dummyConsumer.added, []int{1})

	// Case: Track an existing podContainerKey
	// pod1 container 2
	filter.Add(2)
	assert.Equal(t, dummyConsumer.added, []int{1})
	filter.TrackPodContainers("pod1", "container2")
	assert.Equal(t, dummyConsumer.added, []int{1, 2})

	// track multiple podContainerKeys
	// pod2 container 1
	filter.Add(11)
	// pod2 container 2
	filter.Add(12)
	assert.Equal(t, dummyConsumer.added, []int{1, 2})
	filter.TrackPodContainers("pod2", "container1", "container2")
	assert.Equal(t, dummyConsumer.added, []int{1, 2, 11, 12})
}

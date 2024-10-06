package proc

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

var (
	procFS = "/proc"
	ErrorNotK8sProcess = fmt.Errorf("pod UID and container name not found, not a k8s process")
	ErrorProcessNotFound = fmt.Errorf("process not found")
)

func SetProcFS(path string) error {
	_, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("failed to set proc filesystem ti %s: %w", path, err)
	}
	procFS = path
	return nil
}

// GetCmdline returns the command line of the process with the given PID.
func GetCmdline(pid int) (string, error) {
	path := fmt.Sprintf("%s/%d/cmdline", procFS, pid)

	res, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", ErrorProcessNotFound
		}
		return "", fmt.Errorf("failed to read cmdline for pid %d: %w", pid, err)
	}

	return getCleanCmdLine(res), nil
}

func getCleanCmdLine(b []byte) string {
	s := strings.ReplaceAll(string(b), "\x00", " ")
	s = strings.TrimSpace(s)

	return s
}

func GetPodIDContainerName(pid int) (string, string, error) {
	path := fmt.Sprintf("%s/%d/mountinfo", procFS, pid)
	f, err := os.Open(path)
	if err != nil {
		return "", "", err
	}
	defer f.Close()

	return getPodIDContainerNameFromReader(f)
}

func getPodIDContainerNameFromReader(r io.Reader) (string, string, error) {
	const podsDelimiter = "pods/"
	const containersDelimiter = "/containers/"
	var podUIDIndex, containerNameIndex int

	// looking for entries which have the following format:
	// .../pods/<podUID>/containers/<containerName>/...
	// this is the way kubelet creates mount points for pods and containers
	// https://github.com/kubernetes/kubernetes/blob/b42772c3b1b5464838761372042891b6888fb2af/pkg/kubelet/config/defaults.go#L21
	// https://github.com/kubernetes/kubernetes/blob/master/pkg/kubelet/kubelet_getters.go#L200

	s := bufio.NewScanner(r)
	for s.Scan() {
		line := s.Text()

		index := strings.LastIndex(line, podsDelimiter)
		if index == -1 {
			continue
		}
		podUIDIndex = index + len(podsDelimiter)
		line = line[podUIDIndex:]

		index = strings.Index(line, containersDelimiter)
		if index == -1 {
			continue
		}

		podUID := line[:index]
		containerNameIndex = index + len(containersDelimiter)

		line = line[containerNameIndex:]
		index = strings.Index(line, "/")
		if index == -1 {
			continue
		}

		containerName := line[:index]
		return podUID, containerName, nil
	}

	return "", "", ErrorNotK8sProcess
}

func AllProcesses() ([]int, error) {
	d, err := os.Open(procFS)
	if err != nil {
		return nil, err
	}
	defer d.Close()

	names, err := d.Readdirnames(-1)
	if err != nil {
		return nil, fmt.Errorf("failed to read procFS directory: %w", err)
	}

	var res []int
	for _, name := range names {
		pid, err := strconv.ParseInt(name, 10, 64)
		if err != nil {
			continue
		}

		res = append(res, int(pid))
	}

	return res, nil
}
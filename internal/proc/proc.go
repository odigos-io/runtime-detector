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
	procFS               = "/proc"
	ErrorNotK8sProcess   = fmt.Errorf("pod UID and container name not found, not a k8s process")
	ErrorProcessNotFound = fmt.Errorf("process not found")
)

const (
	odigosEnvVarKeyPrefix = "ODIGOS_POD"
)

func procFile(pid int, filename string) string {
	return fmt.Sprintf("%s/%d/%s", procFS, pid, filename)
}

func GetCurrentPIDNameSpaceIndoe() (uint32, error) {
	// look at the pid namespace of the root process
	path := procFile(1, "ns/pid")
	content, err := os.Readlink(path)
	if err != nil {
		return 0, fmt.Errorf("failed to read link %s: %w", path, err)
	}

	return extractNSInode(content)
}

func extractNSInode(content string) (uint32, error) {
	parts := strings.Split(content, "[")
	if len(parts) != 2 {
		return 0, fmt.Errorf("unexpected content %s", content)
	}

	inodeStr := strings.TrimRight(parts[1], "]")
	inode, err := strconv.ParseUint(inodeStr, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("failed to parse inode %s: %w", inodeStr, err)
	}

	return uint32(inode), nil
}

// GetCmdline returns the command line of the process with the given PID.
func GetCmdline(pid int) (string, error) {
	path := procFile(pid, "cmdline")

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
	path := procFile(pid, "mountinfo")
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

func isProcessRelevantToOdigos(pid int) bool {
	path := procFile(pid, "environ")
	fileContent, err := os.ReadFile(path)
	if err != nil {
		return false
	}

	// don't fully pares the environment, just check if it contains the ODIGOS_ prefix
	return strings.Contains(string(fileContent), odigosEnvVarKeyPrefix)
}

func AllRelevantProcesses() ([]int, error) {
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

		if !isProcessRelevantToOdigos(int(pid)) {
			continue
		}

		res = append(res, int(pid))
	}

	return res, nil
}

func GetEnvironmentVars(pid int, keys map[string]struct{}) (map[string]string, error) {
	path := procFile(pid, "environ")
	fileContent, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	return parseEnvironments(strings.NewReader(string(fileContent)), keys)
}

func parseEnvironments(r io.Reader, keys map[string]struct{}) (map[string]string, error) {
	bufReader := bufio.NewReader(r)

	result := make(map[string]string)

	for {
		// The entries are  separated  by
		// null bytes ('\0'), and there may be a null byte at the end.
		str, err := bufReader.ReadString(0)
		if err == io.EOF {
			break
		}

		if err != nil {
			return nil, fmt.Errorf("failed to read environ file: %w", err)
		}

		str = strings.TrimRight(str, "\x00")
		parts := strings.SplitN(str, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := parts[0]
		if _, ok := keys[key]; ok {
			result[key] = parts[1]
		}
	}

	return result, nil
}

// The exe Symbolic Link: Inside each process's directory in /proc,
// there is a symbolic link named exe. This link points to the executable
// file that was used to start the process.
// For instance, if a process was started from /usr/bin/python,
// the exe symbolic link in that process's /proc directory will point to /usr/bin/python.
func GetExeNameAndLink(pid int) (link, exeName string) {
	link = procFile(pid, "exe")
	exeName, err := os.Readlink(link)
	if err != nil {
		// Read link may fail if target process runs not as root
		return "", ""
	}
	return link, exeName
}

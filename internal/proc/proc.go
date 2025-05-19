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

func isProcessRelevantToOdigos(pid int, prefix string) bool {
	path := procFile(pid, "environ")
	fileContent, err := os.ReadFile(path)
	if err != nil {
		return false
	}

	// don't fully pares the environment, just check if it contains the prefix
	return strings.Contains(string(fileContent), prefix)
}

func AllRelevantProcesses(envPrefix string, exePathsToFilter map[string]struct{}) ([]int, error) {
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

		if !isProcessRelevantToOdigos(int(pid), envPrefix) {
			continue
		}

		_, exePath := GetExePathAndLink(int(pid))
		if _, ok := exePathsToFilter[exePath]; ok {
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
func GetExePathAndLink(pid int) (link, exePath string) {
	link = procFile(pid, "exe")
	exePath, err := os.Readlink(link)
	if err != nil {
		// Read link may fail if target process runs not as root
		return "", ""
	}
	return link, exePath
}

// IsProcess checks if the given PID corresponds to a process or a thread.
// It returns true if the PID is a process, and false if it is a thread.
func IsProcess(pid int) (bool, error) {
	status := procFile(pid, "status")

	f, err := os.Open(status)
	if err != nil {
		return false, err
	}
	defer f.Close()

	return isProcessFromReader(f)
}

func isProcessFromReader(r io.Reader) (bool, error) {
	var tgid, pid int
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()

		if strings.HasPrefix(line, "Tgid:") {
			_, err := fmt.Sscanf(line, "Tgid:\t%d", &tgid)
			if err != nil {
				return false, fmt.Errorf("failed to parse Tgid: %w", err)
			}
		} else if strings.HasPrefix(line, "Pid:") {
			_, err := fmt.Sscanf(line, "Pid:\t%d", &pid)
			if err != nil {
				return false, fmt.Errorf("failed to parse Pid: %w", err)
			}
		}

		if tgid != 0 && pid != 0 {
			break
		}
	}

	if err := scanner.Err(); err != nil {
		return false, fmt.Errorf("failed to read /proc/<pid>/status file %v", err)
	}

	return tgid == pid, nil
}

func InnerMostPID(rootPID int) (int, error) {
	status := procFile(rootPID, "status")

	f, err := os.Open(status)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	return innerMostPIDFromReader(f)
}

func innerMostPIDFromReader(r io.Reader) (int, error) {
	// from https://man7.org/linux/man-pages/man5/proc_pid_status.5.html
	// NStgid Thread group ID (i.e., PID) in each of the PID
	// namespaces of which pid is a member.  The leftmost
	// entry shows the value with respect to the PID
	// namespace of the process that mounted this procfs
	// (or the root namespace if mounted by the kernel),
	// followed by the value in successively nested inner
	// namespaces.  (Since Linux 4.1.)
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "NStgid:") {
			parts := strings.Fields(line[len("NStgid:"):])
			if len(parts) == 0 {
				return 0, fmt.Errorf("no NStgid values found")
			}
			// The last value is the inner most PID
			pid, err := strconv.Atoi(parts[len(parts)-1])
			if err != nil {
				return 0, fmt.Errorf("failed to parse NStgid value: %w", err)
			}
			return pid, nil
		}
	}

	if err := scanner.Err(); err != nil {
		return 0, fmt.Errorf("failed to read /proc/<pid>/status file %v", err)
	}
	return 0, fmt.Errorf("NStgid not found in status file")
}

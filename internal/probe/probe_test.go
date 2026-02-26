package probe

import (
	"log/slog"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func repeatedString(length int, s string) string {
	b := make([]byte, length*len(s))
	for i := range b {
		b[i] = s[i%len(s)]
	}
	return string(b)
}

func TestLoad(t *testing.T) {
	t.Run("load with empty env prefix", func(t *testing.T) {
		p := &Probe{
			logger: slog.Default(),
		}
		err := p.load(uint32(4026532561))
		defer func() {
			err := p.Close()
			assert.NoError(t, err)
		}()
		assert.NoError(t, err)
	})

	t.Run("load with env prefix", func(t *testing.T) {
		p := &Probe{
			logger:          slog.Default(),
			envPrefixFilter: "ODIGOS_POD_NAME",
		}
		err := p.load(uint32(4026532561))
		defer p.Close()
		require.NoError(t, err)
		m := p.c.Maps[envPrefixMapName]
		assert.NotNil(t, m)

		value := bpfEnvPrefixT{}
		err = m.Lookup(uint32(0), &value)
		assert.NoError(t, err)
		assert.Equal(t, uint64(len("ODIGOS_POD_NAME")), value.Len)

		prefixStr := make([]byte, len("ODIGOS_POD_NAME"))
		copy(prefixStr, value.Prefix[:])
		assert.Equal(t, []byte("ODIGOS_POD_NAME"), prefixStr)
	})

	t.Run("load with too long env prefix", func(t *testing.T) {
		p := &Probe{
			logger:          slog.Default(),
			envPrefixFilter: repeatedString(100, "TEST"),
		}
		err := p.load(uint32(4026532561))
		defer p.Close()
		assert.ErrorContains(t, err, "env prefix filter is too long")
	})

	t.Run("load with tracked PIDs", func(t *testing.T) {
		p := &Probe{
			logger: slog.Default(),
		}
		err := p.load(uint32(4026532561))
		require.NoError(t, err)
		defer p.Close()

		confMap, ok := p.c.Maps[detectorConfigMapName]
		assert.True(t, ok)
		assert.NotNil(t, confMap)
		value := bpfDetectorConfigT{}
		err = confMap.Lookup(uint32(0), &value)
		assert.NoError(t, err)
		assert.Equal(t, uint32(4026532561), value.ConfiguredPidNsInode)
		assert.Equal(t, uint8(0), value.NumOpenPathsToTrack)
		assert.Equal(t, uint8(0), value.NumExecPathsToFilter)

		pids := []int{1, 2, 3, 4, 5}
		err = p.TrackPIDs(pids)
		assert.NoError(t, err)

		for _, pid := range pids {
			containerPID, err := p.GetContainerPID(pid)
			assert.NoError(t, err)
			assert.Equal(t, 0, containerPID)
		}
	})

	t.Run("load with too long file name to track for open", func(t *testing.T) {
		p := &Probe{
			logger:           slog.Default(),
			openFilesToTrack: []string{repeatedString(129, "a")},
		}
		err := p.load(uint32(4026532561))
		defer p.Close()
		assert.ErrorContains(t, err, "filename is too long")
	})

	t.Run("load with too long executable filename to filter", func(t *testing.T) {
		p := &Probe{
			logger: slog.Default(),
			execFilesToFilter: map[string]struct{}{
				repeatedString(65, "a"): {},
			},
		}
		err := p.load(uint32(4026532561))
		defer p.Close()
		assert.ErrorContains(t, err, "executable filename is too long")
	})

	t.Run("load with too many file name for open tracking", func(t *testing.T) {
		p := &Probe{
			logger:           slog.Default(),
			openFilesToTrack: make([]string, 9),
		}
		err := p.load(uint32(4026532561))
		defer p.Close()
		assert.ErrorContains(t, err, "too many files to track for open")
	})

	t.Run("load with too many executable files to filter", func(t *testing.T) {
		p := &Probe{
			logger: slog.Default(),
			// create map with 33 entries
			execFilesToFilter: map[string]struct{}{
				"a": {}, "b": {}, "c": {}, "d": {},
				"e": {}, "f": {}, "g": {}, "h": {},
				"i": {}, "j": {}, "k": {}, "l": {},
				"m": {}, "n": {}, "o": {}, "p": {},
				"q": {}, "r": {}, "s": {}, "t": {},
				"u": {}, "v": {}, "w": {}, "x": {},
				"y": {}, "z": {}, "aa": {}, "bb": {},
				"cc": {}, "dd": {}, "ee": {}, "ff": {},
				"gg": {},
			},
		}
		err := p.load(uint32(4026532561))
		defer p.Close()
		assert.ErrorContains(t, err, "too many executable files to ignore")
	})

	t.Run("load with multiple file names", func(t *testing.T) {
		p := &Probe{
			logger:           slog.Default(),
			openFilesToTrack: []string{"/var/file1.so", "/var/file2.so"},
			execFilesToFilter: map[string]struct{}{
				"/usr/bin/bash": {},
				"/usr/tini":     {},
				"/usr/bin/sh":   {},
			},
		}
		err := p.load(uint32(4026532561))
		defer p.Close()
		require.NoError(t, err)

		confMap, ok := p.c.Maps[detectorConfigMapName]
		assert.True(t, ok)
		assert.NotNil(t, confMap)
		value := bpfDetectorConfigT{}
		err = confMap.Lookup(uint32(0), &value)
		assert.NoError(t, err)
		assert.Equal(t, uint32(4026532561), value.ConfiguredPidNsInode)
		assert.Equal(t, uint8(2), value.NumOpenPathsToTrack)
		assert.Equal(t, uint8(3), value.NumExecPathsToFilter)

		m := p.c.Maps[openTrackingFilenameMapName]
		assert.NotNil(t, m)

		for i, file := range p.openFilesToTrack {
			value := bpfOpenFilenameT{}
			err = m.Lookup(uint32(i), &value)
			assert.NoError(t, err)
			assert.Equal(t, uint64(len(file)), value.Len)

			filename := make([]byte, len(file))
			copy(filename, value.Buf[:])
			assert.Equal(t, []byte(file), filename)
		}

		m = p.c.Maps[execFilesToFilterMapName]
		assert.NotNil(t, m)

		collectedExeFiles := make(map[string]struct{})
		for i := range len(p.execFilesToFilter) {
			value := bpfExecFilenameT{}
			err = m.Lookup(uint32(i), &value)
			assert.NoError(t, err)

			filename := make([]byte, value.Len)
			copy(filename, value.Buf[:])
			collectedExeFiles[string(filename)] = struct{}{}
		}

		assert.Equal(t, p.execFilesToFilter, collectedExeFiles)
	})
}

// TestFailedExecCleanup verifies that a failed execve does not leave stale
// entries in the BPF tracking maps.
func TestFailedExecCleanup(t *testing.T) {
	p := &Probe{
		logger:          slog.Default(),
		envPrefixFilter: "DETECTOR_TEST_",
		execFilesToFilter: map[string]struct{}{
			"/bin/bash":     {},
			"/bin/sh":       {},
			"/usr/bin/bash": {},
			"/usr/bin/sh":   {},
		},
	}
	// pid_ns_inode = 0 → report PIDs as seen by the host namespace
	err := p.load(0)
	require.NoError(t, err)
	defer p.Close()
	err = p.attach()
	require.NoError(t, err)

	// Pipe for stdin so bash's "read" builtin blocks indefinitely.
	pr, pw, err := os.Pipe()
	require.NoError(t, err)
	defer pw.Close()
	defer pr.Close()

	// bash is exec'd with an empty env → initial exec does NOT match the prefix.
	// bash then exports the matching var and calls "exec /nonexistent..." which
	// fails (ENOENT). "shopt -s execfail" keeps bash alive after the failure.
	cmd := exec.Command("bash", "-c",
		`shopt -s execfail; export DETECTOR_TEST_VAR=1; exec /nonexistent/binary_that_does_not_exist 2>/dev/null; read`)
	cmd.Stdin = pr
	cmd.Env = []string{}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	err = cmd.Start()
	require.NoError(t, err)
	defer func() {
		// Kill the entire process group to clean up bash.
		syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		cmd.Wait()
	}()

	// Give the BPF programs time to process the failed exec.
	time.Sleep(time.Second)

	assertMapsAreEmpty(t, p)
}

// TestNonLeaderThreadExecLeak verifies that when a non-leader thread calls
// execve, the map entry keyed on the old thread-id is cleaned up after the
// process exits.
//
// Kernel behavior: when a non-leader thread (tid != tgid) calls execve and
// it succeeds, the kernel changes the thread's pid to the tgid.
// sys_enter_execve fires BEFORE the change (key = old tid), but
// sys_exit_execve fires AFTER (key = tgid). The lookup in sys_exit_execve
// uses the new pid and won't find the old entry. sched_process_exit only
// cleans up the tgid key, so the old tid entry leaks permanently.
func TestNonLeaderThreadExecLeak(t *testing.T) {
	pythonPath, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not found in PATH, skipping")
	}

	execTarget, err := exec.LookPath("true")
	require.NoError(t, err)

	p := &Probe{
		logger:          slog.Default(),
		envPrefixFilter: "DETECTOR_TEST_",
		execFilesToFilter: map[string]struct{}{
			pythonPath: {},
		},
	}
	err = p.load(0)
	require.NoError(t, err)
	defer p.Close()
	err = p.attach()
	require.NoError(t, err)

	// Python is filtered (execFilesToFilter) so its initial exec is not tracked.
	// Inside Python a non-leader thread calls os.execve on the target binary
	// ("true") with the matching env prefix — this IS tracked.
	// After exec succeeds the process (now "true") exits immediately.
	cmd := exec.Command(pythonPath, "-c", `
import threading, os, sys, time
def do_exec():
    time.sleep(0.1)
    os.execve(sys.argv[1], [sys.argv[1]], os.environ)
t = threading.Thread(target=do_exec)
t.start()
t.join()
`, execTarget)
	cmd.Env = []string{"DETECTOR_TEST_VAR=1"}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	err = cmd.Start()
	require.NoError(t, err)

	err = cmd.Wait()
	require.NoError(t, err)

	// Both maps should be empty: the process has exited.
	// BUG: the entry added in sys_enter_execve under the old thread-id is
	// never cleaned — sys_exit_execve and sched_process_exit only know
	// about the new pid (tgid).
	assertMapsAreEmpty(t, p)
}

func assertMapsAreEmpty(t *testing.T, p *Probe) {
	t.Helper()
	for _, mapName := range []string{pidToContainerPIDMapName, trackedPidsMapName} {
		m, ok := p.c.Maps[mapName]
		assert.True(t, ok)
		assert.NotNil(t, m)

		iterator := m.Iterate()
		var key, value uint32
		count := 0
		for iterator.Next(&key, &value) {
			t.Log("found entry", "key", key, "value", value)
			count++
		}
		assert.Equal(t, 0, count, "map %s is not empty, have %d entries", mapName, count)
		assert.NoError(t, iterator.Err())
	}
}

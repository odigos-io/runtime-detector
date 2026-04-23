package detector

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	// bigEnvVarsMapWithUserVal is a map with a lot of environment variables to test the detector's handling of a process
	// with many environment variables.
	bigEnvVarsMapWithUserVal = func() map[string]string {
		m := make(map[string]string)
		for i := 0; i < 2000; i++ {
			m[fmt.Sprintf("TEST_ENV_VAR_%d", i)] = fmt.Sprintf("value%d", i)
		}

		m["USER_ENV"] = "value"
		return m
	}()

	bigEnvVarsMapWithoutUserVal = func() map[string]string {
		m := make(map[string]string)
		for i := 0; i < 2000; i++ {
			m[fmt.Sprintf("TEST_ENV_VAR_%d", i)] = fmt.Sprintf("value%d", i)
		}
		return m
	}()

	// sleepLocation finds and resolves the sleep binary path
	sleepLocation = func() string {
		path, err := exec.LookPath("sleep")
		if err != nil {
			return ""
		}
		return path
	}()

	// bashLocation finds the path of the bash executable
	bashLocation = func() string {
		path, err := exec.LookPath("bash")
		if err != nil {
			return ""
		}
		return path
	}()

	defaultMinDurationFilter = 100 * time.Millisecond
	zeroDurationFilter       = time.Duration(0)
)

type testProcess struct {
	cmd     *exec.Cmd
	pid     int
	stopped bool
}

func (p *testProcess) stop() {
	if p.stopped {
		return
	}
	p.stopped = true
	if p.cmd != nil && p.cmd.Process != nil {
		p.cmd.Process.Kill()
	}
}

type testCase struct {
	name              string
	envVarsForExec    map[string]string
	envVarsToAssert   map[string]string
	exePath           string
	args              []string
	shouldDetect      bool
	expectedEvents    []ProcessEventType
	minDurationFilter *time.Duration
	// whether to assert the events arrived in the order defined in expectedEvents.
	eventsNotInOrder bool

	skipTest func(t *testing.T) bool
}

func TestDetector(t *testing.T) {
	testDir := t.TempDir()

	// Create a test file that will be opened by processes
	testFile := filepath.Join(testDir, "test.txt")
	err := os.WriteFile(testFile, []byte("test"), 0o644)
	require.NoError(t, err)

	// Create a second test file for the multi-file test
	testFile2 := filepath.Join(testDir, "test2.txt")
	err = os.WriteFile(testFile2, []byte("test2"), 0o644)
	require.NoError(t, err)
	defer os.Remove(testFile2)

	currentDir, err := os.Getwd()
	require.NoError(t, err)

	// require bash on the machine to simplify symlinks handling in the tests.
	// on alpine multiple paths are pointing to the same busybox executable
	require.NotEmpty(t, bashLocation, "bash must be installed for the test")

	testCases := []testCase{
		{
			name:           "basic process",
			envVarsForExec: map[string]string{"USER_ENV": "value"},
			exePath:        sleepLocation,
			args:           []string{"1"},
			shouldDetect:   true,
			expectedEvents: []ProcessEventType{
				ProcessExecEvent,
				ProcessExitEvent,
			},
		},
		{
			name:           "multiple file opens by Go program",
			envVarsForExec: map[string]string{"USER_ENV": "value"},
			exePath:        filepath.Join(testDir, "file_open"),
			args:           []string{testFile, testFile2},
			shouldDetect:   true,
			expectedEvents: []ProcessEventType{
				ProcessExecEvent,
				ProcessFileOpenEvent,
				ProcessFileOpenEvent,
				ProcessExitEvent,
			},
		},
		{
			name:           "multiple file opens by C program",
			envVarsForExec: map[string]string{"USER_ENV": "value"},
			exePath:        filepath.Join(currentDir, "test/bin/file_open"),
			args:           []string{testFile, testFile2},
			shouldDetect:   true,
			expectedEvents: []ProcessEventType{
				ProcessExecEvent,
				ProcessFileOpenEvent,
				ProcessFileOpenEvent,
				ProcessExitEvent,
			},
		},
		{
			name:            "process with a lot of environment variables and user env var",
			envVarsForExec:  bigEnvVarsMapWithUserVal,
			envVarsToAssert: map[string]string{"USER_ENV": "value"},
			exePath:         sleepLocation,
			args:            []string{"1"},
			shouldDetect:    true,
			expectedEvents: []ProcessEventType{
				ProcessExecEvent,
				ProcessExitEvent,
			},
		},
		{
			name:           "process with a lot of environment variables without user env var",
			envVarsForExec: bigEnvVarsMapWithoutUserVal,
			exePath:        sleepLocation,
			args:           []string{"1"},
			shouldDetect:   false, // Should be filtered out by environment variable filter
		},
		{
			name:           "short lived process with duration filter",
			envVarsForExec: map[string]string{"USER_ENV": "value"},
			exePath:        filepath.Join(testDir, "short_lived"),
			args:           []string{testFile},
			shouldDetect:   false, // Should be filtered out by duration filter
		},
		{
			name:              "short lived process with zero duration filter",
			envVarsForExec:    map[string]string{"USER_ENV": "value"},
			exePath:           filepath.Join(testDir, "short_lived"),
			args:              []string{testFile},
			shouldDetect:      true,
			minDurationFilter: &zeroDurationFilter,
			expectedEvents: []ProcessEventType{
				ProcessExecEvent,
				ProcessExitEvent,
			},
		},
		{
			name:           "filtered process by env prefix",
			envVarsForExec: map[string]string{},
			exePath:        sleepLocation,
			args:           []string{"1"},
			shouldDetect:   false, // should be filtered out in eBPF based on env prefix
		},
		{
			name:           "process executable is filtered",
			envVarsForExec: map[string]string{"USER_ENV": "value"},
			exePath:        bashLocation,
			args:           []string{"-c", "start=$SECONDS; while (( SECONDS - start < 1 )); do :; done"},
			shouldDetect:   false,
		},
		{
			name:           "bash script is filtered",
			envVarsForExec: map[string]string{"USER_ENV": "value"},
			exePath:        "test/script.sh",
			args:           []string{},
			shouldDetect:   false,
		},
		{
			name:              "non-leader thread exec is reported correctly",
			envVarsForExec:    map[string]string{"USER_ENV": "value"},
			exePath:           filepath.Join(currentDir, "test/bin/thread_exec"),
			args:              []string{},
			shouldDetect:      true,
			eventsNotInOrder:  true,
			minDurationFilter: &zeroDurationFilter,
			expectedEvents: []ProcessEventType{
				ProcessExecEvent, // initial exec of this binary
				ProcessExitEvent, // leader is killed by the kernel after the non-leader thread's execve
				ProcessExecEvent, // non-leader thread's exec succeeds — this binary in --child mode
				ProcessExitEvent, // process exits after sleep
			},
		},
		{
			name:              "non-leader thread fork child is detected",
			envVarsForExec:    map[string]string{"USER_ENV": "value"},
			exePath:           filepath.Join(currentDir, "test/bin/thread_fork"),
			args:              []string{},
			shouldDetect:      true,
			eventsNotInOrder:  true,
			minDurationFilter: &zeroDurationFilter,
			expectedEvents: []ProcessEventType{
				ProcessExecEvent, // initial exec of thread_fork
				ProcessForkEvent, // child created by the non-leader thread's fork
				ProcessExitEvent, // child exits
				ProcessExitEvent, // parent exits
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.skipTest != nil && tc.skipTest(t) {
				t.Skipf("Skipping test %s", tc.name)
			}
			events := make(chan ProcessEvent, 100)

			// Compile the test program if it's a Go program
			if strings.HasPrefix(tc.exePath, testDir) {
				cmd := exec.Command("go", "build", "-o", tc.exePath, "./test/go_processes/"+filepath.Base(tc.exePath)+"/main.go")
				err := cmd.Run()
				require.NoError(t, err)
				defer os.Remove(tc.exePath)
			}

			opts := []DetectorOption{
				WithExePathsToFilter(bashLocation),
				WithEnvironments("USER_ENV"),
				WithEnvPrefixFilter("USER_E"),
				WithFilesOpenTrigger(testFile, testFile2),
			}

			duration := defaultMinDurationFilter
			if tc.minDurationFilter != nil {
				duration = *tc.minDurationFilter
			}
			opts = append(opts, WithMinDuration(duration))

			d, err := NewDetector(events, opts...)
			require.NoError(t, err)

			// Create context for the detector
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			go func() {
				err := d.Run(ctx)
				require.NoError(t, err)
			}()

			// Give the detector time to start
			// this is required here for testing to avoid race condition in which
			// the target process performs relevant actions before the detector starts
			time.Sleep(500 * time.Millisecond)

			// Create and run the test process
			cmd := exec.Command(tc.exePath, tc.args...)
			cmd.Env = append(os.Environ(), envVarsToSlice(tc.envVarsForExec)...)

			// Capture stdout and stderr
			var stdout, stderr strings.Builder
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr

			err = cmd.Start()
			require.NoError(t, err)

			proc := &testProcess{
				cmd: cmd,
				pid: cmd.Process.Pid,
			}
			defer proc.stop()

			// Wait for the process to finish
			err = cmd.Wait()
			require.NoError(t, err)

			// Print stdout and stderr
			t.Logf("stdout: %s", stdout.String())
			t.Logf("stderr: %s", stderr.String())

			// Give the detector time to process events
			time.Sleep(100 * time.Millisecond)

			// Cancel the context to stop the detector
			cancel()

			// Collect all events
			var receivedEvents []ProcessEvent
			for event := range events {
				receivedEvents = append(receivedEvents, event)
			}

			if !tc.shouldDetect {
				assert.Empty(t, receivedEvents, "should not have detected any events")
				return
			}

			if tc.eventsNotInOrder {
				assertEventsNotInOrder(t, receivedEvents, tc)
			} else {
				assertEventsInOrder(t, receivedEvents, tc)
			}
		})
	}
}

func assertEventsNotInOrder(t *testing.T, receivedEvents []ProcessEvent, tc testCase) {
	// Verify we received the expected events
	if !assert.Len(t, receivedEvents, len(tc.expectedEvents), "unexpected number of events") {
		t.Logf("received events: %v\n", receivedEvents)
		return
	}

	expectedEventTypes := make(map[ProcessEventType]int)
	for _, eventType := range tc.expectedEvents {
		expectedEventTypes[eventType]++
	}

	for _, event := range receivedEvents {
		count, exists := expectedEventTypes[event.EventType]
		if !exists || count == 0 {
			assert.Failf(t, "unexpected event type: %s", event.EventType.String())
			continue
		}
		expectedEventTypes[event.EventType]--
		assertExecDetails(t, event, tc)
	}
}

func assertExecDetails(t *testing.T, event ProcessEvent, tc testCase) {
	if event.ExecDetails != nil {
		// use the resolved path if one is relevant to check the actual expected executable is reported
		expectedPath := tc.exePath
		resolved, err := filepath.EvalSymlinks(expectedPath)
		if err == nil {
			expectedPath = resolved
		}
		assert.Equal(t, expectedPath, event.ExecDetails.ExePath, "unexpected executable path")

		var envVarsToAssert map[string]string
		if len(tc.envVarsToAssert) > 0 {
			envVarsToAssert = tc.envVarsToAssert
		} else {
			envVarsToAssert = tc.envVarsForExec
		}

		if len(envVarsToAssert) > 0 {
			for k, v := range envVarsToAssert {
				assert.Equal(t, v, event.ExecDetails.Environments[k], "unexpected environment variable value")
			}
		}
	}
}

func assertEventsInOrder(t *testing.T, receivedEvents []ProcessEvent, tc testCase) {
	// Verify we received the expected events
	if !assert.Len(t, receivedEvents, len(tc.expectedEvents), "unexpected number of events") {
		t.Logf("received events: %v\n", receivedEvents)
		return
	}

	for i, event := range receivedEvents {
		assert.Equal(t, tc.expectedEvents[i].String(), event.EventType.String(), "unexpected event type for the event %d", i)
		assertExecDetails(t, event, tc)
	}
}

func TestDetectorInitialScan(t *testing.T) {
	testCases := []testCase{
		{
			name:           "initial scan - basic process with user env",
			envVarsForExec: map[string]string{"USER_ENV": "value"},
			exePath:        sleepLocation,
			args:           []string{"10"}, // Long sleep to keep process alive, we'll kill it before it exits
			shouldDetect:   true,
			expectedEvents: []ProcessEventType{
				ProcessExecEvent, // exec event for initial scan
				ProcessExitEvent, // exit event after the process ends
			},
		},
		{
			name:            "initial scan - process with many env vars and user env",
			envVarsForExec:  bigEnvVarsMapWithUserVal,
			envVarsToAssert: map[string]string{"USER_ENV": "value"},
			exePath:         sleepLocation,
			args:            []string{"10"},
			shouldDetect:    true,
			expectedEvents: []ProcessEventType{
				ProcessExecEvent,
				ProcessExitEvent,
			},
		},
		{
			name:           "initial scan - process with many env vars without user env",
			envVarsForExec: bigEnvVarsMapWithoutUserVal,
			exePath:        sleepLocation,
			args:           []string{"10"},
			shouldDetect:   false, // Should be filtered out by environment variable filter
		},
		{
			name:           "initial scan - process without any env vars",
			envVarsForExec: map[string]string{},
			exePath:        sleepLocation,
			args:           []string{"10"},
			shouldDetect:   false, // Should be filtered out by env prefix filter
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			events := make(chan ProcessEvent, 100)

			// Start the test process BEFORE the detector
			cmd := exec.Command(tc.exePath, tc.args...)
			cmd.Env = append(os.Environ(), envVarsToSlice(tc.envVarsForExec)...)

			// Capture stdout and stderr
			var stdout, stderr strings.Builder
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr

			err := cmd.Start()
			require.NoError(t, err)

			proc := &testProcess{
				cmd: cmd,
				pid: cmd.Process.Pid,
			}
			defer proc.stop()

			// Give the process time to start and potentially open files
			time.Sleep(100 * time.Millisecond)

			// Now start the detector - this should trigger the initial scan
			opts := []DetectorOption{
				WithMinDuration(100 * time.Millisecond),
				WithExePathsToFilter(bashLocation),
				WithEnvironments("USER_ENV"),
				WithEnvPrefixFilter("USER_E"),
			}

			d, err := NewDetector(events, opts...)
			require.NoError(t, err)

			// Create context for the detector
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()

			go func() {
				err := d.Run(ctx)
				require.NoError(t, err)
			}()

			// Give the detector time to complete initial scan and process events
			time.Sleep(1 * time.Second)
			proc.stop()

			// Give the detector time to process exit event
			time.Sleep(100 * time.Millisecond)

			// Cancel the context to stop the detector
			cancel()

			// Print stdout and stderr for debugging
			t.Logf("stdout: %s", stdout.String())
			t.Logf("stderr: %s", stderr.String())

			// Collect all events
			var receivedEvents []ProcessEvent
			for event := range events {
				receivedEvents = append(receivedEvents, event)
			}

			if !tc.shouldDetect {
				assert.Empty(t, receivedEvents, "should not have detected any events")
				return
			}

			assertEventsInOrder(t, receivedEvents, tc)
		})
	}
}

func TestSignalFork(t *testing.T) {
	currentDir, err := os.Getwd()
	require.NoError(t, err)

	signalForkBin := filepath.Join(currentDir, "test/bin/signal_fork")

	events := make(chan ProcessEvent, 100)

	// Start the target process BEFORE the detector.
	cmd := exec.Command(signalForkBin)
	cmd.Env = append(os.Environ(), "USER_ENV=value")

	stdout, err := cmd.StdoutPipe()
	require.NoError(t, err)

	var stderr strings.Builder
	cmd.Stderr = &stderr

	err = cmd.Start()
	require.NoError(t, err)
	defer func() {
		_ = cmd.Process.Signal(syscall.SIGTERM)
		_ = cmd.Wait()
	}()

	// Wait for the process to signal readiness.
	scanner := bufio.NewScanner(stdout)
	require.True(t, scanner.Scan(), "expected 'ready' line from signal_fork")
	require.Equal(t, "ready", scanner.Text())

	// Now start the detector — this triggers the initial scan and should pick up
	// the already-running signal_fork process.
	opts := []DetectorOption{
		WithMinDuration(0),
		WithExePathsToFilter(bashLocation),
		WithEnvironments("USER_ENV"),
		WithEnvPrefixFilter("USER_E"),
	}

	d, err := NewDetector(events, opts...)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	go func() {
		err := d.Run(ctx)
		require.NoError(t, err)
	}()

	// Collect the initial exec event from the initial scan.
	var execEvent ProcessEvent
	select {
	case execEvent = <-events:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for initial exec event")
	}
	assert.Equal(t, ProcessExecEvent.String(), execEvent.EventType.String(), "first event should be exec")
	assert.Equal(t, signalForkBin, execEvent.ExecDetails.ExePath)
	t.Logf("got exec event for pid %d\n", execEvent.PID)

	time.Sleep(time.Second)
	// Send SIGUSR1 to trigger a fork inside the target process.
	err = cmd.Process.Signal(syscall.SIGUSR1)
	require.NoError(t, err)

	// Collect fork event
	var forkEvent ProcessEvent
	select {
	case forkEvent = <-events:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting fork event")
	}
	assert.Equal(t, ProcessForkEvent.String(), forkEvent.EventType.String(), "second event should be fork")

	// Send SIGTERM to trigger exit inside the target process.
	err = cmd.Process.Signal(syscall.SIGTERM)
	require.NoError(t, err)

	// Collect exit event
	var exitEvent ProcessEvent
	select {
	case exitEvent = <-events:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for exit event")
	}
	assert.Equal(t, ProcessExitEvent.String(), exitEvent.EventType.String(), "third event should be exit")
}

func TestTrackProcessesBeforeRun(t *testing.T) {
	require.NotEmpty(t, sleepLocation, "sleep must be installed for the test")

	// start a process before starting the detector
	cmd := exec.Command(sleepLocation, "30")
	require.NoError(t, cmd.Start())
	proc := &testProcess{cmd: cmd, pid: cmd.Process.Pid}
	defer proc.stop()

	events := make(chan ProcessEvent, 100)
	d, err := NewDetector(events,
		// set no duration filter
		WithMinDuration(0),
		// our test process doesn't have this env var,
		// but we want to make sure TrackProcesses causes the detector to emit an exit event for the tracked pid
		// even if the process doesn't match the environment variable filters
		WithEnvPrefixFilter("USER_E"),
	)
	require.NoError(t, err)

	// the detector should handle TrackProcesses being called before Run
	require.NotPanics(t, func() {
		err := d.TrackProcesses([]int{proc.pid})
		require.NoError(t, err)
	}, "TrackProcesses should not panic when called before Run")

	// run the detector and kill the target process before it exits
	// we expect to receive an exit event
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	runDone := make(chan struct{})
	go func() {
		defer close(runDone)
		err := d.Run(ctx)
		require.NoError(t, err)
	}()

	time.Sleep(500 * time.Millisecond)
	proc.stop()

	var gotExit bool
	deadline := time.After(2 * time.Second)
collect:
	for {
		select {
		case e, ok := <-events:
			if !ok {
				break collect
			}
			if e.PID == proc.pid && e.EventType == ProcessExitEvent {
				gotExit = true
				break collect
			}
		case <-deadline:
			break collect
		}
	}

	cancel()
	<-runDone

	require.True(t, gotExit, "expected exit event for tracked pid %d registered before Run", proc.pid)
}

func envVarsToSlice(envVars map[string]string) []string {
	var result []string
	for k, v := range envVars {
		result = append(result, k+"="+v)
	}

	slices.Sort(result)
	return result
}

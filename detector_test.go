package detector

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// bigEnvVarsMapWithUserVal is a map with a lot of environment variables to test the detector's handling of a process
// with many environment variables.
var (
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
}

func TestDetector(t *testing.T) {
	testDir, err := os.MkdirTemp("", "detector-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(testDir)

	// Create a test file that will be opened by processes
	testFile := filepath.Join(testDir, "test.txt")
	err = os.WriteFile(testFile, []byte("test"), 0644)
	require.NoError(t, err)

	// Create a second test file for the multi-file test
	testFile2 := filepath.Join(testDir, "test2.txt")
	err = os.WriteFile(testFile2, []byte("test2"), 0644)
	require.NoError(t, err)
	defer os.Remove(testFile2)

	testCases := []testCase{
		{
			name:           "basic process",
			envVarsForExec: map[string]string{"USER_ENV": "value"},
			exePath:        "/usr/bin/sleep",
			args:           []string{"1"},
			shouldDetect:   true,
			expectedEvents: []ProcessEventType{
				ProcessExecEvent,
				ProcessExitEvent,
			},
		},
		{
			name:           "multiple file opens",
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
			name:            "process with a lot of environment variables and user env var",
			envVarsForExec:  bigEnvVarsMapWithUserVal,
			envVarsToAssert: map[string]string{"USER_ENV": "value"},
			exePath:         "/usr/bin/sleep",
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
			exePath:        "/usr/bin/sleep",
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
			exePath:        "/usr/bin/sleep",
			args:           []string{"1"},
			shouldDetect:   false, // should be filtered out in eBPF based on env prefix
		},
		{
			name:           "process executable is filtered",
			envVarsForExec: map[string]string{"USER_ENV": "value"},
			exePath:        "/usr/bin/bash",
			args:           []string{"-c", "start=$SECONDS; while (( SECONDS - start < 1 )); do :; done"},
			shouldDetect:   false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			events := make(chan ProcessEvent, 100)

			// Compile the test program if it's a Go program
			if strings.HasPrefix(tc.exePath, testDir) {
				cmd := exec.Command("go", "build", "-o", tc.exePath, "./test/go_processes/"+filepath.Base(tc.exePath)+"/main.go")
				err := cmd.Run()
				require.NoError(t, err)
				defer os.Remove(tc.exePath)
			}

			opts := []DetectorOption{
				WithExePathsToFilter("/usr/bin/bash"),
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

			// Verify we received the expected events
			if !assert.Equal(t, len(tc.expectedEvents), len(receivedEvents), "unexpected number of events") {
				t.Logf("received events: %v\n", receivedEvents)
				return
			}

			for i, event := range receivedEvents {
				assert.Equal(t, tc.expectedEvents[i].String(), event.EventType.String(), fmt.Sprintf("unexpected event type for the event %d", i))
				if event.ExecDetails != nil {
					assert.Equal(t, tc.exePath, event.ExecDetails.ExePath, "unexpected executable path")

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
		})
	}
}

func TestDetectorInitialScan(t *testing.T) {
	testCases := []testCase{
		{
			name:           "initial scan - basic process with user env",
			envVarsForExec: map[string]string{"USER_ENV": "value"},
			exePath:        "/usr/bin/sleep",
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
			exePath:         "/usr/bin/sleep",
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
			exePath:        "/usr/bin/sleep",
			args:           []string{"10"},
			shouldDetect:   false, // Should be filtered out by environment variable filter
		},
		{
			name:           "initial scan - process without any env vars",
			envVarsForExec: map[string]string{},
			exePath:        "/usr/bin/sleep",
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
				WithExePathsToFilter("/usr/bin/bash"),
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

			// Verify we received the expected events
			if !assert.Equal(t, len(tc.expectedEvents), len(receivedEvents), "unexpected number of events") {
				t.Logf("received events: %v\n", receivedEvents)
				return
			}

			for i, event := range receivedEvents {
				assert.Equal(t, tc.expectedEvents[i].String(), event.EventType.String(), fmt.Sprintf("unexpected event type for the event %d", i))
				if event.ExecDetails != nil {
					assert.Equal(t, tc.exePath, event.ExecDetails.ExePath, "unexpected executable path")

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
		})
	}
}

func envVarsToSlice(envVars map[string]string) []string {
	var result []string
	for k, v := range envVars {
		result = append(result, k+"="+v)
	}

	slices.Sort(result)
	return result
}

package detector

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	name           string
	envVars        map[string]string
	exePath        string
	args           []string
	shouldDetect   bool
	expectedEvents []ProcessEventType
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
			name:         "basic process",
			envVars:      map[string]string{"USER_ENV": "value"},
			exePath:      "/usr/bin/sleep",
			args:         []string{"1"},
			shouldDetect: true,
			expectedEvents: []ProcessEventType{
				ProcessExecEvent,
				ProcessExitEvent,
			},
		},
		{
			name:         "multiple file opens",
			envVars:      map[string]string{"USER_ENV": "value"},
			exePath:      filepath.Join(testDir, "file_open"),
			args:         []string{testFile, testFile2},
			shouldDetect: true,
			expectedEvents: []ProcessEventType{
				ProcessExecEvent,
				ProcessFileOpenEvent,
				ProcessFileOpenEvent,
				ProcessExitEvent,
			},
		},
		{
			name:         "short lived process",
			envVars:      map[string]string{"USER_ENV": "value"},
			exePath:      filepath.Join(testDir, "short_lived"),
			args:         []string{testFile},
			shouldDetect: false, // Should be filtered out by duration filter
		},
		{
			name:         "filtered process",
			envVars:      map[string]string{},
			exePath:      "/usr/bin/sleep",
			args:         []string{"1"},
			shouldDetect: false,
		},
		{
			name:         "process executable is filtered",
			envVars:      map[string]string{"USER_ENV": "value"},
			exePath:      "/usr/bin/bash",
			args:         []string{"-c", "echo hello"},
			shouldDetect: false,
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
				WithMinDuration(100 * time.Millisecond),
				WithExePathsToFilter("/usr/bin/bash"),
				WithEnvironments("USER_ENV"),
				WithEnvPrefixFilter("USER_"),
				WithFilesOpenTrigger(testFile, testFile2),
			}

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
			time.Sleep(100 * time.Millisecond)

			// Create and run the test process
			cmd := exec.Command(tc.exePath, tc.args...)
			cmd.Env = append(os.Environ(), envVarsToSlice(tc.envVars)...)

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
					if len(tc.envVars) > 0 {
						for k, v := range tc.envVars {
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
	return result
}

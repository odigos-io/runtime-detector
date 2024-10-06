package proc

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetPodIDContainerNameFromReader(t *testing.T) {
	tests := []struct {
		name             string
		input            string
		expectedPodUID   string
		expectedContainerName string
		expectError      bool
	}{
		{
			name:             "Valid log with pod and container",
			input:            "some/log/output/pods/pod1234/containers/my-cool-container-12/",
			expectedPodUID:   "pod1234",
			expectedContainerName: "my-cool-container-12",
			expectError:      false,
		},
		{
			name:             "Log with no pod info",
			input:            "some/log/output/without/pods/info",
			expectedPodUID:   "",
			expectedContainerName: "",
			expectError:      true,
		},
		{
			name:             "Log with pod but no container",
			input:            "some/log/output/pods/pod1234/no/containers/",
			expectedPodUID:   "",
			expectedContainerName: "",
			expectError:      true,
		},
		{
			name:             "Log with extra slashes in container info",
			input:            "docker/volumes/b78a9ca486ff58e62e860b6a247796230d80b6c7c4fa54e63854d7f99f4820ef/_data/lib/kubelet/pods/d7db6d70-28a3-41f1-a666-8cc5604e695d/containers/frontend/12775f2a",
			expectedPodUID:   "d7db6d70-28a3-41f1-a666-8cc5604e695d",
			expectedContainerName: "frontend",
			expectError:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := strings.NewReader(tt.input)
			podUID, containerName, err := getPodIDContainerNameFromReader(reader)

			if (err != nil) != tt.expectError {
				t.Errorf("expected error: %v, got: %v", tt.expectError, err)
			}
			if podUID != tt.expectedPodUID {
				t.Errorf("expected podUID: %s, got: %s", tt.expectedPodUID, podUID)
			}
			if containerName != tt.expectedContainerName {
				t.Errorf("expected containerName: %s, got: %s", tt.expectedContainerName, containerName)
			}
		})
	}
}

func BenchmarkGetPodIDContainerNameFromReader(b *testing.B) {
	input := "some/log/output/pods/pod1234/containers/container5678/some/other/data"

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		reader := strings.NewReader(input)
		_, _, _ = getPodIDContainerNameFromReader(reader)
	}
}

func TestGetCleanCmdLine(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Command with args",
			input:    "java\u0000-jar\u0000/app/frontend.jar\u0000",
			expected: "java -jar /app/frontend.jar",
		},
		{
			name:     "Command with no args",
			input:    "nginx\u0000",
			expected: "nginx",
		},
		{
			name:     "Command with args which contain spaces",
			input:    "python\u0000/app/script.py\u0000--arg1\u0000\"value 1\"\u0000--arg2\u0000value2\u0000",
			expected: "python /app/script.py --arg1 \"value 1\" --arg2 value2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output := getCleanCmdLine([]byte(tt.input))

			if output != tt.expected {
				t.Errorf("expected: %s, got: %s", tt.expected, output)
			}
		})
	}
}

func TestGetCmdlineNoExists(t *testing.T) {
	_, err := GetCmdline(999999999)
	assert.ErrorIs(t, err, ErrorProcessNotFound)
}
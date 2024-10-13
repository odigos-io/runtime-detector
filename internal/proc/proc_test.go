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

func TestParseEnvironments(t *testing.T) {
	tests := []struct {
		name          string
		input         string
		keys          map[string]struct{}
		expected      map[string]string
	}{
		{
			name:  "Basic valid input",
			input: "KEY1=value1\x00KEY2=value2\x00KEY3=value3\x00",
			keys: map[string]struct{}{
				"KEY1": {},
				"KEY2": {},
			},
			expected: map[string]string{
				"KEY1": "value1",
				"KEY2": "value2",
			},
		},
		{
			name:  "Key not in the map",
			input: "KEY1=value1\x00KEY2=value2\x00",
			keys: map[string]struct{}{
				"KEY3": {},
			},
			expected:      map[string]string{},
		},
		{
			name:          "Empty input",
			input:         "",
			keys:          map[string]struct{}{},
			expected:      map[string]string{},
		},
		{
			name: "Val with '='",
			input: "KEY1=value1\x00KEY2=value2\x00KEY3=value3\x00KEY4=value4=foo\x00",
			keys: map[string]struct{}{
				"KEY2": {},
				"KEY4": {},
			},
			expected: map[string]string{
				"KEY2": "value2",
				"KEY4": "value4=foo",
			},
		},
		{
			name: "Empty value",
			input: "KEY1=\x00KEY2=value2\x00",
			keys: map[string]struct{}{
				"KEY1": {},
				"KEY2": {},
			},
			expected: map[string]string{
				"KEY1": "",
				"KEY2": "value2",
			},
		},
	}

	compareEnvs := func(t *testing.T, expected, actual map[string]string) {
		if !assert.Equal(t, len(expected), len(actual)) {
			return
		}

		for k, v := range expected {
			assert.Equal(t, v, actual[k])
		}
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := strings.NewReader(string(tt.input))
			result, err := parseEnvironments(r, tt.keys)
			assert.NoError(t, err)

			compareEnvs(t, tt.expected, result)
		})
	}
}

func TestExtractNSInode(t *testing.T) {
	inode, err := extractNSInode("pid:[4026531835]")
	assert.NoError(t, err)
	assert.Equal(t, uint32(4026531835), inode)

	inode, err = extractNSInode("pid:[12]")
	assert.NoError(t, err)
	assert.Equal(t, uint32(12), inode)
}
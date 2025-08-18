package probe

import (
	"log/slog"
	"testing"

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

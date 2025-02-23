package probe

import (
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
)


func repeatedString(length int, s string) string {
	b := make([]byte, length * len(s))
	for i := range b {
		b[i] = s[i % len(s)]
	}
	return string(b)
}

func TestLoad(t *testing.T) {
	t.Run("load with empty env prefix", func(t *testing.T) {
		p := &Probe{
			logger: slog.Default(),
		}
		err := p.load(uint32(4026532561))
		defer p.Close()
		assert.NoError(t, err)
	})

	t.Run("load with env prefix", func(t *testing.T) {
		p := &Probe{
			logger: slog.Default(),
			envPrefixFilter: "TEST",
		}
		err := p.load(uint32(4026532561))
		defer p.Close()
		assert.NoError(t, err)

		m := p.c.Maps[envPrefixMapName]
		assert.NotNil(t, m)

		value := bpfEnvPrefixT{}
		err = m.Lookup(uint32(0), &value)
		assert.NoError(t, err)
		assert.Equal(t, uint64(len("TEST")), value.Len)

		prefixStr := make([]byte, len("TEST"))
		copy(prefixStr, value.Prefix[:])
		assert.Equal(t, []byte("TEST"), prefixStr)
	})

	t.Run("load with too long env prefix", func(t *testing.T) {
		p := &Probe{
			logger: slog.Default(),
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
		assert.NoError(t, err)
		defer p.Close()

		pids := []int{1, 2, 3, 4, 5}
		err = p.TrackPIDs(pids)
		assert.NoError(t, err)

		for _, pid := range pids {
			containerPID, err := p.GetContainerPID(pid)
			assert.NoError(t, err)
			assert.Equal(t, 0, containerPID)
		}
	})

	t.Run("load with too long file name", func(t *testing.T) {
		p := &Probe{
			logger: slog.Default(),
			openFilesToTrack: []string{repeatedString(129, "a")},
		}
		err := p.load(uint32(4026532561))
		defer p.Close()
		assert.ErrorContains(t, err, "filename is too long")
	})

	t.Run("load with too many file names", func(t *testing.T) {
		p := &Probe{
			logger: slog.Default(),
			openFilesToTrack: make([]string, 9),
		}
		err := p.load(uint32(4026532561))
		defer p.Close()
		assert.ErrorContains(t, err, "too many files to track")
	})

	t.Run("load with multiple file names", func(t *testing.T) {
		p := &Probe{
			logger: slog.Default(),
			openFilesToTrack: []string{"/var/file1.so", "/var/file2.so"},
		}
		err := p.load(uint32(4026532561))
		defer p.Close()
		assert.NoError(t, err)

		m := p.c.Maps[filenameMapName]
		assert.NotNil(t, m)

		for i, file := range p.openFilesToTrack {
			value := bpfFilenameT{}
			err = m.Lookup(uint32(i), &value)
			assert.NoError(t, err)
			assert.Equal(t, uint64(len(file)), value.Len)

			filename := make([]byte, len(file))
			copy(filename, value.Buf[:])
			assert.Equal(t, []byte(file), filename)
		}
	})
}

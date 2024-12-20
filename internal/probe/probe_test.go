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
}
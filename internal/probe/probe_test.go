package probe

import (
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLoad(t *testing.T) {
	p := &Probe{
		logger: slog.Default(),
	}

	err := p.load()
	defer p.close()
	assert.NoError(t, err)
}
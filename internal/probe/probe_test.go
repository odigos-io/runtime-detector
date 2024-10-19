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

	err := p.load(uint32(4026532561))
	defer p.Close()
	assert.NoError(t, err)
}
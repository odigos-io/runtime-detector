package lang

import (
	"log/slog"

	filter "github.com/odigos-io/runtime-detector/internal/process_filter"
)

type LangFilter struct {
	l *slog.Logger
}

func NewLangFilter(l *slog.Logger) filter.ProcessesFilter {
	return &LangFilter{
		l: l,
	}
}

func (lf *LangFilter) Add(pid int) {
	lf.l.Info("adding pid to lang filter", "pid", pid)
}

func (lf *LangFilter) Remove(pid int) {
	lf.l.Info("removing pid from lang filter", "pid", pid)
}

func (lf *LangFilter) Close() error {
	lf.l.Info("closing lang filter")
	return nil
}




package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/odigos-io/runtime-detector/internal/probe"
)

func newLogger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		AddSource: true,
		Level:    slog.LevelInfo,
	}))
}

func main() {
	l := newLogger()
	p := probe.New(l)

	defer func() {
		err := p.Close()
		if err != nil {
			l.Error("failed to close probe", "error", err)
		}
	}()

	err := p.Load()
	if err != nil {
		l.Error("failed to load probe", "error", err)
		return
	}

	err = p.Attach()
	if err != nil {
		l.Error("failed to attach probe", "error", err)
		return
	}

	l.Info("probe attached")

	ctx, cancel := context.WithCancel(context.Background())
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	defer func() {
		signal.Stop(ch)
		cancel()
	}()
	go func() {
		select {
		case <-ch:
			cancel()
		case <-ctx.Done():
		}
	}()

	go p.Run(ctx)

	<-ctx.Done()
}
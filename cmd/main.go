package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	detector "github.com/odigos-io/runtime-detector"
)

func newLogger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		AddSource: true,
		Level:     slog.LevelInfo,
	}))
}

func main() {
	ctx := context.Background()
	l := newLogger()
	opts := []detector.DetectorOption{
		detector.WithLogger(l),
		detector.WithEnvironments("NODE_OPTIONS", "PYTHONPATH", "NODE_VERSION", "PYTHON_VERSION", "JAVA_VERSION", "ODIGOS_POD_NAME", "ODIGOS_CONTAINER_NAME", "ODIGOS_WORKLOAD_NAMESPACE"),
	}

	details := make(chan *detector.Details)
	done := make(chan struct{})
	go func() {
		for d := range details {
			l.Info("detected new process",
				"pid", d.ProcessID,
				"cmd", d.CmdLine,
				"exeName", d.ExeName,
				"exeLink", d.ExeLink,
				"envs", d.Environments,
				"container PID", d.ContainerProcessID,
			)
		}
		close(done)
	}()
	defer close(details)

	d, err := detector.NewDetector(ctx, details, opts...)
	if err != nil {
		l.Error("failed to create detector", "error", err)
		os.Exit(1)
	}
	defer d.Stop()

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

	go d.Run(ctx)

	<-ctx.Done()
	<-done
}

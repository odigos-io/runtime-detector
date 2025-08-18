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
		Level:     slog.LevelInfo,
	}))
}

func main() {
	ctx := context.Background()
	l := newLogger()
	opts := []detector.DetectorOption{
		detector.WithLogger(l),
		detector.WithEnvironments("NODE_OPTIONS", "PYTHONPATH", "NODE_VERSION", "PYTHON_VERSION", "JAVA_VERSION", "ODIGOS_POD_NAME", "ODIGOS_CONTAINER_NAME", "ODIGOS_WORKLOAD_NAMESPACE"),
		detector.WithEnvPrefixFilter("ODIGOS_POD_NAME"),
		detector.WithExePathsToFilter(
			"/usr/bin/bash",
			"/usr/local/sbin/bash",
			"/usr/local/bin/bash",
			"/bin/bash",
			"/bin/sh",
			"/usr/sbin/bash",
			"/usr/bin/sh",
			"/bin/busybox",
			"/usr/bin/dash",
		),
	}

	procFS, ok := os.LookupEnv("HOST_PROCFS")
	if ok && procFS != "" {
		opts = append(opts, detector.WithProcFSPath(procFS))
	}

	details := make(chan detector.ProcessEvent)
	done := make(chan struct{})
	go func() {
		for d := range details {
			switch d.EventType {
			case detector.ProcessExecEvent, detector.ProcessFileOpenEvent, detector.ProcessForkEvent:
				l.Info("detected new process",
					"eventType", d.EventType.String(),
					"pid", d.PID,
					"cmd", d.ExecDetails.CmdLine,
					"exePath", d.ExecDetails.ExePath,
					"exeLink", d.ExecDetails.ExeLink,
					"envs", d.ExecDetails.Environments,
					"container PID", d.ExecDetails.ContainerProcessID,
				)
			case detector.ProcessExitEvent:
				l.Info("detected process exit",
					"pid", d.PID,
				)
			}
		}
		close(done)
	}()

	d, err := detector.NewDetector(details, opts...)
	if err != nil {
		l.Error("failed to create detector", "error", err)
		os.Exit(1)
	}

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

	if err := d.Run(ctx); err != nil {
		l.Error("detector failed", "error", err)
	}
	l.Info("detector stopped")

	// wait for the details channel to be closed
	<-done
	l.Info("exiting")
}

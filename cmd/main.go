package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	detector "github.com/odigos-io/runtime-detector"
)

const envProcFS = "PROC_FS_PATH"

func newLogger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		AddSource: true,
		Level:    slog.LevelInfo,
	}))
}

func startDummyHTTPServer(d *detector.Detector) {
	http.HandleFunc("POST /{podUID}/{containerName}", func(w http.ResponseWriter, r *http.Request) {
		podUID := r.PathValue("podUID")
		containerName := r.PathValue("containerName")
		d.TrackPodContainers(podUID, containerName)
		w.WriteHeader(http.StatusOK)
		response := fmt.Sprintf("Tracking pod %s container %s", podUID, containerName)
		w.Write([]byte(response))
	})
	go http.ListenAndServe(":8080", nil)
}

func main() {
	ctx := context.Background()
	l := newLogger()
	opts := []detector.DetectorOption{detector.WithLogger(l)}
	if p := os.Getenv(envProcFS); p != "" {
		opts = append(opts, detector.WithProcFSPath(p))
	}
	d, err := detector.NewDetector(ctx, opts...)
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
	startDummyHTTPServer(d)

	<-ctx.Done()
}
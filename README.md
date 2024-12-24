> ⚠️ **Note:**
> This is a WIP project

<p align="center">
    <a href="https://godoc.org/github.com/odigos-io/runtime-detector" target="_blank">
        <img src="https://godoc.org/github.com/odigos-io/runtime-detector?status.svg" alt="GoDoc" style="border: 1px solid #f39c12; border-radius: 4px; padding: 5px;">
    </a>
</p>

# runtime-detector

A Go library for getting notification for linux process events.
Using eBPF, events are reported with minimal overhead. A detector will reports all process creation and exit events which match the configured criteria.

```Go
import (
    ...

	detector "github.com/odigos-io/runtime-detector"
)


	l := newLogger()
	opts := []detector.DetectorOption{
		detector.WithLogger(l),
		detector.WithEnvironments("NODE_OPTIONS", "PYTHONPATH"),
		detector.WithEnvPrefixFilter("RELEVANT_PROC"),
	}

	details := make(chan detector.ProcessEvent)
	done := make(chan struct{})
	go func() {
		for d := range details {
			switch d.EventType {
			case detector.ProcessExecEvent:
				l.Info("detected new process",
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
        ...
	}

	if err := d.Run(ctx); err != nil {
        ...
	}
```

A `Detector` can be configured to filter reported processes based on various options:
- Processes with specific environment variable.
- Processes with specified minimum duration - to filter notifications for short lived processes.
- Filter processes executing a specific binary.

# Local testing and development

Under `cmd` is an example usage of the library which includes setting up a director, and listening for events it reports.
The example program will log each event.

To run the example in a `kind` cluster:

1. Create a kind cluster
```Bash
kind create cluster
```

2. Build an image containing the example program:
```Bash
docker build -t dev/runtime-detector:test .
```

3. Load the image to kind:
```Bash
kind load docker-image dev/runtime-detector:test
```

4. Create a daemonset running the example:
```Bash
kubectl apply -f daemonset.yaml
```

5. Add some services to the cluster, or edit current deployments.
Note that the example is currently configured to report process that have a `ODIGOS_POD_NAME` environment variable,
so consider adding this env var or editing the example code and re-build it.

6. Examine the logs of the `runtime-detector` pod.

**Note** This above steps are for running inside Kubernetes, however the library can be used and tested in VM/bare-metal setups as well.
This can be done by building the example program and running it inside a VM.



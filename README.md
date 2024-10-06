> ⚠️ **Note:**
> This is a WIP project

### Basic testing:
```
kind create cluster --config=kind-config.yaml
docker build -t dev/runtime-detector:test .
kind load docker-image dev/runtime-detector:test
kubectl apply -f daemonset.yaml
```

Add some apps to the cluster

```
kubectl port-forward <runtime-detector pod> 8080:8080
```

Register to get notification for a pod, container tuple:
```
curl -X POST http://localhost:8080/<podUID>/<containerName>
```

Inspect the logs of the `runtime-detector` pod



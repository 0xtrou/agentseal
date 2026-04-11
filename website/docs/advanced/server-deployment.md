---
sidebar_position: 3
---

# Server Deployment

`snapfzz-seal-server` is an HTTP server that wraps the compile and sandbox-dispatch workflow. It is an early-stage component. The API surface is minimal, there is no built-in authentication, and job state is held in memory with no persistence. Review the limitations section before planning a production deployment.

## What the server provides

The server exposes five HTTP endpoints under the `axum` framework:

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/v1/compile` | Start an async compile job |
| `POST` | `/api/v1/dispatch` | Dispatch a ready job to a Docker sandbox |
| `GET` | `/api/v1/jobs/{job_id}` | Poll job status |
| `GET` | `/api/v1/jobs/{job_id}/results` | Retrieve execution results |
| `GET` | `/health` | Liveness probe |

Job state (`pending`, `compiling`, `ready`, `dispatched`, `running`, `completed`, `failed`) is tracked in an in-memory `RwLock`-protected `HashMap`. All state is lost on process restart.

The only sandbox backend is `DockerBackend`. It requires a Docker daemon accessible from the server process.

## Starting the server

```bash
snapfzz-seal-server \
  --bind 127.0.0.1:9090 \
  --compile-dir /var/lib/snapfzz-seal/compile \
  --output-dir /var/lib/snapfzz-seal/output
```

Both directories are created automatically on startup if they do not exist. Default values if flags are omitted:

- `--bind`: `127.0.0.1:9090`
- `--compile-dir`: `./.snapfzz-seal/compile`
- `--output-dir`: `./.snapfzz-seal/output`

Logging is controlled via `RUST_LOG`. Set `RUST_LOG=info` for standard operational output.

```bash
export RUST_LOG=info
snapfzz-seal-server --bind 127.0.0.1:9090 \
  --compile-dir /var/lib/snapfzz-seal/compile \
  --output-dir /var/lib/snapfzz-seal/output
```

The server handles `SIGTERM` and `Ctrl-C` with graceful shutdown.

## API usage

### Compile a project

`POST /api/v1/compile`

```json
{
  "project_dir": "/var/lib/snapfzz-seal/compile/my-agent",
  "user_fingerprint": "<64-hex string>",
  "sandbox_fingerprint": "auto"
}
```

The `project_dir` must be a path within the configured `--compile-dir`. The server rejects paths that resolve outside that boundary. Returns HTTP 202 with a `job_id`:

```json
{
  "job_id": "seal-<timestamp>-<random>",
  "status": "pending"
}
```

Compilation runs asynchronously in a `tokio::task::spawn_blocking` call.

### Poll job status

`GET /api/v1/jobs/{job_id}`

Returns the full `JobStatus` object including `status`, `output_path`, `error`, timestamps, and `sandbox_id` if dispatched. Returns 404 if the job ID is not found.

### Dispatch to sandbox

`POST /api/v1/dispatch`

The job must be in `ready` state. The dispatch request specifies the Docker image and sandbox parameters:

```json
{
  "job_id": "<job_id>",
  "sandbox": {
    "image": "ubuntu:22.04",
    "timeout_secs": 300,
    "memory_mb": 512,
    "env": [["KEY", "value"]]
  }
}
```

The server:
1. Provisions a Docker container from the specified image.
2. Copies the sealed artifact into the container at `/tmp/snapfzz-sealed`.
3. Runs `chmod +x /tmp/snapfzz-sealed && /tmp/snapfzz-sealed`.
4. Destroys the container after execution completes or fails.

The Docker container is run with hardened flags by default: `--security-opt no-new-privileges:true`, `--cap-drop ALL`, `--read-only`, `--tmpfs /tmp`, and `--pids-limit 64`.

### Retrieve results

`GET /api/v1/jobs/{job_id}/results`

Returns the `JobResultResponse` including `status` and `result` (an `ExecutionResult` with `exit_code`, `stdout`, `stderr`), or null if the job has not completed.

## systemd unit

```ini
[Unit]
Description=Snapfzz Seal Server
After=network.target docker.service
Requires=docker.service

[Service]
User=snapfzz
Group=snapfzz
ExecStart=/usr/local/bin/snapfzz-seal-server \
  --bind 127.0.0.1:9090 \
  --compile-dir /var/lib/snapfzz-seal/compile \
  --output-dir /var/lib/snapfzz-seal/output
Environment=RUST_LOG=info
Restart=on-failure
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/snapfzz-seal

[Install]
WantedBy=multi-user.target
```

The `snapfzz` user needs access to the Docker socket to provision containers. Either add the user to the `docker` group, or configure socket-level authorization through a Docker proxy.

## Network topology recommendation

The server API has no authentication layer. It must not be exposed directly to untrusted networks:

```
operator/CI client
  -> authenticated gateway (mTLS or OIDC-aware proxy)
  -> internal reverse proxy (TLS termination)
  -> snapfzz-seal-server (127.0.0.1:9090, private network only)
  -> Docker daemon (unix socket or private TCP)
```

TLS termination and client identity validation must be handled at the gateway layer. The server does not implement TLS, token validation, or RBAC.

## Directory controls

- `--compile-dir` holds project source trees submitted to the compile endpoint. The server validates that all `project_dir` values in compile requests resolve to paths within this directory.
- `--output-dir` holds sealed artifact files produced by successful compile jobs. Each job writes a file named `<job_id>.sealed`.
- Both directories should be owned by the service user and not world-readable.
- Artifact retention must be managed externally. The server does not delete job outputs or expired job state.

## Monitoring

The server emits structured `tracing` spans and events. With `RUST_LOG=info`, expected log output includes:
- Resolved compile fingerprint mode per job.
- Compilation success or failure per job.
- Sandbox provision, copy, exec, and destroy outcomes.

Track job transition rates to `failed` state as the primary signal for operational health. The `/health` endpoint returns 200 while the process is running and can be used as a liveness probe. There is no readiness probe that validates Docker connectivity.

## Limitations

- **No authentication.** All endpoints are unauthenticated. Deploy behind a gateway that enforces client identity before the server receives any request.
- **No persistence.** Job state is in-memory. All jobs are lost on restart.
- **No artifact cleanup.** Compiled artifacts in `--output-dir` accumulate indefinitely.
- **Single sandbox backend.** Only `DockerBackend` is implemented. Alternative container runtimes and VM-based backends must be implemented by the operator.
- **No multi-tenancy.** Job namespacing, per-tenant quotas, and isolation are not implemented.
- **No RBAC.** There is no role separation between compile operations, dispatch operations, and result retrieval.
- **Linux-only execution.** The sealed launcher inside dispatched artifacts requires Linux. Docker containers must use a Linux base image on a Linux Docker host.

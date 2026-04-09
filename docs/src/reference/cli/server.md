# seal server

Start the orchestration API server.

## Usage

```text
seal server [OPTIONS]
```

## Options

| Option | Description |
|--------|-------------|
| `--bind <ADDR>` | Listen address [default: 127.0.0.1:9090] |
| `--compile-dir <PATH>` | Directory for compile artifacts |
| `--output-dir <PATH>` | Directory for output binaries |

## API Routes

| Method | Route | Description |
|--------|-------|-------------|
| GET | `/health` | Health check with job count |
| POST | `/api/v1/compile` | Submit a compile job |
| POST | `/api/v1/dispatch` | Dispatch to sandbox |
| GET | `/api/v1/jobs/{job_id}` | Get job status |
| GET | `/api/v1/jobs/{job_id}/results` | Get execution results |

> ⚠️ **Security Warning:** The API is unauthenticated. Bind to `127.0.0.1` only. Never expose without an auth proxy.

## Job Lifecycle

```text
pending → compiling → ready → dispatched → running → completed
                                              ↘ failed
```

## Compile Job

```bash
curl -X POST http://127.0.0.1:9090/api/v1/compile \
  -H 'Content-Type: application/json' \
  -d '{
    "project_dir": "./my-agent",
    "user_fingerprint": "...",
    "sandbox_fingerprint": "..."
  }'
```

## Dispatch Job

```bash
curl -X POST http://127.0.0.1:9090/api/v1/dispatch \
  -H 'Content-Type: application/json' \
  -d '{
    "job_id": "job-...",
    "sandbox": {
      "image": "python:3.11-slim",
      "timeout_secs": 120
    }
  }'
```

## Get Results

```bash
curl http://127.0.0.1:9090/api/v1/jobs/job-.../results
```

## See Also

- [Server Deployment](../../advanced/server-deployment.md) — Production setup
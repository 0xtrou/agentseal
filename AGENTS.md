# Agent Guidelines

## E2E Testing

This project targets Linux only. All E2E tests must be run inside Docker containers.

**Do NOT run `e2e-tests/run_tests.sh` directly on the host machine.** The test script expects Linux paths (`/app/examples/`, `/usr/local/bin/seal-launcher`) and Linux-specific runtime behavior (memfd_create, seccomp).

### Running E2E Tests

```bash
docker compose -f e2e-tests/docker-compose.yml up --build --abort-on-container-exit
```

To pass environment variables (e.g., API keys):

```bash
SNAPFZZ_SEAL_API_KEY=xxx SNAPFZZ_SEAL_API_BASE=https://... docker compose -f e2e-tests/docker-compose.yml up --build --abort-on-container-exit
```

### What the E2E tests cover

1. **Key generation** — `seal keygen`
2. **Compilation** — `seal compile` with pyinstaller, nuitka, and go backends
3. **Signing** — `seal sign` with builder secret key
4. **Verification** — `seal verify` with builder public key
5. **Launch** — `seal launch` executes the sealed agent and checks output

### Debugging test failures

- If compilation fails, check the Dockerfile has the right dependencies installed
- If launch fails with "fingerprint mismatch", the container environment changed between compile and launch steps
- To get a shell in the test container: `docker compose -f e2e-tests/docker-compose.yml run --entrypoint bash e2e-test`

## Development on macOS

- `cargo build`, `cargo check`, `cargo clippy` work on macOS for development
- Runtime/launch features will not work on macOS (Linux syscalls)
- Always validate changes via the Docker-based E2E tests before considering them complete

# Snapfzz Seal

Encrypted sandbox-bound agent delivery system. Compiles Python/Go agents into sealed, signed binaries that are fingerprint-locked to a specific user and host.

## Project Structure

- `crates/snapfzz-seal` — CLI entrypoint (`seal` binary)
- `crates/snapfzz-seal-compiler` — compilation backends (pyinstaller, nuitka, go)
- `crates/snapfzz-seal-launcher` — runtime launcher (memfd_exec, seccomp, temp_exec)
- `crates/snapfzz-seal-core` — shared crypto, envelope, fingerprint types
- `crates/snapfzz-seal-fingerprint` — host fingerprint collection
- `crates/snapfzz-seal-server` — orchestration server with auth
- `examples/` — sample agents (chat_agent, demo_agent, go_agent)
- `e2e-tests/` — Dockerfile, docker-compose, test scripts

## Platform

This project targets **Linux only**. The launcher uses Linux-specific syscalls (memfd_create, seccomp). macOS is used for development (cargo build/check/clippy) but all runtime testing must happen inside Linux containers.

## Building

```bash
# Dev build (macOS ok for compilation checks)
cargo build

# Release build
BUILD_ID=some-id cargo build --release
```

## Running E2E Tests

E2E tests **must** run inside Docker (Linux container). Never run them directly on macOS.

```bash
# Run all e2e tests
docker compose -f e2e-tests/docker-compose.yml up --build --abort-on-container-exit

# With API key for live LLM testing
SNAPFZZ_SEAL_API_KEY=xxx docker compose -f e2e-tests/docker-compose.yml up --build --abort-on-container-exit

# Build the test image only
docker compose -f e2e-tests/docker-compose.yml build
```

The Docker image builds the Rust binaries (`seal`, `seal-launcher`) in a multi-stage build, installs Python (pyinstaller, nuitka) and Go, then runs `e2e-tests/run_tests.sh` which tests all three compilation backends: pyinstaller, nuitka, and go.

## Coding Conventions

- Workspace uses Rust 2024 edition (resolver = "3")
- `unsafe_code = "deny"` in workspace lints
- Clippy all warnings enabled
- Release builds: LTO + strip + single codegen unit

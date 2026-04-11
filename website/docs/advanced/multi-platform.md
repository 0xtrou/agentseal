---
sidebar_position: 2
---

# Multi-Platform Support

This page describes what is and is not supported on each platform. The short summary: **compilation works on Linux and macOS; secure execution (launch) is Linux-only; Windows is not supported**.

## Platform matrix

| Capability | Linux | macOS | Windows |
|---|---|---|---|
| Compile (Go backend) | Yes | Yes | No |
| Compile (PyInstaller backend) | Yes | Yes | No |
| Compile (Nuitka backend, onefile) | Yes | No (see below) | No |
| Launch / execute sealed binary | Yes | No | No |
| seccomp syscall filter | Yes | No | No |
| memfd in-memory execution | Yes | No | No |
| Anti-debug (`prctl`, `ptrace TRACEME`) | Yes | Partial (PT_DENY_ATTACH only) | No |

## Compilation

### Go backend

The Go backend always sets `GOOS=linux` and `CGO_ENABLED=0` regardless of the host OS. A Go toolchain must be available on `PATH`. `GOARCH` defaults to `amd64` unless the host is `aarch64` (in which case it uses `arm64`) or the `GOARCH` environment variable is set explicitly. Compilation on macOS produces a Linux binary because the cross-compilation target is fixed.

### PyInstaller backend

PyInstaller must be installed on the build host. The backend invokes `pyinstaller --onefile` and requires `main.py` in the project directory. PyInstaller produces a host-platform binary, so compiling on macOS will produce a macOS binary. For production use, PyInstaller compilation should be performed on Linux to produce a Linux-compatible sealed artifact.

### Nuitka backend

Nuitka `--onefile` mode is not supported on macOS. Nuitka's onefile packaging on macOS relies on mechanisms that are incompatible with how the launcher attaches and strips payloads. If you run `seal compile --backend nuitka` on macOS, compilation may appear to succeed but the resulting artifact will not launch correctly. Nuitka compilation should be done on Linux.

Nuitka detects its own binary using `PATH` and falls back to `python3 -m nuitka` if a standalone `nuitka` binary is not found.

### Compiler CLI

```bash
# Build the compiler and launcher for a Linux target from any host
cargo build --release -p snapfzz-seal-compiler
cargo build --release -p snapfzz-seal-launcher --target x86_64-unknown-linux-musl

# Compile a Go agent project
seal compile \
  --project ./my-agent \
  --backend go \
  --user-fingerprint "$USER_FP" \
  --sandbox-fingerprint auto \
  --output ./my-agent.sealed \
  --launcher ./target/x86_64-unknown-linux-musl/release/snapfzz-seal-launcher
```

The `--sandbox-fingerprint auto` option collects the stable fingerprint from the current environment. When compiling on a different machine than the target execution environment, supply the target sandbox's stable fingerprint hash as a hex string instead.

### Cross-compiling the launcher

The launcher binary is embedded into the sealed artifact at compile time. It must be built for the target execution platform (Linux). Cross-compile it explicitly when building on macOS:

```bash
rustup target add x86_64-unknown-linux-musl
cargo build --release -p snapfzz-seal-launcher --target x86_64-unknown-linux-musl
```

Then pass the resulting binary with `--launcher ./target/x86_64-unknown-linux-musl/release/snapfzz-seal-launcher`.

## Execution (launch)

The launcher uses Linux-specific kernel interfaces and cannot run on macOS or Windows. There is no fallback execution path for non-Linux platforms.

### Execution dispatch by backend type

Once the sealed binary is decrypted, the launcher selects an execution path based on the `BackendType` recorded in the payload footer:

| Backend type | Execution path |
|---|---|
| `Go` | `MemfdExecutor` — writes the binary to a `memfd_create` anonymous in-memory file, seals it, then execs it. The binary never appears on the filesystem. |
| `PyInstaller`, `Nuitka` | `TempFileExecutor` — writes the binary to a temporary file on the filesystem, sets the execute bit, execs it, and unlinks the file when the handle is dropped. |
| `Unknown` | Attempts `MemfdExecutor` first; if that fails, falls back to `TempFileExecutor` with a logged warning. |

#### memfd execution (Go backend)

`memfd_create` is a Linux-only syscall (kernel 3.17+). The executor:

1. Creates an anonymous in-memory file descriptor with `MFD_CLOEXEC | MFD_ALLOW_SEALING`.
2. Writes the decrypted binary in chunks.
3. Applies `F_SEAL_WRITE | F_SEAL_SHRINK | F_SEAL_GROW` to make the file immutable.
4. Execs the file descriptor via `/proc/self/fd/<n>`.

This path is preferred for Go binaries because they produce a single static ELF with no external shared-library dependencies, which is compatible with the sealed memfd exec model.

#### TempFile execution (PyInstaller and Nuitka backends)

PyInstaller and Nuitka onefile binaries self-extract at startup and require filesystem access. The `TempFileExecutor`:

1. Writes the binary to a randomly named file in `/tmp`.
2. Sets mode `0o700` via `fchmod`.
3. Forks and execs the temp file.
4. Unlinks the temp file from the `InteractiveHandle` drop implementation.

The temp file is deleted after exec, but the binary image persists in memory as long as the process runs. This provides weaker filesystem-level secrecy than memfd execution.

### Runtime protections (Linux)

On Linux, `apply_protections()` applies:

- `prctl(PR_SET_DUMPABLE, 0)` — prevents core dumps and `/proc/<pid>/mem` access by unprivileged processes.
- `ptrace(PTRACE_TRACEME)` — pre-empts tracer attachment; a process that has called TRACEME cannot be attached by a second tracer.

On macOS, `apply_protections()` applies:

- `ptrace(PT_DENY_ATTACH, ...)` — signals to the kernel that the process should not be attached to by a debugger.
- `setrlimit(RLIMIT_CORE, 0)` — disables core dumps.

Neither of these macOS protections is enforced by the kernel in all scenarios. They are best-effort hints, not enforcement boundaries. The seccomp syscall filter is Linux-only and is not applied on macOS.

## Verification

When testing a new platform configuration:

1. Run CLI smoke tests: `snapfzz-seal-compiler --help`, `seal keygen`, `seal verify`.
2. Compile a representative project with each backend and inspect the artifact.
3. On a Linux target, launch the sealed binary and confirm successful decryption and execution.
4. Confirm that tampered binaries (modified after sealing) are rejected at launch.
5. Confirm that fingerprint mismatch (wrong environment) produces the expected error at launch.

## Limitations

- The launcher is Linux-only. There is no supported path for running sealed artifacts on macOS or Windows.
- Nuitka `--onefile` on macOS is not supported at the compilation stage. Use Linux for Nuitka builds.
- PyInstaller builds on macOS produce macOS binaries; they must be recompiled on Linux for production.
- The `memfd` execution path requires Linux kernel 3.17 or later.
- Cross-platform build success does not imply equivalent runtime security. Platform parity must not be assumed.

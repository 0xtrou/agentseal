# Compatibility

This section summarizes current platform support and feature availability across compilation and execution paths.

## Summary

- **Compilation** (`seal compile`): Linux and macOS are supported for all backends, with one known exception — Nuitka `--onefile` fails on macOS. Windows is not supported.
- **Execution / launch** (`seal launch`): Linux only. The launcher depends on Linux-specific kernel interfaces (`memfd_create`, `execveat`, seccomp BPF, `/proc`, `/dev/shm`). macOS and Windows are not supported.

## Compilation platform matrix

| Backend | Linux | macOS | Windows |
|---|---|---|---|
| Nuitka | Supported | **Fails in `--onefile` mode** (Homebrew dylib issue) | Not supported |
| PyInstaller | Supported | Supported | Not supported |
| Go | Supported | Supported (cross-compiles to Linux via `GOOS=linux`) | Not supported |

All backends always produce a **Linux** target binary, regardless of the compilation host. The Go backend cross-compiles unconditionally (`GOOS=linux`, `CGO_ENABLED=0`). PyInstaller and Nuitka produce Linux ELF binaries only when run on a Linux host; running them on macOS produces macOS binaries, which cannot be executed by the launcher.

:::note

For PyInstaller and Nuitka, compilation must be performed on a **Linux** host if the intent is to produce a binary that will run under `seal launch`. macOS compilation of these backends produces a macOS-native bundle, not a Linux ELF.

:::

## Execution / launch platform matrix

| Platform | `seal launch` | In-memory execution (`memfd`) | Temp-file execution | seccomp filter | Anti-debug |
|---|---|---|---|---|---|
| Linux x86_64 | Supported | Supported (Go backend) | Supported (Python backends) | Enforced | Active |
| macOS | Not supported | Not supported | Not supported | No-op | Not active |
| Windows | Not supported | Not supported | Not supported | No-op | Not active |

The launcher calls `memfd_create` and `execveat` (for Go payloads) and `/dev/shm` with `fork`/`exec` (for Python payloads). These are Linux kernel interfaces with no equivalent on macOS or Windows.

## Feature availability by platform

| Capability | Linux | macOS | Windows |
|---|---|---|---|
| Signature verification | Yes | Yes | Yes |
| Payload header validation | Yes | Yes | Yes |
| Launcher tamper verification | Yes | No | No |
| seccomp BPF filter enforcement | Yes | No (no-op) | No (no-op) |
| `memfd_create` / `execveat` execution | Yes | No | No |
| Temp-file execution (`/dev/shm`) | Yes | No | No |
| Anti-debug checks | Yes | No | No |
| Linux namespace-derived fingerprint signals | Yes | No | No |
| Docker sandbox backend (server) | Yes | Yes (host only; agent runs in Linux container) | Yes (host only; agent runs in Linux container) |

## Compile backend detection heuristics

| Backend | Detection condition |
|---|---|
| Nuitka | `main.py` or `setup.py` present in project root |
| PyInstaller | `main.py` present in project root |
| Go | `go.mod` present in project root |

## Operational recommendations

- Use a Linux host for all production compilation involving Nuitka or PyInstaller.
- macOS is suitable for Go compilation (cross-compiles to Linux) and development workflows.
- All production launch paths require Linux. Treat any non-Linux deployment as unsupported.
- Validate backend toolchain availability in CI before generating release artifacts.
- seccomp and anti-debug hardening are active only on Linux. Do not rely on these controls when testing on macOS.

## Verification commands

```bash
# Identify host
uname -a

# Confirm CLI availability
seal --version
seal compile --help
seal launch --help

# Inspect runtime logs
RUST_LOG=info seal launch --payload ./agent.sealed --user-fingerprint "$USER_FP"
```

## Security considerations

- Security guarantees are platform-scoped, not platform-agnostic.
- seccomp BPF filtering, anti-debug detection, `memfd` execution, and `/dev/shm` temp-file execution all depend on Linux kernel interfaces and provide no protection on other platforms.
- Production policy should explicitly restrict deployment targets to Linux x86_64.

## Limitations

- A formal long-term support matrix by OS version is not currently published.
- Compatibility assertions outside tested CI environments should be treated as provisional until validated in local threat modeling.
- The launcher has only been tested and validated for Linux x86_64; other Linux architectures (e.g., arm64) are not currently supported for execution.

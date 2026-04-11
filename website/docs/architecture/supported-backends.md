---
sidebar_position: 4
---

# Supported Backends

Snapfzz Seal supports compilation backends for transforming agent source code into sealed executables.

## Backend overview

Backends are responsible for compiling agent source code into standalone executables that can be sealed and encrypted. The choice of backend affects:

- **Execution performance** — Native vs interpreted execution
- **Binary size** — Compiled size overhead
- **Dependency handling** — Static vs dynamic linking
- **Platform support** — Target OS and architecture

:::note[Compilation vs execution platform]

All three backends target **Linux** as the execution platform. Compilation (running `seal compile`) can happen on Linux or macOS, but the resulting sealed binary will only execute on Linux. Windows is not supported as a compilation or execution host.

:::

## Currently implemented backends

### PyInstaller backend

**Status**: Implemented

Compiles Python agents into standalone executables using PyInstaller's bundling mechanism.

**Compilation platform support**:
- Linux x86_64: supported
- macOS arm64, x86_64: supported
- Windows: not supported

**Execution platform**: Linux only

PyInstaller bundles produce an ELF executable that cannot be launched via `memfd_exec`. The launcher uses `TempFileExecutor`, which writes the decrypted binary to `/dev/shm`, unlinks it immediately, then executes it via `fork`/`exec`. See [Execution modes](#execution-modes) for details.

**Features**:
- Single-file bundling (`--onefile`)
- Basic dependency detection
- No auto-install (requires pre-installed PyInstaller)
- No `--backend-opts` passthrough
- No UPX compression via CLI

**Configuration**:

```bash
seal compile \
  --backend pyinstaller \
  --project ./my_agent \
  --user-fingerprint "$USER_FP" \
  --sandbox-fingerprint auto \
  --output ./agent.sealed
```

**Requirements**:
- Python 3.7 or later with `main.py` entrypoint
- PyInstaller pre-installed (`pip install pyinstaller`)

**Limitations**:
- Larger binary size (includes Python runtime)
- Slower startup compared to native code
- Execution requires Linux (`TempFileExecutor` uses Linux-specific syscalls)
- Returns error if `pyinstaller` command is not found

---

### Nuitka backend

**Status**: Implemented (default)

Compiles Python agents into optimized native executables using Nuitka's ahead-of-time compilation.

**Compilation platform support**:
- Linux x86_64: fully supported
- macOS arm64, x86_64: compilation in `--onefile` mode **fails** due to a Homebrew dynamic library resolution issue; standalone (non-onefile) mode is untested
- Windows: not supported

**Execution platform**: Linux only

Like PyInstaller, Nuitka bundles use a bootloader that reads the attached package via the filesystem. The launcher therefore routes Nuitka payloads through `TempFileExecutor`. See [Execution modes](#execution-modes) for details.

**Always-on flags**:

The compiler unconditionally passes `--static-libpython=no` to Nuitka. This is required for compatibility with pyenv and other shared-libpython environments. Additionally, `--standalone` and `--onefile` are enabled by default.

**Output**: Nuitka produces `main.bin` in `--onefile` mode (compiling `main.py`).

**Features**:
- Python-to-C compilation
- Better runtime performance than PyInstaller
- No auto-install (requires pre-installed Nuitka)
- No `--backend-opts` passthrough

**Configuration**:

```bash
seal compile \
  --backend nuitka \
  --project ./my_agent \
  --user-fingerprint "$USER_FP" \
  --sandbox-fingerprint auto \
  --output ./agent.sealed
```

**Requirements**:
- Python 3.7 or later with `main.py` entrypoint
- C compiler (gcc or clang)
- Nuitka pre-installed (`pip install nuitka`); also accepts `python3 -m nuitka`
- Development headers for compiled dependencies

**Limitations**:
- macOS `--onefile` builds fail (Homebrew dylib issue); use Linux for Nuitka compilation
- Significantly longer compilation times than PyInstaller (default timeout: 1800 seconds)
- Execution requires Linux

---

### Go backend

**Status**: Implemented

Compiles Go agents into statically-linked native Linux ELF executables.

**Compilation platform support**:
- Linux x86_64: supported
- macOS arm64, x86_64: supported (cross-compiles to Linux via `GOOS=linux`)
- Windows: not supported

**Execution platform**: Linux only

Go binaries are statically-linked ELF executables with no dynamic dependencies. The launcher uses `MemfdExecutor`, which loads the decrypted binary into an anonymous memory file (`memfd_create`), seals it, and executes it via `execveat` — leaving no filesystem artifact at any point during execution. This is the most hardened execution path.

**Build flags**:
- `GOOS=linux` (always set; cross-compiles from macOS)
- `CGO_ENABLED=0` (always set; required for static linking)
- `GOARCH` auto-detected from host (`arm64` or `amd64`) unless overridden via environment
- `-ldflags=-s -w` (strip debug symbols and DWARF)

**Configuration**:

```bash
seal compile \
  --backend go \
  --project ./my_go_agent \
  --user-fingerprint "$USER_FP" \
  --sandbox-fingerprint auto \
  --output ./agent.sealed
```

**Requirements**:
- Go 1.21 or later
- `go.mod` file in project root

**Limitations**:
- Execution requires Linux (memfd execution uses Linux-specific syscalls)
- Default compilation timeout: 600 seconds

---

## Backends not implemented

### Native backend

There is **no native backend** for sealing pre-compiled binaries.

- No `--backend native` option
- No `--binary` flag for pre-compiled executables
- No direct sealing of arbitrary binaries

---

## Backend selection

### Manual selection

Specify the backend explicitly:

```bash
seal compile --backend <nuitka|pyinstaller|go> --project ./agent --user-fingerprint "$FP" --sandbox-fingerprint auto --output ./agent.sealed
```

### Default behavior

When `--backend` is omitted, the default is `nuitka`.

### What is not available

**Auto-detection**: not implemented. There is no automatic detection of project type. Manual selection is required if the default fails.

**Backend options passthrough**: not implemented. Custom flags cannot be passed to the underlying backend tool.

---

## Execution modes

The backend type stored in the payload footer (`BackendType` byte) determines which execution path the launcher uses at runtime.

### Memory execution — Go backend

| Property | Detail |
|---|---|
| Executor | `MemfdExecutor` |
| Syscalls | `memfd_create`, `execveat` |
| Disk artifacts | None |
| Platform | Linux only |

The launcher creates an anonymous memory file (`memfd_create`), writes the decrypted payload into it, seals it (making it immutable), and executes directly via `execveat`. The process never touches the filesystem.

### Temp-file execution — PyInstaller and Nuitka backends

| Property | Detail |
|---|---|
| Executor | `TempFileExecutor` |
| Location | `/dev/shm` (RAM-backed filesystem) |
| Disk artifacts | Brief; unlinked immediately after fork |
| Platform | Linux only |

The launcher writes the decrypted payload to a randomly-named file in `/dev/shm` with `O_EXCL | O_CREAT` to prevent symlink attacks, immediately unlinks the file from the directory (so it exists only as an open file descriptor), and executes via `fork`/`exec`. A `PDEATHSIG` is set so the child terminates if the launcher exits.

**Why not memfd for Python backends?** PyInstaller and Nuitka bootloaders read their embedded package data by reopening the executable via `fopen()` using the path from `/proc/self/exe`. Memory file descriptor paths (e.g., `/memfd:name`) cannot be reopened this way, so memfd execution is incompatible with Python bundled binaries.

### Execution mode comparison

| Execution mode | Disk visibility | Persistence | Forensic recovery |
|---|---|---|---|
| `memfd` (Go) | None | None | Not possible |
| Temp-file (PyInstaller, Nuitka) | Brief (`/dev/shm`, unlinked immediately) | None | Low (possible during active execution) |

---

## Backend performance comparison

| Backend | Default timeout | Binary size | Runtime performance |
|---|---|---|---|
| PyInstaller | 1800 s | Large (50–200 MB) | Slower (interpreter) |
| Nuitka | 1800 s | Medium (30–100 MB) | Fast (compiled native) |
| Go | 600 s | Small (10–50 MB) | Fast (compiled native) |

---

## Troubleshooting

### Backend tool not found

**Symptom**: `pyinstaller not found` or `nuitka not found`

**Cause**: Backend tool not installed or not in `PATH`

**Solution**:
```bash
pip install pyinstaller
pip install nuitka
```

Nuitka also accepts invocation via `python3 -m nuitka` if the standalone binary is unavailable.

### Nuitka fails on macOS

**Symptom**: Nuitka compilation succeeds but the resulting binary crashes or compilation itself errors with Homebrew library resolution messages

**Cause**: Nuitka `--onefile` mode on macOS has a known incompatibility with Homebrew-managed dynamic libraries

**Solution**: Run Nuitka compilation on a Linux host. macOS can be used for Go and PyInstaller compilation.

### Missing dependencies

**Symptom**: Compilation fails with import errors

**Cause**: Dynamic imports not detected by backend

**Solution**:
- For PyInstaller: Manually create a spec file with hidden imports
- For Nuitka: Use a `nuitka.config` file in your project
- Note: `--backend-opts` passthrough is not available via `seal compile`

### Cross-compilation issues

**Symptom**: Binary fails to execute on target platform

**Cause**: Backend compiled for wrong platform

**Solution**: Run compilation on a Linux host, or for Go, ensure `GOOS=linux` is the intended target (it is set automatically).

## Future backends

For planned backends (Rust, Node.js, JVM, .NET), see the [Roadmap](../roadmap.md).

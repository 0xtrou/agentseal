---
sidebar_position: 4
---

# Supported Backends

Snapfzz Seal supports compilation backends for transforming agent source code into sealed executables.

## Backend Overview

Backends are responsible for compiling agent source code into standalone executables that can be sealed and encrypted. The choice of backend affects:

- **Execution performance** — Native vs interpreted execution
- **Binary size** — Compiled size overhead
- **Dependency handling** — Static vs dynamic linking
- **Platform support** — Target OS and architecture

## Currently Implemented Backends

### PyInstaller Backend

**Status**: Implemented

Compiles Python agents into standalone executables using PyInstaller's bundling mechanism.

**Supported platforms**:
- Linux x86_64
- macOS arm64, x86_64
- Windows x86_64

**Features**:
- ✅ Single-file bundling (`--onefile`)
- ✅ Basic dependency detection
- ❌ NO auto-install (requires pre-installed PyInstaller)
- ❌ NO `--backend-opts` passthrough
- ❌ NO UPX compression via CLI

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
- Python 3.7 or later
- **PyInstaller must be pre-installed** (`pip install pyinstaller`)
- Target platform Python environment

**Limitations**:
- Larger binary size (includes Python runtime)
- Slower startup compared to native code
- Returns error if `pyinstaller` command not found

**Best for**:
- Python-based agents with complex dependencies
- Cross-platform deployment requirements
- Rapid prototyping and development

### Nuitka Backend

**Status**: Implemented (Default)

Compiles Python agents into optimized native executables using Nuitka's ahead-of-time compilation.

**Supported platforms**:
- Linux x86_64
- macOS arm64, x86_64
- Windows x86_64

**Features**:
- ✅ Python-to-C compilation
- ✅ Better performance than PyInstaller
- ✅ Smaller binary footprint
- ❌ NO auto-install (requires pre-installed Nuitka)
- ❌ NO `--backend-opts` passthrough
- ❌ NO plugin flags via CLI

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
- Python 3.7 or later
- C compiler (gcc, clang, or MSVC)
- **Nuitka must be pre-installed** (`pip install nuitka`)
- Development headers for compiled dependencies

**Compilation time**: Significantly longer than PyInstaller due to full compilation pass

**Limitations**:
- Longer compilation times
- Returns error if `nuitka` command not found

**Best for**:
- Performance-critical Python agents
- Production deployments requiring minimal overhead
- Agents with computationally intensive workloads

## Backends NOT Exposed via `seal compile`

### Go Backend

**Status**: Implemented internally, **NOT exposed via `seal compile` CLI**

The Go backend exists in the `snapfzz-seal-compiler` crate but is **not accessible through the user-facing `seal compile` command**.

**Why not accessible**:
- `seal compile` only accepts `--backend nuitka` or `--backend pyinstaller`
- No `--backend go` option in current `seal` CLI
- Hardcoded for internal use with `GOOS=linux`, `GOARCH=amd64`

**Technical detail**:
- The lower-level compiler crate (`snapfzz-seal-compiler`) does expose Go as a backend option
- However, users interact with `seal compile`, not the compiler crate directly
- An internal fallback chain (`Nuitka → PyInstaller → Go`) exists but is not user-configurable

**Do NOT attempt**:
```bash
# This will FAIL - go backend not exposed in seal CLI
seal compile --backend go --project ./agent
```

## Backends NOT Implemented

### Native Backend

**Status**: NOT IMPLEMENTED

There is **no native backend** for sealing pre-compiled binaries.

**What doesn't exist**:
- ❌ No `--backend native` option
- ❌ No `--binary` flag for pre-compiled executables
- ❌ No direct sealing of arbitrary binaries

**If you need this**:
- Build your executable separately
- Use a Python shim that calls your binary
- Compile with PyInstaller/Nuitka wrapping your tool

## Backend Selection

### Manual Selection

Specify backend explicitly:

```bash
seal compile --backend <nuitka|pyinstaller> --project ./agent --user-fingerprint "$FP" --sandbox-fingerprint auto --output ./agent.sealed
```

### Default Behavior

When `--backend` is omitted, defaults to `nuitka`.

### What DOESN'T Exist

**Auto-detection**: NOT IMPLEMENTED
- No automatic detection of project type
- Manual selection required if default fails

**Backend chain**: NOT IMPLEMENTED for users
- No `--backend-chain` CLI option
- Internal fallback chain exists in compiler library (Nuitka → PyInstaller → Go)
- Not user-configurable

**Backend options**: NOT IMPLEMENTED
- No `--backend-opts` passthrough
- Cannot pass custom flags to backend tools

## Backend Performance Comparison

| Backend | Compilation Time | Binary Size | Runtime Performance |
|---------|-----------------|-------------|---------------------|
| PyInstaller | Fast (30s-2m) | Large (50-200MB) | Slower (interpreter) |
| Nuitka | Slow (2-10m) | Medium (30-100MB) | Fast (native) |

## Troubleshooting

### Backend Tool Not Found

**Symptom**: `pyinstaller not found` or `nuitka not found`

**Cause**: Backend tool not installed

**Solution**:
```bash
# For PyInstaller
pip install pyinstaller

# For Nuitka
pip install nuitka
```

### Missing Dependencies

**Symptom**: Compilation fails with import errors

**Cause**: Dynamic imports not detected by backend

**Solution**:
- For PyInstaller: Manually create a spec file with hidden imports
- For Nuitka: Use a `nuitka.config` file in your project
- Note: Cannot pass these via `seal compile` CLI (no `--backend-opts`)

### Cross-Compilation Issues

**Symptom**: Binary fails to execute on target platform

**Cause**: Backend compiled for wrong platform

**Solution**:
- Run compilation on target platform
- Or use appropriate cross-compilation setup for the backend tool

## Future Backends

For planned backends (Rust, Node.js, JVM, .NET, Native), see the [Roadmap](../roadmap.md).
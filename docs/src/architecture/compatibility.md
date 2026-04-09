# Compatibility Matrix

## Compile Backends

| Backend | Detection | Produces | Status |
|---------|-----------|----------|--------|
| Nuitka | `main.py` or `setup.py` | Static Linux ELF | Stable |
| PyInstaller | `main.py` | Linux ELF | Stable |
| Go | `go.mod` | Static Linux ELF | Stable |

Auto-detection order: Nuitka → PyInstaller → Go.

## Sandbox Targets

| Backend | API | Isolation | Status |
|---------|-----|-----------|--------|
| Docker | Docker CLI | Process + capabilities | Stable |
| Firecracker | REST API | MicroVM | Planned |

## Platform Support

| Platform | Launcher | Compilation | Status |
|----------|----------|-------------|--------|
| Linux x86_64 | Full (memfd + seccomp) | Native | Stable |
| macOS arm64 | Stub (decrypt only) | Cross-compile | Foundation |
| Windows x86_64 | Stub (no-op) | Cross-compile | Foundation |

### Linux Launcher Features

- seccomp allowlist filter
- `PR_SET_NO_NEW_PRIVS`
- `PR_SET_DUMPABLE(0)`
- ptrace anti-debug
- env scrub (master secret denied to child)
- output size limits (64 MB/stream, silent truncation)
- self-delete on launch

## Fingerprint Signals

| Signal | Stability | Platform | Status |
|--------|-----------|----------|--------|
| Machine ID HMAC | Stable | Linux | Active |
| Hostname | Semi-stable | Linux | Active |
| Kernel release | Stable | Linux | Active |
| Cgroup path | Semi-stable | Linux | Active |
| Proc cmdline hash | Stable | Linux | Active (low entropy in cloud) |
| MAC address | Stable | Linux | Active |
| DMI product UUID | Stable | Linux | Active |
| Namespace inodes | Ephemeral | Linux | Active (session mode) |
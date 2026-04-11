---
sidebar_position: 5
---

# Supported Sandboxes

Snapfzz Seal uses sandbox backends for isolated agent execution.

## Sandbox overview

Sandbox backends create isolated execution environments where sealed agents run. The choice of sandbox affects:

- **Isolation level** — Process, container, or VM isolation
- **Resource overhead** — Memory and CPU overhead
- **Security guarantees** — Attack surface and escape resistance
- **Startup latency** — Time to provision sandbox

:::note[Launcher hardening vs server sandboxes]

The `snapfzz-seal-launcher` crate applies **process-level hardening** to the sealed agent at runtime — including a seccomp BPF filter and anti-debug checks. These are distinct from the server-side Docker sandbox. The launcher hardening is Linux-only. See [Launcher hardening](#launcher-hardening) below.

:::

## Implemented sandboxes

### Docker sandbox

**Status**: Implemented (the only server backend)

Executes sealed agents in Docker containers with security hardening and resource controls.

**Host platform support**:
- Linux x86_64 (native Docker): supported
- macOS arm64, x86_64 (Docker Desktop): supported as host
- Windows x86_64 (WSL2 Docker): supported as host

:::note[Host platform vs execution platform]

The Docker sandbox can run on macOS and Windows **hosts**, but the sealed agent itself still executes inside a **Linux container**. The sealed binary must therefore be compiled for Linux x86_64 regardless of the host platform.

:::

**Implemented features**:

| Feature | Status | Notes |
|---|---|---|
| Container isolation | Implemented | Namespace and cgroup separation |
| Memory limit | Implemented | Optional via `memory_mb` |
| Timeout enforcement | Implemented | Via `timeout_secs`; async cancel and `docker rm -f` |
| Automatic cleanup | Implemented | Container removed after execution |
| No-new-privileges | Implemented | Hardcoded |
| Capabilities dropped | Implemented | `--cap-drop ALL` |
| Read-only rootfs | Implemented | Hardcoded |
| tmpfs `/tmp` | Implemented | Hardcoded |
| PIDs limit | Implemented | Fixed at 64 |
| Environment variables | Implemented | Pass custom env via `env` field |

**Not implemented**:

| Feature | Status |
|---|---|
| CPU quota/period | Not implemented |
| Disk I/O limits | Not implemented |
| Network isolation toggle | Not implemented (containers have network access) |
| Volume mounting | Not implemented |
| Custom seccomp profile | Not configurable |
| AppArmor/SELinux profile | Not configurable |
| User namespace / rootless | Not configurable |
| Log streaming | Not implemented; post-execution capture only |

**Configuration schema**:

```json
{
  "sandbox": {
    "image": "ubuntu:22.04",
    "timeout_secs": 3600,
    "memory_mb": 512,
    "env": [["KEY", "value"]]
  }
}
```

**Example dispatch request**:

```bash
curl -X POST http://localhost:9090/api/v1/dispatch \
  -H "Content-Type: application/json" \
  -d '{
    "job_id": "uuid-from-compile",
    "sandbox": {
      "image": "ubuntu:22.04",
      "timeout_secs": 3600,
      "memory_mb": 512
    }
  }'
```

**Execution flow**:

1. Pull specified Docker image
2. Create container with hardened flags:
   - `--security-opt no-new-privileges:true`
   - `--cap-drop ALL`
   - `--read-only`
   - `--tmpfs /tmp`
   - `--pids-limit 64`
   - `--memory <memory_mb>m` (if specified)
3. Copy sealed binary into container at `/tmp/snapfzz-sealed`
4. Execute: `chmod +x /tmp/snapfzz-sealed && /tmp/snapfzz-sealed`
5. Capture stdout/stderr (post-execution, not streamed)
6. Destroy container
7. Return execution results

**Security properties**:
- Namespace isolation (PID, network, mount, UTS)
- cgroup resource limits
- Reduced capability set (`--cap-drop ALL`)
- Read-only root filesystem
- Privilege escalation prevented (`no-new-privileges`)

**Requirements**:
- Docker Engine 20.10 or later
- Sufficient disk space for images
- Network access for image pulls (or pre-pulled images)

**Limitations**:
- Higher resource overhead than native execution
- Docker daemon dependency
- No network isolation (containers have outbound network access)
- Logs captured post-execution only, not streamed

---

## Not implemented sandboxes

### Native sandbox

There is **no native sandbox backend** in the server. There is no `NativeBackend` implementation, no server-side seccomp sandbox, and no `"type": "native"` config field. Do not attempt:

```json
// This will NOT work
{
  "sandbox": {
    "type": "native"
  }
}
```

Process-level hardening in the launcher (seccomp, anti-debug) is different from a server sandbox and is not accessible via the dispatch API.

### Firecracker sandbox

Firecracker microVM execution has no implementation. The `RuntimeKind::Firecracker` enum variant exists for fingerprint detection heuristics, but there is no `FirecrackerBackend`, no microVM provisioning, and no KVM integration.

For planned sandbox backends, see the [Roadmap](../roadmap.md).

---

## Sandbox selection

**No selection is possible.** Docker is the only backend and is hardcoded:

```rust
pub type SandboxProvisioner = DockerBackend;
```

There is no runtime backend selection.

---

## Launcher hardening

The `snapfzz-seal-launcher` applies process-level protections at agent execution time. These are not server sandbox features — they run inside the launcher process itself.

### seccomp BPF filter (Linux only)

A seccomp allowlist filter is installed before the sealed agent is decrypted or executed. The filter is implemented in `crates/snapfzz-seal-launcher/src/seccomp.rs` and targets **Linux x86_64 only**. On other operating systems, `apply_seccomp_filter()` is a no-op.

The default action for any syscall not on the allowlist is `EPERM`.

**Allowed syscall categories** (x86_64 numbers):

| Category | Syscalls |
|---|---|
| Basic I/O | `read` (0), `write` (1), `close` (3), `lseek` (8), `readv` (19), `writev` (20) |
| Process lifecycle | `exit` (60), `exit_group` (231), `clone` (56), `clone3` (435), `execve` (59), `execveat` (322), `wait4` (61), `waitid` (247), `kill` (62) |
| Memory management | `mmap` (9), `munmap` (11), `mprotect` (10), `brk` (12), `madvise` (28), `mincore` (27) |
| Signal handling | `rt_sigaction` (13), `rt_sigprocmask` (14), `rt_sigreturn` (15), `sigaltstack` (131) |
| Filesystem | `open` (2), `openat` (257), `stat` (4), `fstat` (5), `lstat` (6), `newfstatat` (257), `statx` (332), `unlink` (87), `unlinkat` (263), `readlink` (89), `access` (21), `faccessat2` (439), `getdents64` (217), `getcwd` (79), `chdir` (80), `fchdir` (81), `mkdir` (83), `rmdir` (84), `chmod` (90), `fchmod` (91), `fchownat` (262), `statfs` (98), `fstatfs` (99) |
| Networking | `socket` (41), `connect` (42), `bind` (49), `listen` (50), `accept4` (288), `sendto` (44), `recvfrom` (45), `sendmsg` (46), `recvmsg` (47), `sendmmsg` (307), `recvmmsg` (299), `shutdown` (48), `setsockopt` (54), `getsockopt` (55), `socketpair` (53), `getsockname` (51), `getpeername` (52) |
| I/O multiplexing | `poll` (7), `ppoll` (271), `select` (23), `pselect6` (270), `epoll_create1` (291), `epoll_ctl` (233), `epoll_wait` (232), `epoll_pwait` (281) |
| File descriptors | `dup` (32), `dup2` (33), `dup3` (292), `pipe` (22), `pipe2` (293), `fcntl` (72), `ioctl` (16) |
| Identity / credentials | `getpid` (39), `getppid` (110), `getuid` (102), `getgid` (104), `geteuid` (107), `getegid` (108), `getresuid` (165), `getresgid` (166), `getgroups` (96), `capget` (122), `capset` (123) |
| Scheduling | `sched_yield` (202), `sched_getaffinity` (203), `sched_setaffinity` (204), `nanosleep` (35) |
| Time | `clock_gettime` (228), `clock_getres` (229), `gettimeofday` (169) |
| Synchronization | `futex` (240), `set_robust_list` (273) |
| Misc | `arch_prctl` (158), `uname` (63), `getrandom` (318), `umask` (95), `setpgid` (109), `getpgrp` (111), `setsid` (112), `getsid` (124), `getrlimit` (97), `setrlimit` (160), `prlimit64` (261), `memfd_create` (356), `set_tid_address` (218), `gettid` (186) |

Note: `execveat` (322) is critical for `memfd` execution of Go payloads; `memfd_create` (356) is required for PyInstaller onefile extraction during bootloader initialization.

### Anti-debug checks (Linux only)

The `anti_analysis` module in `snapfzz-seal-launcher` performs runtime environment checks (debugger presence, VM indicators, timing anomalies) before executing the payload. These checks are Linux-specific.

### Environment variable filtering

Both `MemfdExecutor` and `TempFileExecutor` strip the following environment variables from the child process environment to prevent secret leakage:

- `SNAPFZZ_SEAL_MASTER_SECRET_HEX`
- `SNAPFZZ_SEAL_LAUNCHER_SECRET_HEX`
- `SNAPFZZ_SEAL_LAUNCHER_SIZE`
- `SNAPFZZ_SEAL_PAYLOAD_SENTINEL`

---

## Resource management

### Configurable (Docker sandbox)

**Memory limit**:
```json
{
  "sandbox": {
    "memory_mb": 512
  }
}
```

**Timeout**:
```json
{
  "sandbox": {
    "timeout_secs": 3600
  }
}
```

**Environment variables**:
```json
{
  "sandbox": {
    "env": [["API_KEY", "secret"], ["DEBUG", "true"]]
  }
}
```

### Not configurable

- CPU quota/period
- Disk I/O limits
- Network enable/disable
- PIDs limit (fixed at 64)
- Custom security profiles
- Volume mounts

---

## Timeout enforcement

Timeout is enforced via an async timeout wrapper around `docker exec`:

- If execution exceeds `timeout_secs`, the async call times out
- Container is destroyed via `docker rm -f`
- Job status is set to `failed`

Not implemented: SIGTERM grace period, graceful shutdown signaling, custom grace period configuration.

---

## Log handling

Logs are **not streamed** during execution. They are captured after the process completes:

1. Process executes to completion (or timeout)
2. stdout/stderr captured from container
3. Results returned in job result object

**Result schema**:
```json
{
  "job_id": "uuid",
  "status": "completed",
  "result": {
    "exit_code": 0,
    "stdout": "...",
    "stderr": "..."
  }
}
```

Not implemented: streaming log endpoint, SSE/WebSocket log streaming, `GET /logs/{id}`.

---

## Troubleshooting

### Sandbox provisioning failures

**Symptom**: Container creation fails

**Solutions**:
- Check Docker daemon: `docker ps`
- Verify disk space: `df -h`
- Check image availability: `docker images`
- Review Docker logs: `journalctl -u docker`

### Timeout issues

**Symptom**: Agent terminated before completion

**Solutions**:
- Increase `timeout_secs` in dispatch request
- Optimize agent performance

### Resource limit violations

**Symptom**: Agent killed unexpectedly

**Diagnosis**: Check if memory limit was exceeded: `dmesg | grep -i "out of memory"`

**Solutions**: Increase `memory_mb` in dispatch request, or optimize agent memory usage.

---

## Custom sandboxes

The sandbox trait exists in code, but no registration mechanism is exposed for external backends. For planned backends (gVisor, Firecracker, Kata Containers), see the [Roadmap](../roadmap.md).

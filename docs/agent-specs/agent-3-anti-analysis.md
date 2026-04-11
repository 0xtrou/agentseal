# Agent 3: Anti-Analysis Protections

## 1. Purpose

The anti-analysis subsystem applies runtime hardening measures to the launcher process to raise the cost of interactive debugging and memory inspection. The implemented protections are confined to the Linux platform and consist of two mechanisms: disabling core dumps via `prctl(PR_SET_DUMPABLE, 0)` and blocking subsequent `ptrace` attachment via `ptrace(PTRACE_TRACEME)`. A seccomp system call allowlist provides a complementary sandbox that restricts the syscall surface available to the launcher and its children.

---

## 2. Design Rationale

### 2.1 Scope of Implementation

The prior specification for this agent described a comprehensive multi-layer analysis detection system including debugger detection, breakpoint scanning, timing anomaly checks, VM fingerprinting via CPUID and DMI, MAC address inspection, and environment poisoning. **None of these features are present in the current codebase.** The actual implementation is limited to the two `apply_protections` mechanisms and the seccomp filter described below.

The narrower implementation is a defensible engineering choice: the listed aspirational features carry substantial false-positive risk in cloud and containerized environments where VM hypervisor flags, constrained MAC addresses, and co-located tooling are routine. The implemented protections have well-defined semantics and low collateral-impact risk.

### 2.2 Anti-Debug via prctl and ptrace

Two independent mechanisms are applied in sequence by `apply_protections()`:

1. `prctl(PR_SET_DUMPABLE, 0)`: Marks the process as non-dumpable. This prevents core dump generation on crash, suppresses `/proc/self/mem` write access from other processes, and disables `ptrace` attachment by non-root processes on kernels with Yama `ptrace_scope >= 1`.
2. `ptrace(PTRACE_TRACEME)`: A process may only be traced by one tracer at a time. By voluntarily calling `PTRACE_TRACEME`, the launcher occupies its own tracer slot, causing any subsequent `ptrace` attach attempt by an external process to fail with `EPERM`.

Both calls report success or failure via `tracing::info!` / `tracing::warn!` messages, and the list of successfully applied protection labels is returned to the caller.

### 2.3 Seccomp Syscall Allowlist

`crates/snapfzz-seal-launcher/src/seccomp.rs` implements a Linux seccomp-BPF filter that restricts the process to a statically enumerated allowlist of syscall numbers. The allowlist (`ALLOWED_SYSCALLS_X86_64`) is defined for the x86-64 architecture and includes syscalls required for:

- Standard I/O and file operations
- Memory management (`mmap`, `munmap`, `mprotect`, `brk`, `madvise`, `mincore`)
- Process lifecycle (`fork`/`clone`/`clone3`, `execve`, `execveat`, `wait4`, `waitid`, `exit`, `exit_group`)
- Signal handling
- Networking (socket, connect, send/recv variants)
- Subprocess support for Go, PyInstaller, and Nuitka backends
- `memfd_create` (syscall 356) — required for in-memory execution of extracted PyInstaller and Go payloads
- `getrandom` (syscall 318) — required for cryptographic operations

Syscalls not in the allowlist cause the kernel to return `EPERM` to the calling instruction (configured as `SeccompAction::Errno(EPERM)`). The default action for the architecture match is `SeccompAction::Allow`, meaning the filter is applied only to the named architecture; execution on other architectures is unrestricted at the seccomp level.

The filter is constructed using the `seccompiler` crate (`SeccompFilter::new`, `filter.try_into()`), which compiles the allowlist into a BPF program, and applied via `seccompiler::apply_filter`.

On non-Linux platforms (`windows` and other), `apply_seccomp_filter` is a no-op that returns `Ok(())`.

---

## 3. Implementation Details

### 3.1 apply_protections (anti_debug.rs)

**Platform:** Linux only. The `#[cfg(not(target_os = "linux"))]` variant returns an empty `Vec` without any system calls.

```rust
// Linux implementation
pub fn apply_protections() -> Result<Vec<String>, SealError> {
    // Protection 1: disable core dumps and ptrace from non-root
    let dumpable_result = unsafe { nix::libc::prctl(nix::libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
    // Protection 2: occupy tracer slot
    match nix::sys::ptrace::traceme() { ... }
    Ok(applied)
}
```

The function depends on the `nix` crate for both the `libc::prctl` call and `sys::ptrace::traceme()`. Return values are checked: a non-zero `prctl` return indicates failure; the `traceme` result is matched on `Ok`/`Err`. Applied protection names are pushed as string labels (`"prctl_dumpable"`, `"ptrace_traceme"`) for caller logging.

### 3.2 apply_seccomp_filter (seccomp.rs)

**Platform:** Linux x86-64 only for the functional implementation. Windows and other platforms receive a no-op stub.

The filter construction pipeline:

1. `build_seccomp_filter()`: Builds a `BTreeMap<i64, Vec<SeccompRule>>` from `ALLOWED_SYSCALLS_X86_64`, where each entry maps a syscall number to an empty rule vector (unconditional allow). Constructs a `SeccompFilter` with `SeccompAction::Errno(EPERM)` as the default deny action and `TargetArch::x86_64` as the target. Compiles to `BpfProgram` via `TryFrom`.
2. `apply_seccomp_filter()`: Calls `build_seccomp_filter()` then `seccompiler::apply_filter(&filter)`.

The `allowed_syscalls()` function returns a reference to `ALLOWED_SYSCALLS_X86_64` and is used directly in the filter construction and in tests.

### 3.3 memfd_exec.rs Integration Context

`crates/snapfzz-seal-launcher/src/memfd_exec.rs` implements in-memory payload execution using `memfd_create` / `execveat` (for ELF payloads) and manages child process lifecycle including signal forwarding, lifetime enforcement, and output buffering. Relevant constants:

```rust
const ENV_DENYLIST: &[&str] = &[
    "SNAPFZZ_SEAL_MASTER_SECRET_HEX",
    "SNAPFZZ_SEAL_LAUNCHER_SECRET_HEX",
    "SNAPFZZ_SEAL_LAUNCHER_SIZE",
    "SNAPFZZ_SEAL_PAYLOAD_SENTINEL",
];
```

These environment variable names are stripped from the child process environment before execution, preventing secret leakage through process environment inspection.

The `MemfdOps` trait abstracts the memfd operations to support both the kernel implementation (`KernelMemfdOps`) and test doubles.

---

## 4. Security Properties

**Implemented:**
- `PR_SET_DUMPABLE = 0` prevents core dump generation and blocks `/proc/self/mem` writes from unprivileged external processes. On systems with `ptrace_scope >= 1` (default on Ubuntu and many other distributions), this also prevents unprivileged `ptrace` attachment.
- `PTRACE_TRACEME` occupies the launcher's tracer slot, preventing any single external debugger from attaching via `ptrace(PTRACE_ATTACH)` or `ptrace(PTRACE_SEIZE)` for the lifetime of the process.
- The seccomp allowlist reduces the kernel attack surface available to a compromised launcher process or its children.
- `ENV_DENYLIST` prevents child processes from inheriting environment variables that might contain secret material.

**Aspirational / Not Yet Implemented:**
- Debugger detection via `TracerPid` in `/proc/self/status`.
- Hardware and software breakpoint detection.
- Timing-based instrumentation detection.
- VM and hypervisor detection (CPUID, DMI, MAC address).
- Environment poisoning with decoy data.
- Any detection-and-abort logic; the current protections are passive hardening, not detection.

---

## 5. Platform Restrictions

- **Linux only:** `apply_protections` performs system calls only on Linux. The non-Linux variant is an explicit no-op.
- **x86-64 only:** The seccomp allowlist is specific to x86-64 syscall numbers. The `seccompiler` crate requires a `TargetArch` specification; `TargetArch::x86_64` is hardcoded. Other architectures (e.g., aarch64) are not supported.
- **Windows:** `apply_seccomp_filter` returns `Ok(())` on Windows with a debug log message; no equivalent sandboxing mechanism is applied.
- **macOS:** Neither `apply_protections` nor `apply_seccomp_filter` performs any protective action on macOS.

---

## 6. Known Limitations

1. `PTRACE_TRACEME` is ineffective against root-level debuggers (which bypass `ptrace_scope` restrictions), kernel debuggers, hardware-assisted debugging interfaces (e.g., JTAG), or debuggers that patch the running process via `/proc/self/mem` on kernels where dumpable state does not restrict mem access.
2. The `PR_SET_DUMPABLE` call can be reversed by any code executing within the process after the call returns. A compromised dependency or injected code could re-enable dumpability.
3. The seccomp filter uses an allowlist approach, which is appropriate, but the allowlist is broad (approximately 80 syscalls) to accommodate PyInstaller, Go runtime, and networking requirements. A narrower filter tailored to each backend type would reduce the attack surface further.
4. The seccomp filter is applied once at process startup. Syscalls required only during the initialization phase (e.g., `execveat` for payload launch) remain permitted throughout the entire process lifetime, including after the payload has been handed off.
5. No detection-and-abort behavior is implemented. The protections are hardening measures that raise cost, not mechanisms that terminate the process upon detecting analysis.

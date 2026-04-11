---
sidebar_position: 7
---

# Roadmap

This document distinguishes what is implemented in the current release (v0.1), what is in active development, and what is planned for future releases.

---

## v0.1 — Implemented

The features in this section are fully implemented and present in the current codebase. The v0.1 release covers commits up to `2049c86` (2026-04-11).

### Compilation Backends

| Backend | Notes |
|---------|-------|
| **Nuitka** | Default Python backend. Payload is executed via temp-file path (Nuitka's self-extracting archive requires a writable file). |
| **PyInstaller** | Alternative Python backend. Also uses temp-file execution path. |
| **Go** | `--backend go`. Uses `memfd_create` + `fexecve` for in-memory execution on Linux. |

### Sandboxes

| Backend | Notes |
|---------|-------|
| **Docker** | Primary sandbox backend. Used during `seal compile` to produce the payload in a controlled environment. |

### Security Features

| Feature | Notes |
|---------|-------|
| **AES-256-GCM payload encryption** | Streaming 64 KB chunks. Cipher authenticated with per-chunk tags. |
| **Ed25519 builder signatures** | 100-byte block appended to artifact (`ASL\x02` magic, 64-byte signature, 32-byte public key). |
| **HKDF-SHA256 key derivation** | Master secret + user fingerprint + environment fingerprint. Two derivation contexts: `env/v1` and `session/v1`. |
| **Shamir Secret Sharing** | Implemented over the secp256k1 field. 5 shares, threshold 3. Used for distributing secret material embedded in the launcher binary. |
| **Launcher integrity binding** | SHA-256 hash of the launcher binary (via `/proc/self/exe`) bound into key derivation. Linux only. |
| **seccomp-bpf syscall filtering** | Allowlist-based filter applied at launch time on Linux x86-64. Denies syscalls not on the permit list with `EPERM`. |
| **Anti-analysis: debugger detection** | Checks `/proc/self/status` TracerPid, `ptrace(TRACEME)`, software-breakpoint byte scan of critical function entry points, and timing anomaly detection. Linux-extended; timing and breakpoint checks run on all platforms. |
| **Anti-analysis: VM detection** | CPUID hypervisor bit (x86-64), DMI artifact file keyword scan, and MAC address OUI prefix check. Linux-extended; CPUID check runs on all x86-64 platforms. |
| **Anti-analysis: environment poisoning** | On analysis detection, execution is aborted. Decoy env vars and files are written unconditionally at launch to mislead static analysis. |
| **Anti-debug protections** | `prctl(PR_SET_DUMPABLE, 0)` and `ptrace(TRACEME)` applied at launch. Linux only; no-op on other platforms. |
| **Decoy markers (compile-time)** | 5 secret markers and 50 decoy markers are generated at build time and embedded in the launcher binary to complicate static analysis. |
| **Tamper marker verification** | Launcher verifies its own binary hash against the expected hash stored in the payload footer before key derivation. |

### CLI Commands

| Command | Notes |
|---------|-------|
| `seal compile` | Compiles a project, derives environment key, encrypts payload, assembles artifact. |
| `seal launch` | Verifies signature, runs anti-analysis, derives key, decrypts, and executes payload. |
| `seal keygen` | Generates Ed25519 builder key pair (32-byte hex files). |
| `seal sign` | Appends a 100-byte Ed25519 signature block to an assembled artifact. |
| `seal verify` | Verifies the signature block of a sealed artifact without launching. |
| `seal server` | HTTP server for remote compile and launch operations. |

### Partially Implemented

| Feature | Status | Notes |
|---------|--------|-------|
| **White-box AES tables** | Partial | `WhiteBoxTables` and `WhiteBoxAES` data structures and table generation are implemented. The whitebox AES path is not connected to the live payload encryption pipeline; AES-256-GCM is used directly. |

---

## In Progress

These items have been started but are not yet complete or stable.

- **Cross-platform execution parity**: The temp-file fallback executor works for Python backends, but the path lacks the same cleanup guarantees as the `memfd` path. Improving temp-file handling (atomic cleanup, reduced exposure window) is ongoing.
- **End-to-end test coverage across all backends**: E2E tests were stabilized in recent commits (`2049c86`, `edeeb7a`) but coverage is not yet complete for all fingerprint modes and failure cases.

---

## Planned Features

:::info

Features below are **planned** and not yet implemented. They may change based on research, user feedback, and development priorities.

:::

## Compilation Backends

### Native Backend

**Goal**: Seal pre-compiled binaries directly without Python or Go compilation steps.

**Planned features**:
- `--backend native` option
- `--binary <path>` flag for existing executables
- Direct sealing of any Linux ELF binary
- Support for Rust, C/C++, and other native-compiled agents

**Use case**: Integrate with existing build systems without Python shims.

### Rust Backend

**Goal**: Native Rust agent compilation via Cargo.

**Planned features**:
- Automatic Cargo project detection
- `--backend rust` option
- Static linking for minimal binaries
- Cross-compilation support

### Node.js Backend

**Goal**: JavaScript/TypeScript agent compilation.

**Planned features**:
- `--backend nodejs` option
- pkg or nexe integration
- TypeScript support
- npm dependency bundling

### JVM Backend

**Goal**: Java/Kotlin agent compilation via GraalVM native-image.

**Planned features**:
- `--backend graalvm` option
- Native-image compilation
- JVM agent support

### .NET Backend

**Goal**: C#/F# agent compilation.

**Planned features**:
- `--backend dotnet` option
- Native AOT compilation
- .NET 8+ support

## Sandboxes

### Native Sandbox

**Goal**: Server-side native process sandboxing without a container runtime.

**Planned features**:
- `NativeBackend` implementation
- ulimit-based resource controls
- Zero container overhead

Note: seccomp-bpf filtering is already implemented in the launcher itself. A `NativeBackend` sandbox would add independent sandboxing at the server execution layer.

**Use case**: Development environments, trusted agents, performance-critical workloads.

### Firecracker Sandbox

**Goal**: MicroVM isolation for maximum security.

**Planned features**:
- `FirecrackerBackend` implementation
- KVM-based microVM provisioning
- Custom kernel/rootfs management
- Hardware-level isolation

**Use case**: Multi-tenant SaaS, untrusted agent execution, high-security deployments.

### Additional Sandbox Backends

**gVisor** — User-space kernel for enhanced container isolation

**Kata Containers** — Lightweight VM-based containers

**AWS Nitro Enclaves** — Hardware-isolated compute environments

**Azure Confidential Computing** — SGX-based secure enclaves

## Platform Support

### macOS Execution

**Goal**: Full protection coverage on macOS.

**Challenges**:
- No `memfd_create`/`fexecve` equivalent; only temp-file execution is possible
- `/proc`-based checks (`/proc/self/exe`, `/proc/self/status`) are unavailable
- Code signing requirements for distribution

**Possible approaches**:
- Ramdisk-based execution
- Integration with macOS sandbox (Seatbelt) APIs

### Windows Execution

**Goal**: Full protection coverage on Windows.

**Challenges**:
- No `memfd` equivalent
- Different security model; seccomp-bpf is Linux-specific
- PE binary format requires a separate execution path

**Possible approaches**:
- Memory-mapped execution
- Windows job object for resource containment
- Windows sandbox integration

## CLI Enhancements

### Backend Options Passthrough

**Planned**: `--backend-opts` flag to pass custom options to backend tools:

```bash
seal compile --backend nuitka --backend-opts="--enable-plugin=numpy"
```

### Backend Auto-Detection

**Planned**: Automatic backend selection based on project type.

Detection logic:
- `go.mod` → Go backend
- `Cargo.toml` → Rust backend
- `requirements.txt` / `setup.py` → Python backend

### Backend Chain Configuration

**Planned**: `--backend-chain` for fallback behavior:

```bash
seal compile --backend-chain nuitka,pyinstaller --project ./agent
```

## API Enhancements

### Log Streaming

**Goal**: Real-time execution log streaming.

**Planned features**:
- WebSocket/SSE endpoint for live logs
- `GET /api/v1/jobs/{job_id}/logs/stream`
- Configurable log buffering

### Authentication and Authorization

**Goal**: Built-in API security for the `seal server` endpoint.

**Planned features**:
- JWT token authentication
- API key support
- Role-based access control (RBAC)
- Rate limiting middleware

### OpenAPI Specification

**Goal**: Auto-generated API documentation.

**Planned features**:
- OpenAPI 3.0 spec generation
- Swagger UI integration
- Client SDK generation

## Security Features

### Hardware Attestation

**Goal**: TPM/SGX integration for hardware-bound keys.

**Planned features**:
- TPM 2.0 key sealing
- Intel SGX enclaves
- Remote attestation support

### Key Rotation

**Goal**: Built-in key management and rotation.

**Planned features**:
- Key versioning
- Automatic re-signing workflow
- Key distribution API

### Secure Key Distribution

**Goal**: Safe master secret and signing key distribution.

**Planned features**:
- Key wrapping with operator public keys
- Integration with HashiCorp Vault
- Cloud KMS support (AWS KMS, GCP KMS, Azure Key Vault)

### White-box AES Runtime Integration

**Goal**: Connect the implemented `WhiteBoxAES` table generation to the live payload encryption pipeline.

**Current state**: `WhiteBoxTables` and `WhiteBoxAES` structures exist and table generation is implemented. The whitebox path is not yet wired into the compile or launch flow; payload encryption currently uses standard AES-256-GCM directly.

## Orchestration Features

### Job Scheduling

**Goal**: Advanced job management.

**Planned features**:
- Priority queues
- Resource-based scheduling
- Job dependencies
- Cron-style scheduling

### Distributed Execution

**Goal**: Multi-node agent execution.

**Planned features**:
- Worker node registration
- Load balancing
- Fault tolerance
- Result aggregation

### Artifact Registry

**Goal**: Sealed artifact storage and versioning.

**Planned features**:
- Artifact storage backend (S3, GCS, local)
- Version management
- Signature verification on retrieval
- Access control

## Developer Experience

### Language SDKs

**Goal**: Native SDKs for common languages.

**Planned**:
- Python SDK
- TypeScript/Node.js SDK
- Go SDK
- Rust SDK

### VS Code Extension

**Goal**: IDE integration for Snapfzz Seal.

**Planned features**:
- Syntax highlighting for seal manifests
- Compile/launch commands
- Debug integration
- Key management UI

## Timeline

These features are under research and development. No specific timeline is committed. Priority is determined by:

1. **Security impact** — Features that significantly improve security posture
2. **User demand** — Features requested by the community
3. **Implementation complexity** — Balancing effort vs. value

For the latest development status, see [GitHub Issues](https://github.com/0xtrou/snapfzz-seal/issues) and [GitHub Discussions](https://github.com/0xtrou/snapfzz-seal/discussions).

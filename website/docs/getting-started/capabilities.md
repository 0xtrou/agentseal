---
sidebar_position: 4
---

# Capabilities

Snapfzz Seal provides security capabilities designed to protect AI agent deployments in production environments. This page describes only capabilities that are currently implemented.

## Cryptographic Capabilities

### Encryption at Rest

**Specification**: AES-256-GCM with 7-byte stream nonces

All agent payloads are encrypted using AES-256-GCM (Galois/Counter Mode), providing both confidentiality and authenticity. The encryption envelope includes:

- 256-bit encryption key derived via HKDF-SHA256
- 7-byte stream nonce per chunk (not the standard 12-byte nonce)
- 128-bit authentication tag verified on decryption
- Streaming encryption in 64 KB chunks for large payloads

**Security properties**:
- Confidentiality under chosen plaintext attacks (IND-CPA)
- Integrity and authenticity verification via GCM authentication tag
- Resistance to nonce reuse when proper key derivation is used

### Key Derivation

**Specification**: HKDF-SHA256 with dual fingerprint binding and integrity binding

The decryption key is derived in two stages:

**Stage 1 — environment key**:

```text
salt = stable_fingerprint_hash || user_fingerprint
PRK  = HKDF-Extract(salt=salt, IKM=master_secret)
env_key = HKDF-Expand(PRK, info="snapfzz-seal/env/v1", L=32)
```

**Stage 2 — integrity key** (binds decryption to an unmodified launcher):

```text
integrity_key = HKDF-SHA256(env_key, SHA-256(launcher_bytes), "snapfzz-seal/integrity/v1")
```

The final `integrity_key` is used for payload encryption and decryption. If the launcher binary is modified after assembly, the derived key will differ and decryption will fail.

**Security properties**:
- Decryption key is cryptographically bound to environment fingerprints and launcher binary content
- Different fingerprint combinations produce independent keys
- The master secret is not stored in plaintext anywhere in the artifact; it is split using Shamir secret sharing

### Digital Signatures

**Specification**: Ed25519 (EdDSA over Curve25519)

All sealed binaries carry an Ed25519 signature. The signature covers the entire binary content prior to the signature block. The signature block appended by `seal sign` is:

```text
ASL\x02  (4-byte magic marker)
sig      (64 bytes, Ed25519 signature)
pubkey   (32 bytes, embedded Ed25519 public key)
```

**Security properties**:
- 128-bit security level against forgery attacks
- 64-byte signature size
- Fast verification

:::warning[Signature Trust Model]

The launcher verifies signatures using the **public key embedded in the artifact itself**. This means:

- Detects tampering with signed content
- Prevents accidental corruption
- Does **NOT** verify the signer's identity
- An attacker can replace content, re-sign with their own key, and pass embedded-key verification

For production use, verify with `--pubkey` to pin to a trusted builder public key. The `seal verify` command without `--pubkey` performs TOFU verification only.

:::

### Shamir Secret Sharing

**Specification**: 5-of-3 threshold scheme over a prime field

The master secret is split into 5 shares using Shamir secret sharing (secp256k1 modulus as the prime field). Any 3 shares are sufficient to reconstruct the secret. The 5 shares are embedded into dedicated marker slots in the launcher binary at compile time. During launch, the runtime reads all available slots and reconstructs from any 3.

The marker slot positions are derived deterministically from `BUILD_ID`, making them opaque to an observer who does not know `BUILD_ID`.

## Execution Capabilities

### Memory-Only Execution

**Specification**: `memfd_create` + `fexecve` (Linux only)

The sealed payload is decrypted and executed entirely in memory on Linux, without writing the decrypted binary to disk. The implementation:

1. Creates an anonymous memory file via `memfd_create()`
2. Writes the decrypted payload bytes to the memory file
3. Executes via `fexecve()` using the memory file descriptor
4. The memory file is automatically cleaned up on process exit

**Security properties**:
- No persistent decrypted artifact on the filesystem
- Forensic analysis of disk reveals only the encrypted payload
- Protection against disk-based extraction attacks

**Platform limitations**:
- Linux x86_64: Full `memfd` execution supported
- macOS: Not implemented — returns an error
- Windows: Not implemented — returns an error

### Runtime Verification

**Specification**: Multi-stage verification before execution

Before any payload execution, the launcher performs:

1. **Signature verification** — Ed25519 signature validated against the embedded or pinned public key
2. **Launcher integrity check** — SHA-256 of the launcher binary compared against the hash stored in the payload footer
3. **Shamir reconstruction** — Master secret reconstructed from embedded shares
4. **Key derivation** — Runtime environment measured and decryption key derived
5. **Decryption and authentication tag check** — AES-256-GCM authentication tag verified on decryption

If any stage fails, execution is aborted.

### Anti-Debugging Protections

**Specification**: Multi-layer anti-debugging on Linux

The launcher implements the following anti-debugging measures:

- `PR_SET_DUMPABLE=0` — Prevents ptrace attachment
- `ptrace(PTRACE_TRACEME)` — Claims the tracer slot
- `TracerPid` check — Reads `/proc/self/status` to detect an attached debugger
- Timing checks — Detects abnormal delays consistent with single-stepping
- Software breakpoint scanning — Scans for `int3` instructions in launcher code

**Security properties**:
- Raises the cost of dynamic analysis attempts
- Multiple independent detection layers complicate bypass
- Can be bypassed by a sufficiently privileged adversary

### System Call Filtering

**Specification**: seccomp-bpf with allowlist (Linux only)

The launcher installs a seccomp-bpf filter using default-deny semantics after execution begins. Syscalls not in the allowlist return `EPERM`. The allowlist includes:

- Memory operations: `mmap`, `munmap`, `mprotect`, `brk`
- File operations: `read`, `write`, `open`, `close`, `stat`, `lstat`, `fstat`
- Process operations: `exit`, `exit_group`, `arch_prctl`
- Network operations: `socket`, `connect`, `bind`, `listen`, `accept4`, `sendto`, `recvfrom`, `sendmsg`, `recvmsg`
- Process creation: `clone`, `clone3`

`fork` and `vfork` are not in the allowlist and are blocked by the default-deny policy.

:::caution[Best-Effort Enforcement]

If seccomp installation fails, the launcher **logs a warning and continues without the filter**. seccomp is not a hard security boundary.

:::

## Fingerprinting Capabilities

### Host Signal Collection

**Specification**: Multi-source host measurement (Linux only)

The fingerprinting module collects signals from Linux-specific sources:

| Source | Stability |
|--------|-----------|
| Machine ID hash (`/etc/machine-id`) | Stable |
| Hostname | Semi-stable |
| Kernel release (`uname -r`) | Stable |
| cgroup path | Semi-stable |
| Process cmdline hash | Ephemeral |
| MAC address (first non-loopback) | Semi-stable |
| DMI product UUID HMAC | Stable |
| Namespace inodes | Ephemeral |

**Not implemented**:
- CPU model or feature flags
- Memory total
- Mount points table
- Full network interface inventory

**Platform limitations**:
- Linux: Full fingerprinting support
- macOS: Not implemented (uses Linux-only paths such as `/proc` and `/sys`)
- Windows: Not implemented

### Canonicalization

**Specification**: Deterministic canonical representation

Collected signals are canonicalized using:

1. Sort signal IDs lexicographically
2. Encode with a length-prefixed binary format
3. Hash the encoded data with SHA-256

Identical environments produce identical fingerprints.

## Orchestration Capabilities

### REST API

The `seal server` subcommand starts an HTTP server with the following implemented endpoints:

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/v1/compile` | POST | Compile and seal an agent |
| `/api/v1/dispatch` | POST | Launch a sealed agent in a Docker sandbox |
| `/api/v1/jobs/{job_id}` | GET | Check job status |
| `/api/v1/jobs/{job_id}/results` | GET | Get execution results |
| `/health` | GET | Health check |

For complete API documentation with request/response schemas, see [API Reference](../reference/api.md).

**Not implemented**:
- `POST /sign` endpoint
- `POST /launch` endpoint (use `/api/v1/dispatch`)
- `GET /status/{id}` (use `/api/v1/jobs/{id}`)
- `GET /logs/{id}` endpoint
- Real-time log streaming
- JWT authentication
- Rate limiting
- OpenAPI spec generation

:::warning

The server API has **no built-in authentication or authorization**. Deploy behind an authenticated gateway in all non-local environments.

:::

### Sandbox Integration

**Current implementation**: Docker container isolation only

The orchestration API provisions Docker containers with:

- Container isolation with namespace and cgroup separation
- Optional memory limit
- Timeout enforcement
- Automatic cleanup on completion
- Hardened flags: `--security-opt no-new-privileges`, `--cap-drop ALL`, `--read-only`, `--tmpfs /tmp`
- Fixed pids limit (64)

**Not implemented in server sandbox**:
- CPU quota/period configuration
- Disk I/O limits
- Network isolation flag
- Volume mounting
- Custom seccomp profiles
- AppArmor or SELinux profiles
- Log streaming (post-execution capture only)
- Firecracker backend
- Native (non-Docker) backend

## Platform Support

### Linux x86_64

All core capabilities are available on Linux x86_64:

- Native `memfd` execution
- seccomp-bpf filtering (best-effort)
- All fingerprinting sources
- Full encryption and signing
- Docker sandbox execution via `seal server`

Not implemented:
- Firecracker sandbox (planned only)

### macOS arm64 / x86_64

Cannot execute sealed agents.

- No `memfd` execution — returns an error at launch
- No seccomp (different OS)
- No fingerprinting (Linux-only paths)
- Build-side operations (`seal compile`, `seal sign`, `seal verify`, `seal keygen`) work correctly

### Windows x86_64

Cannot execute sealed agents.

- No `memfd` execution — returns an error at launch
- No seccomp
- No fingerprinting
- Build-side operations work correctly

:::warning[Platform Reality]

There is no no-op stub for Windows or macOS that returns a success result. Calling `seal launch` on a non-Linux platform fails with an error.

:::

## Operational Characteristics

### Performance Overhead

The following values are rough estimates based on typical workloads. Benchmark before relying on these numbers for capacity planning.

| Operation | Estimated Overhead |
|-----------|--------------------|
| Encryption (per MB) | ~5–10 ms (varies by CPU and AES-NI availability) |
| Decryption (per MB) | ~5–10 ms |
| Signature verification | ~1 ms |
| Fingerprint collection | ~50–100 ms |
| `memfd` setup and `fexecve` | ~1 ms |

### Resource Requirements

- **Minimum RAM**: Sufficient to hold the launcher plus the full decrypted payload simultaneously in memory
- **Disk space**: Approximately 2× payload size during compilation (source + compiled output)
- **CPU**: x86_64; AES-NI recommended for encryption/decryption performance

### Scalability Limits

- **Maximum payload size**: Limited by available RAM
- **Maximum concurrent executions**: Limited by host resources and Docker daemon
- **Key rotation**: Manual process requiring re-compilation of all artifacts

## Security Guarantees and Limitations

### What Snapfzz Seal Provides

1. **Encryption** — Strong AES-256-GCM encryption of agent payloads
2. **Binding** — Cryptographic binding to runtime environment fingerprints and launcher binary hash
3. **Verification** — Ed25519 signature verification before execution (integrity, not signer identity)
4. **Anti-extraction** — Memory-only execution on Linux prevents disk-based extraction of the decrypted payload
5. **Sandboxing** — Docker container isolation with resource limits via the server API

### What Snapfzz Seal Does NOT Provide

1. **Hardware attestation** — No TPM or Intel SGX integration
2. **Trusted signer identity** — Signatures verify integrity, not signer identity. An attacker can re-sign a modified artifact and pass embedded-key verification
3. **Perfect secrecy** — Expert-level reverse engineering with full memory access can extract the master secret
4. **Network security** — Agent network traffic is not encrypted or authenticated by Snapfzz Seal
5. **Key distribution** — Secure distribution of signing keys is the operator's responsibility
6. **Runtime integrity monitoring** — Once executing, the agent process is not monitored for tampering
7. **Cross-platform execution** — Only Linux supports sealed agent execution

### Threat Model Summary

Snapfzz Seal is effective against:

- Casual extraction attempts from disk
- Execution on unauthorized machines when fingerprints differ
- Accidental artifact corruption (detected by signature and authentication tag)
- Simple dynamic analysis attempts (raised cost via anti-debugging measures)

Snapfzz Seal is NOT effective against:

- Privileged adversaries with full memory access
- Attackers who can re-sign modified artifacts and control verifier key trust
- Compromised signing keys
- Root-level memory dumping or runtime introspection

For comprehensive threat analysis, see [Threat Model](../security/threat-model.md).

## References

- **AES-256-GCM**: Dworkin, M. (2007). NIST SP 800-38D.
- **HKDF-SHA256**: Krawczyk, H. (2010). RFC 5869.
- **Ed25519**: Bernstein, D. et al. (2012). Journal of Cryptographic Engineering 4(2).
- **Shamir Secret Sharing**: Shamir, A. (1979). CACM 22(11):612–613.
- **White-Box AES**: Chow, S. et al. (2002). SAC 2002, LNCS 2595.

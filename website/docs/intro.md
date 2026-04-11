---
sidebar_position: 1
---

# Snapfzz Seal

Snapfzz Seal is a cryptographic packaging and launch system for sealed agent binaries. The system is intended for environments where runtime binding, integrity verification, and controlled execution are required for operational security.

## Scope and audience

This documentation is written for security engineers, platform engineers, incident responders, and researchers who need an implementation-level understanding of the system.

## Problem statement

Modern agent workloads often include high-value credentials, service tokens, and policy logic. Traditional packaging methods provide partial controls, but several risks remain:

1. A copied binary can be executed in unintended environments.
2. Static artifacts can be analyzed and redistributed.
3. Build provenance is difficult to validate without mandatory signature checks.
4. Secrets may be exposed through weak key handling and unstructured deployment.

## Design objectives

Snapfzz Seal implements five primary controls:

- **Environment-bound decryption** through key derivation from deployment signals (sandbox fingerprint and user fingerprint).
- **Authenticated encryption** of payload data using AES-256-GCM with a 64 KB streaming chunk format.
- **Builder authenticity checks** through Ed25519 signatures appended to the assembled artifact.
- **Anti-analysis protections** including debugger detection, VM detection, software-breakpoint scanning, timing anomaly checks, and environment poisoning on analysis detection.
- **Launcher integrity verification** through SHA-256 hash of the launcher binary at runtime, bound into the key derivation path on Linux.

### What this system is not

Snapfzz Seal is not a general-purpose DRM system. It does not enforce licensing, manage subscription entitlements, or prevent authorized users from inspecting their own runtime environments. The goal is to bind execution to a specific deployment context, not to prevent all forms of reverse engineering.

### Platform requirements

The full protection set requires **Linux**. Anti-analysis protections that rely on `/proc/self/status`, `/proc/self/exe`, and `seccomp-bpf` are Linux-only. macOS and Windows builds compile and run but with reduced protection coverage (seccomp and `/proc`-based checks are no-ops on those platforms).

Execution of the decrypted payload uses `memfd_create` and `fexecve` for the Go backend (no disk write). The PyInstaller and Nuitka backends require a temporary file on disk due to how those runtimes handle self-extracting archives; the temp file is removed after execution.

## High-level lifecycle

```text
source project
  -> seal compile
  -> encrypted assembled payload
  -> seal sign
  -> signed artifact
  -> seal launch
  -> signature check, anti-analysis checks, key derivation, decryption, execution
```

### Phase 1: Compile and assemble

The `seal compile` command compiles an agent project, derives an environment key, encrypts the compiled payload using AES-256-GCM in streaming 64 KB chunks, and assembles the launcher binary with the encrypted payload and metadata footer appended.

### Phase 2: Sign

The `seal sign` command appends a 100-byte signature block to the assembled artifact:

- 4-byte signature magic (`ASL\x02`)
- 64-byte Ed25519 signature over the pre-signature bytes
- 32-byte builder public key

The signature covers the entire artifact up to (but not including) the signature block itself.

### Phase 3: Launch

The `seal launch` command (or direct execution of the artifact) performs the following in order:

1. Verifies the Ed25519 signature against the embedded public key.
2. Runs anti-analysis checks (debugger, VM, breakpoints, timing). Aborts if analysis is detected.
3. Applies anti-debug protections (`prctl(PR_SET_DUMPABLE, 0)` and `ptrace(TRACEME)`) and poisons the environment with decoy data.
4. Collects a fingerprint snapshot of the current environment.
5. Derives the decryption key using HKDF-SHA256 from the master secret, user fingerprint, and environment fingerprint. On Linux, launcher binary integrity is also bound into this derivation.
6. Decrypts the payload in memory.
7. Executes the payload — via `memfd`/`fexecve` for Go, or a temp-file path for Python backends.

## Cryptographic profile

The current profile is defined by implementation constants and should be treated as normative for this release series:

- Symmetric encryption: **AES-256-GCM**
- Key derivation: **HKDF-SHA256** (info strings: `snapfzz-seal/env/v1`, `snapfzz-seal/session/v1`)
- Signature scheme: **Ed25519**
- Hash function: **SHA-256**
- Secret splitting: **Shamir Secret Sharing** over secp256k1 field (5 shares, threshold 3)
- Streaming chunk size: **64 KB**

The following standards are relevant:

- NIST SP 800-38D for GCM operation
- RFC 5869 for HKDF
- RFC 8032 for Ed25519

## Practical example

```bash
# 1) Build and install CLI
cargo install --path crates/snapfzz-seal

# 2) Generate signing keys
seal keygen

# 3) Compile and seal
USER_FP=$(openssl rand -hex 32)
seal compile \
  --project ./examples/demo_agent \
  --user-fingerprint "$USER_FP" \
  --sandbox-fingerprint auto \
  --output ./agent.sealed

# 4) Sign artifact
seal sign --key ~/.snapfzz-seal/keys/builder_secret.key --binary ./agent.sealed

# 5) Launch (Linux required for full protection)
SNAPFZZ_SEAL_MASTER_SECRET_HEX=<64-hex-secret> \
seal launch --payload ./agent.sealed --user-fingerprint "$USER_FP"
```

## Security considerations

- Signing keys should be generated and stored in controlled key management systems.
- Public key distribution should be pinned through trusted channels.
- Launch failures due to fingerprint mismatch indicate that the sandbox environment has changed and re-provisioning is required. These events should be logged and reviewed.
- The master secret (`SNAPFZZ_SEAL_MASTER_SECRET_HEX`) must be treated as a high-value secret. Exposure of this value allows an attacker to derive the decryption key given the corresponding fingerprint.
- Server endpoints should not be exposed without authentication and transport protections.

## Limitations

- Runtime memory compromise is out of scope for software-only controls. A root-level host compromise can bypass all process-level protections.
- `--sandbox-fingerprint auto` is a convenience mode and does not represent measured remote attestation. It collects heuristic environment signals.
- Hardware attestation (TPM, SGX) is not currently implemented.
- The full protection surface — including seccomp-bpf syscall filtering, `/proc`-based checks, and `memfd` in-memory execution — requires Linux x86-64.
- Python-backend payloads (Nuitka, PyInstaller) are written to a temporary file before execution; they are not kept purely in memory.
- The anti-analysis checks are heuristic and are not guaranteed to detect all debugger or virtualization configurations.

## Documentation map

- **Getting started**: installation, quick start, signing workflow
- **Architecture**: binary format, crate layout, compatibility profile
- **Reference**: CLI, encryption, fingerprinting, configuration
- **Security**: threat model and audit history
- **Advanced**: custom backends, cross-platform procedures, server deployment

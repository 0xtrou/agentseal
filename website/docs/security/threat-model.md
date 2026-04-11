---
title: Threat Model
sidebar_position: 1
---

# Threat Model

This document defines the adversary model, protected assets, implemented mitigations, and known security boundaries for Snapfzz Seal. It is written in an academic security-analysis style and attempts to be precise about what the system does and does not provide. Claims are grounded in the current implementation; speculative or aspirational protections are explicitly labelled as such.

---

## 1. Assets Under Protection

| Asset | Description |
|-------|-------------|
| **Agent payload** | The encrypted binary or archive attached to a sealed artifact. Confidentiality depends on key material not being recovered by an unauthorized party. |
| **Master secret** | A 32-byte value split into Shamir shares and embedded in the launcher at compile time. It is the root of the decryption key derivation chain. |
| **Sealed artifact binary** | The self-contained launcher + payload file distributed to execution environments. Integrity of this file is attested by an Ed25519 signature. |
| **Signing private key** | The Ed25519 private key used to sign artifacts at build time. Compromise of this key breaks authenticity for all artifacts signed with it. |

---

## 2. Adversary Model

### 2.1 In-Scope Adversaries

- **Passive artifact readers.** Operators, storage systems, or interceptors with read access to sealed artifact files on disk. Goal: extract payload plaintext or recover the master secret.
- **Replay attackers.** Parties attempting to execute a sealed artifact in an environment for which it was not compiled (mismatched fingerprint components).
- **Tamper attackers.** Parties attempting to modify artifact content in transit or at rest and have the modification accepted by the launcher.
- **Static analysts.** Parties performing binary inspection (disassembly, string search, section parsing) without elevated runtime privileges on the execution host.
- **Basic dynamic analysts (Linux).** Parties attempting to attach a debugger or inspect process memory at the user-privilege level.

### 2.2 Out-of-Scope Adversaries

The following adversary classes are explicitly outside the security boundary of Snapfzz Seal:

- **Adversaries with root or kernel-level access to the execution host.** Such adversaries can read decrypted payload from memory, inject code, bypass seccomp via kernel modules, and disable all user-space protections.
- **Adversaries with physical or hardware-level access.** No TPM, secure enclave (SGX/TrustZone), or side-channel countermeasure beyond basic implementation hygiene is present.
- **Nation-state-grade reverse engineers.** The system is not designed to withstand sustained expert cryptanalysis or automated binary analysis tooling of that calibre.

---

## 3. Implemented Mitigations

### 3.1 Shamir Secret Sharing (5-of-3 threshold)

The master secret is split into five shares at compile time using a (3, 5) Shamir threshold scheme implemented over the secp256k1 prime field (`p = 2²⁵⁶ − 2³² − 977`). Polynomial coefficients are drawn from a cryptographically random source. Each share is embedded in the launcher binary in a dedicated slot located by a compile-time marker.

**What this provides:** An attacker who recovers fewer than three share slots from static analysis cannot reconstruct the secret.

**What this does not provide:** If the binary is fully readable, all five slots are available; an attacker who can read the binary can read all five shares. The scheme offers obfuscation overhead, not information-theoretic secrecy.

### 3.2 Binary Integrity Binding (Linux only)

At launch, the master secret is not used directly. Instead, a derived key is computed as `SHA-256(secret || SHA-256(ELF_code_and_data))`, where the hash covers the executable and data PT\_LOAD segments of the launcher ELF, with the share slots, tamper marker region, and payload sentinel excluded from the digest. This means modifying the launcher binary — even outside the secret regions — invalidates the key and decryption fails.

**What this provides:** Resistance to binary patching attacks that attempt to bypass runtime checks by modifying launcher code outside the embedded secret regions.

**What this does not provide:** On non-Linux platforms, the integrity binding is a no-op; the derived key is `SHA-256(secret || secret)`, which is a deterministic function of the secret alone. The protection does not apply on macOS or Windows.

### 3.3 Ed25519 Signature Chain

Each artifact carries an Ed25519 signature over its payload and metadata. The launcher verifies this signature before executing the payload. Unsigned artifacts or artifacts with invalid signatures are rejected.

**Critical limitation — self-validating signatures:** The public key used for verification is embedded in the artifact itself. The launcher verifies that the signature is consistent with the embedded key, not that the key belongs to a trusted party. An attacker who can replace the artifact can re-sign it with their own key and embed a matching public key; the launcher will accept it. This is integrity verification, not authenticity verification.

For authenticity guarantees, operators must implement external key pinning — verifying the embedded public key against a known-good key obtained out-of-band.

### 3.4 Fingerprint Binding

Decryption keys are derived in part from environment-supplied fingerprint components (host identifiers, user-supplied tokens, or combinations thereof). A payload sealed for one environment will not decrypt correctly in a different environment unless the fingerprint components match.

**What this provides:** Prevents trivially copying and running a sealed artifact on an arbitrary machine.

**What this does not provide:** Fingerprint components are software-derived and can be spoofed by a privileged attacker who controls the execution environment. The system does not use hardware attestation or remote attestation.

### 3.5 Memory-Only Payload Execution (Linux only)

On Linux, the decrypted payload is written to an anonymous `memfd_create` file descriptor and executed via `execveat`, avoiding writing plaintext payload bytes to the filesystem. On non-Linux platforms, a temporary file path is used as a fallback, which does leave a transient plaintext artifact on disk.

### 3.6 Seccomp Syscall Allowlist (Linux x86_64 only)

After launch setup, a BPF seccomp filter is applied that restricts the process to an explicit allowlist of syscalls required for normal operation. Denied syscalls return `EPERM` rather than killing the process. The filter is applied on a best-effort basis: if `seccompiler::apply_filter` fails, the failure is logged but execution continues. The filter is a no-op on non-Linux platforms.

**Scope of the allowlist:** The current allowlist is intentionally broad to accommodate diverse payload runtimes (Python/PyInstaller, Go, network-capable agents). It includes `execve`, `execveat`, `clone`, `clone3`, `socket`, `connect`, `bind`, `listen`, `open`, `unlink`, and similar syscalls. The allowlist reduces attack surface for payloads that attempt to invoke unusual or dangerous syscalls, but it is not a tight sandbox.

**No argument-level filtering:** The current filter does not apply argument constraints to any syscall. For example, `socket` is permitted regardless of address family.

### 3.7 Anti-Debug Protections (Linux only)

Two anti-debug mechanisms are applied on Linux:

1. `prctl(PR_SET_DUMPABLE, 0)` — disables core dumps and restricts `/proc/[pid]/mem` access from unprivileged processes.
2. `ptrace(PTRACE_TRACEME)` — occupies the ptrace slot, preventing a second tracer from attaching (a standard self-ptrace trick).

Both are applied on a best-effort basis; failures are logged as warnings and do not abort execution.

**What is not implemented:** The previous documentation claimed VM detection (VMware, VirtualBox, QEMU, Xen), timing-based debugger detection, breakpoint scanning, and environment poisoning. None of these techniques are present in the current codebase. The implemented protections raise the bar modestly against casual user-level debugger attachment on Linux.

### 3.8 Decoy Position Hints

The compiler embeds a position-hint obfuscation value to obscure the index of the real share set among potential decoy locations. Ten decoy secret values are generated deterministically from a compile-time salt. However, these decoy values are not currently embedded as fake marker-and-share structures in the binary. The decoy mechanism provides position-hint obfuscation only; it does not create additional extraction barriers equivalent in form to the real shares.

---

## 4. Known Gaps and Honest Limitations

### 4.1 Master Secret Is In Memory During Execution

The master secret is reconstructed in process memory at launch time and remains there for the duration of key derivation. Any privileged process that can read memory (e.g., via `/proc/[pid]/mem` with sufficient privilege, or via a debugger attached with root) can recover the secret. There is no secure enclave, encrypted memory region, or key isolation mechanism.

### 4.2 No Key Rotation Mechanism

There is no built-in mechanism for rotating the master secret or the signing key without recompiling and redistributing all affected artifacts. Key compromise requires manual intervention and full artifact replacement.

### 4.3 Fallback to Environment Variable

If Shamir share reconstruction fails (e.g., markers not found or shares corrupted), the launcher falls back to reading a secret from an environment variable. This fallback reduces the effective protection of the Shamir scheme in environments where the fallback variable is set or where an attacker can control the environment.

### 4.4 Integrity Binding Is Linux-Only

On macOS and Windows, the key derivation function does not incorporate any measurement of the binary. Binary patching on these platforms has no effect on decryption key derivation.

### 4.5 Signature Does Not Verify Signer Identity

As noted in §3.3, the embedded public key can be replaced by an attacker who controls the artifact. Without an external trust anchor, the signature provides tamper evidence only — it does not authenticate the source of the artifact.

### 4.6 Seccomp Is Best-Effort and Broad

Application of the seccomp filter is non-fatal on failure. The allowlist is broad enough to not meaningfully restrict most payload workloads, limiting its value as a containment mechanism for malicious payloads.

### 4.7 No Hardware Attestation

The system does not integrate with TPM, Intel SGX, AMD SEV, or any hardware-backed attestation mechanism. All protections are software-only and can be bypassed by an attacker with sufficient host privilege.

### 4.8 `seal verify` Exit Code Behaviour

The `seal verify` command currently returns exit code `0` even when verification yields an `INVALID` or unsigned-artifact result. CI/CD pipelines that rely solely on exit code for pass/fail decisions will behave incorrectly. Output text must be parsed, or the `--pubkey` flag used with external key pinning, to obtain a reliable signal.

---

## 5. Attack Surface Summary

| Phase | Attack Vector | Mitigation | Residual Risk |
|-------|--------------|-----------|--------------|
| Build | Signing key compromise | External key custody (operator responsibility) | Full artifact forgery |
| Build | Compiler supply chain | Standard dependency auditing | Malicious share embedding |
| Distribution | Artifact MITM / replacement | External key pinning, authenticated repos | Re-signing attack succeeds without pinning |
| Launch (Linux) | Static share extraction | Shamir (3-of-5) + integrity binding | All shares readable from disk; binding is key-derivation only |
| Launch (Linux) | Debugger attachment | `PR_SET_DUMPABLE` + `PTRACE_TRACEME` | Bypassable with root |
| Launch (Linux) | Dangerous syscall invocation | Seccomp allowlist (best-effort, broad) | Non-fatal on failure; no argument filtering |
| Launch (non-Linux) | All of the above | None beyond encryption | No runtime protections apply |
| Runtime (any) | Memory extraction | Memory-only execution on Linux | Root can read process memory |
| Runtime (any) | Fingerprint spoofing | Fingerprint binding | Spoofable by privileged attacker |

---

## 6. Recommended Controls Beyond Snapfzz Seal

The following controls are necessary in production deployments and are outside Snapfzz Seal's security boundary:

**Critical**
- HSM or managed KMS for signing key custody.
- Authenticated artifact distribution channel (signed repository, content-addressable store with verification).
- Out-of-band public key pinning to provide authenticity verification.

**Important**
- Host hardening and least-privilege service accounts for the execution environment.
- Network segmentation to limit blast radius of payload compromise.
- Monitoring of verification failures and anomalous launch patterns.

**Recommended**
- Short artifact lifetimes to limit exposure window after key compromise.
- Audit logging of compilation and execution events.
- Documented incident response procedure for signing key compromise.

---

## 7. References

### Cryptographic Standards

- Dworkin, M. (2007). "Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC". NIST Special Publication 800-38D. [doi:10.6028/NIST.SP.800-38D](https://doi.org/10.6028/NIST.SP.800-38D)
- Krawczyk, H. & Eronen, P. (2010). "HMAC-based Extract-and-Expand Key Derivation Function (HKDF)". RFC 5869. [doi:10.17487/RFC5869](https://doi.org/10.17487/RFC5869)
- Bernstein, D. J., Duif, N., Lange, T., Schwabe, P. & Yang, B.-Y. (2012). "High-speed high-security signatures". *Journal of Cryptographic Engineering* 2(2):77–89. [doi:10.1007/s13389-012-0007-1](https://doi.org/10.1007/s13389-012-0007-1)

### Secret Sharing

- Shamir, A. (1979). "How to Share a Secret". *Communications of the ACM* 22(11):612–613. [doi:10.1145/359168.359176](https://doi.org/10.1145/359168.359176)

### Security Principles

- Saltzer, J. H. & Schroeder, M. D. (1975). "The Protection of Information in Computer Systems". *Proceedings of the IEEE* 63(9):1278–1308. [doi:10.1109/PROC.1975.9939](https://doi.org/10.1109/PROC.1975.9939)

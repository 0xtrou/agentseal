---
sidebar_position: 3
---

# How It Works

This section describes the internal execution path of Snapfzz Seal from source compilation to in-memory launch.

## End-to-end flow

```text
project source
  -> compile backend (nuitka / pyinstaller / go)
  -> compiled agent binary
  -> key derivation (HKDF-SHA256)
  -> marker embedding (5 Shamir shares + tamper hash + white-box tables)
  -> sentinel + encrypted payload assembly
  -> footer write
  -> signature append
  -> [runtime] signature verification
  -> [runtime] Shamir secret reconstruction
  -> [runtime] key derivation + integrity binding
  -> [runtime] in-memory decryption (AES-256-GCM)
  -> [runtime] memfd execution (Linux only)
```

## Detailed technical sequence

### 1. Compilation stage

`seal compile` selects a backend based on `--backend` (default: `nuitka`). The supported backends are:

- **Nuitka** — Compiles a Python project to a standalone native binary.
- **PyInstaller** — Packages a Python project to a self-contained executable.
- **Go** — Builds a Go project with `go build`.

The output of this stage is a compiled agent binary (ELF on Linux).

### 2. Key derivation stage

An environment key is derived from the master secret and the two fingerprint inputs:

```text
env_key = HKDF-SHA256(
    IKM  = master_secret,
    salt = stable_fingerprint_hash || user_fingerprint,
    info = "snapfzz-seal/env/v1"
)
```

Where:

- `master_secret` — A freshly generated 256-bit random secret, unique per compile invocation.
- `stable_fingerprint_hash` — SHA-256 of canonicalized host signals (machine ID, hostname, kernel release, etc.), or the explicit hex string passed via `--sandbox-fingerprint`.
- `user_fingerprint` — The 64-hex-character value passed via `--user-fingerprint`.

An integrity key is then derived by additionally binding the launcher binary content, so decryption requires an unmodified launcher:

```text
integrity_key = HKDF-SHA256(env_key, SHA-256(launcher_bytes), "snapfzz-seal/integrity/v1")
```

### 3. Launcher embedding stage

The `seal-launcher` binary is patched in memory with the following embedded values, in order:

1. **Master secret via Shamir shares** — The master secret is split into 5 shares with a threshold of 3 using Shamir secret sharing over a prime field. Each share is written into a dedicated marker slot in the launcher binary. The markers are derived deterministically from `BUILD_ID`, so a mismatched `BUILD_ID` between the `seal` CLI and `seal-launcher` will produce markers that cannot be found.
2. **Decoy secrets** — 50 decoy marker slots are embedded to complicate static analysis.
3. **Tamper hash** — A SHA-256 hash of the launcher-with-shares is embedded into the launcher's tamper marker slot. The launcher checks this at runtime to detect modifications.
4. **White-box tables** — Approximately 165 KB of lookup tables are embedded. These tables are generated from the master secret. The launcher currently uses standard AES-GCM decryption; white-box decryption integration is in progress.

### 4. Payload encryption stage

The compiled agent binary is encrypted using AES-256-GCM with the integrity key:

```text
encrypted_payload = AES-256-GCM(key=integrity_key, plaintext=agent_binary)
```

The payload is streamed in 64 KB chunks. Each chunk carries a 7-byte nonce and a 16-byte authentication tag.

### 5. Assembly stage

The final artifact is structured as:

```text
[launcher_binary_with_embedded_shares_and_tables]
[PAYLOAD_SENTINEL  (32 bytes, BUILD_ID-derived)]
[encrypted_payload (header + encrypted chunks)]
[payload_footer    (64 bytes: original_hash + launcher_hash + backend_type)]
```

### 6. Signing stage

`seal sign` reads the assembled artifact, computes an Ed25519 signature over the entire binary content, and appends a 100-byte block:

```text
[artifact bytes]
[ASL\x02 magic   (4 bytes)]
[Ed25519 signature (64 bytes)]
[embedded public key (32 bytes)]
```

The signing key (`--key`) is a hex-encoded 32-byte Ed25519 private key. The corresponding public key is read from the same directory automatically.

### 7. Launch stage (Linux only)

`seal launch` performs the following steps on Linux:

1. **Reads the artifact** from the path given by `--payload`.
2. **Validates the signature block** — checks for the `ASL\x02` magic and verifies the Ed25519 signature. Execution is aborted if the signature is invalid or absent.
3. **Anti-analysis checks** — detects debugger attachment via ptrace and `TracerPid`, VM indicators (VMware, VirtualBox, QEMU strings), and timing anomalies.
4. **Launcher integrity check** — verifies the launcher binary hash against the value stored in the payload footer.
5. **Shamir secret reconstruction** — locates 3 or more of the 5 embedded share slots and reconstructs the master secret.
6. **Key derivation** — re-derives `env_key` and `integrity_key` using the runtime fingerprints.
7. **In-memory decryption** — decrypts the payload using AES-256-GCM. The decrypted bytes are never written to disk.
8. **`memfd` execution** — writes the decrypted binary to an anonymous `memfd_create` file, seals it, and calls `fexecve` to execute it as a child process.

## Cryptographic primitives

| Primitive | Use |
|-----------|-----|
| AES-256-GCM | Authenticated payload encryption/decryption |
| HKDF-SHA256 | Key derivation from master secret and fingerprints |
| SHA-256 | Binary integrity hashes; marker derivation |
| Ed25519 | Artifact signing and verification |
| HMAC-SHA256 | Header authentication field |
| Shamir secret sharing | Master secret split across 5 shares (3-of-5 threshold) |

## Memory layout during runtime

```text
+-----------------------------------------------------------+
| launcher process                                           |
|                                                           |
| read artifact -> verify signature -> integrity check      |
|                        |                                  |
|                        v                                  |
|              reconstruct master_secret                    |
|              (3 of 5 Shamir shares)                       |
|                        |                                  |
|                        v                                  |
|              derive env_key + integrity_key               |
|                        |                                  |
|                        v                                  |
|              AES-256-GCM decrypt (in-memory buffer)       |
|                        |                                  |
|                        v                                  |
|              memfd_create + write + fexecve               |
+-----------------------------------------------------------+
```

Key material is zeroized after use where implemented. The decrypted payload bytes exist in process memory only for the interval between decryption and `fexecve`.

## BUILD_ID requirement

All cryptographic markers — the Shamir share slot positions, the payload sentinel, the tamper marker slot, the white-box table slot, and the decoy marker positions — are derived from the `BUILD_ID` environment variable at compile time via SHA-256:

```text
marker_bytes = SHA-256(BUILD_ID || label || "deterministic_marker_v1")
```

If `BUILD_ID` is not set, it defaults to `"dev"`. The `seal` CLI and `seal-launcher` must be built with the same `BUILD_ID`. A mismatch will cause marker lookup to fail during assembly or during runtime secret reconstruction.

## Security considerations

- Signature validation occurs before decryption and execution.
- Integrity checks bind the decryption key to the launcher binary hash. Any modification to the launcher invalidates the decryption key.
- Linux seccomp-bpf filtering is applied after execution begins (best-effort; a failure to install the filter is logged and execution continues).
- The white-box table embedding is implemented; full white-box decryption at runtime is in progress. Currently, standard AES-GCM decryption is used.

## Limitations

- Complete resistance to runtime memory inspection is not provided. A privileged process can read decrypted payload bytes from process memory.
- Platform behavior differs significantly outside Linux. All runtime hardening features are Linux-specific.
- Security properties depend on a trustworthy host kernel and userspace boundary.
- White-box decryption integration is in progress. The launcher currently performs standard AES-GCM decryption.

## References

- **AES-GCM**: Dworkin, M. (2007). NIST SP 800-38D. Galois/Counter Mode specification.
- **HKDF**: Krawczyk, H. (2010). RFC 5869. HMAC-based Extract-and-Expand Key Derivation Function.
- **Shamir Secret Sharing**: Shamir, A. (1979). "How to Share a Secret". CACM 22(11):612–613.
- **White-Box Cryptography**: Chow, S. et al. (2002). "White-Box Cryptography and an AES Implementation". SAC 2002, LNCS 2595.
- **Defense-in-Depth**: Saltzer & Schroeder (1975). "The Protection of Information in Computer Systems". Proc. IEEE 63(9).

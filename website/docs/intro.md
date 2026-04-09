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

Snapfzz Seal implements four primary controls:

- **Environment-bound decryption** through key derivation from deployment signals.
- **Authenticated encryption** of payload data using AES-256-GCM.
- **Builder authenticity checks** through Ed25519 signatures.
- **In-memory execution path** to avoid writing decrypted payloads to disk.

## High-level lifecycle

```text
source project
  -> seal compile
  -> encrypted assembled payload
  -> seal sign
  -> signed artifact
  -> seal launch
  -> signature check, key derivation, in-memory execution
```

### Phase 1: Compile and assemble

The `seal compile` command compiles an agent project, derives an environment key, encrypts the compiled payload, and appends metadata required by the launcher.

### Phase 2: Sign

The `seal sign` command appends a 100-byte signature block:

- 4-byte signature magic (`ASL\x02`)
- 64-byte Ed25519 signature
- 32-byte builder public key

### Phase 3: Launch

The `seal launch` command verifies the signature, evaluates runtime fingerprint data, derives decryption material, decrypts in memory, and starts execution through the launcher runtime.

## Cryptographic profile

The current profile is defined by implementation constants and should be treated as normative for this release series:

- Symmetric encryption: **AES-256-GCM**
- Key derivation: **HKDF-SHA256**
- Signature scheme: **Ed25519**
- Hash function: **SHA-256**

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

# 5) Launch
SNAPFZZ_SEAL_MASTER_SECRET_HEX=<64-hex-secret> \
seal launch --payload ./agent.sealed --user-fingerprint "$USER_FP"
```

## Security considerations

- Signing keys should be generated and stored in controlled key management systems.
- Public key distribution should be pinned through trusted channels.
- Launch failures due to fingerprint mismatch should be logged and reviewed as potential tamper or drift events.
- Server endpoints should not be exposed without authentication and transport protections.

## Limitations

- Runtime memory compromise is out of scope for software-only controls.
- Root-level host compromise can bypass process-level protections.
- `--sandbox-fingerprint auto` is a convenience mode and does not represent measured remote attestation.
- Hardware attestation is not currently implemented.

## Documentation map

- **Getting started**: installation, quick start, signing workflow
- **Architecture**: binary format, crate layout, compatibility profile
- **Reference**: CLI, encryption, fingerprinting, configuration
- **Security**: threat model and audit history
- **Advanced**: custom backends, cross-platform procedures, server deployment

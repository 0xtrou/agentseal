# Threat Model

This document defines the explicit adversary model and security boundaries for Snapfzz Seal.

## Security objectives

The system is designed to:

1. Increase effort required to extract sensitive payload data from distributed artifacts.
2. Bind decryption to environment-derived inputs.
3. Enforce signature validation before execution.
4. Reduce plaintext disk artifacts during launch.

## Adversary model

### In-scope adversaries

- Operators with read access to artifact files.
- Attackers attempting replay across unintended environments.
- Attackers attempting artifact tampering in transit or at rest.
- Analysts performing static inspection without full host privilege.

### Out-of-scope adversaries

- Attackers with persistent root control of execution host.
- Attackers with kernel-level instrumentation and memory extraction capability.
- Physical adversaries with hardware-level invasive access.

## Security guarantees

### Integrity

- Signature verification is required by launcher path for accepted payload execution.
- Payload header integrity is protected via HMAC over core metadata.
- Launcher hash in footer is checked for tamper evidence in Linux path.

### Confidentiality

- Payload confidentiality relies on AES-256-GCM with derived keys.
- Decryption keys are bound to supplied fingerprint components.

### Execution controls

- Linux runtime path applies process protection hooks and seccomp filtering.
- Decrypted payload bytes are executed from memory-backed file descriptors.

## Attack surface analysis

### Build and sign phase

- Signing key storage and CI runner trust
- Compiler backend supply chain dependencies
- Artifact handling and publication channels

### Distribution phase

- Artifact interception and replacement
- Public key distribution integrity

### Launch phase

- Input parameter manipulation (`--user-fingerprint`, environment secret values)
- Runtime host drift affecting fingerprint matching
- Memory and process introspection by privileged local actors

### Server API phase

- API misuse if exposed without authentication
- Sandbox backend command execution pathways
- Artifact retrieval and job state manipulation

## Known limitations

- Runtime memory compromise can expose decrypted material.
- Host compromise can bypass software controls.
- `auto` sandbox fingerprint mode is convenience-oriented and not equivalent to measured attestation.
- Authentication and authorization for server APIs are deployment responsibilities outside default process behavior.

## Recommended controls beyond Snapfzz Seal

- Host hardening and least-privilege service accounts.
- Strong network segmentation and authenticated service perimeter.
- Key custody through HSM or managed KMS.
- Continuous monitoring of verification failures and unusual launch patterns.

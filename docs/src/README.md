# Agent Seal

![Build](https://github.com/0xtrou/agent-seal/blob/main/docs/badges/build-status.svg)
![Coverage](https://github.com/0xtrou/agent-seal/blob/main/docs/badges/coverage.svg)
![Rust](https://github.com/0xtrou/agent-seal/blob/main/docs/badges/rust-version.svg)

**Encrypted, sandbox-bound agent delivery system for Linux.**

Agent Seal compiles AI agents into sealed binaries that:
- Bind decryption to runtime environment fingerprints
- Execute entirely from memory (memfd + fexecve)
- Verify builder signatures before launch
- Protect API keys with AES-256-GCM encryption

## Quick Links

- [Installation](./getting-started/installation.md) — Get up and running
- [Quick Start](./getting-started/quick-start.md) — Seal your first agent in 5 minutes
- [CLI Reference](./reference/cli.md) — All commands and options
- [Threat Model](./security/threat-model.md) — What's protected, what's not

## Core Workflow

```text
┌─────────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│ seal compile│ ──▶ │  seal sign  │ ──▶ │ seal launch │ ──▶ │   agent    │
│  encrypt &  │     │  Ed25519    │     │  verify &   │     │  executes  │
│   assemble  │     │  signature  │     │   decrypt   │     │  in memory │
└─────────────┘     └─────────────┘     └─────────────┘     └─────────────┘
```

## Features

| Feature | Description |
|---------|-------------|
| **AES-256-GCM encryption** | Streaming chunk encryption with 64 KiB blocks |
| **HKDF key binding** | Dual derivation binds to stable + ephemeral fingerprints |
| **Ed25519 signatures** | Mandatory builder identity verification |
| **memfd execution** | Payload never touches disk |
| **seccomp hardening** | Syscall allowlist + PR_SET_NO_NEW_PRIVS |
| **Orchestration API** | REST API for compile/dispatch/result collection |

## Platform Support

| Platform | Launcher | Status |
|----------|----------|--------|
| Linux x86_64 | Full (memfd + seccomp) | Stable |
| macOS arm64 | Stub (decrypt only) | Foundation |
| Windows x86_64 | Stub (no-op) | Foundation |

See [Compatibility Matrix](./architecture/compatibility.md) for details.

## Security

Agent Seal raises attacker cost and narrows abuse windows. It is **not** a replacement for:
- Host-level trust and attestation
- Root-level compromise protection
- Hardware-backed security modules

See [Threat Model](./security/threat-model.md) for the full security posture.

## License

MIT OR Apache-2.0
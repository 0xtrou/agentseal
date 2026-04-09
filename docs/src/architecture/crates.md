# Crate Overview

Agent Seal is a Rust workspace with 6 crates.

## Crates

| Crate | Type | Role |
|-------|------|------|
| `agent-seal` | bin | Umbrella CLI (`seal` command) |
| `agent-seal-core` | lib | Crypto, types, payload primitives |
| `agent-seal-fingerprint` | lib | Fingerprint collection |
| `agent-seal-launcher` | bin | Runtime launcher |
| `agent-seal-compiler` | lib + bin | Build and seal pipeline |
| `agent-seal-server` | bin | Orchestration API |

## Dependencies

```text
agent-seal (CLI)
  ├── agent-seal-compiler
  ├── agent-seal-launcher
  └── agent-seal-server

agent-seal-compiler
  ├── agent-seal-core
  └── agent-seal-fingerprint

agent-seal-launcher
  ├── agent-seal-core
  └── agent-seal-fingerprint

agent-seal-server
  ├── agent-seal-compiler
  └── (sandbox backends)
```

## Key Modules

### agent-seal-core

- `crypto` — AES-256-GCM streaming encryption
- `derive` — HKDF key derivation
- `payload` — Pack/unpack, header, footer
- `signing` — Ed25519 signature primitives
- `tamper` — Binary hash verification
- `types` — Constants, markers, structs

### agent-seal-fingerprint

- `collector` — Signal collection
- `canonicalize` — Stable/ephemeral canonicalization
- `signals` — Individual signal extractors

### agent-seal-launcher

- `memfd_exec` — Memory execution via memfd + fexecve
- `protection` — seccomp, PR_SET_*, anti-debug
- `cleanup` — Self-delete, env scrub
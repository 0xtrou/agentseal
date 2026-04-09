# Threat Model

## Protected Against

| Threat | Mechanism |
|--------|-----------|
| Casual payload extraction | AES-256-GCM encryption + memfd execution |
| Cross-environment replay | HKDF binding to fingerprints |
| Provider API key exposure | Keys encrypted at rest in payload |
| Payload tampering | Ed25519 signatures + launcher hash verification |

### Qualifications

- **Master secret:** Embedded in binary, recoverable via known marker scan (`ASL_SECRET_MRK_v1...`)
- **Tamper verification:** Linux-only — skipped on macOS/Windows
- **Signatures:** Mandatory enforcement added in commit `977a6dc` (Apr 9, 2026)

## Not Protected Against

| Threat | Reason |
|--------|--------|
| Root-level compromise | Out of scope |
| Hardware attestation bypass | Not implemented |
| Memory extraction by privileged adversary | Out of scope |
| Local process environment inspection | Env var fallback exposes secret in `/proc/[pid]/environ` |
| Server API exposure | Unauthenticated; must stay on localhost |
| Static binary analysis | Known marker allows secret extraction |

## Summary

Agent Seal raises attacker cost and narrows abuse windows. It is **not** a replacement for:
- Host-level trust
- Hardware attestation systems
- Secure key distribution infrastructure

## Security Audit History

See [Security Audits](./audits.md) for the full audit trail.
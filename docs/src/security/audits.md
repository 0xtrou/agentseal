# Security Audit History

Agent Seal has undergone multiple security audits during development.

## Audit Summary

| Round | Date | Findings | Status |
|-------|------|----------|--------|
| Initial Security | Apr 8, 2026 | 15 | ✅ All fixed |
| Revised Security | Apr 9, 2026 | 8 | ✅ All fixed |
| Architectural #1 | Apr 9, 2026 | 5 | ✅ All documented |
| Architectural #2 | Apr 9, 2026 | 2 | ✅ All fixed |
| Claims vs Reality | Apr 9, 2026 | 12 | ✅ All addressed |

**Total:** 42 findings, all resolved.

## Key Fixes

### Mandatory Signature Enforcement

**Commit:** `977a6dc`  
**Issue:** Signature verification was silently optional.  
**Fix:** `verify_signature()` now returns `Err(MissingSignature)` for unsigned payloads.

### Tamper Detection

**Commit:** `d7c118a`  
**Issue:** Hash mismatch between assembly (launcher only) and launch (full binary).  
**Fix:** Use `footer.launcher_hash` with sentinel-based boundary detection.

### io_uring in Seccomp

**Commit:** `977a6dc`  
**Issue:** io_uring syscalls in allowlist (container escape vector).  
**Fix:** Removed syscalls 425/426/427 from allowlist.

### Master Secret Extraction

**Commit:** `0af048f`  
**Issue:** Known marker pattern allows secret extraction.  
**Fix:** Documented in threat model; protection is against casual inspection only.

## Breaking Changes

| Change | Commit | Impact |
|--------|--------|--------|
| Mandatory signing | `977a6dc` | Pre-existing unsigned payloads rejected |
| io_uring removal | `977a6dc` | Agents using io_uring killed by seccomp |
| Tamper fix | `d7c118a` | Old assembled binaries may fail tamper check |

## Current State

- **Tests:** 381 passing
- **Coverage:** 93.19%
- **Critical findings:** 0 open
- **Documentation:** All security properties documented
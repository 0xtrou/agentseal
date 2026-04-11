---
title: Security Audits
sidebar_position: 2
---

# Security Audits

This page documents the security review status of Snapfzz Seal. It is written to be accurate rather than reassuring: where formal work has not been conducted, that is stated plainly.

---

## Current Status

**No formal third-party security audit has been conducted on Snapfzz Seal.**

The project has not been reviewed by an independent security firm, has not been submitted to a public bug-bounty programme, and has not undergone a structured penetration test by a party external to its development. Any prior page content suggesting otherwise was inaccurate and has been corrected here.

---

## Internal Review Activity

The codebase has undergone iterative internal review during development. This includes:

- Code review of cryptographic paths (key derivation, Shamir splitting and reconstruction, AES-256-GCM usage, Ed25519 signing and verification) by the project authors.
- Identification and correction of implementation defects in signature enforcement, tamper detection, and seccomp profile construction, tracked via commits in the project repository.
- Documentation review to align stated security properties with actual implementation behaviour, resulting in corrections to the threat model.

Internal review is a necessary but not sufficient basis for security assurance. It does not substitute for independent analysis.

---

## Known Implementation Corrections

The following categories of issues have been identified and addressed during internal development cycles. These are shared for transparency; they do not constitute a formal findings register.

- **Signature enforcement:** Early launcher versions did not unconditionally enforce signature verification on all execution paths. This was corrected to require valid signature before payload execution.
- **Tamper detection hash handling:** The integrity hash computation incorrectly included or excluded regions in some cases, causing false positives or gaps in tamper detection coverage. Corrected in the ELF region parser.
- **Seccomp profile scope:** The initial seccomp allowlist was insufficient for certain payload runtimes (Python/PyInstaller onefile extraction, Go runtime startup, subprocess network operations), causing launcher failures. Extended iteratively to cover observed requirements.
- **Documentation accuracy:** Prior security documentation overstated the anti-debug capability (claiming VM detection, timing checks, and breakpoint scanning that were not implemented) and overstated the decoy mechanism (describing 55 active extraction barriers that do not exist in the current runtime path). These claims have been removed.

---

## What a Future Audit Should Cover

A thorough independent security audit of Snapfzz Seal should include at minimum:

**Cryptographic correctness**
- Shamir secret sharing implementation over the secp256k1 prime field: field arithmetic, polynomial evaluation, Lagrange interpolation, randomness quality of coefficients.
- AES-256-GCM key derivation chain: HKDF usage, nonce generation, tag verification behaviour on failure.
- Ed25519 signature generation and verification: key serialisation, canonicalisation, and rejection of malformed inputs.
- Integrity binding: correctness of ELF segment parsing, exclusion region logic, and hash-to-key derivation.

**Implementation and integration**
- Marker search and share embedding in `embed.rs`: correct identification of real marker slots, absence of off-by-one errors, behaviour when markers are absent or duplicated.
- Launcher execution path: ordering of security setup (seccomp, anti-debug, signature verification, key derivation) and failure handling at each stage.
- Fallback behaviour: conditions under which the environment-variable secret fallback is triggered, and whether that fallback can be forced by an attacker.
- `seal verify` exit code semantics: whether output parsing is necessary for correct CI integration.

**Platform coverage and limits**
- Non-Linux paths: confirm that integrity binding, seccomp, and anti-debug no-ops do not introduce unexpected trust assumptions.
- Temporary file execution fallback on non-Linux: assess plaintext exposure window.

**Operational security**
- Key generation and storage recommendations: adequacy of current documentation for production deployments.
- Signing key pinning gap: risk characterisation and recommended mitigations for the self-validating signature model.

---

## Reporting Security Issues

If you identify a security vulnerability in Snapfzz Seal, please report it through the project's private disclosure channel rather than filing a public issue. Contact details are available in the project repository's `SECURITY.md` file.

---

## Audit Hygiene Expectations

If a formal audit is commissioned in the future, the following practices should be observed:

- All findings should be recorded against specific commit hashes and reproducible test cases.
- Remediation should address both code and documentation when a security property changes.
- Audit evidence (reports, finding trackers, remediation commits) should be retained with immutable artifact hashes for traceability.
- A public summary of findings and their resolution status should be published after remediation, consistent with responsible disclosure norms.

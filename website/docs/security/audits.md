# Security Audits

This document summarizes recorded audit activities and tracked remediation state.

## Audit history summary

| Audit stream | Findings | Current status |
|---|---:|---|
| Initial security review | 15 | Resolved |
| Revised security review | 8 | Resolved |
| Architectural review | 7 | Resolved |
| Claims and implementation consistency review | 12 | Resolved |

Total findings tracked in project history: **42**.

## Findings and resolutions

The following categories were addressed during remediation cycles:

- Signature enforcement behavior in launch path
- Tamper detection correctness and hash handling
- Sandbox hardening profile adjustments
- Documentation of secret extraction limitations

Representative remediation references mentioned in prior project records:

- `977a6dc` for mandatory signature enforcement and seccomp profile adjustment
- `d7c118a` for tamper detection correction
- `0af048f` for security documentation updates regarding secret exposure limits

## Audit process expectations

A typical audit pass in this project should include:

1. Source review of cryptographic and launch-critical paths.
2. Validation of signature and integrity failure behavior.
3. Verification of threat-model alignment with implementation.
4. Regression checks for previously fixed findings.

## Practical verification examples

```bash
# signature verification baseline
seal verify --binary ./agent.sealed --pubkey ~/.snapfzz-seal/keys/builder_public.key

# launch failure path check with wrong fingerprint
seal launch --payload ./agent.sealed --user-fingerprint <mismatched-fingerprint>
```

Expected behavior:

- Invalid signature artifacts are rejected.
- Fingerprint mismatch prevents successful decryption.

## Security considerations

- Audit evidence should be retained with immutable artifact hashes.
- Findings should map to commit references and reproducible test cases.
- Remediation should include both code change and documentation update when behavior changes.

## Limitations

- This page summarizes repository-tracked findings and does not constitute third-party certification.
- Public details may omit sensitive exploit reproduction information by design.

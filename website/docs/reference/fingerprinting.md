# Fingerprinting

Snapfzz Seal uses host and runtime signals to derive deterministic binding material for decryption keys.

## Collection methodology

Fingerprint data is collected by `FingerprintCollector` and split into two sets:

- **Stable set**: expected to persist across process restarts on the same environment profile
- **Ephemeral set**: expected to vary across sessions or namespace contexts

Signals are normalized and converted into typed source records with confidence and stability metadata.

## Host signal sources

### Stable and semi-stable sources

- `linux.machine_id_hmac`
- `linux.hostname`
- `linux.kernel_release`
- `linux.cgroup_path`
- `linux.proc_cmdline_hash`
- `linux.mac_address`
- `linux.dmi_product_uuid_hmac`

### Ephemeral sources

- `linux.mount_namespace_inode`
- `linux.pid_namespace_inode`
- `linux.net_namespace_inode`
- `linux.uts_namespace_inode`

## Canonicalization process

Source records are canonicalized through deterministic ordering and length-prefixed encoding, then hashed with SHA-256.

```text
canonical_hash = SHA256( concat(sorted_sources(id, value)) )
```

This procedure is applied separately to stable and ephemeral sets.

## Runtime modes

### Stable mode

Only stable source set is used in derivation flow.

### Session mode

Stable set produces env key. Ephemeral set is then applied for session key derivation.

## Practical collection example

```rust
use snapfzz_seal_fingerprint::FingerprintCollector;

let collector = FingerprintCollector::new();
let snapshot = collector.collect().unwrap();
println!("stable sources: {}", snapshot.stable.len());
println!("ephemeral sources: {}", snapshot.ephemeral.len());
```

## Stability considerations

- Hostname and cgroup path are treated as semi-stable and may drift with orchestration changes.
- Namespace inode signals are expected to change between short-lived container sessions.
- Hardware and kernel updates can alter selected stable signals.

## Security considerations

- Source values may include host-identifying material. Access **MUST** be controlled.
- HMAC wrapping is used for selected identifiers when app key context is available.
- Fingerprint mismatch events **SHOULD** be monitored as either drift or adversarial replay indicators.

## Limitations

- Fingerprints are software-observed and do not constitute hardware attestation.
- Environments with aggressive mutation of host metadata can reduce stable binding reliability.
- `sandbox-fingerprint auto` in compile flow does not provide measured remote fingerprint identity.

## References

- **HMAC**: Krawczyk, H., Bellare, M., & Canetti, R. (1997). RFC 2104. HMAC: Keyed-Hashing for Message Authentication.
- **SHA-256**: NIST FIPS 180-4. Secure Hash Standard.

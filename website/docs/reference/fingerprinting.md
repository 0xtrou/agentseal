---
sidebar_position: 5
---

# Fingerprinting

Snapfzz Seal collects host and runtime signals to produce deterministic hash values that are bound into the decryption key derivation chain. This document describes what is collected, how it is canonicalized, and how the resulting hashes are used.

Source code: `crates/snapfzz-seal-fingerprint/src/`.

---

## Overview

The `FingerprintCollector` reads host signals and partitions them into two sets:

- **Stable set**: signals expected to remain constant across process restarts on the same host or container image profile (kernel, machine identity, hardware)
- **Ephemeral set**: signals expected to change between container sessions or namespace recreations (Linux namespace inodes)

Each set is independently canonicalized to a 32-byte SHA-256 hash. Those hashes feed into HKDF key derivation (see [Encryption](./encryption.md)).

---

## Signal sources

All 11 sources are enabled by default. Sources are defined in `FINGERPRINT_SOURCES` in `crates/snapfzz-seal-fingerprint/src/model.rs`.

### Stable sources (placed in the stable set)

| Source ID | Stability class | Privileged | Description |
|-----------|----------------|------------|-------------|
| `linux.machine_id_hmac` | Stable | No | HMAC-SHA256 (with app key) or SHA-256 (fallback) of `/etc/machine-id` |
| `linux.kernel_release` | Stable | No | Kernel release string from `uname` (lowercased) |
| `linux.proc_cmdline_hash` | Stable | No | SHA-256 of allowlisted boot arguments from `/proc/cmdline` |
| `linux.mac_address` | Stable | No | Raw bytes of the first non-loopback MAC address from `/sys/class/net` |
| `linux.dmi_product_uuid_hmac` | Stable | Yes | HMAC-SHA256 (with app key) or SHA-256 (fallback) of `/sys/class/dmi/id/product_uuid` |

### Semi-stable sources (placed in the stable set)

Semi-stable sources are collected into the **stable** snapshot alongside fully stable sources. They are treated as stable for key derivation purposes but may drift under orchestration changes.

| Source ID | Stability class | Privileged | Description |
|-----------|----------------|------------|-------------|
| `linux.hostname` | SemiStable | No | Normalized (lowercased, trimmed) kernel hostname |
| `linux.cgroup_path` | SemiStable | No | Normalized cgroup path from `/proc/self/cgroup`; container-ID segments are stripped |

### Ephemeral sources (placed in the ephemeral set)

| Source ID | Stability class | Privileged | Description |
|-----------|----------------|------------|-------------|
| `linux.mount_namespace_inode` | Ephemeral | No | Inode number of `/proc/self/ns/mnt` |
| `linux.pid_namespace_inode` | Ephemeral | No | Inode number of `/proc/self/ns/pid` |
| `linux.net_namespace_inode` | Ephemeral | No | Inode number of `/proc/self/ns/net` |
| `linux.uts_namespace_inode` | Ephemeral | No | Inode number of `/proc/self/ns/uts` |

Namespace inodes are read by following the symlink at the namespace path and parsing the inode number from the link target (e.g., `mnt:[4026531840]` yields `"4026531840"`).

---

## Collection details

### App key

The `FingerprintCollector` may be initialized with an optional 32-byte `app_key`. When an app key is present, HMAC-SHA256 is used for `linux.machine_id_hmac` and `linux.dmi_product_uuid_hmac` instead of plain SHA-256. This scopes the fingerprint values to the application context.

### Cgroup path normalization

The cgroup path collector reads `/proc/self/cgroup`, selects the unified hierarchy (empty-controller) entry when available (cgroup v2), and falls back to the first non-empty entry. The path is:

1. Lowercased and trimmed.
2. Split into segments; trailing segments that look like container IDs (8+ hex digits, optionally prefixed with `docker-`, `containerd-`, or `cri-containerd-`, optionally suffixed with `.scope`) are stripped.

This normalization keeps the structural path (e.g., `/system.slice/docker.service`) while removing ephemeral container-specific suffixes.

### `/proc/cmdline` allowlist

Only the following boot argument keys are retained when computing `linux.proc_cmdline_hash`:

```
root, ro, rw, console, panic, init, quiet, cgroup_no_v1,
systemd.unified_cgroup_hierarchy, systemd.legacy_systemd_cgroup_controller,
firecracker, boot, nomodeset
```

Arguments not in this list are discarded before hashing. This reduces sensitivity to transient or irrelevant kernel parameters.

### Stable-only collection

`FingerprintCollector::collect_stable_only()` populates the stable set and returns an empty ephemeral set. This is used by `seal compile` when `--sandbox-fingerprint auto` is specified.

---

## Canonicalization

Each set (stable or ephemeral) is independently canonicalized using a deterministic encoding defined in `crates/snapfzz-seal-fingerprint/src/canonical.rs`.

### Algorithm

1. Sort sources by ID string (lexicographic byte order).
2. For each source in sorted order, encode:
   - ID length as a big-endian `u16`
   - ID bytes (UTF-8)
   - Value length as a big-endian `u32`
   - Value bytes (raw)
3. Concatenate all encoded records.
4. Compute SHA-256 of the concatenated bytes.

```text
canonical_hash = SHA-256(
  concat(
    for each source (sorted by id):
      u16_be(len(id)) || id_bytes ||
      u32_be(len(value)) || value_bytes
  )
)
```

This encoding is injection-free: the length prefix for each field prevents ambiguous concatenations. Source ordering is deterministic regardless of collection order.

An empty source set produces a consistent hash (SHA-256 of an empty byte string).

---

## Runtime modes

The fingerprint mode is selected with `--fingerprint-mode` on `seal launch`.

### Stable mode (default)

Only the stable set canonicalization is used. The resulting 32-byte hash feeds into the environment key derivation:

```
env_key = HKDF-SHA256(master_secret, stable_hash || user_fingerprint, "snapfzz-seal/env/v1")
```

The decryption key is `env_key`.

### Session mode

Both sets are used in a two-step derivation:

```
env_key     = HKDF-SHA256(master_secret, stable_hash || user_fingerprint, "snapfzz-seal/env/v1")
session_key = HKDF-SHA256(env_key, ephemeral_hash, "snapfzz-seal/session/v1")
```

The decryption key is `session_key`. Session mode binds the decryption key to the specific Linux namespace context (mount, PID, network, UTS namespace inodes) of the launch environment.

### Compile-time fingerprint binding

`seal compile --sandbox-fingerprint auto` calls `collect_stable_only()` on the build host and uses `canonicalize_stable()` of that snapshot as the `stable_hash` embedded in the sealed artifact. This binds the artifact to the stable fingerprint of the compile environment.

Supplying an explicit 64-hex value overrides this with a caller-provided hash.

---

## API usage

```rust
use snapfzz_seal_fingerprint::FingerprintCollector;
use snapfzz_seal_fingerprint::{canonicalize_stable, canonicalize_ephemeral};

// Collect all signals (stable + ephemeral)
let collector = FingerprintCollector::new();
let snapshot = collector.collect().unwrap();
let stable_hash = canonicalize_stable(&snapshot);
let ephemeral_hash = canonicalize_ephemeral(&snapshot);

// Collect stable signals only
let snapshot_stable = collector.collect_stable_only().unwrap();
assert!(snapshot_stable.ephemeral.is_empty());

// With app key (scopes HMAC-protected sources to the application)
let collector = FingerprintCollector::with_app_key([0x42u8; 32]);
let snapshot = collector.collect().unwrap();
```

---

## Stability considerations

- `linux.hostname` and `linux.cgroup_path` are classified `SemiStable`. Container orchestrators that reassign hostnames or cgroup paths on each deployment will cause the stable hash to change.
- `linux.kernel_release` changes on kernel updates.
- `linux.mac_address` may be absent or change in some virtualized or containerized environments.
- `linux.dmi_product_uuid_hmac` requires read access to `/sys/class/dmi/id/product_uuid`, which may not be available in all container configurations (privileged source).
- Namespace inodes change between container restarts; they are intentionally placed in the ephemeral set.

---

## Security considerations

- Source values include host-identifying material. Access to fingerprint snapshots must be controlled.
- HMAC wrapping for `linux.machine_id_hmac` and `linux.dmi_product_uuid_hmac` requires the `app_key` to produce the same digest. Without the app key, a plain SHA-256 digest is used instead.
- Fingerprint mismatch events (decryption failure at launch) should be monitored as indicators of environment drift or adversarial replay.
- Fingerprints are software-observed values. They do not constitute hardware attestation and can be spoofed by a sufficiently privileged adversary.

---

## Limitations

- Environments that aggressively mutate host metadata reduce the reliability of stable binding.
- `--sandbox-fingerprint auto` binds to the build host's fingerprint, not to a measured remote sandbox identity.
- No hardware attestation (TPM, vTPM) is integrated.

---

## References

- **HMAC**: Krawczyk, H., Bellare, M., & Canetti, R. (1997). RFC 2104. HMAC: Keyed-Hashing for Message Authentication.
- **SHA-256**: NIST FIPS 180-4. Secure Hash Standard.
- **HKDF**: Krawczyk, H. (2010). RFC 5869.

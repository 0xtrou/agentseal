# Fingerprinting

Agent Seal binds decryption to runtime environment fingerprints.

## Signal Types

### Stable Signals

Restart-survivable, consistent across reboots:

| Signal | Platform | Description |
|--------|----------|-------------|
| Machine ID HMAC | Linux | `/etc/machine-id` or `/var/lib/dbus/machine-id` |
| Hostname | Linux | System hostname |
| Kernel release | Linux | `uname -r` |
| Cgroup path | Linux | Container cgroup path |
| Proc cmdline hash | Linux | Kernel cmdline hash (low entropy in cloud) |
| MAC address | Linux | Primary network interface |
| DMI product UUID | Linux | Hardware UUID |

### Ephemeral Signals

Session-level, vary across restarts:

| Signal | Platform | Description |
|--------|----------|-------------|
| Namespace inodes | Linux | mnt/pid/net/uts namespace IDs |
| UIDs | Linux | User/group IDs |

## Collection Modes

### stable (default)

Uses only stable signals. Best for:
- Persistent environments
- Long-running containers
- VMs with stable identities

### session

Includes ephemeral signals. Best for:
- Short-lived containers
- Stricter binding requirements
- Environments where namespaces change

## Important Notes

> **Host-level signals:** Stable fingerprints collect host-level signals (machine-id, hostname, kernel, DMI UUID). These are shared across containers on the same host. In homogeneous cloud fleets, actual binding uniqueness depends on `user_fingerprint` + `sandbox_fingerprint`.

> **Not hardware-attested:** Runtime detection is heuristic-based (cgroups, `/proc` files, env vars), not TPM/SNP-attested. It is advisory metadata.

## sandbox-fingerprint

### auto (default)

Generates a cryptographically random 32-byte nonce. **Not a real sandbox measurement.**

For actual environment binding:
1. Run `seal fingerprint` inside the target sandbox
2. Pass the collected fingerprint explicitly

### Explicit Fingerprint

```bash
# Collect fingerprint in target environment
seal fingerprint --mode stable > sandbox.fp

# Use during compile
seal compile \
  --project ./agent \
  --user-fingerprint $USER_FP \
  --sandbox-fingerprint $(cat sandbox.fp) \
  --output ./agent.sealed
```
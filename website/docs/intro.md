---
sidebar_position: 1
---

# Agent Seal

**Encrypted, sandbox-bound agent delivery system for Linux.**

Agent Seal compiles AI agents into sealed binaries that bind decryption to runtime environment fingerprints, execute entirely from memory, and verify builder signatures before launch.

## Why Agent Seal Exists

Deploying AI agents in production presents unique security challenges that traditional containerization and code signing cannot address:

### The Problem

**API keys embedded in agent binaries** — AI agents require API keys (OpenAI, Anthropic, internal services) to function. These keys are typically stored in environment variables, config files, or compiled directly into binaries. Once an attacker obtains the binary, they can extract keys and use them elsewhere.

**No runtime binding** — A binary compiled for "production" runs anywhere: staging, developer laptops, attacker-controlled VMs. There's no cryptographic binding between the binary and its intended execution environment.

**Disk-based extraction** — Traditional deployment writes binaries to disk, creating forensic artifacts and enabling reverse engineering attacks.

**Supply chain uncertainty** — How do you verify that a binary was built by your CI/CD pipeline and not tampered with during distribution?

### What Agent Seal Provides

Agent Seal addresses these problems through cryptographic binding and runtime enforcement:

| Problem | Solution |
|---------|----------|
| Keys extractable from binary | AES-256-GCM encryption with environment-bound keys |
| Runs on any machine | Decryption keys derived from runtime fingerprints |
| Disk artifacts | memfd execution (payload never touches disk) |
| Supply chain attacks | Mandatory Ed25519 signature verification |

## How It Works

Agent Seal implements a three-phase security model:

### Phase 1: Compile & Encrypt

```
[Agent Source] → [seal compile] → [Encrypted Payload]
                         ↓
                   Fingerprint binding:
                   - User fingerprint (provided)
                   - Sandbox fingerprint (auto-detected)
```

The `seal compile` command encrypts your agent using a key derived from two fingerprints:

1. **User fingerprint** — Arbitrary identifier you control (e.g., customer ID, deployment UUID)
2. **Sandbox fingerprint** — Runtime environment measurements (kernel version, CPU features, mount points)

Only an environment matching both fingerprints can derive the decryption key.

### Phase 2: Sign

```
[Encrypted Payload] → [seal sign] → [Signed Binary]
                              ↓
                        Ed25519 signature
```

The `seal sign` command attaches an Ed25519 signature proving the binary was built by a trusted key holder. The launcher refuses to execute unsigned or invalidly-signed binaries.

### Phase 3: Launch

```
[Signed Binary] → [seal launch] → [Agent Process]
                        ↓
                  Verification chain:
                  1. Verify signature
                  2. Derive decryption key from fingerprints
                  3. Decrypt payload in memory
                  4. Execute via memfd + fexecve
```

The `seal launch` command:

1. Verifies the Ed25519 signature (fails if missing/invalid)
2. Measures the runtime environment
3. Derives the decryption key using HKDF
4. Decrypts the payload entirely in memory
5. Executes the agent without writing to disk

## What Agent Seal Protects Against

Agent Seal raises the cost of various attacks:

| Attack Vector | Protection Level |
|---------------|------------------|
| Binary extraction from disk | **Protected** — Payload encrypted, key bound to environment |
| Running on unauthorized machines | **Protected** — Wrong fingerprint = wrong key = decryption fails |
| Offline brute-force | **Protected** — AES-256-GCM with 256-bit key |
| Supply chain tampering | **Protected** — Mandatory Ed25519 signature verification |
| Runtime memory inspection | **Not protected** — Decrypted in memory during execution |
| Root-level host compromise | **Not protected** — Attacker can read decryption key from memory |
| Physical hardware tampering | **Not protected** — Requires hardware attestation |

**Important**: Agent Seal is a cost-raising measure, not a perfect security boundary. It significantly raises the bar for attackers but cannot prevent all attacks. See [Threat Model](./security/threat-model) for detailed analysis.

## When To Use Agent Seal

Agent Seal is appropriate when:

- **Deploying AI agents with embedded secrets** — API keys, database credentials, internal tokens
- **Distributing binaries to untrusted environments** — Customer machines, edge devices, multi-tenant infrastructure
- **Enforcing runtime binding** — Ensuring binaries only execute in designated environments
- **Preventing casual key extraction** — Raising the bar beyond `strings binary | grep API_KEY`

Agent Seal is **not** appropriate when:

- You need hardware-level attestation (use TPM/SGX instead)
- You're protecting against nation-state adversaries with physical access
- Your threat model includes root-level host compromise
- You need formal security certification

## Best Practices

### Fingerprint Strategy

**User fingerprint** — Use a stable identifier tied to your deployment:
- Customer ID or tenant UUID for multi-tenant systems
- Deployment ID from your orchestration platform
- Combination: `${customer_id}-${environment}`

**Sandbox fingerprint** — Balance stability vs security:
- `auto` — Automatically detect stable host signals (kernel, CPU, mounts)
- Manual — Pin to specific values if you control the environment
- Avoid overly-specific values that break on kernel updates

### Key Management

- Store signing keys in HSM or secure key management systems
- Rotate keys regularly and maintain a key rotation schedule
- Use separate keys for development, staging, and production
- Never commit private keys to version control

### Signature Enforcement

- Always run `seal sign` after `seal compile`
- The launcher rejects unsigned binaries by default
- Distribute public keys securely to execution environments

### Operational Security

- Generate master secrets from cryptographically secure random sources
- Transmit secrets via secure channels (mTLS, encrypted config systems)
- Log verification failures for security monitoring
- Monitor for unusual decryption failure patterns (potential attack indicator)

## Quick Start

Get started in 5 minutes:

```bash
# Install
cargo install --path crates/agent-seal

# Generate signing keys
seal keygen

# Compile your agent
seal compile \
  --project ./examples/demo_agent \
  --user-fingerprint $CUSTOMER_ID \
  --sandbox-fingerprint auto \
  --output ./agent.sealed

# Sign the binary
seal sign --key ~/.agent-seal/keys/key --binary ./agent.sealed

# Launch on target machine
seal launch --payload ./agent.sealed \
  --user-fingerprint $CUSTOMER_ID
```

See [Installation](./getting-started/installation) for detailed setup instructions.

## Architecture Overview

Agent Seal consists of three main crates:

| Crate | Purpose |
|-------|---------|
| `agent-seal` | CLI tool for compile, sign, launch operations |
| `agent-seal-core` | Encryption, fingerprinting, signing primitives |
| `agent-seal-launcher` | Runtime decryption and execution engine |

See [Architecture](./architecture/how-it-works) for detailed technical documentation.

## License

MIT OR Apache-2.0
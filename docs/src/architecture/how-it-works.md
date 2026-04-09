# How It Works

The Agent Seal workflow in 7 steps:

## 1. Compile

`seal compile` turns source projects into Linux executables:
- Detects backend (Nuitka, PyInstaller, Go)
- Compiles agent to static ELF
- Encrypts with AES-256-GCM

## 2. Encrypt

The artifact is chunk-encrypted:
- 64 KiB chunks
- AES-256-GCM per chunk
- Key derived from master secret + fingerprints

## 3. Assemble

Launcher + encrypted payload combined:
- Embeds master secret in launcher
- Appends payload with sentinel marker
- Adds footer with hashes

## 4. Sign

Builders sign with Ed25519:
- Signature covers header + payload + footer
- Appends signature block + pubkey

## 5. Distribute

Ship the sealed binary:
- Single file: launcher + payload + signature
- Distribute pubkey separately (out-of-band)

## 6. Launch

Runtime verification and execution:
1. Verify Ed25519 signature
2. Collect runtime fingerprint
3. Derive decryption key via HKDF
4. Decrypt payload chunks
5. Verify launcher tamper hash
6. Execute from memory (memfd + fexecve)

## 7. Capture

Execution output collected:
- stdout/stderr/exit code
- Timeout enforcement (interactive mode)

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│ seal compile│ ──▶ │  seal sign  │ ──▶ │ seal launch │ ──▶ │   agent    │
│  encrypt &  │     │  Ed25519    │     │  verify &   │     │  executes  │
│   assemble  │     │  signature  │     │   decrypt   │     │  in memory │
└─────────────┘     └─────────────┘     └─────────────┘     └─────────────┘
```
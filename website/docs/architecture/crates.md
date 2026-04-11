# Crate Overview

This section describes the crate-level architecture and API surface of Snapfzz Seal.

## Workspace members

The workspace contains exactly six crates:

| Crate | Responsibility |
|---|---|
| `snapfzz-seal` | Primary CLI entrypoint (`seal`) |
| `snapfzz-seal-core` | Cryptographic primitives, payload types, error model |
| `snapfzz-seal-fingerprint` | Host and runtime signal collection and canonicalization |
| `snapfzz-seal-compiler` | Project compilation, payload assembly, embed operations |
| `snapfzz-seal-launcher` | Runtime verification, key derivation, in-memory execution |
| `snapfzz-seal-server` | Orchestration API and Docker sandbox dispatch |

## Dependency graph

The following graph reflects actual `path` dependencies declared in each crate's `Cargo.toml`. `snapfzz-seal-fingerprint` and `snapfzz-seal-core` have no internal dependencies.

```text
snapfzz-seal (CLI)
  -> snapfzz-seal-core
  -> snapfzz-seal-compiler
      -> snapfzz-seal-core
      -> snapfzz-seal-fingerprint
  -> snapfzz-seal-launcher
      -> snapfzz-seal-core
      -> snapfzz-seal-fingerprint
  -> snapfzz-seal-server
      -> snapfzz-seal-core
      -> snapfzz-seal-compiler
      -> snapfzz-seal-fingerprint
  -> snapfzz-seal-fingerprint
```

`snapfzz-seal-core` is the cryptographic and structural foundation. `snapfzz-seal-fingerprint` is a leaf crate with no dependency on any other workspace member. Note that `snapfzz-seal-server` does **not** depend on `snapfzz-seal-launcher`; the launcher is a separate binary and not consumed as a library by the server.

## API surface by crate

### `snapfzz-seal`

- CLI command tree (`compile`, `keygen`, `launch`, `server`, `sign`, `verify`)
- Argument mapping to lower-level crate interfaces
- Process exit behavior for command failures

Example command dispatch entry:

```rust
match cli.command {
    Command::Compile(cli) => compile::run(cli),
    Command::Launch(cli) => launch::run(cli),
    Command::Sign(cli) => sign::run(cli),
    // ...
}
```

### `snapfzz-seal-core`

Key exported modules include:

- `crypto`: stream encryption and decryption
- `derive`: HKDF-based key derivation
- `payload`: header parsing, payload packing and unpacking
- `signing`: Ed25519 key generation, sign and verify
- `tamper`: hash and integrity verification helpers
- `types`: canonical constants and wire structures (`MAGIC_BYTES`, `VERSION_V1`, `ENC_ALG_AES256_GCM`, `FMT_STREAM`, `CHUNK_SIZE`, `PayloadHeader`, `PayloadFooter`, `BackendType`, `AgentMode`)

### `snapfzz-seal-fingerprint`

- `FingerprintCollector` for stable and ephemeral data capture
- `canonicalize_stable` and `canonicalize_ephemeral` for deterministic hashing
- Source model registry through `FINGERPRINT_SOURCES`

This crate has no workspace-internal dependencies and can be compiled independently.

### `snapfzz-seal-compiler`

- `CompileBackend` trait and three backend implementations: `NuitkaBackend`, `PyInstallerBackend`, `GoBackend`
- `assemble` stage for launcher plus payload composition
- Marker-based embed utilities for launcher metadata
- Decoy secret generation and embedding (`decoys`)
- Shamir share splitting and embedding (`embed`)

Detection heuristics: Nuitka and PyInstaller detect `main.py`; Go detects `go.mod`.

### `snapfzz-seal-launcher`

- Signature verification before execution
- Runtime fingerprint-driven key derivation
- Launcher integrity checks
- `MemfdExecutor` for in-memory execution of statically-linked ELF binaries (Go backend)
- `TempFileExecutor` for temp-file-based execution of Python bundled binaries (PyInstaller, Nuitka)
- seccomp BPF filter installation (Linux only)
- Anti-debug and environment analysis (`anti_analysis`)
- Environment variable denylist to prevent secret leakage into child processes

### `snapfzz-seal-server`

- HTTP routes for compile, dispatch, and job status
- `DockerBackend` as the only sandbox implementation (hardcoded)
- Asynchronous job state transitions and artifact management

## Practical usage example

A minimal end-to-end integration from CLI perspective:

```bash
seal compile --project ./examples/demo_agent --user-fingerprint "$USER_FP" --output ./agent.sealed
seal sign --key ~/.snapfzz-seal/keys/builder_secret.key --binary ./agent.sealed
seal launch --payload ./agent.sealed --user-fingerprint "$USER_FP"
```

## Security architecture

### Defense-in-depth layers

Snapfzz Seal implements multiple security layers to protect master secrets:

| Layer | Module | Protection |
|-------|--------|------------|
| 1 | `build.rs` | Compile-time random marker generation |
| 2 | `shamir.rs` | Shamir Secret Sharing across five shares (threshold: 3) |
| 3 | `decoys.rs` | Decoy secret set generation and embedding |
| 4 | `anti_analysis.rs` | Runtime debugger and VM detection |
| 5 | `integrity.rs` | Binary hash binding |
| 6 | `whitebox/` | White-box AES-256 lookup table cryptography (~165KB tables) |

### Key security components

#### `snapfzz-seal-core`
- `shamir`: Shamir Secret Sharing (prime field with secp256k1 modulus), 5 total shares, threshold 3
- `integrity`: ELF binary parsing and integrity verification
- `whitebox`: White-box AES-256 with T-boxes and mixing tables
- `build.rs`: Compile-time random marker generation

#### `snapfzz-seal-compiler`
- `decoys`: Decoy secret set generation and embedding
- `whitebox_embed`: White-box table generation and binary embedding
- `embed`: Shamir share splitting and embedding

#### `snapfzz-seal-launcher`
- `anti_analysis`: Runtime environment analysis (debugger, VM, timing)
- `seccomp`: BPF allowlist filter for Linux x86_64
- `integrity`: Binary hash computation and verification

## Security considerations

- Cryptographic operations are centralized in `snapfzz-seal-core` to reduce duplicated logic.
- Signature verification is executed by the launcher before payload execution.
- The server crate should be deployed with strict perimeter controls due to its orchestration capabilities.
- The `unsafe_code = "deny"` workspace lint is enforced; the few `#[allow(unsafe_code)]` sites (seccomp, memfd) are explicitly annotated.

## Limitations

- API stability policy across crate internals is not formally versioned yet.
- Backend behavior depends on host toolchain availability and may vary by environment.
- Cross-crate interfaces are documented by source and tests, not yet by generated API reference docs.

## References

### Cryptographic foundations

- **AES-GCM**: Dworkin, M. (2007). NIST SP 800-38D.
- **Shamir Secret Sharing**: Shamir, A. (1979). "How to Share a Secret". CACM 22(11):612-613.
- **White-Box AES**: Chow, S. et al. (2002). SAC 2002, LNCS 2595.
- **Ed25519**: Bernstein, D. et al. (2012). Journal of Cryptographic Engineering 4(2).
- **HKDF**: Krawczyk, H. (2010). RFC 5869.

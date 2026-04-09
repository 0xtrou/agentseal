# Multi-Platform Support

This document describes cross-compilation strategy and platform adaptation requirements.

## Deployment baseline

Linux remains the primary production runtime target for full security behavior. Other operating systems may support development or partial workflows.

## Cross-compilation procedures

### Build workspace artifacts

```bash
cargo build --release --workspace
```

### Example target build

```bash
# target toolchain installation example
rustup target add x86_64-unknown-linux-gnu

# build launcher for target
cargo build --release -p snapfzz-seal-launcher --target x86_64-unknown-linux-gnu
```

### Compile command alignment

The compile stage should reference launcher binaries built for intended runtime architecture.

```bash
seal compile \
  --project ./examples/demo_agent \
  --user-fingerprint "$USER_FP" \
  --sandbox-fingerprint auto \
  --output ./agent.sealed \
  --launcher ./target/x86_64-unknown-linux-gnu/release/snapfzz-seal-launcher
```

## Platform-specific adaptations

### Linux

- Uses Linux process and syscall controls.
- Supports seccomp filter enforcement path.
- Supports primary in-memory launch behavior.

### macOS

- Uses platform-specific anti-debug hook attempts.
- Behavior differs from Linux hardening semantics.

### Windows

- Requires explicit validation for equivalent runtime assumptions.
- Current workflows should be considered limited and non-equivalent for hardened launch paths.

## Verification strategy

For each platform target:

1. Run CLI smoke tests (`--help`, `keygen`, `verify`).
2. Validate compile output and artifact structure.
3. Validate launch failure semantics for invalid signature and fingerprint mismatch.
4. Record differences in runtime hardening behavior.

## Security considerations

- Platform parity must not be assumed.
- Threat model acceptance should be documented per target OS.
- Production controls should be tied to tested kernel and runtime combinations.

## Limitations

- Full hardening capability is Linux-centric.
- Cross-platform build success does not imply equivalent runtime protection.

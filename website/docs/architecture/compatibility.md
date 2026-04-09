# Compatibility

This section summarizes current platform support and feature availability.

## Platform support matrix

| Platform | Compile CLI | Launch verification | In-memory execution path | Hardening controls | Status |
|---|---|---|---|---|---|
| Linux x86_64 | Supported | Supported | Supported (`memfd` + exec flow) | Supported (seccomp and anti-debug path) | Production target |
| macOS arm64 | Supported for selected workflows | Partial | Partial and platform-dependent | Limited | Development use |
| Windows x86_64 | Supported for selected workflows | Limited | Limited | Limited | Experimental/non-production |

## Feature availability by platform

| Capability | Linux | macOS | Windows |
|---|---|---|---|
| Signature verification | Yes | Yes | Yes |
| Payload header validation | Yes | Yes | Yes |
| Launcher tamper verification path | Yes | Partial | Partial |
| Seccomp filter enforcement | Yes | No | No |
| Linux namespace-derived fingerprint signals | Yes | No | No |
| Docker sandbox backend (server) | Yes | Host dependent | Host dependent |

## Compile backend compatibility

| Compile backend | Expected host dependencies | Notes |
|---|---|---|
| Nuitka | Python toolchain and Nuitka packages | Preferred default in CLI mapping |
| PyInstaller | Python and PyInstaller | Alternative Python backend |
| Go backend | Go toolchain | Available in compiler crate |

## Operational recommendations

- Use Linux for production launch paths that require documented runtime controls.
- Treat non-Linux deployments as compatibility workflows, not equivalent security profiles.
- Validate backend toolchain availability in CI before release artifact generation.

## Verification commands

```bash
# identify host
uname -a

# confirm CLI availability
seal --version
seal compile --help
seal launch --help

# inspect runtime logs
RUST_LOG=info seal launch --payload ./agent.sealed --user-fingerprint "$USER_FP"
```

## Security considerations

- Security guarantees are platform-scoped, not platform-agnostic.
- Hardening controls relying on Linux kernel mechanisms are not transferable to other kernels.
- Production policy should explicitly restrict deployment targets.

## Limitations

- A formal long-term support matrix by OS version is not currently published.
- Compatibility assertions outside tested CI environments should be treated as provisional until validated in local threat modeling.

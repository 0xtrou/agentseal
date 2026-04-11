---
sidebar_position: 1
---

# Custom Backends

This page documents the extension points for compile backends and sandbox backends in Snapfzz Seal. Both are defined as Rust traits. There is no plugin ABI: custom implementations must be compiled into the binary or linked as a Rust crate.

## Compile backend interface

The `CompileBackend` trait is defined in `crates/snapfzz-seal-compiler/src/backend/mod.rs`. All three built-in backends (Nuitka, PyInstaller, Go) implement it directly.

```rust
pub trait CompileBackend: Send + Sync {
    fn name(&self) -> &str;
    fn can_compile(&self, project_dir: &Path) -> bool;
    fn compile(&self, config: &CompileConfig) -> Result<PathBuf, SealError>;
}
```

### CompileConfig

The `CompileConfig` struct is passed to every `compile` call:

```rust
pub struct CompileConfig {
    pub project_dir: PathBuf,
    pub output_dir: PathBuf,
    pub target_triple: String,
    pub timeout_secs: u64,
}
```

Note that `target_triple` is available in the config but it is the backend's responsibility to use it. The built-in Go backend reads `GOARCH` from the environment and hardcodes `GOOS=linux`, ignoring `target_triple` directly. Custom backends should apply similar or stronger cross-compilation discipline.

### Method contracts

**`name`** — Returns a short identifier used in log output and error messages. Should be unique within any chain.

**`can_compile`** — Inspects `project_dir` and returns `true` if the backend can handle the project. This call should be deterministic and side-effect free. The `ChainBackend` calls this before attempting `compile`.

**`compile`** — Performs the compilation. On success, returns a `PathBuf` pointing to the output artifact on the local filesystem. On failure, returns a `SealError`; use `SealError::CompilationError(String)` for build failures and `SealError::CompilationTimeout(u64)` for timeout conditions. The caller is responsible for creating `output_dir` before calling `compile` if it does not already exist.

### Reference implementation: Go backend

The Go backend (`crates/snapfzz-seal-compiler/src/backend/golang.rs`) is the cleanest reference implementation:

- `can_compile` checks for `go.mod` in `project_dir`.
- `compile` invokes `go build -ldflags="-s -w" -o <output> .` with `CGO_ENABLED=0`, `GOOS=linux`, and `GOARCH` derived from the host architecture or the `GOARCH` environment variable.
- Compilation runs with a thread-sleep polling loop so timeout is enforced without blocking the async runtime.
- If the `go` binary is not on `PATH`, the error maps to `SealError::CompilationError("go not found")`.

```rust
pub struct GoBackend;

impl CompileBackend for GoBackend {
    fn name(&self) -> &str {
        "go"
    }

    fn can_compile(&self, project_dir: &Path) -> bool {
        project_dir.join("go.mod").exists()
    }

    fn compile(&self, config: &CompileConfig) -> Result<PathBuf, SealError> {
        let go_cfg = GoConfig {
            project_dir: config.project_dir.clone(),
            output_dir: config.output_dir.clone(),
            timeout_secs: config.timeout_secs,
        };
        compile_with_go(&go_cfg)
    }
}
```

### Reference implementation: PyInstaller backend

The PyInstaller backend (`crates/snapfzz-seal-compiler/src/backend/pyinstaller.rs`) illustrates Python project compilation:

- `can_compile` checks for `main.py` in `project_dir`.
- `compile` invokes `pyinstaller --onefile --distpath <output_dir> --workpath <tmp> --specpath <tmp> --name <project_name> main.py`.
- The backend also scans `stderr` for the strings `Error:`, `error:`, and `FAILED` in addition to checking the exit code, because PyInstaller sometimes exits 0 on partial failure.
- Default timeout is 1800 seconds (30 minutes).

### Implementing a custom backend

A minimal skeleton:

```rust
use snapfzz_seal_compiler::backend::{CompileBackend, CompileConfig};
use snapfzz_seal_core::error::SealError;
use std::path::{Path, PathBuf};

pub struct MyBackend;

impl CompileBackend for MyBackend {
    fn name(&self) -> &str {
        "my-backend"
    }

    fn can_compile(&self, project_dir: &Path) -> bool {
        // Return true if this backend recognises the project layout.
        project_dir.join("my_manifest.toml").exists()
    }

    fn compile(&self, config: &CompileConfig) -> Result<PathBuf, SealError> {
        let output = config.output_dir.join("agent");

        // Invoke your toolchain, enforce config.timeout_secs,
        // write the artifact to `output`, and return its path.

        if !output.exists() {
            return Err(SealError::CompilationError(
                "build succeeded but output was not produced".to_string(),
            ));
        }

        Ok(output)
    }
}
```

## ChainBackend

`ChainBackend` composes multiple `CompileBackend` implementations. It iterates backends in order, skipping those where `can_compile` returns `false`. If a backend returns an error, the chain logs a warning and tries the next eligible backend. If no backend succeeds, it returns `SealError::CompilationError` with a message indicating no backend could compile the project.

```rust
let chain = ChainBackend::new(vec![
    Box::new(NuitkaBackend),
    Box::new(PyInstallerBackend),
]);
```

A backend that returns `false` from `can_compile` is never passed to `compile`. A backend that returns `true` from `can_compile` but then fails `compile` causes the chain to fall through to the next eligible backend.

## Sandbox backend interface

The `SandboxBackend` trait is defined in `crates/snapfzz-seal-server/src/sandbox/mod.rs` and is used by the server to run sealed artifacts inside isolated containers.

```rust
#[async_trait]
pub trait SandboxBackend: Send + Sync {
    async fn provision(&self, config: &SandboxConfig) -> Result<SandboxHandle, SealError>;
    async fn copy_into(
        &self,
        handle: &SandboxHandle,
        host_path: &Path,
        target: &str,
    ) -> Result<(), SealError>;
    async fn exec(
        &self,
        handle: &SandboxHandle,
        command: &str,
        timeout_secs: u64,
    ) -> Result<ExecutionResult, SealError>;
    async fn destroy(&self, handle: &SandboxHandle) -> Result<(), SealError>;
    fn runtime_kind(&self) -> RuntimeKind;
}
```

### Supporting types

```rust
pub struct SandboxHandle {
    pub id: String,
    pub container_id: Option<String>,
    pub vm_id: Option<String>,
    pub socket_path: Option<String>,
    pub config: SandboxConfig,
    pub backend_data: HashMap<String, String>,
}

pub struct SandboxConfig {
    pub image: String,
    pub env: Vec<(String, String)>,
    pub memory_mb: Option<u64>,
    pub timeout_secs: u64,
}
```

### Method contracts

**`provision`** — Allocates a new isolated execution unit (container, VM, etc.) and returns a `SandboxHandle`. The handle must remain valid until `destroy` is called. A `backend_data` map in the handle is available for storing backend-specific state such as the container ID.

**`copy_into`** — Transfers a file from the host at `host_path` into the sandbox at `target`. Implementations should validate that the target path is within expected bounds and not subject to path traversal.

**`exec`** — Runs `command` inside the sandbox with the given timeout. Returns `ExecutionResult` containing `exit_code`, `stdout`, and `stderr`. Timeout enforcement is the responsibility of the implementation.

**`destroy`** — Terminates and cleans up the execution unit. This should be called even after exec failure. Implementations should aim to be idempotent.

**`runtime_kind`** — Returns the `RuntimeKind` variant that identifies this backend type for fingerprinting and diagnostics.

### Built-in implementation: DockerBackend

`DockerBackend` is the only production sandbox backend. It locates the `docker` binary at construction time using `PATH` discovery, and each `provision` call runs:

```
docker run -d \
  --security-opt no-new-privileges:true \
  --cap-drop ALL \
  --read-only \
  --tmpfs /tmp \
  --pids-limit 64 \
  [--memory Nm] \
  [-e KEY=VALUE ...] \
  <image> sleep <timeout_secs>
```

`copy_into` uses `docker cp`. `exec` runs `docker exec`. `destroy` calls `docker rm -f`.

### Custom sandbox backend skeleton

```rust
use async_trait::async_trait;
use snapfzz_seal_server::sandbox::{SandboxBackend, SandboxConfig, SandboxHandle};
use snapfzz_seal_core::{error::SealError, types::ExecutionResult};
use snapfzz_seal_fingerprint::model::RuntimeKind;
use std::path::Path;

pub struct MySandboxBackend;

#[async_trait]
impl SandboxBackend for MySandboxBackend {
    async fn provision(&self, config: &SandboxConfig) -> Result<SandboxHandle, SealError> {
        // Start an isolated execution unit.
        unimplemented!()
    }

    async fn copy_into(
        &self,
        handle: &SandboxHandle,
        host_path: &Path,
        target: &str,
    ) -> Result<(), SealError> {
        // Transfer artifact into the sandbox.
        unimplemented!()
    }

    async fn exec(
        &self,
        handle: &SandboxHandle,
        command: &str,
        timeout_secs: u64,
    ) -> Result<ExecutionResult, SealError> {
        // Run command inside the sandbox, enforcing timeout.
        unimplemented!()
    }

    async fn destroy(&self, handle: &SandboxHandle) -> Result<(), SealError> {
        // Terminate and clean up the sandbox.
        unimplemented!()
    }

    fn runtime_kind(&self) -> RuntimeKind {
        RuntimeKind::Unknown
    }
}
```

## Validation checklist

- Unit tests covering `can_compile` for both positive and negative project layouts.
- Unit test for the `name` return value.
- Compilation failure propagation test using a known-bad project or a missing toolchain binary.
- Timeout test using a command that exceeds the configured limit.
- For sandbox backends: lifecycle tests covering provision, copy, exec, and destroy in sequence.
- Negative test for missing toolchain binary producing an appropriate `SealError::CompilationError("... not found")` message.

## Security considerations

- Validate all externally supplied paths before passing them to subprocesses or filesystem operations. Do not trust `project_dir` or `target` path components.
- Enforce `timeout_secs` strictly. Build tools and container runtimes can hang indefinitely without explicit timeout management.
- Filter environment variables passed into sandbox environments. The launcher enforces an `ENV_DENYLIST` covering internal secret variables; sandbox backends should not expose them either.
- Apply least-privilege container flags by default. The built-in `DockerBackend` drops all capabilities, sets read-only root filesystem, and limits PIDs.

## Stability note

The `CompileBackend` and `SandboxBackend` traits are internal Rust interfaces with no formal versioning guarantee. Any crate implementing them must be kept in sync with the `snapfzz-seal-compiler` and `snapfzz-seal-server` crates respectively. Breaking changes may occur without a major version bump while the project is pre-1.0.

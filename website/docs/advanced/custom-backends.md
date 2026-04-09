# Custom Backends

This section documents extension points for compile and sandbox backend implementations.

## Compile backend interface

Custom compile backends implement the `CompileBackend` trait.

```rust
pub trait CompileBackend: Send + Sync {
    fn name(&self) -> &str;
    fn can_compile(&self, project_dir: &Path) -> bool;
    fn compile(&self, config: &CompileConfig) -> Result<PathBuf, SealError>;
}
```

### Implementation requirements

- `can_compile` should be deterministic for identical project input.
- `compile` should return a path to a valid compiled executable artifact.
- Errors should use descriptive `SealError` variants to support operator diagnosis.

### Integration pattern

Backends may be composed in a chain.

```rust
let chain = ChainBackend::new(vec![
    Box::new(NuitkaBackend),
    Box::new(PyInstallerBackend),
]);
```

## Sandbox backend interface

Custom sandbox runtimes implement `SandboxBackend`.

```rust
#[async_trait]
pub trait SandboxBackend: Send + Sync {
    async fn provision(&self, config: &SandboxConfig) -> Result<SandboxHandle, SealError>;
    async fn copy_into(&self, handle: &SandboxHandle, host_path: &Path, target: &str) -> Result<(), SealError>;
    async fn exec(&self, handle: &SandboxHandle, command: &str, timeout_secs: u64) -> Result<ExecutionResult, SealError>;
    async fn destroy(&self, handle: &SandboxHandle) -> Result<(), SealError>;
    fn runtime_kind(&self) -> RuntimeKind;
}
```

### Implementation requirements

- `provision` should return a unique handle that can be safely destroyed.
- `copy_into` should reject path traversal and unsafe destination handling.
- `exec` should enforce timeout semantics.
- `destroy` should be idempotent where practical.

## Example skeleton

```rust
pub struct MyBackend;

#[async_trait]
impl SandboxBackend for MyBackend {
    async fn provision(&self, config: &SandboxConfig) -> Result<SandboxHandle, SealError> {
        // create runtime
        unimplemented!()
    }

    async fn copy_into(&self, handle: &SandboxHandle, host_path: &Path, target: &str) -> Result<(), SealError> {
        // transfer artifact
        unimplemented!()
    }

    async fn exec(&self, handle: &SandboxHandle, command: &str, timeout_secs: u64) -> Result<ExecutionResult, SealError> {
        // execute command
        unimplemented!()
    }

    async fn destroy(&self, handle: &SandboxHandle) -> Result<(), SealError> {
        // cleanup
        unimplemented!()
    }

    fn runtime_kind(&self) -> RuntimeKind {
        RuntimeKind::Unknown
    }
}
```

## Validation checklist

- Unit tests for backend selection and failure fallback behavior.
- Integration tests for artifact copy, execution, and cleanup lifecycle.
- Negative tests for malformed config and command injection attempts.

## Security considerations

- Validate all externally supplied paths and command fragments.
- Apply least-privilege runtime settings in sandbox provision logic.
- Avoid implicit trust of environment variables in backend command invocations.

## Limitations

- Backend APIs are code-level contracts and may evolve.
- Stability guarantees for external plugin ecosystems are not formally versioned.

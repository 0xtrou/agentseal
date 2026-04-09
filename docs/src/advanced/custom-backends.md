# Custom Backends

Agent Seal supports extensible compile and sandbox backends.

## Compile Backends

### Built-in Backends

| Backend | Use Case |
|---------|----------|
| Nuitka | Python → C → Native |
| PyInstaller | Python import freeze |
| Go | Static Go binaries |

### Adding a Custom Backend

Implement the `CompileBackend` trait:

```rust
use agent_seal_compiler::backend::CompileBackend;

pub struct MyBackend;

impl CompileBackend for MyBackend {
    fn detect(&self, project_dir: &Path) -> bool {
        // Return true if this backend applies
        project_dir.join("my-config.toml").exists()
    }

    fn compile(
        &self,
        project_dir: &Path,
        output_path: &Path,
    ) -> Result<(), CompileError> {
        // Compile the agent to a static ELF
        // ...
        Ok(())
    }
}
```

Register in `compile.rs`:

```rust
let backends: Vec<Box<dyn CompileBackend>> = vec![
    Box::new(NuitkaBackend),
    Box::new(PyInstallerBackend),
    Box::new(GoBackend),
    Box::new(MyBackend),
];
```

## Sandbox Backends

### Built-in Backends

| Backend | Isolation |
|---------|-----------|
| Docker | Process + capabilities |

### Adding a Custom Sandbox

Implement the `SandboxBackend` trait:

```rust
use agent_seal_server::sandbox::SandboxBackend;

pub struct MySandbox;

impl SandboxBackend for MySandbox {
    fn provision(&self, config: &SandboxConfig) -> Result<String, SandboxError> {
        // Create sandbox, return sandbox ID
    }

    fn copy(&self, sandbox_id: &str, src: &Path, dest: &Path) -> Result<(), SandboxError> {
        // Copy files into sandbox
    }

    fn exec(&self, sandbox_id: &str, config: &ExecConfig) -> Result<ExecutionResult, SandboxError> {
        // Execute agent in sandbox
    }

    fn destroy(&self, sandbox_id: &str) -> Result<(), SandboxError> {
        // Clean up sandbox
    }
}
```

## Trait Locations

- Compile backend: `crates/agent-seal-compiler/src/backend.rs`
- Sandbox backend: `crates/agent-seal-server/src/sandbox.rs`
#[path = "sandbox/mod.rs"]
mod backend;

pub use backend::{DockerBackend, SandboxBackend, SandboxConfig, SandboxHandle};

pub type SandboxProvisioner = DockerBackend;

pub async fn copy_into_sandbox<B: SandboxBackend + ?Sized>(
    provisioner: &B,
    handle: &SandboxHandle,
    host_path: &std::path::Path,
    target_path: &str,
) -> Result<(), snapfzz_seal_core::error::SealError> {
    provisioner.copy_into(handle, host_path, target_path).await
}

pub async fn exec_in_sandbox<B: SandboxBackend + ?Sized>(
    provisioner: &B,
    handle: &SandboxHandle,
    command: &str,
    timeout_secs: u64,
) -> Result<snapfzz_seal_core::types::ExecutionResult, snapfzz_seal_core::error::SealError> {
    provisioner.exec(handle, command, timeout_secs).await
}

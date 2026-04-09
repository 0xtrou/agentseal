//! Sandbox backend abstraction for agent execution environments.

use snapfzz_seal_core::error::SealError;
use snapfzz_seal_core::types::ExecutionResult;
use snapfzz_seal_fingerprint::model::RuntimeKind;
use async_trait::async_trait;
use std::collections::HashMap;
use std::path::Path;

mod docker;
pub use docker::DockerBackend;

#[derive(Debug, Clone)]
pub struct SandboxHandle {
    pub id: String,
    pub container_id: Option<String>,
    pub vm_id: Option<String>,
    pub socket_path: Option<String>,
    pub config: SandboxConfig,
    pub backend_data: HashMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct SandboxConfig {
    pub image: String,
    pub env: Vec<(String, String)>,
    pub memory_mb: Option<u64>,
    pub timeout_secs: u64,
}

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

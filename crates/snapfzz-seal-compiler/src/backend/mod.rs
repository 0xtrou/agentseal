mod nuitka;
mod pyinstaller;
mod golang;

use snapfzz_seal_core::error::SealError;
use std::path::{Path, PathBuf};

pub use golang::{GoBackend, GoConfig, compile_with_go};
pub use nuitka::{NuitkaBackend, NuitkaConfig, compile_with_nuitka};
pub use pyinstaller::{PyInstallerBackend, PyInstallerConfig, compile_with_pyinstaller};

#[derive(Debug, Clone)]
pub struct CompileConfig {
    pub project_dir: PathBuf,
    pub output_dir: PathBuf,
    pub target_triple: String,
    pub timeout_secs: u64,
}

pub trait CompileBackend: Send + Sync {
    fn name(&self) -> &str;
    fn can_compile(&self, project_dir: &Path) -> bool;
    fn compile(&self, config: &CompileConfig) -> Result<PathBuf, SealError>;
}

pub struct ChainBackend {
    backends: Vec<Box<dyn CompileBackend>>,
}

impl ChainBackend {
    pub fn new(backends: Vec<Box<dyn CompileBackend>>) -> Self {
        Self { backends }
    }
}

impl CompileBackend for ChainBackend {
    fn name(&self) -> &str {
        "chain"
    }

    fn can_compile(&self, project_dir: &Path) -> bool {
        self.backends
            .iter()
            .any(|backend| backend.can_compile(project_dir))
    }

    fn compile(&self, config: &CompileConfig) -> Result<PathBuf, SealError> {
        for backend in &self.backends {
            if backend.can_compile(&config.project_dir) {
                match backend.compile(config) {
                    Ok(path) => {
                        tracing::info!("compiled with backend '{}'", backend.name());
                        return Ok(path);
                    }
                    Err(err) => {
                        tracing::warn!("backend '{}' failed: {}", backend.name(), err);
                    }
                }
            }
        }

        Err(SealError::CompilationError(format!(
            "no backend could compile project at {}",
            config.project_dir.display()
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    struct TestBackend {
        name: &'static str,
        can_compile: bool,
        output: Option<PathBuf>,
        error: Option<&'static str>,
        calls: Arc<AtomicUsize>,
    }

    impl TestBackend {
        fn succeeds(
            name: &'static str,
            can_compile: bool,
            output: PathBuf,
            calls: Arc<AtomicUsize>,
        ) -> Self {
            Self {
                name,
                can_compile,
                output: Some(output),
                error: None,
                calls,
            }
        }

        fn fails(
            name: &'static str,
            can_compile: bool,
            error: &'static str,
            calls: Arc<AtomicUsize>,
        ) -> Self {
            Self {
                name,
                can_compile,
                output: None,
                error: Some(error),
                calls,
            }
        }
    }

    impl CompileBackend for TestBackend {
        fn name(&self) -> &str {
            self.name
        }

        fn can_compile(&self, _project_dir: &Path) -> bool {
            self.can_compile
        }

        fn compile(&self, _config: &CompileConfig) -> Result<PathBuf, SealError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if let Some(output) = &self.output {
                Ok(output.clone())
            } else {
                Err(SealError::CompilationError(
                    self.error
                        .expect("test backend error should exist")
                        .to_string(),
                ))
            }
        }
    }

    fn test_config(project_dir: PathBuf) -> CompileConfig {
        CompileConfig {
            project_dir,
            output_dir: std::env::temp_dir(),
            target_triple: "x86_64-unknown-linux-musl".to_string(),
            timeout_secs: 60,
        }
    }

    #[test]
    fn chain_backend_reports_chain_name() {
        let backend = ChainBackend::new(Vec::new());
        assert_eq!(backend.name(), "chain");
    }

    #[test]
    fn chain_backend_can_compile_when_any_backend_matches() {
        let backend = ChainBackend::new(vec![
            Box::new(TestBackend::fails(
                "nuitka",
                false,
                "skip",
                Arc::new(AtomicUsize::new(0)),
            )),
            Box::new(TestBackend::fails(
                "pyinstaller",
                true,
                "fail",
                Arc::new(AtomicUsize::new(0)),
            )),
        ]);

        assert!(backend.can_compile(Path::new("/tmp/project")));
    }

    #[test]
    fn chain_backend_skips_backends_that_cannot_compile() {
        let skipped_calls = Arc::new(AtomicUsize::new(0));
        let used_calls = Arc::new(AtomicUsize::new(0));
        let success_path = std::env::temp_dir().join("snapfzz-seal-chain-success.bin");

        let backend = ChainBackend::new(vec![
            Box::new(TestBackend::fails(
                "nuitka",
                false,
                "should not run",
                skipped_calls.clone(),
            )),
            Box::new(TestBackend::succeeds(
                "pyinstaller",
                true,
                success_path.clone(),
                used_calls.clone(),
            )),
        ]);

        let result = backend
            .compile(&test_config(PathBuf::from("/tmp/project")))
            .expect("matching backend should compile successfully");

        assert_eq!(result, success_path);
        assert_eq!(skipped_calls.load(Ordering::SeqCst), 0);
        assert_eq!(used_calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn chain_backend_falls_back_after_failure() {
        let first_calls = Arc::new(AtomicUsize::new(0));
        let second_calls = Arc::new(AtomicUsize::new(0));
        let second_output = std::env::temp_dir().join("snapfzz-seal-chain-fallback.bin");

        let backend = ChainBackend::new(vec![
            Box::new(TestBackend::fails(
                "nuitka",
                true,
                "nuitka failed",
                first_calls.clone(),
            )),
            Box::new(TestBackend::succeeds(
                "pyinstaller",
                true,
                second_output.clone(),
                second_calls.clone(),
            )),
        ]);

        let result = backend
            .compile(&test_config(PathBuf::from("/tmp/project")))
            .expect("second backend should be used after first fails");

        assert_eq!(result, second_output);
        assert_eq!(first_calls.load(Ordering::SeqCst), 1);
        assert_eq!(second_calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn chain_backend_errors_when_no_backend_can_compile() {
        let backend = ChainBackend::new(vec![
            Box::new(TestBackend::fails(
                "nuitka",
                false,
                "skip",
                Arc::new(AtomicUsize::new(0)),
            )),
            Box::new(TestBackend::fails(
                "pyinstaller",
                false,
                "skip",
                Arc::new(AtomicUsize::new(0)),
            )),
        ]);

        let err = backend
            .compile(&test_config(PathBuf::from("/tmp/project")))
            .expect_err("non-matching chain should return compilation error");

        match err {
            SealError::CompilationError(message) => {
                assert!(message.contains("no backend could compile project"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn chain_backend_errors_when_all_matching_backends_fail() {
        let first_calls = Arc::new(AtomicUsize::new(0));
        let second_calls = Arc::new(AtomicUsize::new(0));
        let backend = ChainBackend::new(vec![
            Box::new(TestBackend::fails(
                "nuitka",
                true,
                "nuitka failed",
                first_calls.clone(),
            )),
            Box::new(TestBackend::fails(
                "pyinstaller",
                true,
                "pyinstaller failed",
                second_calls.clone(),
            )),
        ]);

        let err = backend
            .compile(&test_config(PathBuf::from("/tmp/project")))
            .expect_err("all backend failures should bubble as generic chain error");

        match err {
            SealError::CompilationError(message) => {
                assert!(message.contains("no backend could compile project"));
            }
            other => panic!("unexpected error: {other:?}"),
        }

        assert_eq!(first_calls.load(Ordering::SeqCst), 1);
        assert_eq!(second_calls.load(Ordering::SeqCst), 1);
    }
}

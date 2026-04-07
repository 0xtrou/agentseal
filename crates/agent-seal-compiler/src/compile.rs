use crate::{
    nuitka::{NuitkaConfig, compile_with_nuitka},
    pyinstaller::{PyInstallerConfig, compile_with_pyinstaller},
};
use agent_seal_core::error::SealError;
use std::{
    path::{Path, PathBuf},
    process::Command,
};
use tracing::warn;

#[derive(Debug, Clone, PartialEq)]
pub enum Backend {
    Nuitka,
    PyInstaller,
}

pub fn compile_agent(
    project_dir: &Path,
    output_dir: &Path,
    backend: Backend,
) -> Result<PathBuf, SealError> {
    compile_agent_with_backends(
        project_dir,
        output_dir,
        backend,
        |project_dir, output_dir| {
            let nuitka_cfg = NuitkaConfig {
                project_dir: project_dir.to_path_buf(),
                output_dir: output_dir.to_path_buf(),
                ..NuitkaConfig::default()
            };
            compile_with_nuitka(&nuitka_cfg)
        },
        |project_dir, output_dir| {
            let pyinstaller_cfg = PyInstallerConfig {
                project_dir: project_dir.to_path_buf(),
                output_dir: output_dir.to_path_buf(),
                onefile: true,
                timeout_secs: 1_800,
            };
            compile_with_pyinstaller(&pyinstaller_cfg)
        },
    )
}

fn compile_agent_with_backends<FN, FP>(
    project_dir: &Path,
    output_dir: &Path,
    backend: Backend,
    compile_nuitka: FN,
    compile_pyinstaller: FP,
) -> Result<PathBuf, SealError>
where
    FN: Fn(&Path, &Path) -> Result<PathBuf, SealError>,
    FP: Fn(&Path, &Path) -> Result<PathBuf, SealError>,
{
    let output = match backend {
        Backend::Nuitka => match compile_nuitka(project_dir, output_dir) {
            Ok(path) => path,
            Err(_nuitka_err) => {
                warn!("nuitka compilation failed, falling back to pyinstaller: {_nuitka_err}");
                compile_pyinstaller(project_dir, output_dir)?
            }
        },
        Backend::PyInstaller => compile_pyinstaller(project_dir, output_dir)?,
    };

    run_strip(&output)?;
    verify_non_empty(&output)?;

    Ok(output)
}

fn run_strip(binary_path: &Path) -> Result<(), SealError> {
    let output = Command::new("strip").arg(binary_path).output();
    match output {
        Ok(result) => {
            if result.status.success() {
                Ok(())
            } else {
                let stderr = String::from_utf8_lossy(&result.stderr);
                Err(SealError::CompilationError(format!(
                    "strip failed for {}: {}",
                    binary_path.display(),
                    stderr.trim()
                )))
            }
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(SealError::Io(err)),
    }
}

fn verify_non_empty(binary_path: &Path) -> Result<(), SealError> {
    let metadata = std::fs::metadata(binary_path)?;
    if !metadata.is_file() {
        return Err(SealError::CompilationError(format!(
            "compiled output is not a file: {}",
            binary_path.display()
        )));
    }
    if metadata.len() == 0 {
        return Err(SealError::CompilationError(format!(
            "compiled output is empty: {}",
            binary_path.display()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backend_variants_compare_as_expected() {
        assert_eq!(Backend::Nuitka, Backend::Nuitka);
        assert_eq!(Backend::PyInstaller, Backend::PyInstaller);
        assert_ne!(Backend::Nuitka, Backend::PyInstaller);
    }

    #[test]
    fn compile_agent_returns_error_when_no_backend_available() {
        let project_dir = PathBuf::from("/tmp/project");
        let output_dir = std::env::temp_dir().join("agent-seal-compile-no-backend-test");

        let err = compile_agent_with_backends(
            &project_dir,
            &output_dir,
            Backend::Nuitka,
            |_project_dir, _output_dir| {
                Err(SealError::CompilationError("nuitka not found".to_string()))
            },
            |_project_dir, _output_dir| {
                Err(SealError::CompilationError(
                    "pyinstaller not found".to_string(),
                ))
            },
        )
        .expect_err("both backend failures should bubble up as error");

        match err {
            SealError::CompilationError(message) => {
                assert!(message.contains("pyinstaller not found"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    fn unique_temp_dir(prefix: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock should be after unix epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("{prefix}-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir should be creatable");
        dir
    }

    #[test]
    fn run_strip_succeeds_for_valid_binary() {
        let temp_dir = unique_temp_dir("agent-seal-compile-strip-success");
        let binary_path = temp_dir.join("ls-copy");
        std::fs::copy("/bin/ls", &binary_path).expect("binary should be copied");

        let result = run_strip(&binary_path);
        assert!(result.is_ok(), "strip on copied binary should succeed");
    }

    #[test]
    fn run_strip_fails_for_missing_input_file() {
        let temp_dir = unique_temp_dir("agent-seal-compile-strip-failure");
        let missing_binary = temp_dir.join("does-not-exist.bin");

        let err = run_strip(&missing_binary).expect_err("strip should fail for missing file");
        match err {
            SealError::CompilationError(message) => {
                assert!(message.contains("strip failed"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn run_strip_returns_ok_when_strip_command_missing() {
        if std::env::var_os("AGENT_SEAL_TEST_STRIP_MISSING_CHILD").is_some() {
            let result = run_strip(Path::new("/this/path/is/never/read"));
            assert!(
                result.is_ok(),
                "missing strip command should be treated as non-fatal"
            );
            return;
        }

        let current_exe = std::env::current_exe().expect("current test binary path should resolve");
        let output = std::process::Command::new(current_exe)
            .arg("--exact")
            .arg("compile::tests::run_strip_returns_ok_when_strip_command_missing")
            .env("AGENT_SEAL_TEST_STRIP_MISSING_CHILD", "1")
            .env("PATH", "")
            .output()
            .expect("child test process should execute");

        assert!(
            output.status.success(),
            "child process should pass when strip is missing: stdout={}, stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn verify_non_empty_rejects_empty_file() {
        let temp_dir = unique_temp_dir("agent-seal-compile-verify-empty");
        let binary_path = temp_dir.join("empty.bin");
        std::fs::write(&binary_path, b"").expect("empty test file should be writable");

        let err = verify_non_empty(&binary_path).expect_err("empty file should be rejected");
        match err {
            SealError::CompilationError(message) => {
                assert!(message.contains("compiled output is empty"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn verify_non_empty_rejects_non_file_path() {
        let temp_dir = unique_temp_dir("agent-seal-compile-verify-non-file");

        let err = verify_non_empty(&temp_dir).expect_err("directory should be rejected");
        match err {
            SealError::CompilationError(message) => {
                assert!(message.contains("compiled output is not a file"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn verify_non_empty_accepts_non_empty_file() {
        let temp_dir = unique_temp_dir("agent-seal-compile-verify-valid");
        let binary_path = temp_dir.join("valid.bin");
        std::fs::write(&binary_path, b"abc").expect("non-empty test file should be writable");

        verify_non_empty(&binary_path).expect("non-empty file should be accepted");
    }

    #[test]
    fn compile_agent_with_backends_uses_nuitka_output_when_successful() {
        let temp_dir = unique_temp_dir("agent-seal-compile-nuitka-success");
        let output_path = temp_dir.join("nuitka.bin");
        std::fs::copy("/bin/ls", &output_path).expect("binary should be copied");

        let pyinstaller_calls = std::cell::Cell::new(0_u32);
        let result = compile_agent_with_backends(
            &temp_dir,
            &temp_dir,
            Backend::Nuitka,
            |_project_dir, _output_dir| Ok(output_path.clone()),
            |_project_dir, _output_dir| {
                pyinstaller_calls.set(pyinstaller_calls.get() + 1);
                Err(SealError::CompilationError(
                    "fallback should not run".to_string(),
                ))
            },
        )
        .expect("nuitka success should return output path");

        assert_eq!(result, output_path);
        assert_eq!(pyinstaller_calls.get(), 0);
    }

    #[test]
    fn compile_agent_with_backends_falls_back_to_pyinstaller_after_nuitka_failure() {
        let temp_dir = unique_temp_dir("agent-seal-compile-fallback");
        let fallback_path = temp_dir.join("fallback.bin");
        std::fs::copy("/bin/ls", &fallback_path).expect("binary should be copied");

        let pyinstaller_calls = std::cell::Cell::new(0_u32);
        let result = compile_agent_with_backends(
            &temp_dir,
            &temp_dir,
            Backend::Nuitka,
            |_project_dir, _output_dir| {
                Err(SealError::CompilationError("nuitka failed".to_string()))
            },
            |_project_dir, _output_dir| {
                pyinstaller_calls.set(pyinstaller_calls.get() + 1);
                Ok(fallback_path.clone())
            },
        )
        .expect("fallback pyinstaller output should be returned");

        assert_eq!(result, fallback_path);
        assert_eq!(pyinstaller_calls.get(), 1);
    }
}

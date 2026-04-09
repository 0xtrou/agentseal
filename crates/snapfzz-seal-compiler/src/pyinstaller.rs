use snapfzz_seal_core::error::SealError;
use std::{
    ffi::OsStr,
    fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

#[derive(Debug, Clone)]
pub struct PyInstallerConfig {
    pub project_dir: PathBuf,
    pub output_dir: PathBuf,
    pub onefile: bool,
    pub timeout_secs: u64,
}

impl Default for PyInstallerConfig {
    fn default() -> Self {
        Self {
            project_dir: PathBuf::new(),
            output_dir: PathBuf::new(),
            onefile: true,
            timeout_secs: 1_800,
        }
    }
}

pub fn compile_with_pyinstaller(config: &PyInstallerConfig) -> Result<PathBuf, SealError> {
    compile_with_command("pyinstaller", config)
}

fn compile_with_command(
    command_name: &str,
    config: &PyInstallerConfig,
) -> Result<PathBuf, SealError> {
    let project_name = project_name(&config.project_dir)?;
    let source_file = config.project_dir.join("main.py");
    if !source_file.exists() {
        return Err(SealError::CompilationError(format!(
            "missing entrypoint: {}",
            source_file.display()
        )));
    }

    let temp_root = std::env::temp_dir().join(format!("snapfzz-seal-pyinstaller-{project_name}"));
    let workpath = temp_root.join("work");
    let specpath = temp_root.join("spec");

    fs::create_dir_all(&config.output_dir)?;
    fs::create_dir_all(&workpath)?;
    fs::create_dir_all(&specpath)?;

    let mut command = Command::new(command_name);
    if config.onefile {
        command.arg("--onefile");
    }

    command
        .arg("--distpath")
        .arg(&config.output_dir)
        .arg("--workpath")
        .arg(&workpath)
        .arg("--specpath")
        .arg(&specpath)
        .arg("--name")
        .arg(&project_name)
        .arg(source_file);

    let output = run_with_timeout(command, config.timeout_secs, command_name)?;

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    if !output.status.success() || contains_error_indicator(&stderr) {
        return Err(SealError::CompilationError(format!(
            "pyinstaller failed: status={:?}, stderr={}, stdout={}",
            output.status.code(),
            stderr.trim(),
            stdout.trim()
        )));
    }

    Ok(config.output_dir.join(project_name))
}

fn run_with_timeout(
    mut command: Command,
    timeout_secs: u64,
    command_name: &str,
) -> Result<std::process::Output, SealError> {
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| map_spawn_error(err, command_name))?;

    let timeout = Duration::from_secs(timeout_secs.max(1));
    let start = Instant::now();

    loop {
        match child.try_wait() {
            Ok(Some(_)) => {
                let output = child.wait_with_output()?;
                return Ok(output);
            }
            Ok(None) => {
                if start.elapsed() >= timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(SealError::CompilationTimeout(timeout_secs));
                }
                thread::sleep(Duration::from_millis(100));
            }
            Err(err) => return Err(SealError::Io(err)),
        }
    }
}

fn map_spawn_error(err: std::io::Error, command_name: &str) -> SealError {
    if err.kind() == std::io::ErrorKind::NotFound {
        SealError::CompilationError(format!("{command_name} not found"))
    } else {
        SealError::Io(err)
    }
}

fn project_name(path: &Path) -> Result<String, SealError> {
    path.file_name()
        .and_then(OsStr::to_str)
        .map(ToOwned::to_owned)
        .ok_or_else(|| SealError::InvalidInput(format!("invalid project path: {}", path.display())))
}

fn contains_error_indicator(stderr: &str) -> bool {
    ["Error:", "error:", "FAILED"]
        .iter()
        .any(|needle| stderr.contains(needle))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unique_temp_dir(prefix: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock should be after unix epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("{prefix}-{}-{nanos}", std::process::id()));
        fs::create_dir_all(&dir).expect("temp dir should be creatable");
        dir
    }

    #[test]
    fn pyinstaller_missing_binary_returns_compilation_error() {
        let test_root = unique_temp_dir("snapfzz-seal-pyinstaller-test-missing");
        let project_dir = test_root.join("project");
        let output_dir = test_root.join("dist");
        fs::create_dir_all(&project_dir).expect("project dir should be creatable");
        fs::write(project_dir.join("main.py"), "print('hello')")
            .expect("main.py should be writable");

        let config = PyInstallerConfig {
            project_dir,
            output_dir,
            onefile: true,
            timeout_secs: 1,
        };

        let err = compile_with_command("definitely-missing-pyinstaller", &config)
            .expect_err("missing command should return an error");

        match err {
            SealError::CompilationError(message) => {
                assert!(message.contains("not found"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn project_name_returns_filename_for_valid_path() {
        let name = project_name(Path::new("/tmp/example_project"))
            .expect("valid project path should return file name");
        assert_eq!(name, "example_project");
    }

    #[test]
    fn project_name_rejects_path_without_filename() {
        let err = project_name(Path::new("/"))
            .expect_err("root path should not contain a usable file name");
        match err {
            SealError::InvalidInput(message) => {
                assert!(message.contains("invalid project path"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn contains_error_indicator_detects_known_patterns() {
        assert!(contains_error_indicator("Error: fatal"));
        assert!(contains_error_indicator("error: lower case"));
        assert!(contains_error_indicator("build FAILED unexpectedly"));
        assert!(!contains_error_indicator("all good"));
    }

    #[test]
    fn run_with_timeout_succeeds_for_fast_command() {
        let mut command = Command::new("echo");
        command.arg("hello");

        let output = run_with_timeout(command, 5, "echo")
            .expect("fast echo command should complete within timeout");
        assert!(output.status.success());
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("hello"));
    }

    #[test]
    fn compile_with_command_errors_when_main_py_missing() {
        let test_root = unique_temp_dir("snapfzz-seal-pyinstaller-missing-main");
        let project_dir = test_root.join("project-no-main");
        let output_dir = test_root.join("dist");
        fs::create_dir_all(&project_dir).expect("project dir should be creatable");

        let config = PyInstallerConfig {
            project_dir: project_dir.clone(),
            output_dir,
            onefile: true,
            timeout_secs: 1,
        };

        let err = compile_with_command("pyinstaller", &config)
            .expect_err("missing main.py should return compilation error");
        match err {
            SealError::CompilationError(message) => {
                assert!(message.contains("missing entrypoint"));
                assert!(message.contains(&project_dir.join("main.py").display().to_string()));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn default_config_sets_expected_defaults() {
        let config = PyInstallerConfig::default();
        assert!(config.project_dir.as_os_str().is_empty());
        assert!(config.output_dir.as_os_str().is_empty());
        assert!(config.onefile);
        assert_eq!(config.timeout_secs, 1_800);
    }

    #[test]
    fn compile_with_pyinstaller_surfaces_invalid_project_path() {
        let config = PyInstallerConfig {
            project_dir: PathBuf::from("/"),
            output_dir: unique_temp_dir("snapfzz-seal-pyinstaller-invalid-project"),
            onefile: true,
            timeout_secs: 1,
        };

        let err = compile_with_pyinstaller(&config)
            .expect_err("invalid project path should fail before command execution");
        match err {
            SealError::InvalidInput(message) => {
                assert!(message.contains("invalid project path"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn run_with_timeout_returns_timeout_for_slow_command() {
        let mut command = Command::new("python3");
        command.arg("-c").arg("import time; time.sleep(2)");

        let err = run_with_timeout(command, 0, "python3")
            .expect_err("slow command should time out even when timeout is zero");
        match err {
            SealError::CompilationTimeout(timeout) => {
                assert_eq!(timeout, 0);
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn map_spawn_error_preserves_non_not_found_io_errors() {
        let err = map_spawn_error(
            std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied"),
            "pyinstaller",
        );

        match err {
            SealError::Io(io) => {
                assert_eq!(io.kind(), std::io::ErrorKind::PermissionDenied);
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn compile_with_command_treats_error_text_as_failure() {
        let test_root = unique_temp_dir("snapfzz-seal-pyinstaller-error-indicator");
        let project_dir = test_root.join("project");
        let output_dir = test_root.join("dist");
        let fake_pyinstaller = test_root.join("fake-pyinstaller.sh");
        fs::create_dir_all(&project_dir).expect("project dir should be creatable");
        fs::write(project_dir.join("main.py"), "print('hello')")
            .expect("main.py should be writable");
        fs::write(
            &fake_pyinstaller,
            "#!/bin/sh\necho 'Error: simulated pyinstaller failure' >&2\nexit 0\n",
        )
        .expect("fake pyinstaller should be writable");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&fake_pyinstaller)
                .expect("fake pyinstaller metadata should be readable")
                .permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&fake_pyinstaller, perms)
                .expect("fake pyinstaller should be executable");
        }

        let config = PyInstallerConfig {
            project_dir,
            output_dir,
            onefile: true,
            timeout_secs: 5,
        };

        let err = compile_with_command(
            fake_pyinstaller
                .to_str()
                .expect("fake pyinstaller path should be valid utf-8"),
            &config,
        )
        .expect_err("stderr error indicator should be treated as failure");
        match err {
            SealError::CompilationError(message) => {
                assert!(message.contains("pyinstaller failed"));
                assert!(message.contains("status=Some(0)"));
                assert!(message.contains("Error: simulated pyinstaller failure"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }
}

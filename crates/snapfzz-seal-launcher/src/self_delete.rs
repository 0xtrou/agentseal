use snapfzz_seal_core::error::SealError;

pub fn self_delete() -> Result<(), SealError> {
    let executable_path = std::fs::read_link("/proc/self/exe")?;

    if !executable_path.exists() {
        return Ok(());
    }

    match std::fs::remove_file(&executable_path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
            tracing::warn!(
                "self-delete skipped due to permission denied (likely overlayfs): {}",
                executable_path.display()
            );
            Ok(())
        }
        Err(err) => Err(SealError::Io(err)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map_remove_result(result: std::io::Result<()>) -> Result<(), SealError> {
        match result {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => Ok(()),
            Err(err) => Err(SealError::Io(err)),
        }
    }

    fn self_delete_from_path(executable_path: &std::path::Path) -> Result<(), SealError> {
        if !executable_path.exists() {
            return Ok(());
        }
        map_remove_result(std::fs::remove_file(executable_path))
    }

    #[test]
    fn self_delete_symbol_is_available() {
        let func: fn() -> Result<(), SealError> = self_delete;
        let _ = func;
    }

    #[cfg(unix)]
    #[test]
    fn self_delete_returns_ok_for_nonexistent_symlink_target() {
        let symlink_path = std::env::temp_dir().join(format!(
            "snapfzz-seal-launcher-self-delete-missing-target-{}",
            std::process::id()
        ));
        let missing_target = symlink_path.with_extension("missing");
        let _ = std::fs::remove_file(&symlink_path);
        std::os::unix::fs::symlink(&missing_target, &symlink_path).unwrap();

        let resolved = std::fs::read_link(&symlink_path).unwrap();
        let result = self_delete_from_path(&resolved);
        assert!(result.is_ok());

        std::fs::remove_file(symlink_path).unwrap();
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn self_delete_returns_io_error_when_read_link_fails() {
        let err = self_delete().expect_err("non-linux read_link should fail");
        assert!(matches!(err, SealError::Io(_)));
    }

    #[test]
    fn self_delete_permission_denied_path_is_treated_as_ok() {
        let result = map_remove_result(Err(std::io::Error::from(
            std::io::ErrorKind::PermissionDenied,
        )));
        assert!(result.is_ok());
    }

    #[test]
    fn self_delete_non_permission_denied_maps_to_io_error() {
        let result = map_remove_result(Err(std::io::Error::other("boom")));
        assert!(matches!(result, Err(SealError::Io(_))));
    }

    #[test]
    fn self_delete_from_path_removes_existing_file() {
        let path = std::env::temp_dir().join(format!(
            "snapfzz-seal-launcher-self-delete-file-{}",
            std::process::id()
        ));
        std::fs::write(&path, b"temporary payload").unwrap();

        self_delete_from_path(&path).unwrap();

        assert!(!path.exists());
    }
}

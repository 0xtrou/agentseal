use thiserror::Error;

#[derive(Error, Debug)]
pub enum FingerprintError {
    #[error("IO error reading {source_name}: {err}")]
    ReadFailed { source_name: String, err: String },
    #[error("parse error for {source_name}: {err}")]
    ParseFailed { source_name: String, err: String },
    #[error("{0}")]
    Other(#[from] anyhow::Error),
}

#[cfg(test)]
mod tests {
    use super::FingerprintError;

    #[test]
    fn read_failed_formats_message_with_source_and_reason() {
        let err = FingerprintError::ReadFailed {
            source_name: "linux.machine_id_hmac".to_string(),
            err: "permission denied".to_string(),
        };

        let rendered = err.to_string();
        assert!(rendered.contains("IO error reading linux.machine_id_hmac"));
        assert!(rendered.contains("permission denied"));
    }

    #[test]
    fn parse_failed_formats_message_with_source_and_reason() {
        let err = FingerprintError::ParseFailed {
            source_name: "linux.cgroup_path".to_string(),
            err: "invalid format".to_string(),
        };

        let rendered = err.to_string();
        assert!(rendered.contains("parse error for linux.cgroup_path"));
        assert!(rendered.contains("invalid format"));
    }

    #[test]
    fn other_variant_wraps_anyhow_error_via_from() {
        let err: FingerprintError = anyhow::anyhow!("unexpected").into();

        match err {
            FingerprintError::Other(inner) => {
                assert!(inner.to_string().contains("unexpected"));
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }
}

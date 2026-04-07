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

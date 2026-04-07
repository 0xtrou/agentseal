use agent_seal_core::{error::SealError, types::LAUNCHER_MARKER};

pub fn embed_master_secret(launcher_bytes: &[u8], secret: &[u8; 32]) -> Result<Vec<u8>, SealError> {
    replace_after_marker(launcher_bytes, secret)
}

pub fn embed_tamper_hash(launcher_bytes: &[u8], hash: &[u8; 32]) -> Result<Vec<u8>, SealError> {
    replace_after_marker(launcher_bytes, hash)
}

fn replace_after_marker(
    launcher_bytes: &[u8],
    replacement: &[u8; 32],
) -> Result<Vec<u8>, SealError> {
    let Some(marker_offset) = find_marker(launcher_bytes, LAUNCHER_MARKER) else {
        return Err(embed_failed("marker not found"));
    };

    let secret_offset = marker_offset + LAUNCHER_MARKER.len();
    let end_offset = secret_offset + replacement.len();
    if launcher_bytes.len() < end_offset {
        return Err(embed_failed("launcher too small for embedded payload"));
    }

    let mut modified = launcher_bytes.to_vec();
    modified[secret_offset..end_offset].copy_from_slice(replacement);
    Ok(modified)
}

fn find_marker(haystack: &[u8], marker: &[u8]) -> Option<usize> {
    haystack
        .windows(marker.len())
        .position(|window| window == marker)
}

fn embed_failed(detail: &str) -> SealError {
    SealError::CompilationError(format!("EmbedFailed: {detail}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embed_master_secret_replaces_bytes_after_marker() {
        let mut launcher = vec![0xAA; 64];
        launcher.extend_from_slice(LAUNCHER_MARKER);
        launcher.extend_from_slice(&[0_u8; 32]);
        launcher.extend_from_slice(&[0xBB; 64]);

        let secret = [0xCC; 32];
        let modified = embed_master_secret(&launcher, &secret).expect("embed should succeed");

        let start = 64 + LAUNCHER_MARKER.len();
        assert_eq!(&modified[start..start + 32], &secret);
    }

    #[test]
    fn embed_tamper_hash_replaces_bytes_after_marker() {
        let mut launcher = vec![0x10; 8];
        launcher.extend_from_slice(LAUNCHER_MARKER);
        launcher.extend_from_slice(&[0_u8; 32]);
        launcher.extend_from_slice(&[0x20; 8]);

        let hash = [0x44; 32];
        let modified = embed_tamper_hash(&launcher, &hash).expect("embed should succeed");

        let start = 8 + LAUNCHER_MARKER.len();
        assert_eq!(&modified[start..start + 32], &hash);
    }

    #[test]
    fn embed_returns_error_when_marker_missing() {
        let err =
            embed_master_secret(&[1_u8; 64], &[2_u8; 32]).expect_err("missing marker should fail");

        assert!(matches!(err, SealError::CompilationError(_)));
    }
}

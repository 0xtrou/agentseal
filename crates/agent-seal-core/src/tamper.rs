use crate::error::SealError;
use subtle::ConstantTimeEq;

use sha2::{Digest, Sha256};
#[cfg(target_os = "linux")]
use std::fs::File;
#[cfg(target_os = "linux")]
use std::io::Read;

/// Compute SHA-256 hash of arbitrary bytes.
/// Used for launcher portion tamper verification.
pub fn compute_hash_of_bytes(bytes: &[u8]) -> [u8; 32] {
    let hash = Sha256::digest(bytes);
    let mut out = [0_u8; 32];
    out.copy_from_slice(&hash);
    out
}

#[cfg(target_os = "linux")]
pub fn compute_binary_hash() -> Result<[u8; 32], SealError> {
    let mut file = File::open("/proc/self/exe")?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 8192];

    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }

    let hash = hasher.finalize();
    let mut out = [0_u8; 32];
    out.copy_from_slice(&hash);
    Ok(out)
}

#[cfg(not(target_os = "linux"))]
pub fn compute_binary_hash() -> Result<[u8; 32], SealError> {
    Err(SealError::Io(std::io::Error::other(
        "tamper verification requires Linux: /proc/self/exe is unavailable on this platform",
    )))
}

pub fn verify_tamper(expected_hash: &[u8]) -> Result<(), SealError> {
    if expected_hash.len() != 32 {
        return Err(SealError::InvalidInput(
            "expected hash must be exactly 32 bytes".to_string(),
        ));
    }

    let current_hash = compute_binary_hash()?;
    if current_hash.ct_eq(expected_hash).into() {
        Ok(())
    } else {
        Err(SealError::TamperDetected)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn binary_hash_is_32_bytes() {
        let hash = compute_binary_hash().expect("hash should be computed on linux");
        assert_eq!(hash.len(), 32);
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn binary_hash_requires_linux() {
        let err = compute_binary_hash().expect_err("should fail on non-linux");
        match err {
            SealError::Io(io_err) => {
                assert!(io_err.to_string().contains("requires Linux"));
            }
            other => panic!("expected io error, got {other:?}"),
        }
    }

    #[test]
    fn verify_tamper_rejects_wrong_hash_length() {
        let err = verify_tamper(&[0_u8; 31]).expect_err("31-byte hash must be rejected");
        match err {
            SealError::InvalidInput(message) => {
                assert!(message.contains("exactly 32 bytes"));
            }
            other => panic!("expected invalid input, got {other:?}"),
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn verify_tamper_detects_mismatch_on_linux() {
        let err = verify_tamper(&[0_u8; 32]).expect_err("wrong hash should be detected");
        assert!(matches!(err, SealError::TamperDetected));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn verify_tamper_accepts_current_binary_hash_on_linux() {
        let hash = compute_binary_hash().expect("hash should be computed on linux");
        verify_tamper(&hash).expect("current binary hash should verify");
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn verify_tamper_propagates_io_error_on_non_linux() {
        let err = verify_tamper(&[7_u8; 32]).expect_err("non-linux should propagate io error");
        match err {
            SealError::Io(io_err) => {
                assert!(io_err.to_string().contains("requires Linux"));
            }
            other => panic!("expected io error, got {other:?}"),
        }
    }

    #[test]
    fn verify_tamper_rejects_empty_hash_length() {
        let err = verify_tamper(&[]).expect_err("empty hash must be rejected");
        assert!(matches!(err, SealError::InvalidInput(_)));
    }
}

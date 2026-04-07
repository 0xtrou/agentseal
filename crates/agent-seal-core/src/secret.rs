use crate::error::SealError;
use rand::{RngCore, rngs::OsRng};
use std::fmt;
use zeroize::Zeroize;

pub fn generate_master_secret() -> [u8; 32] {
    let mut secret = [0_u8; 32];
    OsRng.fill_bytes(&mut secret);
    secret
}

#[derive(Clone)]
pub struct MasterSecret([u8; 32]);

impl MasterSecret {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn from_slice(slice: &[u8]) -> Result<Self, SealError> {
        if slice.len() != 32 {
            return Err(SealError::InvalidInput(
                "master secret must be exactly 32 bytes".to_string(),
            ));
        }

        let mut inner = [0_u8; 32];
        inner.copy_from_slice(slice);
        Ok(Self(inner))
    }
}

impl From<[u8; 32]> for MasterSecret {
    fn from(value: [u8; 32]) -> Self {
        Self(value)
    }
}

impl fmt::Debug for MasterSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MasterSecret([REDACTED])")
    }
}

impl Drop for MasterSecret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_master_secret_returns_32_unique_bytes() {
        let secret_a = generate_master_secret();
        let secret_b = generate_master_secret();

        assert_eq!(secret_a.len(), 32);
        assert_eq!(secret_b.len(), 32);
        assert_ne!(secret_a, secret_b);
    }

    #[test]
    fn from_slice_rejects_wrong_length() {
        let err = MasterSecret::from_slice(&[1_u8; 31]).expect_err("expected invalid input error");
        assert!(matches!(err, SealError::InvalidInput(_)));
    }

    #[test]
    fn debug_output_is_redacted() {
        let secret = MasterSecret::from([42_u8; 32]);
        let debug = format!("{secret:?}");

        assert_eq!(debug, "MasterSecret([REDACTED])");
        assert!(!debug.contains("42"));
    }
}

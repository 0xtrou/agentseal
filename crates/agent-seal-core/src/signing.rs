use crate::error::SealError;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;

pub fn keygen() -> ([u8; 32], [u8; 32]) {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    (signing_key.to_bytes(), verifying_key.to_bytes())
}

pub fn sign(secret_key_bytes: &[u8; 32], data: &[u8]) -> Result<[u8; 64], SealError> {
    sign_impl(secret_key_bytes, data)
}

pub fn verify(
    public_key_bytes: &[u8; 32],
    data: &[u8],
    signature: &[u8; 64],
) -> Result<bool, SealError> {
    verify_impl(public_key_bytes, data, signature)
}

fn sign_impl(secret_key_bytes: &[u8], data: &[u8]) -> Result<[u8; 64], SealError> {
    let secret_key = to_32(secret_key_bytes, "secret key")?;
    let signing_key = SigningKey::from_bytes(secret_key);
    let signature: Signature = signing_key.sign(data);
    Ok(signature.to_bytes())
}

fn verify_impl(public_key_bytes: &[u8], data: &[u8], signature: &[u8]) -> Result<bool, SealError> {
    let public_key = to_32(public_key_bytes, "public key")?;
    let signature = to_64(signature, "signature")?;

    let verifying_key = VerifyingKey::from_bytes(public_key)
        .map_err(|err| SealError::InvalidInput(format!("invalid public key: {err}")))?;
    let signature = Signature::from_bytes(signature);

    Ok(verifying_key.verify(data, &signature).is_ok())
}

fn to_32<'a>(bytes: &'a [u8], label: &str) -> Result<&'a [u8; 32], SealError> {
    bytes
        .try_into()
        .map_err(|_| SealError::InvalidInput(format!("{label} must be exactly 32 bytes")))
}

fn to_64<'a>(bytes: &'a [u8], label: &str) -> Result<&'a [u8; 64], SealError> {
    bytes
        .try_into()
        .map_err(|_| SealError::InvalidInput(format!("{label} must be exactly 64 bytes")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keygen_returns_32_byte_keys() {
        let (secret_key, public_key) = keygen();

        assert_eq!(secret_key.len(), 32);
        assert_eq!(public_key.len(), 32);
    }

    #[test]
    fn keygen_produces_unique_keys() {
        let (secret_a, public_a) = keygen();
        let (secret_b, public_b) = keygen();

        assert_ne!(secret_a, secret_b);
        assert_ne!(public_a, public_b);
    }

    #[test]
    fn sign_produces_64_byte_signature() {
        let (secret_key, _) = keygen();
        let signature = sign(&secret_key, b"agent-seal").expect("sign should succeed");

        assert_eq!(signature.len(), 64);
    }

    #[test]
    fn verify_accepts_valid_signature() {
        let (secret_key, public_key) = keygen();
        let data = b"builder signature verification";
        let signature = sign(&secret_key, data).expect("sign should succeed");

        let is_valid = verify(&public_key, data, &signature).expect("verify should succeed");
        assert!(is_valid);
    }

    #[test]
    fn verify_rejects_tampered_data() {
        let (secret_key, public_key) = keygen();
        let signature = sign(&secret_key, b"original data").expect("sign should succeed");

        let is_valid =
            verify(&public_key, b"tampered data", &signature).expect("verify should run");
        assert!(!is_valid);
    }

    #[test]
    fn verify_rejects_wrong_key() {
        let (secret_key_a, _) = keygen();
        let (_, public_key_b) = keygen();

        let data = b"same message";
        let signature = sign(&secret_key_a, data).expect("sign should succeed");
        let is_valid = verify(&public_key_b, data, &signature).expect("verify should run");

        assert!(!is_valid);
    }

    #[test]
    fn verify_rejects_tampered_signature() {
        let (secret_key, public_key) = keygen();
        let data = b"signed data";
        let mut signature = sign(&secret_key, data).expect("sign should succeed");
        signature[7] ^= 0x01;

        let is_valid = verify(&public_key, data, &signature).expect("verify should run");
        assert!(!is_valid);
    }

    #[test]
    fn sign_with_invalid_key_length_returns_error() {
        let short_key = [0_u8; 31];
        let err = sign_impl(&short_key, b"data").expect_err("31-byte key must fail");

        match err {
            SealError::InvalidInput(message) => {
                assert!(message.contains("secret key must be exactly 32 bytes"));
            }
            other => panic!("expected invalid input, got {other:?}"),
        }
    }

    #[test]
    fn verify_with_invalid_key_length_returns_error() {
        let short_public = [0_u8; 31];
        let signature = [0_u8; 64];
        let err = verify_impl(&short_public, b"data", &signature)
            .expect_err("31-byte public key must fail");

        match err {
            SealError::InvalidInput(message) => {
                assert!(message.contains("public key must be exactly 32 bytes"));
            }
            other => panic!("expected invalid input, got {other:?}"),
        }
    }

    #[test]
    fn verify_with_invalid_signature_length_returns_error() {
        let (_, public_key) = keygen();
        let short_signature = [0_u8; 63];
        let err = verify_impl(&public_key, b"data", &short_signature)
            .expect_err("63-byte signature must fail");

        match err {
            SealError::InvalidInput(message) => {
                assert!(message.contains("signature must be exactly 64 bytes"));
            }
            other => panic!("expected invalid input, got {other:?}"),
        }
    }

    #[test]
    fn sign_deterministic_for_same_key_and_data() {
        let (secret_key, _) = keygen();
        let data = b"deterministic check";

        let signature_a = sign(&secret_key, data).expect("first sign should succeed");
        let signature_b = sign(&secret_key, data).expect("second sign should succeed");

        assert_eq!(signature_a, signature_b);
    }

    #[test]
    fn round_trip_large_data() {
        let (secret_key, public_key) = keygen();
        let data = vec![42_u8; 1024 * 1024];

        let signature = sign(&secret_key, &data).expect("sign should succeed for large data");
        let is_valid = verify(&public_key, &data, &signature).expect("verify should succeed");

        assert!(is_valid);
    }
}

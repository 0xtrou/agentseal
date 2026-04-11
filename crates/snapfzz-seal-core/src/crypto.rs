//! Streaming AES-256-GCM encryption using the STREAM-BE32 construction.
//!
//! The wire format is identical to what the `aead-stream` crate (0.6.0-rc.x)
//! produced with `EncryptorBE32<Aes256Gcm>` / `DecryptorBE32<Aes256Gcm>`.
//! That crate has no stable release; we reproduce the construction here using
//! only stable `aes-gcm 0.10` and `aead 0.5` so that the codebase has no RC
//! dependencies.
//!
//! # STREAM-BE32 nonce layout (per chunk)
//!
//! AES-GCM requires a 12-byte nonce.  STREAM-BE32 reserves the last 5 bytes
//! for its own metadata, leaving 7 bytes for the user-supplied prefix:
//!
//! ```text
//! [ prefix (7 bytes) | counter-BE32 (4 bytes) | last-block flag (1 byte) ]
//! ```
//!
//! The counter starts at 0 and is incremented for every chunk.  The last-block
//! flag is `0x00` for non-final chunks and `0x01` for the final chunk.

use crate::{constants::CHUNK_SIZE, error::SealError};
use aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use rand::{RngCore, rngs::OsRng};
use std::io::Read;
use zeroize::Zeroize;

/// Number of bytes in the user-supplied stream nonce prefix.
///
/// AES-GCM nonce = 12 bytes; STREAM-BE32 overhead = 5 bytes (4 counter + 1 flag).
const STREAM_NONCE_SIZE: usize = 7;
const TAG_SIZE: usize = 16;
const ENCRYPTED_CHUNK_SIZE: usize = CHUNK_SIZE + TAG_SIZE;

/// Build the 12-byte AES-GCM nonce for a single STREAM-BE32 chunk.
fn chunk_nonce(prefix: &[u8; STREAM_NONCE_SIZE], counter: u32, last: bool) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[..7].copy_from_slice(prefix);
    nonce[7..11].copy_from_slice(&counter.to_be_bytes());
    nonce[11] = last as u8;
    nonce
}

pub fn encrypt_stream(mut plaintext: impl Read, key: &[u8; 32]) -> Result<Vec<u8>, SealError> {
    let mut key_copy = *key;
    let mut stream_nonce = [0_u8; STREAM_NONCE_SIZE];
    OsRng.fill_bytes(&mut stream_nonce);

    let cipher = Aes256Gcm::new_from_slice(&key_copy)
        .map_err(|err| SealError::EncryptionFailed(err.to_string()))?;

    let mut output = Vec::with_capacity(STREAM_NONCE_SIZE);
    output.extend_from_slice(&stream_nonce);

    let first_chunk = read_chunk(&mut plaintext, CHUNK_SIZE)?;
    let mut counter: u32 = 0;

    match first_chunk {
        None => {
            // Empty plaintext: emit a single last-block chunk with empty payload.
            let nonce_bytes = chunk_nonce(&stream_nonce, counter, true);
            let nonce = Nonce::from(nonce_bytes);
            let mut buf: Vec<u8> = Vec::new();
            cipher
                .encrypt_in_place(&nonce, b"", &mut buf)
                .map_err(|err| SealError::EncryptionFailed(err.to_string()))?;
            output.extend_from_slice(&buf);
        }
        Some(mut current) => loop {
            match read_chunk(&mut plaintext, CHUNK_SIZE)? {
                Some(next) => {
                    // Non-final chunk.
                    let nonce_bytes = chunk_nonce(&stream_nonce, counter, false);
                    let nonce = Nonce::from(nonce_bytes);
                    let mut buf = current.clone();
                    cipher
                        .encrypt_in_place(&nonce, b"", &mut buf)
                        .map_err(|err| SealError::EncryptionFailed(err.to_string()))?;
                    output.extend_from_slice(&buf);
                    current.zeroize();
                    current = next;
                    counter = counter
                        .checked_add(1)
                        .ok_or_else(|| SealError::EncryptionFailed("counter overflow".into()))?;
                }
                None => {
                    // Final chunk.
                    let nonce_bytes = chunk_nonce(&stream_nonce, counter, true);
                    let nonce = Nonce::from(nonce_bytes);
                    let mut buf = current.clone();
                    cipher
                        .encrypt_in_place(&nonce, b"", &mut buf)
                        .map_err(|err| SealError::EncryptionFailed(err.to_string()))?;
                    output.extend_from_slice(&buf);
                    current.zeroize();
                    break;
                }
            }
        },
    }

    key_copy.zeroize();
    stream_nonce.zeroize();
    Ok(output)
}

pub fn decrypt_stream(mut ciphertext: impl Read, key: &[u8; 32]) -> Result<Vec<u8>, SealError> {
    let mut key_copy = *key;
    let mut stream_nonce = [0_u8; STREAM_NONCE_SIZE];
    ciphertext
        .read_exact(&mut stream_nonce)
        .map_err(|err| SealError::DecryptionFailed(format!("failed to read nonce: {err}")))?;

    let cipher = Aes256Gcm::new_from_slice(&key_copy)
        .map_err(|err| SealError::DecryptionFailed(err.to_string()))?;

    let mut output = Vec::new();
    let mut counter: u32 = 0;

    let first_segment = read_chunk(&mut ciphertext, ENCRYPTED_CHUNK_SIZE)?;
    let mut current = first_segment.ok_or_else(|| {
        SealError::DecryptionFailed("ciphertext missing encrypted payload".to_string())
    })?;

    loop {
        match read_chunk(&mut ciphertext, ENCRYPTED_CHUNK_SIZE)? {
            Some(next) => {
                if current.len() != ENCRYPTED_CHUNK_SIZE {
                    current.zeroize();
                    return Err(SealError::DecryptionFailed(
                        "truncated ciphertext chunk before final segment".to_string(),
                    ));
                }

                // Non-final chunk.
                let nonce_bytes = chunk_nonce(&stream_nonce, counter, false);
                let nonce = Nonce::from(nonce_bytes);
                let mut buf = current.clone();
                cipher
                    .decrypt_in_place(&nonce, b"", &mut buf)
                    .map_err(|err| SealError::DecryptionFailed(err.to_string()))?;
                output.extend_from_slice(&buf);
                current.zeroize();
                current = next;
                counter = counter
                    .checked_add(1)
                    .ok_or_else(|| SealError::DecryptionFailed("counter overflow".into()))?;
            }
            None => {
                // Final chunk.
                let nonce_bytes = chunk_nonce(&stream_nonce, counter, true);
                let nonce = Nonce::from(nonce_bytes);
                let mut buf = current.clone();
                cipher
                    .decrypt_in_place(&nonce, b"", &mut buf)
                    .map_err(|err| SealError::DecryptionFailed(err.to_string()))?;
                output.extend_from_slice(&buf);
                current.zeroize();
                break;
            }
        }
    }

    key_copy.zeroize();
    stream_nonce.zeroize();
    Ok(output)
}

fn read_chunk(reader: &mut impl Read, max_len: usize) -> Result<Option<Vec<u8>>, SealError> {
    let mut chunk = Vec::with_capacity(max_len);
    let mut buffer = [0_u8; 8192];

    while chunk.len() < max_len {
        let to_read = (max_len - chunk.len()).min(buffer.len());
        let read = reader.read(&mut buffer[..to_read])?;
        if read == 0 {
            break;
        }
        chunk.extend_from_slice(&buffer[..read]);
    }

    buffer.zeroize();
    if chunk.is_empty() {
        Ok(None)
    } else {
        Ok(Some(chunk))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Read};

    struct ErrReader;

    impl Read for ErrReader {
        fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("forced read failure"))
        }
    }

    fn patterned_bytes(len: usize) -> Vec<u8> {
        (0..len).map(|idx| (idx % 251) as u8).collect()
    }

    #[test]
    fn round_trip_encrypts_and_decrypts_1kb() {
        let key = [7_u8; 32];
        let plaintext = patterned_bytes(1024);

        let encrypted =
            encrypt_stream(Cursor::new(&plaintext), &key).expect("encryption should work");
        let decrypted =
            decrypt_stream(Cursor::new(encrypted), &key).expect("decryption should work");

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn round_trip_encrypts_and_decrypts_1mb() {
        let key = [9_u8; 32];
        let plaintext = patterned_bytes(1024 * 1024);

        let encrypted =
            encrypt_stream(Cursor::new(&plaintext), &key).expect("encryption should work");
        let decrypted =
            decrypt_stream(Cursor::new(encrypted), &key).expect("decryption should work");

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn round_trip_encrypts_and_decrypts_10mb() {
        let key = [11_u8; 32];
        let plaintext = patterned_bytes(10 * 1024 * 1024);

        let encrypted =
            encrypt_stream(Cursor::new(&plaintext), &key).expect("encryption should work");
        let decrypted =
            decrypt_stream(Cursor::new(encrypted), &key).expect("decryption should work");

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn round_trip_encrypts_and_decrypts_empty_payload() {
        let key = [5_u8; 32];
        let plaintext = Vec::<u8>::new();

        let encrypted =
            encrypt_stream(Cursor::new(&plaintext), &key).expect("encryption should work");
        let decrypted =
            decrypt_stream(Cursor::new(encrypted), &key).expect("decryption should work");

        assert!(decrypted.is_empty());
    }

    #[test]
    fn wrong_key_returns_decryption_failed() {
        let key = [1_u8; 32];
        let wrong_key = [2_u8; 32];
        let plaintext = patterned_bytes(2048);

        let encrypted =
            encrypt_stream(Cursor::new(&plaintext), &key).expect("encryption should work");
        let err =
            decrypt_stream(Cursor::new(encrypted), &wrong_key).expect_err("wrong key should fail");

        match err {
            SealError::DecryptionFailed(message) => {
                assert!(!message.is_empty());
            }
            other => panic!("expected decryption failure, got {other:?}"),
        }
    }

    #[test]
    fn truncated_ciphertext_returns_decryption_failed() {
        let key = [3_u8; 32];
        let plaintext = patterned_bytes(4096);

        let mut encrypted =
            encrypt_stream(Cursor::new(&plaintext), &key).expect("encryption should work");
        encrypted.truncate(encrypted.len().saturating_sub(8));

        let err = decrypt_stream(Cursor::new(encrypted), &key)
            .expect_err("truncated ciphertext should fail");
        assert!(matches!(err, SealError::DecryptionFailed(_)));
    }

    #[test]
    fn decrypt_stream_rejects_missing_nonce() {
        let key = [4_u8; 32];
        let err = decrypt_stream(Cursor::new(Vec::<u8>::new()), &key)
            .expect_err("missing nonce must fail");
        assert!(matches!(err, SealError::DecryptionFailed(_)));
    }

    #[test]
    fn decrypt_stream_rejects_nonce_without_ciphertext() {
        let key = [6_u8; 32];
        let err = decrypt_stream(Cursor::new(vec![0_u8; STREAM_NONCE_SIZE]), &key)
            .expect_err("missing encrypted body must fail");
        assert!(matches!(err, SealError::DecryptionFailed(_)));
    }

    #[test]
    fn decrypt_stream_detects_truncated_non_final_chunk() {
        let key = [8_u8; 32];
        let plaintext = patterned_bytes((CHUNK_SIZE * 2) + 17);
        let encrypted = encrypt_stream(Cursor::new(&plaintext), &key).unwrap();

        let nonce = encrypted[..STREAM_NONCE_SIZE].to_vec();
        let body = &encrypted[STREAM_NONCE_SIZE..];
        let first_full = &body[..ENCRYPTED_CHUNK_SIZE];
        let truncated_middle = &body[ENCRYPTED_CHUNK_SIZE..(ENCRYPTED_CHUNK_SIZE * 2) - 5];
        let last = &body[(ENCRYPTED_CHUNK_SIZE * 2)..];

        let mut malformed = Vec::new();
        malformed.extend_from_slice(&nonce);
        malformed.extend_from_slice(first_full);
        malformed.extend_from_slice(truncated_middle);
        malformed.extend_from_slice(last);

        let err = decrypt_stream(Cursor::new(malformed), &key)
            .expect_err("truncated middle chunk must fail");
        assert!(matches!(err, SealError::DecryptionFailed(_)));
    }

    #[test]
    fn read_chunk_returns_none_for_empty_reader() {
        let mut cursor = Cursor::new(Vec::<u8>::new());
        let chunk = read_chunk(&mut cursor, 16).unwrap();
        assert!(chunk.is_none());
    }

    #[test]
    fn read_chunk_limits_to_max_len() {
        let mut cursor = Cursor::new(patterned_bytes(100));
        let first = read_chunk(&mut cursor, 33).unwrap().unwrap();
        let second = read_chunk(&mut cursor, 33).unwrap().unwrap();
        let third = read_chunk(&mut cursor, 33).unwrap().unwrap();
        let fourth = read_chunk(&mut cursor, 33).unwrap().unwrap();
        let fifth = read_chunk(&mut cursor, 33).unwrap();

        assert_eq!(first.len(), 33);
        assert_eq!(second.len(), 33);
        assert_eq!(third.len(), 33);
        assert_eq!(fourth.len(), 1);
        assert!(fifth.is_none());
    }

    #[test]
    fn encrypt_stream_propagates_reader_io_errors() {
        let key = [10_u8; 32];
        let err = encrypt_stream(ErrReader, &key).expect_err("reader error must propagate");
        assert!(matches!(err, SealError::Io(_)));
    }

    #[test]
    fn decrypt_stream_propagates_reader_io_errors_after_nonce() {
        struct NonceThenErrReader {
            nonce: [u8; STREAM_NONCE_SIZE],
            emitted_nonce: bool,
        }

        impl Read for NonceThenErrReader {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                if !self.emitted_nonce {
                    let len = self.nonce.len().min(buf.len());
                    buf[..len].copy_from_slice(&self.nonce[..len]);
                    self.emitted_nonce = true;
                    return Ok(len);
                }
                Err(std::io::Error::other("forced body read failure"))
            }
        }

        let key = [12_u8; 32];
        let reader = NonceThenErrReader {
            nonce: [0_u8; STREAM_NONCE_SIZE],
            emitted_nonce: false,
        };

        let err = decrypt_stream(reader, &key).expect_err("reader error must propagate");
        assert!(matches!(err, SealError::Io(_)));
    }
}

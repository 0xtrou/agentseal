use serde::{Deserialize, Serialize};

/// 4-byte magic: "ASL\x01"
pub const MAGIC_BYTES: [u8; 4] = [0x41, 0x53, 0x4C, 0x01];
pub const VERSION_V1: u16 = 0x0001;
pub const ENC_ALG_AES256_GCM: u16 = 0x0001;
pub const FMT_STREAM: u16 = 0x0001;
pub const CHUNK_SIZE: usize = 65536; // 64KB
pub const KDF_INFO_ENV: &[u8] = b"agent-seal/env/v1";
pub const KDF_INFO_SESSION: &[u8] = b"agent-seal/session/v1";
pub const LAUNCHER_MARKER: &[u8; 17] = b"ASL_SECRET_MRK_01";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PayloadHeader {
    pub magic: [u8; 4],
    pub version: u16,
    pub enc_alg: u16,
    pub fmt_version: u16,
    pub chunk_count: u32,
    pub header_hmac: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ChunkRecord {
    pub len: u32,
    pub data: Vec<u8>, // ciphertext + 16-byte tag
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PayloadFooter {
    pub original_hash: [u8; 32],
    pub launcher_hash: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionResult {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

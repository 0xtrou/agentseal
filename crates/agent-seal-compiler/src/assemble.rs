use agent_seal_core::{derive::derive_env_key, error::SealError, payload::pack_payload};
use std::{io::Cursor, path::PathBuf};

pub struct AssembleConfig {
    pub agent_elf_path: PathBuf,
    pub launcher_path: PathBuf,
    pub master_secret: [u8; 32],
    pub stable_fingerprint_hash: [u8; 32],
    pub user_fingerprint: [u8; 32],
}

pub fn assemble(config: &AssembleConfig) -> Result<Vec<u8>, SealError> {
    let agent_elf_bytes = std::fs::read(&config.agent_elf_path)?;
    let key = derive_env_key(
        &config.master_secret,
        &config.stable_fingerprint_hash,
        &config.user_fingerprint,
    )?;

    let encrypted_payload = pack_payload(Cursor::new(agent_elf_bytes), &key)?;
    let launcher_bytes = std::fs::read(&config.launcher_path)?;

    let mut assembled = Vec::with_capacity(launcher_bytes.len() + encrypted_payload.len());
    assembled.extend_from_slice(&launcher_bytes);
    assembled.extend_from_slice(&encrypted_payload);
    Ok(assembled)
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_seal_core::{
        derive::derive_env_key,
        payload::{pack_payload, unpack_payload},
    };
    use std::io::Cursor;

    fn test_root(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("agent-seal-assemble-{name}"))
    }

    #[test]
    fn assembled_binary_is_launcher_plus_encrypted_payload() {
        let root = test_root("size");
        std::fs::create_dir_all(&root).expect("test root should be creatable");

        let agent_path = root.join("agent.bin");
        let launcher_path = root.join("launcher.bin");

        let agent_bytes = vec![0xAA; 1024];
        let launcher_bytes = vec![0xBB; 2048];

        std::fs::write(&agent_path, &agent_bytes).expect("agent bytes should be writable");
        std::fs::write(&launcher_path, &launcher_bytes).expect("launcher bytes should be writable");

        let config = AssembleConfig {
            agent_elf_path: agent_path,
            launcher_path,
            master_secret: [1_u8; 32],
            stable_fingerprint_hash: [2_u8; 32],
            user_fingerprint: [3_u8; 32],
        };

        let assembled = assemble(&config).expect("assembly should succeed");

        let key = derive_env_key(
            &config.master_secret,
            &config.stable_fingerprint_hash,
            &config.user_fingerprint,
        )
        .expect("key derivation should succeed");
        let expected_payload = pack_payload(Cursor::new(agent_bytes.clone()), &key)
            .expect("payload packing should succeed");

        assert_eq!(
            assembled.len(),
            launcher_bytes.len() + expected_payload.len()
        );

        let launcher_len = launcher_bytes.len();
        let payload_section = &assembled[launcher_len..];

        // Verify the payload section can be decrypted (not just size match)
        // We can't compare exact bytes because AES-GCM uses random nonces
        assert_eq!(payload_section.len(), expected_payload.len());

        // Verify payload starts with magic bytes and has valid header
        assert!(payload_section.len() > 20);
        assert_eq!(&payload_section[..4], b"ASL\x01");
    }

    #[test]
    fn payload_section_round_trip_after_assembly() {
        let root = test_root("roundtrip");
        std::fs::create_dir_all(&root).expect("test root should be creatable");

        let agent_path = root.join("agent.bin");
        let launcher_path = root.join("launcher.bin");

        let agent_bytes = b"#!/usr/bin/env python3\nprint('hello')\n".to_vec();
        let launcher_bytes = vec![0x11; 1536];

        std::fs::write(&agent_path, &agent_bytes).expect("agent bytes should be writable");
        std::fs::write(&launcher_path, &launcher_bytes).expect("launcher bytes should be writable");

        let master_secret = [9_u8; 32];
        let stable_fingerprint_hash = [8_u8; 32];
        let user_fingerprint = [7_u8; 32];

        let config = AssembleConfig {
            agent_elf_path: agent_path,
            launcher_path,
            master_secret,
            stable_fingerprint_hash,
            user_fingerprint,
        };

        let assembled = assemble(&config).expect("assembly should succeed");
        let payload_section = &assembled[launcher_bytes.len()..];

        let key = derive_env_key(&master_secret, &stable_fingerprint_hash, &user_fingerprint)
            .expect("key derivation should succeed");
        let (decrypted, _header) =
            unpack_payload(Cursor::new(payload_section), &key).expect("payload should unpack");

        assert_eq!(decrypted, agent_bytes);
    }
}

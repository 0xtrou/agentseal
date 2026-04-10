use snapfzz_seal_core::{
    error::SealError,
    whitebox::{WhiteBoxAES, WhiteBoxTables},
};

pub const WHITEBOX_TABLES_MARKER: &[u8] = b"ASL_WB_TABLES_v1";

pub fn generate_whitebox_tables(master_key: &[u8; 32]) -> WhiteBoxTables {
    WhiteBoxAES::generate_tables(master_key)
}

pub fn embed_whitebox_tables(binary: &[u8], tables: &WhiteBoxTables) -> Result<Vec<u8>, SealError> {
    let tables_bytes = tables.to_bytes();

    let mut modified = binary.to_vec();

    if let Some(pos) = modified
        .windows(WHITEBOX_TABLES_MARKER.len())
        .position(|w| w == WHITEBOX_TABLES_MARKER)
    {
        let table_start = pos + WHITEBOX_TABLES_MARKER.len();

        if table_start + tables_bytes.len() > modified.len() {
            let needed = table_start + tables_bytes.len() - modified.len();
            modified.extend_from_slice(&vec![0u8; needed]);
        }

        modified[table_start..table_start + tables_bytes.len()].copy_from_slice(&tables_bytes);
    } else {
        modified.extend_from_slice(WHITEBOX_TABLES_MARKER);
        modified.extend_from_slice(&tables_bytes);
    }

    tracing::info!(
        tables_size = tables_bytes.len(),
        total_size = modified.len(),
        "embedded white-box tables"
    );

    Ok(modified)
}

pub fn estimate_whitebox_size() -> usize {
    2_000_000
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_tables() {
        let key = [0x42u8; 32];
        let tables = generate_whitebox_tables(&key);

        assert_eq!(tables.t_boxes.len(), 224);
        assert_eq!(tables.type_i.len(), 13);
        assert_eq!(tables.type_ii.len(), 13);

        let size = tables.estimate_size();
        assert!(size > 100_000);
        assert!(size < 5_000_000);
    }

    #[test]
    fn test_embed_tables_without_marker() {
        let key = [0x42u8; 32];
        let tables = generate_whitebox_tables(&key);
        let binary = b"launcher binary content".to_vec();

        let embedded = embed_whitebox_tables(&binary, &tables).unwrap();

        assert!(embedded.len() > binary.len());
        assert!(
            embedded
                .windows(WHITEBOX_TABLES_MARKER.len())
                .any(|w| w == WHITEBOX_TABLES_MARKER)
        );
    }

    #[test]
    fn test_embed_tables_with_marker() {
        let key = [0x42u8; 32];
        let tables = generate_whitebox_tables(&key);
        let mut binary = b"launcher binary content".to_vec();
        binary.extend_from_slice(WHITEBOX_TABLES_MARKER);
        binary.extend_from_slice(&[0u8; 1024]);

        let embedded = embed_whitebox_tables(&binary, &tables).unwrap();

        assert!(embedded.starts_with(&binary[..binary.len() - 1024]));
    }

    #[test]
    fn test_estimate_size() {
        let size = estimate_whitebox_size();
        assert!(size >= 500_000);
        assert!(size <= 5_000_000);
    }
}

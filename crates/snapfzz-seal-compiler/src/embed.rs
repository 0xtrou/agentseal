use snapfzz_seal_core::{
    error::SealError,
    shamir::split_secret,
    types::{
        LAUNCHER_PAYLOAD_SENTINEL, LAUNCHER_TAMPER_MARKER, SHAMIR_THRESHOLD, SHAMIR_TOTAL_SHARES,
        get_secret_marker,
    },
};

pub fn embed_master_secret(launcher_bytes: &[u8], secret: &[u8; 32]) -> Result<Vec<u8>, SealError> {
    embed_master_secret_with_shamir(launcher_bytes, secret)
}

pub fn embed_master_secret_with_shamir(
    launcher_bytes: &[u8],
    secret: &[u8; 32],
) -> Result<Vec<u8>, SealError> {
    let shares = split_secret(secret, SHAMIR_THRESHOLD, SHAMIR_TOTAL_SHARES)
        .map_err(|e| embed_failed(&format!("shamir split failed: {e}")))?;

    let mut modified = launcher_bytes.to_vec();

    for (i, (_x, share)) in shares.iter().enumerate() {
        let marker = get_secret_marker(i);
        let marker_offset = find_marker_with_slot(&modified, marker, share.len())
            .ok_or_else(|| embed_failed(&format!("marker {} not found", i + 1)))?;

        let share_offset = marker_offset + marker.len();
        let end_offset = share_offset + share.len();
        if modified.len() < end_offset {
            return Err(embed_failed(&format!(
                "launcher too small for share slot {}",
                i + 1
            )));
        }

        modified[share_offset..end_offset].copy_from_slice(share);
    }

    Ok(modified)
}

pub fn embed_tamper_hash(launcher_bytes: &[u8], hash: &[u8; 32]) -> Result<Vec<u8>, SealError> {
    replace_after_marker(launcher_bytes, LAUNCHER_TAMPER_MARKER, hash)
}

fn replace_after_marker(
    launcher_bytes: &[u8],
    marker: &[u8; 32],
    replacement: &[u8; 32],
) -> Result<Vec<u8>, SealError> {
    let Some(marker_offset) = find_marker_with_slot(launcher_bytes, marker, replacement.len())
    else {
        return Err(embed_failed("marker not found"));
    };

    let payload_offset = marker_offset + marker.len();
    let end_offset = payload_offset + replacement.len();
    if launcher_bytes.len() < end_offset {
        return Err(embed_failed("launcher too small for embedded payload"));
    }

    let mut modified = launcher_bytes.to_vec();
    modified[payload_offset..end_offset].copy_from_slice(replacement);
    Ok(modified)
}

fn find_marker(haystack: &[u8], marker: &[u8]) -> Option<usize> {
    haystack
        .windows(marker.len())
        .position(|window| window == marker)
}

fn marker_is_followed_by_slot(
    launcher_bytes: &[u8],
    marker_offset: usize,
    slot_len: usize,
) -> bool {
    let slot_start = marker_offset + 32;
    let slot_end = slot_start + slot_len;

    if launcher_bytes.len() < slot_end {
        return false;
    }

    if launcher_bytes[slot_start..slot_end]
        .windows(32)
        .any(|window| window == LAUNCHER_PAYLOAD_SENTINEL || window == LAUNCHER_TAMPER_MARKER)
    {
        return false;
    }

    for index in 0..SHAMIR_TOTAL_SHARES {
        if launcher_bytes[slot_start..slot_end]
            .windows(32)
            .any(|window| window == get_secret_marker(index))
        {
            return false;
        }
    }

    true
}

fn find_marker_with_slot(
    launcher_bytes: &[u8],
    marker: &[u8; 32],
    slot_len: usize,
) -> Option<usize> {
    let mut search_from = 0usize;

    while search_from + marker.len() <= launcher_bytes.len() {
        let relative_offset = find_marker(&launcher_bytes[search_from..], marker)?;
        let marker_offset = search_from + relative_offset;
        if marker_is_followed_by_slot(launcher_bytes, marker_offset, slot_len) {
            return Some(marker_offset);
        }
        search_from = marker_offset + marker.len();
    }

    None
}

fn embed_failed(detail: &str) -> SealError {
    SealError::CompilationError(format!("EmbedFailed: {detail}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use snapfzz_seal_core::{
        shamir::reconstruct_secret,
        types::{
            LAUNCHER_PAYLOAD_SENTINEL, LAUNCHER_TAMPER_MARKER, SHAMIR_THRESHOLD,
            SHAMIR_TOTAL_SHARES, get_secret_marker,
        },
    };

    fn launcher_with_share_slots(slot_len: usize) -> Vec<u8> {
        let mut launcher = vec![0xAA; 64];
        for i in 0..SHAMIR_TOTAL_SHARES {
            launcher.extend_from_slice(get_secret_marker(i));
            launcher.extend_from_slice(&vec![0_u8; slot_len]);
            launcher.extend_from_slice(&[0xA0 + i as u8; 7]);
        }
        launcher.extend_from_slice(LAUNCHER_TAMPER_MARKER);
        launcher.extend_from_slice(&[0x11_u8; 32]);
        launcher.extend_from_slice(&[0xBB; 64]);
        launcher
    }

    #[test]
    fn embed_master_secret_replaces_all_five_secret_share_slots() {
        let launcher = launcher_with_share_slots(32);
        let secret = [0x0C; 32];

        let modified = embed_master_secret(&launcher, &secret).expect("embed should succeed");

        let mut shares = Vec::new();
        for i in 0..SHAMIR_TOTAL_SHARES {
            let marker = get_secret_marker(i);
            let marker_offset = find_marker(&modified, marker).expect("marker should remain");
            let share_start = marker_offset + marker.len();
            let mut share = [0u8; 32];
            share.copy_from_slice(&modified[share_start..share_start + 32]);
            shares.push(((i + 1) as u8, share));
        }

        assert_eq!(shares.len(), 5);
        let recovered = reconstruct_secret(&shares[1..4], SHAMIR_THRESHOLD).unwrap();
        assert_eq!(recovered, secret);

        let tamper_marker_offset =
            find_marker(&modified, LAUNCHER_TAMPER_MARKER).expect("tamper marker exists");
        let tamper_start = tamper_marker_offset + LAUNCHER_TAMPER_MARKER.len();
        assert_eq!(&modified[tamper_start..tamper_start + 32], &[0x11_u8; 32]);
    }

    #[test]
    fn embed_tamper_hash_replaces_bytes_after_tamper_marker() {
        let launcher = launcher_with_share_slots(32);

        let hash = [0x44; 32];
        let modified = embed_tamper_hash(&launcher, &hash).expect("embed should succeed");

        let tamper_start =
            find_marker(&modified, LAUNCHER_TAMPER_MARKER).unwrap() + LAUNCHER_TAMPER_MARKER.len();
        assert_eq!(&modified[tamper_start..tamper_start + 32], &hash);
    }

    #[test]
    fn embed_skips_false_positive_marker_without_slot() {
        let marker0 = get_secret_marker(0);
        let marker1 = get_secret_marker(1);

        let mut launcher = vec![0xAA; 16];
        launcher.extend_from_slice(marker0);
        launcher.extend_from_slice(marker1);
        launcher.extend_from_slice(&[0xBB; 16]);
        launcher.extend_from_slice(marker0);
        launcher.extend_from_slice(&[0u8; 32]);

        let marker_offset = find_marker_with_slot(&launcher, marker0, 32)
            .expect("real marker slot should be found");

        assert_eq!(marker_offset, 16 + 32 + 32 + 16);
    }

    #[test]
    fn marker_slot_rejects_payload_or_tamper_markers_inside_slot() {
        let marker0 = get_secret_marker(0);

        let mut launcher = vec![0xCC; 24];
        launcher.extend_from_slice(marker0);
        launcher.extend_from_slice(LAUNCHER_PAYLOAD_SENTINEL);

        assert!(find_marker_with_slot(&launcher, marker0, 32).is_none());

        launcher.truncate(24 + 32);
        launcher.extend_from_slice(LAUNCHER_TAMPER_MARKER);

        assert!(find_marker_with_slot(&launcher, marker0, 32).is_none());
    }

    #[test]
    fn embed_returns_error_when_any_secret_marker_is_missing() {
        let err =
            embed_master_secret(&[1_u8; 64], &[2_u8; 32]).expect_err("missing marker should fail");

        match err {
            SealError::CompilationError(message) => {
                assert!(message.contains("EmbedFailed: marker 1 not found"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn embed_tamper_hash_returns_error_when_marker_missing() {
        let err = embed_tamper_hash(&[1_u8; 64], &[3_u8; 32])
            .expect_err("missing tamper marker should fail");

        match err {
            SealError::CompilationError(message) => {
                assert!(message.contains("EmbedFailed: marker not found"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn embed_master_secret_returns_error_when_any_share_slot_is_too_short() {
        let launcher = launcher_with_share_slots(8);

        let err = embed_master_secret(&launcher, &[0x55_u8; 32])
            .expect_err("insufficient bytes after marker should fail");

        match err {
            SealError::CompilationError(message) => {
                assert!(message.contains("EmbedFailed:"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }
}

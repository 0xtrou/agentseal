#![allow(unsafe_code)]

mod anti_debug;
mod memfd_exec;
mod self_delete;

use std::io::Cursor;

use agent_seal_core::{
    derive::derive_env_key,
    error::SealError,
    payload::{unpack_payload, validate_payload_header},
    types::LAUNCHER_PAYLOAD_SENTINEL,
};
use agent_seal_fingerprint::{FingerprintCollector, canonicalize_stable};
use clap::{Parser, ValueEnum};
use memfd_exec::{ExecConfig, KernelMemfdOps, MemfdExecutor};
use tracing_subscriber::EnvFilter;
use zeroize::{Zeroize, Zeroizing};

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum FingerprintMode {
    Stable,
    Session,
}

#[derive(Debug, Parser)]
#[command(name = "agent-seal-launcher")]
#[command(about = "Agent Seal launcher")]
pub struct Cli {
    #[arg(long)]
    pub payload: Option<String>,
    #[arg(long, value_enum, default_value_t = FingerprintMode::Stable)]
    pub fingerprint_mode: FingerprintMode,
    #[arg(long)]
    pub user_fingerprint: Option<String>,
    #[arg(long)]
    pub verbose: bool,
}

pub fn run(cli: Cli) -> Result<(), SealError> {
    let payload_bytes = load_payload_bytes(cli.payload.as_deref())?;
    validate_payload_header(&payload_bytes)?;

    let protections = anti_debug::apply_protections()?;
    tracing::info!(?protections, "anti-debug protections evaluated");

    let collector = FingerprintCollector::new();
    let snapshot = match cli.fingerprint_mode {
        FingerprintMode::Stable => collector
            .collect_stable_only()
            .map_err(|err| SealError::InvalidInput(err.to_string()))?,
        FingerprintMode::Session => collector
            .collect()
            .map_err(|err| SealError::InvalidInput(err.to_string()))?,
    };

    let stable_hash = canonicalize_stable(&snapshot);
    let user_fingerprint = decode_user_fingerprint(cli.user_fingerprint)?;
    let mut master_secret = load_master_secret()?;

    let mut env_key = derive_env_key(&master_secret, &stable_hash, &user_fingerprint)?;
    let decrypted = Zeroizing::new(match unpack_payload(Cursor::new(payload_bytes), &env_key) {
        Ok((bytes, _header)) => bytes,
        Err(SealError::DecryptionFailed(_)) => {
            eprintln!(
                "ERROR: fingerprint mismatch — sandbox environment has changed, re-provisioning required"
            );
            std::process::exit(1);
        }
        Err(err) => return Err(err),
    });

    env_key.zeroize();
    master_secret.zeroize();

    self_delete::self_delete()?;

    let executor = MemfdExecutor::new(KernelMemfdOps);
    let config = ExecConfig {
        args: Vec::new(),
        env: Vec::new(),
        cwd: None,
    };

    let result = executor.execute(decrypted.as_slice(), &config)?;
    let json = serde_json::to_string(&result).map_err(|err| {
        SealError::InvalidInput(format!("failed to serialize execution result: {err}"))
    })?;
    println!("{json}");
    Ok(())
}

pub fn init_tracing(verbose: bool) {
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        if verbose {
            EnvFilter::new("debug")
        } else {
            EnvFilter::new("info")
        }
    });

    let _ = tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .try_init();
}

pub fn format_user_error(err: &SealError) -> String {
    match err {
        SealError::EncryptionFailed(_) => "ERROR: failed to encrypt payload".to_string(),
        SealError::DecryptionFailed(_) => "ERROR: failed to decrypt payload".to_string(),
        SealError::InvalidPayload(msg) => format!("ERROR: invalid payload: {msg}"),
        SealError::UnsupportedPayloadVersion(version) => {
            format!("ERROR: unsupported payload version: {version}")
        }
        SealError::TamperDetected => "ERROR: tamper detected".to_string(),
        SealError::FingerprintMismatch => {
            "ERROR: fingerprint mismatch — sandbox environment has changed".to_string()
        }
        SealError::Io(msg) => format!("ERROR: IO failure: {msg}"),
        SealError::InvalidInput(msg) => format!("ERROR: invalid input: {msg}"),
        SealError::CompilationError(msg) => format!("ERROR: compilation error: {msg}"),
        SealError::CompilationTimeout(seconds) => {
            format!("ERROR: compilation timeout after {seconds}s")
        }
        SealError::Other(msg) => format!("ERROR: {msg}"),
    }
}

fn load_payload_bytes(payload_arg: Option<&str>) -> Result<Vec<u8>, SealError> {
    match payload_arg {
        Some(path) if !path.eq_ignore_ascii_case("self") => std::fs::read(path).map_err(Into::into),
        _ => {
            let executable_bytes = std::fs::read("/proc/self/exe")?;
            extract_payload_from_assembled_binary(&executable_bytes)
        }
    }
}

fn extract_payload_from_assembled_binary(executable_bytes: &[u8]) -> Result<Vec<u8>, SealError> {
    if let Ok(raw_launcher_size) = std::env::var("AGENT_SEAL_LAUNCHER_SIZE") {
        let launcher_size = raw_launcher_size.parse::<usize>().map_err(|err| {
            SealError::InvalidInput(format!("invalid AGENT_SEAL_LAUNCHER_SIZE: {err}"))
        })?;
        return extract_payload_at_launcher_size(executable_bytes, launcher_size);
    }

    let marker_offset = find_marker(executable_bytes, LAUNCHER_PAYLOAD_SENTINEL).ok_or_else(|| {
        SealError::InvalidInput(
            "unable to locate embedded payload in self executable; set AGENT_SEAL_LAUNCHER_SIZE or provide --payload"
                .to_string(),
        )
    })?;

    payload_from_offset(
        executable_bytes,
        marker_offset + LAUNCHER_PAYLOAD_SENTINEL.len(),
    )
}

fn extract_payload_at_launcher_size(
    executable_bytes: &[u8],
    launcher_size: usize,
) -> Result<Vec<u8>, SealError> {
    if launcher_size >= executable_bytes.len() {
        return Err(SealError::InvalidInput(
            "AGENT_SEAL_LAUNCHER_SIZE points beyond executable length".to_string(),
        ));
    }

    let mut payload_offset = launcher_size;
    if executable_bytes[payload_offset..].starts_with(LAUNCHER_PAYLOAD_SENTINEL) {
        payload_offset += LAUNCHER_PAYLOAD_SENTINEL.len();
    }

    payload_from_offset(executable_bytes, payload_offset)
}

fn payload_from_offset(
    executable_bytes: &[u8],
    payload_offset: usize,
) -> Result<Vec<u8>, SealError> {
    if payload_offset >= executable_bytes.len() {
        return Err(SealError::InvalidInput(
            "embedded payload section is empty".to_string(),
        ));
    }

    Ok(executable_bytes[payload_offset..].to_vec())
}

fn find_marker(haystack: &[u8], marker: &[u8]) -> Option<usize> {
    haystack
        .windows(marker.len())
        .position(|window| window == marker)
}

fn decode_user_fingerprint(user_fingerprint_hex: Option<String>) -> Result<[u8; 32], SealError> {
    let value = user_fingerprint_hex.ok_or_else(|| {
        SealError::InvalidInput("--user-fingerprint <HEX> is required".to_string())
    })?;

    let decoded = hex::decode(&value)
        .map_err(|err| SealError::InvalidInput(format!("invalid user fingerprint hex: {err}")))?;

    if decoded.len() != 32 {
        return Err(SealError::InvalidInput(
            "user fingerprint must be 64 hex chars (32 bytes)".to_string(),
        ));
    }

    let mut out = [0_u8; 32];
    out.copy_from_slice(&decoded);
    Ok(out)
}

fn load_master_secret() -> Result<[u8; 32], SealError> {
    let raw = std::env::var("AGENT_SEAL_MASTER_SECRET_HEX").map_err(|_| {
        tracing::error!("AGENT_SEAL_MASTER_SECRET_HEX is required");
        SealError::InvalidInput(
            "AGENT_SEAL_MASTER_SECRET_HEX is required and must contain 64 hex chars (32 bytes)"
                .to_string(),
        )
    })?;

    let decoded = hex::decode(raw).map_err(|err| {
        SealError::InvalidInput(format!("invalid AGENT_SEAL_MASTER_SECRET_HEX: {err}"))
    })?;

    if decoded.len() != 32 {
        return Err(SealError::InvalidInput(
            "AGENT_SEAL_MASTER_SECRET_HEX must be 64 hex chars (32 bytes)".to_string(),
        ));
    }

    let mut secret = [0_u8; 32];
    secret.copy_from_slice(&decoded);
    Ok(secret)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicU64, Ordering};

    static ENV_LOCK: Mutex<()> = Mutex::new(());
    static TEMP_ID: AtomicU64 = AtomicU64::new(1);

    fn unique_temp_path(stem: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "agent-seal-launcher-{stem}-{}-{}",
            std::process::id(),
            TEMP_ID.fetch_add(1, Ordering::Relaxed)
        ))
    }

    #[test]
    fn cli_parses_required_and_optional_args() {
        let cli = Cli::try_parse_from([
            "agent-seal-launcher",
            "--payload",
            "./payload.seal",
            "--fingerprint-mode",
            "session",
            "--user-fingerprint",
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
            "--verbose",
        ])
        .unwrap();

        assert_eq!(cli.payload.as_deref(), Some("./payload.seal"));
        assert_eq!(cli.fingerprint_mode, FingerprintMode::Session);
        assert_eq!(
            cli.user_fingerprint.as_deref(),
            Some("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
        );
        assert!(cli.verbose);
    }

    #[test]
    fn cli_uses_default_fingerprint_mode() {
        let cli = Cli::try_parse_from([
            "agent-seal-launcher",
            "--payload",
            "./payload.seal",
            "--user-fingerprint",
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
        ])
        .unwrap();

        assert_eq!(cli.fingerprint_mode, FingerprintMode::Stable);
    }

    #[test]
    fn cli_allows_self_extraction_without_payload_flag() {
        let cli = Cli::try_parse_from([
            "agent-seal-launcher",
            "--user-fingerprint",
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
        ])
        .unwrap();

        assert_eq!(cli.payload, None);
    }

    #[test]
    fn extract_payload_from_sentinel_without_launcher_size_env() {
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::remove_var("AGENT_SEAL_LAUNCHER_SIZE");
        }

        let payload = b"ASL\x01payload-data".to_vec();
        let mut assembled = vec![0xAA; 12];
        assembled.extend_from_slice(LAUNCHER_PAYLOAD_SENTINEL);
        assembled.extend_from_slice(&payload);

        let extracted = extract_payload_from_assembled_binary(&assembled).unwrap();
        assert_eq!(extracted, payload);
    }

    #[test]
    fn extract_payload_from_launcher_size_env_skips_sentinel() {
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::set_var("AGENT_SEAL_LAUNCHER_SIZE", "12");
        }

        let payload = b"ASL\x01payload-data".to_vec();
        let mut assembled = vec![0xAA; 12];
        assembled.extend_from_slice(LAUNCHER_PAYLOAD_SENTINEL);
        assembled.extend_from_slice(&payload);

        let extracted = extract_payload_from_assembled_binary(&assembled).unwrap();
        assert_eq!(extracted, payload);

        unsafe {
            std::env::remove_var("AGENT_SEAL_LAUNCHER_SIZE");
        }
    }

    #[test]
    fn load_master_secret_fails_when_env_missing() {
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::remove_var("AGENT_SEAL_MASTER_SECRET_HEX");
        }

        let err = load_master_secret().expect_err("missing env must fail");
        assert!(matches!(err, SealError::InvalidInput(_)));
    }

    #[test]
    fn init_tracing_handles_verbose_false_without_env_filter() {
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::remove_var("RUST_LOG");
        }
        init_tracing(false);
    }

    #[test]
    fn init_tracing_handles_verbose_true_without_env_filter() {
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::remove_var("RUST_LOG");
        }
        init_tracing(true);
    }

    #[test]
    fn init_tracing_prefers_env_filter_when_present() {
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::set_var("RUST_LOG", "warn");
        }
        init_tracing(false);
        unsafe {
            std::env::remove_var("RUST_LOG");
        }
    }

    #[test]
    fn format_user_error_covers_all_variants() {
        let cases = vec![
            (
                SealError::EncryptionFailed("enc".to_string()),
                "ERROR: failed to encrypt payload".to_string(),
            ),
            (
                SealError::DecryptionFailed("dec".to_string()),
                "ERROR: failed to decrypt payload".to_string(),
            ),
            (
                SealError::InvalidPayload("bad".to_string()),
                "ERROR: invalid payload: bad".to_string(),
            ),
            (
                SealError::UnsupportedPayloadVersion(7),
                "ERROR: unsupported payload version: 7".to_string(),
            ),
            (
                SealError::TamperDetected,
                "ERROR: tamper detected".to_string(),
            ),
            (
                SealError::FingerprintMismatch,
                "ERROR: fingerprint mismatch — sandbox environment has changed".to_string(),
            ),
            (
                SealError::Io(std::io::Error::other("io")),
                "ERROR: IO failure: io".to_string(),
            ),
            (
                SealError::InvalidInput("input".to_string()),
                "ERROR: invalid input: input".to_string(),
            ),
            (
                SealError::CompilationError("compile".to_string()),
                "ERROR: compilation error: compile".to_string(),
            ),
            (
                SealError::CompilationTimeout(42),
                "ERROR: compilation timeout after 42s".to_string(),
            ),
            (
                SealError::Other(std::io::Error::other("other").into()),
                "ERROR: other".to_string(),
            ),
        ];

        for (err, expected) in cases {
            assert_eq!(format_user_error(&err), expected);
        }
    }

    #[test]
    fn load_payload_bytes_uses_explicit_path() {
        let path = unique_temp_path("payload");
        let payload = b"ASL\x01direct-path".to_vec();
        std::fs::write(&path, &payload).unwrap();

        let loaded = load_payload_bytes(path.to_str()).unwrap();
        assert_eq!(loaded, payload);

        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn load_payload_bytes_self_and_none_error_on_non_embedded_binary() {
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::remove_var("AGENT_SEAL_LAUNCHER_SIZE");
        }

        let self_result = load_payload_bytes(Some("self"));
        let none_result = load_payload_bytes(None);

        assert!(matches!(
            self_result,
            Err(SealError::Io(_)) | Err(SealError::InvalidInput(_))
        ));
        assert!(matches!(
            none_result,
            Err(SealError::Io(_)) | Err(SealError::InvalidInput(_))
        ));
    }

    #[test]
    fn extract_payload_from_assembled_binary_rejects_launcher_size_beyond_length() {
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::set_var("AGENT_SEAL_LAUNCHER_SIZE", "100");
        }

        let assembled = vec![1_u8; 8];
        let err = extract_payload_from_assembled_binary(&assembled).expect_err("must fail");
        assert!(matches!(err, SealError::InvalidInput(_)));

        unsafe {
            std::env::remove_var("AGENT_SEAL_LAUNCHER_SIZE");
        }
    }

    #[test]
    fn extract_payload_at_launcher_size_skips_sentinel_when_present() {
        let payload = b"ASL\x01embedded".to_vec();
        let mut assembled = vec![0xEF; 5];
        assembled.extend_from_slice(LAUNCHER_PAYLOAD_SENTINEL);
        assembled.extend_from_slice(&payload);

        let extracted = extract_payload_at_launcher_size(&assembled, 5).unwrap();
        assert_eq!(extracted, payload);
    }

    #[test]
    fn payload_from_offset_rejects_offset_beyond_length() {
        let bytes = vec![1_u8, 2, 3];
        let err = payload_from_offset(&bytes, 3).expect_err("must fail");
        assert!(matches!(err, SealError::InvalidInput(_)));
    }

    #[test]
    fn find_marker_returns_expected_results() {
        let haystack = b"abc123markerxyz";
        let marker = b"marker";
        assert_eq!(find_marker(haystack, marker), Some(6));
        assert_eq!(find_marker(haystack, b"missing"), None);
    }

    #[test]
    fn decode_user_fingerprint_errors_when_missing() {
        let err = decode_user_fingerprint(None).expect_err("must fail");
        assert!(matches!(err, SealError::InvalidInput(_)));
    }

    #[test]
    fn decode_user_fingerprint_errors_on_invalid_hex() {
        let err = decode_user_fingerprint(Some("not-hex".to_string())).expect_err("must fail");
        assert!(matches!(err, SealError::InvalidInput(_)));
    }

    #[test]
    fn decode_user_fingerprint_errors_on_short_hex() {
        let err = decode_user_fingerprint(Some("aa".repeat(31))).expect_err("must fail");
        assert!(matches!(err, SealError::InvalidInput(_)));
    }

    #[test]
    fn decode_user_fingerprint_accepts_valid_hex() {
        let out = decode_user_fingerprint(Some("11".repeat(32))).unwrap();
        assert_eq!(out, [0x11; 32]);
    }

    #[test]
    fn load_master_secret_errors_when_hex_invalid() {
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::set_var("AGENT_SEAL_MASTER_SECRET_HEX", "zzzz");
        }

        let err = load_master_secret().expect_err("must fail");
        assert!(matches!(err, SealError::InvalidInput(_)));

        unsafe {
            std::env::remove_var("AGENT_SEAL_MASTER_SECRET_HEX");
        }
    }

    #[test]
    fn load_master_secret_errors_when_hex_too_short() {
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::set_var("AGENT_SEAL_MASTER_SECRET_HEX", "aa".repeat(31));
        }

        let err = load_master_secret().expect_err("must fail");
        assert!(matches!(err, SealError::InvalidInput(_)));

        unsafe {
            std::env::remove_var("AGENT_SEAL_MASTER_SECRET_HEX");
        }
    }
}

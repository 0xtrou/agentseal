#![allow(clippy::all)]
#![allow(unsafe_code)]

mod anti_debug;
mod memfd_exec;
mod self_delete;

use std::io::Cursor;

use agent_seal_core::{
    derive::derive_env_key,
    error::SealError,
    payload::{unpack_payload, validate_payload_header},
};
use agent_seal_fingerprint::{FingerprintCollector, canonicalize_stable};
use clap::{Parser, ValueEnum};
use memfd_exec::{ExecConfig, KernelMemfdOps, MemfdExecutor};
use tracing_subscriber::EnvFilter;
use zeroize::Zeroize;

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum FingerprintMode {
    Stable,
    Session,
}

#[derive(Debug, Parser)]
#[command(name = "agent-seal-launcher")]
#[command(about = "Agent Seal launcher")]
struct Cli {
    #[arg(long)]
    payload: String,
    #[arg(long, value_enum, default_value_t = FingerprintMode::Stable)]
    fingerprint_mode: FingerprintMode,
    #[arg(long)]
    user_fingerprint: Option<String>,
    #[arg(long)]
    verbose: bool,
}

fn main() {
    let cli = Cli::parse();
    init_tracing(cli.verbose);

    if let Err(err) = run(cli) {
        eprintln!("{}", format_user_error(&err));
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<(), SealError> {
    let payload_bytes = std::fs::read(&cli.payload)?;
    let _ = validate_payload_header(&payload_bytes)?;

    let protections = anti_debug::apply_protections();
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
    let decrypted = match unpack_payload(Cursor::new(payload_bytes), &env_key) {
        Ok((bytes, _header)) => bytes,
        Err(SealError::DecryptionFailed(_)) => {
            eprintln!(
                "ERROR: fingerprint mismatch — sandbox environment has changed, re-provisioning required"
            );
            std::process::exit(1);
        }
        Err(err) => return Err(err),
    };

    env_key.zeroize();
    master_secret.zeroize();

    self_delete::self_delete()?;

    let executor = MemfdExecutor::new(KernelMemfdOps);
    let config = ExecConfig {
        args: Vec::new(),
        env: Vec::new(),
        cwd: None,
    };

    let result = executor.execute(&decrypted, &config)?;
    let json = serde_json::to_string(&result).map_err(|err| {
        SealError::InvalidInput(format!("failed to serialize execution result: {err}"))
    })?;
    println!("{json}");
    Ok(())
}

fn init_tracing(verbose: bool) {
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
    let Some(raw) = std::env::var("AGENT_SEAL_MASTER_SECRET_HEX").ok() else {
        tracing::warn!(
            "AGENT_SEAL_MASTER_SECRET_HEX not set; using development zero key (DO NOT USE IN PRODUCTION)"
        );
        return Ok([0_u8; 32]);
    };

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

fn format_user_error(err: &SealError) -> String {
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

#[cfg(test)]
mod tests {
    use super::*;

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

        assert_eq!(cli.payload, "./payload.seal");
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
}

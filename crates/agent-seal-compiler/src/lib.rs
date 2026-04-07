pub mod assemble;
pub mod compile;
pub mod embed;
pub mod nuitka;
pub mod pyinstaller;

use agent_seal_core::{error::SealError, secret::generate_master_secret};
use clap::{Parser, ValueEnum};
use std::{path::PathBuf, str::FromStr};

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum CliBackend {
    Nuitka,
    Pyinstaller,
}

#[derive(Debug, Parser)]
#[command(name = "agent-seal-compiler")]
#[command(about = "Agent Seal compiler")]
pub struct Cli {
    #[arg(long)]
    pub project: PathBuf,
    #[arg(long)]
    pub user_fingerprint: String,
    #[arg(long)]
    pub sandbox_fingerprint: String,
    #[arg(long)]
    pub output: PathBuf,
    #[arg(long, value_enum, default_value_t = CliBackend::Nuitka)]
    pub backend: CliBackend,
    #[arg(long)]
    pub launcher: Option<PathBuf>,
}

pub fn run(cli: Cli) -> Result<(), SealError> {
    let launcher_path = resolve_launcher_path(cli.launcher)?;

    let user_fingerprint = parse_hex_32(&cli.user_fingerprint, "user fingerprint")?;
    let stable_fingerprint_hash = if cli.sandbox_fingerprint == "auto" {
        generate_master_secret()
    } else {
        parse_hex_32(&cli.sandbox_fingerprint, "sandbox fingerprint")?
    };

    let master_secret = generate_master_secret();
    let output_parent = cli
        .output
        .parent()
        .ok_or_else(|| SealError::InvalidInput("output path has no parent".to_string()))?
        .to_path_buf();

    std::fs::create_dir_all(&output_parent)?;

    let backend = match cli.backend {
        CliBackend::Nuitka => compile::Backend::Nuitka,
        CliBackend::Pyinstaller => compile::Backend::PyInstaller,
    };

    let compiled_binary = compile::compile_agent(&cli.project, &output_parent, backend)?;

    let assembled = assemble::assemble(&assemble::AssembleConfig {
        agent_elf_path: compiled_binary,
        launcher_path,
        master_secret,
        stable_fingerprint_hash,
        user_fingerprint,
    })?;

    std::fs::write(&cli.output, &assembled)?;
    println!(
        "compiled and assembled binary: {} ({} bytes)",
        cli.output.display(),
        assembled.len()
    );

    Ok(())
}

fn resolve_launcher_path(cli_launcher: Option<PathBuf>) -> Result<PathBuf, SealError> {
    if let Some(path) = cli_launcher {
        return Ok(path);
    }

    let raw = std::env::var("AGENT_SEAL_LAUNCHER_PATH").map_err(|_| {
        SealError::InvalidInput(
            "launcher path missing: use --launcher or AGENT_SEAL_LAUNCHER_PATH".to_string(),
        )
    })?;

    PathBuf::from_str(&raw)
        .map_err(|_| SealError::InvalidInput("invalid launcher path".to_string()))
}

fn parse_hex_32(input: &str, label: &str) -> Result<[u8; 32], SealError> {
    let decoded = hex::decode(input)
        .map_err(|err| SealError::InvalidInput(format!("invalid {label} hex: {err}")))?;
    if decoded.len() != 32 {
        return Err(SealError::InvalidInput(format!(
            "{label} must be exactly 64 hex chars"
        )));
    }

    let mut bytes = [0_u8; 32];
    bytes.copy_from_slice(&decoded);
    Ok(bytes)
}

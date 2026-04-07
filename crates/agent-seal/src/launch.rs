#[derive(clap::Args)]
#[command(name = "launch")]
#[command(about = "Launch a sealed agent")]
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

#[derive(Clone, Copy, Debug, Eq, PartialEq, clap::ValueEnum)]
pub enum FingerprintMode {
    Stable,
    Session,
}

pub fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    let launcher_cli = agent_seal_launcher::Cli {
        payload: cli.payload,
        fingerprint_mode: match cli.fingerprint_mode {
            FingerprintMode::Stable => agent_seal_launcher::FingerprintMode::Stable,
            FingerprintMode::Session => agent_seal_launcher::FingerprintMode::Session,
        },
        user_fingerprint: cli.user_fingerprint,
        verbose: cli.verbose,
    };
    agent_seal_launcher::run(launcher_cli).map_err(Into::into)
}

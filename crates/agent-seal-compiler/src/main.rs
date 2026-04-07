use clap::Parser;

fn main() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();

    let cli = agent_seal_compiler::Cli::parse();
    if let Err(err) = agent_seal_compiler::run(cli) {
        eprintln!("{err}");
        std::process::exit(1);
    }
}

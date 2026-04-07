use clap::{Parser, Subcommand};

mod compile;
mod launch;
mod proxy;
mod server;

#[derive(Parser)]
#[command(name = "seal")]
#[command(about = "Agent Seal — encrypted sandbox-bound agent delivery")]
#[command(version, long_version = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Compile(compile::Cli),
    Launch(launch::Cli),
    Server(server::Cli),
    Proxy(proxy::Cli),
}

fn main() {
    let cli = Cli::parse();
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();

    let result = match cli.command {
        Command::Compile(cli) => compile::run(cli),
        Command::Launch(cli) => launch::run(cli),
        Command::Server(cli) => server::run(cli),
        Command::Proxy(cli) => proxy::run(cli),
    };

    if let Err(err) = result {
        eprintln!("{err}");
        std::process::exit(1);
    }
}

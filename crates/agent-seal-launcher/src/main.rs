#![allow(unsafe_code)]

use clap::Parser;

fn main() {
    let cli = agent_seal_launcher::Cli::parse();
    agent_seal_launcher::init_tracing(cli.verbose);

    if let Err(err) = agent_seal_launcher::run(cli) {
        eprintln!("{}", agent_seal_launcher::format_user_error(&err));
        std::process::exit(1);
    }
}

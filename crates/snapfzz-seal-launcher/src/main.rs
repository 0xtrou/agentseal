#![allow(unsafe_code)]

use clap::Parser;

fn main() {
    let cli = snapfzz_seal_launcher::Cli::parse();
    snapfzz_seal_launcher::init_tracing(cli.verbose);

    if let Err(err) = snapfzz_seal_launcher::run(cli) {
        eprintln!("{}", snapfzz_seal_launcher::format_user_error(&err));
        std::process::exit(1);
    }
}

#[derive(clap::Args)]
#[command(name = "server")]
#[command(about = "Start the Agent Seal orchestration server")]
pub struct Cli {
    #[arg(long, default_value = "0.0.0.0:9090")]
    pub bind: String,
    #[arg(long, default_value = "./.agent-seal/compile")]
    pub compile_dir: std::path::PathBuf,
    #[arg(long, default_value = "./.agent-seal/output")]
    pub output_dir: std::path::PathBuf,
}

pub fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(async {
            tokio::fs::create_dir_all(&cli.compile_dir).await?;
            tokio::fs::create_dir_all(&cli.output_dir).await?;
            let state = agent_seal_server::state::ServerState::new(cli.compile_dir, cli.output_dir);
            let app = agent_seal_server::create_app(state);
            let addr: std::net::SocketAddr = cli.bind.parse()?;
            let listener = tokio::net::TcpListener::bind(addr).await?;
            tracing::info!("agent-seal server listening on {}", addr);
            axum::serve(listener, app)
                .with_graceful_shutdown(shutdown_signal())
                .await?;
            Ok(())
        })
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut sigterm) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            let _ = sigterm.recv().await;
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {}
        _ = terminate => {}
    }
}

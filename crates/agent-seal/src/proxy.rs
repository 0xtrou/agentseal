#[derive(clap::Args)]
#[command(name = "proxy")]
#[command(about = "Start the Agent Seal LLM proxy")]
pub struct Cli {
    #[arg(long)]
    pub provider_key: String,
    #[arg(long, default_value = "openai")]
    pub provider: String,
    #[arg(long, default_value = "0.0.0.0:8080")]
    pub bind: String,
}

pub fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let state = agent_seal_proxy::state::ProxyState::new(cli.provider_key, cli.provider);
            let app = agent_seal_proxy::create_app(state);
            let addr: std::net::SocketAddr = cli.bind.parse()?;
            let listener = tokio::net::TcpListener::bind(addr).await?;
            tracing::info!("agent-seal proxy listening on {}", addr);
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

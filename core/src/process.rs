use tokio::{
    select,
    signal::unix::{signal, SignalKind},
};
use tracing::debug;

// Functions

pub async fn wait_for_sigint_or_sigterm() -> std::io::Result<()> {
    let mut sigint = signal(SignalKind::interrupt())?;
    let mut sigterm = signal(SignalKind::terminate())?;
    select! {
        _ = sigint.recv() => {
            debug!("sigint received");
            Ok(())
        },
        _ = sigterm.recv() => {
            debug!("sigterm received");
            Ok(())
        },
    }
}

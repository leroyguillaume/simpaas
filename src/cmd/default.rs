use std::{ffi::OsStr, process::Output};

use tokio::process::Command;
use tracing::{debug, error, instrument, Level};

use super::{CommandRunner, Error, Result};

// Macros

macro_rules! log_output {
    ($lvl:ident, $cmd:expr, $output:expr) => {{
        let output = String::from_utf8_lossy(&$output);
        for line in output.lines() {
            $lvl!("{}: {line}", $cmd);
        }
    }};
}

// DefaultCommandRunner

pub struct DefaultCommandRunner;

impl CommandRunner for DefaultCommandRunner {
    #[instrument(skip(self, args))]
    async fn run<S: AsRef<OsStr> + Send + Sync>(&self, cmd: &str, args: &[S]) -> Result<Output> {
        debug!("running command");
        let output = Command::new(cmd).args(args).output().await?;
        if tracing::enabled!(Level::DEBUG) {
            log_output!(debug, cmd, output.stdout);
        }
        if output.status.success() {
            if tracing::enabled!(Level::DEBUG) {
                log_output!(debug, cmd, output.stderr);
            }
            Ok(output)
        } else {
            log_output!(error, cmd, output.stderr);
            Err(Error::Failure(output))
        }
    }
}

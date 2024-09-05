use std::future::Future;

use tokio::process::Command;
use tracing::{debug, instrument};

use crate::err::{Error, Result};

// Macros

macro_rules! log_output {
    ($log:ident, $lvl:ident, $name:literal, $output:expr) => {
        if tracing::enabled!(tracing::Level::$lvl) {
            let out = String::from_utf8_lossy(&$output);
            tracing::$log!(output = $name, "{out}");
        }
    };
}

// Traits

#[cfg_attr(test, mockall::automock)]
pub trait CommandRunner: Send + Sync {
    fn run<'a>(&self, cmd: &str, args: &[&'a str]) -> impl Future<Output = Result> + Send;
}

// DefaultCommandRunner

pub struct DefaultCommandRunner;

impl CommandRunner for DefaultCommandRunner {
    #[instrument(skip(self, cmd, args))]
    async fn run<'a>(&self, cmd: &str, args: &[&'a str]) -> Result {
        debug!("running command");
        let output = Command::new(cmd).args(args).output().await?;
        log_output!(debug, DEBUG, "stdout", output.stdout);
        if output.status.success() {
            log_output!(debug, DEBUG, "stderr", output.stderr);
            Ok(())
        } else {
            log_output!(error, ERROR, "stderr", output.stderr);
            Err(Error::CommandFailed)
        }
    }
}

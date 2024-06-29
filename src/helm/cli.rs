use std::{
    path::PathBuf,
    process::{ExitStatus, Output},
};

use tokio::process::Command;
use tracing::{debug, error, instrument, Level};

use crate::kube::{App, Chart};

use super::{HelmClient, Result};

macro_rules! log_output {
    ($lvl:ident, $output:expr) => {{
        let output = String::from_utf8_lossy(&$output);
        for line in output.lines() {
            $lvl!("helm: {line}");
        }
    }};
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("helm {0}")]
    Command(ExitStatus),
    #[error("invalid unicode")]
    InvalidUnicode,
    #[error("i/o error: {0}")]
    Io(
        #[from]
        #[source]
        std::io::Error,
    ),
}

#[derive(clap::Args, Clone, Debug, Eq, PartialEq)]
pub struct CliHelmClientArgs {
    #[arg(
        long = "helm-bin",
        env = "HELM_BIN",
        name = "HELM_BIN",
        default_value = "helm",
        long_help = "Helm binary to use"
    )]
    pub bin: String,
    #[arg(
        long,
        env,
        default_value = "charts/simpaas-app",
        long_help = "Path to built-in simpaas-app chart"
    )]
    pub chart_path: PathBuf,
}

impl Default for CliHelmClientArgs {
    fn default() -> Self {
        Self {
            bin: "helm".into(),
            chart_path: "charts/simpaas-app".into(),
        }
    }
}

pub struct CliHelmClient(CliHelmClientArgs);

impl CliHelmClient {
    pub fn new(args: CliHelmClientArgs) -> Self {
        Self(args)
    }

    fn handle_output(output: Output) -> Result {
        if tracing::enabled!(Level::DEBUG) {
            log_output!(debug, output.stdout);
        }
        if output.status.success() {
            if tracing::enabled!(Level::DEBUG) {
                log_output!(debug, output.stderr);
            }
            Ok(())
        } else {
            log_output!(error, output.stderr);
            Err(Error::Command(output.status).into())
        }
    }
}

impl HelmClient for CliHelmClient {
    #[instrument("helm_uninstall", skip(self, app), fields(app.namespace = app.spec.namespace, app.release = app.spec.release))]
    async fn uninstall(&self, app: &App) -> Result {
        debug!("running helm uninstall");
        let output = Command::new(&self.0.bin)
            .arg("uninstall")
            .arg("-n")
            .arg(&app.spec.namespace)
            .arg(&app.spec.release)
            .output()
            .await?;
        Self::handle_output(output)
    }

    #[instrument("helm_upgrade", skip(self, app, filepaths), fields(app.chart = %app.spec.chart, app.namespace = app.spec.namespace, app.release = app.spec.release))]
    async fn upgrade(&self, app: &App, filepaths: &[PathBuf]) -> Result {
        let chart = match &app.spec.chart {
            Chart::BuiltIn {} => self.0.chart_path.to_str().ok_or(Error::InvalidUnicode)?,
        };
        let mut cmd = Command::new(&self.0.bin);
        cmd.arg("upgrade")
            .arg("-n")
            .arg(&app.spec.namespace)
            .arg("--create-namespace")
            .arg("--install");
        for path in filepaths {
            cmd.arg("--values").arg(path);
        }
        debug!("running helm upgrade");
        let output = cmd.arg(&app.spec.release).arg(chart).output().await?;
        Self::handle_output(output)
    }
}

impl From<Error> for super::Error {
    fn from(err: Error) -> Self {
        Self(Box::new(err))
    }
}

impl From<std::io::Error> for super::Error {
    fn from(err: std::io::Error) -> Self {
        Error::Io(err).into()
    }
}

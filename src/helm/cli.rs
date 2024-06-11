use std::{
    fs::File,
    path::PathBuf,
    process::{ExitStatus, Output},
};

use tempdir::TempDir;
use tokio::process::Command;
use tracing::{debug, error, instrument, Level};

use crate::kube::App;

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
    #[error("i/o error: {0}")]
    Io(
        #[from]
        #[source]
        std::io::Error,
    ),
    #[error("yaml error: {0}")]
    Yaml(
        #[from]
        #[source]
        serde_yaml::Error,
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
    #[arg(
        long,
        env,
        long_help = "Path to YAML file of default values of simpaas-app chart"
    )]
    pub chart_values: Option<PathBuf>,
}

impl Default for CliHelmClientArgs {
    fn default() -> Self {
        Self {
            bin: "helm".into(),
            chart_path: "charts/simpaas-app".into(),
            chart_values: None,
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

    #[instrument("helm_upgrade", skip(self, app), fields(app.namespace = app.spec.namespace, app.release = app.spec.release))]
    async fn upgrade(&self, app: &App) -> Result {
        debug!("creating temporary file");
        let dir = TempDir::new(&app.spec.release)?;
        let filepath = dir.path().join("values.yaml");
        let mut file = File::create(&filepath)?;
        debug!("dumping app into yaml");
        serde_yaml::to_writer(&mut file, &app.spec)?;
        debug!("running helm upgrade");
        let mut cmd = Command::new(&self.0.bin);
        cmd.arg("upgrade")
            .arg("-n")
            .arg(&app.spec.namespace)
            .arg("--create-namespace")
            .arg("--install");
        if let Some(path) = &self.0.chart_values {
            cmd.arg("--values").arg(path);
        }
        let output = cmd
            .arg("--values")
            .arg(&filepath)
            .arg(&app.spec.release)
            .arg(&self.0.chart_path)
            .output()
            .await?;
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

impl From<serde_yaml::Error> for super::Error {
    fn from(err: serde_yaml::Error) -> Self {
        Error::Yaml(err).into()
    }
}

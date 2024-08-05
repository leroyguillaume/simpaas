use std::path::PathBuf;

use tracing::{debug, error, instrument};

use crate::{cmd::CommandRunner, domain::App};

use super::{HelmClient, Result};

// Defaults

const DEFAULT_BIN: &str = "helm";
const DEFAULT_CHART_PATH: &str = "charts/simpaas-app";

// Errors

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Command(
        #[from]
        #[source]
        crate::cmd::Error,
    ),
    #[error("invalid unicode")]
    InvalidUnicode,
}

// Data structs

#[derive(clap::Args, Clone, Debug, Eq, PartialEq)]
pub struct DefaultHelmClientArgs {
    #[arg(
        long = "helm-bin",
        env = "HELM_BIN",
        name = "HELM_BIN",
        default_value = DEFAULT_BIN,
        long_help = "Helm binary to use"
    )]
    pub bin: String,
    #[arg(
        long,
        env,
        default_value = DEFAULT_CHART_PATH,
        long_help = "Path to built-in simpaas-app chart"
    )]
    pub chart_path: PathBuf,
}

impl Default for DefaultHelmClientArgs {
    fn default() -> Self {
        Self {
            bin: DEFAULT_BIN.into(),
            chart_path: DEFAULT_CHART_PATH.into(),
        }
    }
}

// DefaultHelmClient

pub struct DefaultHelmClient<R: CommandRunner> {
    args: DefaultHelmClientArgs,
    runner: R,
}

impl<R: CommandRunner> DefaultHelmClient<R> {
    pub fn new(args: DefaultHelmClientArgs, runner: R) -> Self {
        Self { args, runner }
    }
}

impl<R: CommandRunner> HelmClient for DefaultHelmClient<R> {
    #[instrument("helm_uninstall", skip(self, name, app), fields(app.name = name, app.namespace = app.spec.namespace))]
    async fn uninstall(&self, name: &str, app: &App) -> Result {
        debug!("running helm uninstall");
        self.runner
            .run(
                "helm",
                &[
                    "uninstall",
                    "-n",
                    &app.spec.namespace,
                    "--ignore-not-found",
                    name,
                ],
            )
            .await?;
        Ok(())
    }

    #[instrument("helm_upgrade", skip(self, app, filepaths), fields(app.name = name, app.namespace = app.spec.namespace))]
    async fn upgrade(&self, name: &str, app: &App, filepaths: &[PathBuf]) -> Result {
        let chart = self.args.chart_path.to_str().ok_or(Error::InvalidUnicode)?;
        let mut args = vec![
            "upgrade",
            "-n",
            &app.spec.namespace,
            "--create-namespace",
            "--install",
        ];
        for path in filepaths {
            let path = path.to_str().ok_or(Error::InvalidUnicode)?;
            args.push("--values");
            args.push(path);
        }
        debug!("running helm upgrade");
        args.push(name);
        args.push(chart);
        self.runner.run("helm", &args).await?;
        Ok(())
    }
}

// super::Error

impl From<Error> for super::Error {
    fn from(err: Error) -> Self {
        Self(Box::new(err))
    }
}

impl From<crate::cmd::Error> for super::Error {
    fn from(err: crate::cmd::Error) -> Self {
        Error::Command(err).into()
    }
}

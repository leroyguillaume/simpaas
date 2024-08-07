use std::path::PathBuf;

use tracing::{debug, error, instrument};

use crate::cmd::CommandRunner;

use super::{HelmClient, Result};

// Defaults

const DEFAULT_BIN: &str = "helm";

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
}

impl Default for DefaultHelmClientArgs {
    fn default() -> Self {
        Self {
            bin: DEFAULT_BIN.into(),
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
    #[instrument("helm_uninstall", skip(self))]
    async fn uninstall(&self, release: &str, namespace: &str) -> Result {
        debug!("running helm uninstall");
        self.runner
            .run(
                &self.args.bin,
                &["uninstall", "-n", namespace, "--ignore-not-found", release],
            )
            .await?;
        Ok(())
    }

    #[instrument("helm_upgrade", skip(self, filepaths))]
    async fn upgrade(
        &self,
        chart: &str,
        release: &str,
        namespace: &str,
        filepaths: &[PathBuf],
    ) -> Result {
        let mut args = vec![
            "upgrade",
            "-n",
            namespace,
            "--create-namespace",
            "--install",
        ];
        for path in filepaths {
            let path = path.to_str().ok_or(Error::InvalidUnicode)?;
            args.push("--values");
            args.push(path);
        }
        debug!("running helm upgrade");
        args.push(release);
        args.push(chart);
        self.runner.run(&self.args.bin, &args).await?;
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

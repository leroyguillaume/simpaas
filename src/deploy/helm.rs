use std::{fs::File, path::PathBuf};

use serde::Serialize;
use tempdir::TempDir;
use tracing::{debug, info, instrument};
use uuid::Uuid;

use crate::{domain::App, helm::HelmClient, kube::KubeClient};

use super::{Deployer, Result};

// Defaults

const DEFAULT_CHART_PATH: &str = "charts/simpaas-app";

// Errors

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Helm(
        #[from]
        #[source]
        crate::helm::Error,
    ),
    #[error("i/o error: {0}")]
    Io(
        #[from]
        #[source]
        std::io::Error,
    ),
    #[error("{0}")]
    Kube(
        #[from]
        #[source]
        crate::kube::Error,
    ),
    #[error("yaml error: {0}")]
    Yaml(
        #[from]
        #[source]
        serde_yaml::Error,
    ),
}

// Data structs

#[derive(clap::Args, Clone, Debug, Eq, PartialEq)]
pub struct HelmDeployerArgs {
    #[arg(
        long,
        env,
        default_value = DEFAULT_CHART_PATH,
        long_help = "Path to built-in simpaas-app chart"
    )]
    pub app_chart: String,
    #[arg(
        long,
        env,
        long_help = "Path to YAML file of default values of simpaas-app chart"
    )]
    pub app_chart_values: Option<PathBuf>,
}

impl Default for HelmDeployerArgs {
    fn default() -> Self {
        Self {
            app_chart: DEFAULT_CHART_PATH.into(),
            app_chart_values: None,
        }
    }
}

// HelmDeployer

pub struct HelmDeployer<H: HelmClient> {
    args: HelmDeployerArgs,
    helm: H,
}

impl<H: HelmClient> HelmDeployer<H> {
    pub fn new(args: HelmDeployerArgs, helm: H) -> Self {
        Self { args, helm }
    }

    fn dump_yaml<T: Serialize>(dir: &TempDir, values: &T) -> Result<PathBuf> {
        let filename = Uuid::new_v4().to_string();
        let filepath = dir.path().join(filename).with_extension("yaml");
        let mut file = File::create(&filepath)?;
        serde_yaml::to_writer(&mut file, &values)?;
        Ok(filepath)
    }
}

impl<H: HelmClient> Deployer for HelmDeployer<H> {
    #[instrument(skip(self, app, _kube), fields(app.name = name))]
    async fn deploy_app<K: KubeClient>(&self, name: &str, app: &App, _kube: &K) -> Result {
        info!("deploying app");
        debug!("creating temporary directory");
        let dir = TempDir::new(name)?;
        let app_filepath = Self::dump_yaml(&dir, &app.spec)?;
        let mut filepaths = vec![];
        if let Some(path) = &self.args.app_chart_values {
            filepaths.push(path.clone());
        };
        filepaths.push(app_filepath);
        self.helm
            .upgrade(&self.args.app_chart, name, &app.spec.namespace, &filepaths)
            .await?;
        info!("app deployed");
        Ok(())
    }

    #[instrument(skip(self, app, kube), fields(app.name = name))]
    async fn undeploy_app<K: KubeClient>(&self, name: &str, app: &App, kube: &K) -> Result {
        info!("undeploying app");
        self.helm.uninstall(name, &app.spec.namespace).await?;
        kube.delete_namespace(&app.spec.namespace).await?;
        info!("app undeployed");
        Ok(())
    }
}

// super::Error

impl From<Error> for super::Error {
    fn from(err: Error) -> Self {
        Self(Box::new(err))
    }
}

impl From<crate::helm::Error> for super::Error {
    fn from(err: crate::helm::Error) -> Self {
        Error::Helm(err).into()
    }
}

impl From<crate::kube::Error> for super::Error {
    fn from(err: crate::kube::Error) -> Self {
        Error::Kube(err).into()
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

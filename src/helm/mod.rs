use std::path::PathBuf;

use futures::Future;

use crate::kube::App;

pub mod cli;

pub type Result<T = ()> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
#[error("helm error: {0}")]
pub struct Error(#[source] pub Box<dyn std::error::Error + Send + Sync>);

pub trait HelmClient: Send + Sync {
    fn uninstall(&self, name: &str, app: &App) -> impl Future<Output = Result> + Send;

    fn upgrade(
        &self,
        name: &str,
        app: &App,
        filepaths: &[PathBuf],
    ) -> impl Future<Output = Result> + Send;
}

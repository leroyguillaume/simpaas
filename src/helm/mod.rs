use std::path::PathBuf;

use futures::Future;

use crate::domain::App;

// Mods

pub mod default;

// Types

pub type Result<T = ()> = std::result::Result<T, Error>;

// Errors

#[derive(Debug, thiserror::Error)]
#[error("helm error: {0}")]
pub struct Error(#[source] pub Box<dyn std::error::Error + Send + Sync>);

// Traits

pub trait HelmClient: Send + Sync {
    fn uninstall(&self, name: &str, app: &App) -> impl Future<Output = Result> + Send;

    fn upgrade(
        &self,
        name: &str,
        app: &App,
        filepaths: &[PathBuf],
    ) -> impl Future<Output = Result> + Send;
}

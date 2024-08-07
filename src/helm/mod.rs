use std::path::PathBuf;

use futures::Future;

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
    fn uninstall(&self, release: &str, namespace: &str) -> impl Future<Output = Result> + Send;

    fn upgrade(
        &self,
        chart: &str,
        release: &str,
        namespace: &str,
        filepaths: &[PathBuf],
    ) -> impl Future<Output = Result> + Send;
}

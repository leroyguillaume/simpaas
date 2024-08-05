use futures::Future;

use crate::{domain::App, kube::KubeClient};

// Mods

pub mod helm;

// Types

pub type Result<T = ()> = std::result::Result<T, Error>;

// Errors

#[derive(Debug, thiserror::Error)]
#[error("deployer error: {0}")]
pub struct Error(#[source] pub Box<dyn std::error::Error + Send + Sync>);

// Traits

pub trait Deployer: Send + Sync {
    fn deploy<K: KubeClient>(
        &self,
        name: &str,
        app: &App,
        kube: &K,
    ) -> impl Future<Output = Result> + Send;

    fn undeploy<K: KubeClient>(
        &self,
        name: &str,
        app: &App,
        kube: &K,
    ) -> impl Future<Output = Result> + Send;
}

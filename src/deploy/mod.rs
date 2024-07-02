use futures::Future;

use crate::{domain::App, kube::KubeClient};

pub mod helm;

pub type Result<T = ()> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
#[error("deployer error: {0}")]
pub struct Error(#[source] pub Box<dyn std::error::Error + Send + Sync>);

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

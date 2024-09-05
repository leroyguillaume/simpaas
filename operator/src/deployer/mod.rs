use std::future::Future;

use crate::{err::Result, DeployableResource};

// Mods

pub mod svcinst;

// Traits

#[cfg_attr(test, mockall::automock)]
pub trait Deployer<RESOURCE: DeployableResource>: Send + Sync {
    fn deploy(&self, ns: &str, name: &str, res: &RESOURCE) -> impl Future<Output = Result> + Send;

    fn undeploy(&self, ns: &str, name: &str, res: &RESOURCE)
        -> impl Future<Output = Result> + Send;
}

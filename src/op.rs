use std::{sync::Arc, time::Duration};

use futures::StreamExt;
use kube::{
    runtime::{controller::Action, Controller},
    Api,
};
use tracing::{debug, error, info, info_span, Instrument};

use crate::{
    deploy::Deployer,
    kube::{App, KubeClient},
    SignalListener,
};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Deployer(
        #[from]
        #[source]
        crate::deploy::Error,
    ),
    #[error("resource doesn't have name")]
    NoName,
}

pub struct OpContext<D: Deployer, K: KubeClient> {
    pub deployer: D,
    pub kube: K,
    pub requeue_delay: Duration,
}

pub async fn start_op<D: Deployer + 'static, K: KubeClient + 'static>(
    api: Api<App>,
    ctx: OpContext<D, K>,
) -> anyhow::Result<()> {
    let mut sig = SignalListener::new()?;
    info!("operator started");
    Controller::new(api, Default::default())
        .graceful_shutdown_on(async move { sig.recv().await })
        .run(reconcile, on_error, Arc::new(ctx))
        .for_each(|res| async move {
            match res {
                Ok(_) => {
                    debug!("reconcilation succeeded");
                }
                Err(err) => {
                    error!("reconcilation failed: {err}");
                }
            }
        })
        .await;
    info!("operator stopped");
    Ok(())
}

fn on_error<D: Deployer, K: KubeClient>(
    app: Arc<App>,
    err: &::kube::Error,
    ctx: Arc<OpContext<D, K>>,
) -> Action {
    let name = app.metadata.name.as_deref().unwrap_or("");
    error!(app.name = name, "{err}");
    Action::requeue(ctx.requeue_delay)
}

async fn reconcile<D: Deployer, K: KubeClient>(
    app: Arc<App>,
    ctx: Arc<OpContext<D, K>>,
) -> Result<Action, ::kube::Error> {
    let name = app.metadata.name.as_ref().ok_or(Error::NoName)?;
    let span = info_span!("reconcile", app.name = name,);
    async {
        debug!("reconciling app");
        if app.metadata.deletion_timestamp.is_some() {
            ctx.deployer.undeploy(name, &app, &ctx.kube).await?;
        } else {
            ctx.deployer.deploy(name, &app, &ctx.kube).await?;
        }
        Ok(Action::await_change())
    }
    .instrument(span)
    .await
}

impl From<Error> for ::kube::Error {
    fn from(err: Error) -> Self {
        Self::Service(Box::new(err))
    }
}

impl From<crate::deploy::Error> for ::kube::Error {
    fn from(err: crate::deploy::Error) -> Self {
        Error::Deployer(err).into()
    }
}

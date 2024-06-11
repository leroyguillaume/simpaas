use std::{sync::Arc, time::Duration};

use futures::StreamExt;
use kube::{
    runtime::{controller::Action, Controller},
    Api,
};
use tracing::{debug, error, info, info_span, Instrument};

use crate::{
    helm::{self, HelmClient},
    kube::App,
    SignalListener,
};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Helm(
        #[from]
        #[source]
        helm::Error,
    ),
    #[error("resource doesn't have name")]
    NoName,
}

pub struct OpContext<H: HelmClient> {
    pub helm: H,
    pub requeue_delay: Duration,
}

pub async fn start_op<H: HelmClient + 'static>(
    api: Api<App>,
    ctx: OpContext<H>,
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

fn on_error<H: HelmClient>(app: Arc<App>, err: &::kube::Error, ctx: Arc<OpContext<H>>) -> Action {
    let name = app.metadata.name.as_deref().unwrap_or("");
    error!(
        app.name = name,
        app.namespace = app.spec.namespace,
        app.release = app.spec.release,
        "{err}"
    );
    Action::requeue(ctx.requeue_delay)
}

async fn reconcile<H: HelmClient>(
    app: Arc<App>,
    ctx: Arc<OpContext<H>>,
) -> Result<Action, ::kube::Error> {
    let name = app.metadata.name.as_ref().ok_or(Error::NoName)?;
    let span = info_span!(
        "reconcile",
        app.name = name,
        app.namespace = app.spec.namespace,
        app.release = app.spec.release
    );
    async {
        debug!("reconciling app");
        if app.metadata.deletion_timestamp.is_some() {
            info!("uninstalling app");
            ctx.helm.uninstall(&app).await?;
            info!("app uninstalled");
        } else {
            info!("deploying app");
            ctx.helm.upgrade(&app).await?;
            info!("app deployed");
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

impl From<helm::Error> for ::kube::Error {
    fn from(err: helm::Error) -> Self {
        Error::Helm(err).into()
    }
}

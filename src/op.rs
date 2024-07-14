use std::{sync::Arc, time::Duration};

use futures::StreamExt;
use kube::{
    api::ObjectMeta,
    runtime::{controller::Action, Controller},
    Api,
};
use tokio::{sync::broadcast::channel, task::JoinSet};
use tracing::{debug, error, info, info_span, Instrument};

use crate::{
    deploy::Deployer,
    domain::{App, Invitation},
    kube::{KubeClient, FINALIZER},
    mail::MailSender,
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
    #[error("{0}")]
    Kube(
        #[from]
        #[source]
        crate::kube::Error,
    ),
    #[error("{0}")]
    Mail(
        #[from]
        #[source]
        crate::mail::Error,
    ),
    #[error("resource doesn't have name")]
    NoName,
}

pub struct OpContext<D: Deployer, K: KubeClient, M: MailSender> {
    pub deployer: D,
    pub kube: K,
    pub mail_sender: M,
    pub requeue_delay: Duration,
}

pub async fn start_op<D: Deployer + 'static, K: KubeClient + 'static, M: MailSender + 'static>(
    kube: ::kube::Client,
    ctx: OpContext<D, K, M>,
) -> anyhow::Result<()> {
    let (tx, mut rx) = channel(1);
    let ctx = Arc::new(ctx);
    let mut tasks = JoinSet::new();
    let app_api = Api::default_namespaced(kube.clone());
    let app_ctrl = Controller::new(app_api, Default::default())
        .graceful_shutdown_on({
            let mut rx = tx.subscribe();
            async move {
                rx.recv().await.ok();
            }
        })
        .run(reconcile_app, on_error, ctx.clone())
        .for_each(|res| async move {
            match res {
                Ok(_) => {
                    debug!("app reconcilation succeeded");
                }
                Err(err) => {
                    error!("app reconcilation failed: {err}");
                }
            }
        });
    let invit_api = Api::default_namespaced(kube);
    let invit_ctrl = Controller::new(invit_api, Default::default())
        .graceful_shutdown_on(async move {
            rx.recv().await.ok();
        })
        .run(reconcile_invitation, on_error, ctx)
        .for_each(|res| async move {
            match res {
                Ok(_) => {
                    debug!("invitation reconcilation succeeded");
                }
                Err(err) => {
                    error!("invitation reconcilation failed: {err}");
                }
            }
        });
    tasks.spawn(app_ctrl);
    tasks.spawn(invit_ctrl);
    let mut sig = SignalListener::new()?;
    info!("operator started");
    sig.recv().await;
    tx.send(())?;
    while let Some(res) = tasks.join_next().await {
        if let Err(err) = res {
            error!("{err}");
        }
    }
    info!("operator stopped");
    Ok(())
}

fn on_error<D: Deployer, K: KubeClient, M: MailSender, R>(
    _res: Arc<R>,
    _err: &::kube::Error,
    ctx: Arc<OpContext<D, K, M>>,
) -> Action {
    Action::requeue(ctx.requeue_delay)
}

async fn reconcile_app<D: Deployer, K: KubeClient, M: MailSender>(
    app: Arc<App>,
    ctx: Arc<OpContext<D, K, M>>,
) -> Result<Action, ::kube::Error> {
    let name = app.metadata.name.as_ref().ok_or(Error::NoName)?;
    let span = info_span!("reconcile_app", app.name = name,);
    async {
        debug!("reconciling app");
        if app.metadata.deletion_timestamp.is_some() {
            if let Some(finalizers) = &app.metadata.finalizers {
                if finalizers.iter().any(|finalizer| finalizer == FINALIZER) {
                    let mut app = app.as_ref().clone();
                    ctx.deployer.undeploy(name, &app, &ctx.kube).await?;
                    let mut finalizers = finalizers.clone();
                    finalizers.retain(|finalizer| finalizer != FINALIZER);
                    app.metadata = ObjectMeta {
                        finalizers: Some(finalizers),
                        managed_fields: None,
                        ..app.metadata
                    };
                    ctx.kube.patch_app(name, &app).await?;
                }
            }
        } else {
            ctx.deployer.deploy(name, &app, &ctx.kube).await?;
        }
        Ok(Action::await_change())
    }
    .instrument(span)
    .await
}

async fn reconcile_invitation<D: Deployer, K: KubeClient, M: MailSender>(
    invit: Arc<Invitation>,
    ctx: Arc<OpContext<D, K, M>>,
) -> Result<Action, ::kube::Error> {
    let token = invit.metadata.name.as_ref().ok_or(Error::NoName)?;
    let span = info_span!("reconcile_invitation", invit.token = token);
    async {
        debug!("reconciling invitation");
        ctx.mail_sender.send_invitation(token, &invit).await?;
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

impl From<crate::kube::Error> for ::kube::Error {
    fn from(err: crate::kube::Error) -> Self {
        Error::Kube(err).into()
    }
}

impl From<crate::mail::Error> for ::kube::Error {
    fn from(err: crate::mail::Error) -> Self {
        Error::Mail(err).into()
    }
}

use std::{collections::BTreeMap, sync::Arc, time::Duration};

use futures::{Future, StreamExt};
use kube::{
    api::ObjectMeta,
    runtime::{
        controller::{Action, Error as ControllerError},
        Controller,
    },
    Api,
};
use tokio::{sync::broadcast::channel, task::JoinSet};
use tracing::{debug, error, info, info_span, warn, Instrument};

use crate::{
    deploy::Deployer,
    domain::{App, AppStatus, Invitation, InvitationStatus, ServiceStatus},
    kube::{KubeClient, KubeEvent, KubeEventKind, KubeEventPublisher, ServicePodStatus, FINALIZER},
    mail::MailSender,
    DelayArgs, SignalListener,
};

pub type Result<T = ()> = std::result::Result<T, Error>;

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Delays {
    app_status: Duration,
    retry: Duration,
}

impl From<DelayArgs> for Delays {
    fn from(args: DelayArgs) -> Self {
        Self {
            app_status: Duration::from_secs(args.app_status),
            retry: Duration::from_secs(args.retry),
        }
    }
}

pub struct OpContext<D: Deployer, K: KubeClient, M: MailSender, P: KubeEventPublisher> {
    pub delays: Delays,
    pub deployer: D,
    pub kube: K,
    pub mail_sender: M,
    pub publisher: P,
}

pub async fn start_op<
    D: Deployer + 'static,
    K: KubeClient + 'static,
    M: MailSender + 'static,
    P: KubeEventPublisher + 'static,
>(
    kube: ::kube::Client,
    ctx: OpContext<D, K, M, P>,
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
                    log_controller_error(&err);
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
                    log_controller_error(&err);
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

fn on_error<D: Deployer, K: KubeClient, M: MailSender, P: KubeEventPublisher, R>(
    _res: Arc<R>,
    _err: &::kube::Error,
    ctx: Arc<OpContext<D, K, M, P>>,
) -> Action {
    Action::requeue(ctx.delays.retry)
}

fn log_controller_error<Q: std::error::Error + 'static, R: std::error::Error + 'static>(
    err: &ControllerError<R, Q>,
) {
    match err {
        ControllerError::ReconcilerFailed(err, _) => {
            error!("{err}");
        }
        ControllerError::QueueError(err) => {
            error!("{err}");
        }
        ControllerError::RunnerError(err) => {
            error!("{err}");
        }
        _ => {}
    }
}

async fn reconcile_app<D: Deployer, K: KubeClient, M: MailSender, P: KubeEventPublisher>(
    app: Arc<App>,
    ctx: Arc<OpContext<D, K, M, P>>,
) -> ::kube::Result<Action> {
    let name = app.metadata.name.as_ref().ok_or(Error::NoName)?;
    let span = info_span!("reconcile_app", app.name = name,);
    async {
        debug!("reconciling app");
        if app.metadata.deletion_timestamp.is_some() {
            if let Some(finalizers) = &app.metadata.finalizers {
                if finalizers.iter().any(|finalizer| finalizer == FINALIZER) {
                    let mut app = app.as_ref().clone();
                    publishing_event(
                        ctx.deployer.undeploy(name, &app, &ctx.kube),
                        "Undeploying",
                        "Undeployed",
                        "Undeploying".into(),
                        |_| "Successfully undeployed".into(),
                        |err| format!("Failed to undeploy: {err}"),
                        |event| ctx.publisher.publish_app_event(&app, event),
                    )
                    .await?;
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
            match app.status {
                Some(AppStatus::Deployed(_)) => {
                    update_service_statuses(name, &app, &ctx.kube, &ctx.publisher).await?;
                }
                Some(AppStatus::WaitingForDeploy {}) | None => {
                    publishing_event(
                        ctx.deployer.deploy(name, &app, &ctx.kube),
                        "Deploying",
                        "Deployed",
                        "Deploying".into(),
                        |_| "Successfully deployed".into(),
                        |err| format!("Failed to deploy: {err}"),
                        |event| ctx.publisher.publish_app_event(&app, event),
                    )
                    .await?;
                    update_service_statuses(name, &app, &ctx.kube, &ctx.publisher).await?;
                }
            }
        }
        Ok(Action::requeue(ctx.delays.app_status))
    }
    .instrument(span)
    .await
}

async fn reconcile_invitation<D: Deployer, K: KubeClient, M: MailSender, P: KubeEventPublisher>(
    invit: Arc<Invitation>,
    ctx: Arc<OpContext<D, K, M, P>>,
) -> ::kube::Result<Action> {
    let token = invit.metadata.name.as_ref().ok_or(Error::NoName)?;
    let span = info_span!("reconcile_invitation", invit.token = token);
    async {
        debug!("reconciling invitation");
        if let Some(status) = &invit.status {
            if status.email_sent {
                debug!("email was already sent");
            } else {
                send_invitation(token, &invit, &ctx.mail_sender, &ctx.kube, &ctx.publisher).await?;
            }
        } else {
            send_invitation(token, &invit, &ctx.mail_sender, &ctx.kube, &ctx.publisher).await?;
        }
        Ok(Action::await_change())
    }
    .instrument(span)
    .await
}

async fn send_invitation<K: KubeClient, M: MailSender, P: KubeEventPublisher>(
    token: &str,
    invit: &Invitation,
    sender: &M,
    kube: &K,
    publisher: &P,
) -> Result {
    publishing_event(
        sender.send_invitation(token, invit),
        "Sending",
        "Sent",
        format!("Sending email to {}", invit.spec.to),
        |_| format!("Successfully sent to {}", invit.spec.to),
        |err| format!("Failed to send mail to {}: {err}", invit.spec.to),
        |event| publisher.publish_invitation_event(invit, event),
    )
    .await?;
    let status = InvitationStatus { email_sent: true };
    kube.patch_invitation_status(token, &status).await?;
    Ok(())
}

async fn update_service_statuses<K: KubeClient, P: KubeEventPublisher>(
    name: &str,
    app: &App,
    kube: &K,
    publisher: &P,
) -> Result {
    let monitor = async {
        let mut statuses = BTreeMap::new();
        for service in &app.spec.services {
            let pods = kube.list_service_pods(name, &service.name).await?;
            let mut stopped = 0;
            for pod in &pods {
                if let ServicePodStatus::Stopped = pod.status {
                    warn!(pod.name, "pod is stopped");
                    stopped += 1;
                }
            }
            let status = if stopped == 0 {
                ServiceStatus::Running
            } else if stopped == pods.len() {
                ServiceStatus::Stopped
            } else {
                ServiceStatus::Degraded
            };
            statuses.insert(service.name.clone(), status);
        }
        Ok(statuses) as Result<BTreeMap<String, ServiceStatus>>
    };
    let statuses = publishing_event(
        monitor,
        "Monitoring",
        "Monitored",
        "Checking probes".into(),
        |_| "Probes successfully checked".into(),
        |err| format!("Failed to check service probes: {err}"),
        |event| publisher.publish_app_event(app, event),
    )
    .await?;
    kube.patch_app_status(name, &AppStatus::Deployed(statuses))
        .await?;
    Ok(())
}

async fn publishing_event<
    E: std::error::Error + Into<Error>,
    FUT: Future<Output = std::result::Result<V, E>>,
    NERR: Fn(&E) -> String,
    NOK: Fn(&V) -> String,
    P: Fn(KubeEvent) -> PFUT,
    PFUT: Future<Output = ()>,
    V,
>(
    fut: FUT,
    action: &'static str,
    ok_reason: &'static str,
    note: String,
    ok_note: NOK,
    err_note: NERR,
    publish: P,
) -> Result<V> {
    let event = KubeEvent {
        action,
        kind: KubeEventKind::Normal,
        note,
        reason: action,
    };
    publish(event).await;
    match fut.await {
        Ok(val) => {
            let event = KubeEvent {
                action,
                kind: KubeEventKind::Normal,
                note: ok_note(&val),
                reason: ok_reason,
            };
            publish(event).await;
            Ok(val)
        }
        Err(err) => {
            let event = KubeEvent {
                action,
                kind: KubeEventKind::Warn,
                note: err_note(&err),
                reason: "Failed",
            };
            publish(event).await;
            Err(err.into())
        }
    }
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

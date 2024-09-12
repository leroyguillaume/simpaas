use std::{
    fmt::{Debug, Display},
    fs::read_to_string,
    future::Future,
    path::PathBuf,
    sync::Arc,
};

use clap::Parser;
use ctrl::controller;
use db::DefaultDatabaseManager;
use deployer::{app::ApplicationDeployer, svcinst::ServiceInstanceDeployer};
use err::Result;
use hasher::Hasher;
use helm::DefaultHelmRunner;
use k8s_openapi::NamespaceResourceScope;
use kube::{
    runtime::events::{Event, EventType},
    Api, Client, Resource,
};
use monitor::DefaultMonitor;
use reconciler::{db::DatabaseReconciler, dep::DeployableReconciler};
use renderer::LiquidRenderer;
use serde::{de::DeserializeOwned, Serialize};
use simpaas_core::{
    kube::{DefaultKubeClient, KubeClient},
    process::wait_for_sigint_or_sigterm,
    tracer::init_tracer,
    Application, Chart, Database, DatabaseStatus, DeployableStatus, Service, ServiceInstance,
};
use tokio::{sync::broadcast::channel, task::JoinSet};
use tracing::{debug, info, warn};

// Main

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let (stop_tx, stop_rx) = channel(1);
    let mut jobs = JoinSet::new();
    let args = Args::parse();
    init_tracer(args.log_filter)?;
    let values = if let Some(path) = args.chart_values {
        debug!("loading chart values");
        read_to_string(path)?
    } else {
        debug!("using default chart values");
        include_str!("../resources/values.yaml.liquid").into()
    };
    let chart = Chart {
        name: args.chart,
        values,
        version: args.chart_version,
    };
    let requeue_delay = std::time::Duration::from_secs(args.requeue_delay);
    let kube = Client::try_default().await?;
    let svc_inst_api: Api<ServiceInstance> = Api::all(kube.clone());
    let db_api: Api<Database> = Api::all(kube.clone());
    let app_api: Api<Application> = Api::all(kube.clone());
    let kube = Arc::new(DefaultKubeClient::new(args.pod_name, kube));
    let helm = Arc::new(DefaultHelmRunner::new(args.helm_bin));
    let renderer = Arc::new(LiquidRenderer::new());
    let monitor = Arc::new(DefaultMonitor::new(kube.clone()));
    let svc_inst_deployer =
        ServiceInstanceDeployer::new(helm.clone(), kube.clone(), renderer.clone());
    let svc_inst_reconciler =
        DeployableReconciler::new(svc_inst_deployer, kube.clone(), monitor.clone());
    let svc_inst_ctrl = controller(
        requeue_delay,
        svc_inst_api,
        kube.clone(),
        svc_inst_reconciler,
        stop_tx.subscribe(),
    );
    jobs.spawn(svc_inst_ctrl);
    debug!("service instance controller started");
    let db_mgr = DefaultDatabaseManager::new(args.cluster_domain, kube.clone(), renderer.clone());
    let db_reconciler = DatabaseReconciler::new(db_mgr, monitor.clone());
    let db_ctrl = controller(
        requeue_delay,
        db_api,
        kube.clone(),
        db_reconciler,
        stop_tx.subscribe(),
    );
    jobs.spawn(db_ctrl);
    debug!("database controller started");
    let app_deployer = ApplicationDeployer::new(chart, helm, renderer);
    let app_reconciler = DeployableReconciler::new(app_deployer, kube.clone(), monitor);
    let app_ctrl = controller(requeue_delay, app_api, kube, app_reconciler, stop_rx);
    jobs.spawn(app_ctrl);
    debug!("application controller started");
    info!("operator started");
    wait_for_sigint_or_sigterm().await?;
    stop_tx.send(()).ok();
    info!("waiting for controllers to stop");
    while let Some(res) = jobs.join_next().await {
        if let Err(err) = res {
            warn!("{err}");
        }
    }
    info!("operator stopped");
    Ok(())
}

// Mods

mod clock;
mod cmd;
mod ctrl;
mod db;
mod deployer;
mod err;
mod hasher;
mod helm;
mod monitor;
mod pwd;
mod reconciler;
mod renderer;

// Consts

const ACTION_CREATING: &str = "Creating";
const ACTION_DEPLOYING: &str = "Deploying";
const ACTION_DROPPING: &str = "Dropping";
const ACTION_MONITORING: &str = "Monitoring";
const ACTION_UNDEPLOYING: &str = "Undeploying";

const JOB_KIND_CREATION: &str = "creation";
const JOB_KIND_DELETION: &str = "deletion";

const LABEL_APPLICATION: &str = "simpaas.gleroy.dev/application";
const LABEL_DATABASE: &str = "simpaas.gleroy.dev/database";
const LABEL_JOB_KIND: &str = "simpaas.gleroy.dev/job-kind";
const LABEL_SERVICE_INSTANCE: &str = "simpaas.gleroy.dev/service-instance";
const LABEL_SERVICE: &str = "simpaas.gleroy.dev/service";

const REASON_CREATED: &str = "Created";
const REASON_DEPLOYED: &str = "Deployed";
const REASON_FAILED: &str = "Failed";

// Args

#[derive(Clone, Debug, Eq, Parser, PartialEq)]
#[command(version)]
struct Args {
    #[arg(
        long,
        env,
        default_value = "charts/simpaas-application",
        long_help = "Chart used to deploy application"
    )]
    chart: String,
    #[arg(long, env, long_help = "Path to template of chart values file")]
    chart_values: Option<PathBuf>,
    #[arg(long, env, long_help = "Version of the chart")]
    chart_version: Option<String>,
    #[arg(
        long,
        env,
        default_value = "cluster.local",
        long_help = "Domain of Kubernetes cluster"
    )]
    cluster_domain: String,
    #[arg(long, env, default_value = "helm", long_help = "Path to Helm binary")]
    helm_bin: String,
    #[arg(
        long,
        env,
        default_value = "simpaas_core=info,simpaas_operator=info,warn",
        long_help = "Log filter (https://docs.rs/tracing-subscriber/latest/tracing_subscriber/filter/struct.EnvFilter.html#directives)"
    )]
    log_filter: String,
    #[arg(long, env, long_help = "Name of the current pod")]
    pod_name: Option<String>,
    #[arg(
        long,
        env,
        default_value_t = 30,
        long_help = "Number of seconds between two reconciliations"
    )]
    requeue_delay: u64,
}

// Traits

trait DeployableResource: ReconcilableResource<DeployableStatus> {
    fn hash<HASHER: Hasher>(&self, hasher: &HASHER) -> String;

    fn monitor_delay<KUBE: KubeClient + 'static>(
        &self,
        kube: &KUBE,
    ) -> impl Future<Output = Result<chrono::Duration>> + Send;

    fn selector<'a>(&'a self, name: &'a str) -> Vec<(&'a str, &'a str)>;
}

trait ReconcilableResourceEvent: Clone + Debug + Into<Event> + Send + Sync {}

trait ReconcilableResource<STATUS: Status>:
    Clone
    + Debug
    + DeserializeOwned
    + Resource<DynamicType = (), Scope = NamespaceResourceScope>
    + Send
    + Serialize
    + Sync
{
    fn status(&self) -> Option<STATUS>;
}

trait Status: Clone + Copy + Debug + DeserializeOwned + Display + Send + Serialize + Sync {}

// Events

#[derive(Clone, Debug, Eq, PartialEq)]
enum DatabaseEvent {
    Created,
    CreationFailed(String),
    DropFailed(String),
    MonitoringFailed(String),
}

impl ReconcilableResourceEvent for DatabaseEvent {}

#[derive(Clone, Debug, Eq, PartialEq)]
enum DeployableEvent {
    Deployed,
    DeploymentFailed(String),
    MonitoringFailed(String),
    UndeploymentFailed(String),
}

impl ReconcilableResourceEvent for DeployableEvent {}

// Application

impl DeployableResource for Application {
    fn hash<HASHER: Hasher>(&self, hasher: &HASHER) -> String {
        let bytes = serde_json::to_vec(&self.spec).unwrap();
        hasher.hash(&bytes)
    }

    async fn monitor_delay<KUBE: KubeClient>(&self, _kube: &KUBE) -> Result<chrono::Duration> {
        Ok(chrono::Duration::seconds(self.spec.monitor_delay.into()))
    }

    fn selector<'a>(&'a self, name: &'a str) -> Vec<(&'a str, &'a str)> {
        vec![(LABEL_APPLICATION, name)]
    }
}

impl ReconcilableResource<DeployableStatus> for Application {
    fn status(&self) -> Option<DeployableStatus> {
        self.status
    }
}

// Database

impl ReconcilableResource<DatabaseStatus> for Database {
    fn status(&self) -> Option<DatabaseStatus> {
        self.status
    }
}

// DatabaseStatus

impl Status for DatabaseStatus {}

// DeployableStatus

impl Status for DeployableStatus {}

// ServiceInstance

impl DeployableResource for ServiceInstance {
    fn hash<HASHER: Hasher>(&self, hasher: &HASHER) -> String {
        let bytes = serde_json::to_vec(&self.spec).unwrap();
        hasher.hash(&bytes)
    }

    async fn monitor_delay<KUBE: KubeClient>(&self, kube: &KUBE) -> Result<chrono::Duration> {
        let delay = kube
            .get::<Service>(&self.spec.service)
            .await?
            .map(|svc| chrono::Duration::seconds(svc.spec.monitor_delay.into()))
            .unwrap_or_default();
        Ok(delay)
    }

    fn selector<'a>(&'a self, name: &'a str) -> Vec<(&'a str, &'a str)> {
        vec![
            (LABEL_SERVICE_INSTANCE, name),
            (LABEL_SERVICE, &self.spec.service),
        ]
    }
}

impl ReconcilableResource<DeployableStatus> for ServiceInstance {
    fn status(&self) -> Option<DeployableStatus> {
        self.status
    }
}

// Event

impl From<DatabaseEvent> for Event {
    fn from(evt: DatabaseEvent) -> Self {
        match evt {
            DatabaseEvent::Created => Self {
                action: ACTION_CREATING.into(),
                note: Some("Successfully created".into()),
                reason: REASON_CREATED.into(),
                type_: EventType::Normal,
                secondary: None,
            },
            DatabaseEvent::CreationFailed(err) => Self {
                action: ACTION_CREATING.into(),
                note: Some(format!("Failed to create: {err}")),
                reason: REASON_FAILED.into(),
                type_: EventType::Warning,
                secondary: None,
            },
            DatabaseEvent::DropFailed(err) => Self {
                action: ACTION_DROPPING.into(),
                note: Some(format!("Failed to drop: {err}")),
                reason: REASON_FAILED.into(),
                type_: EventType::Warning,
                secondary: None,
            },
            DatabaseEvent::MonitoringFailed(err) => Self {
                action: ACTION_MONITORING.into(),
                note: Some(format!("Failed to monitor: {err}")),
                reason: REASON_FAILED.into(),
                type_: EventType::Warning,
                secondary: None,
            },
        }
    }
}

impl From<DeployableEvent> for Event {
    fn from(evt: DeployableEvent) -> Self {
        match evt {
            DeployableEvent::Deployed => Self {
                action: ACTION_DEPLOYING.into(),
                note: Some("Successfully deployed".into()),
                reason: REASON_DEPLOYED.into(),
                type_: EventType::Normal,
                secondary: None,
            },
            DeployableEvent::DeploymentFailed(err) => Self {
                action: ACTION_DEPLOYING.into(),
                note: Some(format!("Failed to deploy: {err}")),
                reason: REASON_FAILED.into(),
                type_: EventType::Warning,
                secondary: None,
            },
            DeployableEvent::MonitoringFailed(err) => Self {
                action: ACTION_MONITORING.into(),
                note: Some(format!("Failed to monitor: {err}")),
                reason: REASON_FAILED.into(),
                type_: EventType::Warning,
                secondary: None,
            },
            DeployableEvent::UndeploymentFailed(err) => Self {
                action: ACTION_UNDEPLOYING.into(),
                note: Some(format!("Failed to undeploy: {err}")),
                reason: REASON_FAILED.into(),
                type_: EventType::Warning,
                secondary: None,
            },
        }
    }
}

#[cfg(test)]
mod test {
    use std::{future::Future, pin::Pin, sync::Arc};

    use k8s_openapi::api::{batch::v1::Job, core::v1::Secret};
    use mockall::{predicate::*, Predicate};

    use super::*;

    // Macros

    macro_rules! eq_resource {
        ($ident:ident, $ty:ty) => {
            eq_resource!($ident, $ty, spec);
        };

        ($ident:ident, $ty:ty, $spec:ident) => {
            pub fn $ident(expected: &$ty) -> impl Predicate<$ty> {
                let expected = expected.clone();
                function(move |res: &$ty| {
                    res.metadata.name == expected.metadata.name
                        && res.metadata.namespace == expected.metadata.namespace
                        && res.metadata.annotations == expected.metadata.annotations
                        && res.metadata.labels == expected.metadata.labels
                        && res.$spec == expected.$spec
                })
            }
        };
    }

    // Types

    pub type MockFn<VALUE> = Arc<Box<dyn Fn() -> VALUE + Send + Sync>>;

    // Functions

    pub fn async_ok<VALUE: Clone + Send + Sync + 'static, ERR>(
        val: VALUE,
    ) -> Pin<Box<dyn Future<Output = std::result::Result<VALUE, ERR>> + Send>> {
        Box::pin(async move { Ok(val.clone()) })
    }

    pub fn call_mock_fn_opt_async<VALUE: 'static>(
        f: &Option<MockFn<VALUE>>,
    ) -> Pin<Box<dyn Future<Output = VALUE> + Send>> {
        let f = f.clone().unwrap();
        Box::pin(async move { f() })
    }

    pub fn eq_event<EVENT: ReconcilableResourceEvent>(evt: &EVENT) -> impl Predicate<Event> {
        let expected: Event = evt.clone().into();
        function(move |evt: &Event| {
            evt.action == expected.action
                && evt.note == expected.note
                && evt.reason == expected.reason
                && evt.secondary == expected.secondary
                && evt.type_ == expected.type_
        })
    }

    eq_resource!(eq_database, Database);

    eq_resource!(eq_job, Job);

    eq_resource!(eq_secret, Secret, data);

    eq_resource!(eq_service_instance, ServiceInstance);

    pub fn mock_fn<
        DATA: Clone + Send + Sync + 'static,
        FN: Fn(DATA) -> VALUE + Send + Sync + 'static,
        VALUE,
    >(
        data: &DATA,
        fun: FN,
    ) -> MockFn<VALUE> {
        let data = data.clone();
        Arc::new(Box::new(move || fun(data.clone())) as Box<dyn Fn() -> VALUE + Send + Sync>)
    }

    pub fn init_tracer() {
        simpaas_core::tracer::init_tracer("simpaas_operator=debug,warn").ok();
    }
}

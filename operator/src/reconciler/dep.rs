use std::{collections::BTreeMap, marker::PhantomData, sync::Arc};

use chrono::DateTime;
use simpaas_core::{
    kube::{selector, KubeClient},
    DeployableStatus,
};
use tracing::{debug, instrument, warn};

use crate::{
    clock::{Clock, DefaultClock},
    deployer::Deployer,
    hasher::{Hasher, Sha256Hasher},
    monitor::Monitor,
    reconciler::FINALIZER,
    DeployableEvent, DeployableResource,
};

use super::Reconciler;

// Consts

const ANNOT_CHECKSUM: &str = "simpaas.gleroy.dev/checksum";
const ANNOT_LAST_UPDATE: &str = "simpaas.gleroy.dev/last-update";

// Types

pub type Result<VALUE = ()> = super::Result<DeployableEvent, DeployableStatus, VALUE>;
pub type State = super::State<DeployableEvent, DeployableStatus>;

// Error

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub enum Error {
    Deployment(#[source] crate::err::Error),
    Monitoring(#[source] crate::err::Error),
    Undeployment(#[source] crate::err::Error),
}

impl Error {
    pub fn deployment_boxed(
        err: crate::err::Error,
    ) -> Box<dyn super::Error<DeployableEvent, DeployableStatus>> {
        Box::new(Self::Deployment(err))
    }

    pub fn monitoring_boxed(
        err: crate::err::Error,
    ) -> Box<dyn super::Error<DeployableEvent, DeployableStatus>> {
        Box::new(Self::Monitoring(err))
    }

    pub fn undeployment_boxed(
        err: crate::err::Error,
    ) -> Box<dyn super::Error<DeployableEvent, DeployableStatus>> {
        Box::new(Self::Undeployment(err))
    }
}

impl super::Error<DeployableEvent, DeployableStatus> for Error {
    fn state(self: Box<Self>) -> State {
        match *self {
            Self::Deployment(err) => State {
                event: Some(DeployableEvent::DeploymentFailed(err.to_string())),
                should_requeue: true,
                status: Some(DeployableStatus::DeploymentFailed),
                ..Default::default()
            },
            Self::Monitoring(err) => State {
                event: Some(DeployableEvent::MonitoringFailed(err.to_string())),
                should_requeue: true,
                ..Default::default()
            },
            Self::Undeployment(err) => State {
                event: Some(DeployableEvent::UndeploymentFailed(err.to_string())),
                should_requeue: true,
                status: Some(DeployableStatus::UndeploymentFailed),
                ..Default::default()
            },
        }
    }
}

// DeployableReconciler

pub struct DeployableReconciler<
    CLOCK: Clock,
    DEPLOYER: Deployer<RESOURCE>,
    HASHER: Hasher,
    KUBE: KubeClient,
    MONITOR: Monitor,
    RESOURCE: DeployableResource,
> {
    clock: CLOCK,
    deployer: DEPLOYER,
    hasher: HASHER,
    kube: Arc<KUBE>,
    monitor: Arc<MONITOR>,
    _resource: PhantomData<RESOURCE>,
}

impl<
        DEPLOYER: Deployer<RESOURCE>,
        KUBE: KubeClient,
        MONITOR: Monitor,
        RESOURCE: DeployableResource,
    > DeployableReconciler<DefaultClock, DEPLOYER, Sha256Hasher, KUBE, MONITOR, RESOURCE>
{
    pub fn new(dep: DEPLOYER, kube: Arc<KUBE>, monitor: Arc<MONITOR>) -> Self {
        Self {
            clock: DefaultClock,
            deployer: dep,
            hasher: Sha256Hasher,
            kube,
            monitor,
            _resource: PhantomData,
        }
    }
}

impl<
        CLOCK: Clock,
        DEPLOYER: Deployer<RESOURCE>,
        HASHER: Hasher,
        KUBE: KubeClient + 'static,
        MONITOR: Monitor,
        RESOURCE: DeployableResource,
    > Reconciler<DeployableEvent, RESOURCE, DeployableStatus>
    for DeployableReconciler<CLOCK, DEPLOYER, HASHER, KUBE, MONITOR, RESOURCE>
{
    #[instrument(skip(self, ns, name, res), fields(resource.api_version = %RESOURCE::api_version(&()), resource.kind = %RESOURCE::kind(&()), resource.name = name, resource.namespace = ns))]
    async fn reconcile(&self, ns: &str, name: &str, res: &RESOURCE) -> Result<State> {
        let meta = res.meta();
        if meta.deletion_timestamp.is_some() {
            self.deployer
                .undeploy(ns, name, res)
                .await
                .map_err(Error::undeployment_boxed)?;
            Ok(State {
                finalizers: Some(vec![]),
                ..Default::default()
            })
        } else {
            let checksum = res.hash(&self.hasher);
            let unchanged = meta
                .annotations
                .as_ref()
                .and_then(|annots| annots.get(ANNOT_CHECKSUM))
                .is_some_and(|annot| *annot == checksum);
            let should_deploy = !unchanged
                || matches!(
                    res.status(),
                    None | Some(DeployableStatus::DeploymentFailed)
                );
            if should_deploy {
                self.deployer
                    .deploy(ns, name, res)
                    .await
                    .map_err(Error::deployment_boxed)?;
                Ok(State {
                    annotations: Some(BTreeMap::from_iter([
                        (ANNOT_CHECKSUM.into(), checksum),
                        (ANNOT_LAST_UPDATE.into(), self.clock.utc().to_rfc3339()),
                    ])),
                    event: Some(DeployableEvent::Deployed),
                    finalizers: Some(vec![FINALIZER.into()]),
                    should_requeue: true,
                    status: Some(DeployableStatus::Deploying),
                })
            } else {
                let monitor_delay = res
                    .monitor_delay(self.kube.as_ref())
                    .await
                    .map_err(Error::monitoring_boxed)?;
                let now = self.clock.utc();
                let last_update = meta
                    .annotations
                    .as_ref()
                    .and_then(|annots| annots.get(ANNOT_LAST_UPDATE))
                    .map(|annot| {
                        DateTime::parse_from_rfc3339(annot).unwrap_or_else(|err| {
                            warn!("failed to parse last update: {err}");
                            now - monitor_delay
                        })
                    })
                    .unwrap_or_else(|| now - monitor_delay);
                if now - last_update < monitor_delay {
                    debug!("last update is too recent to monitor");
                    Ok(State {
                        annotations: Some(BTreeMap::from_iter([
                            (ANNOT_CHECKSUM.into(), checksum),
                            (ANNOT_LAST_UPDATE.into(), last_update.to_rfc3339()),
                        ])),
                        finalizers: Some(vec![FINALIZER.into()]),
                        should_requeue: true,
                        ..Default::default()
                    })
                } else {
                    let sel = res.selector(name);
                    let stats = self
                        .monitor
                        .monitor_apps(ns, &selector(&sel))
                        .await
                        .map_err(Error::monitoring_boxed)?;
                    let status = if let Some(stats) = stats {
                        if stats.running == 0 || stats.running < stats.expected {
                            debug!("deployment is degraded");
                            DeployableStatus::Degraded
                        } else {
                            debug!("deployment is healthy");
                            DeployableStatus::Healthy
                        }
                    } else {
                        debug!("no stats to dertermine deployment status");
                        DeployableStatus::Unknown
                    };
                    Ok(State {
                        annotations: Some(BTreeMap::from_iter([
                            (ANNOT_CHECKSUM.into(), checksum),
                            (ANNOT_LAST_UPDATE.into(), last_update.to_rfc3339()),
                        ])),
                        finalizers: Some(vec![FINALIZER.into()]),
                        should_requeue: true,
                        status: Some(status),
                        ..Default::default()
                    })
                }
            }
        }
    }
}

// Tests

#[cfg(test)]
mod test {
    use chrono::{Duration, FixedOffset, Utc};
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::Time;
    use kube::api::ObjectMeta;
    use mockall::predicate::*;
    use simpaas_core::{
        kube::MockKubeClient, Service, ServiceInstance, ServiceInstanceSpec, ServiceSpec,
    };

    use crate::{
        clock::MockClock,
        deployer::MockDeployer,
        hasher::MockHasher,
        monitor::{AppStats, MockMonitor},
        test::*,
    };

    use super::*;

    // Mods

    mod deployable_reconciler {
        use super::*;

        // Mods

        mod reconcile {
            use super::*;

            // Data

            #[derive(Clone)]
            struct Data {
                checksum: &'static str,
                instance: ServiceInstance,
                name: &'static str,
                namespace: &'static str,
                now: DateTime<FixedOffset>,
                service: Service,
                stats: AppStats,
            }

            impl Default for Data {
                fn default() -> Self {
                    let name = "instance";
                    let ns = "namespace";
                    let svc_name = "service";
                    Self {
                        checksum: "checksum",
                        instance: ServiceInstance {
                            metadata: ObjectMeta {
                                name: Some(name.into()),
                                namespace: Some(ns.into()),
                                ..Default::default()
                            },
                            spec: ServiceInstanceSpec {
                                service: svc_name.into(),
                                values: Default::default(),
                            },
                            status: None,
                        },
                        name,
                        namespace: ns,
                        now: Utc::now().into(),
                        service: Service {
                            metadata: ObjectMeta {
                                name: Some(svc_name.into()),
                                ..Default::default()
                            },
                            spec: ServiceSpec {
                                chart: "chart".into(),
                                consumes: Default::default(),
                                monitor_delay: 30,
                                values: "values".into(),
                                version: None,
                            },
                        },
                        stats: AppStats {
                            expected: 3,
                            running: 4,
                        },
                    }
                }
            }

            // Mocks

            #[derive(Default)]
            struct Mocks {
                deploy: Option<MockFn<crate::err::Result>>,
                get_service: Option<MockFn<kube::Result<Option<Service>>>>,
                hash: bool,
                monitor_deployable: Option<MockFn<crate::err::Result<Option<AppStats>>>>,
                undeploy: Option<MockFn<crate::err::Result>>,
                utc: bool,
            }

            // Tests

            fn add_annotation<VALUE: Into<String>>(key: &str, value: VALUE, data: &mut Data) {
                let annots = data.instance.metadata.annotations.as_mut();
                if let Some(annots) = annots {
                    annots.insert(key.into(), value.into());
                } else {
                    data.instance.metadata.annotations =
                        Some(BTreeMap::from_iter([(key.into(), value.into())]));
                }
            }

            async fn test(data: Data, mocks: Mocks) -> Result<State> {
                init_tracer();
                let mut clock = MockClock::new();
                clock.expect_utc().times(mocks.utc as usize).returning({
                    let now = data.now;
                    move || now
                });
                let mut deployer = MockDeployer::new();
                deployer
                    .expect_deploy()
                    .with(
                        eq(data.namespace),
                        eq(data.name),
                        eq_service_instance(&data.instance),
                    )
                    .times(mocks.deploy.is_some() as usize)
                    .returning({
                        let deploy = mocks.deploy.clone();
                        move |_, _, _| call_mock_fn_opt_async(&deploy)
                    });
                deployer
                    .expect_undeploy()
                    .with(
                        eq(data.namespace),
                        eq(data.name),
                        eq_service_instance(&data.instance),
                    )
                    .times(mocks.undeploy.is_some() as usize)
                    .returning({
                        let undeploy = mocks.undeploy.clone();
                        move |_, _, _| call_mock_fn_opt_async(&undeploy)
                    });
                let mut hasher = MockHasher::new();
                hasher
                    .expect_hash()
                    .with(eq(serde_json::to_vec(&data.instance.spec).unwrap()))
                    .times(mocks.hash as usize)
                    .returning({
                        let checksum = data.checksum;
                        |_: &Vec<u8>| checksum.into()
                    });
                let mut kube = MockKubeClient::new();
                kube.expect_get::<Service>()
                    .with(eq(data.instance.spec.service.clone()))
                    .times(mocks.get_service.is_some() as usize)
                    .returning({
                        let get = mocks.get_service.clone();
                        move |_| call_mock_fn_opt_async(&get)
                    });
                let mut monitor = MockMonitor::new();
                let sel = selector(&data.instance.selector(data.name));
                monitor
                    .expect_monitor_apps()
                    .with(eq(data.namespace), eq(sel))
                    .times(mocks.monitor_deployable.is_some() as usize)
                    .returning({
                        let monitor_deployable = mocks.monitor_deployable.clone();
                        move |_, _| call_mock_fn_opt_async(&monitor_deployable)
                    });
                let reconciler = DeployableReconciler {
                    clock,
                    deployer,
                    hasher,
                    kube: Arc::new(kube),
                    monitor: Arc::new(monitor),
                    _resource: PhantomData,
                };
                reconciler
                    .reconcile(data.namespace, data.name, &data.instance)
                    .await
            }

            #[tokio::test]
            async fn degraded_deletion_no_checksum() {
                let mut data = Data::default();
                data.instance.metadata.deletion_timestamp = Some(Time(Utc::now()));
                data.instance.status = Some(DeployableStatus::Degraded);
                let mocks = Mocks {
                    undeploy: Some(mock_fn(&data, |_| Ok(()))),
                    ..Default::default()
                };
                let state = test(data, mocks).await.unwrap();
                let expected = State {
                    finalizers: Some(vec![]),
                    ..Default::default()
                };
                assert_eq!(state, expected);
            }

            #[tokio::test]
            async fn degraded_deletion_checksum_unchanged() {
                let mut data = Data::default();
                add_annotation(ANNOT_CHECKSUM, data.checksum, &mut data);
                data.instance.metadata.deletion_timestamp = Some(Time(Utc::now()));
                data.instance.status = Some(DeployableStatus::Degraded);
                let mocks = Mocks {
                    undeploy: Some(mock_fn(&data, |_| Ok(()))),
                    ..Default::default()
                };
                let state = test(data, mocks).await.unwrap();
                let expected = State {
                    finalizers: Some(vec![]),
                    ..Default::default()
                };
                assert_eq!(state, expected);
            }

            #[tokio::test]
            async fn degraded_deletion_checksum_changed() {
                let mut data = Data::default();
                add_annotation(ANNOT_CHECKSUM, format!("{}_old", data.checksum), &mut data);
                data.instance.metadata.deletion_timestamp = Some(Time(Utc::now()));
                data.instance.status = Some(DeployableStatus::Degraded);
                let mocks = Mocks {
                    undeploy: Some(mock_fn(&data, |_| Ok(()))),
                    ..Default::default()
                };
                let state = test(data, mocks).await.unwrap();
                let expected = State {
                    finalizers: Some(vec![]),
                    ..Default::default()
                };
                assert_eq!(state, expected);
            }

            #[tokio::test]
            async fn degraded_no_deletion_checksum_changed() {
                let mut data = Data::default();
                add_annotation(ANNOT_CHECKSUM, format!("{}_old", data.checksum), &mut data);
                data.instance.status = Some(DeployableStatus::Degraded);
                let mocks = Mocks {
                    deploy: Some(mock_fn(&data, |_| Ok(()))),
                    hash: true,
                    utc: true,
                    ..Default::default()
                };
                let state = test(data.clone(), mocks).await.unwrap();
                let expected = State {
                    annotations: Some(BTreeMap::from_iter([
                        (ANNOT_CHECKSUM.into(), data.checksum.into()),
                        (ANNOT_LAST_UPDATE.into(), data.now.to_rfc3339()),
                    ])),
                    event: Some(DeployableEvent::Deployed),
                    finalizers: Some(vec![FINALIZER.into()]),
                    should_requeue: true,
                    status: Some(DeployableStatus::Deploying),
                };
                assert_eq!(state, expected);
            }

            #[tokio::test]
            async fn degraded_no_deletion_checksum_unchanged_last_update_malformed() {
                let mut data = Data::default();
                add_annotation(ANNOT_CHECKSUM, data.checksum, &mut data);
                add_annotation(ANNOT_LAST_UPDATE, "", &mut data);
                data.instance.status = Some(DeployableStatus::Degraded);
                let mocks = Mocks {
                    get_service: Some(mock_fn(&data, |data| Ok(Some(data.service)))),
                    hash: true,
                    monitor_deployable: Some(mock_fn(&data, |data| Ok(Some(data.stats)))),
                    utc: true,
                    ..Default::default()
                };
                let state = test(data.clone(), mocks).await.unwrap();
                let expected = State {
                    annotations: Some(BTreeMap::from_iter([
                        (ANNOT_CHECKSUM.into(), data.checksum.into()),
                        (
                            ANNOT_LAST_UPDATE.into(),
                            (data.now - Duration::seconds(data.service.spec.monitor_delay.into()))
                                .to_rfc3339(),
                        ),
                    ])),
                    finalizers: Some(vec![FINALIZER.into()]),
                    should_requeue: true,
                    status: Some(DeployableStatus::Healthy),
                    ..Default::default()
                };
                assert_eq!(state, expected);
            }

            #[tokio::test]
            async fn degraded_no_deletion_checksum_unchanged_last_update_old() {
                let mut data = Data::default();
                let last_update =
                    data.now - Duration::seconds(data.service.spec.monitor_delay.into());
                add_annotation(ANNOT_CHECKSUM, data.checksum, &mut data);
                add_annotation(ANNOT_LAST_UPDATE, last_update.to_rfc3339(), &mut data);
                data.instance.status = Some(DeployableStatus::Degraded);
                let mocks = Mocks {
                    get_service: Some(mock_fn(&data, |data| Ok(Some(data.service)))),
                    hash: true,
                    monitor_deployable: Some(mock_fn(&data, |data| Ok(Some(data.stats)))),
                    utc: true,
                    ..Default::default()
                };
                let state = test(data.clone(), mocks).await.unwrap();
                let expected = State {
                    annotations: Some(BTreeMap::from_iter([
                        (ANNOT_CHECKSUM.into(), data.checksum.into()),
                        (ANNOT_LAST_UPDATE.into(), last_update.to_rfc3339()),
                    ])),
                    finalizers: Some(vec![FINALIZER.into()]),
                    should_requeue: true,
                    status: Some(DeployableStatus::Healthy),
                    ..Default::default()
                };
                assert_eq!(state, expected);
            }

            #[tokio::test]
            async fn degraded_no_deletion_checksum_unchanged_last_update_too_recent() {
                let mut data = Data::default();
                add_annotation(ANNOT_CHECKSUM, data.checksum, &mut data);
                add_annotation(ANNOT_LAST_UPDATE, data.now.to_rfc3339(), &mut data);
                data.instance.status = Some(DeployableStatus::Degraded);
                let mocks = Mocks {
                    get_service: Some(mock_fn(&data, |data| Ok(Some(data.service)))),
                    hash: true,
                    utc: true,
                    ..Default::default()
                };
                let state = test(data.clone(), mocks).await.unwrap();
                let expected = State {
                    annotations: Some(BTreeMap::from_iter([
                        (ANNOT_CHECKSUM.into(), data.checksum.into()),
                        (ANNOT_LAST_UPDATE.into(), data.now.to_rfc3339()),
                    ])),
                    finalizers: Some(vec![FINALIZER.into()]),
                    should_requeue: true,
                    ..Default::default()
                };
                assert_eq!(state, expected);
            }

            #[tokio::test]
            async fn degraded_no_deletion_checksum_unchanged_no_last_update_degraded() {
                let mut data = Data::default();
                add_annotation(ANNOT_CHECKSUM, data.checksum, &mut data);
                data.instance.status = Some(DeployableStatus::Degraded);
                let mocks = Mocks {
                    get_service: Some(mock_fn(&data, |data| Ok(Some(data.service)))),
                    hash: true,
                    monitor_deployable: Some(mock_fn(&data, |_| {
                        Ok(Some(AppStats {
                            expected: 6,
                            running: 5,
                        }))
                    })),
                    utc: true,
                    ..Default::default()
                };
                let state = test(data.clone(), mocks).await.unwrap();
                let expected = State {
                    annotations: Some(BTreeMap::from_iter([
                        (ANNOT_CHECKSUM.into(), data.checksum.into()),
                        (
                            ANNOT_LAST_UPDATE.into(),
                            (data.now - Duration::seconds(data.service.spec.monitor_delay.into()))
                                .to_rfc3339(),
                        ),
                    ])),
                    finalizers: Some(vec![FINALIZER.into()]),
                    should_requeue: true,
                    status: Some(DeployableStatus::Degraded),
                    ..Default::default()
                };
                assert_eq!(state, expected);
            }

            #[tokio::test]
            async fn degraded_no_deletion_checksum_unchanged_no_last_update_healthy() {
                let mut data = Data::default();
                add_annotation(ANNOT_CHECKSUM, data.checksum, &mut data);
                data.instance.status = Some(DeployableStatus::Degraded);
                let mocks = Mocks {
                    get_service: Some(mock_fn(&data, |data| Ok(Some(data.service)))),
                    hash: true,
                    monitor_deployable: Some(mock_fn(&data, |data| Ok(Some(data.stats)))),
                    utc: true,
                    ..Default::default()
                };
                let state = test(data.clone(), mocks).await.unwrap();
                let expected = State {
                    annotations: Some(BTreeMap::from_iter([
                        (ANNOT_CHECKSUM.into(), data.checksum.into()),
                        (
                            ANNOT_LAST_UPDATE.into(),
                            (data.now - Duration::seconds(data.service.spec.monitor_delay.into()))
                                .to_rfc3339(),
                        ),
                    ])),
                    finalizers: Some(vec![FINALIZER.into()]),
                    should_requeue: true,
                    status: Some(DeployableStatus::Healthy),
                    ..Default::default()
                };
                assert_eq!(state, expected);
            }

            #[tokio::test]
            async fn degraded_no_deletion_checksum_unchanged_no_last_update_unknown() {
                let mut data = Data::default();
                add_annotation(ANNOT_CHECKSUM, data.checksum, &mut data);
                data.instance.status = Some(DeployableStatus::Degraded);
                let mocks = Mocks {
                    get_service: Some(mock_fn(&data, |data| Ok(Some(data.service)))),
                    hash: true,
                    monitor_deployable: Some(mock_fn(&data, |_| Ok(None))),
                    utc: true,
                    ..Default::default()
                };
                let state = test(data.clone(), mocks).await.unwrap();
                let expected = State {
                    annotations: Some(BTreeMap::from_iter([
                        (ANNOT_CHECKSUM.into(), data.checksum.into()),
                        (
                            ANNOT_LAST_UPDATE.into(),
                            (data.now - Duration::seconds(data.service.spec.monitor_delay.into()))
                                .to_rfc3339(),
                        ),
                    ])),
                    finalizers: Some(vec![FINALIZER.into()]),
                    should_requeue: true,
                    status: Some(DeployableStatus::Unknown),
                    ..Default::default()
                };
                assert_eq!(state, expected);
            }

            #[tokio::test]
            async fn degraded_no_deletion_no_checksum() {
                let mut data = Data::default();
                data.instance.status = Some(DeployableStatus::Degraded);
                let mocks = Mocks {
                    deploy: Some(mock_fn(&data, |_| Ok(()))),
                    hash: true,
                    utc: true,
                    ..Default::default()
                };
                let state = test(data.clone(), mocks).await.unwrap();
                let expected = State {
                    annotations: Some(BTreeMap::from_iter([
                        (ANNOT_CHECKSUM.into(), data.checksum.into()),
                        (ANNOT_LAST_UPDATE.into(), data.now.to_rfc3339()),
                    ])),
                    event: Some(DeployableEvent::Deployed),
                    finalizers: Some(vec![FINALIZER.into()]),
                    should_requeue: true,
                    status: Some(DeployableStatus::Deploying),
                };
                assert_eq!(state, expected);
            }

            #[tokio::test]
            async fn deploy_err() {
                let data = Data::default();
                let mocks = Mocks {
                    deploy: Some(mock_fn(&data, |_| Err(crate::err::Error::CommandFailed))),
                    hash: true,
                    ..Default::default()
                };
                let state = test(data, mocks).await.unwrap_err().state();
                let err = crate::err::Error::CommandFailed.to_string();
                let expected = State {
                    event: Some(DeployableEvent::DeploymentFailed(err)),
                    should_requeue: true,
                    status: Some(DeployableStatus::DeploymentFailed),
                    ..Default::default()
                };
                assert_eq!(state, expected);
            }

            #[tokio::test]
            async fn deploying_deletion_no_checksum() {
                let mut data = Data::default();
                data.instance.metadata.deletion_timestamp = Some(Time(Utc::now()));
                data.instance.status = Some(DeployableStatus::Deploying);
                let mocks = Mocks {
                    undeploy: Some(mock_fn(&data, |_| Ok(()))),
                    ..Default::default()
                };
                let state = test(data, mocks).await.unwrap();
                let expected = State {
                    finalizers: Some(vec![]),
                    ..Default::default()
                };
                assert_eq!(state, expected);
            }

            #[tokio::test]
            async fn deploying_deletion_checksum_unchanged() {
                let mut data = Data::default();
                add_annotation(ANNOT_CHECKSUM, data.checksum, &mut data);
                data.instance.metadata.deletion_timestamp = Some(Time(Utc::now()));
                data.instance.status = Some(DeployableStatus::Deploying);
                let mocks = Mocks {
                    undeploy: Some(mock_fn(&data, |_| Ok(()))),
                    ..Default::default()
                };
                let state = test(data, mocks).await.unwrap();
                let expected = State {
                    finalizers: Some(vec![]),
                    ..Default::default()
                };
                assert_eq!(state, expected);
            }

            #[tokio::test]
            async fn deploying_deletion_checksum_changed() {
                let mut data = Data::default();
                add_annotation(ANNOT_CHECKSUM, format!("{}_old", data.checksum), &mut data);
                data.instance.metadata.deletion_timestamp = Some(Time(Utc::now()));
                data.instance.status = Some(DeployableStatus::Deploying);
                let mocks = Mocks {
                    undeploy: Some(mock_fn(&data, |_| Ok(()))),
                    ..Default::default()
                };
                let state = test(data, mocks).await.unwrap();
                let expected = State {
                    finalizers: Some(vec![]),
                    ..Default::default()
                };
                assert_eq!(state, expected);
            }

            #[tokio::test]
            async fn deploying_no_deletion_checksum_changed() {
                let mut data = Data::default();
                add_annotation(ANNOT_CHECKSUM, format!("{}_old", data.checksum), &mut data);
                data.instance.status = Some(DeployableStatus::Deploying);
                let mocks = Mocks {
                    deploy: Some(mock_fn(&data, |_| Ok(()))),
                    hash: true,
                    utc: true,
                    ..Default::default()
                };
                let state = test(data.clone(), mocks).await.unwrap();
                let expected = State {
                    annotations: Some(BTreeMap::from_iter([
                        (ANNOT_CHECKSUM.into(), data.checksum.into()),
                        (ANNOT_LAST_UPDATE.into(), data.now.to_rfc3339()),
                    ])),
                    event: Some(DeployableEvent::Deployed),
                    finalizers: Some(vec![FINALIZER.into()]),
                    should_requeue: true,
                    status: Some(DeployableStatus::Deploying),
                };
                assert_eq!(state, expected);
            }

            #[tokio::test]
            async fn deploying_no_deletion_checksum_unchanged_no_last_update_healthy_no_service() {
                let mut data = Data::default();
                add_annotation(ANNOT_CHECKSUM, data.checksum, &mut data);
                data.instance.status = Some(DeployableStatus::Deploying);
                let mocks = Mocks {
                    get_service: Some(mock_fn(&data, |_| Ok(None))),
                    hash: true,
                    monitor_deployable: Some(mock_fn(&data, |data| Ok(Some(data.stats)))),
                    utc: true,
                    ..Default::default()
                };
                let state = test(data.clone(), mocks).await.unwrap();
                let expected = State {
                    annotations: Some(BTreeMap::from_iter([
                        (ANNOT_CHECKSUM.into(), data.checksum.into()),
                        (
                            ANNOT_LAST_UPDATE.into(),
                            (data.now - Duration::default()).to_rfc3339(),
                        ),
                    ])),
                    finalizers: Some(vec![FINALIZER.into()]),
                    should_requeue: true,
                    status: Some(DeployableStatus::Healthy),
                    ..Default::default()
                };
                assert_eq!(state, expected);
            }

            #[tokio::test]
            async fn deploying_no_deletion_checksum_unchanged_no_last_update_healthy_get_service_err(
            ) {
                let err = "error";
                let mut data = Data::default();
                add_annotation(ANNOT_CHECKSUM, data.checksum, &mut data);
                data.instance.status = Some(DeployableStatus::Deploying);
                let mocks = Mocks {
                    get_service: Some(mock_fn(&data, |_| Err(kube::Error::Service(err.into())))),
                    hash: true,
                    ..Default::default()
                };
                let state = test(data.clone(), mocks).await.unwrap_err().state();
                let err = crate::err::Error::Kube(kube::Error::Service(err.into())).to_string();
                let expected = State {
                    event: Some(DeployableEvent::MonitoringFailed(err)),
                    should_requeue: true,
                    ..Default::default()
                };
                assert_eq!(state, expected);
            }

            #[tokio::test]
            async fn deploying_no_deletion_checksum_unchanged_no_last_update_healthy() {
                let mut data = Data::default();
                add_annotation(ANNOT_CHECKSUM, data.checksum, &mut data);
                data.instance.status = Some(DeployableStatus::Deploying);
                let mocks = Mocks {
                    get_service: Some(mock_fn(&data, |data| Ok(Some(data.service)))),
                    hash: true,
                    monitor_deployable: Some(mock_fn(&data, |data| Ok(Some(data.stats)))),
                    utc: true,
                    ..Default::default()
                };
                let state = test(data.clone(), mocks).await.unwrap();
                let expected = State {
                    annotations: Some(BTreeMap::from_iter([
                        (ANNOT_CHECKSUM.into(), data.checksum.into()),
                        (
                            ANNOT_LAST_UPDATE.into(),
                            (data.now - Duration::seconds(data.service.spec.monitor_delay.into()))
                                .to_rfc3339(),
                        ),
                    ])),
                    finalizers: Some(vec![FINALIZER.into()]),
                    should_requeue: true,
                    status: Some(DeployableStatus::Healthy),
                    ..Default::default()
                };
                assert_eq!(state, expected);
            }

            #[tokio::test]
            async fn deploying_no_deletion_no_checksum() {
                let mut data = Data::default();
                data.instance.status = Some(DeployableStatus::Deploying);
                let mocks = Mocks {
                    deploy: Some(mock_fn(&data, |_| Ok(()))),
                    hash: true,
                    utc: true,
                    ..Default::default()
                };
                let state = test(data.clone(), mocks).await.unwrap();
                let expected = State {
                    annotations: Some(BTreeMap::from_iter([
                        (ANNOT_CHECKSUM.into(), data.checksum.into()),
                        (ANNOT_LAST_UPDATE.into(), data.now.to_rfc3339()),
                    ])),
                    event: Some(DeployableEvent::Deployed),
                    finalizers: Some(vec![FINALIZER.into()]),
                    should_requeue: true,
                    status: Some(DeployableStatus::Deploying),
                };
                assert_eq!(state, expected);
            }

            #[tokio::test]
            async fn deployment_failed_deletion_no_checksum() {
                let mut data = Data::default();
                data.instance.metadata.deletion_timestamp = Some(Time(Utc::now()));
                data.instance.status = Some(DeployableStatus::DeploymentFailed);
                let mocks = Mocks {
                    undeploy: Some(mock_fn(&data, |_| Ok(()))),
                    ..Default::default()
                };
                let state = test(data, mocks).await.unwrap();
                let expected = State {
                    finalizers: Some(vec![]),
                    ..Default::default()
                };
                assert_eq!(state, expected);
            }

            #[tokio::test]
            async fn deployment_failed_deletion_checksum_unchanged() {
                let mut data = Data::default();
                add_annotation(ANNOT_CHECKSUM, data.checksum, &mut data);
                data.instance.metadata.deletion_timestamp = Some(Time(Utc::now()));
                data.instance.status = Some(DeployableStatus::DeploymentFailed);
                let mocks = Mocks {
                    undeploy: Some(mock_fn(&data, |_| Ok(()))),
                    ..Default::default()
                };
                let state = test(data, mocks).await.unwrap();
                let expected = State {
                    finalizers: Some(vec![]),
                    ..Default::default()
                };
                assert_eq!(state, expected);
            }

            #[tokio::test]
            async fn deployment_failed_deletion_checksum_changed() {
                let mut data = Data::default();
                add_annotation(ANNOT_CHECKSUM, format!("{}_old", data.checksum), &mut data);
                data.instance.metadata.deletion_timestamp = Some(Time(Utc::now()));
                data.instance.status = Some(DeployableStatus::DeploymentFailed);
                let mocks = Mocks {
                    undeploy: Some(mock_fn(&data, |_| Ok(()))),
                    ..Default::default()
                };
                let state = test(data, mocks).await.unwrap();
                let expected = State {
                    finalizers: Some(vec![]),
                    ..Default::default()
                };
                assert_eq!(state, expected);
            }

            #[tokio::test]
            async fn deployment_failed_no_deletion_checksum_changed() {
                let mut data = Data::default();
                add_annotation(ANNOT_CHECKSUM, format!("{}_old", data.checksum), &mut data);
                data.instance.status = Some(DeployableStatus::DeploymentFailed);
                let mocks = Mocks {
                    deploy: Some(mock_fn(&data, |_| Ok(()))),
                    hash: true,
                    utc: true,
                    ..Default::default()
                };
                let state = test(data.clone(), mocks).await.unwrap();
                let expected = State {
                    annotations: Some(BTreeMap::from_iter([
                        (ANNOT_CHECKSUM.into(), data.checksum.into()),
                        (ANNOT_LAST_UPDATE.into(), data.now.to_rfc3339()),
                    ])),
                    event: Some(DeployableEvent::Deployed),
                    finalizers: Some(vec![FINALIZER.into()]),
                    should_requeue: true,
                    status: Some(DeployableStatus::Deploying),
                };
                assert_eq!(state, expected);
            }

            #[tokio::test]
            async fn deployment_failed_no_deletion_checksum_unchanged() {
                let mut data = Data::default();
                add_annotation(ANNOT_CHECKSUM, data.checksum, &mut data);
                data.instance.status = Some(DeployableStatus::DeploymentFailed);
                let mocks = Mocks {
                    deploy: Some(mock_fn(&data, |_| Ok(()))),
                    hash: true,
                    utc: true,
                    ..Default::default()
                };
                let state = test(data.clone(), mocks).await.unwrap();
                let expected = State {
                    annotations: Some(BTreeMap::from_iter([
                        (ANNOT_CHECKSUM.into(), data.checksum.into()),
                        (ANNOT_LAST_UPDATE.into(), data.now.to_rfc3339()),
                    ])),
                    event: Some(DeployableEvent::Deployed),
                    finalizers: Some(vec![FINALIZER.into()]),
                    should_requeue: true,
                    status: Some(DeployableStatus::Deploying),
                };
                assert_eq!(state, expected);
            }

            #[tokio::test]
            async fn deployment_failed_no_deletion_no_checksum() {
                let mut data = Data::default();
                data.instance.status = Some(DeployableStatus::DeploymentFailed);
                let mocks = Mocks {
                    deploy: Some(mock_fn(&data, |_| Ok(()))),
                    hash: true,
                    utc: true,
                    ..Default::default()
                };
                let state = test(data.clone(), mocks).await.unwrap();
                let expected = State {
                    annotations: Some(BTreeMap::from_iter([
                        (ANNOT_CHECKSUM.into(), data.checksum.into()),
                        (ANNOT_LAST_UPDATE.into(), data.now.to_rfc3339()),
                    ])),
                    event: Some(DeployableEvent::Deployed),
                    finalizers: Some(vec![FINALIZER.into()]),
                    should_requeue: true,
                    status: Some(DeployableStatus::Deploying),
                };
                assert_eq!(state, expected);
            }

            #[tokio::test]
            async fn healthy_deletion_no_checksum() {
                let mut data = Data::default();
                data.instance.metadata.deletion_timestamp = Some(Time(Utc::now()));
                data.instance.status = Some(DeployableStatus::Healthy);
                let mocks = Mocks {
                    undeploy: Some(mock_fn(&data, |_| Ok(()))),
                    ..Default::default()
                };
                let state = test(data, mocks).await.unwrap();
                let expected = State {
                    finalizers: Some(vec![]),
                    ..Default::default()
                };
                assert_eq!(state, expected);
            }

            #[tokio::test]
            async fn healthy_deletion_checksum_unchanged() {
                let mut data = Data::default();
                add_annotation(ANNOT_CHECKSUM, data.checksum, &mut data);
                data.instance.metadata.deletion_timestamp = Some(Time(Utc::now()));
                data.instance.status = Some(DeployableStatus::Healthy);
                let mocks = Mocks {
                    undeploy: Some(mock_fn(&data, |_| Ok(()))),
                    ..Default::default()
                };
                let state = test(data, mocks).await.unwrap();
                let expected = State {
                    finalizers: Some(vec![]),
                    ..Default::default()
                };
                assert_eq!(state, expected);
            }

            #[tokio::test]
            async fn healthy_deletion_checksum_changed() {
                let mut data = Data::default();
                add_annotation(ANNOT_CHECKSUM, format!("{}_old", data.checksum), &mut data);
                data.instance.metadata.deletion_timestamp = Some(Time(Utc::now()));
                data.instance.status = Some(DeployableStatus::Healthy);
                let mocks = Mocks {
                    undeploy: Some(mock_fn(&data, |_| Ok(()))),
                    ..Default::default()
                };
                let state = test(data, mocks).await.unwrap();
                let expected = State {
                    finalizers: Some(vec![]),
                    ..Default::default()
                };
                assert_eq!(state, expected);
            }

            #[tokio::test]
            async fn healthy_monitor_deployable_err() {
                let mut data = Data::default();
                add_annotation(ANNOT_CHECKSUM, data.checksum, &mut data);
                data.instance.status = Some(DeployableStatus::Healthy);
                let mocks = Mocks {
                    get_service: Some(mock_fn(&data, |data| Ok(Some(data.service)))),
                    hash: true,
                    monitor_deployable: Some(mock_fn(&data, |_| {
                        Err(crate::err::Error::CommandFailed)
                    })),
                    utc: true,
                    ..Default::default()
                };
                let state = test(data, mocks).await.unwrap_err().state();
                let err = crate::err::Error::CommandFailed.to_string();
                let expected = State {
                    event: Some(DeployableEvent::MonitoringFailed(err)),
                    should_requeue: true,
                    ..Default::default()
                };
                assert_eq!(state, expected);
            }

            #[tokio::test]
            async fn healthy_no_deletion_checksum_changed() {
                let mut data = Data::default();
                add_annotation(ANNOT_CHECKSUM, format!("{}_old", data.checksum), &mut data);
                data.instance.status = Some(DeployableStatus::Healthy);
                let mocks = Mocks {
                    deploy: Some(mock_fn(&data, |_| Ok(()))),
                    hash: true,
                    utc: true,
                    ..Default::default()
                };
                let state = test(data.clone(), mocks).await.unwrap();
                let expected = State {
                    annotations: Some(BTreeMap::from_iter([
                        (ANNOT_CHECKSUM.into(), data.checksum.into()),
                        (ANNOT_LAST_UPDATE.into(), data.now.to_rfc3339()),
                    ])),
                    event: Some(DeployableEvent::Deployed),
                    finalizers: Some(vec![FINALIZER.into()]),
                    should_requeue: true,
                    status: Some(DeployableStatus::Deploying),
                };
                assert_eq!(state, expected);
            }

            #[tokio::test]
            async fn healthy_no_deletion_checksum_unchanged_no_last_update_healthy() {
                let mut data = Data::default();
                add_annotation(ANNOT_CHECKSUM, data.checksum, &mut data);
                data.instance.status = Some(DeployableStatus::Healthy);
                let mocks = Mocks {
                    get_service: Some(mock_fn(&data, |data| Ok(Some(data.service)))),
                    hash: true,
                    monitor_deployable: Some(mock_fn(&data, |data| Ok(Some(data.stats)))),
                    utc: true,
                    ..Default::default()
                };
                let state = test(data.clone(), mocks).await.unwrap();
                let expected = State {
                    annotations: Some(BTreeMap::from_iter([
                        (ANNOT_CHECKSUM.into(), data.checksum.into()),
                        (
                            ANNOT_LAST_UPDATE.into(),
                            (data.now - Duration::seconds(data.service.spec.monitor_delay.into()))
                                .to_rfc3339(),
                        ),
                    ])),
                    finalizers: Some(vec![FINALIZER.into()]),
                    should_requeue: true,
                    status: Some(DeployableStatus::Healthy),
                    ..Default::default()
                };
                assert_eq!(state, expected);
            }

            #[tokio::test]
            async fn healthy_no_deletion_no_checksum() {
                let mut data = Data::default();
                data.instance.status = Some(DeployableStatus::Healthy);
                let mocks = Mocks {
                    deploy: Some(mock_fn(&data, |_| Ok(()))),
                    hash: true,
                    utc: true,
                    ..Default::default()
                };
                let state = test(data.clone(), mocks).await.unwrap();
                let expected = State {
                    annotations: Some(BTreeMap::from_iter([
                        (ANNOT_CHECKSUM.into(), data.checksum.into()),
                        (ANNOT_LAST_UPDATE.into(), data.now.to_rfc3339()),
                    ])),
                    event: Some(DeployableEvent::Deployed),
                    finalizers: Some(vec![FINALIZER.into()]),
                    should_requeue: true,
                    status: Some(DeployableStatus::Deploying),
                };
                assert_eq!(state, expected);
            }

            #[tokio::test]
            async fn no_status_deletion_no_checksum() {
                let mut data = Data::default();
                data.instance.metadata.deletion_timestamp = Some(Time(Utc::now()));
                let mocks = Mocks {
                    undeploy: Some(mock_fn(&data, |_| Ok(()))),
                    ..Default::default()
                };
                let state = test(data, mocks).await.unwrap();
                let expected = State {
                    finalizers: Some(vec![]),
                    ..Default::default()
                };
                assert_eq!(state, expected);
            }

            #[tokio::test]
            async fn no_status_deletion_checksum_unchanged() {
                let mut data = Data::default();
                add_annotation(ANNOT_CHECKSUM, data.checksum, &mut data);
                data.instance.metadata.deletion_timestamp = Some(Time(Utc::now()));
                let mocks = Mocks {
                    undeploy: Some(mock_fn(&data, |_| Ok(()))),
                    ..Default::default()
                };
                let state = test(data, mocks).await.unwrap();
                let expected = State {
                    finalizers: Some(vec![]),
                    ..Default::default()
                };
                assert_eq!(state, expected);
            }

            #[tokio::test]
            async fn no_status_deletion_checksum_changed() {
                let mut data = Data::default();
                add_annotation(ANNOT_CHECKSUM, format!("{}_old", data.checksum), &mut data);
                data.instance.metadata.deletion_timestamp = Some(Time(Utc::now()));
                let mocks = Mocks {
                    undeploy: Some(mock_fn(&data, |_| Ok(()))),
                    ..Default::default()
                };
                let state = test(data, mocks).await.unwrap();
                let expected = State {
                    finalizers: Some(vec![]),
                    ..Default::default()
                };
                assert_eq!(state, expected);
            }

            #[tokio::test]
            async fn no_status_no_deletion_checksum_changed() {
                let mut data = Data::default();
                add_annotation(ANNOT_CHECKSUM, format!("{}_old", data.checksum), &mut data);
                let mocks = Mocks {
                    deploy: Some(mock_fn(&data, |_| Ok(()))),
                    hash: true,
                    utc: true,
                    ..Default::default()
                };
                let state = test(data.clone(), mocks).await.unwrap();
                let expected = State {
                    annotations: Some(BTreeMap::from_iter([
                        (ANNOT_CHECKSUM.into(), data.checksum.into()),
                        (ANNOT_LAST_UPDATE.into(), data.now.to_rfc3339()),
                    ])),
                    event: Some(DeployableEvent::Deployed),
                    finalizers: Some(vec![FINALIZER.into()]),
                    should_requeue: true,
                    status: Some(DeployableStatus::Deploying),
                };
                assert_eq!(state, expected);
            }

            #[tokio::test]
            async fn no_status_no_deletion_checksum_unchanged_no_last_update_healthy() {
                let mut data = Data::default();
                add_annotation(ANNOT_CHECKSUM, data.checksum, &mut data);
                let mocks = Mocks {
                    deploy: Some(mock_fn(&data, |_| Ok(()))),
                    hash: true,
                    utc: true,
                    ..Default::default()
                };
                let state = test(data.clone(), mocks).await.unwrap();
                let expected = State {
                    annotations: Some(BTreeMap::from_iter([
                        (ANNOT_CHECKSUM.into(), data.checksum.into()),
                        (ANNOT_LAST_UPDATE.into(), data.now.to_rfc3339()),
                    ])),
                    event: Some(DeployableEvent::Deployed),
                    finalizers: Some(vec![FINALIZER.into()]),
                    should_requeue: true,
                    status: Some(DeployableStatus::Deploying),
                };
                assert_eq!(state, expected);
            }

            #[tokio::test]
            async fn no_status_no_deletion_no_checksum() {
                let data = Data::default();
                let mocks = Mocks {
                    deploy: Some(mock_fn(&data, |_| Ok(()))),
                    hash: true,
                    utc: true,
                    ..Default::default()
                };
                let state = test(data.clone(), mocks).await.unwrap();
                let expected = State {
                    annotations: Some(BTreeMap::from_iter([
                        (ANNOT_CHECKSUM.into(), data.checksum.into()),
                        (ANNOT_LAST_UPDATE.into(), data.now.to_rfc3339()),
                    ])),
                    event: Some(DeployableEvent::Deployed),
                    finalizers: Some(vec![FINALIZER.into()]),
                    should_requeue: true,
                    status: Some(DeployableStatus::Deploying),
                };
                assert_eq!(state, expected);
            }

            #[tokio::test]
            async fn undeploy_err() {
                let mut data = Data::default();
                data.instance.metadata.deletion_timestamp = Some(Time(Utc::now()));
                let mocks = Mocks {
                    undeploy: Some(mock_fn(&data, |_| Err(crate::err::Error::CommandFailed))),
                    ..Default::default()
                };
                let state = test(data, mocks).await.unwrap_err().state();
                let err = crate::err::Error::CommandFailed.to_string();
                let expected = State {
                    event: Some(DeployableEvent::UndeploymentFailed(err)),
                    should_requeue: true,
                    status: Some(DeployableStatus::UndeploymentFailed),
                    ..Default::default()
                };
                assert_eq!(state, expected);
            }

            #[tokio::test]
            async fn undeployment_failed_deletion_no_checksum() {
                let mut data = Data::default();
                data.instance.metadata.deletion_timestamp = Some(Time(Utc::now()));
                data.instance.status = Some(DeployableStatus::UndeploymentFailed);
                let mocks = Mocks {
                    undeploy: Some(mock_fn(&data, |_| Ok(()))),
                    ..Default::default()
                };
                let state = test(data, mocks).await.unwrap();
                let expected = State {
                    finalizers: Some(vec![]),
                    ..Default::default()
                };
                assert_eq!(state, expected);
            }

            #[tokio::test]
            async fn undeployment_failed_deletion_checksum_unchanged() {
                let mut data = Data::default();
                add_annotation(ANNOT_CHECKSUM, data.checksum, &mut data);
                data.instance.metadata.deletion_timestamp = Some(Time(Utc::now()));
                data.instance.status = Some(DeployableStatus::UndeploymentFailed);
                let mocks = Mocks {
                    undeploy: Some(mock_fn(&data, |_| Ok(()))),
                    ..Default::default()
                };
                let state = test(data, mocks).await.unwrap();
                let expected = State {
                    finalizers: Some(vec![]),
                    ..Default::default()
                };
                assert_eq!(state, expected);
            }

            #[tokio::test]
            async fn undeployment_failed_deletion_checksum_changed() {
                let mut data = Data::default();
                add_annotation(ANNOT_CHECKSUM, format!("{}_old", data.checksum), &mut data);
                data.instance.metadata.deletion_timestamp = Some(Time(Utc::now()));
                data.instance.status = Some(DeployableStatus::UndeploymentFailed);
                let mocks = Mocks {
                    undeploy: Some(mock_fn(&data, |_| Ok(()))),
                    ..Default::default()
                };
                let state = test(data, mocks).await.unwrap();
                let expected = State {
                    finalizers: Some(vec![]),
                    ..Default::default()
                };
                assert_eq!(state, expected);
            }

            #[tokio::test]
            async fn unknown_deletion_no_checksum() {
                let mut data = Data::default();
                data.instance.metadata.deletion_timestamp = Some(Time(Utc::now()));
                data.instance.status = Some(DeployableStatus::Unknown);
                let mocks = Mocks {
                    undeploy: Some(mock_fn(&data, |_| Ok(()))),
                    ..Default::default()
                };
                let state = test(data, mocks).await.unwrap();
                let expected = State {
                    finalizers: Some(vec![]),
                    ..Default::default()
                };
                assert_eq!(state, expected);
            }

            #[tokio::test]
            async fn unknown_deletion_checksum_unchanged() {
                let mut data = Data::default();
                add_annotation(ANNOT_CHECKSUM, data.checksum, &mut data);
                data.instance.metadata.deletion_timestamp = Some(Time(Utc::now()));
                data.instance.status = Some(DeployableStatus::Unknown);
                let mocks = Mocks {
                    undeploy: Some(mock_fn(&data, |_| Ok(()))),
                    ..Default::default()
                };
                let state = test(data, mocks).await.unwrap();
                let expected = State {
                    finalizers: Some(vec![]),
                    ..Default::default()
                };
                assert_eq!(state, expected);
            }

            #[tokio::test]
            async fn unknown_deletion_checksum_changed() {
                let mut data = Data::default();
                add_annotation(ANNOT_CHECKSUM, format!("{}_old", data.checksum), &mut data);
                data.instance.metadata.deletion_timestamp = Some(Time(Utc::now()));
                data.instance.status = Some(DeployableStatus::Unknown);
                let mocks = Mocks {
                    undeploy: Some(mock_fn(&data, |_| Ok(()))),
                    ..Default::default()
                };
                let state = test(data, mocks).await.unwrap();
                let expected = State {
                    finalizers: Some(vec![]),
                    ..Default::default()
                };
                assert_eq!(state, expected);
            }

            #[tokio::test]
            async fn unknown_no_deletion_checksum_changed() {
                let mut data = Data::default();
                add_annotation(ANNOT_CHECKSUM, format!("{}_old", data.checksum), &mut data);
                data.instance.status = Some(DeployableStatus::Unknown);
                let mocks = Mocks {
                    deploy: Some(mock_fn(&data, |_| Ok(()))),
                    hash: true,
                    utc: true,
                    ..Default::default()
                };
                let state = test(data.clone(), mocks).await.unwrap();
                let expected = State {
                    annotations: Some(BTreeMap::from_iter([
                        (ANNOT_CHECKSUM.into(), data.checksum.into()),
                        (ANNOT_LAST_UPDATE.into(), data.now.to_rfc3339()),
                    ])),
                    event: Some(DeployableEvent::Deployed),
                    finalizers: Some(vec![FINALIZER.into()]),
                    should_requeue: true,
                    status: Some(DeployableStatus::Deploying),
                };
                assert_eq!(state, expected);
            }

            #[tokio::test]
            async fn unknown_no_deletion_checksum_unchanged_no_last_update_healthy() {
                let mut data = Data::default();
                add_annotation(ANNOT_CHECKSUM, data.checksum, &mut data);
                data.instance.status = Some(DeployableStatus::Unknown);
                let mocks = Mocks {
                    get_service: Some(mock_fn(&data, |data| Ok(Some(data.service)))),
                    hash: true,
                    monitor_deployable: Some(mock_fn(&data, |data| Ok(Some(data.stats)))),
                    utc: true,
                    ..Default::default()
                };
                let state = test(data.clone(), mocks).await.unwrap();
                let expected = State {
                    annotations: Some(BTreeMap::from_iter([
                        (ANNOT_CHECKSUM.into(), data.checksum.into()),
                        (
                            ANNOT_LAST_UPDATE.into(),
                            (data.now - Duration::seconds(data.service.spec.monitor_delay.into()))
                                .to_rfc3339(),
                        ),
                    ])),
                    finalizers: Some(vec![FINALIZER.into()]),
                    should_requeue: true,
                    status: Some(DeployableStatus::Healthy),
                    ..Default::default()
                };
                assert_eq!(state, expected);
            }

            #[tokio::test]
            async fn unknown_no_deletion_no_checksum() {
                let mut data = Data::default();
                data.instance.status = Some(DeployableStatus::Unknown);
                let mocks = Mocks {
                    deploy: Some(mock_fn(&data, |_| Ok(()))),
                    hash: true,
                    utc: true,
                    ..Default::default()
                };
                let state = test(data.clone(), mocks).await.unwrap();
                let expected = State {
                    annotations: Some(BTreeMap::from_iter([
                        (ANNOT_CHECKSUM.into(), data.checksum.into()),
                        (ANNOT_LAST_UPDATE.into(), data.now.to_rfc3339()),
                    ])),
                    event: Some(DeployableEvent::Deployed),
                    finalizers: Some(vec![FINALIZER.into()]),
                    should_requeue: true,
                    status: Some(DeployableStatus::Deploying),
                };
                assert_eq!(state, expected);
            }
        }
    }
}

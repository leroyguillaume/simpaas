use std::{future::Future, ops::Add, sync::Arc};

use k8s_openapi::api::apps::v1::{Deployment, DeploymentStatus, StatefulSet, StatefulSetStatus};
use simpaas_core::kube::KubeClient;
use tracing::instrument;

use crate::err::Result;

// AppStats

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AppStats {
    pub expected: i32,
    pub running: i32,
}

impl Add for AppStats {
    type Output = Self;

    fn add(self, stats: Self) -> Self::Output {
        Self {
            expected: self.expected + stats.expected,
            running: self.running + stats.running,
        }
    }
}

impl From<DeploymentStatus> for AppStats {
    fn from(status: DeploymentStatus) -> Self {
        Self {
            expected: status.replicas.unwrap_or_default(),
            running: status.ready_replicas.unwrap_or_default(),
        }
    }
}

impl From<StatefulSetStatus> for AppStats {
    fn from(status: StatefulSetStatus) -> Self {
        Self {
            expected: status.replicas,
            running: status.ready_replicas.unwrap_or_default(),
        }
    }
}

// Traits

#[cfg_attr(test, mockall::automock)]
pub trait Monitor: Send + Sync {
    fn monitor_apps(
        &self,
        ns: &str,
        sel: &str,
    ) -> impl Future<Output = Result<Option<AppStats>>> + Send;
}

// DefaultMonitor

pub struct DefaultMonitor<KUBE: KubeClient> {
    kube: Arc<KUBE>,
}

impl<KUBE: KubeClient> DefaultMonitor<KUBE> {
    pub fn new(kube: Arc<KUBE>) -> Self {
        Self { kube }
    }
}

impl<KUBE: KubeClient> Monitor for DefaultMonitor<KUBE> {
    #[instrument(skip(self, ns, sel), fields(resource.namespace = ns))]
    async fn monitor_apps(&self, ns: &str, sel: &str) -> Result<Option<AppStats>> {
        let dep_stats = self
            .kube
            .list_from::<Deployment>(ns, sel)
            .await?
            .into_iter()
            .filter_map(|dep| dep.status)
            .map(AppStats::from)
            .reduce(|acc, stats| acc + stats);
        let ss_stats = self
            .kube
            .list_from::<StatefulSet>(ns, sel)
            .await?
            .into_iter()
            .filter_map(|dep| dep.status)
            .map(AppStats::from)
            .reduce(|acc, stats| acc + stats);
        if let Some(dep_stats) = dep_stats {
            if let Some(ss_stats) = ss_stats {
                Ok(Some(dep_stats + ss_stats))
            } else {
                Ok(Some(dep_stats))
            }
        } else if let Some(ss_stats) = ss_stats {
            Ok(Some(ss_stats))
        } else {
            Ok(None)
        }
    }
}

// Tests

#[cfg(test)]
mod test {
    use mockall::predicate::*;
    use simpaas_core::kube::MockKubeClient;

    use crate::test::*;

    use super::*;

    // Mods

    mod default_monitor {
        use super::*;

        // Mods

        mod monitor_apps {
            use super::*;

            // Data

            #[derive(Clone)]
            struct Data {
                deployments: Vec<Deployment>,
                namespace: &'static str,
                selector: &'static str,
                staeful_sets: Vec<StatefulSet>,
            }

            impl Default for Data {
                fn default() -> Self {
                    Self {
                        deployments: vec![],
                        namespace: "namespace",
                        selector: "selector",
                        staeful_sets: vec![],
                    }
                }
            }

            // Tests

            async fn test(data: Data) -> Option<AppStats> {
                init_tracer();
                let mut kube = MockKubeClient::new();
                kube.expect_list_from::<Deployment>()
                    .with(eq(data.namespace), eq(data.selector))
                    .times(1)
                    .returning({
                        let deps = data.deployments.clone();
                        move |_, _| async_ok(deps.clone())
                    });
                kube.expect_list_from::<StatefulSet>()
                    .with(eq(data.namespace), eq(data.selector))
                    .times(1)
                    .returning({
                        let ss = data.staeful_sets.clone();
                        move |_, _| async_ok(ss.clone())
                    });
                let monitor = DefaultMonitor {
                    kube: Arc::new(kube),
                };
                monitor
                    .monitor_apps(data.namespace, data.selector)
                    .await
                    .unwrap()
            }

            #[tokio::test]
            async fn deployments_no_stateful_set() {
                let data = Data {
                    deployments: vec![
                        Deployment {
                            status: Some(DeploymentStatus {
                                replicas: Some(3),
                                ready_replicas: Some(1),
                                ..Default::default()
                            }),
                            ..Default::default()
                        },
                        Deployment {
                            status: Some(DeploymentStatus::default()),
                            ..Default::default()
                        },
                        Deployment {
                            status: Some(DeploymentStatus {
                                replicas: Some(4),
                                ready_replicas: Some(3),
                                ..Default::default()
                            }),
                            ..Default::default()
                        },
                        Deployment::default(),
                    ],
                    ..Default::default()
                };
                let stats = test(data).await.unwrap();
                let expected = AppStats {
                    expected: 7,
                    running: 4,
                };
                assert_eq!(stats, expected);
            }

            #[tokio::test]
            async fn deployments_stateful_sets() {
                let data = Data {
                    deployments: vec![
                        Deployment {
                            status: Some(DeploymentStatus {
                                ready_replicas: Some(1),
                                replicas: Some(3),
                                ..Default::default()
                            }),
                            ..Default::default()
                        },
                        Deployment {
                            status: Some(DeploymentStatus::default()),
                            ..Default::default()
                        },
                        Deployment {
                            status: Some(DeploymentStatus {
                                ready_replicas: Some(3),
                                replicas: Some(4),
                                ..Default::default()
                            }),
                            ..Default::default()
                        },
                        Deployment::default(),
                    ],
                    staeful_sets: vec![
                        StatefulSet {
                            status: Some(StatefulSetStatus {
                                ready_replicas: Some(1),
                                replicas: 5,
                                ..Default::default()
                            }),
                            ..Default::default()
                        },
                        StatefulSet::default(),
                        StatefulSet {
                            status: Some(StatefulSetStatus {
                                ready_replicas: Some(0),
                                replicas: 1,
                                ..Default::default()
                            }),
                            ..Default::default()
                        },
                        StatefulSet {
                            status: Some(StatefulSetStatus::default()),
                            ..Default::default()
                        },
                    ],
                    ..Default::default()
                };
                let stats = test(data).await.unwrap();
                let expected = AppStats {
                    expected: 13,
                    running: 5,
                };
                assert_eq!(stats, expected);
            }

            #[tokio::test]
            async fn no_deployment_no_stateful_set() {
                let data = Data::default();
                let stats = test(data).await;
                assert!(stats.is_none());
            }

            #[tokio::test]
            async fn no_deployment_stateful_sets() {
                let data = Data {
                    staeful_sets: vec![
                        StatefulSet {
                            status: Some(StatefulSetStatus {
                                ready_replicas: Some(1),
                                replicas: 5,
                                ..Default::default()
                            }),
                            ..Default::default()
                        },
                        StatefulSet::default(),
                        StatefulSet {
                            status: Some(StatefulSetStatus {
                                ready_replicas: Some(0),
                                replicas: 1,
                                ..Default::default()
                            }),
                            ..Default::default()
                        },
                        StatefulSet {
                            status: Some(StatefulSetStatus::default()),
                            ..Default::default()
                        },
                    ],
                    ..Default::default()
                };
                let stats = test(data).await.unwrap();
                let expected = AppStats {
                    expected: 6,
                    running: 1,
                };
                assert_eq!(stats, expected);
            }
        }
    }
}

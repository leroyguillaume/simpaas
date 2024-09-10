use std::sync::Arc;

use kube::Resource;
use simpaas_core::{kube::selector, Database, DatabaseStatus};
use tracing::{debug, instrument};

use crate::{
    db::DatabaseManager, monitor::Monitor, reconciler::FINALIZER, DatabaseEvent, JOB_KIND_CREATION,
    JOB_KIND_DELETION, LABEL_DATABASE, LABEL_JOB_KIND, LABEL_SERVICE_INSTANCE,
};

use super::Reconciler;

// Types

pub type Result<VALUE = ()> = super::Result<DatabaseEvent, DatabaseStatus, VALUE>;
pub type State = super::State<DatabaseEvent, DatabaseStatus>;

// Error

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub enum Error {
    Clean(#[source] crate::err::Error),
    Creation(#[source] crate::err::Error),
    Drop(#[source] crate::err::Error),
    Monitoring(#[source] crate::err::Error),
}

impl Error {
    pub fn clean_boxed(
        err: crate::err::Error,
    ) -> Box<dyn super::Error<DatabaseEvent, DatabaseStatus>> {
        Box::new(Self::Clean(err))
    }

    pub fn creation_boxed(
        err: crate::err::Error,
    ) -> Box<dyn super::Error<DatabaseEvent, DatabaseStatus>> {
        Box::new(Self::Creation(err))
    }

    pub fn drop_boxed(
        err: crate::err::Error,
    ) -> Box<dyn super::Error<DatabaseEvent, DatabaseStatus>> {
        Box::new(Self::Drop(err))
    }

    pub fn monitoring_boxed(
        err: crate::err::Error,
    ) -> Box<dyn super::Error<DatabaseEvent, DatabaseStatus>> {
        Box::new(Self::Monitoring(err))
    }
}

impl super::Error<DatabaseEvent, DatabaseStatus> for Error {
    fn state(self: Box<Self>) -> State {
        match *self {
            Self::Clean(_err) => State {
                finalizers: Some(vec![FINALIZER.into()]),
                should_requeue: true,
                status: Some(DatabaseStatus::Dropping),
                ..Default::default()
            },
            Self::Creation(err) => State {
                event: Some(DatabaseEvent::CreationFailed(err.to_string())),
                finalizers: Some(vec![FINALIZER.into()]),
                should_requeue: true,
                status: Some(DatabaseStatus::CreationFailed),
                ..Default::default()
            },
            Self::Monitoring(err) => State {
                event: Some(DatabaseEvent::MonitoringFailed(err.to_string())),
                finalizers: Some(vec![FINALIZER.into()]),
                should_requeue: true,
                ..Default::default()
            },
            Self::Drop(err) => State {
                event: Some(DatabaseEvent::DropFailed(err.to_string())),
                finalizers: Some(vec![FINALIZER.into()]),
                should_requeue: true,
                status: Some(DatabaseStatus::DropFailed),
                ..Default::default()
            },
        }
    }
}

// DatabaseReconciler

pub struct DatabaseReconciler<MANAGER: DatabaseManager, MONITOR: Monitor> {
    manager: MANAGER,
    monitor: Arc<MONITOR>,
}

impl<MANAGER: DatabaseManager, MONITOR: Monitor> DatabaseReconciler<MANAGER, MONITOR> {
    pub fn new(mgr: MANAGER, monitor: Arc<MONITOR>) -> Self {
        Self {
            manager: mgr,
            monitor,
        }
    }
}

impl<MANAGER: DatabaseManager, MONITOR: Monitor> Reconciler<DatabaseEvent, Database, DatabaseStatus>
    for DatabaseReconciler<MANAGER, MONITOR>
{
    #[instrument(skip(self, ns, name, db), fields(resource.api_version = %Database::api_version(&()), resource.kind = %Database::kind(&()), resource.name = name, resource.namespace = ns))]
    async fn reconcile(&self, ns: &str, name: &str, db: &Database) -> Result<State> {
        if db.metadata.deletion_timestamp.is_some() {
            match db.status {
                Some(DatabaseStatus::Dropping) => {
                    let sel = selector(&[
                        (LABEL_DATABASE, name),
                        (LABEL_JOB_KIND, JOB_KIND_DELETION),
                        (LABEL_SERVICE_INSTANCE, &db.spec.instance),
                    ]);
                    let stats = self
                        .monitor
                        .monitor_jobs(ns, &sel)
                        .await
                        .map_err(Error::monitoring_boxed)?;
                    if let Some(stats) = stats {
                        if stats.succeeded == 0 || stats.succeeded < stats.expected {
                            Ok(State {
                                finalizers: Some(vec![FINALIZER.into()]),
                                should_requeue: true,
                                ..Default::default()
                            })
                        } else {
                            self.manager
                                .clean(ns, name, db)
                                .await
                                .map_err(Error::clean_boxed)?;
                            Ok(State {
                                finalizers: Some(vec![]),
                                ..Default::default()
                            })
                        }
                    } else {
                        debug!("no stats to dertermine job status");
                        Ok(State {
                            finalizers: Some(vec![FINALIZER.into()]),
                            should_requeue: true,
                            status: Some(DatabaseStatus::Unknown),
                            ..Default::default()
                        })
                    }
                }
                _ => {
                    self.manager
                        .start_drop_job(ns, name, db)
                        .await
                        .map_err(Error::drop_boxed)?;
                    Ok(State {
                        finalizers: Some(vec![FINALIZER.into()]),
                        should_requeue: true,
                        status: Some(DatabaseStatus::Dropping),
                        ..Default::default()
                    })
                }
            }
        } else {
            match db.status {
                None | Some(DatabaseStatus::CreationFailed) => {
                    self.manager
                        .start_creation_job(ns, name, db)
                        .await
                        .map_err(Error::creation_boxed)?;
                    Ok(State {
                        finalizers: Some(vec![FINALIZER.into()]),
                        should_requeue: true,
                        status: Some(DatabaseStatus::Creating),
                        ..Default::default()
                    })
                }
                Some(DatabaseStatus::Created) => Ok(State {
                    finalizers: Some(vec![FINALIZER.into()]),
                    ..Default::default()
                }),
                _ => {
                    let sel = selector(&[
                        (LABEL_DATABASE, name),
                        (LABEL_JOB_KIND, JOB_KIND_CREATION),
                        (LABEL_SERVICE_INSTANCE, &db.spec.instance),
                    ]);
                    let stats = self
                        .monitor
                        .monitor_jobs(ns, &sel)
                        .await
                        .map_err(Error::monitoring_boxed)?;
                    if let Some(stats) = stats {
                        if stats.succeeded == 0 || stats.succeeded < stats.expected {
                            Ok(State {
                                finalizers: Some(vec![FINALIZER.into()]),
                                should_requeue: true,
                                ..Default::default()
                            })
                        } else {
                            Ok(State {
                                event: Some(DatabaseEvent::Created),
                                finalizers: Some(vec![FINALIZER.into()]),
                                status: Some(DatabaseStatus::Created),
                                ..Default::default()
                            })
                        }
                    } else {
                        debug!("no stats to dertermine job status");
                        Ok(State {
                            finalizers: Some(vec![FINALIZER.into()]),
                            should_requeue: true,
                            status: Some(DatabaseStatus::Unknown),
                            ..Default::default()
                        })
                    }
                }
            }
        }
    }
}

// Tests

#[cfg(test)]
mod test {
    use chrono::Utc;
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::Time;
    use kube::api::ObjectMeta;
    use mockall::predicate::*;
    use simpaas_core::DatabaseSpec;

    use crate::{
        db::MockDatabaseManager,
        monitor::{JobStats, MockMonitor},
        test::*,
    };

    use super::*;

    // Mods

    mod database_reconciler {
        use super::*;

        // Mods

        mod reconcile {
            use super::*;

            // Data

            #[derive(Clone)]
            struct Data {
                database: Database,
                name: &'static str,
                namespace: &'static str,
                stats: JobStats,
            }

            impl Default for Data {
                fn default() -> Self {
                    let name = "name";
                    let ns = "namespace";
                    Self {
                        database: Database {
                            metadata: ObjectMeta {
                                name: Some(name.into()),
                                namespace: Some(ns.into()),
                                ..Default::default()
                            },
                            spec: DatabaseSpec {
                                database: "database".into(),
                                instance: "instance".into(),
                                user: "user".into(),
                            },
                            status: None,
                        },
                        name,
                        namespace: ns,
                        stats: JobStats {
                            expected: 1,
                            succeeded: 2,
                        },
                    }
                }
            }

            // Mocks

            #[derive(Default)]
            struct Mocks {
                clean: Option<MockFn<crate::err::Result>>,
                monitor_creation_job: Option<MockFn<crate::err::Result<Option<JobStats>>>>,
                monitor_drop_job: Option<MockFn<crate::err::Result<Option<JobStats>>>>,
                start_creation_job: Option<MockFn<crate::err::Result>>,
                start_drop_job: Option<MockFn<crate::err::Result>>,
            }

            // Tests

            async fn test(data: Data, mocks: Mocks) -> Result<State> {
                init_tracer();
                let mut mgr = MockDatabaseManager::new();
                mgr.expect_clean()
                    .with(
                        eq(data.namespace),
                        eq(data.name),
                        eq_database(&data.database),
                    )
                    .times(mocks.clean.is_some() as usize)
                    .returning({
                        let clean = mocks.clean.clone();
                        move |_, _, _| call_mock_fn_opt_async(&clean)
                    });
                mgr.expect_start_creation_job()
                    .with(
                        eq(data.namespace),
                        eq(data.name),
                        eq_database(&data.database),
                    )
                    .times(mocks.start_creation_job.is_some() as usize)
                    .returning({
                        let start = mocks.start_creation_job.clone();
                        move |_, _, _| call_mock_fn_opt_async(&start)
                    });
                mgr.expect_start_drop_job()
                    .with(
                        eq(data.namespace),
                        eq(data.name),
                        eq_database(&data.database),
                    )
                    .times(mocks.start_drop_job.is_some() as usize)
                    .returning({
                        let drop = mocks.start_drop_job.clone();
                        move |_, _, _| call_mock_fn_opt_async(&drop)
                    });
                let mut monitor = MockMonitor::new();
                let sel = selector(&[
                    (LABEL_DATABASE, data.name),
                    (LABEL_JOB_KIND, JOB_KIND_DELETION),
                    (LABEL_SERVICE_INSTANCE, &data.database.spec.instance),
                ]);
                monitor
                    .expect_monitor_jobs()
                    .with(eq(data.namespace), eq(sel))
                    .times(mocks.monitor_drop_job.is_some() as usize)
                    .returning({
                        let monitor = mocks.monitor_drop_job.clone();
                        move |_, _| call_mock_fn_opt_async(&monitor)
                    });
                let sel = selector(&[
                    (LABEL_DATABASE, data.name),
                    (LABEL_JOB_KIND, JOB_KIND_CREATION),
                    (LABEL_SERVICE_INSTANCE, &data.database.spec.instance),
                ]);
                monitor
                    .expect_monitor_jobs()
                    .with(eq(data.namespace), eq(sel))
                    .times(mocks.monitor_creation_job.is_some() as usize)
                    .returning({
                        let monitor = mocks.monitor_creation_job.clone();
                        move |_, _| call_mock_fn_opt_async(&monitor)
                    });
                let reconciler = DatabaseReconciler {
                    manager: mgr,
                    monitor: Arc::new(monitor),
                };
                reconciler
                    .reconcile(data.namespace, data.name, &data.database)
                    .await
            }

            #[tokio::test]
            async fn clean_err() {
                let mut data = Data::default();
                data.database.metadata.deletion_timestamp = Some(Time(Utc::now()));
                data.database.status = Some(DatabaseStatus::Dropping);
                let mocks = Mocks {
                    clean: Some(mock_fn(&data, |_| Err(crate::err::Error::CommandFailed))),
                    monitor_drop_job: Some(mock_fn(&data, |data| Ok(Some(data.stats)))),
                    ..Default::default()
                };
                let state = test(data, mocks).await.unwrap_err().state();
                let expected = State {
                    finalizers: Some(vec![FINALIZER.into()]),
                    should_requeue: true,
                    status: Some(DatabaseStatus::Dropping),
                    ..Default::default()
                };
                assert_eq!(state, expected);
            }

            #[tokio::test]
            async fn created_deletion() {
                let mut data = Data::default();
                data.database.metadata.deletion_timestamp = Some(Time(Utc::now()));
                data.database.status = Some(DatabaseStatus::Created);
                let mocks = Mocks {
                    start_drop_job: Some(mock_fn(&data, |_| Ok(()))),
                    ..Default::default()
                };
                let state = test(data, mocks).await.unwrap();
                let expected = State {
                    finalizers: Some(vec![FINALIZER.into()]),
                    should_requeue: true,
                    status: Some(DatabaseStatus::Dropping),
                    ..Default::default()
                };
                assert_eq!(state, expected);
            }

            #[tokio::test]
            async fn created_no_deletion() {
                let mut data = Data::default();
                data.database.status = Some(DatabaseStatus::Created);
                let mocks = Mocks::default();
                let state = test(data, mocks).await.unwrap();
                let expected = State {
                    finalizers: Some(vec![FINALIZER.into()]),
                    ..Default::default()
                };
                assert_eq!(state, expected);
            }

            #[tokio::test]
            async fn creating_deletion() {
                let mut data = Data::default();
                data.database.metadata.deletion_timestamp = Some(Time(Utc::now()));
                data.database.status = Some(DatabaseStatus::Creating);
                let mocks = Mocks {
                    start_drop_job: Some(mock_fn(&data, |_| Ok(()))),
                    ..Default::default()
                };
                let state = test(data, mocks).await.unwrap();
                let expected = State {
                    finalizers: Some(vec![FINALIZER.into()]),
                    should_requeue: true,
                    status: Some(DatabaseStatus::Dropping),
                    ..Default::default()
                };
                assert_eq!(state, expected);
            }

            #[tokio::test]
            async fn creating_no_deletion_running() {
                let mut data = Data {
                    stats: JobStats {
                        expected: 1,
                        succeeded: 0,
                    },
                    ..Default::default()
                };
                data.database.status = Some(DatabaseStatus::Creating);
                let mocks = Mocks {
                    monitor_creation_job: Some(mock_fn(&data, |data| Ok(Some(data.stats)))),
                    ..Default::default()
                };
                let state = test(data, mocks).await.unwrap();
                let expected = State {
                    finalizers: Some(vec![FINALIZER.into()]),
                    should_requeue: true,
                    ..Default::default()
                };
                assert_eq!(state, expected);
            }

            #[tokio::test]
            async fn creating_no_deletion_succeeded() {
                let mut data = Data::default();
                data.database.status = Some(DatabaseStatus::Creating);
                let mocks = Mocks {
                    monitor_creation_job: Some(mock_fn(&data, |data| Ok(Some(data.stats)))),
                    ..Default::default()
                };
                let state = test(data, mocks).await.unwrap();
                let expected = State {
                    event: Some(DatabaseEvent::Created),
                    finalizers: Some(vec![FINALIZER.into()]),
                    status: Some(DatabaseStatus::Created),
                    ..Default::default()
                };
                assert_eq!(state, expected);
            }

            #[tokio::test]
            async fn creating_no_deletion_unknown() {
                let mut data = Data::default();
                data.database.status = Some(DatabaseStatus::Creating);
                let mocks = Mocks {
                    monitor_creation_job: Some(mock_fn(&data, |_| Ok(None))),
                    ..Default::default()
                };
                let state = test(data, mocks).await.unwrap();
                let expected = State {
                    finalizers: Some(vec![FINALIZER.into()]),
                    should_requeue: true,
                    status: Some(DatabaseStatus::Unknown),
                    ..Default::default()
                };
                assert_eq!(state, expected);
            }

            #[tokio::test]
            async fn creation_failed_deletion() {
                let mut data = Data::default();
                data.database.metadata.deletion_timestamp = Some(Time(Utc::now()));
                data.database.status = Some(DatabaseStatus::CreationFailed);
                let mocks = Mocks {
                    start_drop_job: Some(mock_fn(&data, |_| Ok(()))),
                    ..Default::default()
                };
                let state = test(data, mocks).await.unwrap();
                let expected = State {
                    finalizers: Some(vec![FINALIZER.into()]),
                    should_requeue: true,
                    status: Some(DatabaseStatus::Dropping),
                    ..Default::default()
                };
                assert_eq!(state, expected);
            }

            #[tokio::test]
            async fn creation_failed_no_deletion() {
                let mut data = Data::default();
                data.database.status = Some(DatabaseStatus::CreationFailed);
                let mocks = Mocks {
                    start_creation_job: Some(mock_fn(&data, |_| Ok(()))),
                    ..Default::default()
                };
                let state = test(data, mocks).await.unwrap();
                let expected = State {
                    finalizers: Some(vec![FINALIZER.into()]),
                    should_requeue: true,
                    status: Some(DatabaseStatus::Creating),
                    ..Default::default()
                };
                assert_eq!(state, expected);
            }

            #[tokio::test]
            async fn drop_failed_deletion() {
                let mut data = Data::default();
                data.database.metadata.deletion_timestamp = Some(Time(Utc::now()));
                data.database.status = Some(DatabaseStatus::DropFailed);
                let mocks = Mocks {
                    start_drop_job: Some(mock_fn(&data, |_| Ok(()))),
                    ..Default::default()
                };
                let state = test(data, mocks).await.unwrap();
                let expected = State {
                    finalizers: Some(vec![FINALIZER.into()]),
                    should_requeue: true,
                    status: Some(DatabaseStatus::Dropping),
                    ..Default::default()
                };
                assert_eq!(state, expected);
            }

            #[tokio::test]
            async fn dropping_deletion_running() {
                let mut data = Data {
                    stats: JobStats {
                        expected: 1,
                        succeeded: 0,
                    },
                    ..Default::default()
                };
                data.database.metadata.deletion_timestamp = Some(Time(Utc::now()));
                data.database.status = Some(DatabaseStatus::Dropping);
                let mocks = Mocks {
                    monitor_drop_job: Some(mock_fn(&data, |data| Ok(Some(data.stats)))),
                    ..Default::default()
                };
                let state = test(data, mocks).await.unwrap();
                let expected = State {
                    finalizers: Some(vec![FINALIZER.into()]),
                    should_requeue: true,
                    ..Default::default()
                };
                assert_eq!(state, expected);
            }

            #[tokio::test]
            async fn dropping_deletion_succeeded() {
                let mut data = Data::default();
                data.database.metadata.deletion_timestamp = Some(Time(Utc::now()));
                data.database.status = Some(DatabaseStatus::Dropping);
                let mocks = Mocks {
                    clean: Some(mock_fn(&data, |_| Ok(()))),
                    monitor_drop_job: Some(mock_fn(&data, |data| Ok(Some(data.stats)))),
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
            async fn dropping_deletion_unknown() {
                let mut data = Data::default();
                data.database.metadata.deletion_timestamp = Some(Time(Utc::now()));
                data.database.status = Some(DatabaseStatus::Dropping);
                let mocks = Mocks {
                    monitor_drop_job: Some(mock_fn(&data, |_| Ok(None))),
                    ..Default::default()
                };
                let state = test(data, mocks).await.unwrap();
                let expected = State {
                    finalizers: Some(vec![FINALIZER.into()]),
                    should_requeue: true,
                    status: Some(DatabaseStatus::Unknown),
                    ..Default::default()
                };
                assert_eq!(state, expected);
            }

            #[tokio::test]
            async fn monitor_creation_job_err() {
                let mut data = Data::default();
                data.database.status = Some(DatabaseStatus::Creating);
                let mocks = Mocks {
                    monitor_creation_job: Some(mock_fn(&data, |_| {
                        Err(crate::err::Error::ServiceNotFound)
                    })),
                    ..Default::default()
                };
                let state = test(data, mocks).await.unwrap_err().state();
                let err = crate::err::Error::ServiceNotFound.to_string();
                let expected = State {
                    event: Some(DatabaseEvent::MonitoringFailed(err)),
                    finalizers: Some(vec![FINALIZER.into()]),
                    should_requeue: true,
                    ..Default::default()
                };
                assert_eq!(state, expected);
            }

            #[tokio::test]
            async fn monitor_drop_job_err() {
                let mut data = Data::default();
                data.database.metadata.deletion_timestamp = Some(Time(Utc::now()));
                data.database.status = Some(DatabaseStatus::Dropping);
                let mocks = Mocks {
                    monitor_drop_job: Some(mock_fn(&data, |_| {
                        Err(crate::err::Error::ServiceNotFound)
                    })),
                    ..Default::default()
                };
                let state = test(data, mocks).await.unwrap_err().state();
                let err = crate::err::Error::ServiceNotFound.to_string();
                let expected = State {
                    event: Some(DatabaseEvent::MonitoringFailed(err)),
                    finalizers: Some(vec![FINALIZER.into()]),
                    should_requeue: true,
                    ..Default::default()
                };
                assert_eq!(state, expected);
            }

            #[tokio::test]
            async fn no_status_deletion() {
                let mut data = Data::default();
                data.database.metadata.deletion_timestamp = Some(Time(Utc::now()));
                let mocks = Mocks {
                    start_drop_job: Some(mock_fn(&data, |_| Ok(()))),
                    ..Default::default()
                };
                let state = test(data, mocks).await.unwrap();
                let expected = State {
                    finalizers: Some(vec![FINALIZER.into()]),
                    should_requeue: true,
                    status: Some(DatabaseStatus::Dropping),
                    ..Default::default()
                };
                assert_eq!(state, expected);
            }

            #[tokio::test]
            async fn no_status_no_deletion() {
                let data = Data::default();
                let mocks = Mocks {
                    start_creation_job: Some(mock_fn(&data, |_| Ok(()))),
                    ..Default::default()
                };
                let state = test(data, mocks).await.unwrap();
                let expected = State {
                    finalizers: Some(vec![FINALIZER.into()]),
                    should_requeue: true,
                    status: Some(DatabaseStatus::Creating),
                    ..Default::default()
                };
                assert_eq!(state, expected);
            }

            #[tokio::test]
            async fn start_creation_job_err() {
                let data = Data::default();
                let mocks = Mocks {
                    start_creation_job: Some(mock_fn(&data, |_| {
                        Err(crate::err::Error::ServiceNotFound)
                    })),
                    ..Default::default()
                };
                let state = test(data, mocks).await.unwrap_err().state();
                let err = crate::err::Error::ServiceNotFound.to_string();
                let expected = State {
                    event: Some(DatabaseEvent::CreationFailed(err)),
                    finalizers: Some(vec![FINALIZER.into()]),
                    should_requeue: true,
                    status: Some(DatabaseStatus::CreationFailed),
                    ..Default::default()
                };
                assert_eq!(state, expected);
            }

            #[tokio::test]
            async fn start_drop_job_err() {
                let mut data = Data::default();
                data.database.metadata.deletion_timestamp = Some(Time(Utc::now()));
                let mocks = Mocks {
                    start_drop_job: Some(mock_fn(&data, |_| {
                        Err(crate::err::Error::ServiceNotFound)
                    })),
                    ..Default::default()
                };
                let state = test(data, mocks).await.unwrap_err().state();
                let err = crate::err::Error::ServiceNotFound.to_string();
                let expected = State {
                    event: Some(DatabaseEvent::DropFailed(err)),
                    finalizers: Some(vec![FINALIZER.into()]),
                    should_requeue: true,
                    status: Some(DatabaseStatus::DropFailed),
                    ..Default::default()
                };
                assert_eq!(state, expected);
            }

            #[tokio::test]
            async fn unknown_deletion() {
                let mut data = Data::default();
                data.database.metadata.deletion_timestamp = Some(Time(Utc::now()));
                data.database.status = Some(DatabaseStatus::Unknown);
                let mocks = Mocks {
                    start_drop_job: Some(mock_fn(&data, |_| Ok(()))),
                    ..Default::default()
                };
                let state = test(data, mocks).await.unwrap();
                let expected = State {
                    finalizers: Some(vec![FINALIZER.into()]),
                    should_requeue: true,
                    status: Some(DatabaseStatus::Dropping),
                    ..Default::default()
                };
                assert_eq!(state, expected);
            }

            #[tokio::test]
            async fn unknown_no_deletion_succeeded() {
                let mut data = Data::default();
                data.database.status = Some(DatabaseStatus::Unknown);
                let mocks = Mocks {
                    monitor_creation_job: Some(mock_fn(&data, |data| Ok(Some(data.stats)))),
                    ..Default::default()
                };
                let state = test(data, mocks).await.unwrap();
                let expected = State {
                    event: Some(DatabaseEvent::Created),
                    finalizers: Some(vec![FINALIZER.into()]),
                    status: Some(DatabaseStatus::Created),
                    ..Default::default()
                };
                assert_eq!(state, expected);
            }
        }
    }
}

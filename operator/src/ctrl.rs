use std::{future::Future, marker::PhantomData, sync::Arc, time::Duration};

use futures::StreamExt;
use kube::{
    api::ObjectMeta,
    runtime::{controller::Action, Controller},
    Api, Result,
};
use simpaas_core::kube::KubeClient;
use tokio::sync::broadcast::Receiver;
use tracing::{debug, error, warn};

use crate::{
    err::Error, reconciler::Reconciler, ReconcilableResource, ReconcilableResourceEvent, Status,
};

// Context

struct Context<
    EVENT: ReconcilableResourceEvent,
    KUBE: KubeClient,
    RECONCILER: Reconciler<EVENT, RESOURCE, STATUS>,
    RESOURCE: ReconcilableResource<STATUS>,
    STATUS: Status,
> {
    kube: Arc<KUBE>,
    reconciler: RECONCILER,
    requeue_delay: Duration,
    _event: PhantomData<EVENT>,
    _resource: PhantomData<RESOURCE>,
    _status: PhantomData<STATUS>,
}

// Functions

pub fn controller<
    EVENT: ReconcilableResourceEvent + 'static,
    KUBE: KubeClient + 'static,
    RECONCILER: Reconciler<EVENT, RESOURCE, STATUS> + 'static,
    RESOURCE: ReconcilableResource<STATUS> + 'static,
    STATUS: Status + 'static,
>(
    requeue_delay: Duration,
    api: Api<RESOURCE>,
    kube: Arc<KUBE>,
    reconciler: RECONCILER,
    mut stop_rx: Receiver<()>,
) -> impl Future<Output = ()> {
    let ctx = Arc::new(Context {
        kube,
        reconciler,
        requeue_delay,
        _event: PhantomData,
        _resource: PhantomData,
        _status: PhantomData,
    });
    Controller::new(api, Default::default())
        .graceful_shutdown_on(async move {
            stop_rx.recv().await.ok();
            debug!("controller stopped");
        })
        .run(reconcile, on_error, ctx)
        .for_each(|_| async {})
}

fn on_error<
    EVENT: ReconcilableResourceEvent,
    KUBE: KubeClient,
    RECONCILER: Reconciler<EVENT, RESOURCE, STATUS>,
    RESOURCE: ReconcilableResource<STATUS> + 'static,
    STATUS: Status + 'static,
>(
    _res: Arc<RESOURCE>,
    err: &kube::Error,
    ctx: Arc<Context<EVENT, KUBE, RECONCILER, RESOURCE, STATUS>>,
) -> Action {
    let should_requeue = if let kube::Error::Service(err) = err {
        if let Some(err) = err.downcast_ref::<Error>() {
            match err {
                Error::UnnamedResource | Error::UnnamespacedResource => {
                    warn!("{err}");
                    false
                }
                _ => {
                    error!("{err}");
                    true
                }
            }
        } else {
            error!("{err}");
            true
        }
    } else {
        error!("{err}");
        true
    };
    if should_requeue {
        Action::requeue(ctx.requeue_delay)
    } else {
        Action::await_change()
    }
}

async fn reconcile<
    EVENT: ReconcilableResourceEvent,
    KUBE: KubeClient,
    RECONCILER: Reconciler<EVENT, RESOURCE, STATUS>,
    RESOURCE: ReconcilableResource<STATUS> + 'static,
    STATUS: Status + 'static,
>(
    res: Arc<RESOURCE>,
    ctx: Arc<Context<EVENT, KUBE, RECONCILER, RESOURCE, STATUS>>,
) -> Result<Action> {
    let meta = res.meta();
    let name = meta.name.as_ref().ok_or(Error::UnnamedResource)?;
    let ns = meta.namespace.as_ref().ok_or(Error::UnnamespacedResource)?;
    let state = ctx
        .reconciler
        .reconcile(ns, name, &res)
        .await
        .unwrap_or_else(|err| {
            error!("{err}");
            err.state()
        });
    let meta = ObjectMeta {
        annotations: state.annotations,
        finalizers: state.finalizers,
        managed_fields: None,
        ..meta.clone()
    };
    ctx.kube
        .patch_metadata_from::<RESOURCE>(ns, name, meta)
        .await?;
    if let Some(status) = &state.status {
        ctx.kube
            .patch_status_from::<RESOURCE, _>(ns, name, status)
            .await?;
    }
    if let Some(evt) = state.event {
        ctx.kube.publish_event(evt.into(), res.as_ref()).await?;
    }
    if state.should_requeue {
        Ok(Action::requeue(ctx.requeue_delay))
    } else {
        Ok(Action::await_change())
    }
}

// kube::Error

impl From<Error> for kube::Error {
    fn from(err: Error) -> Self {
        Self::Service(Box::new(err))
    }
}

// Tests

#[cfg(test)]
mod test {
    use std::collections::BTreeMap;

    use mockall::predicate::*;
    use simpaas_core::{
        kube::MockKubeClient, DeployableStatus, ServiceInstance, ServiceInstanceSpec,
    };

    use crate::{
        reconciler::{dep::State, MockReconciler},
        test::*,
        DeployableEvent,
    };

    use super::*;

    // Mods

    mod on_error {
        use super::*;

        // Data

        struct Data {
            error: kube::Error,
            instance: ServiceInstance,
            requeue_delay: Duration,
        }

        impl Default for Data {
            fn default() -> Self {
                Self {
                    error: kube::Error::TlsRequired,
                    instance: ServiceInstance {
                        metadata: ObjectMeta {
                            name: Some("name".into()),
                            namespace: Some("ns".into()),
                            ..Default::default()
                        },
                        spec: ServiceInstanceSpec {
                            service: "service".into(),
                            values: Default::default(),
                        },
                        status: None,
                    },
                    requeue_delay: Duration::from_secs(30),
                }
            }
        }

        // Tests

        fn test(data: Data) -> Action {
            let ctx = Arc::new(Context {
                kube: Arc::new(MockKubeClient::new()),
                reconciler: MockReconciler::new(),
                requeue_delay: data.requeue_delay,
                _event: PhantomData::<DeployableEvent>,
                _resource: PhantomData,
                _status: PhantomData,
            });
            on_error(Arc::new(data.instance), &data.error, ctx)
        }

        #[test]
        fn unnamed_resource() {
            let data = Data {
                error: kube::Error::Service(Box::new(Error::UnnamedResource)),
                ..Default::default()
            };
            let action = test(data);
            assert_eq!(action, Action::await_change());
        }

        #[test]
        fn unnamespaced_resource() {
            let data = Data {
                error: kube::Error::Service(Box::new(Error::UnnamespacedResource)),
                ..Default::default()
            };
            let action = test(data);
            assert_eq!(action, Action::await_change());
        }
    }

    mod reconcile {
        use super::*;

        // Macros

        macro_rules! assert_error {
            ($err:expr, $expected:pat) => {
                match $err {
                    kube::Error::Service(err) => {
                        let err = err.downcast::<Error>().unwrap();
                        assert!(matches!(*err, $expected));
                    }
                    err => panic!("{err}"),
                }
            };
        }

        // Data

        #[derive(Clone)]
        struct Data {
            event: DeployableEvent,
            instance: ServiceInstance,
            name: &'static str,
            namespace: &'static str,
            requeue_delay: Duration,
            state: State,
            status: DeployableStatus,
        }

        impl Default for Data {
            fn default() -> Self {
                let evt = DeployableEvent::Deployed;
                let name = "instance";
                let ns = "namespace";
                let status = DeployableStatus::Healthy;
                Self {
                    event: evt.clone(),
                    instance: ServiceInstance {
                        metadata: ObjectMeta {
                            name: Some(name.into()),
                            namespace: Some(ns.into()),
                            ..Default::default()
                        },
                        spec: ServiceInstanceSpec {
                            service: "service".into(),
                            values: Default::default(),
                        },
                        status: None,
                    },
                    name,
                    namespace: ns,
                    requeue_delay: Duration::from_secs(30),
                    state: State {
                        annotations: Some(BTreeMap::from_iter([("foo".into(), "bar".into())])),
                        event: Some(evt),
                        finalizers: Some(vec!["finalizer".into()]),
                        should_requeue: false,
                        status: Some(status),
                    },
                    status,
                }
            }
        }

        // Mocks

        #[derive(Default)]
        struct Mocks {
            patch_metadata_from: bool,
            patch_status_from: bool,
            publish_event: bool,
            reconcile: Option<MockFn<crate::reconciler::dep::Result<State>>>,
        }

        // Tests

        async fn test(data: Data, mocks: Mocks) -> Result<Action> {
            init_tracer();
            let mut reconciler = MockReconciler::new();
            reconciler
                .expect_reconcile()
                .with(
                    eq(data.namespace),
                    eq(data.name),
                    eq_service_instance(&data.instance),
                )
                .times(mocks.reconcile.is_some() as usize)
                .returning({
                    let reconcile = mocks.reconcile.clone();
                    move |_, _, _| call_mock_fn_opt_async(&reconcile)
                });
            let mut kube = MockKubeClient::new();
            let meta = ObjectMeta {
                annotations: data.state.annotations.clone(),
                finalizers: data.state.finalizers.clone(),
                managed_fields: None,
                ..data.instance.metadata.clone()
            };
            kube.expect_patch_metadata_from::<ServiceInstance>()
                .with(eq(data.namespace), eq(data.name), eq(meta))
                .times(mocks.patch_metadata_from as usize)
                .returning(|_, _, _| async_ok(()));
            kube.expect_patch_status_from::<ServiceInstance, _>()
                .with(eq(data.namespace), eq(data.name), eq(data.status))
                .times(mocks.patch_status_from as usize)
                .returning(|_, _, _| async_ok(()));
            kube.expect_publish_event()
                .with(eq_event(&data.event), eq_service_instance(&data.instance))
                .times(mocks.publish_event as usize)
                .returning(|_, _| async_ok(()));
            let ctx = Arc::new(Context {
                kube: Arc::new(kube),
                reconciler,
                requeue_delay: data.requeue_delay,
                _event: PhantomData::<DeployableEvent>,
                _resource: PhantomData,
                _status: PhantomData,
            });
            reconcile(Arc::new(data.instance), ctx).await
        }

        #[tokio::test]
        async fn err() {
            let mut data = Data::default();
            data.state.event = None;
            data.state.status = None;
            let mocks = Mocks {
                patch_metadata_from: true,
                reconcile: Some(mock_fn(&data, |data| {
                    Err(crate::reconciler::MockError::new_boxed(data.state))
                })),
                ..Default::default()
            };
            let action = test(data, mocks).await.unwrap();
            assert_eq!(action, Action::await_change());
        }

        #[tokio::test]
        async fn err_status_event() {
            let data = Data::default();
            let mocks = Mocks {
                patch_metadata_from: true,
                patch_status_from: true,
                publish_event: true,
                reconcile: Some(mock_fn(&data, |data| {
                    Err(crate::reconciler::MockError::new_boxed(data.state))
                })),
            };
            let action = test(data, mocks).await.unwrap();
            assert_eq!(action, Action::await_change());
        }

        #[tokio::test]
        async fn err_status_event_requeue() {
            let mut data = Data::default();
            data.state.should_requeue = true;
            let mocks = Mocks {
                patch_metadata_from: true,
                patch_status_from: true,
                publish_event: true,
                reconcile: Some(mock_fn(&data, |data| {
                    Err(crate::reconciler::MockError::new_boxed(data.state))
                })),
            };
            let action = test(data.clone(), mocks).await.unwrap();
            assert_eq!(action, Action::requeue(data.requeue_delay));
        }

        #[tokio::test]
        async fn ok() {
            let mut data = Data::default();
            data.state.event = None;
            data.state.status = None;
            let mocks = Mocks {
                patch_metadata_from: true,
                reconcile: Some(mock_fn(&data, |data| Ok(data.state))),
                ..Default::default()
            };
            let action = test(data, mocks).await.unwrap();
            assert_eq!(action, Action::await_change());
        }

        #[tokio::test]
        async fn ok_status_event() {
            let data = Data::default();
            let mocks = Mocks {
                patch_metadata_from: true,
                patch_status_from: true,
                publish_event: true,
                reconcile: Some(mock_fn(&data, |data| Ok(data.state))),
            };
            let action = test(data, mocks).await.unwrap();
            assert_eq!(action, Action::await_change());
        }

        #[tokio::test]
        async fn ok_status_event_requeue() {
            let mut data = Data::default();
            data.state.should_requeue = true;
            let mocks = Mocks {
                patch_metadata_from: true,
                patch_status_from: true,
                publish_event: true,
                reconcile: Some(mock_fn(&data, |data| Ok(data.state))),
            };
            let action = test(data.clone(), mocks).await.unwrap();
            assert_eq!(action, Action::requeue(data.requeue_delay));
        }

        #[tokio::test]
        async fn unnamed_resource() {
            let mut data = Data::default();
            data.instance.metadata.name = None;
            let mocks = Mocks::default();
            let err = test(data, mocks).await.unwrap_err();
            assert_error!(err, Error::UnnamedResource);
        }

        #[tokio::test]
        async fn unnamespaced_resource() {
            let mut data = Data::default();
            data.instance.metadata.namespace = None;
            let mocks = Mocks::default();
            let err = test(data, mocks).await.unwrap_err();
            assert_error!(err, Error::UnnamespacedResource);
        }
    }
}

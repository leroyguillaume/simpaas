use std::{collections::BTreeMap, future::Future, sync::Arc};

use k8s_openapi::api::{batch::v1::Job, core::v1::Secret};
use kube::{api::ObjectMeta, Resource};
use serde::{Deserialize, Serialize};
use simpaas_core::{
    kube::{selector, KubeClient},
    Database, SecretRef, Selector, Service, ServiceInstance,
};
use tracing::{debug, info, instrument, warn};

use crate::{
    err::{Error, Result},
    pwd::{DefaultPasswordGenerator, PasswordGenerator},
    renderer::Renderer,
    LABEL_DATABASE,
};

// Traits

#[cfg_attr(test, mockall::automock)]
pub trait DatabaseManager: Send + Sync {
    fn clean(&self, ns: &str, name: &str, db: &Database) -> impl Future<Output = Result> + Send;

    fn start_creation_job(
        &self,
        ns: &str,
        name: &str,
        db: &Database,
    ) -> impl Future<Output = Result> + Send;

    fn start_drop_job(
        &self,
        ns: &str,
        name: &str,
        db: &Database,
    ) -> impl Future<Output = Result> + Send;
}

// DefaultDatabaseManager

pub struct DefaultDatabaseManager<
    KUBE: KubeClient,
    PASSWORDGENERATOR: PasswordGenerator,
    RENDERER: Renderer,
> {
    domain: String,
    kube: Arc<KUBE>,
    password_generator: PASSWORDGENERATOR,
    renderer: Arc<RENDERER>,
}

impl<KUBE: KubeClient, RENDERER: Renderer>
    DefaultDatabaseManager<KUBE, DefaultPasswordGenerator, RENDERER>
{
    pub fn new(domain: String, kube: Arc<KUBE>, renderer: Arc<RENDERER>) -> Self {
        Self {
            domain,
            kube,
            password_generator: DefaultPasswordGenerator::new(),
            renderer,
        }
    }
}

impl<KUBE: KubeClient, PASSWORDGENERATOR: PasswordGenerator, RENDERER: Renderer>
    DefaultDatabaseManager<KUBE, PASSWORDGENERATOR, RENDERER>
{
    async fn delete_secrets(&self, ns: &str, sel: &str) -> Result {
        let secs = self.kube.list_from::<Secret>(ns, sel).await?;
        for sec in secs {
            if let Some(name) = sec.metadata.name {
                self.kube.delete_from::<Secret>(ns, &name).await?;
            } else {
                warn!("secret is unnamed");
            }
        }
        Ok(())
    }
}

impl<KUBE: KubeClient, PASSWORDGENERATOR: PasswordGenerator, RENDERER: Renderer> DatabaseManager
    for DefaultDatabaseManager<KUBE, PASSWORDGENERATOR, RENDERER>
{
    #[instrument(skip(self, ns, name, db), fields(resource.api_version = %Database::api_version(&()), resource.kind = %Database::kind(&()), resource.name = name, resource.namespace = ns))]
    async fn clean(&self, ns: &str, name: &str, db: &Database) -> Result {
        let sel = selector(&[(LABEL_DATABASE, name)]);
        let jobs = self
            .kube
            .list_from::<Job>(&db.spec.instance.namespace, &sel)
            .await?;
        for job in jobs {
            if let Some(name) = job.metadata.name {
                self.kube
                    .delete_from::<Job>(&db.spec.instance.namespace, &name)
                    .await?;
            } else {
                warn!("job is unnamed");
            }
        }
        self.delete_secrets(&db.spec.instance.namespace, &sel)
            .await?;
        self.delete_secrets(ns, &sel).await?;
        Ok(())
    }

    #[instrument(skip(self, ns, name, db), fields(resource.api_version = %Database::api_version(&()), resource.kind = %Database::kind(&()), resource.name = name, resource.namespace = ns))]
    async fn start_creation_job(&self, ns: &str, name: &str, db: &Database) -> Result {
        let svc_inst = self
            .kube
            .get_from::<ServiceInstance>(&db.spec.instance.namespace, &db.spec.instance.name)
            .await?
            .ok_or(Error::ServiceInstanceNotFound)?;
        let svc = self
            .kube
            .get::<Service>(&svc_inst.spec.service)
            .await?
            .ok_or(Error::ServiceNotFound)?;
        let cons = svc
            .spec
            .consumes
            .database
            .ok_or(Error::ResourceNotConsumed)?;
        debug!("creating credentials secret");
        let mut vars = Variables {
            database: db.spec.database.clone(),
            domain: self.domain.clone(),
            instance: db.spec.instance.clone(),
            name: name.into(),
            namespace: ns.into(),
            password_secret: None,
            service: svc_inst.spec.service.clone(),
            user: db.spec.user.clone(),
        };
        let mut sec_name = vec![];
        self.renderer
            .render(&cons.password_secret.name, &vars, &mut sec_name)?;
        let sec_name = String::from_utf8(sec_name)?;
        let mut sec = Secret {
            metadata: ObjectMeta {
                labels: Some(BTreeMap::from_iter([(LABEL_DATABASE.into(), name.into())])),
                name: Some(sec_name.clone()),
                namespace: Some(ns.into()),
                ..Default::default()
            },
            string_data: Some(BTreeMap::from_iter([(
                cons.password_secret.key.clone(),
                self.password_generator.generate(),
            )])),
            ..Default::default()
        };
        self.kube.patch_from(ns, &sec_name, &sec).await?;
        sec.metadata.namespace = Some(db.spec.instance.namespace.clone());
        self.kube
            .patch_from(&db.spec.instance.namespace, &sec_name, &sec)
            .await?;
        debug!("creating creation job");
        vars.password_secret = Some(SecretRef {
            key: cons.password_secret.key,
            name: sec_name,
        });
        let mut yaml = vec![];
        self.renderer.render(&cons.creation_job, &vars, &mut yaml)?;
        let job: Job = serde_yaml::from_slice(&yaml)?;
        let job_name = job.metadata.name.as_ref().ok_or(Error::UnnamedJob)?;
        self.kube
            .patch_from(&db.spec.instance.namespace, job_name, &job)
            .await?;
        info!("creation job started");
        Ok(())
    }

    #[instrument(skip(self, ns, name, db), fields(resource.api_version = %Database::api_version(&()), resource.kind = %Database::kind(&()), resource.name = name, resource.namespace = ns))]
    async fn start_drop_job(&self, ns: &str, name: &str, db: &Database) -> Result {
        let svc_inst = self
            .kube
            .get_from::<ServiceInstance>(&db.spec.instance.namespace, &db.spec.instance.name)
            .await?
            .ok_or(Error::ServiceInstanceNotFound)?;
        let svc = self
            .kube
            .get::<Service>(&svc_inst.spec.service)
            .await?
            .ok_or(Error::ServiceNotFound)?;
        let cons = svc
            .spec
            .consumes
            .database
            .ok_or(Error::ResourceNotConsumed)?;
        let mut vars = Variables {
            database: db.spec.database.clone(),
            domain: self.domain.clone(),
            instance: db.spec.instance.clone(),
            name: name.into(),
            namespace: ns.into(),
            password_secret: None,
            service: svc_inst.spec.service,
            user: db.spec.user.clone(),
        };
        let mut sec_name = vec![];
        self.renderer
            .render(&cons.password_secret.name, &vars, &mut sec_name)?;
        let sec_name = String::from_utf8(sec_name)?;
        debug!("creating drop job");
        vars.password_secret = Some(SecretRef {
            key: cons.password_secret.key,
            name: sec_name,
        });
        let mut yaml = vec![];
        self.renderer.render(&cons.drop_job, &vars, &mut yaml)?;
        let job: Job = serde_yaml::from_slice(&yaml)?;
        let job_name = job.metadata.name.as_ref().ok_or(Error::UnnamedJob)?;
        self.kube
            .patch_from(&db.spec.instance.namespace, job_name, &job)
            .await?;
        info!("drop job started");
        Ok(())
    }
}

// Variables

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct Variables {
    database: String,
    domain: String,
    instance: Selector,
    name: String,
    namespace: String,
    password_secret: Option<SecretRef>,
    service: String,
    user: String,
}

// Tests

#[cfg(test)]
mod test {
    use mockall::predicate::*;
    use simpaas_core::{
        kube::MockKubeClient, Chart, DatabaseConsumable, DatabaseSpec, ServiceConsumable,
        ServiceInstanceSpec, ServiceSpec,
    };

    use crate::{pwd::MockPasswordGenerator, renderer::MockRenderer, test::*};

    use super::*;

    // Mods

    mod default_database_manager {
        use super::*;

        // Mods

        mod clean {
            use super::*;

            // Data

            #[derive(Clone)]
            struct Data {
                database: Database,
                domain: &'static str,
                jobs: Vec<Job>,
                job_name: &'static str,
                name: &'static str,
                namespace: &'static str,
                secrets: Vec<Secret>,
                secret_name: &'static str,
            }

            impl Default for Data {
                fn default() -> Self {
                    let name = "name";
                    let ns = "namespace";
                    let sec_name = "secret_name";
                    let job_name = "job";
                    Self {
                        database: Database {
                            metadata: ObjectMeta {
                                name: Some(name.into()),
                                namespace: Some(ns.into()),
                                ..Default::default()
                            },
                            spec: DatabaseSpec {
                                database: "database".into(),
                                instance: Selector {
                                    name: "instance".into(),
                                    namespace: "instance_namespace".into(),
                                },
                                user: "user".into(),
                            },
                            status: None,
                        },
                        domain: "domain",
                        job_name,
                        jobs: vec![
                            Job::default(),
                            Job {
                                metadata: ObjectMeta {
                                    name: Some(job_name.into()),
                                    namespace: Some(ns.into()),
                                    ..Default::default()
                                },
                                ..Default::default()
                            },
                        ],
                        name,
                        namespace: ns,
                        secret_name: sec_name,
                        secrets: vec![
                            Secret::default(),
                            Secret {
                                metadata: ObjectMeta {
                                    name: Some(sec_name.into()),
                                    namespace: Some(ns.into()),
                                    ..Default::default()
                                },
                                ..Default::default()
                            },
                        ],
                    }
                }
            }

            // Tests

            #[tokio::test]
            async fn test() {
                init_tracer();
                let data = Data::default();
                let mut kube = MockKubeClient::new();
                let sel = selector(&[(LABEL_DATABASE, data.name)]);
                kube.expect_delete_from::<Job>()
                    .with(
                        eq(data.database.spec.instance.namespace.clone()),
                        eq(data.job_name),
                    )
                    .times(1)
                    .returning(|_, _| async_ok(()));
                kube.expect_delete_from::<Secret>()
                    .with(eq(data.namespace), eq(data.secret_name))
                    .times(1)
                    .returning(|_, _| async_ok(()));
                kube.expect_delete_from::<Secret>()
                    .with(
                        eq(data.database.spec.instance.namespace.clone()),
                        eq(data.secret_name),
                    )
                    .times(1)
                    .returning(|_, _| async_ok(()));
                kube.expect_list_from()
                    .with(
                        eq(data.database.spec.instance.namespace.clone()),
                        eq(sel.clone()),
                    )
                    .times(1)
                    .returning({
                        let jobs = data.jobs.clone();
                        move |_, _| async_ok(jobs.clone())
                    });
                kube.expect_list_from()
                    .with(eq(data.namespace), eq(sel.clone()))
                    .times(1)
                    .returning({
                        let secs = data.secrets.clone();
                        move |_, _| async_ok(secs.clone())
                    });
                kube.expect_list_from()
                    .with(eq(data.database.spec.instance.namespace.clone()), eq(sel))
                    .times(1)
                    .returning({
                        let secs = data.secrets.clone();
                        move |_, _| async_ok(secs.clone())
                    });
                let mgr = DefaultDatabaseManager {
                    domain: data.domain.into(),
                    kube: Arc::new(kube),
                    password_generator: MockPasswordGenerator::new(),
                    renderer: Arc::new(MockRenderer::new()),
                };
                mgr.clean(data.namespace, data.name, &data.database)
                    .await
                    .unwrap();
            }
        }

        mod start_creation_job {
            use super::*;

            // Data

            #[derive(Clone)]
            struct Data {
                consumable: DatabaseConsumable,
                database: Database,
                domain: &'static str,
                instance: ServiceInstance,
                job: Job,
                job_name: &'static str,
                name: &'static str,
                namespace: &'static str,
                password: &'static str,
                secret: Secret,
                secret_name: &'static str,
                service: Service,
            }

            impl Default for Data {
                fn default() -> Self {
                    let name = "name";
                    let ns = "namespace";
                    let svc_inst_name = "instance";
                    let svc_name = "service";
                    let sec_name = "secret_name";
                    let sec_key = "secret_key";
                    let pwd = "password";
                    let job_name = "job";
                    let consumable = DatabaseConsumable {
                        creation_job: "creation_job".into(),
                        drop_job: "drop_job".into(),
                        host: "host".into(),
                        password_secret: SecretRef {
                            name: "password_secret_name".into(),
                            key: sec_name.into(),
                        },
                        port: 5432,
                    };
                    Self {
                        consumable: consumable.clone(),
                        database: Database {
                            metadata: ObjectMeta {
                                name: Some(name.into()),
                                namespace: Some(ns.into()),
                                ..Default::default()
                            },
                            spec: DatabaseSpec {
                                database: "database".into(),
                                instance: Selector {
                                    name: svc_inst_name.into(),
                                    namespace: "instance_namespace".into(),
                                },
                                user: "user".into(),
                            },
                            status: None,
                        },
                        domain: "domain",
                        instance: ServiceInstance {
                            metadata: ObjectMeta {
                                name: Some(svc_inst_name.into()),
                                namespace: Some(ns.into()),
                                ..Default::default()
                            },
                            spec: ServiceInstanceSpec {
                                values: Default::default(),
                                service: svc_name.into(),
                            },
                            status: None,
                        },
                        job: Job {
                            metadata: ObjectMeta {
                                name: Some(job_name.into()),
                                ..Default::default()
                            },
                            ..Default::default()
                        },
                        job_name,
                        name,
                        namespace: ns,
                        password: pwd,
                        secret: Secret {
                            metadata: ObjectMeta {
                                labels: Some(BTreeMap::from_iter([(
                                    LABEL_DATABASE.into(),
                                    name.into(),
                                )])),
                                name: Some(sec_name.into()),
                                namespace: Some(ns.into()),
                                ..Default::default()
                            },
                            string_data: Some(BTreeMap::from_iter([(sec_key.into(), pwd.into())])),
                            ..Default::default()
                        },
                        secret_name: sec_name,
                        service: Service {
                            metadata: ObjectMeta {
                                name: Some(svc_name.into()),
                                ..Default::default()
                            },
                            spec: ServiceSpec {
                                chart: Chart {
                                    name: "chart".into(),
                                    values: "values".into(),
                                    version: None,
                                },
                                consumes: ServiceConsumable {
                                    database: Some(consumable),
                                },
                                monitor_delay: 30,
                            },
                        },
                    }
                }
            }

            // Mocks

            #[derive(Default)]
            struct Mocks {
                generate_password: bool,
                get_service: Option<MockFn<kube::Result<Option<Service>>>>,
                instance: Option<ServiceInstance>,
                patch_job: bool,
                patch_secret: bool,
                render_secret_name: bool,
                render_job: bool,
            }

            // Tests

            async fn test(data: Data, mocks: Mocks) -> Result {
                init_tracer();
                let mut kube = MockKubeClient::new();
                kube.expect_get_from::<ServiceInstance>()
                    .with(
                        eq(data.database.spec.instance.namespace.clone()),
                        eq(data.database.spec.instance.name.clone()),
                    )
                    .times(1)
                    .returning({
                        let inst = mocks.instance.clone();
                        move |_, _| async_ok(inst.clone())
                    });
                kube.expect_get()
                    .with(eq(data.instance.spec.service.clone()))
                    .times(mocks.get_service.is_some() as usize)
                    .returning({
                        let get_svc = mocks.get_service.clone();
                        move |_| call_mock_fn_opt_async(&get_svc)
                    });
                kube.expect_patch_from()
                    .with(
                        eq(data.namespace),
                        eq(data.secret_name),
                        eq_secret(&data.secret),
                    )
                    .times(mocks.patch_secret as usize)
                    .returning(|_, _, _| async_ok(()));
                let mut secret = data.secret.clone();
                secret.metadata.namespace = Some(data.database.spec.instance.namespace.clone());
                kube.expect_patch_from()
                    .with(
                        eq(data.database.spec.instance.namespace.clone()),
                        eq(data.secret_name),
                        eq_secret(&secret),
                    )
                    .times(mocks.patch_secret as usize)
                    .returning(|_, _, _| async_ok(()));
                kube.expect_patch_from()
                    .with(
                        eq(data.database.spec.instance.namespace.clone()),
                        eq(data.job_name),
                        eq_job(&data.job),
                    )
                    .times(mocks.patch_job as usize)
                    .returning(|_, _, _| async_ok(()));
                let mut pwd_gen = MockPasswordGenerator::new();
                pwd_gen
                    .expect_generate()
                    .times(mocks.generate_password as usize)
                    .returning(|| data.password.into());
                let mut renderer = MockRenderer::new();
                let vars = Variables {
                    database: data.database.spec.database.clone(),
                    domain: data.domain.into(),
                    instance: data.database.spec.instance.clone(),
                    name: data.name.into(),
                    namespace: data.namespace.into(),
                    password_secret: None,
                    service: data.instance.spec.service.clone(),
                    user: data.database.spec.user.clone(),
                };
                renderer
                    .expect_render()
                    .with(
                        eq(data.consumable.password_secret.name.clone()),
                        eq(vars.clone()),
                        always(),
                    )
                    .times(mocks.render_secret_name as usize)
                    .returning(|_, _, out: &mut Vec<u8>| {
                        *out = data.secret_name.as_bytes().to_vec();
                        Ok(())
                    });
                let vars = Variables {
                    password_secret: Some(SecretRef {
                        key: data.consumable.password_secret.key.clone(),
                        name: data.secret_name.into(),
                    }),
                    ..vars
                };
                renderer
                    .expect_render()
                    .with(eq(data.consumable.creation_job.clone()), eq(vars), always())
                    .times(mocks.render_job as usize)
                    .returning({
                        let job = data.job.clone();
                        move |_, _, out: &mut Vec<u8>| {
                            serde_yaml::to_writer(out, &job).unwrap();
                            Ok(())
                        }
                    });
                let mgr = DefaultDatabaseManager {
                    kube: Arc::new(kube),
                    domain: data.domain.into(),
                    password_generator: pwd_gen,
                    renderer: Arc::new(renderer),
                };
                mgr.start_creation_job(data.namespace, data.name, &data.database)
                    .await
            }

            #[tokio::test]
            async fn resource_not_consumed() {
                let mut data = Data::default();
                data.service.spec.consumes.database = None;
                let mocks = Mocks {
                    get_service: Some(mock_fn(&data, |data: Data| Ok(Some(data.service.clone())))),
                    instance: Some(data.instance.clone()),
                    ..Default::default()
                };
                let err = test(data, mocks).await.unwrap_err();
                assert!(matches!(err, Error::ResourceNotConsumed));
            }

            #[tokio::test]
            async fn service_instance_not_found() {
                let data = Data::default();
                let mocks = Mocks::default();
                let err = test(data, mocks).await.unwrap_err();
                assert!(matches!(err, Error::ServiceInstanceNotFound));
            }

            #[tokio::test]
            async fn service_not_found() {
                let data = Data::default();
                let mocks = Mocks {
                    get_service: Some(mock_fn(&data, |_| Ok(None))),
                    instance: Some(data.instance.clone()),
                    ..Default::default()
                };
                let err = test(data, mocks).await.unwrap_err();
                assert!(matches!(err, Error::ServiceNotFound));
            }

            #[tokio::test]
            async fn ok() {
                let data = Data::default();
                let mocks = Mocks {
                    generate_password: true,
                    get_service: Some(mock_fn(&data, |data: Data| Ok(Some(data.service.clone())))),
                    instance: Some(data.instance.clone()),
                    patch_job: true,
                    patch_secret: true,
                    render_job: true,
                    render_secret_name: true,
                };
                test(data, mocks).await.unwrap();
            }

            #[tokio::test]
            async fn unnamed_job() {
                let mut data = Data::default();
                data.job.metadata.name = None;
                let mocks = Mocks {
                    generate_password: true,
                    get_service: Some(mock_fn(&data, |data: Data| Ok(Some(data.service.clone())))),
                    instance: Some(data.instance.clone()),
                    patch_secret: true,
                    render_job: true,
                    render_secret_name: true,
                    ..Default::default()
                };
                let err = test(data, mocks).await.unwrap_err();
                assert!(matches!(err, Error::UnnamedJob));
            }
        }

        mod start_drop_job {
            use super::*;

            // Data

            #[derive(Clone)]
            struct Data {
                consumable: DatabaseConsumable,
                database: Database,
                domain: &'static str,
                instance: ServiceInstance,
                job: Job,
                job_name: &'static str,
                name: &'static str,
                namespace: &'static str,
                secret_name: &'static str,
                service: Service,
            }

            impl Default for Data {
                fn default() -> Self {
                    let name = "name";
                    let ns = "namespace";
                    let svc_inst_name = "instance";
                    let svc_name = "service";
                    let sec_name = "secret_name";
                    let job_name = "job";
                    let consumable = DatabaseConsumable {
                        creation_job: "creation_job".into(),
                        drop_job: "drop_job".into(),
                        host: "host".into(),
                        password_secret: SecretRef {
                            name: "password_secret_name".into(),
                            key: sec_name.into(),
                        },
                        port: 5432,
                    };
                    Self {
                        consumable: consumable.clone(),
                        database: Database {
                            metadata: ObjectMeta {
                                name: Some(name.into()),
                                namespace: Some(ns.into()),
                                ..Default::default()
                            },
                            spec: DatabaseSpec {
                                database: "database".into(),
                                instance: Selector {
                                    name: svc_inst_name.into(),
                                    namespace: "instance_namespace".into(),
                                },
                                user: "user".into(),
                            },
                            status: None,
                        },
                        domain: "domain",
                        instance: ServiceInstance {
                            metadata: ObjectMeta {
                                name: Some(svc_inst_name.into()),
                                namespace: Some(ns.into()),
                                ..Default::default()
                            },
                            spec: ServiceInstanceSpec {
                                values: Default::default(),
                                service: svc_name.into(),
                            },
                            status: None,
                        },
                        job: Job {
                            metadata: ObjectMeta {
                                name: Some(job_name.into()),
                                ..Default::default()
                            },
                            ..Default::default()
                        },
                        job_name,
                        name,
                        namespace: ns,
                        secret_name: sec_name,
                        service: Service {
                            metadata: ObjectMeta {
                                name: Some(svc_name.into()),
                                ..Default::default()
                            },
                            spec: ServiceSpec {
                                chart: Chart {
                                    name: "chart".into(),
                                    values: "values".into(),
                                    version: None,
                                },
                                consumes: ServiceConsumable {
                                    database: Some(consumable),
                                },
                                monitor_delay: 30,
                            },
                        },
                    }
                }
            }

            // Mocks

            #[derive(Default)]
            struct Mocks {
                get_service: Option<MockFn<kube::Result<Option<Service>>>>,
                instance: Option<ServiceInstance>,
                patch_job: bool,
                render_secret_name: bool,
                render_job: bool,
            }

            // Tests

            async fn test(data: Data, mocks: Mocks) -> Result {
                init_tracer();
                let mut kube = MockKubeClient::new();
                kube.expect_get_from::<ServiceInstance>()
                    .with(
                        eq(data.database.spec.instance.namespace.clone()),
                        eq(data.database.spec.instance.name.clone()),
                    )
                    .times(1)
                    .returning({
                        let inst = mocks.instance.clone();
                        move |_, _| async_ok(inst.clone())
                    });
                kube.expect_get()
                    .with(eq(data.instance.spec.service.clone()))
                    .times(mocks.get_service.is_some() as usize)
                    .returning({
                        let get_svc = mocks.get_service.clone();
                        move |_| call_mock_fn_opt_async(&get_svc)
                    });
                kube.expect_patch_from()
                    .with(
                        eq(data.database.spec.instance.namespace.clone()),
                        eq(data.job_name),
                        eq_job(&data.job),
                    )
                    .times(mocks.patch_job as usize)
                    .returning(|_, _, _| async_ok(()));
                let mut renderer = MockRenderer::new();
                let vars = Variables {
                    database: data.database.spec.database.clone(),
                    domain: data.domain.into(),
                    instance: data.database.spec.instance.clone(),
                    name: data.name.into(),
                    namespace: data.namespace.into(),
                    password_secret: None,
                    service: data.instance.spec.service.clone(),
                    user: data.database.spec.user.clone(),
                };
                renderer
                    .expect_render()
                    .with(
                        eq(data.consumable.password_secret.name.clone()),
                        eq(vars.clone()),
                        always(),
                    )
                    .times(mocks.render_secret_name as usize)
                    .returning(|_, _, out: &mut Vec<u8>| {
                        *out = data.secret_name.as_bytes().to_vec();
                        Ok(())
                    });
                let vars = Variables {
                    password_secret: Some(SecretRef {
                        key: data.consumable.password_secret.key.clone(),
                        name: data.secret_name.into(),
                    }),
                    ..vars
                };
                renderer
                    .expect_render()
                    .with(eq(data.consumable.drop_job.clone()), eq(vars), always())
                    .times(mocks.render_job as usize)
                    .returning({
                        let job = data.job.clone();
                        move |_, _, out: &mut Vec<u8>| {
                            serde_yaml::to_writer(out, &job).unwrap();
                            Ok(())
                        }
                    });
                let mgr = DefaultDatabaseManager {
                    kube: Arc::new(kube),
                    domain: data.domain.into(),
                    password_generator: MockPasswordGenerator::new(),
                    renderer: Arc::new(renderer),
                };
                mgr.start_drop_job(data.namespace, data.name, &data.database)
                    .await
            }

            #[tokio::test]
            async fn resource_not_consumed() {
                let mut data = Data::default();
                data.service.spec.consumes.database = None;
                let mocks = Mocks {
                    get_service: Some(mock_fn(&data, |data: Data| Ok(Some(data.service.clone())))),
                    instance: Some(data.instance.clone()),
                    ..Default::default()
                };
                let err = test(data, mocks).await.unwrap_err();
                assert!(matches!(err, Error::ResourceNotConsumed));
            }

            #[tokio::test]
            async fn service_instance_not_found() {
                let data = Data::default();
                let mocks = Mocks::default();
                let err = test(data, mocks).await.unwrap_err();
                assert!(matches!(err, Error::ServiceInstanceNotFound));
            }

            #[tokio::test]
            async fn service_not_found() {
                let data = Data::default();
                let mocks = Mocks {
                    get_service: Some(mock_fn(&data, |_| Ok(None))),
                    instance: Some(data.instance.clone()),
                    ..Default::default()
                };
                let err = test(data, mocks).await.unwrap_err();
                assert!(matches!(err, Error::ServiceNotFound));
            }

            #[tokio::test]
            async fn ok() {
                let data = Data::default();
                let mocks = Mocks {
                    get_service: Some(mock_fn(&data, |data: Data| Ok(Some(data.service.clone())))),
                    instance: Some(data.instance.clone()),
                    patch_job: true,
                    render_job: true,
                    render_secret_name: true,
                };
                test(data, mocks).await.unwrap();
            }

            #[tokio::test]
            async fn unnamed_job() {
                let mut data = Data::default();
                data.job.metadata.name = None;
                let mocks = Mocks {
                    get_service: Some(mock_fn(&data, |data: Data| Ok(Some(data.service.clone())))),
                    instance: Some(data.instance.clone()),
                    render_job: true,
                    render_secret_name: true,
                    ..Default::default()
                };
                let err = test(data, mocks).await.unwrap_err();
                assert!(matches!(err, Error::UnnamedJob));
            }
        }
    }
}

use std::{borrow::Cow, collections::BTreeMap, sync::Arc};

use kube::Resource;
use serde::Serialize;
use serde_json::json;
use simpaas_core::{
    kube::KubeClient, renderer::Renderer, Application, Chart, Database,
    DatabaseConnectionInfoVariables, Exposition, SecretRef, Service, ServiceInstance,
};
use tempfile::NamedTempFile;
use tracing::{debug, info, instrument};

use crate::{
    err::{Error, Result},
    helm::HelmRunner,
};

use super::Deployer;

// ApplicationDeployer

pub struct ApplicationDeployer<HELM: HelmRunner, KUBE: KubeClient, RENDERER: Renderer> {
    chart: Chart,
    domain: String,
    helm: Arc<HELM>,
    kube: Arc<KUBE>,
    renderer: Arc<RENDERER>,
}

impl<HELM: HelmRunner, KUBE: KubeClient, RENDERER: Renderer>
    ApplicationDeployer<HELM, KUBE, RENDERER>
{
    pub fn new(
        domain: String,
        chart: Chart,
        helm: Arc<HELM>,
        kube: Arc<KUBE>,
        renderer: Arc<RENDERER>,
    ) -> Self {
        Self {
            chart,
            domain,
            helm,
            kube,
            renderer,
        }
    }
}

impl<HELM: HelmRunner, KUBE: KubeClient, RENDERER: Renderer> Deployer<Application>
    for ApplicationDeployer<HELM, KUBE, RENDERER>
{
    #[instrument(skip(self, ns, name, app), fields(resource.api_version = %Application::api_version(&()), resource.kind = %Application::kind(&()), resource.name = name))]
    async fn deploy(&self, ns: &str, name: &str, app: &Application) -> Result {
        debug!("rendering variables into temporary file");
        let mut file = NamedTempFile::new()?;
        let mut cmpts = vec![];
        let mut ing_rules: BTreeMap<&String, IngressRuleVariable<'_>> = BTreeMap::new();
        let mut svcs = vec![];
        for cont in &app.spec.containers {
            let mut env = vec![];
            let mut secs = vec![];
            for db_ref in &cont.databases {
                let db: Database = self
                    .kube
                    .get_from(ns, &db_ref.name)
                    .await?
                    .ok_or(Error::DatabaseNotFound)?;
                let svc_inst: ServiceInstance = self
                    .kube
                    .get_from(&db.spec.instance.namespace, &db.spec.instance.name)
                    .await?
                    .ok_or(Error::ServiceInstanceNotFound)?;
                let svc: Service = self
                    .kube
                    .get(&svc_inst.spec.service)
                    .await?
                    .ok_or(Error::ServiceNotFound)?;
                let cons = svc
                    .spec
                    .consumes
                    .database
                    .ok_or(Error::DatabaseNotConsumed)?;
                let conn_info_vars = DatabaseConnectionInfoVariables {
                    database: &db.spec.database,
                    domain: &self.domain,
                    instance: &db.spec.instance,
                    name: &db_ref.name,
                    namespace: ns,
                    user: &db.spec.user,
                };
                let conn_info = cons.connection_info(&conn_info_vars, self.renderer.as_ref())?;
                env.extend_from_slice(&[
                    EnvironmentVariable {
                        key: Cow::Borrowed(&db_ref.mapping.host),
                        value: conn_info.host,
                    },
                    EnvironmentVariable {
                        key: Cow::Borrowed(&db_ref.mapping.name),
                        value: conn_info.database.into_owned(),
                    },
                    EnvironmentVariable {
                        key: Cow::Borrowed(&db_ref.mapping.port),
                        value: conn_info.port.to_string(),
                    },
                    EnvironmentVariable {
                        key: Cow::Borrowed(&db_ref.mapping.user),
                        value: conn_info.user.into_owned(),
                    },
                ]);
                secs.push(SecretVariable {
                    key: Cow::Borrowed(&db_ref.mapping.password),
                    secret: conn_info.password_secret,
                });
            }
            if !cont.exposes.is_empty() {
                for exp in &cont.exposes {
                    if let Some(ing) = &exp.ingress {
                        let ing_rule_path = IngressRulePathVariable {
                            port: exp.port,
                            service: &cont.name,
                            value: &ing.path,
                        };
                        if let Some(ing_rule) = ing_rules.get_mut(&ing.domain) {
                            ing_rule.paths.push(ing_rule_path);
                        } else {
                            ing_rules.insert(
                                &ing.domain,
                                IngressRuleVariable {
                                    domain: &ing.domain,
                                    paths: vec![ing_rule_path],
                                },
                            );
                        }
                    }
                }
                svcs.push(ServiceVariable {
                    exposes: Cow::Borrowed(&cont.exposes),
                    name: &cont.name,
                });
            };
            cmpts.push(ComponentVariable {
                environment: env,
                exposes: Cow::Borrowed(&cont.exposes),
                image: ImageVariable {
                    repository: &cont.image,
                    tag: &cont.tag,
                },
                name: &cont.name,
                secrets: secs,
            });
        }
        let ing_rules: Vec<_> = ing_rules.into_values().collect();
        let vars = json!({
            "components": cmpts,
            "ingressRules": ing_rules,
            "name": name,
            "services": svcs,
            "tlsDomains": app.spec.tls_domains,
        });
        self.renderer.render(&self.chart.values, &vars, &mut file)?;
        self.helm
            .upgrade(
                ns,
                name,
                &self.chart.name,
                file.path(),
                self.chart.version.as_deref(),
            )
            .await?;
        info!("application deployed");
        Ok(())
    }

    #[instrument(skip(self, ns, name, _app), fields(resource.api_version = %Application::api_version(&()), resource.kind = %Application::kind(&()), resource.name = name))]
    async fn undeploy(&self, ns: &str, name: &str, _app: &Application) -> Result {
        self.helm.uninstall(ns, name).await?;
        info!("application undeployed");
        Ok(())
    }
}

// Variables

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct ComponentVariable<'a> {
    environment: Vec<EnvironmentVariable<'a>>,
    exposes: Cow<'a, Vec<Exposition>>,
    image: ImageVariable<'a>,
    name: &'a str,
    secrets: Vec<SecretVariable<'a>>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct EnvironmentVariable<'a> {
    key: Cow<'a, str>,
    value: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct ImageVariable<'a> {
    repository: &'a str,
    tag: &'a str,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct IngressRulePathVariable<'a> {
    port: u16,
    service: &'a str,
    value: &'a str,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct IngressRuleVariable<'a> {
    domain: &'a str,
    paths: Vec<IngressRulePathVariable<'a>>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct SecretVariable<'a> {
    key: Cow<'a, str>,
    secret: SecretRef,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct ServiceVariable<'a> {
    exposes: Cow<'a, Vec<Exposition>>,
    name: &'a str,
}

// Tests

#[cfg(test)]
mod test {
    use simpaas_core::{
        kube::MockKubeClient, renderer::MockRenderer, ApplicationSpec, Container,
        DatabaseConsumable, DatabaseRef, DatabaseSpec, Ingress, Selector, ServiceConsumable,
        ServiceInstanceSpec, ServiceSpec,
    };
    use std::{path::PathBuf, sync::Mutex};

    use kube::api::ObjectMeta;
    use mockall::predicate::*;

    use crate::{helm::MockHelmRunner, test::*};

    use super::*;

    // Mods

    mod application_deployer {
        use super::*;

        mod deploy {
            use super::*;

            // Data

            #[derive(Clone)]
            struct Data {
                application: Application,
                chart: Chart,
                components: Vec<ComponentVariable<'static>>,
                database: Database,
                database_consumable: DatabaseConsumable,
                database_host: &'static str,
                database_instance: ServiceInstance,
                database_ref: DatabaseRef,
                database_secret_name: &'static str,
                database_service: Service,
                domain: &'static str,
                ingress_rules: Vec<IngressRuleVariable<'static>>,
                name: &'static str,
                namespace: &'static str,
                services: Vec<ServiceVariable<'static>>,
            }

            impl Default for Data {
                fn default() -> Self {
                    let name = "name";
                    let ns = "namespace";
                    let db_name = "database";
                    let db_inst_name = "database_instance";
                    let db_inst_namespace = "database_instance_namespace";
                    let db_svc_name = "database_service";
                    let db_host = "host";
                    let db_sec_name = "password_secret_name_template";
                    let db_db = "data_base";
                    let db_user = "user";
                    let db_cons = DatabaseConsumable {
                        creation_job: "creation_job".into(),
                        drop_job: "dop_job".into(),
                        host: "host_template".into(),
                        password_secret: SecretRef {
                            key: "password_secret_key".into(),
                            name: "password_secret_name_template".into(),
                        },
                        port: 5432,
                    };
                    let db_ref = DatabaseRef {
                        mapping: Default::default(),
                        name: db_name.into(),
                    };
                    let domain_1 = "container_domain_1";
                    let domain_2 = "container_domain_2";
                    let cont_1_name = "container_1_name";
                    let cont_1_exposes = vec![];
                    let cont_1_image = "container_1_image";
                    let cont_1_tag = "container_1_tag";
                    let cont_2_name = "container_2_name";
                    let cont_2_port_1 = 2;
                    let cont_2_exposes = vec![Exposition {
                        ingress: None,
                        port: cont_2_port_1,
                    }];
                    let cont_2_image = "container_2_image";
                    let cont_2_tag = "container_2_tag";
                    let cont_3_name = "container_3_name";
                    let cont_3_port_1 = 31;
                    let cont_3_port_2 = 32;
                    let cont_3_port_3 = 33;
                    let cont_3_port_2_path = "container_3_port_2_path";
                    let cont_3_port_3_path = "container_3_port_3_path";
                    let cont_3_exposes = vec![
                        Exposition {
                            ingress: None,
                            port: cont_3_port_1,
                        },
                        Exposition {
                            ingress: Some(Ingress {
                                domain: domain_1.into(),
                                path: cont_3_port_2_path.into(),
                            }),
                            port: cont_3_port_2,
                        },
                        Exposition {
                            ingress: Some(Ingress {
                                domain: domain_2.into(),
                                path: cont_3_port_3_path.into(),
                            }),
                            port: cont_3_port_3,
                        },
                    ];
                    let cont_3_image = "container_3_image";
                    let cont_3_tag = "container_3_tag";
                    let cont_4_name = "container_4_name";
                    let cont_4_port_1 = 31;
                    let cont_4_port_1_path = "container_4_port_1_path";
                    let cont_4_exposes = vec![
                        Exposition {
                            ingress: None,
                            port: cont_4_port_1,
                        },
                        Exposition {
                            ingress: Some(Ingress {
                                domain: domain_1.into(),
                                path: cont_4_port_1_path.into(),
                            }),
                            port: cont_4_port_1,
                        },
                    ];
                    let cont_4_image = "container_4_image";
                    let cont_4_tag = "container_4_tag";
                    Self {
                        application: Application {
                            metadata: ObjectMeta {
                                name: Some(name.into()),
                                namespace: Some(ns.into()),
                                ..Default::default()
                            },
                            spec: ApplicationSpec {
                                containers: vec![
                                    Container {
                                        databases: vec![db_ref.clone()],
                                        exposes: cont_1_exposes.clone(),
                                        image: cont_1_image.into(),
                                        name: cont_1_name.into(),
                                        tag: cont_1_tag.into(),
                                    },
                                    Container {
                                        databases: vec![],
                                        exposes: cont_2_exposes.clone(),
                                        image: cont_2_image.into(),
                                        name: cont_2_name.into(),
                                        tag: cont_2_tag.into(),
                                    },
                                    Container {
                                        databases: vec![],
                                        exposes: cont_3_exposes.clone(),
                                        image: cont_3_image.into(),
                                        name: cont_3_name.into(),
                                        tag: cont_3_tag.into(),
                                    },
                                    Container {
                                        databases: vec![],
                                        exposes: cont_4_exposes.clone(),
                                        image: cont_4_image.into(),
                                        name: cont_4_name.into(),
                                        tag: cont_4_tag.into(),
                                    },
                                ],
                                ..Default::default()
                            },
                            status: None,
                        },
                        chart: Chart {
                            name: "chart".into(),
                            values: "values".into(),
                            version: None,
                        },
                        components: vec![
                            ComponentVariable {
                                environment: vec![
                                    EnvironmentVariable {
                                        key: Cow::Owned(db_ref.mapping.host.clone()),
                                        value: db_host.into(),
                                    },
                                    EnvironmentVariable {
                                        key: Cow::Owned(db_ref.mapping.name.clone()),
                                        value: db_db.into(),
                                    },
                                    EnvironmentVariable {
                                        key: Cow::Owned(db_ref.mapping.port.clone()),
                                        value: db_cons.port.to_string(),
                                    },
                                    EnvironmentVariable {
                                        key: Cow::Owned(db_ref.mapping.user.clone()),
                                        value: db_user.into(),
                                    },
                                ],
                                exposes: Cow::Owned(cont_1_exposes),
                                image: ImageVariable {
                                    repository: cont_1_image,
                                    tag: cont_1_tag,
                                },
                                name: cont_1_name,
                                secrets: vec![SecretVariable {
                                    key: Cow::Owned(db_ref.mapping.password.clone()),
                                    secret: SecretRef {
                                        key: db_cons.password_secret.key.clone(),
                                        name: db_sec_name.into(),
                                    },
                                }],
                            },
                            ComponentVariable {
                                environment: vec![],
                                exposes: Cow::Owned(cont_2_exposes.clone()),
                                image: ImageVariable {
                                    repository: cont_2_image,
                                    tag: cont_2_tag,
                                },
                                name: cont_2_name,
                                secrets: vec![],
                            },
                            ComponentVariable {
                                environment: vec![],
                                exposes: Cow::Owned(cont_3_exposes.clone()),
                                image: ImageVariable {
                                    repository: cont_3_image,
                                    tag: cont_3_tag,
                                },
                                name: cont_3_name,
                                secrets: vec![],
                            },
                            ComponentVariable {
                                environment: vec![],
                                exposes: Cow::Owned(cont_4_exposes.clone()),
                                image: ImageVariable {
                                    repository: cont_4_image,
                                    tag: cont_4_tag,
                                },
                                name: cont_4_name,
                                secrets: vec![],
                            },
                        ],
                        database: Database {
                            metadata: ObjectMeta {
                                name: Some(db_name.into()),
                                namespace: Some(ns.into()),
                                ..Default::default()
                            },
                            spec: DatabaseSpec {
                                database: db_db.into(),
                                instance: Selector {
                                    name: db_inst_name.into(),
                                    namespace: db_inst_namespace.into(),
                                },
                                user: db_user.into(),
                            },
                            status: None,
                        },
                        database_consumable: db_cons.clone(),
                        database_host: db_host,
                        database_instance: ServiceInstance {
                            metadata: ObjectMeta {
                                name: Some(db_inst_name.into()),
                                namespace: Some(db_inst_namespace.into()),
                                ..Default::default()
                            },
                            spec: ServiceInstanceSpec {
                                values: Default::default(),
                                service: db_svc_name.into(),
                            },
                            status: None,
                        },
                        database_ref: db_ref,
                        database_secret_name: db_sec_name,
                        database_service: Service {
                            metadata: ObjectMeta {
                                name: Some(db_svc_name.into()),
                                ..Default::default()
                            },
                            spec: ServiceSpec {
                                chart: Chart {
                                    name: "chart".into(),
                                    values: "values".into(),
                                    version: None,
                                },
                                consumes: ServiceConsumable {
                                    database: Some(db_cons),
                                },
                                monitor_delay: 30,
                            },
                        },
                        domain: "domain",
                        ingress_rules: vec![
                            IngressRuleVariable {
                                domain: domain_1,
                                paths: vec![
                                    IngressRulePathVariable {
                                        port: cont_3_port_2,
                                        service: cont_3_name,
                                        value: cont_3_port_2_path,
                                    },
                                    IngressRulePathVariable {
                                        port: cont_4_port_1,
                                        service: cont_4_name,
                                        value: cont_4_port_1_path,
                                    },
                                ],
                            },
                            IngressRuleVariable {
                                domain: domain_2,
                                paths: vec![IngressRulePathVariable {
                                    port: cont_3_port_3,
                                    service: cont_3_name,
                                    value: cont_3_port_3_path,
                                }],
                            },
                        ],
                        name,
                        namespace: ns,
                        services: vec![
                            ServiceVariable {
                                exposes: Cow::Owned(cont_2_exposes),
                                name: cont_2_name,
                            },
                            ServiceVariable {
                                exposes: Cow::Owned(cont_3_exposes),
                                name: cont_3_name,
                            },
                            ServiceVariable {
                                exposes: Cow::Owned(cont_4_exposes),
                                name: cont_4_name,
                            },
                        ],
                    }
                }
            }

            // Mocks

            #[derive(Default)]
            struct Mocks {
                database: Option<Database>,
                get_database_instance: Option<MockFn<kube::Result<Option<ServiceInstance>>>>,
                get_database_service: Option<MockFn<kube::Result<Option<Service>>>>,
                render_database_host: bool,
                render_database_secret_name: bool,
                render_values: bool,
                upgrade: bool,
            }

            // Tests

            async fn test(data: Data, mocks: Mocks) -> Result {
                init_tracer();
                let temp_filepath = Arc::new(Mutex::new(None::<PathBuf>));
                let mut helm = MockHelmRunner::new();
                helm.expect_upgrade()
                    .withf({
                        let data = data.clone();
                        let temp_filepath = temp_filepath.clone();
                        move |ns, name, chart, values_filepath, version| {
                            let temp_filepath = temp_filepath.lock().unwrap().clone().unwrap();
                            ns == data.namespace
                                && name == data.name
                                && chart == data.chart.name
                                && values_filepath == temp_filepath
                                && version.map(String::from) == data.chart.version
                        }
                    })
                    .times(mocks.upgrade as usize)
                    .returning(|_, _, _, _, _| async_ok(()));
                let mut kube = MockKubeClient::new();
                kube.expect_get_from::<Database>()
                    .with(eq(data.namespace), eq(data.database_ref.name.clone()))
                    .times(1)
                    .returning({
                        let db = mocks.database.clone();
                        move |_, _| async_ok(db.clone())
                    });
                kube.expect_get_from::<ServiceInstance>()
                    .with(
                        eq(data.database.spec.instance.namespace.clone()),
                        eq(data.database.spec.instance.name.clone()),
                    )
                    .times(mocks.get_database_instance.is_some() as usize)
                    .returning({
                        let get_inst = mocks.get_database_instance.clone();
                        move |_, _| call_mock_fn_opt_async(&get_inst)
                    });
                kube.expect_get()
                    .with(eq(data.database_instance.spec.service.clone()))
                    .times(mocks.get_database_service.is_some() as usize)
                    .returning({
                        let get_svc = mocks.get_database_service.clone();
                        move |_| call_mock_fn_opt_async(&get_svc)
                    });
                let mut renderer = MockRenderer::new();
                let conn_info_vars = serde_json::to_value(&DatabaseConnectionInfoVariables {
                    database: &data.database.spec.database,
                    domain: data.domain,
                    instance: &data.database.spec.instance,
                    name: &data.database_ref.name,
                    namespace: data.namespace,
                    user: &data.database.spec.user,
                })
                .unwrap();
                renderer
                    .expect_render()
                    .with(
                        eq(data.database_consumable.host.clone()),
                        eq(conn_info_vars.clone()),
                        always(),
                    )
                    .times(mocks.render_database_host as usize)
                    .returning(|_, _, out: &mut Vec<u8>| {
                        *out = data.database_host.as_bytes().to_vec();
                        Ok(())
                    });
                renderer
                    .expect_render()
                    .with(
                        eq(data.database_consumable.password_secret.name.clone()),
                        eq(conn_info_vars),
                        always(),
                    )
                    .times(mocks.render_database_secret_name as usize)
                    .returning(|_, _, out: &mut Vec<u8>| {
                        *out = data.database_secret_name.as_bytes().to_vec();
                        Ok(())
                    });
                let vars = json!({
                    "components": data.components,
                    "ingressRules": data.ingress_rules,
                    "name": data.name,
                    "services": data.services,
                    "tlsDomains": data.application.spec.tls_domains,
                });
                renderer
                    .expect_render()
                    .with(eq(data.chart.values.clone()), eq(vars), always())
                    .times(mocks.render_values as usize)
                    .returning({
                        let temp_filepath = temp_filepath.clone();
                        move |_, _, file: &mut NamedTempFile| {
                            let mut temp_filepath = temp_filepath.lock().unwrap();
                            *temp_filepath = Some(file.path().to_path_buf());
                            Ok(())
                        }
                    });
                let deployer = ApplicationDeployer {
                    chart: data.chart,
                    domain: data.domain.into(),
                    helm: Arc::new(helm),
                    kube: Arc::new(kube),
                    renderer: Arc::new(renderer),
                };
                deployer
                    .deploy(data.namespace, data.name, &data.application)
                    .await
            }

            #[tokio::test]
            async fn database_not_found() {
                let data = Data::default();
                let mocks = Mocks::default();
                let err = test(data, mocks).await.unwrap_err();
                assert!(matches!(err, Error::DatabaseNotFound));
            }

            #[tokio::test]
            async fn database_instance_not_found() {
                let data = Data::default();
                let mocks = Mocks {
                    database: Some(data.database.clone()),
                    get_database_instance: Some(mock_fn(&data, |_| Ok(None))),
                    ..Default::default()
                };
                let err = test(data, mocks).await.unwrap_err();
                assert!(matches!(err, Error::ServiceInstanceNotFound));
            }

            #[tokio::test]
            async fn database_service_not_found() {
                let data = Data::default();
                let mocks = Mocks {
                    database: Some(data.database.clone()),
                    get_database_instance: Some(mock_fn(&data, |data| {
                        Ok(Some(data.database_instance))
                    })),
                    get_database_service: Some(mock_fn(&data, |_| Ok(None))),
                    ..Default::default()
                };
                let err = test(data, mocks).await.unwrap_err();
                assert!(matches!(err, Error::ServiceNotFound));
            }

            #[tokio::test]
            async fn database_service_doesnt_consume_database() {
                let mut data = Data::default();
                data.database_service.spec.consumes.database = None;
                let mocks = Mocks {
                    database: Some(data.database.clone()),
                    get_database_instance: Some(mock_fn(&data, |data| {
                        Ok(Some(data.database_instance))
                    })),
                    get_database_service: Some(mock_fn(&data, |data| {
                        Ok(Some(data.database_service))
                    })),
                    ..Default::default()
                };
                let err = test(data, mocks).await.unwrap_err();
                assert!(matches!(err, Error::DatabaseNotConsumed));
            }

            #[tokio::test]
            async fn ok() {
                let data = Data::default();
                let mocks = Mocks {
                    database: Some(data.database.clone()),
                    get_database_instance: Some(mock_fn(&data, |data| {
                        Ok(Some(data.database_instance))
                    })),
                    get_database_service: Some(mock_fn(&data, |data| {
                        Ok(Some(data.database_service))
                    })),
                    render_database_host: true,
                    render_database_secret_name: true,
                    render_values: true,
                    upgrade: true,
                };
                test(data, mocks).await.unwrap();
            }
        }

        mod undeploy {
            use super::*;

            // Data

            #[derive(Clone)]
            struct Data {
                application: Application,
                chart: Chart,
                domain: &'static str,
                name: &'static str,
                namespace: &'static str,
            }

            impl Default for Data {
                fn default() -> Self {
                    let name = "name";
                    let ns = "namespace";
                    Self {
                        application: Application {
                            metadata: ObjectMeta {
                                name: Some(name.into()),
                                namespace: Some(ns.into()),
                                ..Default::default()
                            },
                            spec: Default::default(),
                            status: None,
                        },
                        chart: Chart {
                            name: "chart".into(),
                            values: "values".into(),
                            version: None,
                        },
                        domain: "domain",
                        name,
                        namespace: ns,
                    }
                }
            }

            // Tests

            #[tokio::test]
            async fn test() {
                init_tracer();
                let data = Data::default();
                let mut helm = MockHelmRunner::new();
                helm.expect_uninstall()
                    .with(eq(data.namespace), eq(data.name))
                    .times(1)
                    .returning(|_, _| async_ok(()));
                let deployer = ApplicationDeployer {
                    chart: data.chart,
                    domain: data.domain.into(),
                    helm: Arc::new(helm),
                    kube: Arc::new(MockKubeClient::new()),
                    renderer: Arc::new(MockRenderer::new()),
                };
                deployer
                    .undeploy(data.namespace, data.name, &data.application)
                    .await
                    .unwrap();
            }
        }
    }
}

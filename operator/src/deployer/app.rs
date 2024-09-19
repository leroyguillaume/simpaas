use std::{borrow::Cow, collections::BTreeMap, sync::Arc};

use kube::Resource;
use serde::Serialize;
use serde_json::json;
use simpaas_core::{renderer::Renderer, Application, Chart, Exposition};
use tempfile::NamedTempFile;
use tracing::{debug, info, instrument};

use crate::{err::Result, helm::HelmRunner};

use super::Deployer;

// ApplicationDeployer

pub struct ApplicationDeployer<HELM: HelmRunner, RENDERER: Renderer> {
    chart: Chart,
    helm: Arc<HELM>,
    renderer: Arc<RENDERER>,
}

impl<HELM: HelmRunner, RENDERER: Renderer> ApplicationDeployer<HELM, RENDERER> {
    pub fn new(chart: Chart, helm: Arc<HELM>, renderer: Arc<RENDERER>) -> Self {
        Self {
            chart,
            helm,
            renderer,
        }
    }
}

impl<HELM: HelmRunner, RENDERER: Renderer> Deployer<Application>
    for ApplicationDeployer<HELM, RENDERER>
{
    #[instrument(skip(self, ns, name, app), fields(resource.api_version = %Application::api_version(&()), resource.kind = %Application::kind(&()), resource.name = name))]
    async fn deploy(&self, ns: &str, name: &str, app: &Application) -> Result {
        debug!("rendering variables into temporary file");
        let mut file = NamedTempFile::new()?;
        let mut svcs = vec![];
        let mut rules: BTreeMap<&str, Vec<IngressRuleVariable>> = BTreeMap::new();
        for container in &app.spec.containers {
            if !container.exposes.is_empty() {
                svcs.push(ServiceVariable {
                    exposes: Cow::Borrowed(&container.exposes),
                    name: &container.name,
                });
                for exposition in &container.exposes {
                    if let Some(ing) = &exposition.ingress {
                        let var = IngressRuleVariable {
                            path: &ing.path,
                            port: exposition.port,
                            service: &container.name,
                        };
                        if let Some(svc) = rules.get_mut(ing.domain.as_str()) {
                            svc.push(var);
                        } else {
                            rules.insert(&ing.domain, vec![var]);
                        }
                    }
                }
            }
        }
        let vars = json!({
            "containers": app.spec.containers,
            "ingressRules": rules,
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

// Data structs

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct IngressRuleVariable<'a> {
    path: &'a str,
    port: u16,
    service: &'a str,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct ServiceVariable<'a> {
    exposes: Cow<'a, [Exposition]>,
    name: &'a str,
}

// Tests

#[cfg(test)]
mod test {
    use simpaas_core::{renderer::MockRenderer, ApplicationSpec, Container, Ingress};
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
                ingress_rules: BTreeMap<&'static str, Vec<IngressRuleVariable<'static>>>,
                name: &'static str,
                namespace: &'static str,
                services: Vec<ServiceVariable<'static>>,
            }

            impl Default for Data {
                fn default() -> Self {
                    let name = "name";
                    let ns = "namespace";
                    let cont_name1 = "name1";
                    let cont_name2 = "name2";
                    let cont_name3 = "name3";
                    let domain1 = "domain1";
                    let domain2 = "domain2";
                    let domain3 = "domain3";
                    let path1 = "path1";
                    let path2 = "path2";
                    let path3 = "path3";
                    let port1a = 8080;
                    let port1b = 8081;
                    let port1c = 8082;
                    let port1d = 8083;
                    let port2a = 8080;
                    let port2b = 8081;
                    let port2c = 8082;
                    let exp1a = Exposition {
                        port: port1a,
                        ingress: None,
                    };
                    let exp1b = Exposition {
                        port: port1b,
                        ingress: Some(Ingress {
                            domain: domain1.into(),
                            path: path1.into(),
                        }),
                    };
                    let exp1c = Exposition {
                        port: port1c,
                        ingress: Some(Ingress {
                            domain: domain2.into(),
                            path: path1.into(),
                        }),
                    };
                    let exp1d = Exposition {
                        port: port1d,
                        ingress: Some(Ingress {
                            domain: domain1.into(),
                            path: path2.into(),
                        }),
                    };
                    let exp2a = Exposition {
                        port: port2a,
                        ingress: Some(Ingress {
                            domain: domain2.into(),
                            path: path2.into(),
                        }),
                    };
                    let exp2b = Exposition {
                        port: port2b,
                        ingress: Some(Ingress {
                            domain: domain1.into(),
                            path: path3.into(),
                        }),
                    };
                    let exp2c = Exposition {
                        port: port2c,
                        ingress: Some(Ingress {
                            domain: domain3.into(),
                            path: path3.into(),
                        }),
                    };
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
                                        exposes: vec![],
                                        image: "image".into(),
                                        name: cont_name1.into(),
                                        tag: "tag".into(),
                                    },
                                    Container {
                                        exposes: vec![
                                            exp1a.clone(),
                                            exp1b.clone(),
                                            exp1c.clone(),
                                            exp1d.clone(),
                                        ],
                                        image: "image".into(),
                                        name: cont_name2.into(),
                                        tag: "tag".into(),
                                    },
                                    Container {
                                        exposes: vec![exp2a.clone(), exp2b.clone(), exp2c.clone()],
                                        image: "image".into(),
                                        name: cont_name3.into(),
                                        tag: "tag".into(),
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
                        ingress_rules: BTreeMap::from_iter([
                            (
                                domain1,
                                vec![
                                    IngressRuleVariable {
                                        path: path1,
                                        port: port1b,
                                        service: cont_name2,
                                    },
                                    IngressRuleVariable {
                                        path: path2,
                                        port: port1d,
                                        service: cont_name2,
                                    },
                                    IngressRuleVariable {
                                        path: path3,
                                        port: port2b,
                                        service: cont_name3,
                                    },
                                ],
                            ),
                            (
                                domain2,
                                vec![
                                    IngressRuleVariable {
                                        path: path1,
                                        port: port1c,
                                        service: cont_name2,
                                    },
                                    IngressRuleVariable {
                                        path: path2,
                                        port: port2a,
                                        service: cont_name3,
                                    },
                                ],
                            ),
                            (
                                domain3,
                                vec![IngressRuleVariable {
                                    path: path3,
                                    port: port2c,
                                    service: cont_name3,
                                }],
                            ),
                        ]),
                        name,
                        namespace: ns,
                        services: vec![
                            ServiceVariable {
                                exposes: Cow::Owned(vec![exp1a, exp1b, exp1c, exp1d]),
                                name: cont_name2,
                            },
                            ServiceVariable {
                                exposes: Cow::Owned(vec![exp2a, exp2b, exp2c]),
                                name: cont_name3,
                            },
                        ],
                    }
                }
            }

            // Tests

            #[tokio::test]
            async fn test() -> Result {
                init_tracer();
                let data = Data::default();
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
                    .times(1)
                    .returning(|_, _, _, _, _| async_ok(()));
                let mut renderer = MockRenderer::new();
                let vars = json!({
                    "containers": data.application.spec.containers,
                    "ingressRules": data.ingress_rules,
                    "name": data.name,
                    "services": data.services,
                    "tlsDomains": data.application.spec.tls_domains,
                });
                renderer
                    .expect_render()
                    .with(eq(data.chart.values.clone()), eq(vars), always())
                    .times(1)
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
                    helm: Arc::new(helm),
                    renderer: Arc::new(renderer),
                };
                deployer
                    .deploy(data.namespace, data.name, &data.application)
                    .await
            }
        }

        mod undeploy {
            use super::*;

            // Data

            #[derive(Clone)]
            struct Data {
                application: Application,
                chart: Chart,
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
                    helm: Arc::new(helm),
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

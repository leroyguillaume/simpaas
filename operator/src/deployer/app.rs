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
        let mut cmpts = vec![];
        let mut ing_rules: BTreeMap<&String, IngressRuleVariable<'_>> = BTreeMap::new();
        let mut svcs = vec![];
        for cont in &app.spec.containers {
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
                exposes: Cow::Borrowed(&cont.exposes),
                image: ImageVariable {
                    repository: &cont.image,
                    tag: &cont.tag,
                },
                name: &cont.name,
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
    exposes: Cow<'a, Vec<Exposition>>,
    image: ImageVariable<'a>,
    name: &'a str,
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
struct ServiceVariable<'a> {
    exposes: Cow<'a, Vec<Exposition>>,
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
                components: Vec<ComponentVariable<'static>>,
                ingress_rules: Vec<IngressRuleVariable<'static>>,
                name: &'static str,
                namespace: &'static str,
                services: Vec<ServiceVariable<'static>>,
            }

            impl Default for Data {
                fn default() -> Self {
                    let name = "name";
                    let ns = "namespace";
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
                                        exposes: cont_1_exposes.clone(),
                                        image: cont_1_image.into(),
                                        name: cont_1_name.into(),
                                        tag: cont_1_tag.into(),
                                    },
                                    Container {
                                        exposes: cont_2_exposes.clone(),
                                        image: cont_2_image.into(),
                                        name: cont_2_name.into(),
                                        tag: cont_2_tag.into(),
                                    },
                                    Container {
                                        exposes: cont_3_exposes.clone(),
                                        image: cont_3_image.into(),
                                        name: cont_3_name.into(),
                                        tag: cont_3_tag.into(),
                                    },
                                    Container {
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
                                exposes: Cow::Owned(cont_1_exposes),
                                image: ImageVariable {
                                    repository: cont_1_image,
                                    tag: cont_1_tag,
                                },
                                name: cont_1_name,
                            },
                            ComponentVariable {
                                exposes: Cow::Owned(cont_2_exposes.clone()),
                                image: ImageVariable {
                                    repository: cont_2_image,
                                    tag: cont_2_tag,
                                },
                                name: cont_2_name,
                            },
                            ComponentVariable {
                                exposes: Cow::Owned(cont_3_exposes.clone()),
                                image: ImageVariable {
                                    repository: cont_3_image,
                                    tag: cont_3_tag,
                                },
                                name: cont_3_name,
                            },
                            ComponentVariable {
                                exposes: Cow::Owned(cont_4_exposes.clone()),
                                image: ImageVariable {
                                    repository: cont_4_image,
                                    tag: cont_4_tag,
                                },
                                name: cont_4_name,
                            },
                        ],
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
                    "components": data.components,
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

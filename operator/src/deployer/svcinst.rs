use std::sync::Arc;

use kube::Resource;
use serde_json::json;
use simpaas_core::{kube::KubeClient, renderer::Renderer, Service, ServiceInstance};
use tempfile::NamedTempFile;
use tracing::{debug, info, instrument};

use crate::{
    err::{Error, Result},
    helm::HelmRunner,
};

use super::Deployer;

// ServiceInstanceDeployer

pub struct ServiceInstanceDeployer<HELM: HelmRunner, KUBE: KubeClient, RENDERER: Renderer> {
    helm: Arc<HELM>,
    kube: Arc<KUBE>,
    renderer: Arc<RENDERER>,
}

impl<HELM: HelmRunner, KUBE: KubeClient, RENDERER: Renderer>
    ServiceInstanceDeployer<HELM, KUBE, RENDERER>
{
    pub fn new(helm: Arc<HELM>, kube: Arc<KUBE>, renderer: Arc<RENDERER>) -> Self {
        Self {
            helm,
            kube,
            renderer,
        }
    }
}

impl<HELM: HelmRunner, KUBE: KubeClient, RENDERER: Renderer> Deployer<ServiceInstance>
    for ServiceInstanceDeployer<HELM, KUBE, RENDERER>
{
    #[instrument(skip(self, ns, name, svc_inst), fields(resource.api_version = %ServiceInstance::api_version(&()), resource.kind = %ServiceInstance::kind(&()), resource.name = name, resource.namespace = ns, resource.service = svc_inst.spec.service))]
    async fn deploy(&self, ns: &str, name: &str, svc_inst: &ServiceInstance) -> Result {
        let svc = self
            .kube
            .get::<Service>(&svc_inst.spec.service)
            .await?
            .ok_or(Error::ServiceNotFound)?;
        debug!("rendering variables into temporary file");
        let mut file = NamedTempFile::new()?;
        let vars = json!({
            "name": name,
            "namespace": ns,
            "service": svc_inst.spec.service,
            "values": svc_inst.spec.values,
        });
        self.renderer
            .render(&svc.spec.chart.values, &vars, &mut file)?;
        self.helm
            .upgrade(
                ns,
                name,
                &svc.spec.chart.name,
                file.path(),
                svc.spec.chart.version.as_deref(),
            )
            .await?;
        info!("service instance deployed");
        Ok(())
    }

    #[instrument(skip(self, ns, name, svc_inst), fields(resource.name = name, resource.namespace = ns, resource.service = svc_inst.spec.service))]
    async fn undeploy(&self, ns: &str, name: &str, svc_inst: &ServiceInstance) -> Result {
        self.helm.uninstall(ns, name).await?;
        info!("service instance undeployed");
        Ok(())
    }
}

// Tests

#[cfg(test)]
mod test {
    use std::{path::PathBuf, sync::Mutex};

    use kube::api::ObjectMeta;
    use mockall::predicate::*;
    use simpaas_core::{
        kube::MockKubeClient, renderer::MockRenderer, Chart, Service, ServiceInstanceSpec,
        ServiceSpec,
    };

    use crate::{helm::MockHelmRunner, test::*};

    use super::*;

    // Mods

    mod service_instance_deployer {
        use super::*;

        mod deploy {
            use super::*;

            // Data

            #[derive(Clone)]
            struct Data {
                instance: ServiceInstance,
                name: &'static str,
                namespace: &'static str,
                service: Service,
            }

            impl Default for Data {
                fn default() -> Self {
                    let svc_name = "service";
                    let svc_inst_name = "instance";
                    let ns = "namespace";
                    Self {
                        instance: ServiceInstance {
                            metadata: ObjectMeta {
                                name: Some(svc_inst_name.into()),
                                namespace: Some(ns.into()),
                                ..Default::default()
                            },
                            spec: ServiceInstanceSpec {
                                service: svc_name.into(),
                                values: Default::default(),
                            },
                            status: None,
                        },
                        name: svc_inst_name,
                        namespace: ns,
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
                                consumes: Default::default(),
                                monitor_delay: 0,
                            },
                        },
                    }
                }
            }

            // Mocks

            #[derive(Default)]
            struct Mocks {
                render: bool,
                service: Option<Service>,
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
                                && chart == data.service.spec.chart.name
                                && values_filepath == temp_filepath
                                && version.map(String::from) == data.service.spec.chart.version
                        }
                    })
                    .times(mocks.upgrade as usize)
                    .returning(|_, _, _, _, _| async_ok(()));
                let mut kube = MockKubeClient::new();
                kube.expect_get()
                    .with(eq(data.instance.spec.service.clone()))
                    .times(1)
                    .returning({
                        let svc = mocks.service.clone();
                        move |_| async_ok(svc.clone())
                    });
                let mut renderer = MockRenderer::new();
                let vars = json!({
                    "name": data.name,
                    "namespace": data.namespace,
                    "service": data.instance.spec.service,
                    "values": data.instance.spec.values,
                });
                renderer
                    .expect_render()
                    .with(eq(data.service.spec.chart.values), eq(vars), always())
                    .times(mocks.render as usize)
                    .returning({
                        let temp_filepath = temp_filepath.clone();
                        move |_, _, file: &mut NamedTempFile| {
                            let mut temp_filepath = temp_filepath.lock().unwrap();
                            *temp_filepath = Some(file.path().to_path_buf());
                            Ok(())
                        }
                    });
                let deployer = ServiceInstanceDeployer {
                    kube: Arc::new(kube),
                    helm: Arc::new(helm),
                    renderer: Arc::new(renderer),
                };
                deployer
                    .deploy(data.namespace, data.name, &data.instance)
                    .await
            }

            #[tokio::test]
            async fn service_not_found() {
                let data = Data::default();
                let mocks = Mocks::default();
                let err = test(data, mocks).await.unwrap_err();
                assert!(matches!(err, Error::ServiceNotFound));
            }

            #[tokio::test]
            async fn ok() {
                let data = Data::default();
                let mocks = Mocks {
                    service: Some(data.service.clone()),
                    render: true,
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
                instance: ServiceInstance,
                name: &'static str,
                namespace: &'static str,
            }

            impl Default for Data {
                fn default() -> Self {
                    let svc_inst_name = "instance";
                    let ns = "namespace";
                    Self {
                        instance: ServiceInstance {
                            metadata: ObjectMeta {
                                name: Some(svc_inst_name.into()),
                                namespace: Some(ns.into()),
                                ..Default::default()
                            },
                            spec: ServiceInstanceSpec {
                                service: "service".into(),
                                values: Default::default(),
                            },
                            status: None,
                        },
                        name: svc_inst_name,
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
                let deployer = ServiceInstanceDeployer {
                    helm: Arc::new(helm),
                    kube: Arc::new(MockKubeClient::new()),
                    renderer: Arc::new(MockRenderer::new()),
                };
                deployer
                    .undeploy(data.namespace, data.name, &data.instance)
                    .await
                    .unwrap();
            }
        }
    }
}

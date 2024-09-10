use std::{
    fmt::{Debug, Display},
    future::Future,
};

use k8s_openapi::NamespaceResourceScope;
use kube::{
    api::{DeleteParams, ListParams, ObjectMeta, PartialObjectMetaExt, Patch, PatchParams},
    runtime::events::{Event, Recorder, Reporter},
    Api, Client, Resource, Result,
};
use serde::{de::DeserializeOwned, Serialize};
use serde_json::json;
use tracing::{debug, instrument};

// Consts

const MANAGER: &str = "simpaas";

// Traits

#[cfg_attr(feature = "mock", mockall::automock)]
pub trait KubeClient: Send + Sync {
    fn delete_from<
        RESOURCE: Clone
            + Debug
            + DeserializeOwned
            + Resource<DynamicType = (), Scope = NamespaceResourceScope>
            + Send
            + Serialize
            + Sync
            + 'static,
    >(
        &self,
        ns: &str,
        name: &str,
    ) -> impl Future<Output = Result<()>> + Send;

    fn get<
        RESOURCE: Clone
            + Debug
            + DeserializeOwned
            + Resource<DynamicType = (), Scope = NamespaceResourceScope>
            + Send
            + Serialize
            + Sync
            + 'static,
    >(
        &self,
        name: &str,
    ) -> impl Future<Output = Result<Option<RESOURCE>>> + Send;

    fn get_from<
        RESOURCE: Clone
            + Debug
            + DeserializeOwned
            + Resource<DynamicType = (), Scope = NamespaceResourceScope>
            + Send
            + Serialize
            + Sync
            + 'static,
    >(
        &self,
        ns: &str,
        name: &str,
    ) -> impl Future<Output = Result<Option<RESOURCE>>> + Send;

    fn list_from<
        RESOURCE: Clone
            + Debug
            + DeserializeOwned
            + Resource<DynamicType = (), Scope = NamespaceResourceScope>
            + Send
            + Serialize
            + Sync
            + 'static,
    >(
        &self,
        ns: &str,
        sel: &str,
    ) -> impl Future<Output = Result<Vec<RESOURCE>>> + Send;

    fn patch_from<
        RESOURCE: Clone
            + Debug
            + DeserializeOwned
            + Resource<DynamicType = (), Scope = NamespaceResourceScope>
            + Send
            + Serialize
            + Sync
            + 'static,
    >(
        &self,
        ns: &str,
        name: &str,
        res: &RESOURCE,
    ) -> impl Future<Output = Result<()>> + Send;

    fn patch_metadata_from<
        RESOURCE: Clone
            + Debug
            + DeserializeOwned
            + Resource<DynamicType = (), Scope = NamespaceResourceScope>
            + Send
            + Serialize
            + Sync
            + 'static,
    >(
        &self,
        ns: &str,
        name: &str,
        meta: ObjectMeta,
    ) -> impl Future<Output = Result<()>> + Send;

    fn patch_status_from<
        RESOURCE: Clone
            + Debug
            + DeserializeOwned
            + Resource<DynamicType = (), Scope = NamespaceResourceScope>
            + Send
            + Serialize
            + Sync
            + 'static,
        STATUS: Display + Send + Serialize + Sync + 'static,
    >(
        &self,
        ns: &str,
        name: &str,
        status: &STATUS,
    ) -> impl Future<Output = Result<()>> + Send;

    fn publish_event<
        RESOURCE: Clone
            + Debug
            + DeserializeOwned
            + Resource<DynamicType = (), Scope = NamespaceResourceScope>
            + Send
            + Serialize
            + Sync
            + 'static,
    >(
        &self,
        evt: Event,
        res: &RESOURCE,
    ) -> impl Future<Output = Result<()>> + Send;
}

// DefaultKubeClient

pub struct DefaultKubeClient {
    kube: Client,
    reporter: Reporter,
}

impl DefaultKubeClient {
    pub fn new(pod_name: Option<String>, kube: Client) -> Self {
        Self {
            kube,
            reporter: Reporter {
                controller: MANAGER.into(),
                instance: pod_name,
            },
        }
    }

    async fn get<
        RESOURCE: Clone
            + Debug
            + DeserializeOwned
            + Resource<DynamicType = (), Scope = NamespaceResourceScope>
            + Send
            + Serialize
            + Sync,
    >(
        name: &str,
        api: Api<RESOURCE>,
    ) -> Result<Option<RESOURCE>> {
        debug!("getting resource");
        api.get_opt(name).await
    }
}

impl KubeClient for DefaultKubeClient {
    #[instrument(skip(self, ns, name), fields(resource.api_version = %RESOURCE::api_version(&()), resource.kind = %RESOURCE::kind(&()), resource.name = name, resource.namespace = ns))]
    async fn delete_from<
        RESOURCE: Clone
            + Debug
            + DeserializeOwned
            + Resource<DynamicType = (), Scope = NamespaceResourceScope>
            + Send
            + Serialize
            + Sync,
    >(
        &self,
        ns: &str,
        name: &str,
    ) -> Result<()> {
        debug!("deleting resource");
        let api: Api<RESOURCE> = Api::namespaced(self.kube.clone(), ns);
        let params = DeleteParams::default();
        api.delete(name, &params).await?;
        Ok(())
    }

    #[instrument(skip(self, name), fields(resource.api_version = %RESOURCE::api_version(&()), resource.kind = %RESOURCE::kind(&()), resource.name = name))]
    async fn get<
        RESOURCE: Clone
            + Debug
            + DeserializeOwned
            + Resource<DynamicType = (), Scope = NamespaceResourceScope>
            + Send
            + Serialize
            + Sync,
    >(
        &self,
        name: &str,
    ) -> Result<Option<RESOURCE>> {
        let api = Api::default_namespaced(self.kube.clone());
        Self::get(name, api).await
    }

    #[instrument(skip(self, ns, name), fields(resource.api_version = %RESOURCE::api_version(&()), resource.kind = %RESOURCE::kind(&()), resource.name = name, resource.namespace = ns))]
    async fn get_from<
        RESOURCE: Clone
            + Debug
            + DeserializeOwned
            + Resource<DynamicType = (), Scope = NamespaceResourceScope>
            + Send
            + Serialize
            + Sync,
    >(
        &self,
        ns: &str,
        name: &str,
    ) -> Result<Option<RESOURCE>> {
        let api = Api::namespaced(self.kube.clone(), ns);
        Self::get(name, api).await
    }

    #[instrument(skip(self, ns, sel), fields(resource.api_version = %RESOURCE::api_version(&()), resource.kind = %RESOURCE::kind(&()), resource.namespace = ns))]
    async fn list_from<
        RESOURCE: Clone
            + Debug
            + DeserializeOwned
            + Resource<DynamicType = (), Scope = NamespaceResourceScope>
            + Send
            + Serialize
            + Sync,
    >(
        &self,
        ns: &str,
        sel: &str,
    ) -> Result<Vec<RESOURCE>> {
        debug!("listing resources");
        let api = Api::namespaced(self.kube.clone(), ns);
        let params = ListParams {
            label_selector: Some(sel.into()),
            ..Default::default()
        };
        let list = api.list(&params).await?;
        Ok(list.items)
    }

    #[instrument(skip(self, ns, name, res), fields(resource.api_version = %RESOURCE::api_version(&()), resource.kind = %RESOURCE::kind(&()), resource.name = name, resource.namespace = ns))]
    async fn patch_from<
        RESOURCE: Clone
            + Debug
            + DeserializeOwned
            + Resource<DynamicType = (), Scope = NamespaceResourceScope>
            + Send
            + Serialize
            + Sync,
    >(
        &self,
        ns: &str,
        name: &str,
        res: &RESOURCE,
    ) -> Result<()> {
        debug!("patching resource");
        let api: Api<RESOURCE> = Api::namespaced(self.kube.clone(), ns);
        let params = PatchParams::apply(MANAGER);
        let patch = Patch::Apply(res);
        api.patch(name, &params, &patch).await?;
        Ok(())
    }

    #[instrument(skip(self, ns, name, meta), fields(resource.api_version = %RESOURCE::api_version(&()), resource.kind = %RESOURCE::kind(&()), resource.name = name, resource.namespace = ns))]
    async fn patch_metadata_from<
        RESOURCE: Clone
            + Debug
            + DeserializeOwned
            + Resource<DynamicType = (), Scope = NamespaceResourceScope>
            + Send
            + Serialize
            + Sync,
    >(
        &self,
        ns: &str,
        name: &str,
        meta: ObjectMeta,
    ) -> Result<()> {
        debug!("patching resource metadata");
        let api: Api<RESOURCE> = Api::namespaced(self.kube.clone(), ns);
        let params = PatchParams::apply(MANAGER);
        let patch = Patch::Apply(meta.into_request_partial::<RESOURCE>());
        api.patch_metadata(name, &params, &patch).await?;
        Ok(())
    }

    #[instrument(skip(self, ns, name, status), fields(resource.api_version = %RESOURCE::api_version(&()), resource.kind = %RESOURCE::kind(&()), resource.name = name, resource.namespace = ns, resource.status = %status))]
    async fn patch_status_from<
        RESOURCE: Clone
            + Debug
            + DeserializeOwned
            + Resource<DynamicType = (), Scope = NamespaceResourceScope>
            + Send
            + Serialize
            + Sync,
        STATUS: Display + Send + Serialize + Sync,
    >(
        &self,
        ns: &str,
        name: &str,
        status: &STATUS,
    ) -> Result<()> {
        debug!("patching resource status");
        let api: Api<RESOURCE> = Api::namespaced(self.kube.clone(), ns);
        let params = PatchParams::default();
        let patch = Patch::Merge(json!({
            "status": status,
        }));
        api.patch_status(name, &params, &patch).await?;
        Ok(())
    }

    #[instrument(skip(self, evt, res))]
    async fn publish_event<
        RESOURCE: Clone
            + Debug
            + DeserializeOwned
            + Resource<DynamicType = (), Scope = NamespaceResourceScope>
            + Send
            + Serialize
            + Sync,
    >(
        &self,
        evt: Event,
        res: &RESOURCE,
    ) -> Result<()> {
        debug!("publishing event");
        let recorder = Recorder::new(
            self.kube.clone(),
            self.reporter.clone(),
            res.object_ref(&()),
        );
        recorder.publish(evt).await?;
        Ok(())
    }
}

// Functions

pub fn selector(sel: &[(&str, &str)]) -> String {
    sel.iter()
        .map(|(key, val)| format!("{key}={val}"))
        .reduce(|acc, sel| format!("{acc},{sel}"))
        .unwrap_or_default()
}

// Tests

#[cfg(test)]
mod test {
    use super::*;

    // Mods

    mod selector {
        use super::*;

        // Data

        #[derive(Clone, Default)]
        struct Data {
            selector: Vec<(&'static str, &'static str)>,
        }

        // Tests

        #[test]
        fn empty() {
            let data = Data::default();
            let sel = selector(&data.selector);
            assert!(sel.is_empty());
        }

        #[test]
        fn one() {
            let data = Data {
                selector: vec![("foo", "bar")],
            };
            let sel = selector(&data.selector);
            assert_eq!(sel, "foo=bar");
        }

        #[test]
        fn two() {
            let data = Data {
                selector: vec![("foo", "bar"), ("foo", "bar")],
            };
            let sel = selector(&data.selector);
            assert_eq!(sel, "foo=bar,foo=bar");
        }
    }
}

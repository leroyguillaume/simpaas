use k8s_openapi::api::{core::v1::Namespace, networking::v1::Ingress};
use kube::{
    api::{DeleteParams, ListParams, Patch, PatchParams},
    Api, Client,
};
use tracing::{debug, instrument, warn};

use crate::{
    domain::{Action, App, Invitation, PermissionError, Role, Service, User},
    CARGO_PKG_NAME,
};

use super::{DomainUsage, KubeClient, Result};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Permission(
        #[from]
        #[source]
        PermissionError,
    ),
    #[error("{0}")]
    Kube(
        #[from]
        #[source]
        ::kube::Error,
    ),
}

pub struct ApiKubeClient(Client);

impl ApiKubeClient {
    pub fn new(client: Client) -> Self {
        Self(client)
    }
}

impl KubeClient for ApiKubeClient {
    #[instrument(skip(self, name), fields(app.name = name))]
    async fn delete_app(&self, name: &str) -> Result {
        let api: Api<App> = Api::default_namespaced(self.0.clone());
        let params = DeleteParams::background();
        debug!("deleting app");
        api.delete(name, &params).await?;
        Ok(())
    }

    #[instrument(skip(self, token), fields(invit.token = token))]
    async fn delete_invitation(&self, token: &str) -> Result {
        let api: Api<Invitation> = Api::default_namespaced(self.0.clone());
        let params = DeleteParams::background();
        debug!("deleting invitation");
        api.delete(token, &params).await?;
        Ok(())
    }

    #[instrument(skip(self, namespace), fields(app.namespace = namespace))]
    async fn delete_namespace(&self, namespace: &str) -> Result {
        let api: Api<Namespace> = Api::all(self.0.clone());
        if api.get_opt(namespace).await?.is_some() {
            let params = DeleteParams::background();
            debug!("deleting namespace");
            api.delete(namespace, &params).await?;
        } else {
            warn!("namespace can't be deleted because it doesn't exist");
        }
        Ok(())
    }

    #[instrument(skip(self, name, svcs), fields(app.name = name))]
    async fn domain_usages(&self, name: &str, svcs: &[Service]) -> Result<Vec<DomainUsage>> {
        let domains: Vec<&String> = svcs
            .iter()
            .flat_map(|svc| {
                svc.expose
                    .iter()
                    .filter_map(|exp| exp.ingress.as_ref().map(|ing| &ing.domain))
            })
            .collect();
        let api: Api<Ingress> = Api::all(self.0.clone());
        let params = ListParams::default();
        let mut usages = vec![];
        debug!("listing all ingresses");
        for ing in api.list(&params).await? {
            if let Some(spec) = ing.spec {
                if let Some(rules) = spec.rules {
                    for rule in rules {
                        if let Some(host) = rule.host {
                            if domains.iter().any(|domain| *domain == &host) {
                                let app = ing
                                    .metadata
                                    .labels
                                    .as_ref()
                                    .and_then(|annot| annot.get("simpaas.gleroy.dev/app"))
                                    .cloned();
                                if let Some(app) = app {
                                    if app != name {
                                        usages.push(DomainUsage {
                                            app: Some(app),
                                            domain: host,
                                        });
                                    }
                                } else {
                                    usages.push(DomainUsage {
                                        app: None,
                                        domain: host,
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }
        Ok(usages)
    }

    #[instrument(skip(self, name), fields(app.name = name))]
    async fn get_app(&self, name: &str) -> Result<Option<App>> {
        let api: Api<App> = Api::default_namespaced(self.0.clone());
        debug!("getting app");
        api.get_opt(name).await.map_err(super::Error::from)
    }

    #[instrument(skip(self, token), fields(invit.token = token))]
    async fn get_invitation(&self, token: &str) -> Result<Option<Invitation>> {
        let api: Api<Invitation> = Api::default_namespaced(self.0.clone());
        debug!("getting invitation");
        api.get_opt(token).await.map_err(super::Error::from)
    }

    #[instrument(skip(self, name), fields(role.name = name))]
    async fn get_role(&self, name: &str) -> Result<Option<Role>> {
        let api: Api<Role> = Api::default_namespaced(self.0.clone());
        debug!("getting role");
        api.get_opt(name).await.map_err(super::Error::from)
    }

    #[instrument(skip(self, name), fields(user.name = name))]
    async fn get_user(&self, name: &str) -> Result<Option<User>> {
        let api: Api<User> = Api::default_namespaced(self.0.clone());
        debug!("getting user");
        api.get_opt(name).await.map_err(super::Error::from)
    }

    #[instrument(skip(self, name, app), fields(app.name = name))]
    async fn patch_app(&self, name: &str, app: &App) -> Result {
        let api: Api<App> = Api::default_namespaced(self.0.clone());
        let params = PatchParams::apply(CARGO_PKG_NAME);
        debug!("patching app");
        api.patch(name, &params, &Patch::Apply(&app)).await?;
        Ok(())
    }

    #[instrument(skip(self, token, invit), fields(invit.to = invit.spec.to, invit.token = token))]
    async fn patch_invitation(&self, token: &str, invit: &Invitation) -> Result {
        let api: Api<Invitation> = Api::default_namespaced(self.0.clone());
        let params = PatchParams::apply(CARGO_PKG_NAME);
        debug!("patching invitation");
        api.patch(token, &params, &Patch::Apply(&invit)).await?;
        Ok(())
    }

    #[instrument(skip(self, name, user), fields(user.name = name))]
    async fn patch_user(&self, name: &str, user: &User) -> Result {
        let api: Api<User> = Api::default_namespaced(self.0.clone());
        let params = PatchParams::apply(CARGO_PKG_NAME);
        debug!("patching user");
        api.patch(name, &params, &Patch::Apply(&user)).await?;
        Ok(())
    }

    #[instrument(skip(self, user, action), fields(%action))]
    async fn user_has_permission(&self, user: &User, action: Action<'_>) -> Result<bool> {
        for role in &user.spec.roles {
            let role = self.get_role(role).await?;
            if let Some(role) = role {
                for role_perm in role.spec.permissions {
                    if role_perm.allows(action)? {
                        return Ok(true);
                    }
                }
            }
        }
        Ok(false)
    }
}

impl From<Error> for super::Error {
    fn from(err: Error) -> Self {
        Self(Box::new(err))
    }
}

impl From<::kube::Error> for super::Error {
    fn from(err: ::kube::Error) -> Self {
        Error::Kube(err).into()
    }
}

impl From<PermissionError> for super::Error {
    fn from(err: PermissionError) -> Self {
        Error::Permission(err).into()
    }
}

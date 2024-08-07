use std::collections::HashSet;

use k8s_openapi::api::{
    core::v1::{Namespace, Pod, PodStatus},
    networking::v1::Ingress,
};
use kube::{
    api::{DeleteParams, ListParams, Patch, PatchParams},
    runtime::events::{Event, EventType, Recorder, Reporter},
    Api, Client, Resource,
};
use regex::Regex;
use serde_json::json;
use tracing::{debug, instrument, warn};

use crate::{
    domain::{
        Action, App, AppStatus, ContainerService, Invitation, InvitationStatus, Permission,
        PermissionError, Role, User,
    },
    CARGO_PKG_NAME,
};

use super::{
    AppEvent, AppFilter, DomainUsage, InvitationEvent, KubeClient, KubeEventPublisher, Result,
    ServicePod, ServicePodStatus, LABEL_APP, LABEL_SERVICE,
};

// Errors

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Kube(
        #[from]
        #[source]
        ::kube::Error,
    ),
    #[error("failed to map kubernetes resource")]
    Mapping,
    #[error("{0}")]
    Permission(
        #[from]
        #[source]
        PermissionError,
    ),
    #[error("regex error: {0}")]
    Regex(
        #[from]
        #[source]
        regex::Error,
    ),
}

// DefaultKubeClient

pub struct DefaultKubeClient(Client);

impl DefaultKubeClient {
    pub fn new(client: Client) -> Self {
        Self(client)
    }
}

impl KubeClient for DefaultKubeClient {
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
    async fn domain_usages(
        &self,
        name: &str,
        svcs: &[ContainerService],
    ) -> Result<Vec<DomainUsage>> {
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

    #[instrument(skip(self, filter, username, user), fields(filter.name = filter.name.as_str(), user.name = username))]
    async fn list_apps(&self, filter: &AppFilter, username: &str, user: &User) -> Result<Vec<App>> {
        let allowed = self
            .user_permissions(user)
            .await?
            .into_iter()
            .filter_map(|perm| {
                if let Permission::ReadApp { name } = perm {
                    Some(Regex::new(&name))
                } else {
                    None
                }
            })
            .collect::<std::result::Result<Vec<Regex>, regex::Error>>()?;
        let api: Api<App> = Api::default_namespaced(self.0.clone());
        let params = ListParams::default();
        debug!("listing apps");
        let apps = api
            .list(&params)
            .await?
            .into_iter()
            .filter_map(|app| {
                if let Some(name) = &app.metadata.name {
                    if app.spec.owner != username
                        && !allowed.iter().any(|allowed| allowed.is_match(name))
                    {
                        debug!(app.name = name, "user is not allowed to get app");
                        return None;
                    }
                    if !filter.name.is_match(name) {
                        debug!(app.name = name, "app name doesn't match filter");
                        return None;
                    }
                    Some(app)
                } else {
                    warn!("app doesn't have name");
                    None
                }
            })
            .collect();
        Ok(apps)
    }

    #[instrument(skip(self, app, service), fields(app.name = app, service.name = service))]
    async fn list_service_pods(&self, app: &str, service: &str) -> Result<Vec<ServicePod>> {
        let api: Api<Pod> = Api::namespaced(self.0.clone(), app);
        let params =
            ListParams::default().labels(&format!("{LABEL_APP}={app},{LABEL_SERVICE}={service}"));
        debug!("listing pods");
        api.list(&params)
            .await?
            .into_iter()
            .map(|pod| pod.try_into().map_err(super::Error::from))
            .collect()
    }

    #[instrument(skip(self, name, app), fields(app.name = name))]
    async fn patch_app(&self, name: &str, app: &App) -> Result {
        let api: Api<App> = Api::default_namespaced(self.0.clone());
        let params = PatchParams::apply(CARGO_PKG_NAME);
        debug!("patching app");
        api.patch(name, &params, &Patch::Apply(app)).await?;
        Ok(())
    }

    #[instrument(skip(self, name, status), fields(app.name = name))]
    async fn patch_app_status(&self, name: &str, status: &AppStatus) -> Result {
        let api: Api<App> = Api::default_namespaced(self.0.clone());
        let params = PatchParams::default();
        debug!("patching app status");
        let status = json!({
            "status": status,
        });
        api.patch_status(name, &params, &Patch::Merge(status))
            .await?;
        Ok(())
    }

    #[instrument(skip(self, token, invit), fields(invit.to = invit.spec.to, invit.token = token))]
    async fn patch_invitation(&self, token: &str, invit: &Invitation) -> Result {
        let api: Api<Invitation> = Api::default_namespaced(self.0.clone());
        let params = PatchParams::apply(CARGO_PKG_NAME);
        debug!("patching invitation");
        api.patch(token, &params, &Patch::Apply(invit)).await?;
        Ok(())
    }

    #[instrument(skip(self, token, status), fields(invit.token = token))]
    async fn patch_invitation_status(&self, token: &str, status: &InvitationStatus) -> Result {
        let api: Api<Invitation> = Api::default_namespaced(self.0.clone());
        let params = PatchParams::default();
        debug!("patching invitation status");
        let status = json!({
            "status": status,
        });
        api.patch_status(token, &params, &Patch::Merge(status))
            .await?;
        Ok(())
    }

    #[instrument(skip(self, name, user), fields(user.name = name))]
    async fn patch_user(&self, name: &str, user: &User) -> Result {
        let api: Api<User> = Api::default_namespaced(self.0.clone());
        let params = PatchParams::apply(CARGO_PKG_NAME);
        debug!("patching user");
        api.patch(name, &params, &Patch::Apply(user)).await?;
        Ok(())
    }

    #[instrument(skip(self, user))]
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

    #[instrument(skip(self, user))]
    async fn user_permissions(&self, user: &User) -> Result<HashSet<Permission>> {
        debug!("getting user permissions");
        let mut perms = HashSet::new();
        for role in &user.spec.roles {
            let role = self.get_role(role).await?;
            if let Some(role) = role {
                for perm in role.spec.permissions {
                    perms.insert(perm);
                }
            }
        }
        Ok(perms)
    }
}

// DefaultKubeEventPublisher

pub struct DefaultKubeEventPublisher {
    client: Client,
    reporter: Reporter,
}

impl DefaultKubeEventPublisher {
    pub fn new(client: Client, instance: Option<String>) -> Self {
        Self {
            client,
            reporter: Reporter {
                controller: CARGO_PKG_NAME.into(),
                instance,
            },
        }
    }

    async fn publish(event: Event, recorder: Recorder) {
        if let Err(err) = recorder.publish(event).await {
            warn!("failed to publish event: {err}");
        }
    }
}

impl KubeEventPublisher for DefaultKubeEventPublisher {
    #[instrument(skip(self, app, event))]
    async fn publish_app_event(&self, app: &App, event: AppEvent) {
        debug!("publishing app event");
        let recorder = Recorder::new(
            self.client.clone(),
            self.reporter.clone(),
            app.object_ref(&()),
        );
        Self::publish(event.into(), recorder).await;
    }

    #[instrument(skip(self, invit, event))]
    async fn publish_invitation_event(&self, invit: &Invitation, event: InvitationEvent) {
        debug!("publishing invitation event");
        let recorder = Recorder::new(
            self.client.clone(),
            self.reporter.clone(),
            invit.object_ref(&()),
        );
        Self::publish(event.into(), recorder).await;
    }
}

// super::Error

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

impl From<regex::Error> for super::Error {
    fn from(err: regex::Error) -> Self {
        Error::Regex(err).into()
    }
}

// Event

impl From<AppEvent> for Event {
    fn from(event: AppEvent) -> Self {
        match event {
            AppEvent::Deployed => Self {
                action: "Deploying".into(),
                type_: EventType::Normal,
                reason: "Deployed".into(),
                note: Some("App deployed successfully".into()),
                secondary: None,
            },
            AppEvent::Deploying => Self {
                action: "Deploying".into(),
                type_: EventType::Normal,
                reason: "Deploying".into(),
                note: Some("Deployment started".into()),
                secondary: None,
            },
            AppEvent::DeploymentFailed(err) => Self {
                action: "Deploying".into(),
                type_: EventType::Warning,
                reason: "Failed".into(),
                note: Some(format!("Deployment failed: {err}")),
                secondary: None,
            },
            AppEvent::MonitoringFailed(err) => Self {
                action: "Monitoring".into(),
                type_: EventType::Warning,
                reason: "Failed".into(),
                note: Some(format!("Monitoring failed: {err}")),
                secondary: None,
            },
            AppEvent::Undeploying => Self {
                action: "Undeploying".into(),
                type_: EventType::Normal,
                reason: "Undeploying".into(),
                note: Some("Undeployment started".into()),
                secondary: None,
            },
            AppEvent::UndeploymentFailed(err) => Self {
                action: "Undeploying".into(),
                type_: EventType::Warning,
                reason: "Failed".into(),
                note: Some(format!("Undeployment failed: {err}")),
                secondary: None,
            },
        }
    }
}

impl From<InvitationEvent> for Event {
    fn from(event: InvitationEvent) -> Self {
        match event {
            InvitationEvent::SendingFailed(err) => Self {
                action: "Sending".into(),
                type_: EventType::Warning,
                reason: "Failed".into(),
                note: Some(format!("Sending email failed: {err}")),
                secondary: None,
            },
            InvitationEvent::Sent => Self {
                action: "Sending".into(),
                type_: EventType::Normal,
                reason: "Sent".into(),
                note: Some("Email sent".into()),
                secondary: None,
            },
        }
    }
}

// ServicePod

impl TryFrom<Pod> for ServicePod {
    type Error = Error;

    fn try_from(pod: Pod) -> std::result::Result<Self, Self::Error> {
        Ok(Self {
            name: pod.metadata.name.ok_or_else(|| {
                debug!("pod doesn't have name");
                Error::Mapping
            })?,
            status: pod
                .status
                .map(ServicePodStatus::from)
                .unwrap_or(ServicePodStatus::Stopped),
        })
    }
}

// ServicePodStatus

impl From<PodStatus> for ServicePodStatus {
    fn from(status: PodStatus) -> Self {
        match status.phase.as_deref() {
            Some("Running") => Self::Running,
            _ => Self::Stopped,
        }
    }
}

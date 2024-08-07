use std::collections::HashSet;

use futures::Future;
use regex::Regex;

use crate::domain::{
    Action, App, AppStatus, ContainerService, Invitation, InvitationStatus, Permission, Role, User,
};

// Mods

pub mod default;

// Finalizers

pub const FINALIZER: &str = "simpaas.gleroy.dev/finalizer";

// Labels

pub const LABEL_APP: &str = "simpaas.gleroy.dev/app";
pub const LABEL_SERVICE: &str = "simpaas.gleroy.dev/service";

// Types

pub type Result<T = ()> = std::result::Result<T, Error>;

// Errors

#[derive(Debug, thiserror::Error)]
#[error("kubernetes error: {0}")]
pub struct Error(#[source] pub Box<dyn std::error::Error + Send + Sync>);

// Data structs

#[derive(Clone, Debug)]
pub struct AppFilter {
    pub name: Regex,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DomainUsage {
    /// App that owns domain.
    pub app: Option<String>,
    /// Domain.
    pub domain: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServicePod {
    pub name: String,
    pub status: ServicePodStatus,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServicePodStatus {
    Running,
    Stopped,
}

// Events

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AppEvent {
    Deployed,
    Deploying,
    DeploymentFailed(String),
    MonitoringFailed(String),
    Undeploying,
    UndeploymentFailed(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InvitationEvent {
    SendingFailed(String),
    Sent,
}

// Traits

pub trait KubeClient: Send + Sync {
    fn delete_app(&self, name: &str) -> impl Future<Output = Result> + Send;

    fn delete_invitation(&self, token: &str) -> impl Future<Output = Result> + Send;

    fn delete_namespace(&self, namespace: &str) -> impl Future<Output = Result> + Send;

    fn domain_usages(
        &self,
        name: &str,
        svcs: &[ContainerService],
    ) -> impl Future<Output = Result<Vec<DomainUsage>>> + Send;

    fn get_app(&self, name: &str) -> impl Future<Output = Result<Option<App>>> + Send;

    fn get_invitation(
        &self,
        token: &str,
    ) -> impl Future<Output = Result<Option<Invitation>>> + Send;

    fn get_role(&self, name: &str) -> impl Future<Output = Result<Option<Role>>> + Send;

    fn get_user(&self, name: &str) -> impl Future<Output = Result<Option<User>>> + Send;

    fn list_apps(
        &self,
        filter: &AppFilter,
        username: &str,
        user: &User,
    ) -> impl Future<Output = Result<Vec<App>>> + Send;

    fn list_service_pods(
        &self,
        app: &str,
        service: &str,
    ) -> impl Future<Output = Result<Vec<ServicePod>>> + Send;

    fn patch_app(&self, name: &str, app: &App) -> impl Future<Output = Result> + Send;

    fn patch_app_status(
        &self,
        name: &str,
        status: &AppStatus,
    ) -> impl Future<Output = Result> + Send;

    fn patch_invitation(
        &self,
        token: &str,
        invit: &Invitation,
    ) -> impl Future<Output = Result> + Send;

    fn patch_invitation_status(
        &self,
        token: &str,
        status: &InvitationStatus,
    ) -> impl Future<Output = Result> + Send;

    fn patch_user(&self, name: &str, user: &User) -> impl Future<Output = Result> + Send;

    fn user_has_permission(
        &self,
        user: &User,
        action: Action,
    ) -> impl Future<Output = Result<bool>> + Send;

    fn user_permissions(
        &self,
        user: &User,
    ) -> impl Future<Output = Result<HashSet<Permission>>> + Send;
}

pub trait KubeEventPublisher: Send + Sync {
    fn publish_app_event(&self, app: &App, event: AppEvent) -> impl Future<Output = ()> + Send;

    fn publish_invitation_event(
        &self,
        invit: &Invitation,
        event: InvitationEvent,
    ) -> impl Future<Output = ()> + Send;
}

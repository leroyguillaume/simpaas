use futures::Future;

use crate::domain::{Action, App, Invitation, Role, Service, User};

pub mod api;

pub const FINALIZER: &str = "simpaas.gleroy.dev/finalizer";

pub type Result<T = ()> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
#[error("kubernetes error: {0}")]
pub struct Error(#[source] pub Box<dyn std::error::Error + Send + Sync>);

pub struct DomainUsage {
    /// App that owns domain.
    pub app: Option<String>,
    /// Domain.
    pub domain: String,
}

pub trait KubeClient: Send + Sync {
    fn delete_app(&self, name: &str) -> impl Future<Output = Result> + Send;

    fn delete_invitation(&self, token: &str) -> impl Future<Output = Result> + Send;

    fn delete_namespace(&self, namespace: &str) -> impl Future<Output = Result> + Send;

    fn domain_usages(
        &self,
        name: &str,
        svcs: &[Service],
    ) -> impl Future<Output = Result<Vec<DomainUsage>>> + Send;

    fn get_app(&self, name: &str) -> impl Future<Output = Result<Option<App>>> + Send;

    fn get_invitation(
        &self,
        token: &str,
    ) -> impl Future<Output = Result<Option<Invitation>>> + Send;

    fn get_role(&self, name: &str) -> impl Future<Output = Result<Option<Role>>> + Send;

    fn get_user(&self, name: &str) -> impl Future<Output = Result<Option<User>>> + Send;

    fn patch_app(&self, name: &str, app: &App) -> impl Future<Output = Result> + Send;

    fn patch_invitation(
        &self,
        token: &str,
        invit: &Invitation,
    ) -> impl Future<Output = Result> + Send;

    fn patch_user(&self, name: &str, user: &User) -> impl Future<Output = Result> + Send;

    fn user_has_permission(
        &self,
        user: &User,
        action: Action,
    ) -> impl Future<Output = Result<bool>> + Send;
}

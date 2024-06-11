use std::{
    collections::{BTreeSet, HashSet},
    fmt::{Display, Formatter},
};

use futures::Future;
use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use serde_trim::string_trim;
use validator::Validate;

pub mod api;

pub type Result<T = ()> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
#[error("kubernetes error: {0}")]
pub struct Error(#[source] pub Box<dyn std::error::Error + Send + Sync>);

#[derive(Clone, CustomResource, Debug, Deserialize, Eq, PartialEq, JsonSchema, Serialize)]
#[kube(
    group = "simpaas.gleroy.dev",
    version = "v1",
    kind = "App",
    doc = "SimPaaS application",
    plural = "apps",
    namespaced
)]
#[serde(rename_all = "camelCase")]
pub struct AppSpec {
    /// Chart to use to install app.
    pub chart: Chart,
    /// Namespace.
    pub namespace: String,
    /// Release name.
    pub release: String,
    /// List of app services.
    pub services: Vec<Service>,
    /// Helm chart values.
    #[serde(default)]
    pub values: Map<String, Value>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, JsonSchema, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Chart {
    /// Built-in chart.
    BuiltIn {},
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, JsonSchema, Serialize, Validate)]
#[serde(rename_all = "camelCase")]
pub struct Expose {
    /// If specified, an ingress will be created to expose the service. If not specified, the serive is only exposes locally.
    #[validate(nested)]
    pub ingress: Option<Ingress>,
    /// The port to expose.
    pub port: u16,
    #[serde(default = "default_protocol", deserialize_with = "string_trim")]
    #[validate(length(min = 1))]
    pub protocol: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, JsonSchema, Serialize, Validate)]
#[serde(rename_all = "camelCase")]
pub struct Ingress {
    /// Domain part of URL.
    #[serde(deserialize_with = "string_trim")]
    #[validate(length(min = 3))]
    pub domain: String,
    /// True if TLS is enabled.
    #[serde(default)]
    pub tls: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, JsonSchema, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Permission {
    /// Allow role to create app.
    CreateApp {},
    /// Allow role to invite users.
    InviteUsers {},
}

impl Permission {
    pub fn allows(&self, perm: &Self) -> bool {
        match self {
            Self::CreateApp {} => matches!(perm, Self::CreateApp {}),
            Self::InviteUsers {} => matches!(perm, Self::InviteUsers {}),
        }
    }
}

impl Display for Permission {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match self {
            Self::CreateApp {} => write!(f, "create_app"),
            Self::InviteUsers {} => write!(f, "invite_users"),
        }
    }
}

#[derive(Clone, CustomResource, Debug, Deserialize, Eq, PartialEq, JsonSchema, Serialize)]
#[kube(
    group = "simpaas.gleroy.dev",
    version = "v1",
    kind = "Invitation",
    doc = "SimPaaS user invitation",
    plural = "invitations",
    namespaced
)]
#[serde(rename_all = "camelCase")]
pub struct InvitationSpec {
    /// User who created the invitation.
    pub from: String,
    /// User roles.
    pub roles: BTreeSet<String>,
    /// Invited user email.
    pub to: String,
}

#[derive(Clone, CustomResource, Debug, Deserialize, Eq, PartialEq, JsonSchema, Serialize)]
#[kube(
    group = "simpaas.gleroy.dev",
    version = "v1",
    kind = "Role",
    doc = "SimPaaS user role",
    plural = "roles",
    namespaced
)]
#[serde(rename_all = "camelCase")]
pub struct RoleSpec {
    /// Role permissions.
    #[serde(default)]
    pub permissions: HashSet<Permission>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, JsonSchema, Serialize, Validate)]
#[serde(rename_all = "camelCase")]
pub struct Service {
    /// List of ports to expose.
    #[serde(default)]
    #[validate(nested)]
    pub expose: Vec<Expose>,
    /// Image repository.
    #[serde(deserialize_with = "string_trim")]
    #[validate(length(min = 1))]
    pub image: String,
    /// Service name.
    #[serde(deserialize_with = "string_trim")]
    #[validate(length(min = 1))]
    pub name: String,
    /// Replicas.
    #[serde(default = "default_replicas")]
    pub replicas: u16,
    /// Image tag.
    #[serde(default = "default_tag", deserialize_with = "string_trim")]
    #[validate(length(min = 1))]
    pub tag: String,
    /// Helm chart values.
    #[serde(default)]
    pub values: Map<String, Value>,
}

#[derive(Clone, CustomResource, Debug, Deserialize, Eq, PartialEq, JsonSchema, Serialize)]
#[kube(
    group = "simpaas.gleroy.dev",
    version = "v1",
    kind = "User",
    doc = "SimPaaS user",
    plural = "users",
    namespaced
)]
#[serde(rename_all = "camelCase")]
pub struct UserSpec {
    /// Email.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// BCrypt-encoded password.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    /// User roles.
    #[serde(default)]
    pub roles: BTreeSet<String>,
}

pub trait KubeClient: Send + Sync {
    fn delete_invitation(&self, token: &str) -> impl Future<Output = Result> + Send;

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
        perm: &Permission,
    ) -> impl Future<Output = Result<bool>> + Send;
}

fn default_protocol() -> String {
    "TCP".into()
}

fn default_replicas() -> u16 {
    1
}

fn default_tag() -> String {
    "latest".into()
}

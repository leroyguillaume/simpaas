use std::{
    collections::{BTreeSet, HashSet},
    fmt::{Display, Formatter},
};

use kube::CustomResource;
use regex::Regex;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use serde_trim::string_trim;
use validator::Validate;

const PERM_CREATE_APP: &str = "createApp";
const PERM_DELETE_APP: &str = "deleteApp";
const PERM_INVITE_USERS: &str = "inviteUsers";
const PERM_READ_APP: &str = "readApp";
const PERM_UPDATE_APP: &str = "updateApp";

#[derive(Debug, thiserror::Error)]
#[error("regex error: {0}")]
pub struct PermissionError(
    #[from]
    #[source]
    pub regex::Error,
);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Action<'a> {
    CreateApp,
    DeleteApp(&'a str),
    InviteUsers,
    ReadApp(&'a str),
    UpdateApp(&'a str),
}

impl Display for Action<'_> {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match self {
            Self::CreateApp => write!(f, "{PERM_CREATE_APP}"),
            Self::DeleteApp(pattern) => write!(f, "{PERM_DELETE_APP}(`{pattern}`)"),
            Self::InviteUsers => write!(f, "{PERM_INVITE_USERS}"),
            Self::ReadApp(pattern) => write!(f, "{PERM_READ_APP}(`{pattern}`)"),
            Self::UpdateApp(pattern) => write!(f, "{PERM_UPDATE_APP}(`{pattern}`)"),
        }
    }
}

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
    /// Namespace.
    pub namespace: String,
    /// Owner of the app.
    pub owner: String,
    /// List of app services.
    pub services: Vec<Service>,
    /// Helm chart values.
    #[serde(default)]
    pub values: Map<String, Value>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, JsonSchema, Serialize, Validate)]
#[serde(rename_all = "camelCase")]
pub struct Expose {
    /// If specified, an ingress will be created to expose the service. If not specified, the serive is only exposes locally.
    #[validate(nested)]
    pub ingress: Option<Ingress>,
    /// The port to expose.
    pub port: u16,
    /// The protocol.
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
    /// Allow role to delete app.
    DeleteApp {
        /// Pattern that matches app name.
        #[serde(default = "default_perm_pattern")]
        name: String,
    },
    /// Allow role to invite users.
    InviteUsers {},
    /// Allow role to read app.
    ReadApp {
        /// Pattern that matches app name.
        #[serde(default = "default_perm_pattern")]
        name: String,
    },
    /// Allow roel to update app.
    UpdateApp {
        /// Pattern that matches app name.
        #[serde(default = "default_perm_pattern")]
        name: String,
    },
}

impl Permission {
    pub fn allows(&self, action: Action) -> Result<bool, PermissionError> {
        match self {
            Self::CreateApp {} => Ok(matches!(action, Action::CreateApp)),
            Self::DeleteApp { name: pattern } => {
                if let Action::DeleteApp(name) = action {
                    Self::name_matches(name, pattern)
                } else {
                    Ok(false)
                }
            }
            Self::InviteUsers {} => Ok(matches!(action, Action::InviteUsers)),
            Self::ReadApp { name: pattern } => {
                if let Action::ReadApp(name) = action {
                    Self::name_matches(name, pattern)
                } else {
                    Ok(false)
                }
            }
            Self::UpdateApp { name: pattern } => {
                if let Action::UpdateApp(name) = action {
                    Self::name_matches(name, pattern)
                } else {
                    Ok(false)
                }
            }
        }
    }

    fn name_matches(name: &str, pattern: &str) -> Result<bool, PermissionError> {
        let regex = Regex::new(pattern)?;
        Ok(regex.is_match(name))
    }
}

impl Display for Permission {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match self {
            Self::CreateApp {} => write!(f, "{PERM_CREATE_APP}"),
            Self::DeleteApp { name } => write!(f, "{PERM_DELETE_APP}(`{name}`)"),
            Self::InviteUsers {} => write!(f, "{PERM_INVITE_USERS}"),
            Self::ReadApp { name } => write!(f, "{PERM_READ_APP}(`{name}`)"),
            Self::UpdateApp { name } => write!(f, "{PERM_UPDATE_APP}(`{name}`)"),
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
    namespaced,
    status = "InvitationStatus"
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

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, JsonSchema, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InvitationStatus {
    /// True if email was sent.
    pub email_sent: bool,
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
    pub email: Option<String>,
    /// BCrypt-encoded password.
    pub password: Option<String>,
    /// User roles.
    #[serde(default)]
    pub roles: BTreeSet<String>,
}

fn default_perm_pattern() -> String {
    r".*".into()
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

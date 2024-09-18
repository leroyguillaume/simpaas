use std::{collections::BTreeSet, fmt::Debug};

use ::kube::CustomResource;
use enum_display::EnumDisplay;
use schemars::{gen::SchemaGenerator, schema::Schema, JsonSchema};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

// Mods

pub mod kube;
pub mod process;
pub mod tracer;

// Specs

#[derive(Clone, CustomResource, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[kube(
    group = "simpaas.gleroy.dev",
    version = "v1",
    kind = "Application",
    doc = "An application",
    plural = "applications",
    namespaced,
    shortname = "app",
    status = "DeployableStatus"
)]
#[serde(rename_all = "camelCase")]
pub struct ApplicationSpec {
    #[serde(default)]
    pub containers: Vec<Container>,
    #[serde(default = "default_monitor_delay")]
    pub monitor_delay: u32,
    #[serde(default)]
    pub tls_domains: BTreeSet<String>,
}

impl Default for ApplicationSpec {
    fn default() -> Self {
        Self {
            containers: vec![],
            monitor_delay: default_monitor_delay(),
            tls_domains: Default::default(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Chart {
    pub name: String,
    pub values: String,
    pub version: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Container {
    #[serde(default)]
    pub exposes: Vec<Exposition>,
    pub image: String,
    pub name: String,
    pub tag: String,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DatabaseConsumable {
    pub creation_job: String,
    pub drop_job: String,
    pub host: String,
    #[serde(default = "default_database_password_secret")]
    pub password_secret: SecretRef,
    pub port: u32,
}

#[derive(Clone, CustomResource, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[kube(
    group = "simpaas.gleroy.dev",
    version = "v1",
    kind = "Database",
    doc = "A database",
    plural = "databases",
    namespaced,
    shortname = "db",
    status = "DatabaseStatus"
)]
#[serde(rename_all = "camelCase")]
pub struct DatabaseSpec {
    #[schemars(schema_with = "property_immutable_string")]
    pub database: String,
    #[schemars(schema_with = "property_immutable_selector")]
    pub instance: Selector,
    #[schemars(schema_with = "property_immutable_string")]
    pub user: String,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Exposition {
    pub ingress: Option<Ingress>,
    pub port: u16,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Ingress {
    pub domain: String,
    #[serde(default = "default_ingress_path")]
    pub path: String,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SecretRef {
    pub key: String,
    pub name: String,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Selector {
    pub name: String,
    pub namespace: String,
}

#[derive(Clone, CustomResource, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[kube(
    group = "simpaas.gleroy.dev",
    version = "v1",
    kind = "Service",
    doc = "A service",
    plural = "services",
    namespaced,
    shortname = "svc"
)]
#[serde(rename_all = "camelCase")]
pub struct ServiceSpec {
    pub chart: Chart,
    #[serde(default)]
    pub consumes: ServiceConsumable,
    #[serde(default = "default_monitor_delay")]
    pub monitor_delay: u32,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceConsumable {
    pub database: Option<DatabaseConsumable>,
}

#[derive(Clone, CustomResource, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[kube(
    group = "simpaas.gleroy.dev",
    version = "v1",
    kind = "ServiceInstance",
    doc = "An instance of a service",
    plural = "serviceinstances",
    namespaced,
    shortname = "svcinst",
    status = "DeployableStatus"
)]
#[serde(rename_all = "camelCase")]
pub struct ServiceInstanceSpec {
    #[serde(default)]
    pub values: Map<String, Value>,
    #[schemars(schema_with = "property_immutable_string")]
    pub service: String,
}

// Statuses

#[derive(Clone, Copy, Debug, Deserialize, EnumDisplay, Eq, JsonSchema, PartialEq, Serialize)]
pub enum DatabaseStatus {
    Created,
    Creating,
    CreationFailed,
    DropFailed,
    Dropping,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, EnumDisplay, Eq, JsonSchema, PartialEq, Serialize)]
pub enum DeployableStatus {
    Healthy,
    Degraded,
    Deploying,
    DeploymentFailed,
    UndeploymentFailed,
    Unknown,
}

// Defaults

fn default_database_password_secret() -> SecretRef {
    SecretRef {
        key: "password".into(),
        name: "db-creds-{{ name }}".into(),
    }
}

fn default_ingress_path() -> String {
    "/".into()
}

fn default_monitor_delay() -> u32 {
    30
}

// Properties

fn property_immutable_selector(gen: &mut SchemaGenerator) -> Schema {
    property_immutable::<Selector>(gen)
}

fn property_immutable_string(gen: &mut SchemaGenerator) -> Schema {
    property_immutable::<String>(gen)
}

fn property_immutable<TYPE: JsonSchema>(gen: &mut SchemaGenerator) -> Schema {
    let schema = serde_json::to_value(gen.subschema_for::<TYPE>()).unwrap();
    println!("{schema:#?}");
    let mut schema = match schema {
        Value::Object(schema) => schema,
        _ => unreachable!(),
    };
    schema.insert(
        "x-kubernetes-validations".into(),
        json!([
            {
                "rule": "self == oldSelf",
            },
        ]),
    );
    serde_json::from_value(Value::Object(schema)).unwrap()
}

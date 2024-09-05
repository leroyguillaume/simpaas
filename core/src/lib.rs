use std::fmt::Debug;

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
    kind = "Service",
    doc = "A service",
    plural = "services",
    namespaced,
    shortname = "svc"
)]
#[serde(rename_all = "camelCase")]
pub struct ServiceSpec {
    pub chart: String,
    #[serde(default = "default_monitor_delay")]
    pub monitor_delay: u32,
    pub values: String,
    pub version: Option<String>,
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
    #[schemars(schema_with = "property_immutable")]
    pub service: String,
}

// Statuses

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

fn default_monitor_delay() -> u32 {
    30
}

// Properties

fn property_immutable(_: &mut SchemaGenerator) -> Schema {
    serde_json::from_value(json!({
        "type": "string",
        "x-kubernetes-validations": [
            {
                "rule": "self == oldSelf",
            },
        ],
    }))
    .unwrap()
}

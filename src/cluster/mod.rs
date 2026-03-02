mod builder;
mod client;
mod provider;

pub use builder::*;
pub use client::KubernetesClient;
pub use provider::*;

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(CustomResource, Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[kube(group = "example.dev", version = "v1", kind = "DummyCRD", namespaced)]
pub struct DummyCRDSpec {
    pub info: String,
}

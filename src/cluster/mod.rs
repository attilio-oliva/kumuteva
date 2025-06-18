mod builder;
mod client;
mod provider;

pub use builder::*;
pub use client::KubernetesClient;
pub use provider::*;

use k8s_openapi::api::core::v1::{Container, Pod, PodSpec};
use kube::api::ObjectMeta;
use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::sync::LazyLock;
pub static NGINX_POD: LazyLock<Pod> = LazyLock::new(|| Pod {
    metadata: ObjectMeta {
        name: Some(String::from("nginx-pod")),
        ..Default::default()
    },
    spec: Some(PodSpec {
        containers: vec![Container {
            name: String::from("nginx-container"),
            image: Some(String::from("nginx")),
            ..Default::default()
        }],
        ..Default::default()
    }),
    ..Default::default()
});

#[derive(CustomResource, Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[kube(group = "example.dev", version = "v1", kind = "DummyCRD", namespaced)]
pub struct DummyCRDSpec {
    pub info: String,
}

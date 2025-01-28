mod builder;
mod kind;
mod kubernetes;

pub use kind::KindCluster;
pub use kubernetes::KubernetesCluster;

use k8s_openapi::api::core::v1::{Container, Pod, PodSpec};
use kube::api::ObjectMeta;
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

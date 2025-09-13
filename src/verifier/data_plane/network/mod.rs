mod network_autonomy;
mod network_isolation;

pub use network_autonomy::*;
pub use network_isolation::*;

use k8s_openapi::api::core::v1::{Pod, Service};
use std::sync::LazyLock;

const NETWORK_MULTITOOL_IMAGE: &str = "wbitt/network-multitool";
const NETWORK_MULTITOOL_POD_NAME: &str = "network-multitool";
static NETWORK_MULTITOOL_POD: LazyLock<Pod> = LazyLock::new(|| {
    serde_json::from_value(serde_json::json!(
    {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": NETWORK_MULTITOOL_POD_NAME,
        },
        "spec": {
            "containers": [
                {
                    "name": NETWORK_MULTITOOL_POD_NAME,
                    "image": NETWORK_MULTITOOL_IMAGE,
                    "ports": [
                        {
                            "containerPort": 80,
                        }
                    ],
                }
            ]
        }
    }
    ))
    .unwrap()
});

static WEBSERVER_SERVICE: LazyLock<Service> = LazyLock::new(|| {
    serde_json::from_value(serde_json::json!(
    {
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {
            "name": "tenant-service",
        },
        "spec": {
            "selector": {
                "app": "tenant-service",
            },
            "ports": [
                {
                    "protocol": "TCP",
                    "port": 80,
                    "targetPort": 80,
                }
            ],
            "type": "ClusterIP",
        }
    }
    ))
    .unwrap()
});

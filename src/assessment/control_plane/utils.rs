use crate::assessment::control_plane::KubernetesObject;
use anyhow::Result;

/// Create a minimal valid Kubernetes object of the specified kind with the given name and namespace.
pub(super) fn create_minimal_object(
    object_kind: &KubernetesObject,
    object_name: &str,
    namespace: &str,
) -> Result<serde_json::Value> {
    let mut base_object = serde_json::json!({
        "apiVersion": object_kind.api_version(),
        "kind": object_kind.kind(),
        "metadata": {
            "name": object_name,
        }
    });

    // Add namespace if required
    if object_kind.is_namespaced() {
        base_object["metadata"]["namespace"] = serde_json::Value::String(namespace.to_string());
    }

    // Add kind-specific required fields
    match object_kind {
        KubernetesObject::Pod => {
            base_object["spec"] = serde_json::json!({
                "containers": [{
                    "name": "test-container",
                    "image": "nginx:latest"
                }]
            });
        }
        KubernetesObject::Deployment => {
            base_object["spec"] = serde_json::json!({
                "replicas": 1,
                "selector": {
                    "matchLabels": {
                        "app": object_name
                    }
                },
                "template": {
                    "metadata": {
                        "labels": {
                            "app": object_name
                        }
                    },
                    "spec": {
                        "containers": [{
                            "name": "test-container",
                            "image": "nginx:latest"
                        }]
                    }
                }
            });
        }
        KubernetesObject::Service => {
            base_object["spec"] = serde_json::json!({
                "selector": {
                    "app": object_name
                },
                "ports": [{
                    "protocol": "TCP",
                    "port": 80,
                    "targetPort": 8080
                }]
            });
        }
        KubernetesObject::ConfigMap => {
            base_object["data"] = serde_json::json!({
                "key": "value"
            });
        }
        KubernetesObject::Secret => {
            base_object["type"] = serde_json::Value::String("Opaque".to_string());
            base_object["data"] = serde_json::json!({
                "key": "dmFsdWU=" // base64 encoded "value"
            });
        }

        KubernetesObject::DaemonSet => {
            base_object["spec"] = serde_json::json!({
                "selector": {
                    "matchLabels": {
                        "app": object_name
                    }
                },
                "template": {
                    "metadata": {
                        "labels": {
                            "app": object_name
                        }
                    },
                    "spec": {
                        "containers": [{
                            "name": "test-container",
                            "image": "nginx:latest"
                        }]
                    }
                }
            });
        }

        KubernetesObject::PersistentVolumeClaim => {
            base_object["spec"] = serde_json::json!({
                "accessModes": ["ReadWriteOnce"],
                "resources": {
                    "requests": {
                        "storage": "1Gi"
                    }
                },

            });
        }

        KubernetesObject::PersistentVolume => {
            // Use hostPath type - the path doesn't need to exist on the API server
            // as we're just testing authorization, not actually mounting volumes
            base_object["spec"] = serde_json::json!({
                "capacity": {
                    "storage": "1Gi"
                },
                "accessModes": ["ReadWriteOnce"],
                "persistentVolumeReclaimPolicy": "Retain",
                "hostPath": {
                    "path": format!("/tmp/test-pv-{}", object_name)
                }
            });
        }

        KubernetesObject::ReplicaSet => {
            base_object["spec"] = serde_json::json!({
                "replicas": 1,
                "selector": {
                    "matchLabels": {
                        "app": object_name
                    }
                },
                "template": {
                    "metadata": {
                        "labels": {
                            "app": object_name
                        }
                    },
                    "spec": {
                        "containers": [{
                            "name": "test-container",
                            "image": "nginx:latest"
                        }]
                    }
                }
            });
        }

        KubernetesObject::StatefulSet => {
            base_object["spec"] = serde_json::json!({
                "serviceName": object_name,
                "replicas": 1,
                "selector": {
                    "matchLabels": {
                        "app": object_name
                    }
                },
                "template": {
                    "metadata": {
                        "labels": {
                            "app": object_name
                        }
                    },
                    "spec": {
                        "containers": [{
                            "name": "test-container",
                            "image": "nginx:latest"
                        }]
                    }
                },
                "volumeClaimTemplates": [{
                    "metadata": {
                        "name": object_name
                    },
                    "spec": {
                        "accessModes": ["ReadWriteOnce"],
                        "resources": {
                            "requests": {
                                "storage": "1Gi"
                            }
                        }
                    }
                }]
            });
        }

        KubernetesObject::Ingress => {
            base_object["spec"] = serde_json::json!({
                "rules": [{
                    "host": format!("{}.example.com", object_name),
                    "http": {
                        "paths": [{
                            "path": "/",
                            "pathType": "Prefix",
                            "backend": {
                                "service": {
                                    "name": object_name,
                                    "port": {
                                        "number": 80
                                    }
                                }
                            }
                        }]
                    }
                }]
            });
        }

        KubernetesObject::HorizontalPodAutoscaler => {
            base_object["spec"] = serde_json::json!({
                "scaleTargetRef": {
                    "apiVersion": object_kind.api_version(),
                    "kind": object_kind.kind(),
                    "name": object_name
                },
                "minReplicas": 1,
                "maxReplicas": 2,
                "targetCPUUtilizationPercentage": 50
            });
        }

        KubernetesObject::RoleBinding => {
            base_object["roleRef"] = serde_json::json!({
                "apiGroup": "rbac.authorization.k8s.io",
                "kind": "Role",
                "name": object_name
            });
            base_object["subjects"] = serde_json::json!([{
                "kind": "User",
                "name": "test-user",
                "apiGroup": "rbac.authorization.k8s.io"
            }]);
        }

        KubernetesObject::ClusterRoleBinding => {
            base_object["roleRef"] = serde_json::json!({
                "apiGroup": "rbac.authorization.k8s.io",
                "kind": "ClusterRole",
                "name": object_name
            });
            base_object["subjects"] = serde_json::json!([{
                "kind": "User",
                "name": "test-user",
                "apiGroup": "rbac.authorization.k8s.io"
            }]);
        }

        KubernetesObject::Job => {
            base_object["spec"] = serde_json::json!({
                "template": {
                    "metadata": {
                        "labels": {
                            "job-name": object_name
                        }
                    },
                    "spec": {
                        "containers": [{
                            "name": "test-container",
                            "image": "nginx:latest"
                        }],
                        "restartPolicy": "Never"
                    }
                }
            });
        }

        KubernetesObject::CronJob => {
            base_object["spec"] = serde_json::json!({
                "schedule": "*/5 * * * *",
                "jobTemplate": {
                    "spec": {
                        "template": {
                            "metadata": {
                                "labels": {
                                    "job-name": object_name
                                }
                            },
                            "spec": {
                                "containers": [{
                                    "name": "test-container",
                                    "image": "nginx:latest"
                                }],
                                "restartPolicy": "Never"
                            }
                        }
                    }
                }
            });
        }

        KubernetesObject::StorageClass => {
            base_object["provisioner"] =
                serde_json::Value::String("kubernetes.io/no-provisioner".to_string());
            // no-provisioner doesn't require any parameters
            base_object["volumeBindingMode"] =
                serde_json::Value::String("WaitForFirstConsumer".to_string());
        }

        KubernetesObject::IngressClass => {
            // IngressClass only requires controller field
            base_object["spec"] = serde_json::json!({
                "controller": "k8s.io/ingress-nginx"
            });
        }

        KubernetesObject::NetworkPolicy => {
            base_object["spec"] = serde_json::json!({
                "podSelector": {
                    "matchLabels": {
                        "app": object_name
                    }
                },
                "policyTypes": ["Ingress", "Egress"],
                "ingress": [{
                    "from": [{
                        "podSelector": {
                            "matchLabels": {
                                "app": object_name
                            }
                        }
                    }]
                }],
                "egress": [{
                    "to": [{
                        "podSelector": {
                            "matchLabels": {
                                "app": object_name
                            }
                        }
                    }]
                }]
            });
        }

        // Add more specific cases as needed
        _ => {
            // For other resources, the base object should be sufficient
        }
    }

    Ok(base_object)
}

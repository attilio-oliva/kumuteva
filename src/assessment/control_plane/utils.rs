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
                    "image": "nginx:latest",
                    "resources": {
                        "requests": {
                            "memory": "64Mi",
                            "cpu": "250m"
                        },
                        "limits": {
                            "memory": "128Mi",
                            "cpu": "500m"
                        }
                    }
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
                            "image": "nginx:latest",
                            "resources": {
                                "requests": {
                                    "memory": "64Mi",
                                    "cpu": "250m"
                                },
                                "limits": {
                                    "memory": "128Mi",
                                    "cpu": "500m"
                                }
                            }
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
            // Bind a ClusterRole that exists, rather than a Role named after
            // this binding — which is never created, so the reference cannot be
            // resolved.
            //
            // Kubernetes refuses a binding whose referenced role it cannot read,
            // because it cannot then run the privilege-escalation check that
            // says the creator already holds everything being granted. The
            // result is a 403 whatever the tenant's real rights are, which this
            // assessment recorded as "operation not authorized" and hence as
            // zero autonomy. kubectl-mtb, creating a well-formed binding,
            // finds the same tenant can create RoleBindings perfectly well.
            //
            // `view` is a default ClusterRole present on every cluster, and
            // binding it is the ordinary self-service operation a tenant owner
            // is expected to be able to perform.
            base_object["roleRef"] = serde_json::json!({
                "apiGroup": "rbac.authorization.k8s.io",
                "kind": "ClusterRole",
                "name": "view"
            });
            base_object["subjects"] = serde_json::json!([{
                "kind": "User",
                "name": "test-user",
                "apiGroup": "rbac.authorization.k8s.io"
            }]);
        }

        KubernetesObject::ClusterRoleBinding => {
            // Same defect as RoleBinding above: the referenced ClusterRole was
            // named after the binding and never created, so the reference could
            // not resolve and the API server refused it for that reason rather
            // than on the tenant's permissions.
            base_object["roleRef"] = serde_json::json!({
                "apiGroup": "rbac.authorization.k8s.io",
                "kind": "ClusterRole",
                "name": "view"
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

        // A Node object with no kubelet behind it never reports Ready, so the
        // scheduler would ignore it anyway. `unschedulable` says so outright
        // rather than relying on that: this node exists for a few seconds to be
        // created and deleted, and a tenant workload landing on a machine that
        // does not exist would be a bad way to discover the assumption was
        // wrong.
        KubernetesObject::Node => {
            base_object["spec"] = serde_json::json!({ "unschedulable": true });
        }

        // Add more specific cases as needed
        _ => {
            // For other resources, the base object should be sufficient
        }
    }

    Ok(base_object)
}

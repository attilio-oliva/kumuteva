use k8s_openapi::{NamespaceResourceScope, Resource};

/// Macro to define Kubernetes object kinds with their k8s-openapi mappings
macro_rules! define_kubernetes_objects {
    ($(
        $variant:ident => $resource_type:ty,
    )*) => {
        #[derive(Debug, Clone, PartialEq, Eq, Hash)]
        pub enum KubernetesObject {
            $(
                $variant,
            )*
        }

        impl KubernetesObject {
            /// Returns true if this resource type is namespaced
            pub fn is_namespaced(&self) -> bool {
                match self {
                    $(
                        Self::$variant => {
                            std::any::TypeId::of::<<$resource_type as Resource>::Scope>()
                                == std::any::TypeId::of::<NamespaceResourceScope>()
                        },
                    )*
                }
            }

            /// Returns the API version for this resource
            pub fn api_version(&self) -> &'static str {
                match self {
                    $(
                        Self::$variant => <$resource_type as Resource>::API_VERSION,
                    )*
                }
            }

            /// Returns the group for this resource
            pub fn group(&self) -> &'static str {
                match self {
                    $(
                        Self::$variant => <$resource_type as Resource>::GROUP,
                    )*
                }
            }

            /// Returns the kind for this resource
            pub fn kind(&self) -> &'static str {
                match self {
                    $(
                        Self::$variant => <$resource_type as Resource>::KIND,
                    )*
                }
            }

            /// Returns the version for this resource
            pub fn version(&self) -> &'static str {
                match self {
                    $(
                        Self::$variant => <$resource_type as Resource>::VERSION,
                    )*
                }
            }

            /// Returns the URL path segment for this resource
            pub fn url_path_segment(&self) -> &'static str {
                match self {
                    $(
                        Self::$variant => <$resource_type as Resource>::URL_PATH_SEGMENT,
                    )*
                }
            }

            /// Returns all supported Kubernetes objects
            pub fn all() -> Vec<Self> {
                vec![
                    $(
                        Self::$variant,
                    )*
                ]
            }

            /// Returns only namespaced resources
            pub fn namespaced_resources() -> Vec<Self> {
                Self::all().into_iter().filter(|obj| obj.is_namespaced()).collect()
            }

            /// Returns only cluster-scoped resources
            pub fn cluster_scoped_resources() -> Vec<Self> {
                Self::all().into_iter().filter(|obj| !obj.is_namespaced()).collect()
            }
        }

        $(
            impl From<&$resource_type> for KubernetesObject {
                fn from(_: &$resource_type) -> Self {
                    Self::$variant
                }
            }

            impl From<$resource_type> for KubernetesObject {
                fn from(_: $resource_type) -> Self {
                    Self::$variant
                }
            }
        )*

    };
}

// Convert the old ObjectKind struct to use the new enum
impl From<KubernetesObject> for super::ObjectKind {
    fn from(obj: KubernetesObject) -> Self {
        Self {
            api_version: obj.api_version().to_string(),
            kind: obj.kind().to_string(),
            namespaced: obj.is_namespaced(),
        }
    }
}

impl From<super::ObjectKind> for KubernetesObject {
    fn from(kind: super::ObjectKind) -> Self {
        // This is a fallback conversion - ideally you'd use the enum directly
        match (kind.api_version.as_str(), kind.kind.as_str()) {
            ("v1", "Pod") => Self::Pod,
            ("v1", "Service") => Self::Service,
            ("v1", "ConfigMap") => Self::ConfigMap,
            ("v1", "Secret") => Self::Secret,
            ("v1", "Namespace") => Self::Namespace,
            ("apps/v1", "Deployment") => Self::Deployment,
            ("apps/v1", "ReplicaSet") => Self::ReplicaSet,
            ("apps/v1", "StatefulSet") => Self::StatefulSet,
            ("apps/v1", "DaemonSet") => Self::DaemonSet,
            ("batch/v1", "Job") => Self::Job,
            ("batch/v1", "CronJob") => Self::CronJob,
            ("networking.k8s.io/v1", "NetworkPolicy") => Self::NetworkPolicy,
            ("networking.k8s.io/v1", "Ingress") => Self::Ingress,
            ("rbac.authorization.k8s.io/v1", "Role") => Self::Role,
            ("rbac.authorization.k8s.io/v1", "RoleBinding") => Self::RoleBinding,
            ("rbac.authorization.k8s.io/v1", "ClusterRole") => Self::ClusterRole,
            ("rbac.authorization.k8s.io/v1", "ClusterRoleBinding") => Self::ClusterRoleBinding,
            _ => Self::Pod, // Default fallback
        }
    }
}

// Define all the Kubernetes objects we want to test
// Associate each object with its corresponding k8s-openapi type
define_kubernetes_objects! {
    // Core API (v1)
    Pod => k8s_openapi::api::core::v1::Pod,
    Service => k8s_openapi::api::core::v1::Service,
    ConfigMap => k8s_openapi::api::core::v1::ConfigMap,
    Secret => k8s_openapi::api::core::v1::Secret,
    PersistentVolume => k8s_openapi::api::core::v1::PersistentVolume,
    PersistentVolumeClaim => k8s_openapi::api::core::v1::PersistentVolumeClaim,
    Namespace => k8s_openapi::api::core::v1::Namespace,
    ServiceAccount => k8s_openapi::api::core::v1::ServiceAccount,
    Endpoints => k8s_openapi::api::core::v1::Endpoints,
    Event => k8s_openapi::api::core::v1::Event,
    LimitRange => k8s_openapi::api::core::v1::LimitRange,
    ResourceQuota => k8s_openapi::api::core::v1::ResourceQuota,
    Node => k8s_openapi::api::core::v1::Node,

    // Apps API (apps/v1)
    Deployment => k8s_openapi::api::apps::v1::Deployment,
    ReplicaSet => k8s_openapi::api::apps::v1::ReplicaSet,
    StatefulSet => k8s_openapi::api::apps::v1::StatefulSet,
    DaemonSet => k8s_openapi::api::apps::v1::DaemonSet,

    // Batch API (batch/v1)
    Job => k8s_openapi::api::batch::v1::Job,
    CronJob => k8s_openapi::api::batch::v1::CronJob,

    // Networking API (networking.k8s.io/v1)
    NetworkPolicy => k8s_openapi::api::networking::v1::NetworkPolicy,
    Ingress => k8s_openapi::api::networking::v1::Ingress,
    IngressClass => k8s_openapi::api::networking::v1::IngressClass,

    // RBAC API (rbac.authorization.k8s.io/v1)
    Role => k8s_openapi::api::rbac::v1::Role,
    RoleBinding => k8s_openapi::api::rbac::v1::RoleBinding,
    ClusterRole => k8s_openapi::api::rbac::v1::ClusterRole,
    ClusterRoleBinding => k8s_openapi::api::rbac::v1::ClusterRoleBinding,

    // Policy API (policy/v1)
    PodDisruptionBudget => k8s_openapi::api::policy::v1::PodDisruptionBudget,

    // Autoscaling API (autoscaling/v2)
    HorizontalPodAutoscaler => k8s_openapi::api::autoscaling::v2::HorizontalPodAutoscaler,

    // Storage API (storage.k8s.io/v1)
    StorageClass => k8s_openapi::api::storage::v1::StorageClass,
    VolumeAttachment => k8s_openapi::api::storage::v1::VolumeAttachment,

    // Extensions for custom resources can be added here
}

impl std::fmt::Display for KubernetesObject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.api_version(), self.kind())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_namespaced_detection() {
        assert!(KubernetesObject::Pod.is_namespaced());
        assert!(KubernetesObject::Service.is_namespaced());
        assert!(KubernetesObject::Deployment.is_namespaced());

        assert!(!KubernetesObject::Namespace.is_namespaced());
        assert!(!KubernetesObject::ClusterRole.is_namespaced());
        assert!(!KubernetesObject::Node.is_namespaced());
        assert!(!KubernetesObject::PersistentVolume.is_namespaced());
        assert!(!KubernetesObject::ClusterRoleBinding.is_namespaced());
        assert!(!KubernetesObject::StorageClass.is_namespaced());
    }

    #[test]
    fn test_api_version_extraction() {
        assert_eq!(KubernetesObject::Pod.api_version(), "v1");
        assert_eq!(KubernetesObject::Deployment.api_version(), "apps/v1");
        assert_eq!(
            KubernetesObject::NetworkPolicy.api_version(),
            "networking.k8s.io/v1"
        );
        assert_eq!(
            KubernetesObject::Role.api_version(),
            "rbac.authorization.k8s.io/v1"
        );
    }

    #[test]
    fn test_group_extraction() {
        assert_eq!(KubernetesObject::Pod.group(), "");
        assert_eq!(KubernetesObject::Deployment.group(), "apps");
        assert_eq!(KubernetesObject::NetworkPolicy.group(), "networking.k8s.io");
        assert_eq!(KubernetesObject::Role.group(), "rbac.authorization.k8s.io");
    }

    #[test]
    fn test_from_conversion() {
        let pod = k8s_openapi::api::core::v1::Pod::default();
        let k8s_obj: KubernetesObject = pod.into();
        assert_eq!(k8s_obj, KubernetesObject::Pod);
    }

    #[test]
    fn test_filtering() {
        let namespaced = KubernetesObject::namespaced_resources();
        let cluster_scoped = KubernetesObject::cluster_scoped_resources();

        assert!(namespaced.contains(&KubernetesObject::Pod));
        assert!(namespaced.contains(&KubernetesObject::Deployment));
        assert!(!namespaced.contains(&KubernetesObject::Namespace));

        assert!(cluster_scoped.contains(&KubernetesObject::Namespace));
        assert!(cluster_scoped.contains(&KubernetesObject::ClusterRole));
        assert!(!cluster_scoped.contains(&KubernetesObject::Pod));
    }
}

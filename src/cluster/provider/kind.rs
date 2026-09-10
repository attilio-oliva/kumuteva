use std::{fs::File, io::Write, path::Path, process::Command, str};

use anyhow::Context;
use serde_json::json;

/// Per-container log capacity for the benchmark cluster.
///
/// Sized for the storage assessment, which is by far the most verbose: 10k IOPS
/// for 60 s is ~600k fio lines, ~20 MB, and the intruder runs ten such pods.
/// 512 MB leaves room for longer phases or higher rates without revisiting this.
const CONTAINER_LOG_MAX_SIZE: &str = "512Mi";

/// Kept at the kubelet default; the size is what matters here.
const CONTAINER_LOG_MAX_FILES: u32 = 5;

use crate::cluster::{
    terminal_stderr_to_error, ClusterProfile, ClusterProvider, HostCluster, TenantsPortMapping,
};

/// Build the kind cluster definition.
///
/// Separated from `create` so the generated document can be asserted on without
/// standing up a cluster.
///
/// `profile` carries what a data-plane technology needs decided before the
/// cluster exists — see [`ClusterProfile`]. An empty profile must leave this
/// document exactly as it was before profiles existed, which the tests assert.
fn cluster_config(
    name: &str,
    tenants_port_mapping: &TenantsPortMapping,
    profile: &ClusterProfile,
) -> serde_json::Value {
    let (tenant1_mapping, tenant2_mapping) =
        (&tenants_port_mapping.tenant1, &tenants_port_mapping.tenant2);

    let mut config = json!({
        "kind": "Cluster",
        "apiVersion": "kind.x-k8s.io/v1alpha4",
        "name": name,
        "nodes": [{
            "role": "control-plane",
            "image": "kindest/node:v1.33.4@sha256:25a6018e48dfcaee478f4a59af81157a437f15e6e140bf103f85a2e7cd0cbbf2",
            // Benchmark pods report their measurements over stdout, which is
            // the only channel every multi-tenancy solution leaves open —
            // `exec` is blocked by the more restrictive ones, and those are
            // exactly the ones worth measuring.
            //
            // That makes container log capacity part of the measurement
            // apparatus. fio writes one line per I/O, so a pod at 10k IOPS
            // for 60 s emits roughly 600k lines, about 20 MB, against the
            // 10 Mi kubelet retains by default. Rotation then discards the
            // start of the stream and the pod's entire sample is lost — not
            // truncated, lost, because the parser can no longer find where
            // the log begins.
            "kubeadmConfigPatches": [
                format!(
                    "kind: KubeletConfiguration\ncontainerLogMaxSize: \"{}\"\ncontainerLogMaxFiles: {}\n",
                    CONTAINER_LOG_MAX_SIZE, CONTAINER_LOG_MAX_FILES
                )
            ],
            "extraPortMappings": [
                {
                    "containerPort": tenant1_mapping.container_port,
                    "hostPort": tenant1_mapping.host_port
                },
                {
                    "containerPort": tenant2_mapping.container_port,
                    "hostPort": tenant2_mapping.host_port
                }
            ]
        }]
    });

    // Everything below is additive: an empty profile leaves the document
    // byte-identical to what it was before profiles existed.

    if profile.disable_default_cni || profile.pod_subnet.is_some() {
        let mut networking = serde_json::Map::new();
        if profile.disable_default_cni {
            networking.insert("disableDefaultCNI".to_string(), json!(true));
        }
        if let Some(subnet) = &profile.pod_subnet {
            networking.insert("podSubnet".to_string(), json!(subnet));
        }
        config["networking"] = serde_json::Value::Object(networking);
    }

    if !profile.containerd_config_patches.is_empty() {
        // A cluster-level field in kind, not a node-level one: the patch edits
        // containerd's configuration on every node.
        config["containerdConfigPatches"] = json!(profile.containerd_config_patches);
    }

    if !profile.extra_mounts.is_empty() {
        config["nodes"][0]["extraMounts"] = json!(profile
            .extra_mounts
            .iter()
            .map(|(host, node)| json!({ "hostPath": host, "containerPath": node }))
            .collect::<Vec<_>>());
    }

    config
}

pub type KindCluster = HostCluster<KindProvider>;

#[derive(Debug, Clone)]
pub struct KindProvider;

impl ClusterProvider for KindProvider {
    async fn create(
        name: &str,
        kubeconfig_path: &Path,
        tenants_port_mapping: TenantsPortMapping,
        profile: &ClusterProfile,
    ) -> anyhow::Result<()> {
        let config_json = cluster_config(name, &tenants_port_mapping, profile);

        let yaml_config =
            serde_yaml::to_string(&config_json).context("Failed to convert JSON config to YAML")?;

        // Named after the cluster rather than a fixed `/tmp/kind-config.yaml`:
        // two campaigns running at once would otherwise overwrite each other's
        // config between writing it and kind reading it, and the loser would
        // quietly get the wrong cluster.
        let config_path = std::env::temp_dir().join(format!("kind-config-{name}.yaml"));
        let config_path = config_path.as_path();
        let mut file = File::create(config_path).context("Failed to create kind config file")?;
        file.write_all(yaml_config.as_bytes())
            .context("Failed to write kind config to file")?;

        let output = Command::new("kind")
            .arg("create")
            .arg("cluster")
            .arg("--name")
            .arg(name)
            .arg("--config")
            .arg(config_path)
            .output()
            .context("Failed to execute kind create command")?;

        if output.status.success() {
            Self::export_kubeconfig(name, kubeconfig_path).await?;
            Ok(())
        } else {
            Err(terminal_stderr_to_error(output))
        }
    }

    async fn exists(name: &str) -> anyhow::Result<bool> {
        let output = Command::new("kind")
            .arg("get")
            .arg("clusters")
            .output()
            .context("Failed to execute kind get clusters command")?;

        if output.status.success() {
            let clusters = str::from_utf8(&output.stdout)
                .context("Failed to parse kind get clusters output")?;
            Ok(clusters.contains(name))
        } else {
            Err(terminal_stderr_to_error(output))
        }
    }

    async fn export_kubeconfig(name: &str, path: &Path) -> anyhow::Result<()> {
        let output = Command::new("kind")
            .arg("get")
            .arg("kubeconfig")
            .arg("--name")
            .arg(name)
            .output()
            .context("Failed to execute kind get kubeconfig command")?;

        if output.status.success() {
            let mut file = File::create(path).context("Failed to create kubeconfig file")?;
            file.write_all(&output.stdout)
                .context("Failed to write kubeconfig to file")?;
            Ok(())
        } else {
            Err(terminal_stderr_to_error(output))
        }
    }

    async fn delete_cluster(name: &str) -> anyhow::Result<()> {
        let output = Command::new("kind")
            .arg("delete")
            .arg("cluster")
            .arg("--name")
            .arg(name)
            .output()
            .context("Failed to execute kind delete command")?;

        if output.status.success() {
            println!("Kind cluster deleted successfully");
            Ok(())
        } else {
            println!("Failed to delete Kind cluster");
            Err(terminal_stderr_to_error(output))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use crate::cluster::PortMapping;

    use super::*;

    const CLUSTER_NAME: &str = "test-cluster";
    const TEMP_KUBECONFIG_PATH: &str = "/tmp/kubeconfig";

    // Provisions a real kind cluster via Docker, so it cannot run on a clean
    // checkout or in CI. Run explicitly with `cargo test -- --ignored`.
    #[ignore]
    #[tokio::test]
    async fn test_create_and_delete_kind_cluster() {
        let dummy_port_mapping = TenantsPortMapping {
            tenant1: PortMapping {
                container_port: 31111,
                host_port: 32222,
            },
            tenant2: PortMapping {
                container_port: 33333,
                host_port: 34444,
            },
        };
        let cluster = KindCluster::create(
            CLUSTER_NAME,
            PathBuf::from(TEMP_KUBECONFIG_PATH),
            dummy_port_mapping,
            &Default::default(),
        )
        .await;

        assert!(
            cluster.is_ok(),
            "Failed to create a Kind cluster: {:?}",
            cluster.err()
        );

        let cluster = cluster.unwrap();

        // check if the new cluster exists and can be loaded
        let load_cluster =
            KindCluster::load(CLUSTER_NAME, PathBuf::from(TEMP_KUBECONFIG_PATH)).await;
        assert!(
            load_cluster.is_ok(),
            "Failed to load Kind cluster: {:?}",
            load_cluster.err()
        );

        let deletion = cluster.delete().await;
        assert!(
            deletion.is_ok(),
            "Failed to delete Kind cluster: {:?}",
            deletion.err()
        );
    }
}

#[cfg(test)]
mod config_tests {
    use super::*;
    use crate::cluster::PortMapping;

    fn mappings() -> TenantsPortMapping {
        TenantsPortMapping {
            tenant1: PortMapping {
                host_port: 30010,
                container_port: 30001,
            },
            tenant2: PortMapping {
                host_port: 30020,
                container_port: 30002,
            },
        }
    }

    /// Container log capacity is part of the measurement apparatus, not a
    /// convenience: benchmark pods report their samples over stdout because it
    /// is the only channel every multi-tenancy solution leaves open. At the
    /// kubelet default of 10 Mi the storage assessment loses whole pods, so the
    /// cluster the tool builds must raise it.
    #[test]
    fn cluster_config_raises_the_container_log_limit() {
        let config = cluster_config("bench", &mappings(), &ClusterProfile::default());
        let node = &config["nodes"][0];

        let patches = node["kubeadmConfigPatches"]
            .as_array()
            .expect("kubeadmConfigPatches must be a list of documents");
        assert_eq!(patches.len(), 1);

        let patch = patches[0].as_str().expect("a patch is a YAML string");
        assert!(patch.contains("kind: KubeletConfiguration"), "{patch}");
        assert!(patch.contains("containerLogMaxSize: \"512Mi\""), "{patch}");
        assert!(patch.contains("containerLogMaxFiles: 5"), "{patch}");

        // 20 MB per pod is what the default could not hold; the new limit must
        // clear it with room to spare.
        assert!(
            CONTAINER_LOG_MAX_SIZE.ends_with("Mi"),
            "the kubelet expects a quantity suffix"
        );
        let megabytes: u32 = CONTAINER_LOG_MAX_SIZE
            .trim_end_matches("Mi")
            .parse()
            .unwrap();
        assert!(
            megabytes >= 64,
            "{megabytes}Mi is too small for a storage run"
        );
    }

    /// kind renders the config as YAML, so the patch has to survive that trip
    /// intact — a multi-line string is where this would break.
    #[test]
    fn config_serialises_to_yaml_kind_can_read() {
        let config = cluster_config("bench", &mappings(), &ClusterProfile::default());
        let yaml = serde_yaml::to_string(&config).expect("config must serialise");

        assert!(yaml.contains("kind: Cluster"));
        assert!(yaml.contains("kubeadmConfigPatches"));
        assert!(yaml.contains("containerLogMaxSize"));

        // Round-trip it: whatever kind parses must still carry the patch.
        let parsed: serde_json::Value = serde_yaml::from_str(&yaml).expect("must re-parse");
        let patch = parsed["nodes"][0]["kubeadmConfigPatches"][0]
            .as_str()
            .expect("patch survives the YAML round trip");
        assert!(patch.contains("containerLogMaxSize"), "{patch}");
    }

    /// The guarantee the profile was introduced under: selecting no data-plane
    /// technology must build the cluster the tool built before profiles
    /// existed. Every result taken so far was taken on that cluster, so a stray
    /// key here would silently invalidate comparison against them.
    #[test]
    fn an_empty_profile_adds_nothing() {
        let config = cluster_config("bench", &mappings(), &ClusterProfile::default());

        assert!(config.get("networking").is_none(), "{config}");
        assert!(config.get("containerdConfigPatches").is_none(), "{config}");
        assert!(config["nodes"][0].get("extraMounts").is_none(), "{config}");

        // Only the keys that were always there.
        let node = config["nodes"][0].as_object().expect("a node is an object");
        let mut keys: Vec<_> = node.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            ["extraPortMappings", "image", "kubeadmConfigPatches", "role"]
        );
    }

    /// A CNI cannot be swapped after the cluster exists, so these two land in
    /// the document rather than being applied later. `disableDefaultCNI` alone
    /// leaves the cluster NotReady, which is why whatever sets it owns
    /// installing a replacement.
    #[test]
    fn a_cni_profile_reaches_the_networking_section() {
        let profile = ClusterProfile {
            disable_default_cni: true,
            pod_subnet: Some("192.168.0.0/16".to_string()),
            ..Default::default()
        };
        let config = cluster_config("bench", &mappings(), &profile);

        assert_eq!(config["networking"]["disableDefaultCNI"], true);
        assert_eq!(config["networking"]["podSubnet"], "192.168.0.0/16");
    }

    /// containerd patches are cluster-level in kind, not node-level. Putting
    /// them under `nodes[0]` would be silently ignored — kind does not reject
    /// unknown node keys — and the runtime handler would simply never exist,
    /// leaving sandboxed pods stuck in ContainerCreating.
    #[test]
    fn containerd_patches_and_mounts_land_where_kind_reads_them() {
        let profile = ClusterProfile {
            containerd_config_patches: vec!["[plugins.\"io.containerd.grpc.v1.cri\"]".to_string()],
            extra_mounts: vec![("/dev/kvm".to_string(), "/dev/kvm".to_string())],
            ..Default::default()
        };
        let config = cluster_config("bench", &mappings(), &profile);

        assert!(
            config["containerdConfigPatches"].is_array(),
            "must be a top-level key, not a node key: {config}"
        );
        assert!(config["nodes"][0].get("containerdConfigPatches").is_none());

        let mount = &config["nodes"][0]["extraMounts"][0];
        assert_eq!(mount["hostPath"], "/dev/kvm");
        assert_eq!(mount["containerPath"], "/dev/kvm");
    }

    #[test]
    fn port_mappings_are_preserved() {
        let config = cluster_config("bench", &mappings(), &ClusterProfile::default());
        let ports = &config["nodes"][0]["extraPortMappings"];
        assert_eq!(ports[0]["hostPort"], 30010);
        assert_eq!(ports[0]["containerPort"], 30001);
        assert_eq!(ports[1]["hostPort"], 30020);
        assert_eq!(ports[1]["containerPort"], 30002);
    }
}

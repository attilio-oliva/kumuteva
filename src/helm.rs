use std::process::{Command, ExitStatus};

/// A builder for Helm charts.
/// You can use this to build a command to run `helm` with the given arguments.
///
/// # Example
/// let command = HelmBuilder::install("my-chart").namespace("my-namespace").build();
/// assert_eq!(command, "helm install my-chart --namespace my-namespace");
///
/// # Example
/// let command = HelmBuilder::repo_add("my-repo", "https://my-repo.com").build();
/// assert_eq!(command, "helm repo add my-repo https://my-repo.com");
///
/// # Example
/// let command = HelmBuilder::repo_update().build();
/// assert_eq!(command, "helm repo update");
///
/// # Example
/// let command = HelmBuilder::delete("my-chart").namespace("my-namespace").build();
/// assert_eq!(command, "helm delete my-chart --namespace my-namespace");
use derive_builder::Builder;

#[derive(Debug, Clone, Default, Builder)]
//#[builder(build_fn(name = "build_internal", private))]
#[builder(pattern = "mutable", setter(into, strip_option), default)]
pub struct InstallChart {
    chart: String,
    repo: Option<String>,
    namespace: Option<String>,
    kubeconfig: Option<String>,
}

#[derive(Debug, Clone, Default, Builder)]
#[builder(pattern = "mutable", setter(into, strip_option), default)]
pub struct UpgradeChart {
    chart: String,
    release: String,
    repo: Option<String>,
    namespace: Option<String>,
    kubeconfig: Option<String>,
    install_flag: bool,
}

#[derive(Debug, Clone, Default, Builder)]
#[builder(pattern = "mutable")]
pub struct RepoAdd {
    name: String,
    url: String,
}

#[derive(Debug, Clone, Default, Builder)]
#[builder(pattern = "mutable", setter(into, strip_option), default)]
pub struct DeleteChart {
    chart: String,
    namespace: Option<String>,
}

pub struct Helm;

impl Helm {
    pub fn install(chart: &str) -> InstallChartBuilder {
        let mut builder = InstallChartBuilder::default();
        builder.chart(chart.to_string());
        builder
    }

    pub fn upgrade(chart: &str, release: &str) -> UpgradeChartBuilder {
        let mut builder = UpgradeChartBuilder::default();
        builder.chart(chart.to_string());
        builder.release(release.to_string());
        builder
    }

    pub fn repo_add(name: &str, url: &str) -> RepoAddBuilder {
        let mut builder = RepoAddBuilder::default();
        builder.name(name.to_string());
        builder.url(url.to_string());
        builder
    }

    pub fn delete(chart: &str) -> DeleteChartBuilder {
        let mut builder = DeleteChartBuilder::default();
        builder.chart(chart.to_string());
        builder
    }

    pub fn repo_update() -> String {
        "helm repo update".to_string()
    }
}

// Implement display for each command type
impl InstallChart {
    pub fn run(&self) -> std::io::Result<ExitStatus> {
        let args = self.to_args();
        Command::new("helm").args(args).status()
    }

    pub fn to_args(&self) -> Vec<String> {
        let mut args = vec!["install".to_string(), self.chart.clone()];
        if let Some(repo) = &self.repo {
            args.push("--repo".to_string());
            args.push(repo.clone());
        }
        if let Some(namespace) = &self.namespace {
            args.push("--namespace".to_string());
            args.push(namespace.clone());
        }
        if let Some(kubeconfig) = &self.kubeconfig {
            args.push("--kubeconfig".to_string());
            args.push(kubeconfig.clone());
        }
        args
    }
}

impl UpgradeChart {
    pub fn run(&self) -> std::io::Result<ExitStatus> {
        let args = self.to_args();
        Command::new("helm").args(args).status()
    }

    pub fn to_args(&self) -> Vec<String> {
        let mut args = vec![
            "upgrade".to_string(),
            self.release.clone(),
            self.chart.clone(),
        ];
        if let Some(repo) = &self.repo {
            args.push("--repo".to_string());
            args.push(repo.clone());
        }
        if let Some(namespace) = &self.namespace {
            args.push("--namespace".to_string());
            args.push(namespace.clone());
        }
        if let Some(kubeconfig) = &self.kubeconfig {
            args.push("--kubeconfig".to_string());
            args.push(kubeconfig.clone());
        }
        if self.install_flag {
            args.push("--install".to_string());
        }
        args
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_install_command() {
        let helm_args = Helm::install("my-chart")
            .namespace("my-ns")
            .kubeconfig("/path/to/config")
            .build()
            .unwrap()
            .to_args();

        assert_eq!(
            helm_args.join(" "),
            "install my-chart --namespace my-ns --kubeconfig /path/to/config"
        );
    }

    #[test]
    fn test_repo_add() {
        //let cmd = Helm::repo_add("my-repo", "https://my-repo.com")
        //    .build()
        //    .unwrap()
        //    .args();
        //
        //assert_eq!(cmd, "helm repo add my-repo https://my-repo.com");
    }
}

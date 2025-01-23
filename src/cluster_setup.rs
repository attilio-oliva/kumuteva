use std::{
    fs::File,
    io::Write,
    path::Path,
    process::{self, Command},
    str,
};

use anyhow::Error;

/// Create a kind cluster using the terminal
pub fn create_kind_cluster(name: &str) -> anyhow::Result<()> {
    let output = Command::new("kind")
        .arg("create")
        .arg("cluster")
        .arg("--name")
        .arg(name)
        .output()?;
    if output.status.success() {
        return Ok(());
    } else {
        return Err(terminal_stderr_to_error(output));
    }
}

pub fn export_kubeconfig(name: &str, path: &Path) -> anyhow::Result<()> {
    let output = Command::new("kind")
        .arg("get")
        .arg("kubeconfig")
        .arg("--name")
        .arg(name)
        .output()?;
    if output.status.success() {
        let mut file = File::create(path)?;
        file.write_all(&output.stdout)?;
        Ok(())
    } else {
        Err(terminal_stderr_to_error(output))
    }
}

pub fn delete_kind_cluster(name: &str) -> anyhow::Result<()> {
    let output = Command::new("kind")
        .arg("delete")
        .arg("cluster")
        .arg("--name")
        .arg(name)
        .output()?;
    if output.status.success() {
        println!("Kind cluster deleted successfully");
    } else {
        println!("Failed to delete Kind cluster");
        return Err(Error::msg("Failed to delete Kind cluster"));
    }
    Ok(())
}

pub fn terminal_stderr_to_error(output: process::Output) -> Error {
    let stderr = str::from_utf8(&output.stderr)
        .unwrap_or("Non utf-8 characters in stderr")
        .to_string();
    Error::msg(stderr)
}

#[cfg(test)]
mod tests {
    use std::{cell::LazyCell, path::PathBuf};

    use super::*;

    const CLUSTER_NAME: &str = "test-cluster";
    const TEMP_KUBECONFIG_PATH: LazyCell<PathBuf> = LazyCell::new(|| {
        let mut path = PathBuf::new();
        path.push(std::env::temp_dir());
        path.push("kubeconfig");
        path
    });

    #[test]
    fn test_create_kind_cluster() {
        let creation = create_kind_cluster(CLUSTER_NAME);
        assert!(
            creation.is_ok(),
            "Failed to create a Kind cluster {:?}",
            creation.err()
        );

        let kubeconfig_extraction = export_kubeconfig(CLUSTER_NAME, &TEMP_KUBECONFIG_PATH);
        assert!(
            kubeconfig_extraction.is_ok(),
            "Failed to extract kubeconfig: {:?}",
            kubeconfig_extraction.err()
        );
    }

    #[test]
    fn test_delete_kind_cluster() {
        let creation = create_kind_cluster(CLUSTER_NAME);
        assert!(
            creation.is_ok(),
            "Failed to create a temporary Kind cluster to delete {:?}",
            creation.err()
        );

        let result = delete_kind_cluster(CLUSTER_NAME);
        assert!(
            result.is_ok(),
            "Failed to delete Kind cluster {:?}",
            result.err()
        );
    }
}

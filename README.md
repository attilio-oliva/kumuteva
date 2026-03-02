# KuMuTeVa
KuMuTeVa (**Ku**bernetes **Mu**lti-**Te**nancy **Va**lidator) is a tool for assessing the effectiveness of multi-tenancy solutions for a Kubernetes cluster.
By impersonating two users provisioned by the cluster, one user dynamically attempt to access the other user resources. 
By looking at the behaviour of the cluster just from the view of these two end-user it is possible to infer isolation breaches and the solution quality (fairness).  

## Dependencies for the provisioner (setup command)
> [!NOTE]
> You only need this instructions if you want to use the setup command. If you already have a cluster to assess, you do not need to install anything other than KuMuTeVa. 

In case you want to test the tool for some solution, KuMuTeVa can provision a simple kind cluster for you with a set of relevant solutions.
Only in this case you need some dependencies to setup such environment:

- kubectl
- kind (for creating a simple cluster)
- helm (for deploying solutions)


## Installation
It is possible to download the compiled application binaries in the [Releases page](https://github.com/attilio-oliva/kumuteva/releases).

Alternatively, you can compile it yourself installing the [Rust toolchain](https://doc.rust-lang.org/cargo/getting-started/installation.html) and then using cargo:
```sh
cargo build --release
```
The application binaries will be in `target/release/` path.

## Usage
For any command you can use the `--help` flag to have an overview on all the options available.

For a complete isolation and autonomy assessment you can use the `verify` command:
```sh
kumuteva verify <tenant1-kubeconfig-path> <tenant2-kubeconfig-path>
```

For fairness test you can use the `fairness` command:
```sh
kumuteva fairness <tenant1-kubeconfig-path> <tenant2-kubeconfig-path>
```

In case you want to provision a simple cluster to try the tool and have install the [dependencies](#dependencies-for-the-provisioner), you can use the setup command:
```sh
kumuteva setup -t <type>
```
For example, you can use the "capsule" or "vcluster" types. You can see the full list with
```sh
kumuteva setup --help
```
You can also install a solution in an already existing cluster by passing its kubeconfig:
```sh
kumuteva setup -t <type> -p none -f <kubeconfig-path>
```


## Common issues

### Tests using kind clusters are failing

- Make sure you have kind installed
- In case the error is `ERROR: failed to create cluster: could not find a log line that matches "Reached target .*Multi-User System.*|detected cgroup v1"`, you can try to run the following command and then retry:

```bash
sudo sysctl fs.inotify.max_user_watches=524288
sudo sysctl fs.inotify.max_user_instances=512
```


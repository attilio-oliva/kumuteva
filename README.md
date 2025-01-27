## Dev Dependencies

- helm (for vCluster)
- kind (for creating k8s cluster samples)

## Common issues

### Tests using kind clusters are failing

- Make sure you have kind installed
- In case the error is `ERROR: failed to create cluster: could not find a log line that matches "Reached target .*Multi-User System.*|detected cgroup v1"`, you can try to run the following command:

```bash
sudo sysctl fs.inotify.max_user_watches=524288
sudo sysctl fs.inotify.max_user_instances=512
```

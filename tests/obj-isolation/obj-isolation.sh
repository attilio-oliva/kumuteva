vcluster create tenant-1 --namespace tenant1 --values ../../solution_config/vcluster.yaml
vcluster create tenant-2 --namespace tenant2 --values ../../solution_config/vcluster.yaml

# Deploy nginx application in tenant-1
kubectl apply -f nginx-deployment.yaml -n tenant1

# Check if the nginx pod is running in tenant-1
kubectl get pods -n tenant1 --context vcluster_tenant-1_tenant1_kind-vcluster

# Check if user tenant-2 can access tenant-1
kubectl get pods -n tenant1 --context vcluster_tenant-2_tenant2_kind-vcluster

# Deploy nginx application in tenant-2
kubectl apply -f nginx-deployment.yaml -n tenant2

# Check if the nginx pod is running in tenant-2
kubectl get pods -n tenant2 --context vcluster_tenant-2_tenant2_kind-vcluster

# Check if user tenant-1 can access tenant-2
kubectl get pods -n tenant2 --context vcluster_tenant-1_tenant1_kind-vcluster

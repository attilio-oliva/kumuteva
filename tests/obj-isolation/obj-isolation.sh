vcluster create tenant1 --namespace tenant1 --values ../../solution_config/vcluster.yaml
vcluster create tenant2 --namespace tenant2 --values ../../solution_config/vcluster.yaml

# Save the kubeconfig of tenant1 and tenant2
vcluster connect tenant1 -n tenant1 --insecure --print > kubeconfig_tenant1.yaml
vcluster connect tenant2 -n tenant2 --insecure --print > kubeconfig_tenant2.yaml

# Deploy nginx application in tenant1
kubectl create ns tenant1-apps --kubeconfig kubeconfig_tenant1.yaml
kubectl apply -f nginx-deployment.yaml -n tenant1-apps --kubeconfig kubeconfig_tenant1.yaml

# Check if the nginx pod is running in tenant1
kubectl get pods -n tenant1-apps --kubeconfig kubeconfig_tenant1.yaml

# Check if user tenant2 can access tenant1
kubectl get pods -n tenant1-apps --kubeconfig kubeconfig_tenant2.yaml

# Deploy nginx application in tenant2
kubectl create ns tenant2-apps --kubeconfig kubeconfig_tenant2.yaml
kubectl apply -f nginx-deployment.yaml -n tenant2-apps --kubeconfig kubeconfig_tenant2.yaml

# Check if the nginx pod is running in tenant2
kubectl get pods -n tenant2-apps --kubeconfig kubeconfig_tenant2.yaml

# Check if user tenant1 can access tenant2
kubectl get pods -n tenant2-apps --kubeconfig kubeconfig_tenant1.yaml

# Cleanup
vcluster delete tenant1
vcluster delete tenant2

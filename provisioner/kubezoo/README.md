# KubeZoo provisioner

Brings up the KubeZoo API gateway on the host cluster and adds one tenant per
call, so `kumuteva setup --type kubezoo` needs no manual step.

## Provenance

Everything under this directory derives from
[kubewharf/kubezoo](https://github.com/kubewharf/kubezoo) at commit
`8a3a05f83cfe0576c24d896d898683001bd833e5`, vendored rather than fetched so a
provisioning run is reproducible and needs no access to GitHub.

The commit is recorded instead of a tag on purpose: the repository's only tag is
`v0.1.0` while the images published to Docker Hub — the ones used here — are
`v0.2.0`. Upstream is effectively unmaintained.

| File | Upstream | Changes |
|---|---|---|
| `all_in_one.tmpl.yaml` | `config/setup/all_in_one.yaml` | Service `kubezoo` is a NodePort on `${KUBEZOO_NODEPORT}`; image tag `${KUBEZOO_IMAGE_TAG}` |
| `quota.tmpl.yaml` | `config/setup/quota.tmpl.yaml` | image tag `${KUBEZOO_IMAGE_TAG}`; the `{caBundle}` placeholder is untouched |
| `tenant.tmpl.yaml` | `config/setup/sample_tenant.yaml` | `metadata.name` and `spec.id` are `${TENANT_ID}`; the quota is raised past what the benchmarks request |
| `gen-pki.sh` | `hack/lib/gen_pki.sh` | rewritten — see the header in the file |
| `deploy-kubezoo.sh` | replaces `hack/make-rules/local_up.sh` | ours |
| `create-kubezoo-tenant.sh` | — | ours |

## Why upstream's own scripts are not used

`local_up.sh` builds the images from source, `kind load`s them, and finishes with
a foreground `kubectl port-forward svc/kubezoo 6443:6443`. That command never
returns, so nothing after it runs — which is the step a provisioning run appears
to hang on. Published images plus a NodePort remove both problems: kind's
`extraPortMapping` already carries the port to `127.0.0.1` on the host, which is
also the only address the gateway's serving certificate has a SAN for.

`gen_pki.sh` was rewritten because it needs `cfssl` and `yq` (installed on
neither test box), resolves the cluster through `~/.kube/config` and
`current-context` (the harness passes explicit kubeconfig paths and may have two
clusters up), writes a `zoo` context *into the user's kubeconfig*, and deletes
and recreates the CA on every call — which, on the second tenant's pass, would
invalidate the first tenant's certificate.

## What the harness runs

```
deploy-kubezoo.sh        <host_kubeconfig> <nodeport> <host_port> <work_dir>
create-kubezoo-tenant.sh <out_kubeconfig>  <tenant_id> <host_port> <work_dir>
```

`deploy-kubezoo.sh` is idempotent: the second tenant reuses the gateway the first
one installed, and the readiness checks run either way. The quota webhook is
installed and waited on **before** the gateway, because its
`ValidatingWebhookConfiguration` intercepts pod `CREATE` in every namespace with
`failurePolicy: Fail`; in the other order no pod can be created at all,
`kubezoo-0` included.

`<work_dir>` holds the PKI and the gateway's admin kubeconfig
(`zoo-admin.kubeconfig`). The `Tenant` CR is served by KubeZoo itself, so tenants
can only be created through that address, never through the host kubeconfig.

## Divergences that belong in the write-up

- **Kubernetes 1.24.17, not 1.33.4.** KubeZoo is an aggregated API server
  speaking a fixed set of upstream versions and does not support anything newer.
- **Calico 3.26.5, not 3.30.0.** Calico 3.30 dropped 1.24; installed there the
  manifest applies cleanly and `calico-node` never becomes ready.
- Both tenants share one gateway and one port mapping (`tenant1`'s), the same
  shape as capsule-proxy. `tenant2`'s mapping goes unused.
- Tenant ids are `100001` / `100002`: the Tenant CRD types `spec.id` as an
  integer and `metadata.name` as the same six digits, so a word-shaped id is
  rejected at validation and `tenant1` is in any case one character too long for
  the namespace prefix. A tenant's own `tenant1` namespace is `100001-tenant1`
  upstream.
- The sample tenant's quota (cpu: 2, memory: 2G) is smaller than one benchmark
  pod's request, and the quota webhook rejects anything over it. The template
  raises it well past what the assessment asks for: a quota that binds would be
  measured as KubeZoo's isolation.
- No Virtual Kubelet in this deployment, so tenant pods run on the shared
  upstream cluster and data-plane isolation should resemble the `native` row.

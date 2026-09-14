#!/bin/bash
#
# Mint the PKI KubeZoo needs and load it into the host cluster as Secrets.
#
# Derived from kubewharf/kubezoo hack/lib/gen_pki.sh
#   commit: 8a3a05f83cfe0576c24d896d898683001bd833e5
#
# Rewritten rather than vendored verbatim, for four reasons — each of which is a
# way the upstream script breaks a harness run:
#
#   1. Upstream signs with `cfssl`/`cfssljson` and reads kubeconfigs with `yq`.
#      Neither is installed on the boxes this artifact runs on, and both are Go
#      binaries that would have to be fetched at provisioning time. The same
#      certificates — same subjects, same SANs, same extended key usages — are
#      produced here with `openssl` and `kubectl`, which are already hard
#      requirements of every other provisioner in this tree.
#   2. Upstream resolves the cluster through `kubectl config current-context`
#      and `~/.kube/config`. The harness never touches the user's kubeconfig: it
#      hands every script an explicit path, and two clusters can exist at once.
#   3. Upstream's `set_context` writes a `zoo` context *into the user's
#      kubeconfig*. That is a side effect on a file the harness does not own.
#      The admin context is written to a file inside the work directory instead.
#   4. Upstream unconditionally deletes and recreates the Secrets. KubeZoo's CA
#      signs the tenant client certificates, so regenerating it on the second
#      tenant's pass invalidates the first tenant's kubeconfig. Here an existing
#      `kubezoo-pki` Secret is authoritative: its CA is pulled back out and
#      reused, and only the admin certificate is re-minted.
#
# Usage: gen-pki.sh <host_kubeconfig> <work_dir> <host_port>

set -uo pipefail

KUBECONFIG_PATH="$1"
WORK_DIR="$2"
HOST_PORT="$3"

if [ -z "$KUBECONFIG_PATH" ] || [ -z "$WORK_DIR" ] || [ -z "$HOST_PORT" ]; then
    echo "Usage: $0 <host_kubeconfig> <work_dir> <host_port>"
    exit 1
fi

THIS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

KUBEZOO_IMAGE_TAG=${KUBEZOO_IMAGE_TAG:-v0.2.0}

UPSTREAM_DIR="$WORK_DIR/upstream"
KUBEZOO_DIR="$WORK_DIR/kubezoo"
ADMIN_KUBECONFIG="$WORK_DIR/zoo-admin.kubeconfig"
QUOTA_MANIFEST="$WORK_DIR/quota.yaml"

mkdir -p "$UPSTREAM_DIR" "$KUBEZOO_DIR" || exit 1

kc() { kubectl --kubeconfig "$KUBECONFIG_PATH" "$@"; }

for tool in openssl kubectl docker base64 envsubst; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "ERROR: $tool is required to provision KubeZoo but is not on PATH"
        exit 1
    fi
done

# --- The kind node's own PKI ------------------------------------------------
# KubeZoo mints ServiceAccount tokens that the *upstream* API server has to
# accept, so it needs that cluster's service-account signing key — which lives
# only inside the node, not in any kubeconfig. The front-proxy client identity
# comes from the kubeconfig, where kind already put an admin certificate.

get_upstream_pki() {
    local context cluster_name node

    context="$(kc config current-context 2>/dev/null)"
    if [ -z "$context" ]; then
        echo "ERROR: no current context in $KUBECONFIG_PATH"
        return 1
    fi
    if [ "${context:0:5}" != "kind-" ]; then
        echo "ERROR: KubeZoo provisioning needs a kind host cluster, but the"
        echo "       current context is '$context' — the service-account keys"
        echo "       are read out of the kind node container."
        return 1
    fi
    cluster_name="${context:5}"
    node="$(docker ps --filter "name=${cluster_name}-control-plane" --format '{{.ID}}' | head -1)"
    if [ -z "$node" ]; then
        echo "ERROR: no running container for kind node ${cluster_name}-control-plane"
        return 1
    fi

    docker cp "$node":/etc/kubernetes/pki/sa.pub "$UPSTREAM_DIR"/sa.pub || return 1
    docker cp "$node":/etc/kubernetes/pki/sa.key "$UPSTREAM_DIR"/sa.key || return 1

    # `kubectl config view --raw` is the yq-free equivalent of reading the
    # embedded data out of the kubeconfig, and works whether the credentials are
    # embedded or on disk.
    kc config view --raw --flatten -o \
        "jsonpath={.users[?(@.name==\"$context\")].user.client-certificate-data}" \
        | base64 -d > "$UPSTREAM_DIR"/client.crt || return 1
    kc config view --raw --flatten -o \
        "jsonpath={.users[?(@.name==\"$context\")].user.client-key-data}" \
        | base64 -d > "$UPSTREAM_DIR"/client-key.crt || return 1
    kc config view --raw --flatten -o \
        "jsonpath={.clusters[?(@.name==\"$context\")].cluster.certificate-authority-data}" \
        | base64 -d > "$UPSTREAM_DIR"/ca.crt || return 1

    for f in sa.pub sa.key client.crt client-key.crt ca.crt; do
        if [ ! -s "$UPSTREAM_DIR/$f" ]; then
            echo "ERROR: upstream PKI file $f came out empty"
            return 1
        fi
    done
}

# --- KubeZoo's own CA and leaf certificates ---------------------------------
# The subjects match upstream exactly. They are not decorative: `admin` in
# O=system:masters is the identity the gateway is addressed with, and the
# serving certificate's 127.0.0.1 SAN is the only reason a kubeconfig pointed at
# the published NodePort can verify TLS at all.

CERT_SUBJ_BASE="/C=US/ST=CA/L=Sunnyvale"

gen_ca() {
    openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
        -keyout "$KUBEZOO_DIR"/ca-key.pem \
        -out "$KUBEZOO_DIR"/ca.pem \
        -subj "${CERT_SUBJ_BASE}/O=KubeZoo/OU=CA/CN=Kubernetes" \
        -addext "basicConstraints=critical,CA:TRUE" \
        -addext "keyUsage=critical,digitalSignature,keyCertSign,cRLSign" \
        >/dev/null 2>&1
}

# $1 file stem, $2 subject, $3 SAN list ("" for a client-only certificate)
gen_leaf() {
    local stem="$1" subj="$2" sans="$3"
    local ext="$KUBEZOO_DIR/$stem.ext"

    {
        echo "basicConstraints=CA:FALSE"
        echo "keyUsage=critical,digitalSignature,keyEncipherment"
        # Both usages, as upstream's "kubernetes" cfssl profile does: the same
        # certificate is presented as a server by the gateway and as a client
        # towards the webhook.
        echo "extendedKeyUsage=serverAuth,clientAuth"
        [ -n "$sans" ] && echo "subjectAltName=$sans"
    } > "$ext"

    openssl req -newkey rsa:2048 -nodes \
        -keyout "$KUBEZOO_DIR/$stem-key.pem" \
        -out "$KUBEZOO_DIR/$stem.csr" \
        -subj "$subj" >/dev/null 2>&1 || return 1

    openssl x509 -req -days 3650 \
        -in "$KUBEZOO_DIR/$stem.csr" \
        -CA "$KUBEZOO_DIR"/ca.pem -CAkey "$KUBEZOO_DIR"/ca-key.pem \
        -CAcreateserial \
        -extfile "$ext" \
        -out "$KUBEZOO_DIR/$stem.pem" >/dev/null 2>&1 || return 1
}

gen_admin_cert() {
    gen_leaf admin "${CERT_SUBJ_BASE}/O=system:masters/OU=KubeZoo/CN=admin" ""
}

gen_kubernetes_cert() {
    gen_leaf kubernetes "${CERT_SUBJ_BASE}/O=KubeZoo/OU=KubeZoo/CN=kubernetes" \
        "IP:127.0.0.1,DNS:kubernetes,DNS:kubernetes.default,DNS:kubernetes.default.svc,DNS:kubernetes.default.svc.cluster,DNS:kubernetes.svc.cluster.local,DNS:kubezoo,DNS:kubezoo.default,DNS:kubezoo.default.svc,DNS:localhost"
}

gen_quota_webhook_cert() {
    gen_leaf quota-webhook \
        "${CERT_SUBJ_BASE}/O=system:masters/OU=KubeZoo/CN=kubezoo-cluster-resource-quota" \
        "IP:127.0.0.1,DNS:kubezoo-cluster-resource-quota.default,DNS:kubezoo-cluster-resource-quota.default.svc"
}

# --- Secrets ----------------------------------------------------------------
# `create --dry-run=client | apply` rather than delete-then-create: a Secret
# whose content is unchanged is then a no-op, and the pods mounting it are not
# disturbed by a second tenant's provisioning pass.

apply_secret() {
    kc create "$@" --dry-run=client -o yaml | kc apply -f - >/dev/null
}

create_pki_secrets() {
    apply_secret secret generic kubezoo-pki \
        --from-file=ca-key.pem="$KUBEZOO_DIR"/ca-key.pem \
        --from-file=ca.pem="$KUBEZOO_DIR"/ca.pem \
        --from-file=kubernetes-key.pem="$KUBEZOO_DIR"/kubernetes-key.pem \
        --from-file=kubernetes.pem="$KUBEZOO_DIR"/kubernetes.pem || return 1

    apply_secret secret generic upstream-pki \
        --from-file=sa.pub="$UPSTREAM_DIR"/sa.pub \
        --from-file=sa.key="$UPSTREAM_DIR"/sa.key \
        --from-file=client.crt="$UPSTREAM_DIR"/client.crt \
        --from-file=client-key.crt="$UPSTREAM_DIR"/client-key.crt \
        --from-file=ca.crt="$UPSTREAM_DIR"/ca.crt || return 1

    apply_secret secret tls quota-webhook-pki \
        --key="$KUBEZOO_DIR"/quota-webhook-key.pem \
        --cert="$KUBEZOO_DIR"/quota-webhook.pem || return 1
}

# --- The gateway's admin kubeconfig -----------------------------------------
# Written into the work directory, never into the caller's kubeconfig. The
# server is the published NodePort on the host: KubeZoo serves the Tenant CR
# itself, so tenants can only be created through this address.

write_admin_kubeconfig() {
    rm -f "$ADMIN_KUBECONFIG"
    kubectl --kubeconfig "$ADMIN_KUBECONFIG" config set-cluster zoo \
        --certificate-authority="$KUBEZOO_DIR"/ca.pem \
        --embed-certs=true \
        --server="https://127.0.0.1:${HOST_PORT}" >/dev/null || return 1
    kubectl --kubeconfig "$ADMIN_KUBECONFIG" config set-credentials zoo-admin \
        --client-certificate="$KUBEZOO_DIR"/admin.pem \
        --client-key="$KUBEZOO_DIR"/admin-key.pem \
        --embed-certs=true >/dev/null || return 1
    kubectl --kubeconfig "$ADMIN_KUBECONFIG" config set-context zoo \
        --cluster=zoo --user=zoo-admin >/dev/null || return 1
    kubectl --kubeconfig "$ADMIN_KUBECONFIG" config use-context zoo >/dev/null || return 1
}

render_quota_manifest() {
    local ca_base64
    ca_base64="$(base64 -w 0 "$KUBEZOO_DIR"/ca.pem)"
    KUBEZOO_IMAGE_TAG="$KUBEZOO_IMAGE_TAG" envsubst < "$THIS_DIR"/quota.tmpl.yaml \
        | sed "s|{caBundle}|${ca_base64}|g" > "$QUOTA_MANIFEST"
    [ -s "$QUOTA_MANIFEST" ]
}

# --- Reuse path -------------------------------------------------------------
# The second tenant's provisioning pass must not rotate the CA that signed the
# first tenant's certificate. If the Secret is already in the cluster it is the
# source of truth, even when the work directory has been wiped since.

recover_ca_from_secret() {
    kc get secret kubezoo-pki -o jsonpath='{.data.ca\.pem}' | base64 -d > "$KUBEZOO_DIR"/ca.pem || return 1
    kc get secret kubezoo-pki -o jsonpath='{.data.ca-key\.pem}' | base64 -d > "$KUBEZOO_DIR"/ca-key.pem || return 1
    [ -s "$KUBEZOO_DIR/ca.pem" ] && [ -s "$KUBEZOO_DIR/ca-key.pem" ]
}

if kc get secret kubezoo-pki >/dev/null 2>&1; then
    echo "KubeZoo PKI already present in the cluster; reusing its CA."
    recover_ca_from_secret || { echo "ERROR: could not read the CA back out of secret/kubezoo-pki"; exit 1; }
    gen_admin_cert || { echo "ERROR: failed to mint the admin certificate"; exit 1; }
    render_quota_manifest || { echo "ERROR: failed to render the quota manifest"; exit 1; }
    write_admin_kubeconfig || { echo "ERROR: failed to write $ADMIN_KUBECONFIG"; exit 1; }
    echo "Admin kubeconfig: $ADMIN_KUBECONFIG"
    exit 0
fi

echo "Generating KubeZoo PKI in $WORK_DIR..."
get_upstream_pki       || { echo "ERROR: failed to collect the upstream PKI"; exit 1; }
gen_ca                 || { echo "ERROR: failed to generate the KubeZoo CA"; exit 1; }
gen_admin_cert         || { echo "ERROR: failed to generate the admin certificate"; exit 1; }
gen_kubernetes_cert    || { echo "ERROR: failed to generate the serving certificate"; exit 1; }
gen_quota_webhook_cert || { echo "ERROR: failed to generate the quota webhook certificate"; exit 1; }
create_pki_secrets     || { echo "ERROR: failed to create the PKI secrets"; exit 1; }
render_quota_manifest  || { echo "ERROR: failed to render the quota manifest"; exit 1; }
write_admin_kubeconfig || { echo "ERROR: failed to write $ADMIN_KUBECONFIG"; exit 1; }

echo "KubeZoo PKI ready. Admin kubeconfig: $ADMIN_KUBECONFIG"

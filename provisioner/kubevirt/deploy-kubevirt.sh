#!/bin/bash
#
# Install KubeVirt on the host cluster and make sure it can actually start VMs.
#
# Hardware virtualization is the thing that decides whether a KubeVirt tenant
# cluster works or hangs. Rather than assume it (the previous version pinned
# USE_NESTED_VIRTUALIZATION=y, which made the emulation branch below dead code
# and turned a missing /dev/kvm into a VMI that sits Pending forever with no
# explanation), ask the cluster after virt-handler has had a chance to look.

set -uo pipefail

KV_VER=${KV_VER:-"v1.7.0"}
KUBECONFIG_PATH="$1"

# Force a mode instead of detecting: "y" requires hardware virtualization,
# "n" requires software emulation. Empty means detect.
USE_NESTED_VIRTUALIZATION=${USE_NESTED_VIRTUALIZATION:-""}

if [ -z "$KUBECONFIG_PATH" ]; then
    echo "Usage: $0 <kubeconfig_path>"
    exit 1
fi

kc() { kubectl --kubeconfig "$KUBECONFIG_PATH" "$@"; }

wait_for_kubevirt_available() {
    kc wait -n kubevirt kv kubevirt --for=condition=Available --timeout=10m
}

# virt-handler advertises devices.kubevirt.io/kvm on nodes where it found
# /dev/kvm. That is the authoritative answer for this cluster — checking the
# host's own /dev/kvm would not account for what the node container can see.
node_has_kvm() {
    kc get nodes -o json 2>/dev/null | grep -q 'devices.kubevirt.io/kvm'
}

enable_emulation() {
    echo "Enabling software emulation (useEmulation=true)."
    echo "WARNING: VMs will run under QEMU TCG, which is one to two orders of"
    echo "         magnitude slower than KVM. A kubeadm control plane may take"
    echo "         far longer to converge, and any latency measured inside such"
    echo "         a tenant reflects the emulator more than the platform."
    kc -n kubevirt patch kubevirt kubevirt --type=merge \
        --patch '{"spec":{"configuration":{"developerConfiguration":{"useEmulation":true}}}}'
}

if kc get ns kubevirt &>/dev/null; then
    echo "KubeVirt is already installed."
else
    kc apply -f "https://github.com/kubevirt/kubevirt/releases/download/${KV_VER}/kubevirt-operator.yaml" || exit 1
    kc apply -f "https://github.com/kubevirt/kubevirt/releases/download/${KV_VER}/kubevirt-cr.yaml" || exit 1
fi

if ! wait_for_kubevirt_available; then
    echo "ERROR: KubeVirt did not become Available"
    kc get pods -n kubevirt
    exit 1
fi

case "$USE_NESTED_VIRTUALIZATION" in
    y)
        if ! node_has_kvm; then
            echo "ERROR: USE_NESTED_VIRTUALIZATION=y but no node advertises"
            echo "       devices.kubevirt.io/kvm. On kind the node container is"
            echo "       privileged and inherits the host's /dev/kvm, so this"
            echo "       usually means the host lacks KVM or nested virt is off:"
            echo "         ls -l /dev/kvm"
            echo "         cat /sys/module/kvm_intel/parameters/nested"
            echo "       Re-run with USE_NESTED_VIRTUALIZATION=n to emulate."
            exit 1
        fi
        echo "Hardware virtualization confirmed on at least one node."
        ;;
    n)
        enable_emulation || exit 1
        wait_for_kubevirt_available || exit 1
        ;;
    *)
        if node_has_kvm; then
            echo "Hardware virtualization available; using KVM."
        else
            echo "No node advertises devices.kubevirt.io/kvm."
            enable_emulation || exit 1
            wait_for_kubevirt_available || exit 1
        fi
        ;;
esac

echo "KubeVirt ${KV_VER} is ready."

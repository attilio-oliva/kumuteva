echo 'Testing container escape using custom kernel module...'
capeff=$(sed -n 's/^CapEff:[[:space:]]*//p' /proc/self/status)
capbnd=$(sed -n 's/^CapBnd:[[:space:]]*//p' /proc/self/status)
echo "CAPEFF=${capeff}"
echo "CAPBND=${capbnd}"
cap=$((0x${capeff:-0}))
# CAP_SYS_ADMIN (bit 21, 0x200000) is the capability BOTH breaches need:
# the eBPF loader and the module loader alike. CAP_SYS_MODULE (bit 16,
# 0x10000) and CAP_BPF (bit 39, 0x8000000000) are reported for context
# only, so a platform that strips just CAP_SYS_MODULE — leaving the eBPF
# breach open — is not misread as fully confined.
has_admin=$(( (cap & 0x200000) != 0 ))
has_module=$(( (cap & 0x10000) != 0 ))
has_bpf=$(( (cap & 0x8000000000) != 0 ))
echo "CAP_DETAIL: sys_admin=$has_admin sys_module=$has_module bpf=$has_bpf"
if [ "$has_admin" -ne 0 ]; then
  echo 'CAPS_FULL: CAP_SYS_ADMIN present - privileged breach is possible'
else
  echo 'CAPS_DROPPED: CAP_SYS_ADMIN missing - capabilities confined'
fi

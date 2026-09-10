#!/usr/bin/env bash
#
# Lock the host's CPU behaviour before a fairness campaign, then print the
# resulting state as evidence.
#
#   sudo experiments/host-prep.sh | tee experiments/host-state-$(date +%F).txt
#   sudo experiments/host-prep.sh --restore     # put the machine back
#
# Why this exists: the first submission let the CPU governor scale frequency
# between the baseline and stress phases, which produced a degradation factor
# below 1.0 for KubeVirt — the tenant appearing *faster* under load. A software
# isolation measurement is not readable while the hardware moves underneath it.
#
# Nothing here survives a reboot, so run it again after one.
#
# Every setting is reported whether or not it could be applied. A platform that
# refuses one of them is a fact for the Limitations section, not something to
# paper over, so the script keeps going and tells you.

set -uo pipefail

# Prior state is recorded here so --restore can undo everything. Kept outside
# the repository: it describes this machine, not the experiment.
STATE_FILE=/var/lib/kumuteva-host-prep.state

# Services that will fight the performance governor if left running.
COMPETING_SERVICES=(ondemand tuned power-profiles-daemon thermald cpufrequtils)

failures=0

section() { printf '\n=== %s ===\n' "$1"; }
note()    { printf '  %s\n' "$1"; }
warn()    { printf '  WARNING: %s\n' "$1"; failures=$((failures + 1)); }

if [[ ${EUID} -ne 0 ]]; then
    echo "Must run as root (it writes to /sys and /proc)." >&2
    exit 1
fi

mode=apply
case "${1:-}" in
    --restore) mode=restore ;;
    "")        mode=apply ;;
    *) echo "Usage: $0 [--restore]" >&2; exit 2 ;;
esac

# ---------------------------------------------------------------------------
# Restore
# ---------------------------------------------------------------------------
if [[ ${mode} == restore ]]; then
    printf 'Restoring host settings: %s on %s\n' "$(date -Is)" "$(hostname)"

    if [[ ! -f ${STATE_FILE} ]]; then
        echo "No saved state at ${STATE_FILE}; nothing to restore." >&2
        exit 1
    fi

    section "Services"
    while IFS='=' read -r key value; do
        case "${key}" in
            service_active)
                if systemctl start "${value}" >/dev/null 2>&1; then
                    note "started ${value}"
                else
                    warn "could not start ${value}"
                fi
                ;;
            service_enabled)
                if systemctl enable "${value}" >/dev/null 2>&1; then
                    note "re-enabled ${value}"
                else
                    warn "could not enable ${value}"
                fi
                ;;
        esac
    done < "${STATE_FILE}"

    section "CPU"
    while IFS='=' read -r key value; do
        case "${key}" in
            governor)
                for path in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
                    [[ -w ${path} ]] && echo "${value}" > "${path}" 2>/dev/null
                done
                note "governor restored to ${value}"
                ;;
            turbo)
                path="${value%% *}"; previous="${value##* }"
                if [[ -w ${path} ]] && echo "${previous}" > "${path}" 2>/dev/null; then
                    note "restored ${path} = ${previous}"
                else
                    warn "could not restore ${path}"
                fi
                ;;
            cstate)
                path="${value%% *}"; previous="${value##* }"
                if [[ -w ${path} ]]; then
                    echo "${previous}" > "${path}" 2>/dev/null || true
                fi
                ;;
        esac
    done < "${STATE_FILE}"
    note "idle states restored"

    rm -f "${STATE_FILE}"
    section "Summary"
    note "machine returned to its previous configuration"
    exit 0
fi

# ---------------------------------------------------------------------------
# Apply
# ---------------------------------------------------------------------------
printf 'Host preparation: %s on %s\n' "$(date -Is)" "$(hostname)"

# Start a fresh state file. Overwriting matters: if a previous apply was never
# restored, the "previous" values would already be the locked ones, and the
# restore would put back the benchmark settings rather than the originals.
if [[ -f ${STATE_FILE} ]]; then
    note "note: ${STATE_FILE} already exists — a previous run was never restored."
    note "      keeping the original saved state so --restore still undoes it."
else
    mkdir -p "$(dirname "${STATE_FILE}")"
    : > "${STATE_FILE}"
    chmod 600 "${STATE_FILE}"
    record_state=1
fi
record_state=${record_state:-0}
save() {
    if [[ ${record_state} -eq 1 ]]; then
        printf '%s\n' "$1" >> "${STATE_FILE}"
    fi
}

# --- 1. Stop whatever else manages frequency -------------------------------
# Done before touching the governor: these would otherwise reassert themselves
# over the settings applied below.
section "Competing power managers"
for service in "${COMPETING_SERVICES[@]}"; do
    if ! systemctl list-unit-files "${service}.service" >/dev/null 2>&1; then
        continue
    fi

    state=$(systemctl is-active "${service}" 2>/dev/null || true)
    enabled=$(systemctl is-enabled "${service}" 2>/dev/null || true)

    if [[ ${state} == active ]]; then
        if systemctl stop "${service}" >/dev/null 2>&1; then
            save "service_active=${service}"
            note "${service}: stopped (was active)"
        else
            warn "${service} is active and could not be stopped"
        fi
    else
        note "${service}: already ${state:-absent}"
    fi

    # Disable as well, so a reboot mid-campaign does not bring it back. This is
    # the case that produced the warning worth acting on: inactive but enabled.
    if [[ ${enabled} == enabled ]]; then
        if systemctl disable "${service}" >/dev/null 2>&1; then
            save "service_enabled=${service}"
            note "${service}: disabled (was enabled at boot)"
        else
            warn "${service} is enabled and could not be disabled"
        fi
    fi
done

# --- 2. Frequency governor -------------------------------------------------
section "CPU governor"
# Which driver is in charge decides what governors exist at all: intel_pstate in
# active mode offers only performance and powersave, while acpi-cpufreq offers
# the full ondemand/conservative set. Worth recording — it tells a reader which
# regime the numbers were taken under.
note "driver: $(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_driver 2>/dev/null || echo 'not exposed')"
previous_governor=$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || echo '')
note "before: ${previous_governor:-not exposed}"
note "available: $(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_available_governors 2>/dev/null || echo 'not exposed')"
if [[ -n ${previous_governor} ]]; then
    save "governor=${previous_governor}"
fi

# Applied, then read back, and the read-back is what decides.
#
# `cpupower frequency-set` was previously trusted on its exit status, and the
# sysfs loop below ran only when cpupower was *missing*. On a host where
# cpupower exists, returns 0 and changes nothing — intel_pstate in passive mode
# here — this printed "set to performance" over 96 CPUs still on `ondemand`.
# A whole campaign then ran unpinned, and every degradation factor came out
# below 1.0 because the interference phase woke the cores up.
not_performance() {
    cat /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor 2>/dev/null \
        | grep -cv '^performance$'
}

if command -v cpupower >/dev/null 2>&1; then
    cpupower frequency-set -g performance >/dev/null 2>&1 || true
    if [[ $(not_performance) -eq 0 ]]; then
        note "set to performance via cpupower"
    else
        note "cpupower did not apply it; falling back to sysfs"
    fi
fi

if [[ $(not_performance) -gt 0 ]]; then
    applied=0
    for governor in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
        [[ -w ${governor} ]] || continue
        echo performance > "${governor}" 2>/dev/null && applied=$((applied + 1))
    done
    note "wrote performance to ${applied} CPUs via sysfs"
fi

remaining=$(not_performance)
if [[ ${remaining} -gt 0 ]]; then
    warn "${remaining} CPU(s) are NOT on the performance governor; frequency is not pinned"
fi
note "after: $(cat /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor 2>/dev/null | sort -u | tr '\n' ' ')"

# --- 3. Turbo / boost ------------------------------------------------------
section "Turbo boost"
if [[ -w /sys/devices/system/cpu/intel_pstate/no_turbo ]]; then
    save "turbo=/sys/devices/system/cpu/intel_pstate/no_turbo $(cat /sys/devices/system/cpu/intel_pstate/no_turbo)"
    echo 1 > /sys/devices/system/cpu/intel_pstate/no_turbo
    note "intel_pstate no_turbo = $(cat /sys/devices/system/cpu/intel_pstate/no_turbo) (1 = turbo off)"
elif [[ -w /sys/devices/system/cpu/cpufreq/boost ]]; then
    save "turbo=/sys/devices/system/cpu/cpufreq/boost $(cat /sys/devices/system/cpu/cpufreq/boost)"
    echo 0 > /sys/devices/system/cpu/cpufreq/boost
    note "cpufreq boost = $(cat /sys/devices/system/cpu/cpufreq/boost) (0 = boost off)"
else
    warn "no turbo control exposed; a lightly loaded phase may clock higher than a busy one"
fi

# --- 4. Idle states --------------------------------------------------------
# An idle core that has dropped into a deep C-state pays a wake-up latency the
# busy phase never sees, which shows up as the baseline looking slower than it is.
section "C-states"
if [[ -d /sys/devices/system/cpu/cpu0/cpuidle ]]; then
    disabled=0
    for state in /sys/devices/system/cpu/cpu*/cpuidle/state[1-9]*/disable; do
        [[ -w ${state} ]] || continue
        save "cstate=${state} $(cat "${state}")"
        echo 1 > "${state}" 2>/dev/null && disabled=$((disabled + 1))
    done
    if [[ ${disabled} -gt 0 ]]; then
        note "disabled ${disabled} idle states deeper than C0"
    else
        warn "cpuidle present but no state could be disabled"
    fi
else
    note "cpuidle not present; nothing to disable"
fi

# --- 5. Report what could not be changed at runtime ------------------------
section "Topology (record these in the paper)"
note "SMT: $(cat /sys/devices/system/cpu/smt/control 2>/dev/null || echo 'not exposed')"
note "$(lscpu | grep -E '^(Model name|Socket|Core|Thread|NUMA node\(s\))' | tr -s ' ' | paste -sd'; ')"
if command -v numactl >/dev/null 2>&1; then
    numactl --hardware | sed 's/^/  /'
fi

section "Frequency snapshot"
grep 'MHz' /proc/cpuinfo | awk '{print $4}' | sort -n | awk '
    { values[NR] = $1 }
    END {
        if (NR == 0) { print "  no MHz reported"; exit }
        printf "  min %.0f MHz  median %.0f MHz  max %.0f MHz  (%d CPUs)\n",
               values[1], values[int(NR/2)+1], values[NR], NR
    }'

section "Summary"
if [[ ${failures} -eq 0 ]]; then
    note "all controls applied"
else
    note "${failures} control(s) could not be applied — state them as limitations"
fi
note "prior state saved to ${STATE_FILE}; undo with: sudo $0 --restore"

cat <<'EOF'

  Thermal note: stopping thermald hands throttling decisions to the CPU's own
  hardware protection. That is safe for the silicon, but on a thermally
  constrained machine it can throttle more abruptly than thermald would have.
  Watch for it in the turbostat trace rather than assuming it cannot happen.

  To confirm the lock holds *during* a run, sample in parallel with it:

      turbostat --interval 5 --show Core,CPU,Bzy_MHz,PkgWatt \
        > experiments/turbostat-$(date +%F-%H%M).txt

  Bzy_MHz should stay flat across the baseline and stress phases. A step
  between them means the frequency moved and the degradation factors from that
  run cannot be compared.
EOF

exit 0

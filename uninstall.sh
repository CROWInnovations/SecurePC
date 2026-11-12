#!/usr/bin/env bash
# ==============================================================================
# SecurePC — Complete Production Uninstaller (uninstall.sh)
# Author:  CROW Innovations (https://crowinnovations.com)
# License: GNU General Public License v3.0 (GPL-3.0)
# GitHub:  https://github.com/CROWInnovations/SecurePC
#
# Cleanly and completely removes all SecurePC system integrations:
#   1. Stops, disables & removes securepc-{monitor,firewall,geoip-update} units
#   2. Removes isolated ftrace instance (/sys/kernel/tracing/instances/securepc)
#   3. Removes nftables 'table inet securepc' AND any iptables/ip6tables/ipset rules
#   4. Removes managed browser DoH/ECH policy drop-ins (restoring Firefox backups)
#   5. Removes rsyslog, logrotate, profile.d & Desktop GUI login hooks
#   6. Removes /usr/local/lib/securepc & /usr/local/bin/securepc-ctl
#   7. Preserves /var/log/securepc & /etc/securepc by default (or purges with --purge)
# ==============================================================================
set -euo pipefail

PATH="/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin"
export PATH

SCRIPT_DIR="$(cd -- "$(dirname -- "$(readlink -f -- "${BASH_SOURCE[0]}")")" && pwd -P)"
BIN_DIR="${SCRIPT_DIR}/bin"
INSTALL_ROOT="/usr/local/lib/securepc"

AUTO_YES=0
PURGE_LOGS=0
KEEP_LOGS=0
DRY_RUN=0

usage() {
    cat <<'EOF'
Usage: sudo ./uninstall.sh [OPTIONS]

Options:
  -y, --yes         Skip confirmation prompts
      --purge       Also delete /var/log/securepc, /var/lib/securepc, and /etc/securepc
      --keep-logs   Preserve /var/log/securepc and /etc/securepc (default in non-interactive mode)
  -n, --dry-run     Preview every removal step without modifying the system
  -h, --help        Show this help message
EOF
}

for arg in "$@"; do
    case "${arg}" in
        -y|--yes)       AUTO_YES=1 ;;
        --purge)        PURGE_LOGS=1 ;;
        --keep-logs)    KEEP_LOGS=1 ;;
        -n|--dry-run)   DRY_RUN=1 ;;
        -h|--help)
            if [ -f "${BIN_DIR}/securepc-banner.sh" ]; then
                # shellcheck disable=SC1091
                . "${BIN_DIR}/securepc-banner.sh"
                print_securepc_banner
                echo ""
            fi
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: ${arg}" >&2
            usage >&2
            exit 1
            ;;
    esac
done

if [ "${DRY_RUN}" -eq 0 ] && [ "$(id -u)" -ne 0 ]; then
    echo "Elevating to root via sudo..."
    exec sudo "$0" "$@"
fi

if [ -f "${BIN_DIR}/securepc-banner.sh" ]; then
    # shellcheck disable=SC1091
    . "${BIN_DIR}/securepc-banner.sh"
    print_securepc_banner
    echo ""
fi

TARGET_USER="${SUDO_USER:-$(logname 2>/dev/null || echo "")}"
TARGET_HOME=""
if [ -n "${TARGET_USER}" ] && [ "${TARGET_USER}" != "root" ]; then
    TARGET_HOME="$(getent passwd "${TARGET_USER}" | cut -d: -f6 || true)"
fi

if [ "${DRY_RUN}" -eq 1 ]; then
    echo "[DRY-RUN] Previewing complete SecurePC uninstallation (no changes will be made):"
elif [ "${AUTO_YES}" -eq 0 ]; then
    printf "Are you sure you want to completely uninstall SecurePC from this system? [y/N]: "
    read -r ans
    case "${ans}" in
        [yY]|[yY][eE][sS]) ;;
        *)
            echo "Uninstall cancelled."
            exit 0
            ;;
    esac
    if [ "${PURGE_LOGS}" -eq 0 ] && [ "${KEEP_LOGS}" -eq 0 ]; then
        printf "Also purge /var/log/securepc, /var/lib/securepc, and /etc/securepc? [y/N]: "
        read -r purge_ans
        case "${purge_ans}" in
            [yY]|[yY][eE][sS]) PURGE_LOGS=1 ;;
            *) KEEP_LOGS=1 ;;
        esac
    fi
fi

run_step() {
    if [ "${DRY_RUN}" -eq 1 ]; then
        echo "  [dry-run] $*"
    else
        "$@"
    fi
}

echo "==> [1/8] Stopping and removing systemd units (monitor, firewall, GeoIP timer)..."
if [ "${DRY_RUN}" -eq 1 ]; then
    echo "  [dry-run] Stop/disable/remove securepc-{monitor.service,firewall.service,geoip-update.timer,geoip-update.service}"
else
    for unit in securepc-geoip-update.timer securepc-geoip-update.service securepc-monitor.service securepc-firewall.service; do
        systemctl stop "${unit}" 2>/dev/null || true
        systemctl disable "${unit}" 2>/dev/null || true
        rm -f "/etc/systemd/system/${unit}"
    done
    systemctl daemon-reload 2>/dev/null || true
fi

echo "==> [2/8] Removing isolated SecurePC kernel ftrace instance..."
if [ "${DRY_RUN}" -eq 1 ]; then
    echo "  [dry-run] Disable & remove /sys/kernel/tracing/instances/securepc"
else
    if [ -d /sys/kernel/tracing/instances/securepc ]; then
        for tp in \
            /sys/kernel/tracing/instances/securepc/events/fib/fib_table_lookup/enable \
            /sys/kernel/tracing/instances/securepc/events/sock/inet_sock_set_state/enable \
            /sys/kernel/tracing/instances/securepc/events/sched/sched_process_exec/enable \
            /sys/kernel/tracing/instances/securepc/events/sched/sched_process_fork/enable; do
            [ -f "${tp}" ] && (echo 0 > "${tp}" 2>/dev/null || true)
        done
        rmdir /sys/kernel/tracing/instances/securepc 2>/dev/null || true
    fi
    # Also clean up legacy global tracepoints if an older version enabled them
    for ltp in \
        /sys/kernel/tracing/events/fib/fib_table_lookup/enable \
        /sys/kernel/tracing/events/sock/inet_sock_set_state/enable \
        /sys/kernel/tracing/events/sched/sched_process_exec/enable \
        /sys/kernel/tracing/events/sched/sched_process_fork/enable; do
        [ -f "${ltp}" ] && (echo 0 > "${ltp}" 2>/dev/null || true)
    done
fi

echo "==> [3/8] Removing SecurePC firewall rules (nftables, iptables, ip6tables & ipsets)..."
if [ "${DRY_RUN}" -eq 1 ]; then
    echo "  [dry-run] Remove nftables 'table inet securepc', SECUREPC* chains, and securepc* ipsets"
else
    if [ -x "${BIN_DIR}/disable-securepc-firewall.sh" ]; then
        "${BIN_DIR}/disable-securepc-firewall.sh" --quiet --destroy-sets || true
    elif [ -x "${INSTALL_ROOT}/bin/disable-securepc-firewall.sh" ]; then
        "${INSTALL_ROOT}/bin/disable-securepc-firewall.sh" --quiet --destroy-sets || true
    fi
fi

echo "==> [4/8] Removing OS-level browser DoH/ECH policy drop-ins..."
BPOL_SCRIPT="${BIN_DIR}/securepc-browser-policy.py"
[ ! -f "${BPOL_SCRIPT}" ] && BPOL_SCRIPT="${INSTALL_ROOT}/bin/securepc-browser-policy.py"
if [ -f "${BPOL_SCRIPT}" ]; then
    if [ "${DRY_RUN}" -eq 1 ]; then
        /usr/bin/python3 -I "${BPOL_SCRIPT}" remove --dry-run || true
    else
        /usr/bin/python3 -I "${BPOL_SCRIPT}" remove || true
    fi
fi

echo "==> [5/8] Removing rsyslog, logrotate & login notification hooks..."
for hook in \
    /etc/rsyslog.d/10-securepc.conf \
    /etc/logrotate.d/securepc \
    /etc/profile.d/securepc-login-notify.sh \
    /etc/update-motd.d/99-securepc-alerts; do
    if [ -e "${hook}" ] || [ -L "${hook}" ]; then
        run_step rm -f "${hook}"
    fi
done
if [ "${DRY_RUN}" -eq 0 ] && command -v systemctl >/dev/null 2>&1; then
    systemctl restart rsyslog 2>/dev/null || true
fi

if [ -n "${TARGET_HOME}" ] && [ -d "${TARGET_HOME}" ]; then
    if [ -e "${TARGET_HOME}/.config/autostart/securepc-login-alert.desktop" ]; then
        run_step rm -f "${TARGET_HOME}/.config/autostart/securepc-login-alert.desktop"
    fi
    if [ -d "${TARGET_HOME}/.cache/securepc" ]; then
        run_step rm -rf "${TARGET_HOME}/.cache/securepc"
    fi
fi

echo "==> [6/8] Removing CLI symlinks..."
for link_cand in \
    /usr/local/bin/securepc-ctl \
    "${TARGET_HOME:+${TARGET_HOME}/bin/securepc-ctl}" \
    "${TARGET_HOME:+${TARGET_HOME}/.local/bin/securepc-ctl}"; do
    if [ -n "${link_cand}" ] && [ -L "${link_cand}" ]; then
        run_step rm -f "${link_cand}"
    fi
done

echo "==> [7/8] Removing /usr/local/lib/securepc runtime directory..."
if [ -d "${INSTALL_ROOT}" ]; then
    run_step rm -rf "${INSTALL_ROOT}"
fi

echo "==> [8/8] Handling logs, GeoIP data & /etc/securepc configuration..."
if [ "${PURGE_LOGS}" -eq 1 ]; then
    run_step rm -rf /var/log/securepc /var/lib/securepc /etc/securepc
    echo "  Purged /var/log/securepc, /var/lib/securepc, and /etc/securepc."
else
    rm -f /var/lib/securepc/active-backend 2>/dev/null || true
    echo "  Preserved /var/log/securepc and /etc/securepc (pass --purge to delete)."
fi

echo ""
if [ "${DRY_RUN}" -eq 1 ]; then
    echo "Dry-run complete. No system files or firewall rules were modified."
else
    echo "SecurePC has been completely uninstalled from this system."
fi

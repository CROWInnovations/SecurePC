#!/bin/sh
# ==============================================================================
# SecurePC — Multi-Backend Firewall Disabler (disable-securepc-firewall.sh)
# Author:  CROW Innovations (https://crowinnovations.com)
# License: GNU General Public License v3.0 (GPL-3.0)
# GitHub:  https://github.com/CROWInnovations/SecurePC
#
# Cleanly unhooks and removes SecurePC firewall rules across nftables,
# iptables/ip6tables/ipset, or Solaris pf/ipf without touching unrelated
# host, UFW, firewalld, or Docker rules.
# ==============================================================================
set -eu

PATH="/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin"
export PATH

SCRIPT_PATH="$0"
if command -v readlink >/dev/null 2>&1; then
    _rl="$(readlink -f -- "$0" 2>/dev/null || true)"
    [ -n "${_rl}" ] && SCRIPT_PATH="${_rl}"
fi
SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "${SCRIPT_PATH}")" && pwd -P)"

# shellcheck disable=SC1091
. "${SCRIPT_DIR}/securepc-lib.sh"
securepc_resolve_paths "${SCRIPT_DIR}"

QUIET=0
DESTROY_SETS=0
ONLY_BACKEND=""

for arg in "$@"; do
    case "${arg}" in
        -q|--quiet|--no-banner) QUIET=1 ;;
        --destroy-sets)         DESTROY_SETS=1 ;;
        --only-nftables)        ONLY_BACKEND="nftables" ;;
        --only-iptables)        ONLY_BACKEND="iptables" ;;
    esac
done

if [ "$(id -u)" -ne 0 ]; then
    exec sudo "$0" "$@"
fi

if [ "${QUIET}" -eq 0 ] && [ -f "${SCRIPT_DIR}/securepc-banner.sh" ]; then
    # shellcheck disable=SC1091
    . "${SCRIPT_DIR}/securepc-banner.sh"
    print_securepc_banner
    echo ""
fi

# 1. Remove native nftables table if present
if [ -z "${ONLY_BACKEND}" ] || [ "${ONLY_BACKEND}" = "nftables" ]; then
    if command -v nft >/dev/null 2>&1; then
        if nft list table inet securepc >/dev/null 2>&1; then
            nft delete table inet securepc 2>/dev/null || true
            if [ "${QUIET}" -eq 0 ]; then
                echo "Removed nftables 'table inet securepc'."
            fi
        fi
    fi
fi

# 2. Remove legacy/compat iptables, ip6tables & ipset state if present
if [ -z "${ONLY_BACKEND}" ] || [ "${ONLY_BACKEND}" = "iptables" ]; then
    if command -v iptables >/dev/null 2>&1; then
        while iptables -D OUTPUT -j SECUREPC_OUT 2>/dev/null; do :; done
        while iptables -D INPUT -j SECUREPC_IN 2>/dev/null; do :; done
        while iptables -D FORWARD -j SECUREPC_FWD 2>/dev/null; do :; done
        while iptables -D DOCKER-USER -j SECUREPC_FWD 2>/dev/null; do :; done

        # Flush all SECUREPC_* chains first so cross-chain references release cleanly
        for ch in $(iptables -S 2>/dev/null | awk '/^-N SECUREPC/ {print $2}'); do
            iptables -F "${ch}" 2>/dev/null || true
        done
        for ch in $(iptables -S 2>/dev/null | awk '/^-N SECUREPC/ {print $2}'); do
            iptables -X "${ch}" 2>/dev/null || true
        done
    fi

    if command -v ip6tables >/dev/null 2>&1; then
        while ip6tables -D OUTPUT -j SECUREPC6_OUT 2>/dev/null; do :; done
        while ip6tables -D INPUT -j SECUREPC6_IN 2>/dev/null; do :; done
        while ip6tables -D FORWARD -j SECUREPC6_FWD 2>/dev/null; do :; done

        for ch6 in $(ip6tables -S 2>/dev/null | awk '/^-N SECUREPC6/ {print $2}'); do
            ip6tables -F "${ch6}" 2>/dev/null || true
        done
        for ch6 in $(ip6tables -S 2>/dev/null | awk '/^-N SECUREPC6/ {print $2}'); do
            ip6tables -X "${ch6}" 2>/dev/null || true
        done
    fi

    if [ "${DESTROY_SETS}" -eq 1 ] && command -v ipset >/dev/null 2>&1; then
        for s in $(ipset list -n 2>/dev/null | grep -E '^securepc6?_'); do
            ipset destroy "${s}" 2>/dev/null || true
        done
    fi
fi

# 3. Solaris / illumos pf cleanup
if [ "$(uname -s 2>/dev/null || echo Linux)" = "SunOS" ] && [ -z "${ONLY_BACKEND}" ]; then
    if command -v pfctl >/dev/null 2>&1; then
        pfctl -a securepc -F all 2>/dev/null || true
    fi
fi

if [ -z "${ONLY_BACKEND}" ]; then
    rm -f "${SECUREPC_ACTIVE_BACKEND_FILE}" 2>/dev/null || true
    if [ "${QUIET}" -eq 0 ]; then
        echo "SecurePC firewall rules cleanly disabled."
    fi
fi

exit 0

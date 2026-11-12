#!/bin/sh
# ==============================================================================
# SecurePC — Shared Runtime Path, Config & Backend Detection Library
# Author:  CROW Innovations (https://crowinnovations.com)
# License: GNU General Public License v3.0 (GPL-3.0)
# GitHub:  https://github.com/CROWInnovations/SecurePC
#
# POSIX-portable across Bash, Dash, Zsh, and Solaris/illumos /bin/sh.
# ==============================================================================

# Hardened root-safe PATH
PATH="/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin"
export PATH

SECUREPC_INSTALL_ROOT="/usr/local/lib/securepc"
SECUREPC_CONF_DIR="/etc/securepc"
SECUREPC_VAR_LIB="/var/lib/securepc"
SECUREPC_VAR_LOG="/var/log/securepc"

# Defaults (overridden safely by /etc/securepc/securepc.conf)
FIREWALL_BACKEND="auto"
OUTBOUND_BLOCK_ACTION="reject"
ENABLE_IPV6="1"
BLOCK_DOH_DOT="1"
ENFORCE_BROWSER_POLICIES="1"
ENABLE_NFQUEUE_DPI="1"
NFQUEUE_NUM="5353"
ENABLE_OPENSSL_PROBES="1"
SANDBOX_LAN_ONLY_USERS=""

securepc_resolve_paths() {
    # Caller may pass its resolved BIN_DIR as $1
    _caller_bin="${1:-}"
    if [ -d "${SECUREPC_INSTALL_ROOT}/bin" ] && [ -d "${SECUREPC_VAR_LIB}/lists" ]; then
        SECUREPC_BIN_DIR="${SECUREPC_INSTALL_ROOT}/bin"
        SECUREPC_LISTS_DIR="${SECUREPC_VAR_LIB}/lists"
        SECUREPC_RULES_DIR="${SECUREPC_VAR_LIB}/rules"
    elif [ -n "${_caller_bin}" ] && [ -d "${_caller_bin}/../lists" ]; then
        SECUREPC_BIN_DIR="${_caller_bin}"
        SECUREPC_BASE_TMP="$(CDPATH='' cd -- "${_caller_bin}/.." && pwd -P)"
        SECUREPC_LISTS_DIR="${SECUREPC_BASE_TMP}/lists"
        SECUREPC_RULES_DIR="${SECUREPC_BASE_TMP}/rules"
        if [ ! -d "${SECUREPC_CONF_DIR}" ] && [ -d "${SECUREPC_BASE_TMP}/etc" ]; then
            SECUREPC_CONF_DIR="${SECUREPC_BASE_TMP}/etc"
        fi
    else
        SECUREPC_BIN_DIR="${SECUREPC_INSTALL_ROOT}/bin"
        SECUREPC_LISTS_DIR="${SECUREPC_VAR_LIB}/lists"
        SECUREPC_RULES_DIR="${SECUREPC_VAR_LIB}/rules"
    fi
    SECUREPC_ACTIVE_BACKEND_FILE="${SECUREPC_VAR_LIB}/active-backend"
}

securepc_load_conf() {
    _conf_file="${SECUREPC_CONF_DIR}/securepc.conf"
    [ -r "${_conf_file}" ] || return 0

    # Parse simple KEY=VALUE pairs safely without executing shell commands
    while IFS= read -r _raw_line || [ -n "${_raw_line}" ]; do
        _line="${_raw_line%%#*}"
        # Trim leading/trailing whitespace
        _line="$(printf '%s' "${_line}" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
        [ -n "${_line}" ] || continue
        case "${_line}" in
            *=*) ;;
            *) continue ;;
        esac
        _key="${_line%%=*}"
        _val="${_line#*=}"
        # Strip matching single or double quotes
        case "${_val}" in
            \"*\") _val="${_val#\"}"; _val="${_val%\"}" ;;
            \'*\') _val="${_val#\'}"; _val="${_val%\'}" ;;
        esac
        case "${_key}" in
            FIREWALL_BACKEND)          FIREWALL_BACKEND="${_val}" ;;
            OUTBOUND_BLOCK_ACTION)     OUTBOUND_BLOCK_ACTION="${_val}" ;;
            ENABLE_IPV6)               ENABLE_IPV6="${_val}" ;;
            BLOCK_DOH_DOT)             BLOCK_DOH_DOT="${_val}" ;;
            ENFORCE_BROWSER_POLICIES)  ENFORCE_BROWSER_POLICIES="${_val}" ;;
            ENABLE_NFQUEUE_DPI)        ENABLE_NFQUEUE_DPI="${_val}" ;;
            NFQUEUE_NUM)               NFQUEUE_NUM="${_val}" ;;
            ENABLE_OPENSSL_PROBES)     ENABLE_OPENSSL_PROBES="${_val}" ;;
            SANDBOX_LAN_ONLY_USERS)    SANDBOX_LAN_ONLY_USERS="${_val}" ;;
        esac
    done < "${_conf_file}"
}

securepc_detect_backend() {
    _req="${1:-${FIREWALL_BACKEND:-auto}}"
    case "${_req}" in
        nftables|iptables|solaris_ipf)
            printf '%s\n' "${_req}"
            return 0
            ;;
    esac

    _os="$(uname -s 2>/dev/null || echo Linux)"
    if [ "${_os}" = "SunOS" ]; then
        printf 'solaris_ipf\n'
        return 0
    fi

    # Linux auto-detection:
    # 1. If nft exists and iptables is either absent or using nf_tables backend -> nftables
    # 2. If host uses iptables-legacy (without active nftables service) -> iptables
    if command -v nft >/dev/null 2>&1; then
        if ! command -v iptables >/dev/null 2>&1; then
            printf 'nftables\n'
            return 0
        fi
        _ipt_ver="$(iptables --version 2>/dev/null || true)"
        case "${_ipt_ver}" in
            *nf_tables*)
                printf 'nftables\n'
                return 0
                ;;
        esac
        if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet nftables 2>/dev/null; then
            printf 'nftables\n'
            return 0
        fi
    fi

    if command -v iptables >/dev/null 2>&1 && command -v ipset >/dev/null 2>&1; then
        printf 'iptables\n'
        return 0
    fi

    if command -v nft >/dev/null 2>&1; then
        printf 'nftables\n'
        return 0
    fi

    printf 'iptables\n'
}

securepc_get_active_backend() {
    if [ -r "${SECUREPC_ACTIVE_BACKEND_FILE:-/var/lib/securepc/active-backend}" ]; then
        head -n 1 "${SECUREPC_ACTIVE_BACKEND_FILE:-/var/lib/securepc/active-backend}" | tr -d '[:space:]'
        return 0
    fi
    securepc_detect_backend
}

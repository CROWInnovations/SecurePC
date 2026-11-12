#!/bin/sh
# ==============================================================================
# SecurePC — Multi-Backend Atomic Firewall Loader (enable-securepc-firewall.sh)
# Author:  CROW Innovations (https://crowinnovations.com)
# License: GNU General Public License v3.0 (GPL-3.0)
# GitHub:  https://github.com/CROWInnovations/SecurePC
#
# Automatically detects and atomically loads SecurePC protection via:
#   - Native dual-stack nftables (`table inet securepc`) on modern Linux
#   - Legacy/compat `ipset` + `iptables-restore` + `ip6tables-restore` fallback
#   - Solaris 11.4 Packet Filter (`pfctl`) on SunOS/illumos
#
# Enforces:
#   1. Hard blocking of China (.cn, Beijing, aliyuncs.com), Russia (.ru, .su, .рф),
#      Iran (.ir, .ایران), and all 16 Middle East countries (IPv4 & IPv6).
#   2. Anti-bypass blocking of encrypted DNS (DoT/DoQ port 853 & DoH port 443).
#   3. Fail-safe NFQUEUE synchronous inspection of DNS QNAMEs, TLS SNI & HTTP Host.
#   4. Kernel outbound connection logging ([SECUREPC-OUT:NET]) with socket UID.
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
securepc_load_conf

if [ "$(id -u)" -ne 0 ]; then
    exec sudo "$0" "$@"
fi

QUIET=0
BACKEND_OVERRIDE=""

while [ "$#" -gt 0 ]; do
    case "$1" in
        -q|--quiet|--no-banner)
            QUIET=1
            ;;
        --backend)
            shift
            BACKEND_OVERRIDE="${1:-auto}"
            ;;
        --backend=*)
            BACKEND_OVERRIDE="${1#*=}"
            ;;
    esac
    shift
done

if [ "${QUIET}" -eq 0 ] && [ -f "${SCRIPT_DIR}/securepc-banner.sh" ]; then
    # shellcheck disable=SC1091
    . "${SCRIPT_DIR}/securepc-banner.sh"
    print_securepc_banner
    echo ""
fi

mkdir -p "${SECUREPC_VAR_LIB}" "${SECUREPC_RULES_DIR}" "${SECUREPC_VAR_LOG}"
chmod 0755 "${SECUREPC_VAR_LIB}"
chmod 0750 "${SECUREPC_RULES_DIR}"

TMP_WORK="$(mktemp -d "${SECUREPC_RULES_DIR}/.tmp.XXXXXX")"
cleanup_tmp() {
    rm -rf "${TMP_WORK}" 2>/dev/null || true
}
trap cleanup_tmp EXIT INT TERM HUP

REQUESTED_BACKEND="${BACKEND_OVERRIDE:-${FIREWALL_BACKEND:-auto}}"
SELECTED_BACKEND="$(securepc_detect_backend "${REQUESTED_BACKEND}")"

log_step() {
    if [ "${QUIET}" -eq 0 ]; then
        printf '%s\n' "$*"
    fi
}

apply_nftables_backend() {
    log_step "==> [1/3] Compiling atomic dual-stack nftables ruleset (IPv4 + IPv6 + Anti-DoH/DoT)..."
    /usr/bin/python3 -I "${SCRIPT_DIR}/build-firewall-ruleset.py" \
        --backend nftables \
        --lists-dir "${SECUREPC_LISTS_DIR}" \
        --conf-dir "${SECUREPC_CONF_DIR}" \
        --out-dir "${TMP_WORK}"

    log_step "==> [2/3] Validating nftables ruleset via kernel dry-run (nft -c -f)..."
    if ! nft -c -f "${TMP_WORK}/securepc.nft" >/dev/null 2>&1; then
        return 1
    fi

    log_step "==> [3/3] Atomically activating 'table inet securepc' & cleaning legacy chains..."
    nft -f "${TMP_WORK}/securepc.nft"
    # Sweep away any lingering legacy iptables chains/ipsets so rules never double-run
    "${SCRIPT_DIR}/disable-securepc-firewall.sh" --quiet --only-iptables --destroy-sets || true

    cp -f "${TMP_WORK}/securepc.nft" "${SECUREPC_RULES_DIR}/securepc.nft"
    chmod 0600 "${SECUREPC_RULES_DIR}/securepc.nft"
    printf 'nftables\n' > "${SECUREPC_ACTIVE_BACKEND_FILE}"
    chmod 0644 "${SECUREPC_ACTIVE_BACKEND_FILE}"
    return 0
}

apply_iptables_backend() {
    log_step "==> [1/4] Compiling ipset + iptables/ip6tables rulesets (IPv4 + IPv6 + Anti-DoH/DoT)..."
    /usr/bin/python3 -I "${SCRIPT_DIR}/build-firewall-ruleset.py" \
        --backend iptables \
        --lists-dir "${SECUREPC_LISTS_DIR}" \
        --conf-dir "${SECUREPC_CONF_DIR}" \
        --out-dir "${TMP_WORK}"

    log_step "==> [2/4] Atomically swapping kernel ipset hash tables..."
    ipset restore < "${TMP_WORK}/securepc-ipset.restore"

    # Pre-create target chains idempotently so --noflush restore succeeds cleanly
    while IFS= read -r ch; do
        [ -n "${ch}" ] && (iptables -N "${ch}" 2>/dev/null || true)
    done < "${TMP_WORK}/securepc-chains.v4"

    if [ "${ENABLE_IPV6:-1}" = "1" ] && command -v ip6tables >/dev/null 2>&1; then
        while IFS= read -r ch6; do
            [ -n "${ch6}" ] && (ip6tables -N "${ch6}" 2>/dev/null || true)
        done < "${TMP_WORK}/securepc-chains.v6"
    fi

    log_step "==> [3/4] Preflight-testing & loading iptables/ip6tables custom chains..."
    if ! iptables-restore --test --noflush < "${TMP_WORK}/securepc-iptables.restore" >/dev/null 2>&1; then
        # Kernel lacks xt_NFQUEUE/xt_connbytes -> recompile pure xt_string static fallback
        /usr/bin/python3 -I "${SCRIPT_DIR}/build-firewall-ruleset.py" \
            --backend iptables \
            --no-nfqueue \
            --lists-dir "${SECUREPC_LISTS_DIR}" \
            --conf-dir "${SECUREPC_CONF_DIR}" \
            --out-dir "${TMP_WORK}"
        iptables-restore --test --noflush < "${TMP_WORK}/securepc-iptables.restore"
    fi
    iptables-restore --noflush < "${TMP_WORK}/securepc-iptables.restore"

    # Ensure top-level hooks sit at position 1 without creating an unhooked gap
    iptables -C OUTPUT -j SECUREPC_OUT 2>/dev/null || iptables -I OUTPUT 1 -j SECUREPC_OUT
    iptables -C INPUT -j SECUREPC_IN 2>/dev/null || iptables -I INPUT 1 -j SECUREPC_IN
    iptables -C FORWARD -j SECUREPC_FWD 2>/dev/null || iptables -I FORWARD 1 -j SECUREPC_FWD
    if iptables -L DOCKER-USER >/dev/null 2>&1; then
        iptables -C DOCKER-USER -j SECUREPC_FWD 2>/dev/null || iptables -I DOCKER-USER 1 -j SECUREPC_FWD
    fi

    if [ "${ENABLE_IPV6:-1}" = "1" ] && command -v ip6tables >/dev/null 2>&1; then
        if ip6tables-restore --test --noflush < "${TMP_WORK}/securepc-ip6tables.restore" >/dev/null 2>&1; then
            ip6tables-restore --noflush < "${TMP_WORK}/securepc-ip6tables.restore"
            ip6tables -C OUTPUT -j SECUREPC6_OUT 2>/dev/null || ip6tables -I OUTPUT 1 -j SECUREPC6_OUT
            ip6tables -C INPUT -j SECUREPC6_IN 2>/dev/null || ip6tables -I INPUT 1 -j SECUREPC6_IN
            ip6tables -C FORWARD -j SECUREPC6_FWD 2>/dev/null || ip6tables -I FORWARD 1 -j SECUREPC6_FWD
        fi
    fi

    log_step "==> [4/4] Cleaning any inactive nftables table & persisting state..."
    "${SCRIPT_DIR}/disable-securepc-firewall.sh" --quiet --only-nftables || true

    cp -f "${TMP_WORK}/securepc-ipset.restore" "${SECUREPC_RULES_DIR}/securepc-ipset.restore"
    cp -f "${TMP_WORK}/securepc-iptables.restore" "${SECUREPC_RULES_DIR}/securepc-iptables.rules"
    cp -f "${TMP_WORK}/securepc-ip6tables.restore" "${SECUREPC_RULES_DIR}/securepc-ip6tables.rules"
    chmod 0600 "${SECUREPC_RULES_DIR}/securepc-"*
    printf 'iptables\n' > "${SECUREPC_ACTIVE_BACKEND_FILE}"
    chmod 0644 "${SECUREPC_ACTIVE_BACKEND_FILE}"
    return 0
}

apply_solaris_backend() {
    log_step "==> [1/2] Compiling Solaris Packet Filter (pf) ruleset..."
    /usr/bin/python3 -I "${SCRIPT_DIR}/build-firewall-ruleset.py" \
        --backend solaris_ipf \
        --lists-dir "${SECUREPC_LISTS_DIR}" \
        --conf-dir "${SECUREPC_CONF_DIR}" \
        --out-dir "${TMP_WORK}"
    log_step "==> [2/2] Loading ruleset into Solaris pf anchor 'securepc'..."
    pfctl -a securepc -f "${TMP_WORK}/securepc-pf.conf"
    cp -f "${TMP_WORK}/securepc-pf.conf" "${SECUREPC_RULES_DIR}/securepc-pf.conf"
    printf 'solaris_ipf\n' > "${SECUREPC_ACTIVE_BACKEND_FILE}"
    chmod 0644 "${SECUREPC_ACTIVE_BACKEND_FILE}"
}

ACTIVE_BACKEND=""
if [ "${SELECTED_BACKEND}" = "nftables" ]; then
    if apply_nftables_backend; then
        ACTIVE_BACKEND="nftables"
    elif [ "${REQUESTED_BACKEND}" = "auto" ] && command -v iptables >/dev/null 2>&1 && command -v ipset >/dev/null 2>&1; then
        log_step "    [!] nftables kernel check failed; falling back automatically to iptables + ipset..."
        apply_iptables_backend
        ACTIVE_BACKEND="iptables"
    else
        echo "ERROR: Failed to validate or load nftables ruleset." >&2
        exit 1
    fi
elif [ "${SELECTED_BACKEND}" = "iptables" ]; then
    apply_iptables_backend
    ACTIVE_BACKEND="iptables"
elif [ "${SELECTED_BACKEND}" = "solaris_ipf" ]; then
    apply_solaris_backend
    ACTIVE_BACKEND="solaris_ipf"
else
    echo "ERROR: Unsupported firewall backend '${SELECTED_BACKEND}'." >&2
    exit 1
fi

if [ "${QUIET}" -eq 0 ]; then
    echo "========================================================================"
    echo " SECUREPC PRODUCTION FIREWALL PROFILE ACTIVE"
    echo " - Active Engine:        ${ACTIVE_BACKEND} (Mode: ${OUTBOUND_BLOCK_ACTION})"
    echo " - Hard-Blocked Regions: China (.cn, Beijing, aliyuncs.com),"
    echo "                         Russia (.ru, .su, .рф),"
    echo "                         Iran (.ir, .ایران),"
    echo "                         Middle East (AE,BH,CY,EG,IL,IQ,JO,KW,LB,OM,PS,QA,SA,SY,TR,YE)"
    echo " - Anti-Bypass:          DoT/DoQ (853) & DoH (443) $( [ "${BLOCK_DOH_DOT:-1}" = "1" ] && echo "BLOCKED" || echo "off" ) + NFQUEUE DNS/SNI DPI"
    echo " - Non-US Attribution:   Worldwide GeoIP + OpenSSL X.509 Cert Inspection"
    echo "========================================================================"
fi

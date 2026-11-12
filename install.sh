#!/usr/bin/env bash
# ==============================================================================
# SecurePC — Production Turnkey Linux & Solaris Installer (install.sh)
# Author:  CROW Innovations (https://crowinnovations.com)
# License: GNU General Public License v3.0 (GPL-3.0)
# GitHub:  https://github.com/CROWInnovations/SecurePC
#
# Installs SecurePC into hardened root-owned system locations:
#   - /usr/local/lib/securepc/   (immutable 0755 root:root runtime & backends)
#   - /etc/securepc/             (admin configuration & custom allow/blocklists)
#   - /var/lib/securepc/         (Worldwide RIR GeoIP tables & compiled rules)
#   - /var/log/securepc/         (tamper-protected 0750 root:securepc audit logs)
#   - /usr/local/bin/securepc-ctl
# ==============================================================================
set -euo pipefail

PATH="/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin"
export PATH

SCRIPT_DIR="$(cd -- "$(dirname -- "$(readlink -f -- "${BASH_SOURCE[0]}")")" && pwd -P)"
SRC_BIN_DIR="${SCRIPT_DIR}/bin"
SRC_ETC_DIR="${SCRIPT_DIR}/etc"
SRC_LISTS_DIR="${SCRIPT_DIR}/lists"

INSTALL_ROOT="/usr/local/lib/securepc"
DEST_BIN_DIR="${INSTALL_ROOT}/bin"
CONF_DIR="/etc/securepc"
VAR_LIB_DIR="/var/lib/securepc"
DEST_LISTS_DIR="${VAR_LIB_DIR}/lists"
DEST_RULES_DIR="${VAR_LIB_DIR}/rules"
VAR_LOG_DIR="/var/log/securepc"

BACKEND_OPT=""
BROWSER_POL_OPT=""

usage() {
    cat <<'EOF'
Usage: sudo ./install.sh [OPTIONS]

Options:
  --backend <auto|nftables|iptables|solaris_ipf>  Select firewall engine (default: auto)
  --no-browser-policy                             Skip Firefox/Chromium DoH & ECH lock policies
  -h, --help                                      Show this help message
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --backend)
            shift
            BACKEND_OPT="${1:-auto}"
            ;;
        --backend=*)
            BACKEND_OPT="${1#*=}"
            ;;
        --no-browser-policy)
            BROWSER_POL_OPT="0"
            ;;
        -h|--help)
            if [ -f "${SRC_BIN_DIR}/securepc-banner.sh" ]; then
                # shellcheck disable=SC1091
                . "${SRC_BIN_DIR}/securepc-banner.sh"
                print_securepc_banner
                echo ""
            fi
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            usage >&2
            exit 1
            ;;
    esac
    shift
done

if [ "$(id -u)" -ne 0 ]; then
    echo "Elevating to root via sudo..."
    exec sudo "$0" \
        ${BACKEND_OPT:+--backend "${BACKEND_OPT}"} \
        $( [ "${BROWSER_POL_OPT}" = "0" ] && echo "--no-browser-policy" || true )
fi

if [ -f "${SRC_BIN_DIR}/securepc-banner.sh" ]; then
    # shellcheck disable=SC1091
    . "${SRC_BIN_DIR}/securepc-banner.sh"
    print_securepc_banner
    echo ""
fi

TARGET_USER="${SUDO_USER:-$(logname 2>/dev/null || echo "")}"
if [ "${TARGET_USER}" = "root" ]; then
    TARGET_USER=""
fi

on_install_error() {
    local ec=$?
    echo "" >&2
    echo "[!] SecurePC installation encountered an error (exit code ${ec})." >&2
    echo "    Cleaning up any partial temporary firewall state..." >&2
    if [ -x "${DEST_BIN_DIR}/disable-securepc-firewall.sh" ]; then
        "${DEST_BIN_DIR}/disable-securepc-firewall.sh" --quiet || true
    fi
    exit "${ec}"
}
trap on_install_error ERR

echo "==> [1/8] Checking required system packages (firewall engine, openssl, python3, iproute2, rsyslog, logrotate, acl)..."
install_missing_linux_pkgs() {
    if command -v apt-get >/dev/null 2>&1; then
        local pkgs=()
        command -v openssl >/dev/null 2>&1   || pkgs+=("openssl")
        command -v python3 >/dev/null 2>&1   || pkgs+=("python3")
        command -v ss >/dev/null 2>&1        || pkgs+=("iproute2")
        command -v rsyslogd >/dev/null 2>&1  || pkgs+=("rsyslog")
        command -v logrotate >/dev/null 2>&1 || pkgs+=("logrotate")
        command -v setfacl >/dev/null 2>&1   || pkgs+=("acl")
        if [ "${BACKEND_OPT}" = "iptables" ]; then
            command -v iptables >/dev/null 2>&1 || pkgs+=("iptables")
            command -v ipset >/dev/null 2>&1    || pkgs+=("ipset")
        elif ! command -v nft >/dev/null 2>&1; then
            if apt-cache show nftables >/dev/null 2>&1; then
                pkgs+=("nftables")
            else
                command -v iptables >/dev/null 2>&1 || pkgs+=("iptables")
                command -v ipset >/dev/null 2>&1    || pkgs+=("ipset")
            fi
        fi
        if [ "${#pkgs[@]}" -gt 0 ]; then
            DEBIAN_FRONTEND=noninteractive apt-get update -qq
            DEBIAN_FRONTEND=noninteractive apt-get install -y "${pkgs[@]}"
        fi
    elif command -v dnf >/dev/null 2>&1; then
        local pkgs=()
        command -v openssl >/dev/null 2>&1   || pkgs+=("openssl")
        command -v python3 >/dev/null 2>&1   || pkgs+=("python3")
        command -v ss >/dev/null 2>&1        || pkgs+=("iproute")
        command -v logrotate >/dev/null 2>&1 || pkgs+=("logrotate")
        command -v setfacl >/dev/null 2>&1   || pkgs+=("acl")
        command -v nft >/dev/null 2>&1       || pkgs+=("nftables")
        if [ "${#pkgs[@]}" -gt 0 ]; then
            dnf install -y "${pkgs[@]}"
        fi
    elif command -v yum >/dev/null 2>&1; then
        local pkgs=()
        command -v openssl >/dev/null 2>&1   || pkgs+=("openssl")
        command -v python3 >/dev/null 2>&1   || pkgs+=("python3")
        command -v ss >/dev/null 2>&1        || pkgs+=("iproute")
        command -v iptables >/dev/null 2>&1  || pkgs+=("iptables")
        command -v ipset >/dev/null 2>&1     || pkgs+=("ipset")
        if [ "${#pkgs[@]}" -gt 0 ]; then
            yum install -y "${pkgs[@]}"
        fi
    elif command -v pacman >/dev/null 2>&1; then
        local pkgs=()
        command -v openssl >/dev/null 2>&1   || pkgs+=("openssl")
        command -v python3 >/dev/null 2>&1   || pkgs+=("python")
        command -v ss >/dev/null 2>&1        || pkgs+=("iproute2")
        command -v nft >/dev/null 2>&1       || pkgs+=("nftables")
        if [ "${#pkgs[@]}" -gt 0 ]; then
            pacman -Sy --noconfirm "${pkgs[@]}"
        fi
    elif command -v zypper >/dev/null 2>&1; then
        local pkgs=()
        command -v openssl >/dev/null 2>&1   || pkgs+=("openssl")
        command -v python3 >/dev/null 2>&1   || pkgs+=("python3")
        command -v ss >/dev/null 2>&1        || pkgs+=("iproute2")
        command -v nft >/dev/null 2>&1       || pkgs+=("nftables")
        if [ "${#pkgs[@]}" -gt 0 ]; then
            zypper --non-interactive install "${pkgs[@]}"
        fi
    fi
    return 0
}

if [ "$(uname -s)" = "Linux" ]; then
    install_missing_linux_pkgs
fi

echo "==> [2/8] Installing hardened root-owned runtime (/usr/local/lib/securepc) & config (/etc/securepc)..."
install -d -o root -g root -m 0755 "${INSTALL_ROOT}" "${DEST_BIN_DIR}" "${CONF_DIR}" "${VAR_LIB_DIR}" "${DEST_LISTS_DIR}"
install -d -o root -g root -m 0750 "${DEST_RULES_DIR}"

# Install runtime executables & libraries owned strictly by root:root (eliminates /home LPE risk)
for f in \
    securepc-banner.sh \
    securepc-lib.sh \
    securepc-ctl \
    enable-securepc-firewall.sh \
    disable-securepc-firewall.sh \
    securepc-login-notify.sh \
    securepc-gui-notify.sh \
    build-firewall-ruleset.py \
    build-ip-lists.py \
    securepc-browser-policy.py \
    securepc_geo_cert.py \
    securepc-lookup.py \
    securepc-monitor.py; do
    install -o root -g root -m 0755 "${SRC_BIN_DIR}/${f}" "${DEST_BIN_DIR}/${f}"
done
install -o root -g root -m 0755 "${SCRIPT_DIR}/uninstall.sh" "${INSTALL_ROOT}/uninstall.sh"
ln -sf "${DEST_BIN_DIR}/securepc-ctl" /usr/local/bin/securepc-ctl

# Install default config files without clobbering existing admin customizations
for cf in securepc.conf allowlist-ips.txt blocklist-ips.txt blocklist-domains.txt; do
    if [ ! -f "${CONF_DIR}/${cf}" ]; then
        install -o root -g root -m 0644 "${SRC_ETC_DIR}/${cf}" "${CONF_DIR}/${cf}"
    fi
done

if [ -n "${BACKEND_OPT}" ]; then
    sed -i "s/^FIREWALL_BACKEND=.*/FIREWALL_BACKEND=\"${BACKEND_OPT}\"/" "${CONF_DIR}/securepc.conf"
fi
if [ "${BROWSER_POL_OPT}" = "0" ]; then
    sed -i 's/^ENFORCE_BROWSER_POLICIES=.*/ENFORCE_BROWSER_POLICIES="0"/' "${CONF_DIR}/securepc.conf"
fi

# Clean up any legacy root-owned artifacts inside the user's git workspace
rm -f "${SCRIPT_DIR}/rules/.ipt."* "${SCRIPT_DIR}/rules/.ipset."* 2>/dev/null || true
if [ -n "${TARGET_USER}" ]; then
    chown -R "${TARGET_USER}:${TARGET_USER}" "${SCRIPT_DIR}/logs" "${SCRIPT_DIR}/rules" 2>/dev/null || true
fi

echo "==> [3/8] Deploying Worldwide RIR GeoIP & CIDR blocklists to /var/lib/securepc/lists..."
if ls "${SRC_LISTS_DIR}"/*.txt >/dev/null 2>&1; then
    for lf in "${SRC_LISTS_DIR}"/*.txt "${SRC_LISTS_DIR}"/*.tsv; do
        [ -f "${lf}" ] && install -o root -g root -m 0644 "${lf}" "${DEST_LISTS_DIR}/$(basename -- "${lf}")"
    done
fi
if [ ! -s "${DEST_LISTS_DIR}/world-geoip-v4.tsv" ]; then
    echo "    Building Worldwide RIR GeoIP & CIDR blocklists from upstream RIR feeds..."
    /usr/bin/python3 -I "${DEST_BIN_DIR}/build-ip-lists.py" --lists-dir "${DEST_LISTS_DIR}"
fi

echo "==> [4/8] Configuring tamper-protected /var/log/securepc & securepc audit group..."
if ! getent group securepc >/dev/null 2>&1; then
    groupadd -r securepc 2>/dev/null || groupadd securepc 2>/dev/null || true
fi
LOG_GROUP="root"
if getent group securepc >/dev/null 2>&1; then
    LOG_GROUP="securepc"
elif getent group adm >/dev/null 2>&1; then
    LOG_GROUP="adm"
fi

if [ -n "${TARGET_USER}" ] && [ "${LOG_GROUP}" = "securepc" ]; then
    usermod -aG securepc "${TARGET_USER}" 2>/dev/null || true
fi

install -d -o root -g "${LOG_GROUP}" -m 0750 "${VAR_LOG_DIR}"
for lf in \
    connections.log connections.jsonl \
    outbound-internet.log outbound-internet.jsonl outbound-summary.txt \
    non-us-traffic.log non-us-traffic.jsonl non-us-summary.txt unread-non-us.log \
    blocked-alerts.log unread-alerts.log \
    iptables-blocked.log iptables-outbound.log; do
    touch "${VAR_LOG_DIR}/${lf}"
    chown "root:${LOG_GROUP}" "${VAR_LOG_DIR}/${lf}"
    chmod 0640 "${VAR_LOG_DIR}/${lf}"
done

# Grant read-only POSIX ACL to installing admin user & adm group so non-sudo CLI
# inspection works immediately without requiring a logout/re-login, while keeping
# all audit logs strictly non-writable by non-root processes.
if command -v setfacl >/dev/null 2>&1; then
    if [ -n "${TARGET_USER}" ]; then
        setfacl -m "u:${TARGET_USER}:rx" "${VAR_LOG_DIR}" 2>/dev/null || true
        setfacl -d -m "u:${TARGET_USER}:r,g:${LOG_GROUP}:r" "${VAR_LOG_DIR}" 2>/dev/null || true
        setfacl -m "u:${TARGET_USER}:r" "${VAR_LOG_DIR}"/* 2>/dev/null || true
    fi
fi

echo "==> [5/8] Configuring rsyslog routing, logrotate & Console/SSH/Zsh/GUI login hooks..."
if [ -d /etc/rsyslog.d ] && command -v rsyslogd >/dev/null 2>&1; then
    cat <<EOF > /etc/rsyslog.d/10-securepc.conf
# SecurePC Netfilter Log Routing (Modern RainerScript — stops duplicate syslog spam)
if (\$msg contains '[SECUREPC-BLK:') then {
    action(type="omfile" file="/var/log/securepc/iptables-blocked.log" fileOwner="root" fileGroup="${LOG_GROUP}" fileCreateMode="0640")
    stop
}
if (\$msg contains '[SECUREPC-OUT:') then {
    action(type="omfile" file="/var/log/securepc/iptables-outbound.log" fileOwner="root" fileGroup="${LOG_GROUP}" fileCreateMode="0640")
    stop
}
EOF
    chmod 0644 /etc/rsyslog.d/10-securepc.conf
    systemctl restart rsyslog 2>/dev/null || true
fi

if [ -d /etc/logrotate.d ]; then
    cat <<EOF > /etc/logrotate.d/securepc
/var/log/securepc/*.log /var/log/securepc/*.jsonl {
    weekly
    rotate 8
    maxsize 50M
    missingok
    notifempty
    compress
    delaycompress
    copytruncate
    create 0640 root ${LOG_GROUP}
}
EOF
    chmod 0644 /etc/logrotate.d/securepc
fi

# POSIX / Bash / Zsh interactive login banner hook (uses $- instead of PS1 so Kali/Debian Zsh zprofile works)
cat <<EOF > /etc/profile.d/securepc-login-notify.sh
# SecurePC Interactive Login Notification Hook (Console & SSH — Bash, Dash & Zsh safe)
case "\${-:-}" in
    *i*)
        if [ -z "\${SECUREPC_LOGIN_NOTIFIED:-}" ]; then
            SECUREPC_LOGIN_NOTIFIED=1
            export SECUREPC_LOGIN_NOTIFIED
            if [ -x "${DEST_BIN_DIR}/securepc-login-notify.sh" ]; then
                "${DEST_BIN_DIR}/securepc-login-notify.sh"
            fi
        fi
        ;;
esac
EOF
chmod 0644 /etc/profile.d/securepc-login-notify.sh

if [ -n "${TARGET_USER}" ]; then
    TARGET_HOME="$(getent passwd "${TARGET_USER}" | cut -d: -f6 || true)"
    if [ -n "${TARGET_HOME}" ] && [ -d "${TARGET_HOME}/.config" ]; then
        mkdir -p "${TARGET_HOME}/.config/autostart"
        cat <<EOF > "${TARGET_HOME}/.config/autostart/securepc-login-alert.desktop"
[Desktop Entry]
Type=Application
Name=SecurePC Firewall Login Alert
Comment=Notifies user of blocked traffic (CN, RU, IR, Middle East) and flagged Non-US destinations
Exec=${DEST_BIN_DIR}/securepc-gui-notify.sh
Terminal=false
Hidden=false
X-GNOME-Autostart-enabled=true
EOF
        chown "${TARGET_USER}:${TARGET_USER}" "${TARGET_HOME}/.config/autostart" "${TARGET_HOME}/.config/autostart/securepc-login-alert.desktop" 2>/dev/null || true
    fi
fi

echo "==> [6/8] Enforcing OS-level browser DNS-over-HTTPS (DoH) & ECH anti-bypass policies..."
# shellcheck disable=SC1091
. "${DEST_BIN_DIR}/securepc-lib.sh"
securepc_resolve_paths "${DEST_BIN_DIR}"
securepc_load_conf
if [ "${ENFORCE_BROWSER_POLICIES:-1}" = "1" ]; then
    /usr/bin/python3 -I "${DEST_BIN_DIR}/securepc-browser-policy.py" apply
else
    echo "    Skipped browser policy installation (ENFORCE_BROWSER_POLICIES=0)."
fi

echo "==> [7/8] Installing hardened systemd units (boot-time firewall, daemon & weekly GeoIP updater)..."
if command -v systemctl >/dev/null 2>&1 && [ -d /etc/systemd/system ]; then
    cat <<EOF > /etc/systemd/system/securepc-firewall.service
[Unit]
Description=SecurePC Early-Boot Netfilter/nftables Geo-Firewall & Anti-DoH Profile
DefaultDependencies=no
After=local-fs.target systemd-modules-load.service
Before=network-pre.target shutdown.target
Wants=network-pre.target
Conflicts=shutdown.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=${DEST_BIN_DIR}/enable-securepc-firewall.sh --quiet
ExecReload=${DEST_BIN_DIR}/enable-securepc-firewall.sh --quiet
ExecStop=${DEST_BIN_DIR}/disable-securepc-firewall.sh --quiet --destroy-sets

[Install]
WantedBy=multi-user.target
EOF

    cat <<EOF > /etc/systemd/system/securepc-monitor.service
[Unit]
Description=SecurePC Network Attribution, Synchronous NFQUEUE DPI & OpenSSL X.509 Daemon
After=securepc-firewall.service network-online.target rsyslog.service
Requires=securepc-firewall.service
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=/usr/bin/python3 -I -u ${DEST_BIN_DIR}/securepc-monitor.py
ExecReload=/bin/kill -HUP \$MAINPID
Restart=always
RestartSec=2
PrivateTmp=yes
ProtectSystem=full
ProtectHome=read-only
UMask=0027

[Install]
WantedBy=multi-user.target
EOF

    cat <<EOF > /etc/systemd/system/securepc-geoip-update.service
[Unit]
Description=SecurePC Automatic Worldwide RIR GeoIP & ASN Blocklist Refresh
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
User=root
ExecStart=/usr/bin/python3 -I ${DEST_BIN_DIR}/build-ip-lists.py --lists-dir ${DEST_LISTS_DIR}
ExecStartPost=${DEST_BIN_DIR}/enable-securepc-firewall.sh --quiet
ExecStartPost=-/bin/systemctl kill -s HUP securepc-monitor.service
EOF

    cat <<EOF > /etc/systemd/system/securepc-geoip-update.timer
[Unit]
Description=Weekly Refresh of SecurePC Worldwide RIR GeoIP & Blocklist Tables

[Timer]
OnCalendar=weekly
RandomizedDelaySec=6h
Persistent=true

[Install]
WantedBy=timers.target
EOF

    chmod 0644 \
        /etc/systemd/system/securepc-firewall.service \
        /etc/systemd/system/securepc-monitor.service \
        /etc/systemd/system/securepc-geoip-update.service \
        /etc/systemd/system/securepc-geoip-update.timer

    systemctl daemon-reload
    systemctl enable securepc-firewall.service securepc-monitor.service securepc-geoip-update.timer
fi

echo "==> [8/8] Activating SecurePC firewall profile, starting daemon & verifying installation..."
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    "${DEST_BIN_DIR}/enable-securepc-firewall.sh"
    systemctl start securepc-firewall.service
    systemctl restart securepc-monitor.service
    systemctl start securepc-geoip-update.timer
    sleep 1
    echo ""
    /usr/local/bin/securepc-ctl doctor || true
else
    "${DEST_BIN_DIR}/enable-securepc-firewall.sh"
fi

echo ""
echo "SecurePC installation complete."
echo "Run 'securepc-ctl status', 'securepc-ctl doctor', or 'securepc-ctl banner' to inspect."

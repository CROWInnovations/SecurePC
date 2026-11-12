#!/bin/sh
# ==============================================================================
# SecurePC — Login Notification & Traffic Attribution Banner (POSIX / Bash / Zsh)
# Author:  CROW Innovations (https://crowinnovations.com)
# License: GNU General Public License v3.0 (GPL-3.0)
# GitHub:  https://github.com/CROWInnovations/SecurePC
#
# Displays upon interactive login (Console or SSH) without requiring write
# permissions on /var/log/securepc (tracks per-user login state in ~/.cache).
# ==============================================================================

NO_CLEAR="${1:-}"
SCRIPT_PATH="$0"
if command -v readlink >/dev/null 2>&1; then
    _rl="$(readlink -f -- "$0" 2>/dev/null || true)"
    [ -n "${_rl}" ] && SCRIPT_PATH="${_rl}"
fi
SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "${SCRIPT_PATH}")" && pwd -P)"

if [ -f "${SCRIPT_DIR}/securepc-banner.sh" ]; then
    # shellcheck disable=SC1091
    . "${SCRIPT_DIR}/securepc-banner.sh"
fi

UNREAD_LOG="/var/log/securepc/unread-alerts.log"
BLOCKED_LOG="/var/log/securepc/blocked-alerts.log"
KERN_BLOCK_LOG="/var/log/securepc/iptables-blocked.log"
UNREAD_NON_US_LOG="/var/log/securepc/unread-non-us.log"
OUTBOUND_LOG="/var/log/securepc/outbound-internet.log"
OUTBOUND_SUMMARY="/var/log/securepc/outbound-summary.txt"

if [ -n "${NO_COLOR:-}" ]; then
    RED=""
    YELLOW=""
    MAGENTA=""
    CYAN=""
    GREEN=""
    BLUE=""
    BOLD=""
    RESET=""
else
    RED='\033[1;31m'
    YELLOW='\033[1;33m'
    MAGENTA='\033[1;35m'
    CYAN='\033[1;36m'
    GREEN='\033[1;32m'
    BLUE='\033[1;34m'
    BOLD='\033[1;37m'
    RESET='\033[0m'
fi

count_lines() {
    if [ -r "$1" ] && [ -s "$1" ]; then
        wc -l < "$1" 2>/dev/null | tr -d '[:space:]'
    else
        printf '0'
    fi
}

UNREAD_COUNT="$(count_lines "${UNREAD_LOG}")"
TOTAL_BLK_COUNT="$(count_lines "${BLOCKED_LOG}")"
KERN_COUNT="$(count_lines "${KERN_BLOCK_LOG}")"
UNREAD_NON_US_TOTAL="$(count_lines "${UNREAD_NON_US_LOG}")"
OUTBOUND_COUNT="$(count_lines "${OUTBOUND_LOG}")"

# Compute newly unseen Non-US events for this user via user-owned ~/.cache cursor
NEW_NON_US_START=1
SHOW_NON_US_COUNT=0
CURSOR_DIR="${HOME:-/tmp}/.cache/securepc"
CURSOR_FILE="${CURSOR_DIR}/login-non-us.cursor"

if [ "${UNREAD_NON_US_TOTAL}" -gt 0 ] && [ -r "${UNREAD_NON_US_LOG}" ]; then
    CUR_INO="$(stat -c '%i' "${UNREAD_NON_US_LOG}" 2>/dev/null || echo 0)"
    PREV_INO=""
    PREV_LINES=0
    if [ -r "${CURSOR_FILE}" ]; then
        IFS=: read -r PREV_INO PREV_LINES < "${CURSOR_FILE}" 2>/dev/null || true
    fi
    case "${PREV_LINES}" in ''|*[!0-9]*) PREV_LINES=0 ;; esac

    if [ "${NO_CLEAR}" = "--no-clear" ]; then
        SHOW_NON_US_COUNT="${UNREAD_NON_US_TOTAL}"
        NEW_NON_US_START=1
    elif [ "${CUR_INO}" = "${PREV_INO}" ] && [ "${UNREAD_NON_US_TOTAL}" -ge "${PREV_LINES}" ]; then
        SHOW_NON_US_COUNT=$((UNREAD_NON_US_TOTAL - PREV_LINES))
        NEW_NON_US_START=$((PREV_LINES + 1))
    else
        SHOW_NON_US_COUNT="${UNREAD_NON_US_TOTAL}"
        NEW_NON_US_START=1
    fi

    if [ "${NO_CLEAR}" != "--no-clear" ] && [ "${SHOW_NON_US_COUNT}" -gt 0 ] && [ -n "${HOME:-}" ] && [ -d "${HOME}" ]; then
        mkdir -p "${CURSOR_DIR}" 2>/dev/null || true
        chmod 0700 "${CURSOR_DIR}" 2>/dev/null || true
        printf '%s:%s\n' "${CUR_INO}" "${UNREAD_NON_US_TOTAL}" > "${CURSOR_FILE}" 2>/dev/null || true
    fi
fi

printf '\n'
if command -v print_securepc_banner >/dev/null 2>&1; then
    print_securepc_banner
    printf '\n'
fi

# ------------------------------------------------------------------------------
# SECTION 1: CRITICAL BLOCKED TRAFFIC ALERTS (CHINA / RUSSIA / IRAN / MIDDLE EAST)
# ------------------------------------------------------------------------------
if [ "${UNREAD_COUNT}" -gt 0 ] && [ -r "${UNREAD_LOG}" ]; then
    printf "${RED}===================================================================================================================================================${RESET}\n"
    printf "${RED}  [!] SECUREPC CRITICAL FIREWALL ALERT — BLOCKED THREAT TRAFFIC DETECTED (China / Russia / Iran / Middle East / DoH Bypass)${RESET}\n"
    printf "${YELLOW}  Blocked Regions:${RESET} China (${BOLD}*.cn, Beijing, aliyuncs${RESET}), Russia (${BOLD}*.ru, *.su, .рф${RESET}), Iran (${BOLD}*.ir${RESET}) & Middle East (${BOLD}16 Countries${RESET})\n"
    printf "${YELLOW}  Unread Alerts:${RESET} ${RED}${BOLD}%s${RESET}  |  ${YELLOW}Total Attributed Blocks:${RESET} ${BOLD}%s${RESET}  |  ${YELLOW}Kernel Log Drops:${RESET} ${BOLD}%s${RESET}\n" "${UNREAD_COUNT}" "${TOTAL_BLK_COUNT}" "${KERN_COUNT}"
    printf "${RED}---------------------------------------------------------------------------------------------------------------------------------------------------${RESET}\n"
    tail -n 10 "${UNREAD_LOG}" | sed 's/^/  /'
    printf "${RED}---------------------------------------------------------------------------------------------------------------------------------------------------${RESET}\n"
    printf "  ${GREEN}Acknowledge Alerts:${RESET} Run '${BOLD}sudo securepc-ctl ack${RESET}' to clear unread alert queues\n"
    printf "${RED}===================================================================================================================================================${RESET}\n\n"
fi

# ------------------------------------------------------------------------------
# SECTION 2: FIRST-LOGIN NON-US DESTINATION FLAGS
# ------------------------------------------------------------------------------
if [ "${SHOW_NON_US_COUNT}" -gt 0 ] && [ -r "${UNREAD_NON_US_LOG}" ]; then
    printf "${MAGENTA}===================================================================================================================================================${RESET}\n"
    printf "${MAGENTA}  [⚑] SECUREPC FIRST-LOGIN NON-US TRAFFIC FLAG — %s NEW FOREIGN CONNECTION(S) DETECTED${RESET}\n" "${SHOW_NON_US_COUNT}"
    printf "${MAGENTA}---------------------------------------------------------------------------------------------------------------------------------------------------${RESET}\n"
    sed -n "${NEW_NON_US_START},\$p" "${UNREAD_NON_US_LOG}" | tail -n 8 | sed 's/^/  /'
    printf "${MAGENTA}---------------------------------------------------------------------------------------------------------------------------------------------------${RESET}\n"
    printf "  ${GREEN}Inspect:${RESET} '${BOLD}securepc-ctl non-us${RESET}'  |  ${GREEN}Clear System Queue:${RESET} '${BOLD}sudo securepc-ctl ack${RESET}'\n"
    printf "${MAGENTA}===================================================================================================================================================${RESET}\n\n"
fi

# ------------------------------------------------------------------------------
# SECTION 3: OUTBOUND INTERNET CONNECTIONS SUMMARY (ALL TRAFFIC)
# ------------------------------------------------------------------------------
HOST_UPPER="$(hostname -s 2>/dev/null | tr '[:lower:]' '[:upper:]' || echo "HOST")"
printf "${BLUE}===================================================================================================================================================${RESET}\n"
printf "${CYAN}  [*] %s OUTBOUND INTERNET TRAFFIC MONITOR (Country, PID/PPID, Service/Software, Outbound IP, Port & OpenSSL Cert Domain)${RESET}\n" "${HOST_UPPER}"
printf "  ${YELLOW}Total Logged Outbound Internet Events:${RESET} ${BOLD}%s${RESET}  |  ${YELLOW}Blocked Threats:${RESET} ${BOLD}%s${RESET} (Unread: ${RED}%s${RESET})\n" "${OUTBOUND_COUNT}" "${TOTAL_BLK_COUNT}" "${UNREAD_COUNT}"
printf "${BLUE}---------------------------------------------------------------------------------------------------------------------------------------------------${RESET}\n"

if [ -r "${OUTBOUND_SUMMARY}" ] && [ -s "${OUTBOUND_SUMMARY}" ]; then
    head -n 16 "${OUTBOUND_SUMMARY}" | sed 's/^/  /'
else
    printf "  No outbound internet connections recorded yet in current summary window.\n"
fi

printf "${BLUE}---------------------------------------------------------------------------------------------------------------------------------------------------${RESET}\n"
printf "  ${GREEN}Logs:${RESET}     /var/log/securepc/outbound-internet.log  |  /var/log/securepc/blocked-alerts.log\n"
printf "  ${GREEN}Commands:${RESET} '${BOLD}securepc-ctl status${RESET}' | '${BOLD}securepc-ctl doctor${RESET}' | '${BOLD}securepc-ctl lookup <TARGET>${RESET}' | '${BOLD}securepc-ctl cert <IP>${RESET}'\n"
printf "${BLUE}===================================================================================================================================================${RESET}\n\n"

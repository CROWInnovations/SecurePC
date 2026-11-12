#!/bin/sh
# ==============================================================================
# SecurePC — Desktop GUI Login Alert (securepc-gui-notify.sh)
# Author:  CROW Innovations (https://crowinnovations.com)
# License: GNU General Public License v3.0 (GPL-3.0)
# GitHub:  https://github.com/CROWInnovations/SecurePC
#
# Sends desktop notifications (notify-send) upon GUI session login without
# modifying root-owned audit files in /var/log/securepc.
# ==============================================================================

UNREAD_LOG="/var/log/securepc/unread-alerts.log"
UNREAD_NON_US_LOG="/var/log/securepc/unread-non-us.log"
META_HDR="CROW Innovations (https://crowinnovations.com) | GNU GPL v3.0"

command -v notify-send >/dev/null 2>&1 || exit 0

if [ -r "${UNREAD_LOG}" ] && [ -s "${UNREAD_LOG}" ]; then
    COUNT="$(wc -l < "${UNREAD_LOG}" 2>/dev/null | tr -d '[:space:]')"
    LATEST="$(tail -n 3 "${UNREAD_LOG}" 2>/dev/null)"
    notify-send -u critical -i security-high \
        "SecurePC — ${COUNT} Blocked Threat Attempt(s)" \
        "${META_HDR}\n\nBlocked traffic to CN / RU / IR / Middle East (run 'sudo securepc ack' to clear):\n${LATEST}" 2>/dev/null || true
fi

if [ -r "${UNREAD_NON_US_LOG}" ] && [ -s "${UNREAD_NON_US_LOG}" ]; then
    TOTAL_N="$(wc -l < "${UNREAD_NON_US_LOG}" 2>/dev/null | tr -d '[:space:]')"
    CUR_INO="$(stat -c '%i' "${UNREAD_NON_US_LOG}" 2>/dev/null || echo 0)"
    CURSOR_DIR="${HOME:-/tmp}/.cache/securepc"
    CURSOR_FILE="${CURSOR_DIR}/gui-non-us.cursor"
    PREV_INO=""
    PREV_N=0
    if [ -r "${CURSOR_FILE}" ]; then
        IFS=: read -r PREV_INO PREV_N < "${CURSOR_FILE}" 2>/dev/null || true
    fi
    case "${PREV_N}" in ''|*[!0-9]*) PREV_N=0 ;; esac

    NEW_N="${TOTAL_N}"
    if [ "${CUR_INO}" = "${PREV_INO}" ] && [ "${TOTAL_N}" -ge "${PREV_N}" ]; then
        NEW_N=$((TOTAL_N - PREV_N))
    fi

    if [ "${NEW_N}" -gt 0 ]; then
        NLATEST="$(tail -n 3 "${UNREAD_NON_US_LOG}" 2>/dev/null)"
        notify-send -u normal -i dialog-warning \
            "SecurePC — ${NEW_N} New Non-US Connection(s) Flagged" \
            "${META_HDR}\n\nTraffic outside US observed (run 'securepc non-us'):\n${NLATEST}" 2>/dev/null || true
        if [ -n "${HOME:-}" ] && [ -d "${HOME}" ]; then
            mkdir -p "${CURSOR_DIR}" 2>/dev/null || true
            chmod 0700 "${CURSOR_DIR}" 2>/dev/null || true
            printf '%s:%s\n' "${CUR_INO}" "${TOTAL_N}" > "${CURSOR_FILE}" 2>/dev/null || true
        fi
    fi
fi

#!/bin/sh
# ==============================================================================
# SecurePC — Official CLI & Login Intro Banner (POSIX / Bash / Zsh Compatible)
# Author:  CROW Innovations (https://crowinnovations.com)
# License: GNU General Public License v3.0 (GPL-3.0)
# GitHub:  https://github.com/CROWInnovations/SecurePC
# ==============================================================================

print_securepc_banner() {
    if [ -n "${NO_COLOR:-}" ]; then
        SPC_BDR=""
        SPC_TTL=""
        SPC_LBL=""
        SPC_VAL=""
        SPC_LNK=""
        SPC_RST=""
    else
        SPC_BDR='\033[1;36m'
        SPC_TTL='\033[1;37m'
        SPC_LBL='\033[1;33m'
        SPC_VAL='\033[0;37m'
        SPC_LNK='\033[1;36m'
        SPC_RST='\033[0m'
    fi

    printf "${SPC_BDR}╔════════════════════════════════════════════════════════════════════════════════════════════════╗${SPC_RST}\n"
    printf "${SPC_BDR}║${SPC_RST}%96s${SPC_BDR}║${SPC_RST}\n" ""
    printf "${SPC_BDR}║${SPC_RST}%44s${SPC_TTL}SecurePC${SPC_RST}%44s${SPC_BDR}║${SPC_RST}\n" "" ""
    printf "${SPC_BDR}║${SPC_RST}%96s${SPC_BDR}║${SPC_RST}\n" ""
    printf "${SPC_BDR}║${SPC_RST}   ${SPC_LBL}Author:${SPC_RST}   ${SPC_VAL}CROW Innovations${SPC_RST}%67s${SPC_BDR}║${SPC_RST}\n" ""
    printf "${SPC_BDR}║${SPC_RST}   ${SPC_LBL}Website:${SPC_RST}  ${SPC_LNK}https://crowinnovations.com${SPC_RST}%56s${SPC_BDR}║${SPC_RST}\n" ""
    printf "${SPC_BDR}║${SPC_RST}%96s${SPC_BDR}║${SPC_RST}\n" ""
    printf "${SPC_BDR}║${SPC_RST}   ${SPC_LBL}License:${SPC_RST}  ${SPC_VAL}GNU GPL v3.0 (GPL-3.0)${SPC_RST}       ${SPC_LBL}GitHub:${SPC_RST}  ${SPC_LNK}https://github.com/CROWInnovations/SecurePC${SPC_RST}  ${SPC_BDR}║${SPC_RST}\n"
    printf "${SPC_BDR}║${SPC_RST}%96s${SPC_BDR}║${SPC_RST}\n" ""
    printf "${SPC_BDR}╚════════════════════════════════════════════════════════════════════════════════════════════════╝${SPC_RST}\n"
}

# Execute directly only when invoked as a standalone script (not sourced)
case "${0##*/}" in
    securepc-banner.sh)
        print_securepc_banner
        ;;
esac

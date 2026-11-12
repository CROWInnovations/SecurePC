#!/usr/bin/env python3
"""
SecurePC — Multi-Backend Atomic Firewall Ruleset Compiler
Author:  CROW Innovations (https://crowinnovations.com)
License: GNU General Public License v3.0 (GPL-3.0)
GitHub:  https://github.com/CROWInnovations/SecurePC

Compiles validated, prefix-collapsed IPv4 & IPv6 blocking, anti-DoH/DoT bypass,
and fail-safe NFQUEUE inspection rulesets for:
  1. nftables    - Single atomic dual-stack `table inet securepc` (Ubuntu 22.04+,
                   Linux Mint 21+, Debian 11+, Kali, Fedora, RHEL 8+, Arch)
  2. iptables    - Legacy/compat `ipset` (atomic swap) + `iptables-restore` +
                   `ip6tables-restore` (Ubuntu 18.04/20.04, CentOS 7, legacy hosts)
  3. solaris_ipf - Solaris 11.4 `pf` (`pf.conf`) & illumos/Solaris `ipf` + `ippool`
"""

import argparse
import ipaddress
import os
import pwd
import re
import sys
from typing import Iterable

# Major public DNS-over-HTTPS (DoH) / DNS-over-TLS (DoT) resolver endpoints.
# Note: Standard UDP/TCP port 53 to these IPs remains allowed (and QNAME-inspected);
# only encrypted bypass ports (TCP/UDP 443 & 853) to these resolver IPs are blocked
# when BLOCK_DOH_DOT=1 so browsers/apps fall back cleanly to inspected system DNS.
DOH_IPV4_RAW = [
    # Cloudflare (1.1.1.1 / mozilla.cloudflare-dns.com)
    "1.1.1.1/32", "1.0.0.1/32", "1.1.1.2/32", "1.0.0.2/32", "1.1.1.3/32", "1.0.0.3/32",
    "162.159.36.1/32", "162.159.46.1/32", "104.16.248.249/32", "104.16.249.249/32",
    # Google Public DNS (dns.google)
    "8.8.8.8/32", "8.8.4.4/32",
    # Quad9 (dns.quad9.net)
    "9.9.9.9/32", "9.9.9.10/32", "9.9.9.11/32",
    "149.112.112.112/32", "149.112.112.10/32", "149.112.112.11/32",
    # Cisco OpenDNS / Umbrella (doh.opendns.com)
    "208.67.222.222/32", "208.67.220.220/32", "208.67.222.123/32", "208.67.220.123/32",
    "146.112.41.2/32", "146.112.41.3/32",
    # AdGuard DNS
    "94.140.14.14/32", "94.140.15.15/32", "94.140.14.15/32", "94.140.15.16/32",
    "94.140.14.140/32", "94.140.14.141/32",
    # CleanBrowsing
    "185.228.168.9/32", "185.228.169.9/32", "185.228.168.10/32", "185.228.169.11/32",
    "185.228.168.168/32", "185.228.169.168/32",
    # NextDNS
    "45.90.28.0/24", "45.90.30.0/24",
    # ControlD
    "76.76.2.0/24", "76.76.10.0/24",
    # Mullvad DNS
    "194.242.2.2/32", "194.242.2.3/32", "194.242.2.4/32",
    # Quad101 (TWNIC)
    "101.101.101.101/32", "101.102.103.104/32",
]

DOH_IPV6_RAW = [
    # Cloudflare
    "2606:4700:4700::1111/128", "2606:4700:4700::1001/128",
    "2606:4700:4700::1112/128", "2606:4700:4700::1002/128",
    "2606:4700:4700::1113/128", "2606:4700:4700::1003/128",
    "2606:4700:4700::64/128", "2606:4700:4700::6400/128",
    # Google
    "2001:4860:4860::8888/128", "2001:4860:4860::8844/128",
    "2001:4860:4860::64/128", "2001:4860:4860::6464/128",
    # Quad9
    "2620:fe::fe/128", "2620:fe::9/128", "2620:fe::10/128", "2620:fe::11/128",
    # OpenDNS
    "2620:119:35::35/128", "2620:119:53::53/128",
    # AdGuard
    "2a10:50c0::ad1:ff/128", "2a10:50c0::ad2:ff/128",
    "2a10:50c0::1:ff/128", "2a10:50c0::2:ff/128",
    # CleanBrowsing
    "2a0d:2a00:1::/48", "2a0d:2a00:2::/48",
    # NextDNS
    "2a07:a8c0::/29",
    # ControlD
    "2606:1a40::/32",
    # Mullvad
    "2a07:e340::2/128", "2a07:e340::3/128",
]

LAN_IPV4_RAW = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "169.254.0.0/16",
    "224.0.0.0/4",
    "255.255.255.255/32",
]

LAN_IPV6_RAW = [
    "::1/128",
    "fe80::/10",
    "fc00::/7",
    "ff00::/8",
]

ME_CCTLD_LIST = [
    "ae", "bh", "cy", "eg", "il", "iq", "jo", "kw",
    "lb", "om", "ps", "qa", "sa", "sy", "tr", "ye",
]

ME_IDN_LIST = [
    "xn--mgbaam7a8h", "xn--mgberp4a5d4ar", "xn--wgbh1c", "xn--4dbrk0ce",
    "xn--mgbtx2b", "xn--mgbayh7gpa", "xn--mgb9awbf", "xn--ygbi2ammx",
    "xn--wgbl6a", "xn--ogbpf8fl", "xn--mgbcpq6gpa1a",
]


def parse_conf(conf_path: str) -> dict[str, str]:
    cfg = {
        "FIREWALL_BACKEND": "auto",
        "OUTBOUND_BLOCK_ACTION": "reject",
        "ENABLE_IPV6": "1",
        "BLOCK_DOH_DOT": "1",
        "ENFORCE_BROWSER_POLICIES": "1",
        "ENABLE_NFQUEUE_DPI": "1",
        "NFQUEUE_NUM": "5353",
        "ENABLE_OPENSSL_PROBES": "1",
        "SANDBOX_LAN_ONLY_USERS": "",
    }
    if not conf_path or not os.path.isfile(conf_path):
        return cfg
    try:
        with open(conf_path, "r", encoding="utf-8", errors="replace") as f:
            for raw in f:
                line = raw.split("#", 1)[0].strip()
                if "=" not in line:
                    continue
                k, v = line.split("=", 1)
                k = k.strip()
                v = v.strip()
                if len(v) >= 2 and ((v[0] == '"' and v[-1] == '"') or (v[0] == "'" and v[-1] == "'")):
                    v = v[1:-1]
                if k in cfg:
                    cfg[k] = v
    except Exception:
        pass
    return cfg


def collapse_cidrs(items: Iterable[str]) -> tuple[list[str], list[str]]:
    v4 = []
    v6 = []
    for raw in items:
        tok = raw.split("#", 1)[0].strip()
        if not tok:
            continue
        tok = tok.split()[0]
        try:
            net = ipaddress.ip_network(tok, strict=False)
            if net.version == 4:
                v4.append(net)
            else:
                v6.append(net)
        except ValueError:
            continue
    c4 = [str(n) for n in ipaddress.collapse_addresses(v4)] if v4 else []
    c6 = [str(n) for n in ipaddress.collapse_addresses(v6)] if v6 else []
    return c4, c6


def read_cidr_file(path: str) -> tuple[list[str], list[str]]:
    if not path or not os.path.isfile(path):
        return [], []
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return collapse_cidrs(f)


def resolve_existing_uids(user_spec: str) -> list[tuple[str, int]]:
    """Resolve optional sandboxed usernames to numeric UIDs; skip missing users cleanly."""
    resolved = []
    seen = set()
    for token in re.split(r"[\s,]+", (user_spec or "").strip()):
        if not token or not re.match(r"^[a-zA-Z0-9_.-]+$", token):
            continue
        try:
            pw = pwd.getpwnam(token)
            if pw.pw_uid == 0:
                continue  # Never sandbox root accidentally
            if pw.pw_uid not in seen:
                seen.add(pw.pw_uid)
                resolved.append((token, pw.pw_uid))
        except KeyError:
            # Optional local username not present on this host -> skip safely
            continue
    return resolved


def load_all_sets(lists_dir: str, conf_dir: str) -> dict[str, list[str]]:
    lan_v4, _ = collapse_cidrs(LAN_IPV4_RAW)
    _, lan_v6 = collapse_cidrs(LAN_IPV6_RAW)
    doh_v4, _ = collapse_cidrs(DOH_IPV4_RAW)
    _, doh_v6 = collapse_cidrs(DOH_IPV6_RAW)

    custom_allow_v4, custom_allow_v6 = read_cidr_file(os.path.join(conf_dir, "allowlist-ips.txt"))
    custom_blk_v4, custom_blk_v6 = read_cidr_file(os.path.join(conf_dir, "blocklist-ips.txt"))

    beijing_v4, _ = read_cidr_file(os.path.join(lists_dir, "beijing-cidrs.txt"))
    aliyuncs_v4, _ = read_cidr_file(os.path.join(lists_dir, "aliyuncs-cidrs.txt"))
    cn_v4, _ = read_cidr_file(os.path.join(lists_dir, "cn-cidrs.txt"))
    ru_v4, _ = read_cidr_file(os.path.join(lists_dir, "ru-cidrs.txt"))
    ir_v4, _ = read_cidr_file(os.path.join(lists_dir, "ir-cidrs.txt"))
    me_v4, _ = read_cidr_file(os.path.join(lists_dir, "me-cidrs.txt"))

    _, cn_v6 = read_cidr_file(os.path.join(lists_dir, "cn-ipv6-cidrs.txt"))
    _, ru_v6 = read_cidr_file(os.path.join(lists_dir, "ru-ipv6-cidrs.txt"))
    _, ir_v6 = read_cidr_file(os.path.join(lists_dir, "ir-ipv6-cidrs.txt"))
    _, me_v6 = read_cidr_file(os.path.join(lists_dir, "me-ipv6-cidrs.txt"))

    return {
        "lan_v4": lan_v4,
        "lan_v6": lan_v6,
        "doh_v4": doh_v4,
        "doh_v6": doh_v6,
        "custom_allow_v4": custom_allow_v4,
        "custom_allow_v6": custom_allow_v6,
        "custom_blk_v4": custom_blk_v4,
        "custom_blk_v6": custom_blk_v6,
        "beijing_v4": beijing_v4,
        "aliyuncs_v4": aliyuncs_v4,
        "cn_v4": cn_v4,
        "ru_v4": ru_v4,
        "ir_v4": ir_v4,
        "me_v4": me_v4,
        "cn_v6": cn_v6,
        "ru_v6": ru_v6,
        "ir_v6": ir_v6,
        "me_v6": me_v6,
    }


def _nft_set_block(name: str, addr_type: str, elements: list[str]) -> list[str]:
    lines = [
        f"    set {name} {{",
        f"        type {addr_type}",
        "        flags interval",
        "        auto-merge",
    ]
    if elements:
        lines.append("        elements = {")
        for i in range(0, len(elements), 8):
            chunk = ", ".join(elements[i : i + 8])
            comma = "," if (i + 8) < len(elements) else ""
            lines.append(f"            {chunk}{comma}")
        lines.append("        }")
    lines.append("    }")
    return lines


def generate_nftables(cfg: dict[str, str], sets: dict[str, list[str]], sandbox_uids: list[tuple[str, int]]) -> str:
    enable_v6 = cfg.get("ENABLE_IPV6", "1") == "1"
    block_doh = cfg.get("BLOCK_DOH_DOT", "1") == "1"
    use_nfq = cfg.get("ENABLE_NFQUEUE_DPI", "1") == "1"
    qnum = int(cfg.get("NFQUEUE_NUM", "5353") or "5353")
    use_reject = cfg.get("OUTBOUND_BLOCK_ACTION", "reject").lower() == "reject"

    out = [
        "# Generated by SecurePC build-firewall-ruleset.py (atomic dual-stack nftables)",
        "table inet securepc",
        "delete table inet securepc",
        "",
        "table inet securepc {",
    ]

    v4_set_defs = [
        ("lan_v4", sets["lan_v4"]),
        ("doh_v4", sets["doh_v4"]),
        ("custom_allow_v4", sets["custom_allow_v4"]),
        ("custom_blk_v4", sets["custom_blk_v4"]),
        ("beijing_v4", sets["beijing_v4"]),
        ("aliyuncs_v4", sets["aliyuncs_v4"]),
        ("cn_v4", sets["cn_v4"]),
        ("ru_v4", sets["ru_v4"]),
        ("ir_v4", sets["ir_v4"]),
        ("me_v4", sets["me_v4"]),
    ]
    for sname, elems in v4_set_defs:
        out.extend(_nft_set_block(sname, "ipv4_addr", elems))

    out.extend([
        "    set dyn_blk_v4 {",
        "        type ipv4_addr",
        "        flags timeout",
        "        timeout 1h",
        "    }",
    ])

    if enable_v6:
        v6_set_defs = [
            ("lan_v6", sets["lan_v6"]),
            ("doh_v6", sets["doh_v6"]),
            ("custom_allow_v6", sets["custom_allow_v6"]),
            ("custom_blk_v6", sets["custom_blk_v6"]),
            ("cn_v6", sets["cn_v6"]),
            ("ru_v6", sets["ru_v6"]),
            ("ir_v6", sets["ir_v6"]),
            ("me_v6", sets["me_v6"]),
        ]
        for sname, elems in v6_set_defs:
            out.extend(_nft_set_block(sname, "ipv6_addr", elems))
        out.extend([
            "    set dyn_blk_v6 {",
            "        type ipv6_addr",
            "        flags timeout",
            "        timeout 1h",
            "    }",
        ])

    # Action chains
    blk_chains = [
        ("blk_beijing", "BEIJING"),
        ("blk_aliyuncs", "ALIYUNCS"),
        ("blk_cn", "CN-IP"),
        ("blk_ru", "RU-IP"),
        ("blk_ir", "IR-IP"),
        ("blk_me", "ME-IP"),
        ("blk_dyn", "DYN-DOM"),
        ("blk_custom", "CUSTOM-BLK"),
        ("blk_doh", "DOH-BYPASS"),
        ("blk_sandbox", "QWEN-LLM"),
    ]
    for cname, tag in blk_chains:
        out.append(f"    chain {cname} {{")
        out.append(f'        limit rate 120/minute burst 40 packets log prefix "[SECUREPC-BLK:{tag}] " level warn flags skuid')
        if use_reject:
            out.append("        meta l4proto tcp counter reject with tcp reset")
            out.append("        counter reject with icmpx type port-unreachable")
        else:
            out.append("        counter drop")
        out.append("    }")

    out.extend([
        "    chain blk_inbound {",
        '        limit rate 120/minute burst 40 packets log prefix "[SECUREPC-BLK:INBOUND] " level warn',
        "        counter drop",
        "    }",
    ])

    # Shared Egress Enforcement Chain (invoked by both host output and container forward)
    out.append("    chain egress_enforce {")
    if sets["custom_allow_v4"]:
        out.append("        ip daddr @custom_allow_v4 accept")
    if enable_v6 and sets["custom_allow_v6"]:
        out.append("        ip6 daddr @custom_allow_v6 accept")

    if block_doh:
        out.append("        meta l4proto { tcp, udp } th dport 853 jump blk_doh")
        out.append("        ip daddr @doh_v4 meta l4proto { tcp, udp } th dport 443 jump blk_doh")
        if enable_v6:
            out.append("        ip6 daddr @doh_v6 meta l4proto { tcp, udp } th dport 443 jump blk_doh")

    # Dynamic, custom, and regional CIDR blocks (precede NFQUEUE & established fast-path)
    out.append("        ip daddr @dyn_blk_v4 jump blk_dyn")
    if enable_v6:
        out.append("        ip6 daddr @dyn_blk_v6 jump blk_dyn")
    if sets["custom_blk_v4"]:
        out.append("        ip daddr @custom_blk_v4 jump blk_custom")
    if enable_v6 and sets["custom_blk_v6"]:
        out.append("        ip6 daddr @custom_blk_v6 jump blk_custom")

    out.append("        ip daddr @beijing_v4 jump blk_beijing")
    out.append("        ip daddr @aliyuncs_v4 jump blk_aliyuncs")
    out.append("        ip daddr @cn_v4 jump blk_cn")
    out.append("        ip daddr @ru_v4 jump blk_ru")
    out.append("        ip daddr @ir_v4 jump blk_ir")
    out.append("        ip daddr @me_v4 jump blk_me")
    if enable_v6:
        out.append("        ip6 daddr @cn_v6 jump blk_cn")
        out.append("        ip6 daddr @ru_v6 jump blk_ru")
        out.append("        ip6 daddr @ir_v6 jump blk_ir")
        out.append("        ip6 daddr @me_v6 jump blk_me")

    # Inspect DNS queries BEFORE LAN allowlist so local router DNS (192.168.x.1:53) is also protected
    if use_nfq:
        out.append(f"        meta l4proto {{ tcp, udp }} th dport {{ 53, 5353 }} queue num {qnum} bypass")

    # Exempt private RFC1918 / link-local / multicast LAN traffic
    out.append("        ip daddr @lan_v4 accept")
    if enable_v6:
        out.append("        ip6 daddr @lan_v6 accept")

    # Log every NEW outbound public internet connection
    out.append('        ct state new limit rate 600/minute burst 200 packets log prefix "[SECUREPC-OUT:NET] " level warn flags skuid')

    # Inspect initial HTTP Host & TLS ClientHello SNI packets via fail-safe NFQUEUE
    if use_nfq:
        out.append(
            f"        tcp dport {{ 80, 443, 8080, 8443 }} tcp flags & (syn | fin | rst) == 0 "
            f"ct original packets <= 6 queue num {qnum} bypass"
        )

    out.append("        ct state established,related accept")
    out.append("    }")

    # INPUT hook
    out.extend([
        "    chain input {",
        "        type filter hook input priority -10; policy accept;",
        '        iifname "lo" accept',
        "        ip saddr 127.0.0.0/8 accept",
    ])
    if enable_v6:
        out.append("        ip6 saddr ::1 accept")
    out.append("        ct state invalid drop")
    if sets["custom_allow_v4"]:
        out.append("        ip saddr @custom_allow_v4 accept")
    if enable_v6 and sets["custom_allow_v6"]:
        out.append("        ip6 saddr @custom_allow_v6 accept")
    out.extend([
        "        ip saddr @lan_v4 accept",
        "        ip saddr @dyn_blk_v4 jump blk_inbound",
    ])
    if enable_v6:
        out.extend([
            "        ip6 saddr @lan_v6 accept",
            "        ip6 saddr @dyn_blk_v6 jump blk_inbound",
        ])
    if sets["custom_blk_v4"]:
        out.append("        ip saddr @custom_blk_v4 jump blk_inbound")
    if enable_v6 and sets["custom_blk_v6"]:
        out.append("        ip6 saddr @custom_blk_v6 jump blk_inbound")

    out.extend([
        "        ip saddr @beijing_v4 jump blk_inbound",
        "        ip saddr @aliyuncs_v4 jump blk_inbound",
        "        ip saddr @cn_v4 jump blk_inbound",
        "        ip saddr @ru_v4 jump blk_inbound",
        "        ip saddr @ir_v4 jump blk_inbound",
        "        ip saddr @me_v4 jump blk_inbound",
    ])
    if enable_v6:
        out.extend([
            "        ip6 saddr @cn_v6 jump blk_inbound",
            "        ip6 saddr @ru_v6 jump blk_inbound",
            "        ip6 saddr @ir_v6 jump blk_inbound",
            "        ip6 saddr @me_v6 jump blk_inbound",
        ])
    out.extend([
        "        ct state established,related accept",
        "    }",
    ])

    # OUTPUT hook
    out.extend([
        "    chain output {",
        "        type filter hook output priority -10; policy accept;",
        '        oifname "lo" accept',
        "        ip daddr 127.0.0.0/8 accept",
    ])
    if enable_v6:
        out.append("        ip6 daddr ::1 accept")
    out.append("        ct state invalid drop")

    # Optional per-user LAN sandboxing (only emitted for UIDs verified to exist on this host)
    for uname, uid in sandbox_uids:
        out.append(f"        # Sandboxed LAN-only local user: {uname} (uid={uid})")
        out.append(f"        meta skuid {uid} ip daddr @lan_v4 accept")
        if enable_v6:
            out.append(f"        meta skuid {uid} ip6 daddr @lan_v6 accept")
        out.append(f"        meta skuid {uid} jump blk_sandbox")

    out.extend([
        "        jump egress_enforce",
        "    }",
    ])

    # FORWARD hook (enforces policy across all Docker / LXC / VM bridged & NATed traffic)
    out.extend([
        "    chain forward {",
        "        type filter hook forward priority -10; policy accept;",
        "        ct state invalid drop",
        "        jump egress_enforce",
        "    }",
        "}",
    ])
    return "\n".join(out) + "\n"


def generate_ipset_restore(cfg: dict[str, str], sets: dict[str, list[str]]) -> str:
    enable_v6 = cfg.get("ENABLE_IPV6", "1") == "1"
    lines = []

    def add_swapped_set(name: str, family: str, hashsize: int, maxelem: int, elems: list[str]):
        tmp = f"{name}_t"
        lines.append(f"create {name} hash:net family {family} hashsize {hashsize} maxelem {maxelem} -exist")
        lines.append(f"create {tmp} hash:net family {family} hashsize {hashsize} maxelem {maxelem} -exist")
        lines.append(f"flush {tmp}")
        for cidr in elems:
            lines.append(f"add {tmp} {cidr} -exist")
        lines.append(f"swap {tmp} {name}")
        lines.append(f"destroy {tmp}")

    add_swapped_set("securepc_lan", "inet", 1024, 65536, sets["lan_v4"])
    add_swapped_set("securepc_doh", "inet", 1024, 65536, sets["doh_v4"])
    add_swapped_set("securepc_custom_allow", "inet", 1024, 65536, sets["custom_allow_v4"])
    add_swapped_set("securepc_custom_blk", "inet", 1024, 65536, sets["custom_blk_v4"])
    add_swapped_set("securepc_beijing", "inet", 2048, 65536, sets["beijing_v4"])
    add_swapped_set("securepc_aliyuncs", "inet", 2048, 65536, sets["aliyuncs_v4"])
    add_swapped_set("securepc_cn_all", "inet", 8192, 131072, sets["cn_v4"])
    add_swapped_set("securepc_ru_all", "inet", 8192, 131072, sets["ru_v4"])
    add_swapped_set("securepc_ir_all", "inet", 4096, 65536, sets["ir_v4"])
    add_swapped_set("securepc_me_all", "inet", 8192, 131072, sets["me_v4"])
    lines.append("create securepc_dyn_blk hash:ip family inet hashsize 1024 maxelem 65536 timeout 3600 -exist")

    if enable_v6:
        add_swapped_set("securepc6_lan", "inet6", 1024, 65536, sets["lan_v6"])
        add_swapped_set("securepc6_doh", "inet6", 1024, 65536, sets["doh_v6"])
        add_swapped_set("securepc6_custom_allow", "inet6", 1024, 65536, sets["custom_allow_v6"])
        add_swapped_set("securepc6_custom_blk", "inet6", 1024, 65536, sets["custom_blk_v6"])
        add_swapped_set("securepc6_cn_all", "inet6", 4096, 131072, sets["cn_v6"])
        add_swapped_set("securepc6_ru_all", "inet6", 4096, 131072, sets["ru_v6"])
        add_swapped_set("securepc6_ir_all", "inet6", 4096, 131072, sets["ir_v6"])
        add_swapped_set("securepc6_me_all", "inet6", 4096, 131072, sets["me_v6"])
        lines.append("create securepc6_dyn_blk hash:ip family inet6 hashsize 1024 maxelem 65536 timeout 3600 -exist")

    return "\n".join(lines) + "\n"


def _dns_xt_string_rules(chain: str, prefix: str, proto_v6: bool = False) -> list[str]:
    """Generate static kernel xt_string DNS QNAME backstop rules (port 53/5353)."""
    from_udp = 48 if proto_v6 else 36
    from_tcp = 52 if proto_v6 else 40
    blk_cn = f"{prefix}_BLK_CN_DOM"
    blk_ru = f"{prefix}_BLK_RU_DOM"
    blk_ir = f"{prefix}_BLK_IR_DOM"
    blk_me = f"{prefix}_BLK_ME_DOM"
    blk_bj = f"{prefix}_BLK_BEIJING"
    blk_ali = f"{prefix}_BLK_ALIYUNCS"

    rules = [
        f'-A {chain} -p udp -m multiport --dports 53,5353 -m string --from {from_udp} --string "beijing" --algo bm --icase -j {blk_bj}',
        f'-A {chain} -p tcp --dport 53 -m string --from {from_tcp} --string "beijing" --algo bm --icase -j {blk_bj}',
        f'-A {chain} -p udp -m multiport --dports 53,5353 -m string --from {from_udp} --string "aliyuncs" --algo bm --icase -j {blk_ali}',
        f'-A {chain} -p tcp --dport 53 -m string --from {from_tcp} --string "aliyuncs" --algo bm --icase -j {blk_ali}',
        f'-A {chain} -p udp -m multiport --dports 53,5353 -m string --from {from_udp} --hex-string "|06|aliyun|03|com|00|" --algo bm --icase -j {blk_ali}',
        f'-A {chain} -p tcp --dport 53 -m string --from {from_tcp} --hex-string "|06|aliyun|03|com|00|" --algo bm --icase -j {blk_ali}',
        # China (.cn + IDNs)
        f'-A {chain} -p udp -m multiport --dports 53,5353 -m string --from {from_udp} --hex-string "|02 63 6e 00|" --algo bm --icase -j {blk_cn}',
        f'-A {chain} -p tcp --dport 53 -m string --from {from_tcp} --hex-string "|02 63 6e 00|" --algo bm --icase -j {blk_cn}',
        f'-A {chain} -p udp -m multiport --dports 53,5353 -m string --from {from_udp} --string "xn--fiqs8s" --algo bm --icase -j {blk_cn}',
        f'-A {chain} -p udp -m multiport --dports 53,5353 -m string --from {from_udp} --string "xn--fiqz9s" --algo bm --icase -j {blk_cn}',
        # Russia (.ru, .su, .рф)
        f'-A {chain} -p udp -m multiport --dports 53,5353 -m string --from {from_udp} --hex-string "|02 72 75 00|" --algo bm --icase -j {blk_ru}',
        f'-A {chain} -p tcp --dport 53 -m string --from {from_tcp} --hex-string "|02 72 75 00|" --algo bm --icase -j {blk_ru}',
        f'-A {chain} -p udp -m multiport --dports 53,5353 -m string --from {from_udp} --hex-string "|02 73 75 00|" --algo bm --icase -j {blk_ru}',
        f'-A {chain} -p tcp --dport 53 -m string --from {from_tcp} --hex-string "|02 73 75 00|" --algo bm --icase -j {blk_ru}',
        f'-A {chain} -p udp -m multiport --dports 53,5353 -m string --from {from_udp} --string "xn--p1ai" --algo bm --icase -j {blk_ru}',
        f'-A {chain} -p tcp --dport 53 -m string --from {from_tcp} --string "xn--p1ai" --algo bm --icase -j {blk_ru}',
        # Iran (.ir + IDN)
        f'-A {chain} -p udp -m multiport --dports 53,5353 -m string --from {from_udp} --hex-string "|02 69 72 00|" --algo bm --icase -j {blk_ir}',
        f'-A {chain} -p tcp --dport 53 -m string --from {from_tcp} --hex-string "|02 69 72 00|" --algo bm --icase -j {blk_ir}',
        f'-A {chain} -p udp -m multiport --dports 53,5353 -m string --from {from_udp} --string "xn--mgba3a4f16a" --algo bm --icase -j {blk_ir}',
        f'-A {chain} -p tcp --dport 53 -m string --from {from_tcp} --string "xn--mgba3a4f16a" --algo bm --icase -j {blk_ir}',
    ]
    for tld in ME_CCTLD_LIST:
        h1 = f"{ord(tld[0]):02x}"
        h2 = f"{ord(tld[1]):02x}"
        rules.append(
            f'-A {chain} -p udp -m multiport --dports 53,5353 -m string --from {from_udp} --hex-string "|02 {h1} {h2} 00|" --algo bm --icase -j {blk_me}'
        )
        rules.append(
            f'-A {chain} -p tcp --dport 53 -m string --from {from_tcp} --hex-string "|02 {h1} {h2} 00|" --algo bm --icase -j {blk_me}'
        )
    for me_idn in ME_IDN_LIST:
        rules.append(
            f'-A {chain} -p udp -m multiport --dports 53,5353 -m string --from {from_udp} --string "{me_idn}" --algo bm --icase -j {blk_me}'
        )
        rules.append(
            f'-A {chain} -p tcp --dport 53 -m string --from {from_tcp} --string "{me_idn}" --algo bm --icase -j {blk_me}'
        )
    return rules


def generate_iptables_family(
    cfg: dict[str, str],
    sandbox_uids: list[tuple[str, int]],
    ipv6: bool = False,
    include_nfqueue: bool = True,
) -> tuple[list[str], str]:
    prefix = "SECUREPC6" if ipv6 else "SECUREPC"
    set_pfx = "securepc6" if ipv6 else "securepc"
    block_doh = cfg.get("BLOCK_DOH_DOT", "1") == "1"
    use_nfq = include_nfqueue and (cfg.get("ENABLE_NFQUEUE_DPI", "1") == "1")
    qnum = int(cfg.get("NFQUEUE_NUM", "5353") or "5353")
    use_reject = cfg.get("OUTBOUND_BLOCK_ACTION", "reject").lower() == "reject"
    icmp_unreach = "icmp6-port-unreachable" if ipv6 else "icmp-port-unreachable"

    blk_pairs = [
        (f"{prefix}_BLK_BEIJING", "BEIJING"),
        (f"{prefix}_BLK_ALIYUNCS", "ALIYUNCS"),
        (f"{prefix}_BLK_CN_DOM", "CN-DOM"),
        (f"{prefix}_BLK_CN_IP", "CN-IP"),
        (f"{prefix}_BLK_RU_DOM", "RU-DOM"),
        (f"{prefix}_BLK_RU_IP", "RU-IP"),
        (f"{prefix}_BLK_IR_DOM", "IR-DOM"),
        (f"{prefix}_BLK_IR_IP", "IR-IP"),
        (f"{prefix}_BLK_ME_DOM", "ME-DOM"),
        (f"{prefix}_BLK_ME_IP", "ME-IP"),
        (f"{prefix}_BLK_DOH", "DOH-BYPASS"),
        (f"{prefix}_BLK_CUSTOM", "CUSTOM-BLK"),
        (f"{prefix}_BLK_QWEN_LLM", "QWEN-LLM"),
    ]
    chains = [
        f"{prefix}_OUT",
        f"{prefix}_IN",
        f"{prefix}_FWD",
        f"{prefix}_EGRESS",
        f"{prefix}_DNS_DPI",
        f"{prefix}_LOG_OUT",
        f"{prefix}_BLK_INBOUND",
    ] + [c for c, _ in blk_pairs]

    lines = ["*filter"]
    for ch in chains:
        lines.append(f"-F {ch}")

    for b_ch, b_tag in blk_pairs:
        lines.append(
            f'-A {b_ch} -m limit --limit 120/min --limit-burst 40 -j LOG --log-prefix "[SECUREPC-BLK:{b_tag}] " --log-level 4 --log-uid'
        )
        if use_reject:
            lines.append(f"-A {b_ch} -p tcp -j REJECT --reject-with tcp-reset")
            lines.append(f"-A {b_ch} -j REJECT --reject-with {icmp_unreach}")
        else:
            lines.append(f"-A {b_ch} -j DROP")

    lines.append(
        f'-A {prefix}_BLK_INBOUND -m limit --limit 120/min --limit-burst 40 -j LOG --log-prefix "[SECUREPC-BLK:INBOUND] " --log-level 4'
    )
    lines.append(f"-A {prefix}_BLK_INBOUND -j DROP")

    # Log new outbound connections
    lines.append(
        f'-A {prefix}_LOG_OUT -m conntrack --ctstate NEW -m limit --limit 600/min --limit-burst 200 -j LOG --log-prefix "[SECUREPC-OUT:NET] " --log-level 4 --log-uid'
    )
    lines.append(f"-A {prefix}_LOG_OUT -j RETURN")

    # DNS QNAME DPI chain (static kernel xt_string + fail-safe NFQUEUE)
    lines.extend(_dns_xt_string_rules(f"{prefix}_DNS_DPI", prefix, proto_v6=ipv6))
    if use_nfq:
        lines.append(f"-A {prefix}_DNS_DPI -j NFQUEUE --queue-num {qnum} --queue-bypass")
    lines.append(f"-A {prefix}_DNS_DPI -j RETURN")

    # Shared Egress Chain (host OUTPUT + Docker/container FORWARD)
    eg = f"{prefix}_EGRESS"
    lines.append(f"-A {eg} -m set --match-set {set_pfx}_custom_allow dst -j RETURN")
    if block_doh:
        lines.append(f"-A {eg} -p tcp --dport 853 -j {prefix}_BLK_DOH")
        lines.append(f"-A {eg} -p udp --dport 853 -j {prefix}_BLK_DOH")
        lines.append(f"-A {eg} -p tcp --dport 443 -m set --match-set {set_pfx}_doh dst -j {prefix}_BLK_DOH")
        lines.append(f"-A {eg} -p udp --dport 443 -m set --match-set {set_pfx}_doh dst -j {prefix}_BLK_DOH")

    lines.append(f"-A {eg} -m set --match-set {set_pfx}_dyn_blk dst -j {prefix}_BLK_ME_DOM")
    lines.append(f"-A {eg} -m set --match-set {set_pfx}_custom_blk dst -j {prefix}_BLK_CUSTOM")
    if not ipv6:
        lines.append(f"-A {eg} -m set --match-set securepc_beijing dst -j {prefix}_BLK_BEIJING")
        lines.append(f"-A {eg} -m set --match-set securepc_aliyuncs dst -j {prefix}_BLK_ALIYUNCS")
    lines.append(f"-A {eg} -m set --match-set {set_pfx}_cn_all dst -j {prefix}_BLK_CN_IP")
    lines.append(f"-A {eg} -m set --match-set {set_pfx}_ru_all dst -j {prefix}_BLK_RU_IP")
    lines.append(f"-A {eg} -m set --match-set {set_pfx}_ir_all dst -j {prefix}_BLK_IR_IP")
    lines.append(f"-A {eg} -m set --match-set {set_pfx}_me_all dst -j {prefix}_BLK_ME_IP")

    # Inspect DNS queries before LAN return
    lines.append(f"-A {eg} -p udp -m multiport --dports 53,5353 -j {prefix}_DNS_DPI")
    lines.append(f"-A {eg} -p tcp --dport 53 -j {prefix}_DNS_DPI")

    # Exempt LAN
    lines.append(f"-A {eg} -m set --match-set {set_pfx}_lan dst -j RETURN")

    # Log NEW public internet connections
    lines.append(f"-A {eg} -m conntrack --ctstate NEW -j {prefix}_LOG_OUT")

    # Inspect initial HTTP / TLS ClientHello SNI packets via fail-safe NFQUEUE
    if use_nfq:
        lines.append(
            f"-A {eg} -p tcp -m multiport --dports 80,443,8080,8443 "
            f"--tcp-flags SYN,FIN,RST NONE -m connbytes --connbytes 0:6 "
            f"--connbytes-dir original --connbytes-mode packets "
            f"-j NFQUEUE --queue-num {qnum} --queue-bypass"
        )

    lines.append(f"-A {eg} -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN")
    lines.append(f"-A {eg} -j RETURN")

    # OUTPUT chain
    lo_dst = "::1/128" if ipv6 else "127.0.0.0/8"
    lines.append(f"-A {prefix}_OUT -o lo -j RETURN")
    lines.append(f"-A {prefix}_OUT -d {lo_dst} -j RETURN")
    lines.append(f"-A {prefix}_OUT -m conntrack --ctstate INVALID -j DROP")
    for uname, uid in sandbox_uids:
        lines.append(f"-A {prefix}_OUT -m owner --uid-owner {uid} -m set --match-set {set_pfx}_lan dst -j RETURN")
        lines.append(f"-A {prefix}_OUT -m owner --uid-owner {uid} -j {prefix}_BLK_QWEN_LLM")
    lines.append(f"-A {prefix}_OUT -j {eg}")
    lines.append(f"-A {prefix}_OUT -j RETURN")

    # FORWARD chain
    lines.append(f"-A {prefix}_FWD -m conntrack --ctstate INVALID -j DROP")
    lines.append(f"-A {prefix}_FWD -j {eg}")
    lines.append(f"-A {prefix}_FWD -j RETURN")

    # INPUT chain
    lines.append(f"-A {prefix}_IN -i lo -j RETURN")
    lines.append(f"-A {prefix}_IN -s {lo_dst} -j RETURN")
    lines.append(f"-A {prefix}_IN -m conntrack --ctstate INVALID -j DROP")
    lines.append(f"-A {prefix}_IN -m set --match-set {set_pfx}_custom_allow src -j RETURN")
    lines.append(f"-A {prefix}_IN -m set --match-set {set_pfx}_lan src -j RETURN")
    lines.append(f"-A {prefix}_IN -m set --match-set {set_pfx}_dyn_blk src -j {prefix}_BLK_INBOUND")
    lines.append(f"-A {prefix}_IN -m set --match-set {set_pfx}_custom_blk src -j {prefix}_BLK_INBOUND")
    if not ipv6:
        lines.append(f"-A {prefix}_IN -m set --match-set securepc_beijing src -j {prefix}_BLK_INBOUND")
        lines.append(f"-A {prefix}_IN -m set --match-set securepc_aliyuncs src -j {prefix}_BLK_INBOUND")
    lines.append(f"-A {prefix}_IN -m set --match-set {set_pfx}_cn_all src -j {prefix}_BLK_INBOUND")
    lines.append(f"-A {prefix}_IN -m set --match-set {set_pfx}_ru_all src -j {prefix}_BLK_INBOUND")
    lines.append(f"-A {prefix}_IN -m set --match-set {set_pfx}_ir_all src -j {prefix}_BLK_INBOUND")
    lines.append(f"-A {prefix}_IN -m set --match-set {set_pfx}_me_all src -j {prefix}_BLK_INBOUND")
    lines.append(f"-A {prefix}_IN -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN")
    lines.append(f"-A {prefix}_IN -j RETURN")

    lines.append("COMMIT")
    return chains, "\n".join(lines) + "\n"


def generate_solaris_pf(cfg: dict[str, str], sets: dict[str, list[str]]) -> str:
    """Generate Solaris 11.4 Packet Filter (pf.conf) anchor ruleset."""
    block_doh = cfg.get("BLOCK_DOH_DOT", "1") == "1"
    use_reject = cfg.get("OUTBOUND_BLOCK_ACTION", "reject").lower() == "reject"
    ret_kw = "return" if use_reject else "drop"

    blocked_all = sorted(
        set(
            sets["beijing_v4"]
            + sets["aliyuncs_v4"]
            + sets["cn_v4"]
            + sets["ru_v4"]
            + sets["ir_v4"]
            + sets["me_v4"]
            + sets["custom_blk_v4"]
            + sets["cn_v6"]
            + sets["ru_v6"]
            + sets["ir_v6"]
            + sets["me_v6"]
            + sets["custom_blk_v6"]
        )
    )
    doh_all = sets["doh_v4"] + sets["doh_v6"]
    allow_all = sets["lan_v4"] + sets["lan_v6"] + sets["custom_allow_v4"] + sets["custom_allow_v6"]

    lines = [
        "# Generated by SecurePC for Solaris 11.4 Packet Filter (pf)",
        f"table <securepc_allow> persist {{ {', '.join(allow_all)} }}",
        f"table <securepc_doh> persist {{ {', '.join(doh_all)} }}",
        "table <securepc_dyn_blk> persist",
        f"table <securepc_blocked> persist {{ {', '.join(blocked_all)} }}",
        "",
        "set skip on lo0",
        "pass quick from <securepc_allow> to any no state",
        "pass out quick from any to <securepc_allow> keep state",
    ]
    if block_doh:
        lines.append(f"block {ret_kw} out log quick proto {{ tcp, udp }} from any to any port 853")
        lines.append(f"block {ret_kw} out log quick proto {{ tcp, udp }} from any to <securepc_doh> port 443")
    lines.extend([
        f"block {ret_kw} out log quick from any to <securepc_dyn_blk>",
        f"block {ret_kw} out log quick from any to <securepc_blocked>",
        "block drop in log quick from <securepc_dyn_blk> to any",
        "block drop in log quick from <securepc_blocked> to any",
    ])
    return "\n".join(lines) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description="SecurePC Multi-Backend Firewall Ruleset Compiler")
    ap.add_argument("--backend", required=True, choices=["nftables", "iptables", "solaris_ipf"])
    ap.add_argument("--lists-dir", required=True)
    ap.add_argument("--conf-dir", required=True)
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--no-nfqueue", action="store_true", help="Omit NFQUEUE rules (fallback for kernels without xt_NFQUEUE)")
    args = ap.parse_args()

    os.makedirs(args.out_dir, mode=0o750, exist_ok=True)
    cfg = parse_conf(os.path.join(args.conf_dir, "securepc.conf"))
    sets = load_all_sets(args.lists_dir, args.conf_dir)
    sandbox_uids = resolve_existing_uids(cfg.get("SANDBOX_LAN_ONLY_USERS", ""))

    if args.backend == "nftables":
        nft_text = generate_nftables(cfg, sets, sandbox_uids)
        out_path = os.path.join(args.out_dir, "securepc.nft")
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(nft_text)
        os.chmod(out_path, 0o600)
        return 0

    if args.backend == "iptables":
        ipset_text = generate_ipset_restore(cfg, sets)
        chains4, ipt4_text = generate_iptables_family(
            cfg, sandbox_uids, ipv6=False, include_nfqueue=(not args.no_nfqueue)
        )
        chains6, ipt6_text = generate_iptables_family(
            cfg, sandbox_uids, ipv6=True, include_nfqueue=(not args.no_nfqueue)
        )

        with open(os.path.join(args.out_dir, "securepc-ipset.restore"), "w", encoding="utf-8") as f:
            f.write(ipset_text)
        with open(os.path.join(args.out_dir, "securepc-iptables.restore"), "w", encoding="utf-8") as f:
            f.write(ipt4_text)
        with open(os.path.join(args.out_dir, "securepc-ip6tables.restore"), "w", encoding="utf-8") as f:
            f.write(ipt6_text)
        with open(os.path.join(args.out_dir, "securepc-chains.v4"), "w", encoding="utf-8") as f:
            f.write("\n".join(chains4) + "\n")
        with open(os.path.join(args.out_dir, "securepc-chains.v6"), "w", encoding="utf-8") as f:
            f.write("\n".join(chains6) + "\n")
        for fn in (
            "securepc-ipset.restore",
            "securepc-iptables.restore",
            "securepc-ip6tables.restore",
            "securepc-chains.v4",
            "securepc-chains.v6",
        ):
            os.chmod(os.path.join(args.out_dir, fn), 0o600)
        return 0

    if args.backend == "solaris_ipf":
        pf_text = generate_solaris_pf(cfg, sets)
        out_path = os.path.join(args.out_dir, "securepc-pf.conf")
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(pf_text)
        os.chmod(out_path, 0o600)
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())

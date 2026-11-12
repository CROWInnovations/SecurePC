#!/usr/bin/env python3
"""
SecurePC — Production Network Attribution, Synchronous NFQUEUE DPI,
Worldwide GeoIP & OpenSSL X.509 Certificate Enforcement Daemon

Author:  CROW Innovations (https://crowinnovations.com)
License: GNU General Public License v3.0 (GPL-3.0)
GitHub:  https://github.com/CROWInnovations/SecurePC
"""

import ctypes
import datetime
import grp
import ipaddress
import json
import os
import pwd
import queue
import re
import signal
import socket
import struct
import subprocess
import sys
import threading
import time
from collections import OrderedDict, deque

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

from securepc_geo_cert import (
    GeoIPDatabase,
    OpenSSLCertInspector,
    clean_hostname_token,
    evaluate_traffic_destination,
    is_generic_ptr_or_placeholder,
    match_blocked_domain_policy,
    print_securepc_intro_banner,
)

BASE_DIR = os.path.dirname(SCRIPT_DIR)
CONF_DIR = "/etc/securepc" if os.path.isdir("/etc/securepc") else os.path.join(BASE_DIR, "etc")
VAR_LIB_DIR = "/var/lib/securepc"
LISTS_DIR = (
    os.path.join(VAR_LIB_DIR, "lists")
    if os.path.isdir(os.path.join(VAR_LIB_DIR, "lists"))
    else os.path.join(BASE_DIR, "lists")
)
ACTIVE_BACKEND_FILE = os.path.join(VAR_LIB_DIR, "active-backend")
LOG_DIR_VAR = "/var/log/securepc"
FTRACE_INSTANCE_DIR = "/sys/kernel/tracing/instances/securepc"


class BoundedDict(OrderedDict):
    """Thread-safe bounded LRU dictionary to prevent unbounded memory growth."""

    def __init__(self, maxsize: int = 4096):
        self.maxsize = maxsize
        self._lock = threading.RLock()
        super().__init__()

    def __setitem__(self, key, value):
        with self._lock:
            if super().__contains__(key):
                super().move_to_end(key)
            super().__setitem__(key, value)
            while len(self) > self.maxsize:
                super().popitem(last=False)

    def __getitem__(self, key):
        with self._lock:
            return super().__getitem__(key)

    def get(self, key, default=None):
        with self._lock:
            return super().get(key, default)

    def __contains__(self, key):
        with self._lock:
            return super().__contains__(key)


def resolve_log_gid() -> int:
    for gname in ("securepc", "adm"):
        try:
            return grp.getgrnam(gname).gr_gid
        except KeyError:
            continue
    return 0


LOG_GID = resolve_log_gid()

CONN_LOG_VAR = os.path.join(LOG_DIR_VAR, "connections.log")
CONN_JSONL_VAR = os.path.join(LOG_DIR_VAR, "connections.jsonl")
OUTBOUND_LOG_VAR = os.path.join(LOG_DIR_VAR, "outbound-internet.log")
OUTBOUND_JSONL_VAR = os.path.join(LOG_DIR_VAR, "outbound-internet.jsonl")
OUTBOUND_SUMMARY_VAR = os.path.join(LOG_DIR_VAR, "outbound-summary.txt")
NON_US_LOG_VAR = os.path.join(LOG_DIR_VAR, "non-us-traffic.log")
NON_US_JSONL_VAR = os.path.join(LOG_DIR_VAR, "non-us-traffic.jsonl")
NON_US_SUMMARY_VAR = os.path.join(LOG_DIR_VAR, "non-us-summary.txt")
UNREAD_NON_US_VAR = os.path.join(LOG_DIR_VAR, "unread-non-us.log")
BLOCKED_LOG_VAR = os.path.join(LOG_DIR_VAR, "blocked-alerts.log")
UNREAD_LOG_VAR = os.path.join(LOG_DIR_VAR, "unread-alerts.log")

PROTO_MAP = {
    "1": "ICMP",
    "6": "TCP",
    "17": "UDP",
    "58": "ICMPv6",
    "0": "IP",
}

MY_PID = os.getpid()
running = True
log_lock = threading.Lock()
domain_lock = threading.Lock()
wire_lock = threading.Lock()
policy_lock = threading.Lock()

# Runtime configuration loaded from /etc/securepc/securepc.conf
daemon_cfg = {
    "ENABLE_NFQUEUE_DPI": True,
    "NFQUEUE_NUM": 5353,
    "BLOCK_DOH_DOT": True,
    "ENABLE_OPENSSL_PROBES": True,
}
custom_blocked_domains: set[str] = set()

# Worldwide GeoIP + OpenSSL Certificate Inspector singletons
geo_db = GeoIPDatabase(lists_dir=LISTS_DIR)
cert_inspector = OpenSSLCertInspector(persist_cache=True)

# Async enrichment queue so capture & NFQUEUE threads never stall on OpenSSL handshakes
enrichment_queue: "queue.Queue[dict]" = queue.Queue(maxsize=5000)

# Bounded process & deduplication caches
pid_metadata_cache = BoundedDict(maxsize=8192)
parent_tid_map = BoundedDict(maxsize=8192)
proc_correlation_cache = BoundedDict(maxsize=4096)
recent_pid_cache = deque(maxlen=1500)
seen_connections = BoundedDict(maxsize=4096)
seen_outbound = BoundedDict(maxsize=4096)
seen_non_us = BoundedDict(maxsize=4096)
seen_unread_non_us = BoundedDict(maxsize=2048)

# Summary tables (ordered by recency)
outbound_summary_records = OrderedDict()
non_us_summary_records = OrderedDict()

# Passive & NFQUEUE wire-captured DNS & TLS SNI hints
live_dns_ip_map = BoundedDict(maxsize=4096)          # ip_str -> (qname, ts)
live_dns_sport_map = BoundedDict(maxsize=2048)       # (dst_ip, sport) -> (qname, ts)
live_last_dns_qname: tuple[str, float] = ("", 0.0)
live_sni_map = BoundedDict(maxsize=4096)             # (dst_ip, dport) -> (host, ts)
live_sni_ip_map = BoundedDict(maxsize=4096)          # dst_ip -> (host, ts)

# Domain resolution fallback cache
ip_domain_cache = BoundedDict(maxsize=4096)
for _k, _v in {
    "8.8.8.8": "dns.google",
    "8.8.4.4": "dns.google",
    "1.1.1.1": "one.one.one.one",
    "1.0.0.1": "one.one.one.one",
    "9.9.9.9": "dns.quad9.net",
    "208.67.222.222": "dns.opendns.com",
    "208.67.220.220": "dns.opendns.com",
}.items():
    ip_domain_cache[_k] = _v

cidr_attribution_nets = []
docker_name_cache = BoundedDict(maxsize=512)
docker_cache_ts = 0.0


def load_daemon_policy_config():
    """Load /etc/securepc/securepc.conf and custom blocked domain suffixes."""
    conf_path = os.path.join(CONF_DIR, "securepc.conf")
    new_cfg = dict(daemon_cfg)
    if os.path.isfile(conf_path):
        try:
            with open(conf_path, "r", encoding="utf-8", errors="replace") as f:
                for raw in f:
                    line = raw.split("#", 1)[0].strip()
                    if "=" not in line:
                        continue
                    k, v = line.split("=", 1)
                    k = k.strip()
                    v = v.strip().strip("\"'")
                    if k == "ENABLE_NFQUEUE_DPI":
                        new_cfg["ENABLE_NFQUEUE_DPI"] = v == "1"
                    elif k == "NFQUEUE_NUM" and v.isdigit():
                        new_cfg["NFQUEUE_NUM"] = int(v)
                    elif k == "BLOCK_DOH_DOT":
                        new_cfg["BLOCK_DOH_DOT"] = v == "1"
                    elif k == "ENABLE_OPENSSL_PROBES":
                        new_cfg["ENABLE_OPENSSL_PROBES"] = v == "1"
        except Exception:
            pass

    doms: set[str] = set()
    for dom_file in (
        os.path.join(CONF_DIR, "blocklist-domains.txt"),
        os.path.join(LISTS_DIR, "blocked-domains.txt"),
    ):
        if os.path.isfile(dom_file):
            try:
                with open(dom_file, "r", encoding="utf-8", errors="replace") as f:
                    for raw in f:
                        tok = raw.split("#", 1)[0].strip().lower()
                        if not tok or "*" in tok:
                            tok = tok.lstrip("*.")
                        tok = tok.strip(".")
                        if "." in tok and len(tok) >= 4:
                            doms.add(tok)
            except Exception:
                pass

    with policy_lock:
        daemon_cfg.update(new_cfg)
        custom_blocked_domains.clear()
        custom_blocked_domains.update(doms)


def check_domain_blocked(hostname: str) -> tuple[bool, str]:
    with policy_lock:
        block_doh = daemon_cfg["BLOCK_DOH_DOT"]
        custom_set = set(custom_blocked_domains)
    return match_blocked_domain_policy(
        hostname,
        custom_blocked_suffixes=custom_set,
        block_doh_hosts=block_doh,
    )


def get_active_firewall_backend() -> str:
    try:
        if os.path.isfile(ACTIVE_BACKEND_FILE):
            with open(ACTIVE_BACKEND_FILE, "r", encoding="utf-8") as f:
                b = f.read().strip()
                if b in ("nftables", "iptables", "solaris_ipf"):
                    return b
    except Exception:
        pass
    return "nftables"


def add_dynamic_block_ip(dst_ip: str, timeout_s: int = 3600):
    """Add an offending IPv4 or IPv6 endpoint to the kernel dynamic block set and kill active sockets."""
    try:
        ip_obj = ipaddress.ip_address(dst_ip)
    except ValueError:
        return
    if not is_public_internet_ip(dst_ip):
        return

    backend = get_active_firewall_backend()
    try:
        if backend == "nftables":
            set_name = "dyn_blk_v6" if ip_obj.version == 6 else "dyn_blk_v4"
            subprocess.run(
                ["nft", "add", "element", "inet", "securepc", set_name, f"{{ {dst_ip} timeout {timeout_s}s }}"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=1.5,
            )
        elif backend == "iptables":
            set_name = "securepc6_dyn_blk" if ip_obj.version == 6 else "securepc_dyn_blk"
            subprocess.run(
                ["ipset", "add", set_name, dst_ip, "timeout", str(timeout_s), "-exist"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=1.5,
            )
        elif backend == "solaris_ipf":
            subprocess.run(
                ["pfctl", "-t", "securepc_dyn_blk", "-T", "add", dst_ip],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=1.5,
            )
    except Exception:
        pass

    try:
        target_expr = f"[{dst_ip}]" if ip_obj.version == 6 else dst_ip
        subprocess.run(
            ["ss", "--kill", "dst", target_expr],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=1.5,
        )
    except Exception:
        pass


def is_kernel_or_irq_comm(comm: str) -> bool:
    if not comm:
        return False
    if comm.startswith(("irq/", "swapper", "ksoftirqd", "kworker/", "napi/", "rcu_", "migration/")):
        return True
    if re.match(r"^\d+-[a-zA-Z0-9_:-]+", comm):
        return True
    return False


def is_self_or_probe_process(pid: int, proc_info: dict = None, dst_ip: str = "", dst_port: str = "") -> bool:
    """Prevent SecurePC's own OpenSSL certificate probes from logging recursive outbound events."""
    if pid == MY_PID:
        return True
    if pid > 0 and (parent_tid_map.get(pid) == MY_PID or cert_inspector.is_probe_pid(pid)):
        return True
    if proc_info:
        p_pid = proc_info.get("pid", 0)
        if p_pid == MY_PID or (p_pid > 0 and (parent_tid_map.get(p_pid) == MY_PID or cert_inspector.is_probe_pid(p_pid))):
            return True
        if proc_info.get("service") == "securepc-monitor.service":
            return True
        cmd = proc_info.get("cmdline", "")
        if "openssl s_client -connect" in cmd and proc_info.get("uid", -1) == 0:
            return True
    if dst_ip and cert_inspector.is_active_probe(dst_ip, dst_port):
        if not proc_info or proc_info.get("uid", 0) in (0, -1):
            return True
    return False


def get_timestamp() -> str:
    now = datetime.datetime.now().astimezone()
    return now.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] + " " + now.strftime("%Z")


def get_uid_name(uid: int) -> str:
    if uid < 0:
        return "unknown"
    try:
        return pwd.getpwuid(uid).pw_name
    except Exception:
        return str(uid)


def is_public_internet_ip(ip_str: str) -> bool:
    if not ip_str or ip_str in ("0.0.0.0", "255.255.255.255", "::1", "::", "*"):
        return False
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        if (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_link_local
            or ip_obj.is_multicast
            or ip_obj.is_reserved
            or ip_obj.is_unspecified
        ):
            return False
        if ip_obj.version == 4:
            first = int(ip_str.split(".")[0])
            if first in (0, 10, 127) or ip_str.startswith("192.168.") or ip_str.startswith("169.254."):
                return False
            if first == 172:
                second = int(ip_str.split(".")[1])
                if 16 <= second <= 31:
                    return False
        return True
    except Exception:
        return False


def load_cidr_and_domain_seeds():
    cidr_attribution_nets.clear()
    try:
        with open("/etc/hosts", "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.split("#", 1)[0].strip()
                parts = line.split()
                if len(parts) >= 2 and is_public_internet_ip(parts[0]):
                    ip_domain_cache[parts[0]] = parts[1]
    except Exception:
        pass

    cidr_sources = [
        (os.path.join(LISTS_DIR, "aliyuncs-cidrs.txt"), "aliyuncs.com (.cn)"),
        (os.path.join(LISTS_DIR, "beijing-cidrs.txt"), "beijing-network.cn (.cn)"),
        (os.path.join(LISTS_DIR, "ir-major-cidrs.txt"), "iran-backbone.ir (.ir)"),
        (os.path.join(LISTS_DIR, "ir-cidrs.txt"), "iran-ripe.ir (.ir)"),
        (os.path.join(LISTS_DIR, "ru-major-cidrs.txt"), "russia-network.ru (.ru)"),
        (os.path.join(LISTS_DIR, "ru-cidrs.txt"), "russia-ripe.ru (.ru)"),
        (os.path.join(LISTS_DIR, "cn-cidrs.txt"), "china-apnic.cn (.cn)"),
    ]
    for path, label in cidr_sources:
        if not os.path.exists(path):
            continue
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.split("#", 1)[0].strip()
                    if not line:
                        continue
                    try:
                        cidr_attribution_nets.append((ipaddress.ip_network(line.split()[0], strict=False), label))
                    except Exception:
                        pass
        except Exception:
            pass

    well_known_supernets = [
        ("140.82.112.0/20", "github.com"),
        ("192.30.252.0/22", "github.com"),
        ("185.199.108.0/22", "githubusercontent.com"),
        ("185.125.188.0/22", "canonical.com"),
        ("91.189.88.0/21", "ubuntu.com"),
        ("104.16.0.0/12", "cloudflare.com"),
        ("172.64.0.0/13", "cloudflare.com"),
        ("151.101.0.0/16", "fastly.net"),
    ]
    for cidr_s, label in well_known_supernets:
        try:
            cidr_attribution_nets.append((ipaddress.ip_network(cidr_s, strict=False), label))
        except Exception:
            pass


def extract_domain_from_cmdline(cmdline: str) -> str:
    if not cmdline:
        return ""
    m_url = re.search(r"https?://([a-zA-Z0-9._-]+)", cmdline)
    if m_url:
        host = m_url.group(1).strip(".")
        if "." in host and not host[0].isdigit():
            return host.lower()
    bad_ext = (
        ".so", ".py", ".sh", ".js", ".ts", ".json", ".yaml", ".yml", ".toml",
        ".service", ".scope", ".slice", ".conf", ".log", ".txt", ".pem", ".crt",
        ".key", ".lock", ".pid", ".sock", ".db", ".sqlite", ".gz", ".tar", ".md",
    )
    matches = re.findall(
        r"\b([a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*\.(?:[a-zA-Z]{2,12}|xn--[a-zA-Z0-9-]+))\b",
        cmdline,
    )
    valid = []
    for raw_cand in matches:
        cand = raw_cand.lower()
        if cand.endswith(bad_ext) or cand.startswith("lib") or cand[0].isdigit():
            continue
        valid.append(cand)
    return valid[-1] if valid else ""


def get_wire_hostname_hint(dst_ip: str, dst_port: str, src_port: str = "0") -> str:
    """Retrieve live TLS SNI, HTTP Host, or DNS QNAME observed on the wire for this target."""
    now = time.time()
    with wire_lock:
        if str(dst_port) in ("53", "853", "5353"):
            sp_hit = live_dns_sport_map.get((dst_ip, str(src_port)))
            if sp_hit and now - sp_hit[1] < 10.0:
                return sp_hit[0]
            if live_last_dns_qname[0] and now - live_last_dns_qname[1] < 2.5:
                return live_last_dns_qname[0]

        sni_hit = live_sni_map.get((dst_ip, str(dst_port)))
        if sni_hit and now - sni_hit[1] < 120.0:
            return sni_hit[0]

        sni_ip_hit = live_sni_ip_map.get(dst_ip)
        if sni_ip_hit and now - sni_ip_hit[1] < 120.0:
            return sni_ip_hit[0]

        dns_hit = live_dns_ip_map.get(dst_ip)
        if dns_hit and now - dns_hit[1] < 900.0:
            return dns_hit[0]
    return ""


def resolve_fallback_ptr_or_cidr(ip_str: str, cmdline: str = "", category: str = "") -> str:
    cmd_dom = extract_domain_from_cmdline(cmdline)
    if cmd_dom and (ip_str in ("8.8.8.8", "8.8.4.4", "1.1.1.1", "127.0.0.53") or "DOM" in category):
        return cmd_dom

    with domain_lock:
        cached = ip_domain_cache.get(ip_str)
        if cached:
            return cached

    if not is_public_internet_ip(ip_str):
        if ip_str.startswith("192.168.") or ip_str.startswith("10."):
            return "private-lan.local"
        if ip_str.startswith("127.") or ip_str == "::1":
            return "localhost"
        return "local-network"

    resolved = ""
    try:
        old_to = socket.getdefaulttimeout()
        socket.setdefaulttimeout(1.0)
        try:
            host, _, _ = socket.gethostbyaddr(ip_str)
            if host and host != ip_str:
                resolved = host
        finally:
            socket.setdefaulttimeout(old_to)
    except Exception:
        pass

    if not resolved:
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            if ip_obj.version == 4:
                for net, label in cidr_attribution_nets:
                    if ip_obj in net:
                        resolved = label
                        break
        except Exception:
            pass

    if not resolved:
        resolved = "unresolved-public-ip"

    with domain_lock:
        ip_domain_cache[ip_str] = resolved

    return resolved


def get_docker_container_name(container_id_prefix: str) -> str:
    global docker_cache_ts
    now = time.time()
    if now - docker_cache_ts > 30.0 or container_id_prefix not in docker_name_cache:
        docker_cache_ts = now
        try:
            res = subprocess.run(
                ["docker", "ps", "--no-trunc", "--format", "{{.ID}} {{.Names}}"],
                capture_output=True,
                text=True,
                timeout=2,
            )
            for line in res.stdout.splitlines():
                parts = line.strip().split(None, 1)
                if len(parts) == 2:
                    cid, cname = parts
                    docker_name_cache[cid[:12]] = cname
                    docker_name_cache[cid] = cname
        except Exception:
            pass
    return docker_name_cache.get(
        container_id_prefix[:12],
        docker_name_cache.get(container_id_prefix, f"docker-{container_id_prefix[:12]}"),
    )


def inspect_pid(pid: int, fallback_comm: str = "unknown", fallback_uid: int = -1, force_refresh: bool = False) -> dict:
    cached = pid_metadata_cache.get(pid)
    if not force_refresh and cached and cached.get("exe", "unknown") not in ("unknown", "") and not cached["exe"].startswith("/proc/"):
        if not os.path.exists(f"/proc/{pid}"):
            return cached

    parent_pid = parent_tid_map.get(pid)
    parent_cached = pid_metadata_cache.get(parent_pid) if parent_pid else None

    clean_comm = fallback_comm if fallback_comm and fallback_comm != "<...>" and not is_kernel_or_irq_comm(fallback_comm) else ""
    if not clean_comm and parent_cached:
        clean_comm = parent_cached.get("comm", "unknown")
    if not clean_comm:
        clean_comm = "unknown"

    info = {
        "pid": pid,
        "ppid": parent_pid if parent_pid else (cached.get("ppid", 0) if cached else 0),
        "comm": clean_comm,
        "exe": parent_cached.get("exe", "unknown") if parent_cached else "unknown",
        "cmdline": parent_cached.get("cmdline", "") if parent_cached else "",
        "service": parent_cached.get("service", "unknown") if parent_cached else "unknown",
        "uid": fallback_uid if fallback_uid >= 0 else (parent_cached.get("uid", -1) if parent_cached else -1),
        "user": get_uid_name(fallback_uid) if fallback_uid >= 0 else (parent_cached.get("user", "unknown") if parent_cached else "unknown"),
    }

    if pid <= 0:
        return info

    target_pid = pid if os.path.exists(f"/proc/{pid}") else (parent_pid if parent_pid and os.path.exists(f"/proc/{parent_pid}") else None)

    if target_pid:
        proc_base = f"/proc/{target_pid}"
        try:
            with open(f"{proc_base}/comm", "r", encoding="utf-8", errors="replace") as f:
                c = f.read().strip()
                if c and not is_kernel_or_irq_comm(c) and (target_pid == pid or info["comm"] == "unknown"):
                    info["comm"] = c
        except Exception:
            pass

        try:
            exe_link = os.readlink(f"{proc_base}/exe")
            if target_pid == pid or info["exe"] in ("unknown", ""):
                info["exe"] = exe_link
        except Exception:
            pass

        try:
            with open(f"{proc_base}/cmdline", "rb") as f:
                raw = f.read().replace(b"\x00", b" ").decode("utf-8", errors="replace").strip()
                if raw and (target_pid == pid or not info["cmdline"]):
                    raw_single = re.sub(r"[\r\n\t]+", " ; ", raw)
                    info["cmdline_full"] = raw_single[:1000]
                    info["cmdline"] = raw_single[:240]
        except Exception:
            pass

        try:
            got_ppid = False
            got_uid = False
            got_tgid = False
            with open(f"{proc_base}/status", "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    if line.startswith("Tgid:"):
                        parts = line.split()
                        if len(parts) >= 2 and target_pid == pid:
                            tgid_val = int(parts[1])
                            if tgid_val > 0:
                                info["pid"] = tgid_val
                        got_tgid = True
                    elif line.startswith("PPid:"):
                        parts = line.split()
                        if len(parts) >= 2 and target_pid == pid:
                            info["ppid"] = int(parts[1])
                        got_ppid = True
                    elif line.startswith("Uid:"):
                        parts = line.split()
                        if len(parts) >= 2:
                            uid_val = int(parts[1])
                            info["uid"] = uid_val
                            info["user"] = get_uid_name(uid_val)
                        got_uid = True
                    if got_tgid and got_ppid and got_uid:
                        break
        except Exception:
            pass

        try:
            with open(f"{proc_base}/cgroup", "r", encoding="utf-8", errors="replace") as f:
                cg = f.read()
                m_docker = re.search(r"(?:docker[-/]|/containers/)([0-9a-f]{12,64})", cg)
                m_svc = re.search(r"/([^/\s]+\.service)", cg)
                m_scope = re.search(r"/([^/\s]+\.scope)", cg)
                if m_docker:
                    cname = get_docker_container_name(m_docker.group(1))
                    info["service"] = f"docker:{cname}"
                elif m_svc:
                    info["service"] = m_svc.group(1)
                elif m_scope:
                    info["service"] = m_scope.group(1)
        except Exception:
            pass

    if info["exe"] in ("unknown", "") and info["comm"] not in ("unknown", "<...>"):
        for bin_dir in ("/usr/local/bin", "/usr/bin", "/bin", "/usr/sbin", "/sbin"):
            cand = os.path.join(bin_dir, info["comm"])
            if os.path.exists(cand):
                info["exe"] = cand
                break
        if info["exe"] in ("unknown", ""):
            info["exe"] = info["comm"]

    if not info["cmdline"] or info["cmdline"] == "<...>":
        info["cmdline"] = info["exe"] if info["exe"] != "unknown" else info["comm"]

    if not is_kernel_or_irq_comm(info["comm"]):
        pid_metadata_cache[pid] = info
        if info["pid"] > 0:
            pid_metadata_cache[info["pid"]] = info
    return info


def write_audit_log(var_path: str, line: str):
    """Append tamper-protected audit record strictly to /var/log/securepc (0640 root:securepc/adm)."""
    with log_lock:
        try:
            created = not os.path.exists(var_path)
            with open(var_path, "a", encoding="utf-8") as f:
                f.write(line + "\n")
            if created:
                os.chmod(var_path, 0o640)
                try:
                    os.chown(var_path, 0, LOG_GID)
                except PermissionError:
                    pass
        except Exception:
            pass


def write_atomic_summary(var_path: str, content: str):
    tmp = f"{var_path}.tmp.{MY_PID}"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(content)
        os.chmod(tmp, 0o640)
        try:
            os.chown(tmp, 0, LOG_GID)
        except PermissionError:
            pass
        os.replace(tmp, var_path)
    except Exception:
        pass


def format_port_col(src_port: str, dst_port: str, proto: str) -> str:
    sp = str(src_port or "0")
    dp = str(dst_port or "0")
    if sp not in ("0", ""):
        return f"{sp}->{dp}/{proto}"
    return f"{dp}/{proto}"


def flush_outbound_summary():
    lines = []
    header = (
        f"{'LAST SEEN':<19} | {'STATUS':<9} | {'COUNTRY':<19} | {'PID / PPID':<15} | "
        f"{'SERVICE / SOFTWARE':<25} | {'OUTBOUND IP':<21} | {'PORT (S->D)':<14} | {'DOMAIN / OPENSSL CERT'}"
    )
    sep = "-" * 173
    lines.append(header)
    lines.append(sep)
    items = list(outbound_summary_records.values())[-40:]
    for rec in reversed(items):
        svc_soft = f"{rec['service']} ({rec['software']})"
        if len(svc_soft) > 25:
            svc_soft = svc_soft[:22] + "..."
        pid_ppid = f"{rec.get('pid', 0)}/{rec.get('ppid', 0)}"[:15]
        dst_ip_s = str(rec["dst_ip"])[:21]
        port_col = format_port_col(rec.get("src_port", "0"), rec["dst_port"], rec["proto"])[:14]
        ctry = rec.get("country_short", "US")
        if len(ctry) > 19:
            ctry = ctry[:15] + "...)" if "(" in ctry else ctry[:16] + "..."
        lines.append(
            f"{rec['short_ts']:<19} | {rec['status']:<9} | {ctry:<19} | {pid_ppid:<15} | "
            f"{svc_soft:<25} | {dst_ip_s:<21} | {port_col:<14} | {rec['domain']}"
        )
    write_atomic_summary(OUTBOUND_SUMMARY_VAR, "\n".join(lines) + "\n")


def flush_non_us_summary():
    lines = []
    header = (
        f"{'LAST SEEN':<19} | {'POLICY':<8} | {'COUNTRY':<19} | {'PID / PPID':<15} | "
        f"{'SERVICE / SOFTWARE':<25} | {'OUTBOUND IP':<21} | {'PORT (S->D)':<14} | {'DOMAIN & OPENSSL CERT'}"
    )
    sep = "-" * 172
    lines.append(header)
    lines.append(sep)
    items = list(non_us_summary_records.values())[-40:]
    for rec in reversed(items):
        svc_soft = f"{rec['service']} ({rec['software']})"
        if len(svc_soft) > 25:
            svc_soft = svc_soft[:22] + "..."
        pid_ppid = f"{rec.get('pid', 0)}/{rec.get('ppid', 0)}"[:15]
        dst_ip_s = str(rec["dst_ip"])[:21]
        port_col = format_port_col(rec.get("src_port", "0"), rec["dst_port"], rec["proto"])[:14]
        ctry = rec.get("country_label", "NON-US")[:19]
        lines.append(
            f"{rec['short_ts']:<19} | {rec['policy']:<8} | {ctry:<19} | {pid_ppid:<15} | "
            f"{svc_soft:<25} | {dst_ip_s:<21} | {port_col:<14} | {rec['domain']}"
        )
    write_atomic_summary(NON_US_SUMMARY_VAR, "\n".join(lines) + "\n")


def record_non_us_traffic(
    ts: str,
    status: str,
    proto: str,
    src_ip: str,
    src_port: str,
    dst_ip: str,
    dst_port: str,
    proc_info: dict,
    eval_res: dict,
    note: str = "",
):
    pid = proc_info.get("pid", 0)
    ppid = proc_info.get("ppid", 0)
    user = proc_info.get("user", "unknown")
    service = proc_info.get("service", "unknown")
    exe = proc_info.get("exe", "unknown")
    comm = proc_info.get("comm", "unknown")
    cmdline = proc_info.get("cmdline", comm)
    software = os.path.basename(exe) if exe and exe not in ("unknown", "") and not exe.startswith("UID:") else comm

    is_blocked = status == "BLOCKED" or eval_res.get("is_blocked_region", False)
    policy = "BLOCKED" if is_blocked else "FLAGGED"
    eff_cc = eval_res.get("effective_cc", "NON-US")
    country_label = eval_res.get("country_label", eff_cc)
    best_domain = eval_res.get("best_domain", "unresolved-public-ip")
    cert_summary = eval_res.get("cert_summary", "no-tls-cert")
    reasons_str = ", ".join(eval_res.get("non_us_reasons", [])) or "Non-US-Destination"

    dedup_key = (policy, proto, dst_ip, str(dst_port), best_domain, service, software)
    now = time.time()
    if policy != "BLOCKED":
        last_t = seen_non_us.get(dedup_key, 0)
        if now - last_t < 30.0:
            return
    seen_non_us[dedup_key] = now

    human_line = (
        f"[{ts}] POLICY={policy:<7} COUNTRY=\"{country_label}\" PROTO={proto:<4} PORT={dst_port} "
        f"SRC={src_ip}:{src_port} -> OUTBOUND_IP={dst_ip}:{dst_port} DOMAIN=\"{best_domain}\" OPENSSL_CERT=\"{cert_summary}\" "
        f"REASON=\"{reasons_str}\" | PID={pid} PPID={ppid} USER={user} SERVICE={service} SOFTWARE={software} BINARY={exe} "
        f"CMD=\"{cmdline}\""
        + (f" | NOTE={note}" if note else "")
    )
    write_audit_log(NON_US_LOG_VAR, human_line)

    json_obj = {
        "timestamp": ts,
        "policy": policy,
        "status": status,
        "country_code": eff_cc,
        "country_name": eval_res.get("effective_country", ""),
        "country_label": country_label,
        "ip_country_code": eval_res.get("ip_cc", ""),
        "geoip_cidr": eval_res.get("geoip_cidr", ""),
        "non_us_reasons": eval_res.get("non_us_reasons", []),
        "protocol": proto,
        "port": int(dst_port) if str(dst_port).isdigit() else dst_port,
        "src_ip": src_ip,
        "src_port": int(src_port) if str(src_port).isdigit() else src_port,
        "dst_ip": dst_ip,
        "dst_port": int(dst_port) if str(dst_port).isdigit() else dst_port,
        "domain": best_domain,
        "openssl_cert_summary": cert_summary,
        "openssl_cert": eval_res.get("cert", {}),
        "pid": pid,
        "ppid": ppid,
        "user": user,
        "service": service,
        "software": software,
        "binary": exe,
        "cmdline": cmdline,
        "note": note,
    }
    write_audit_log(NON_US_JSONL_VAR, json.dumps(json_obj))

    if not is_blocked:
        flag_key = (eff_cc, dst_ip, str(dst_port), best_domain, service, software)
        last_flag_ts = seen_unread_non_us.get(flag_key, 0.0)
        if now - last_flag_ts > 3600.0 or not os.path.exists(UNREAD_NON_US_VAR) or os.path.getsize(UNREAD_NON_US_VAR) == 0:
            if now - last_flag_ts > 60.0:
                seen_unread_non_us[flag_key] = now
                flag_line = (
                    f"[{ts[:19]}] [NON-US:{eff_cc}] COUNTRY=\"{country_label}\" PROTO={proto} PORT={dst_port} "
                    f"(SRC={src_ip}:{src_port} -> DST={dst_ip}:{dst_port}) DOMAIN=\"{best_domain}\" "
                    f"CERT=\"{cert_summary}\" | PID={pid} PPID={ppid} SERVICE={service} ({software}) USER={user}"
                )
                write_audit_log(UNREAD_NON_US_VAR, flag_line)

    summary_key = (service, software, dst_ip, str(dst_port), proto, best_domain)
    with log_lock:
        prev_cnt = non_us_summary_records.pop(summary_key, {}).get("count", 0)
        non_us_summary_records[summary_key] = {
            "short_ts": ts[:19],
            "policy": policy,
            "country_label": country_label,
            "pid": pid,
            "ppid": ppid,
            "service": service,
            "software": software,
            "src_port": str(src_port),
            "dst_ip": dst_ip,
            "dst_port": str(dst_port),
            "proto": proto,
            "domain": best_domain,
            "count": prev_cnt + 1,
        }
        while len(non_us_summary_records) > 100:
            non_us_summary_records.popitem(last=False)
        flush_non_us_summary()


def process_enriched_event(ev: dict):
    ts = ev["ts"]
    status = ev["status"]
    proto = ev["proto"]
    src_ip = ev["src_ip"]
    src_port = str(ev["src_port"])
    dst_ip = ev["dst_ip"]
    dst_port = str(ev["dst_port"])
    proc_info = ev["proc_info"]
    note = ev.get("note", "")
    category = ev.get("category", "")
    is_kernel_block = ev.get("is_kernel_block", False)
    explicit_domain = ev.get("explicit_domain", "")

    if is_self_or_probe_process(proc_info.get("pid", 0), proc_info, dst_ip, dst_port):
        return
    if status != "BLOCKED" and proc_info.get("service") in ("unknown", "") and proc_info.get("comm") in ("unknown", ""):
        return

    cmdline = re.sub(r"[\r\n\t]+", " ", proc_info.get("cmdline", ""))[:240]
    cmdline_for_hint = proc_info.get("cmdline_full") or cmdline
    wire_hint = explicit_domain or get_wire_hostname_hint(dst_ip, dst_port, src_port)
    cmd_hint = extract_domain_from_cmdline(cmdline_for_hint)
    sni_or_dns_hint = wire_hint or cmd_hint

    fallback_dom = resolve_fallback_ptr_or_cidr(dst_ip, cmdline=cmdline_for_hint, category=category)

    with policy_lock:
        openssl_enabled = daemon_cfg["ENABLE_OPENSSL_PROBES"]

    eval_res = evaluate_traffic_destination(
        geo_db=geo_db,
        cert_inspector=cert_inspector,
        dst_ip=dst_ip,
        dst_port=dst_port,
        proto=proto,
        fallback_domain=fallback_dom,
        sni_or_dns_hint=sni_or_dns_hint,
        category=category,
        allow_live_openssl=(status != "BLOCKED" and openssl_enabled),
    )

    domain = eval_res["best_domain"]
    if str(dst_port) in ("53", "853", "5353") and sni_or_dns_hint and dst_ip not in domain:
        domain = f"{sni_or_dns_hint} (via {dst_ip})"
        eval_res["best_domain"] = domain

    country_label = eval_res["country_label"]
    eff_cc = eval_res["effective_cc"]
    eff_country = eval_res["effective_country"]
    country_short = f"{eff_cc} ({eff_country})" if (eval_res["is_public"] or eval_res["is_non_us"]) else "LAN"

    # Dynamic OpenSSL Certificate / Custom Domain Block Enforcement (IPv4 & IPv6):
    custom_dom_hit, custom_cat = check_domain_blocked(clean_hostname_token(domain))
    if status != "BLOCKED" and eval_res["is_public"] and (eval_res["is_blocked_region"] or custom_dom_hit) and str(dst_port) not in ("53", "853", "5353"):
        add_dynamic_block_ip(dst_ip, timeout_s=3600)
        status = "BLOCKED"
        category = custom_cat if custom_dom_hit else f"CERT-{eff_cc}"
        is_kernel_block = True

    display_status = status
    if status != "BLOCKED" and eval_res["is_non_us"]:
        display_status = f"NON-US:{eff_cc}"[:9]

    pid = proc_info.get("pid", 0)
    ppid = proc_info.get("ppid", 0)
    user = proc_info.get("user", "unknown")
    service = proc_info.get("service", "unknown")
    exe = proc_info.get("exe", "unknown")
    comm = proc_info.get("comm", "unknown")

    if is_kernel_block:
        blk_dedup_key = ("BLK_ALERT", category, dst_ip, dst_port, domain, service, exe)
        now_blk = time.time()
        if now_blk - seen_non_us.get(blk_dedup_key, 0.0) >= 4.0:
            seen_non_us[blk_dedup_key] = now_blk
            out_if = ev.get("iface", "")
            alert_line = (
                f"[{ts}] [BLOCKED:{category}] COUNTRY=\"{country_label}\" PROTO={proto} PORT={dst_port} "
                f"(SRC={src_ip}:{src_port} -> DST={dst_ip}:{dst_port}) DOMAIN=\"{domain}\" (IF={out_if}) | "
                f"PID={pid} PPID={ppid} USER={user} SERVICE={service} "
                f"BINARY={exe} CMD=\"{cmdline}\""
            )
            write_audit_log(BLOCKED_LOG_VAR, alert_line)
            write_audit_log(UNREAD_LOG_VAR, alert_line)
            try:
                subprocess.run(
                    ["logger", "-p", "security.warn", "-t", "SECUREPC-FIREWALL", alert_line],
                    timeout=2,
                )
            except Exception:
                pass

    conn_line = (
        f"[{ts}] STATUS={display_status:<9} COUNTRY=\"{country_label}\" PROTO={proto:<4} PORT={dst_port} "
        f"SRC={src_ip}:{src_port} -> DST={dst_ip}:{dst_port} DOMAIN=\"{domain}\" | "
        f"PID={pid} PPID={ppid} USER={user} SERVICE={service} BINARY={exe} CMD=\"{cmdline}\""
        + (f" | NOTE={note}" if note else "")
    )
    write_audit_log(CONN_LOG_VAR, conn_line)

    conn_json = {
        "timestamp": ts,
        "status": display_status,
        "country_code": eff_cc,
        "country": country_label,
        "is_non_us": eval_res["is_non_us"],
        "protocol": proto,
        "port": int(dst_port) if dst_port.isdigit() else dst_port,
        "src_ip": src_ip,
        "src_port": int(src_port) if src_port.isdigit() else src_port,
        "dst_ip": dst_ip,
        "dst_port": int(dst_port) if dst_port.isdigit() else dst_port,
        "domain": domain,
        "openssl_cert_summary": eval_res["cert_summary"],
        "pid": pid,
        "ppid": ppid,
        "user": user,
        "service": service,
        "binary": exe,
        "process": comm,
        "cmdline": cmdline,
        "note": note,
    }
    write_audit_log(CONN_JSONL_VAR, json.dumps(conn_json))

    if is_public_internet_ip(dst_ip) or status == "BLOCKED":
        software = os.path.basename(exe) if exe and exe not in ("unknown", "") and not exe.startswith("UID:") else comm
        dedup_key = (display_status, proto, dst_ip, dst_port, service, software)
        now = time.time()
        should_write_outbound = True
        if status != "BLOCKED":
            last_t = seen_outbound.get(dedup_key, 0)
            if now - last_t < 15.0:
                should_write_outbound = False
        if should_write_outbound:
            seen_outbound[dedup_key] = now
            out_line = (
                f"[{ts}] STATUS={display_status:<9} COUNTRY=\"{country_label}\" PROTO={proto:<4} PORT={dst_port} "
                f"SRC={src_ip}:{src_port} -> OUTBOUND_IP={dst_ip}:{dst_port} DOMAIN=\"{domain}\" OPENSSL_CERT=\"{eval_res['cert_summary']}\" | "
                f"PID={pid} PPID={ppid} USER={user} SERVICE={service} SOFTWARE={software} BINARY={exe} CMD=\"{cmdline}\""
                + (f" | NOTE={note}" if note else "")
            )
            write_audit_log(OUTBOUND_LOG_VAR, out_line)

            out_json = dict(conn_json)
            out_json["software"] = software
            out_json["geoip_cidr"] = eval_res["geoip_cidr"]
            out_json["openssl_cert"] = eval_res["cert"]
            write_audit_log(OUTBOUND_JSONL_VAR, json.dumps(out_json))

            summary_key = (service, software, dst_ip, dst_port, proto, domain if dst_port in ("53", "853", "5353") else "")
            with log_lock:
                eff_st = display_status
                if summary_key in outbound_summary_records:
                    prev_rec = outbound_summary_records.pop(summary_key)
                    prev_cnt = prev_rec.get("count", 1)
                    if prev_rec.get("status") == "BLOCKED" and display_status != "BLOCKED":
                        eff_st = "BLOCKED"
                else:
                    prev_cnt = 0
                outbound_summary_records[summary_key] = {
                    "short_ts": ts[:19],
                    "status": eff_st,
                    "country_short": country_short,
                    "pid": pid,
                    "ppid": ppid,
                    "service": service,
                    "software": software,
                    "binary": exe,
                    "src_port": src_port,
                    "dst_ip": dst_ip,
                    "dst_port": dst_port,
                    "proto": proto,
                    "domain": domain,
                    "count": prev_cnt + 1,
                }
                while len(outbound_summary_records) > 100:
                    outbound_summary_records.popitem(last=False)
                flush_outbound_summary()

        if eval_res["is_non_us"] or (status == "BLOCKED" and category not in ("QWEN-LLM", "DOH-BYPASS")):
            record_non_us_traffic(
                ts=ts,
                status=status,
                proto=proto,
                src_ip=src_ip,
                src_port=src_port,
                dst_ip=dst_ip,
                dst_port=dst_port,
                proc_info=proc_info,
                eval_res=eval_res,
                note=note,
            )


def enqueue_connection(
    ts: str,
    status: str,
    proto: str,
    src_ip: str,
    src_port: str,
    dst_ip: str,
    dst_port: str,
    proc_info: dict,
    note: str = "",
    category: str = "",
    is_kernel_block: bool = False,
    iface: str = "",
    explicit_domain: str = "",
):
    if is_self_or_probe_process(proc_info.get("pid", 0), proc_info, dst_ip, str(dst_port)):
        return

    key = (status, proto, src_ip, str(src_port), dst_ip, str(dst_port), proc_info.get("pid", 0))
    now = time.time()
    if status != "BLOCKED":
        last_t = seen_connections.get(key, 0)
        if now - last_t < 5.0:
            return
        seen_connections[key] = now

    ev = {
        "ts": ts,
        "status": status,
        "proto": proto,
        "src_ip": src_ip,
        "src_port": str(src_port),
        "dst_ip": dst_ip,
        "dst_port": str(dst_port),
        "proc_info": proc_info,
        "note": note,
        "category": category,
        "is_kernel_block": is_kernel_block,
        "iface": iface,
        "explicit_domain": explicit_domain,
    }
    try:
        enrichment_queue.put_nowait(ev)
    except queue.Full:
        pass


def enrichment_worker():
    while running:
        try:
            ev = enrichment_queue.get(timeout=1.0)
        except queue.Empty:
            continue
        try:
            process_enriched_event(ev)
        except Exception:
            pass
        finally:
            enrichment_queue.task_done()


# ------------------------------------------------------------------------------
# DNS QNAME, TLS ClientHello SNI & HTTP Host Parsers (IPv4 & IPv6)
# ------------------------------------------------------------------------------
RE_HTTP_HOST = re.compile(rb"\r\nHost:\s*([a-zA-Z0-9._-]+)", re.IGNORECASE)


def parse_dns_qname(buf: bytes, offset: int) -> tuple[str, int]:
    labels = []
    pos = offset
    jumped = False
    end_pos = offset
    hops = 0
    n = len(buf)
    while pos < n and hops < 20:
        hops += 1
        length = buf[pos]
        if length == 0:
            if not jumped:
                end_pos = pos + 1
            break
        if (length & 0xC0) == 0xC0:
            if pos + 1 >= n:
                break
            ptr = ((length & 0x3F) << 8) | buf[pos + 1]
            if not jumped:
                end_pos = pos + 2
                jumped = True
            pos = ptr
            continue
        pos += 1
        if pos + length > n:
            break
        try:
            labels.append(buf[pos : pos + length].decode("ascii", errors="ignore"))
        except Exception:
            pass
        pos += length
    return ".".join(labels).lower().strip("."), end_pos


def parse_dns_packet(payload: bytes, src_ip: str, dst_ip: str, sport: int, dport: int, is_tcp: bool = False) -> str:
    """Parse DNS query/response; returns queried hostname if present."""
    if is_tcp:
        if len(payload) < 14:
            return ""
        payload = payload[2:]
    if len(payload) < 12:
        return ""
    flags, qdcount, ancount, _, _ = struct.unpack("!HHHHH", payload[2:12])
    if qdcount < 1 or qdcount > 8:
        return ""
    qname, pos = parse_dns_qname(payload, 12)
    if not qname or "." not in qname:
        return ""
    pos += 4  # QTYPE + QCLASS

    now = time.time()
    is_response = bool(flags & 0x8000)
    with wire_lock:
        if not is_response and dport in (53, 5353):
            live_dns_sport_map[(dst_ip, str(sport))] = (qname, now)
            global live_last_dns_qname
            live_last_dns_qname = (qname, now)
            return qname

        if is_response and ancount > 0:
            ans_ips = []
            for _ in range(min(ancount, 16)):
                if pos >= len(payload):
                    break
                _, pos = parse_dns_qname(payload, pos)
                if pos + 10 > len(payload):
                    break
                rtype, _, _, rdlen = struct.unpack("!HHIH", payload[pos : pos + 10])
                pos += 10
                if pos + rdlen > len(payload):
                    break
                rdata = payload[pos : pos + rdlen]
                pos += rdlen
                if rtype == 1 and rdlen == 4:
                    ans_ip = socket.inet_ntoa(rdata)
                    live_dns_ip_map[ans_ip] = (qname, now)
                    ans_ips.append(ans_ip)
                elif rtype == 28 and rdlen == 16:
                    ans_ip6 = socket.inet_ntop(socket.AF_INET6, rdata)
                    live_dns_ip_map[ans_ip6] = (qname, now)
                    ans_ips.append(ans_ip6)

            is_blk, _ = check_domain_blocked(qname)
            if is_blk:
                for a_ip in ans_ips:
                    add_dynamic_block_ip(a_ip, timeout_s=3600)
    return qname


def parse_tls_client_hello_sni(payload: bytes) -> str:
    if len(payload) < 43 or payload[0] != 0x16 or payload[1] != 0x03 or payload[5] != 0x01:
        return ""
    pos = 5 + 4 + 2 + 32
    if pos >= len(payload):
        return ""
    sid_len = payload[pos]
    pos += 1 + sid_len
    if pos + 2 > len(payload):
        return ""
    cs_len = struct.unpack("!H", payload[pos : pos + 2])[0]
    pos += 2 + cs_len
    if pos >= len(payload):
        return ""
    comp_len = payload[pos]
    pos += 1 + comp_len
    if pos + 2 > len(payload):
        return ""
    ext_total_len = struct.unpack("!H", payload[pos : pos + 2])[0]
    pos += 2
    end_ext = min(len(payload), pos + ext_total_len)
    while pos + 4 <= end_ext:
        ext_type, ext_len = struct.unpack("!HH", payload[pos : pos + 4])
        pos += 4
        if pos + ext_len > end_ext:
            break
        if ext_type == 0x0000 and ext_len >= 5:
            name_type = payload[pos + 2]
            host_len = struct.unpack("!H", payload[pos + 3 : pos + 5])[0]
            if name_type == 0 and pos + 5 + host_len <= pos + ext_len:
                host = payload[pos + 5 : pos + 5 + host_len].decode("ascii", errors="ignore").lower().strip(".")
                if "." in host:
                    return host
        pos += ext_len
    return ""


def unpack_ip_l4(pkt: bytes) -> tuple[int, str, str, int, int, bytes]:
    """Unpack IPv4 or IPv6 packet into (l4_proto, src_ip, dst_ip, sport, dport, l4_payload)."""
    if len(pkt) < 20:
        return 0, "", "", 0, 0, b""
    ver = pkt[0] >> 4
    if ver == 4:
        ihl = (pkt[0] & 0x0F) * 4
        if len(pkt) < ihl + 8:
            return 0, "", "", 0, 0, b""
        proto = pkt[9]
        src_ip = socket.inet_ntoa(pkt[12:16])
        dst_ip = socket.inet_ntoa(pkt[16:20])
        l4 = pkt[ihl:]
    elif ver == 6:
        if len(pkt) < 48:
            return 0, "", "", 0, 0, b""
        nxt = pkt[6]
        src_ip = socket.inet_ntop(socket.AF_INET6, pkt[8:24])
        dst_ip = socket.inet_ntop(socket.AF_INET6, pkt[24:40])
        off = 40
        # Skip common IPv6 extension headers if present
        hops = 0
        while nxt in (0, 43, 44, 60) and off + 8 <= len(pkt) and hops < 6:
            hops += 1
            hdr_ext_len = (pkt[off + 1] + 1) * 8 if nxt != 44 else 8
            nxt = pkt[off]
            off += hdr_ext_len
        proto = nxt
        l4 = pkt[off:]
    else:
        return 0, "", "", 0, 0, b""

    if proto == 17 and len(l4) >= 8:
        sport, dport = struct.unpack("!HH", l4[:4])
        return 17, src_ip, dst_ip, sport, dport, l4[8:]
    if proto == 6 and len(l4) >= 20:
        sport, dport = struct.unpack("!HH", l4[:4])
        doff = (l4[12] >> 4) * 4
        if len(l4) < doff:
            return 6, src_ip, dst_ip, sport, dport, b""
        return 6, src_ip, dst_ip, sport, dport, l4[doff:]
    return proto, src_ip, dst_ip, 0, 0, b""


# ------------------------------------------------------------------------------
# Synchronous Fail-Safe NFQUEUE Deep Packet Inspector (IPv4 & IPv6)
# ------------------------------------------------------------------------------
NETLINK_NETFILTER = 12
NFNL_SUBSYS_QUEUE = 3
NFQNL_MSG_PACKET = (NFNL_SUBSYS_QUEUE << 8) | 0
NFQNL_MSG_VERDICT = (NFNL_SUBSYS_QUEUE << 8) | 1
NFQNL_MSG_CONFIG = (NFNL_SUBSYS_QUEUE << 8) | 2
NLM_F_REQUEST = 1
NLM_F_ACK = 4
NF_DROP = 0
NF_ACCEPT = 1


def _nla_pack(atype: int, data: bytes) -> bytes:
    alen = 4 + len(data)
    pad = (4 - (alen % 4)) % 4
    return struct.pack("=HH", alen, atype) + data + (b"\x00" * pad)


def _nlmsg_pack(mtype: int, flags: int, qnum: int, attrs: bytes, seq: int = 0) -> bytes:
    nfgen = struct.pack("!BBH", socket.AF_UNSPEC, 0, qnum)
    body = nfgen + attrs
    hdr = struct.pack("=IHHII", 16 + len(body), mtype, flags, seq, 0)
    return hdr + body


def nfqueue_dpi_worker():
    """
    Synchronously inspects outbound DNS queries (53/5353) and initial HTTP/TLS
    ClientHello packets via Linux NFQUEUE (`bypass` + `FAIL_OPEN` fail-safe).
    Blocks forbidden domains BEFORE a single packet leaves the network interface.
    """
    with policy_lock:
        if not daemon_cfg["ENABLE_NFQUEUE_DPI"]:
            return
        qnum = daemon_cfg["NFQUEUE_NUM"]

    if not hasattr(socket, "AF_NETLINK"):
        return

    try:
        nl = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_NETFILTER)
        nl.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
        nl.bind((0, 0))
        # Bind queue + copy_packet(1500) + maxlen(4096) + flags(FAIL_OPEN=1 | GSO=4 | UID_GID=8)
        attrs = (
            _nla_pack(1, struct.pack("!BBH", 1, 0, 0))
            + _nla_pack(2, struct.pack("!IB", 1500, 2))
            + _nla_pack(3, struct.pack("!I", 4096))
            + _nla_pack(4, struct.pack("!I", 13))
            + _nla_pack(5, struct.pack("!I", 13))
        )
        nl.send(_nlmsg_pack(NFQNL_MSG_CONFIG, NLM_F_REQUEST | NLM_F_ACK, qnum, attrs, seq=1))
        ack = nl.recv(4096)
        if len(ack) >= 20:
            err_code = struct.unpack_from("=i", ack, 16)[0]
            if err_code != 0:
                sys.stderr.write(f"[WARN] NFQUEUE {qnum} bind returned {err_code}; static kernel rules remain active.\n")
                nl.close()
                return
    except Exception as e:
        sys.stderr.write(f"[WARN] NFQUEUE {qnum} unavailable ({e}); static kernel rules remain active.\n")
        return

    nl.settimeout(1.0)
    while running:
        try:
            buf = nl.recv(65535)
        except socket.timeout:
            continue
        except Exception:
            if not running:
                break
            time.sleep(0.1)
            continue

        offset = 0
        blen = len(buf)
        while offset + 16 <= blen:
            nl_len, nl_type, _, _, _ = struct.unpack_from("=IHHII", buf, offset)
            if nl_len < 16 or offset + nl_len > blen:
                break

            if nl_type == NFQNL_MSG_PACKET and nl_len >= 20:
                pos = offset + 20
                end_msg = offset + nl_len
                pkt_id = 0
                payload = b""
                uid_val = -1
                out_ifname = ""

                while pos + 4 <= end_msg:
                    alen, raw_atype = struct.unpack_from("=HH", buf, pos)
                    if alen < 4 or pos + alen > end_msg:
                        break
                    atype = raw_atype & 0x3FFF
                    adata = buf[pos + 4 : pos + alen]
                    if atype == 1 and len(adata) >= 7:
                        pkt_id = struct.unpack_from("!I", adata, 0)[0]
                    elif atype == 6 and len(adata) >= 4:
                        ifidx = struct.unpack_from("!I", adata, 0)[0]
                        if ifidx > 0:
                            try:
                                out_ifname = socket.if_indextoname(ifidx)
                            except OSError:
                                pass
                    elif atype == 10:
                        payload = adata
                    elif atype == 16 and len(adata) >= 4:
                        uid_val = struct.unpack_from("!I", adata, 0)[0]
                    pos += (alen + 3) & ~3

                verdict = NF_ACCEPT
                if payload:
                    proto_num, src_ip, dst_ip, sport, dport, l4_data = unpack_ip_l4(payload)
                    if l4_data and not cert_inspector.is_active_probe(dst_ip, dport):
                        inspected_host = ""
                        proto_str = "UDP" if proto_num == 17 else "TCP"

                        if dport in (53, 5353):
                            inspected_host = parse_dns_packet(
                                l4_data, src_ip, dst_ip, sport, dport, is_tcp=(proto_num == 6)
                            )
                        elif proto_num == 6 and dport in (80, 443, 8080, 8443):
                            now = time.time()
                            if l4_data[0] == 0x16:
                                inspected_host = parse_tls_client_hello_sni(l4_data)
                            else:
                                mh = RE_HTTP_HOST.search(l4_data)
                                if mh:
                                    cand = mh.group(1).decode("ascii", errors="ignore").lower().strip(".")
                                    if "." in cand:
                                        inspected_host = cand
                            if inspected_host:
                                with wire_lock:
                                    live_sni_map[(dst_ip, str(dport))] = (inspected_host, now)
                                    live_sni_ip_map[dst_ip] = (inspected_host, now)

                        if inspected_host:
                            is_blk, blk_cat = check_domain_blocked(inspected_host)
                            if is_blk:
                                verdict = NF_DROP
                                if proto_num == 6 and dport not in (53, 5353):
                                    threading.Thread(
                                        target=add_dynamic_block_ip, args=(dst_ip, 3600), daemon=True
                                    ).start()
                                uid_s = str(uid_val) if uid_val >= 0 else ""
                                pinfo = find_correlating_process(
                                    proto_str, src_ip, str(sport), dst_ip, str(dport), uid_s
                                )
                                enqueue_connection(
                                    ts=get_timestamp(),
                                    status="BLOCKED",
                                    proto=proto_str,
                                    src_ip=src_ip,
                                    src_port=str(sport),
                                    dst_ip=dst_ip,
                                    dst_port=str(dport),
                                    proc_info=pinfo,
                                    note=f"Blocked synchronously by SecurePC NFQUEUE DPI ({blk_cat}: {inspected_host})",
                                    category=blk_cat,
                                    is_kernel_block=True,
                                    explicit_domain=inspected_host,
                                    iface=out_ifname,
                                )

                try:
                    # NFQA_VERDICT_HDR = 2 (struct nfqnl_msg_verdict_hdr { __be32 verdict; __be32 id; })
                    vhdr = _nla_pack(2, struct.pack("!II", verdict, pkt_id))
                    nl.send(_nlmsg_pack(NFQNL_MSG_VERDICT, NLM_F_REQUEST, qnum, vhdr, seq=0))
                except Exception:
                    pass

            offset += (nl_len + 3) & ~3

    try:
        nl.close()
    except Exception:
        pass


def attach_dns_sni_bpf(sock: socket.socket):
    """Attach classic BPF filter on cooked IPv4 socket for DNS responses & SNI/HTTP headers."""
    prog_spec = [
        ("start", 0x30, 0, 0, 9),
        ("",      0x15, "udp", "chk_tcp", 17),
        ("udp",   0xB1, 0, 0, 0),
        ("",      0x48, 0, 0, 0),
        ("",      0x15, "pass", 0, 53),
        ("",      0x48, 0, 0, 2),
        ("",      0x15, "pass", "drop", 53),
        ("chk_tcp", 0x15, 0, "drop", 6),
        ("",      0xB1, 0, 0, 0),
        ("",      0x50, 0, 0, 12),
        ("",      0x74, 0, 0, 4),
        ("",      0x64, 0, 0, 2),
        ("",      0x0C, 0, 0, 0),
        ("",      0x07, 0, 0, 0),
        ("",      0x50, 0, 0, 0),
        ("",      0x15, "pass", 0, 0x16),
        ("",      0x15, "pass", 0, 0x47),
        ("",      0x15, "pass", 0, 0x50),
        ("",      0x15, "pass", "drop", 0x43),
        ("pass",  0x06, 0, 0, 1024),
        ("drop",  0x06, 0, 0, 0),
    ]
    labels = {lbl: idx for idx, (lbl, _, _, _, _) in enumerate(prog_spec) if lbl}
    raw_insns = bytearray()
    for idx, (_, code, jt, jf, k) in enumerate(prog_spec):
        jt_num = (labels[jt] - idx - 1) if isinstance(jt, str) else jt
        jf_num = (labels[jf] - idx - 1) if isinstance(jf, str) else jf
        raw_insns.extend(struct.pack("HBBI", code, jt_num, jf_num, k))

    buf = ctypes.create_string_buffer(bytes(raw_insns))

    class SockFprog(ctypes.Structure):
        _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.c_void_p)]

    fprog = SockFprog(len(prog_spec), ctypes.addressof(buf))
    SO_ATTACH_FILTER = 26
    sock.setsockopt(socket.SOL_SOCKET, SO_ATTACH_FILTER, bytes(fprog))


def wire_sni_dns_worker():
    """Passive packet sniffer capturing inbound DNS A/AAAA answers and fallback TLS SNI."""
    if not hasattr(socket, "AF_PACKET"):
        return
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.ntohs(0x0800))
        attach_dns_sni_bpf(sock)
    except Exception as e:
        sys.stderr.write(f"[WARN] Could not start wire SNI/DNS sniffer: {e}\n")
        return

    sock.settimeout(1.0)
    while running:
        try:
            pkt = sock.recv(1024)
        except socket.timeout:
            continue
        except Exception:
            time.sleep(0.2)
            continue

        try:
            proto, src_ip, dst_ip, sport, dport, l4_data = unpack_ip_l4(pkt)
            if not l4_data:
                continue
            if proto == 17 and (sport == 53 or dport == 53):
                parse_dns_packet(l4_data, src_ip, dst_ip, sport, dport, is_tcp=False)
            elif proto == 6 and not cert_inspector.is_active_probe(dst_ip, dport):
                now = time.time()
                if l4_data[0] == 0x16:
                    sni = parse_tls_client_hello_sni(l4_data)
                    if sni:
                        with wire_lock:
                            live_sni_map[(dst_ip, str(dport))] = (sni, now)
                            live_sni_ip_map[dst_ip] = (sni, now)
                else:
                    mh = RE_HTTP_HOST.search(l4_data)
                    if mh:
                        h = mh.group(1).decode("ascii", errors="ignore").lower().strip(".")
                        if "." in h:
                            with wire_lock:
                                live_sni_map[(dst_ip, str(dport))] = (h, now)
                                live_sni_ip_map[dst_ip] = (h, now)
        except Exception:
            pass


def wire_ipv6_dns_worker():
    """Passive IPv6 DNS response sniffer so AAAA answers map IPv6 connections to domains."""
    if not hasattr(socket, "AF_PACKET"):
        return
    try:
        sock6 = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.ntohs(0x86DD))
        sock6.settimeout(1.0)
    except Exception:
        return

    while running:
        try:
            pkt = sock6.recv(1280)
        except socket.timeout:
            continue
        except Exception:
            time.sleep(0.2)
            continue
        try:
            proto, src_ip, dst_ip, sport, dport, l4_data = unpack_ip_l4(pkt)
            if proto == 17 and l4_data and (sport == 53 or dport == 53):
                parse_dns_packet(l4_data, src_ip, dst_ip, sport, dport, is_tcp=False)
        except Exception:
            pass


# ------------------------------------------------------------------------------
# Process Correlation, Isolated ftrace Instance, ss Poller & Netfilter Log Worker
# ------------------------------------------------------------------------------
def cache_proc_event(proto: str, src_ip: str, src_port: str, dst_ip: str, dst_port: str, proc_info: dict):
    if dst_ip.startswith("127.") or src_ip.startswith("127.") or dst_ip == "::1":
        return
    if is_kernel_or_irq_comm(proc_info.get("comm", "")):
        return
    now = time.time()
    entry = {"time": now, "info": proc_info}
    proc_correlation_cache[(proto, dst_ip, str(dst_port))] = entry
    proc_correlation_cache[(dst_ip, str(dst_port))] = entry
    proc_correlation_cache[("DST", dst_ip)] = entry
    if str(src_port) != "0":
        proc_correlation_cache[("SPORT", str(src_port))] = entry
    if proc_info.get("uid", -1) >= 0:
        proc_correlation_cache[("UID", str(proc_info["uid"]))] = entry
    recent_pid_cache.append((now, dst_ip, str(dst_port), proc_info))


def enrich_with_uid(pinfo: dict, uid_str: str) -> dict:
    pinfo = dict(pinfo)
    if uid_str and uid_str.isdigit():
        uid_int = int(uid_str)
        if pinfo.get("uid", -1) < 0 or pinfo.get("user") in ("unknown", ""):
            pinfo["uid"] = uid_int
            pinfo["user"] = get_uid_name(uid_int)
        if pinfo.get("service") in ("unknown", ""):
            pinfo["service"] = f"user-{uid_int}.slice"
    return pinfo


def find_correlating_process(proto: str, src_ip: str, src_port: str, dst_ip: str, dst_port: str, uid_str: str) -> dict:
    for key in [
        ("SPORT", str(src_port)),
        (proto, dst_ip, str(dst_port)),
        (dst_ip, str(dst_port)),
        ("DST", dst_ip),
    ]:
        entry = proc_correlation_cache.get(key)
        if entry and time.time() - entry["time"] < 15.0:
            pinfo = entry["info"]
            if pinfo.get("exe", "").startswith("/proc/") or pinfo.get("comm") == "<...>":
                orig_pid = pinfo.get("pid", 0)
                parent_id = parent_tid_map.get(orig_pid) or pinfo.get("ppid", 0)
                parent_meta = pid_metadata_cache.get(parent_id) if parent_id else None
                if parent_meta:
                    pinfo = dict(parent_meta)
                    if orig_pid > 0:
                        pinfo["pid"] = orig_pid
                        pinfo["ppid"] = parent_id
            return enrich_with_uid(pinfo, uid_str)

    now = time.time()
    for t_ev, d_ip, d_port, pinfo in reversed(recent_pid_cache):
        if now - t_ev > 8.0:
            break
        if pinfo.get("comm") not in ("sshd", "rsyslogd", "systemd-journal", "<...>") and not is_kernel_or_irq_comm(pinfo.get("comm", "")):
            if d_ip == dst_ip or (d_ip == "EXEC" and uid_str and uid_str.isdigit() and pinfo.get("uid", -2) == int(uid_str)):
                return enrich_with_uid(pinfo, uid_str)

    # On-demand live socket inspection for brand-new sockets before ss_poller_worker ticks
    if str(src_port).isdigit() and int(src_port) > 0:
        try:
            res = subprocess.run(
                ["ss", "-H", "-tupna", f"sport = :{src_port}"],
                capture_output=True,
                text=True,
                timeout=0.4,
            )
            mu = re.search(r'\("([^"]+)",pid=(\d+),fd=\d+\)', res.stdout)
            if mu:
                comm_s, pid_s = mu.groups()
                if not is_kernel_or_irq_comm(comm_s):
                    pinfo = inspect_pid(int(pid_s), comm_s)
                    cache_proc_event(proto, src_ip, str(src_port), dst_ip, str(dst_port), pinfo)
                    return enrich_with_uid(pinfo, uid_str)
        except Exception:
            pass

    if not uid_str or not uid_str.isdigit():
        return {
            "pid": 0,
            "ppid": 0,
            "comm": "kernel-tcp",
            "exe": "kernel-netstack",
            "cmdline": f"Kernel packet to {dst_ip}:{dst_port} ({proto})",
            "service": "kernel.net",
            "uid": 0,
            "user": "root",
        }

    uid_int = int(uid_str)
    uname = get_uid_name(uid_int)
    return {
        "pid": 0,
        "ppid": 0,
        "comm": f"uid-{uname}",
        "exe": f"UID:{uid_int} ({uname})",
        "cmdline": f"Outbound packet to {dst_ip}:{dst_port} ({proto})",
        "service": f"user-{uid_int}.slice" if uid_int >= 0 else "system.slice",
        "uid": uid_int,
        "user": uname,
    }


def setup_tracepoints() -> str:
    """Create a dedicated, isolated ftrace instance so SecurePC never collides with global trace_pipe."""
    if not os.path.exists("/sys/kernel/tracing/instances"):
        return ""
    try:
        os.makedirs(FTRACE_INSTANCE_DIR, exist_ok=True)
        buf_kb = os.path.join(FTRACE_INSTANCE_DIR, "buffer_size_kb")
        if os.path.exists(buf_kb):
            with open(buf_kb, "w", encoding="utf-8") as f:
                f.write("2048\n")

        fib_filter = os.path.join(FTRACE_INSTANCE_DIR, "events/fib/fib_table_lookup/filter")
        fib_enable = os.path.join(FTRACE_INSTANCE_DIR, "events/fib/fib_table_lookup/enable")
        sock_enable = os.path.join(FTRACE_INSTANCE_DIR, "events/sock/inet_sock_set_state/enable")
        exec_enable = os.path.join(FTRACE_INSTANCE_DIR, "events/sched/sched_process_exec/enable")
        fork_enable = os.path.join(FTRACE_INSTANCE_DIR, "events/sched/sched_process_fork/enable")

        with open(fib_enable, "w", encoding="utf-8") as f:
            f.write("0\n")
        with open(fib_filter, "w", encoding="utf-8") as f:
            f.write("iif == 0\n")
        with open(fib_enable, "w", encoding="utf-8") as f:
            f.write("1\n")
        with open(sock_enable, "w", encoding="utf-8") as f:
            f.write("1\n")
        with open(exec_enable, "w", encoding="utf-8") as f:
            f.write("1\n")
        with open(fork_enable, "w", encoding="utf-8") as f:
            f.write("1\n")
        return os.path.join(FTRACE_INSTANCE_DIR, "trace_pipe")
    except Exception as e:
        sys.stderr.write(f"[WARN] Could not enable isolated ftrace instance: {e}\n")
        return ""


def cleanup_tracepoints():
    if not os.path.isdir(FTRACE_INSTANCE_DIR):
        return
    for rel in (
        "events/fib/fib_table_lookup/enable",
        "events/sock/inet_sock_set_state/enable",
        "events/sched/sched_process_exec/enable",
        "events/sched/sched_process_fork/enable",
    ):
        p = os.path.join(FTRACE_INSTANCE_DIR, rel)
        try:
            if os.path.exists(p):
                with open(p, "w", encoding="utf-8") as f:
                    f.write("0\n")
        except Exception:
            pass
    try:
        os.rmdir(FTRACE_INSTANCE_DIR)
    except Exception:
        pass


def trace_pipe_worker():
    trace_pipe_path = setup_tracepoints()
    if not trace_pipe_path:
        return

    re_prefix = re.compile(r"^\s*(.+?)-(\d+)\s+\[\d+\]\s+\S+\s+\S+:\s+(\w+):\s+(.*)$")
    re_sock = re.compile(
        r"family=(\S+)\s+protocol=(\S+)\s+sport=(\d+)\s+dport=(\d+)\s+saddr=(\S+)\s+daddr=(\S+).*oldstate=(\S+)\s+newstate=(\S+)"
    )
    re_fib = re.compile(
        r"table\s+\d+\s+oif\s+\d+\s+iif\s+0\s+proto\s+(\d+)\s+([0-9.]+)/(\d+)\s+->\s+([0-9.]+)/(\d+)"
    )
    re_exec = re.compile(r"filename=(\S+)\s+pid=(\d+)\s+old_pid=(\d+)")
    re_fork = re.compile(r"comm=(.+?)\s+pid=(\d+)\s+child_comm=(.+?)\s+child_pid=(\d+)")

    while running:
        try:
            with open(trace_pipe_path, "r", encoding="utf-8", errors="replace") as tp:
                for line in tp:
                    if not running:
                        break
                    m = re_prefix.match(line)
                    if not m:
                        continue
                    comm, pid_s, event_name, rest = m.groups()
                    pid = int(pid_s)
                    if pid == MY_PID or cert_inspector.is_probe_pid(pid):
                        continue

                    if event_name == "sched_process_exec":
                        me = re_exec.search(rest)
                        if me:
                            fname, new_pid_s, _ = me.groups()
                            new_pid = int(new_pid_s)
                            if parent_tid_map.get(new_pid) == MY_PID:
                                continue
                            pinfo = inspect_pid(new_pid, os.path.basename(fname), force_refresh=True)
                            if pinfo["exe"] in ("unknown", "") or pinfo["exe"].startswith("/proc/") or not os.path.exists(f"/proc/{new_pid}"):
                                pinfo = dict(pinfo)
                                pinfo["exe"] = fname
                                pinfo["comm"] = os.path.basename(fname)
                                pinfo["pid"] = new_pid
                                p_parent = parent_tid_map.get(new_pid)
                                if p_parent and not pinfo.get("ppid"):
                                    pinfo["ppid"] = p_parent
                            pid_metadata_cache[new_pid] = pinfo
                            recent_pid_cache.append((time.time(), "EXEC", "0", pinfo))

                    elif event_name == "sched_process_fork":
                        mfk = re_fork.search(rest)
                        if mfk:
                            p_comm, p_pid_s, c_comm, c_pid_s = mfk.groups()
                            p_pid, c_pid = int(p_pid_s), int(c_pid_s)
                            parent_tid_map[c_pid] = p_pid
                            if p_pid == MY_PID:
                                continue
                            p_meta = pid_metadata_cache.get(p_pid)
                            if p_meta:
                                inherited = dict(p_meta)
                                inherited["pid"] = c_pid
                                inherited["ppid"] = p_pid
                                pid_metadata_cache[c_pid] = inherited
                            elif not is_kernel_or_irq_comm(p_comm):
                                pinfo = inspect_pid(p_pid, p_comm)
                                pid_metadata_cache[p_pid] = pinfo
                                c_info = dict(pinfo)
                                c_info["pid"] = c_pid
                                c_info["ppid"] = p_pid
                                pid_metadata_cache[c_pid] = c_info

                    elif event_name == "inet_sock_set_state":
                        ms = re_sock.search(rest)
                        if not ms:
                            continue
                        fam, proto_s, sport, dport, saddr, daddr, oldst, newst = ms.groups()
                        if newst not in ("TCP_SYN_SENT", "TCP_ESTABLISHED", "TCP_LISTEN"):
                            continue
                        if cert_inspector.is_active_probe(daddr, dport):
                            continue
                        proto = "TCP" if "TCP" in proto_s else proto_s
                        if is_kernel_or_irq_comm(comm):
                            cached_entry = (
                                proc_correlation_cache.get(("SPORT", str(sport)))
                                or proc_correlation_cache.get((proto, daddr, str(dport)))
                                or proc_correlation_cache.get(("DST", daddr))
                            )
                            if cached_entry:
                                pinfo = cached_entry["info"]
                            else:
                                continue
                        else:
                            pinfo = inspect_pid(pid, comm)
                            if pinfo.get("service") == "unknown" and pinfo.get("exe") == comm:
                                continue
                            cache_proc_event(proto, saddr, sport, daddr, dport, pinfo)

                        enqueue_connection(
                            ts=get_timestamp(),
                            status="ALLOWED" if newst != "TCP_SYN_SENT" else "OUTBOUND",
                            proto=proto,
                            src_ip=saddr,
                            src_port=sport,
                            dst_ip=daddr,
                            dst_port=dport,
                            proc_info=pinfo,
                            note=f"state={oldst}->{newst}",
                        )

                    elif event_name == "fib_table_lookup":
                        mf = re_fib.search(rest)
                        if not mf or is_kernel_or_irq_comm(comm):
                            continue
                        proto_num, saddr, sport, daddr, dport = mf.groups()
                        if daddr.startswith("127.") or daddr == "0.0.0.0" or cert_inspector.is_active_probe(daddr, dport):
                            continue
                        proto = PROTO_MAP.get(proto_num, f"PROTO-{proto_num}")
                        pinfo = inspect_pid(pid, comm)
                        if pinfo.get("service") == "unknown" and pinfo.get("exe") == comm:
                            continue
                        cache_proc_event(proto, saddr, sport, daddr, dport, pinfo)
                        if proto in ("UDP", "ICMP") or sport != "0" or dport != "0":
                            enqueue_connection(
                                ts=get_timestamp(),
                                status="OUTBOUND",
                                proto=proto,
                                src_ip=saddr,
                                src_port=sport,
                                dst_ip=daddr,
                                dst_port=dport,
                                proc_info=pinfo,
                                note="route-lookup",
                            )
        except Exception:
            time.sleep(1)


def split_ss_host_port(ap: str) -> tuple[str, str]:
    if ap.startswith("["):
        h, p = ap.rsplit(":", 1)
        return h.strip("[]").split("%")[0], p
    if ":" in ap:
        h, p = ap.rsplit(":", 1)
        if h.startswith("::ffff:") and "." in h:
            h = h[7:]
        return h.split("%")[0], p
    return ap, "0"


def ss_poller_worker():
    re_users = re.compile(r'\("([^"]+)",pid=(\d+),fd=\d+\)')
    while running:
        try:
            res = subprocess.run(["ss", "-tupna"], capture_output=True, text=True, timeout=4)
            for line in res.stdout.splitlines()[1:]:
                parts = line.split()
                if len(parts) < 6:
                    continue
                proto = parts[0].upper()
                state = parts[1]
                if state not in ("ESTAB", "SYN-SENT", "UNCONN"):
                    continue
                local_addr = parts[4]
                peer_addr = parts[5]
                if peer_addr in ("0.0.0.0:*", "[::]:*", "*:*"):
                    continue

                s_ip, s_port = split_ss_host_port(local_addr)
                d_ip, d_port = split_ss_host_port(peer_addr)
                if d_ip.startswith("127.") or d_ip == "::1" or cert_inspector.is_active_probe(d_ip, d_port):
                    continue

                mu = re_users.search(line)
                if mu:
                    comm, pid_s = mu.groups()
                    pid_i = int(pid_s)
                    if pid_i == MY_PID or cert_inspector.is_probe_pid(pid_i) or is_kernel_or_irq_comm(comm):
                        continue
                    pinfo = inspect_pid(pid_i, comm)
                    cache_proc_event(proto, s_ip, s_port, d_ip, d_port, pinfo)
                    enqueue_connection(
                        ts=get_timestamp(),
                        status="ALLOWED" if state == "ESTAB" else "OUTBOUND",
                        proto=proto,
                        src_ip=s_ip,
                        src_port=s_port,
                        dst_ip=d_ip,
                        dst_port=d_port,
                        proc_info=pinfo,
                        note=f"socket-{state}",
                    )
        except Exception:
            pass
        time.sleep(3)


def kernel_block_log_worker():
    """Follow kernel logs for [SECUREPC-BLK:*] and [SECUREPC-OUT:*] events."""
    re_sec = re.compile(r"\[SECUREPC-(BLK|OUT):([A-Z0-9_-]+)\]\s+(.*)")
    re_kv = re.compile(r"(\w+)=([^\s]+)")

    try:
        proc = subprocess.Popen(
            ["dmesg", "--follow", "--level=warn,notice,info"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            bufsize=1,
        )
    except Exception:
        return

    startup_cutoff = time.time() + 0.4

    for line in proc.stdout:
        if not running:
            break
        if time.time() < startup_cutoff:
            continue
        m = re_sec.search(line)
        if not m:
            continue
        kind, category, kv_str = m.groups()
        kvs = dict(re_kv.findall(kv_str))
        src_ip = kvs.get("SRC", "0.0.0.0")
        dst_ip = kvs.get("DST", "0.0.0.0")
        proto = kvs.get("PROTO", "IP")
        spt = kvs.get("SPT", "0")
        dpt = kvs.get("DPT", "0")
        uid_s = kvs.get("UID", "")
        out_if = kvs.get("OUT", "")
        in_if = kvs.get("IN", "")

        if kind == "OUT" and cert_inspector.is_active_probe(dst_ip, dpt):
            continue

        pinfo = find_correlating_process(proto, src_ip, spt, dst_ip, dpt, uid_s)
        if kind == "OUT" and is_self_or_probe_process(pinfo.get("pid", 0), pinfo, dst_ip, dpt):
            continue

        ts = get_timestamp()
        if kind == "BLK":
            enqueue_connection(
                ts=ts,
                status="BLOCKED",
                proto=proto,
                src_ip=src_ip,
                src_port=spt,
                dst_ip=dst_ip,
                dst_port=dpt,
                proc_info=pinfo,
                note=f"Blocked by SecurePC kernel firewall ({category})",
                category=category,
                is_kernel_block=True,
                iface=out_if or in_if,
            )
        else:
            enqueue_connection(
                ts=ts,
                status="OUTBOUND",
                proto=proto,
                src_ip=src_ip,
                src_port=spt,
                dst_ip=dst_ip,
                dst_port=dpt,
                proc_info=pinfo,
                note=f"netfilter-outbound ({out_if or 'net'})",
                category=category,
            )


def seed_initial_outbound_summary():
    re_users = re.compile(r'\("([^"]+)",pid=(\d+),fd=\d+\)')
    try:
        res = subprocess.run(["ss", "-tupna"], capture_output=True, text=True, timeout=4)
        for line in res.stdout.splitlines()[1:]:
            parts = line.split()
            if len(parts) < 6:
                continue
            proto = parts[0].upper()
            state = parts[1]
            if state not in ("ESTAB", "SYN-SENT"):
                continue
            local_addr = parts[4]
            peer_addr = parts[5]
            if peer_addr in ("0.0.0.0:*", "[::]:*", "*:*") or ":" not in peer_addr:
                continue
            s_ip, s_port = split_ss_host_port(local_addr)
            d_ip, d_port = split_ss_host_port(peer_addr)
            if not is_public_internet_ip(d_ip):
                continue
            mu = re_users.search(line)
            if mu:
                comm, pid_s = mu.groups()
                if is_kernel_or_irq_comm(comm):
                    continue
                pinfo = inspect_pid(int(pid_s), comm)
            else:
                pinfo = inspect_pid(0, "system-socket")
            enqueue_connection(
                ts=get_timestamp(),
                status="ALLOWED",
                proto=proto,
                src_ip=s_ip,
                src_port=s_port,
                dst_ip=d_ip,
                dst_port=d_port,
                proc_info=pinfo,
                note=f"active-{state}",
            )
    except Exception:
        pass


def handle_shutdown(signum, frame):
    global running
    running = False
    cleanup_tracepoints()
    cert_inspector.save_cache()
    sys.exit(0)


def handle_reload(signum, frame):
    """Hot-reload GeoIP tables and domain policy lists on SIGHUP."""
    try:
        load_daemon_policy_config()
        geo_db.load()
        load_cidr_and_domain_seeds()
    except Exception:
        pass


def main():
    if any(a in ("--banner", "--version", "-V", "-h", "--help") for a in sys.argv[1:]):
        print_securepc_intro_banner()
        sys.exit(0)

    os.makedirs(LOG_DIR_VAR, mode=0o750, exist_ok=True)

    signal.signal(signal.SIGTERM, handle_shutdown)
    signal.signal(signal.SIGINT, handle_shutdown)
    signal.signal(signal.SIGHUP, handle_reload)

    load_daemon_policy_config()
    load_cidr_and_domain_seeds()

    filenames = [
        "connections.log",
        "connections.jsonl",
        "outbound-internet.log",
        "outbound-internet.jsonl",
        "outbound-summary.txt",
        "non-us-traffic.log",
        "non-us-traffic.jsonl",
        "non-us-summary.txt",
        "unread-non-us.log",
        "blocked-alerts.log",
        "unread-alerts.log",
    ]
    for fname in filenames:
        p = os.path.join(LOG_DIR_VAR, fname)
        if not os.path.exists(p):
            open(p, "a", encoding="utf-8").close()
        try:
            os.chmod(p, 0o640)
            os.chown(p, 0, LOG_GID)
        except Exception:
            pass

    flush_outbound_summary()
    flush_non_us_summary()

    for _ in range(4):
        threading.Thread(target=enrichment_worker, daemon=True).start()

    # Bind NFQUEUE 5353 immediately before seeding active socket summaries
    threading.Thread(target=nfqueue_dpi_worker, daemon=True).start()
    threading.Thread(target=wire_sni_dns_worker, daemon=True).start()
    threading.Thread(target=wire_ipv6_dns_worker, daemon=True).start()

    seed_initial_outbound_summary()

    threading.Thread(target=trace_pipe_worker, daemon=True).start()
    threading.Thread(target=ss_poller_worker, daemon=True).start()
    threading.Thread(target=kernel_block_log_worker, daemon=True).start()

    while running:
        time.sleep(1)


if __name__ == "__main__":
    main()

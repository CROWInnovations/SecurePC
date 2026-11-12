#!/usr/bin/env python3
"""
SecurePC — Worldwide RIR GeoIP Country Engine & OpenSSL X.509 Certificate Inspector
Author:  CROW Innovations (https://crowinnovations.com)
License: GNU General Public License v3.0 (GPL-3.0)
GitHub:  https://github.com/CROWInnovations/SecurePC

Identifies:
  1. Exact RIR-allocated Country & CIDR for any IPv4 or IPv6 address (O(log N) binary search).
  2. Remote site domain names, SANs, Organization, and Subject Country directly by IP
     using `openssl s_client` + `openssl x509`.
  3. Non-US traffic detection across IP GeoIP, domain ccTLDs (including IDN punycode),
     and X.509 certificate Subject Country (`C=`), distinguishing:
       - BLOCKED regions: China (.cn / Beijing / aliyuncs), Russia (.ru / .su / .рф),
         Iran (.ir / .ایران), and all Middle East countries (AE, BH, CY, EG, IL, IQ,
         JO, KW, LB, OM, PS, QA, SA, SY, TR, YE).
       - FLAGGED Non-US countries: All other countries outside the United States.
       - ALLOWED US traffic: United States IPs with US/gTLD domains & certs.
"""

import bisect
import ipaddress
import json
import os
import re
import subprocess
import sys
import threading
import time
from typing import Optional

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VAR_LIB_DIR = "/var/lib/securepc"
LOG_DIR_VAR = "/var/log/securepc"
LISTS_DIR = (
    os.path.join(VAR_LIB_DIR, "lists")
    if os.path.isdir(os.path.join(VAR_LIB_DIR, "lists"))
    else os.path.join(BASE_DIR, "lists")
)


def print_securepc_intro_banner() -> None:
    """Print the official CROW Innovations SecurePC CLI Intro Banner."""
    no_color = bool(os.environ.get("NO_COLOR"))
    c_border = "" if no_color else "\033[1;36m"
    c_title = "" if no_color else "\033[1;37m"
    c_label = "" if no_color else "\033[1;33m"
    c_val = "" if no_color else "\033[0;37m"
    c_link = "" if no_color else "\033[1;36m"
    c_rst = "" if no_color else "\033[0m"

    print(f"{c_border}╔{'═' * 96}╗{c_rst}")
    print(f"{c_border}║{c_rst}{'':96s}{c_border}║{c_rst}")
    print(f"{c_border}║{c_rst}{'':44s}{c_title}SecurePC{c_rst}{'':44s}{c_border}║{c_rst}")
    print(f"{c_border}║{c_rst}{'':96s}{c_border}║{c_rst}")
    print(f"{c_border}║{c_rst}   {c_label}Author:{c_rst}   {c_val}CROW Innovations{c_rst}{'':67s}{c_border}║{c_rst}")
    print(f"{c_border}║{c_rst}   {c_label}Website:{c_rst}  {c_link}https://crowinnovations.com{c_rst}{'':56s}{c_border}║{c_rst}")
    print(f"{c_border}║{c_rst}{'':96s}{c_border}║{c_rst}")
    print(
        f"{c_border}║{c_rst}   {c_label}License:{c_rst}  {c_val}GNU GPL v3.0 (GPL-3.0){c_rst}"
        f"       {c_label}GitHub:{c_rst}  {c_link}https://github.com/CROWInnovations/SecurePC{c_rst}  {c_border}║{c_rst}"
    )
    print(f"{c_border}║{c_rst}{'':96s}{c_border}║{c_rst}")
    print(f"{c_border}╚{'═' * 96}╝{c_rst}")


CERT_CACHE_PATHS = [
    os.path.join(LOG_DIR_VAR, "openssl-cert-cache.json"),
    os.path.join(VAR_LIB_DIR, "openssl-cert-cache.json"),
]

# Hard-blocked country code sets per SecurePC security policy
BLOCKED_CHINA_CODES = {"CN"}
BLOCKED_RUSSIA_CODES = {"RU", "SU"}
BLOCKED_IRAN_CODES = {"IR"}
BLOCKED_MIDDLE_EAST_CODES = {
    "AE",  # United Arab Emirates
    "BH",  # Bahrain
    "CY",  # Cyprus
    "EG",  # Egypt
    "IL",  # Israel
    "IQ",  # Iraq
    "JO",  # Jordan
    "KW",  # Kuwait
    "LB",  # Lebanon
    "OM",  # Oman
    "PS",  # Palestine
    "QA",  # Qatar
    "SA",  # Saudi Arabia
    "SY",  # Syria
    "TR",  # Turkey
    "YE",  # Yemen
}

ALL_BLOCKED_COUNTRY_CODES = (
    BLOCKED_CHINA_CODES
    | BLOCKED_RUSSIA_CODES
    | BLOCKED_IRAN_CODES
    | BLOCKED_MIDDLE_EAST_CODES
)

# Comprehensive ISO-3166-1 alpha-2 country names
COUNTRY_NAMES = {
    "US": "United States",
    "CA": "Canada",
    "MX": "Mexico",
    "GB": "United Kingdom",
    "UK": "United Kingdom",
    "IE": "Ireland",
    "DE": "Germany",
    "FR": "France",
    "NL": "Netherlands",
    "BE": "Belgium",
    "LU": "Luxembourg",
    "CH": "Switzerland",
    "AT": "Austria",
    "IT": "Italy",
    "ES": "Spain",
    "PT": "Portugal",
    "SE": "Sweden",
    "NO": "Norway",
    "DK": "Denmark",
    "FI": "Finland",
    "IS": "Iceland",
    "PL": "Poland",
    "CZ": "Czechia",
    "SK": "Slovakia",
    "HU": "Hungary",
    "RO": "Romania",
    "BG": "Bulgaria",
    "GR": "Greece",
    "HR": "Croatia",
    "SI": "Slovenia",
    "EE": "Estonia",
    "LV": "Latvia",
    "LT": "Lithuania",
    "MT": "Malta",
    "UA": "Ukraine",
    "BY": "Belarus",
    "MD": "Moldova",
    "RS": "Serbia",
    "BA": "Bosnia and Herzegovina",
    "ME": "Montenegro",
    "MK": "North Macedonia",
    "AL": "Albania",
    "XK": "Kosovo",
    "EU": "European Union",
    "RU": "Russia",
    "SU": "Soviet Union (RU)",
    "CN": "China",
    "HK": "Hong Kong",
    "MO": "Macau",
    "TW": "Taiwan",
    "JP": "Japan",
    "KR": "South Korea",
    "KP": "North Korea",
    "MN": "Mongolia",
    "SG": "Singapore",
    "MY": "Malaysia",
    "TH": "Thailand",
    "VN": "Vietnam",
    "ID": "Indonesia",
    "PH": "Philippines",
    "KH": "Cambodia",
    "LA": "Laos",
    "MM": "Myanmar",
    "BN": "Brunei",
    "IN": "India",
    "PK": "Pakistan",
    "BD": "Bangladesh",
    "LK": "Sri Lanka",
    "NP": "Nepal",
    "KZ": "Kazakhstan",
    "UZ": "Uzbekistan",
    "TM": "Turkmenistan",
    "KG": "Kyrgyzstan",
    "TJ": "Tajikistan",
    "AF": "Afghanistan",
    "AZ": "Azerbaijan",
    "AM": "Armenia",
    "GE": "Georgia",
    # Iran & Middle East
    "IR": "Iran",
    "AE": "United Arab Emirates",
    "BH": "Bahrain",
    "CY": "Cyprus",
    "EG": "Egypt",
    "IL": "Israel",
    "IQ": "Iraq",
    "JO": "Jordan",
    "KW": "Kuwait",
    "LB": "Lebanon",
    "OM": "Oman",
    "PS": "Palestine",
    "QA": "Qatar",
    "SA": "Saudi Arabia",
    "SY": "Syria",
    "TR": "Turkey",
    "YE": "Yemen",
    # Oceania
    "AU": "Australia",
    "NZ": "New Zealand",
    # Americas
    "BR": "Brazil",
    "AR": "Argentina",
    "CL": "Chile",
    "CO": "Colombia",
    "PE": "Peru",
    "VE": "Venezuela",
    "UY": "Uruguay",
    "PY": "Paraguay",
    "BO": "Bolivia",
    "EC": "Ecuador",
    "CR": "Costa Rica",
    "PA": "Panama",
    "GT": "Guatemala",
    "DO": "Dominican Republic",
    "PR": "Puerto Rico (US)",
    "VI": "U.S. Virgin Islands (US)",
    "GU": "Guam (US)",
    "AS": "American Samoa (US)",
    "MP": "Northern Mariana Islands (US)",
    # Africa
    "ZA": "South Africa",
    "NG": "Nigeria",
    "KE": "Kenya",
    "GH": "Ghana",
    "TZ": "Tanzania",
    "UG": "Uganda",
    "ET": "Ethiopia",
    "MA": "Morocco",
    "DZ": "Algeria",
    "TN": "Tunisia",
    "LY": "Libya",
    "SD": "Sudan",
    "MU": "Mauritius",
    "SC": "Seychelles",
    "SN": "Senegal",
    "CI": "Cote d'Ivoire",
    "CM": "Cameroon",
    "AO": "Angola",
    "MZ": "Mozambique",
    "ZW": "Zimbabwe",
    "ZM": "Zambia",
    "BW": "Botswana",
    "NA": "Namibia",
    "RW": "Rwanda",
}

# US territories treated as United States jurisdiction
US_JURISDICTION_CODES = {"US", "PR", "VI", "GU", "AS", "MP"}

# Repurposed commercial/tech ccTLDs that do NOT by themselves indicate a foreign country
# (Country attribution for these relies on IP GeoIP and X.509 Certificate Subject C=)
COMMERCIAL_TECH_TLDS = {
    "io", "ai", "co", "me", "tv", "gg", "sh", "vc", "fm", "cc", "ws", "to",
}

KNOWN_DOH_DOMAINS = {
    "dns.google",
    "dns.google.com",
    "8888.google",
    "cloudflare-dns.com",
    "one.one.one.one",
    "1dot1dot1dot1.cloudflare-dns.com",
    "mozilla.cloudflare-dns.com",
    "dns.quad9.net",
    "dns9.quad9.net",
    "dns10.quad9.net",
    "dns11.quad9.net",
    "doh.opendns.com",
    "doh.umbrella.com",
    "dns.nextdns.io",
    "dns.adguard-dns.com",
    "dns.adguard.com",
    "doh.mullvad.net",
    "adblock.dns.mullvad.net",
    "freedns.controld.com",
    "doh.cleanbrowsing.org",
    "dns.twnic.tw",
}

US_AND_GENERIC_TLDS = {
    "us", "gov", "mil", "edu", "com", "net", "org", "int", "arpa",
    "info", "biz", "name", "pro", "xyz", "online", "site", "tech", "store",
    "app", "dev", "cloud", "page", "goog", "google", "gle", "youtube",
    "local", "lan", "internal", "localhost", "invalid", "test", "example",
}

# IDN Punycode ccTLD -> ISO country code
IDN_CCTLD_MAP = {
    "xn--fiqs8s": "CN",       # .中国 (China)
    "xn--fiqz9s": "CN",       # .中國 (China)
    "xn--p1ai": "RU",         # .рф (Russia)
    "xn--d1acj3b": "RU",      # .дети (Russia)
    "xn--80adxhks": "RU",     # .москва (Moscow, Russia)
    "xn--mgba3a4f16a": "IR",  # .ایران (Iran)
    "xn--mgbaam7a8h": "AE",   # .امارات (UAE)
    "xn--mgberp4a5d4ar": "SA",# .السعودية (Saudi Arabia)
    "xn--wgbh1c": "EG",       # .مصر (Egypt)
    "xn--4dbrk0ce": "IL",     # .ישראל (Israel)
    "xn--mgbtx2b": "IQ",      # .عراق (Iraq)
    "xn--mgbayh7gpa": "JO",   # .الاردن (Jordan)
    "xn--mgb9awbf": "OM",     # .عمان (Oman)
    "xn--ygbi2ammx": "PS",    # .فلسطين (Palestine)
    "xn--wgbl6a": "QA",       # .قطر (Qatar)
    "xn--ogbpf8fl": "SY",     # .سورية (Syria)
    "xn--mgbcpq6gpa1a": "BH", # .البحرين (Bahrain)
    "xn--j6w193g": "HK",      # .香港 (Hong Kong)
    "xn--kprw13d": "TW",      # .台湾 (Taiwan)
    "xn--kpry57d": "TW",      # .台灣 (Taiwan)
    "xn--3e0b707e": "KR",     # .한국 (South Korea)
    "xn--q9jyb4c": "JP",      # .みんな
    "xn--90ais": "BY",        # .бел (Belarus)
    "xn--j1amh": "UA",        # .укр (Ukraine)
    "xn--80ao21a": "KZ",      # .қаз (Kazakhstan)
}

DUMMY_CERT_NAMES = {
    "invalid2.invalid",
    "invalid",
    "localhost",
    "localhost.localdomain",
    "default",
    "example.com",
    "www.example.com",
    "traefik default cert",
    "ingress.local",
    "kubernetes ingress controller fake certificate",
}

TLS_COMMON_PORTS = {443, 8443, 853, 993, 995, 465, 636, 5443, 8543, 8643, 9443, 11443}


def get_country_name(cc: str) -> str:
    if not cc:
        return "Unknown"
    cc_u = cc.upper()
    return COUNTRY_NAMES.get(cc_u, f"Country-{cc_u}")


def get_block_category_for_country(cc: str, is_domain: bool = False) -> str:
    cc_u = (cc or "").upper()
    suffix = "DOM" if is_domain else "IP"
    if cc_u in BLOCKED_CHINA_CODES:
        return f"CN-{suffix}"
    if cc_u in BLOCKED_RUSSIA_CODES:
        return f"RU-{suffix}"
    if cc_u in BLOCKED_IRAN_CODES:
        return f"IR-{suffix}"
    if cc_u in BLOCKED_MIDDLE_EAST_CODES:
        return f"ME-{suffix}"
    return ""


def clean_hostname_token(raw: str) -> str:
    """Extract clean DNS hostname from an annotated domain string like 'foo.de (via 8.8.8.8)'."""
    if not raw:
        return ""
    s = raw.strip().lower()
    # Strip annotations like " (google.com)" or " [cert:...]"
    s = s.split()[0].strip(".,;:\"'[]()")
    if s.startswith("*."):
        s = s[2:]
    return s


def extract_domain_country(domain: str) -> str:
    """
    If `domain` uses a geographic country-code TLD (ccTLD) or IDN country TLD,
    return its ISO-3166 country code (e.g. 'DE', 'GB', 'CN', 'RU', 'IR', 'AE').
    Returns 'US' for .us/.gov/.mil/.edu, or '' for generic gTLDs (.com, .net, .org, .io, .ai, etc.).
    """
    host = clean_hostname_token(domain)
    if not host or "." not in host:
        return ""
    # Ignore IPv4 literals and reverse-DNS arpa
    if host.endswith(".arpa"):
        return ""
    try:
        ipaddress.ip_address(host)
        return ""
    except ValueError:
        pass

    # Explicit China/Alibaba domain matches
    if host.endswith((".aliyuncs.com", ".aliyun.com", ".alidns.com")) or host in ("aliyuncs.com", "aliyun.com", "alidns.com"):
        return "CN"

    tld = host.rsplit(".", 1)[-1].lower()
    if tld in IDN_CCTLD_MAP:
        return IDN_CCTLD_MAP[tld]
    if tld in ("us", "gov", "mil"):
        return "US"
    if tld in US_AND_GENERIC_TLDS or tld in COMMERCIAL_TECH_TLDS:
        return ""
    if tld == "uk":
        return "GB"
    if tld == "su":
        return "RU"
    if tld == "eu":
        return "EU"
    if len(tld) == 2 and tld.isalpha():
        return tld.upper()
    return ""


def match_blocked_domain_policy(
    raw_domain: str,
    custom_blocked_suffixes: Optional[set[str]] = None,
    block_doh_hosts: bool = False,
) -> tuple[bool, str]:
    """
    Authoritative domain-level blocking check for DNS QNAMEs, TLS ClientHello SNI,
    and HTTP Host headers. Returns (is_blocked, category_tag).
    """
    host = clean_hostname_token(raw_domain)
    if not host or "." not in host:
        return False, ""

    if block_doh_hosts:
        for doh_d in KNOWN_DOH_DOMAINS:
            if host == doh_d or host.endswith("." + doh_d):
                return True, "DOH-BYPASS"

    if host in ("aliyuncs.com", "aliyun.com", "alidns.com") or host.endswith(
        (".aliyuncs.com", ".aliyun.com", ".alidns.com")
    ):
        return True, "ALIYUNCS"

    # Match explicit Beijing cloud/network subdomain labels without mid-body false positives
    labels = host.split(".")
    if any("beijing" in lbl for lbl in labels):
        return True, "BEIJING"

    dcc = extract_domain_country(host)
    if dcc in ALL_BLOCKED_COUNTRY_CODES:
        return True, get_block_category_for_country(dcc, is_domain=True)

    if custom_blocked_suffixes:
        for suf in custom_blocked_suffixes:
            if host == suf or host.endswith("." + suf):
                return True, "CUSTOM-DOM"

    return False, ""


def is_generic_ptr_or_placeholder(domain: str) -> bool:
    if not domain:
        return True
    d = domain.lower().strip()
    if d in (
        "unresolved-public-ip",
        "local-network",
        "localhost",
        "private-lan.local",
        "unknown",
    ):
        return True
    # Cloud / ISP auto-generated PTR records where OpenSSL cert reveals the real site domain
    generic_markers = (
        ".bc.googleusercontent.com",
        ".1e100.net",
        ".amazonaws.com",
        ".cloudfront.net",
        ".linodeusercontent.com",
        ".vultrusercontent.com",
        ".akamaitechnologies.com",
        ".hwclouds-dns.com",
        "in-addr.arpa",
        "ip6.arpa",
    )
    if any(m in d for m in generic_markers):
        return True
    return False


class GeoIPDatabase:
    """Fast O(log N) in-memory RIR country lookup for IPv4 and IPv6 addresses."""

    def __init__(self, lists_dir: str = LISTS_DIR):
        self.lists_dir = lists_dir
        self.v4_starts: list[int] = []
        self.v4_ends: list[int] = []
        self.v4_ccs: list[str] = []
        self.v4_cidrs: list[str] = []

        self.v6_starts: list[int] = []
        self.v6_ends: list[int] = []
        self.v6_ccs: list[str] = []
        self.v6_cidrs: list[str] = []
        self.loaded = False
        self.load()

    def load(self):
        v4_path = os.path.join(self.lists_dir, "world-geoip-v4.tsv")
        v6_path = os.path.join(self.lists_dir, "world-geoip-v6.tsv")

        if os.path.exists(v4_path):
            starts, ends, ccs, cidrs = [], [], [], []
            try:
                with open(v4_path, "r") as f:
                    for line in f:
                        if not line or line[0] == "#":
                            continue
                        parts = line.rstrip("\n").split("\t")
                        if len(parts) >= 4:
                            starts.append(int(parts[0]))
                            ends.append(int(parts[1]))
                            ccs.append(parts[2])
                            cidrs.append(parts[3])
                self.v4_starts = starts
                self.v4_ends = ends
                self.v4_ccs = ccs
                self.v4_cidrs = cidrs
                self.loaded = True
            except Exception:
                pass

        if os.path.exists(v6_path):
            starts, ends, ccs, cidrs = [], [], [], []
            try:
                with open(v6_path, "r") as f:
                    for line in f:
                        if not line or line[0] == "#":
                            continue
                        parts = line.rstrip("\n").split("\t")
                        if len(parts) >= 4:
                            starts.append(int(parts[0], 16))
                            ends.append(int(parts[1], 16))
                            ccs.append(parts[2])
                            cidrs.append(parts[3])
                self.v6_starts = starts
                self.v6_ends = ends
                self.v6_ccs = ccs
                self.v6_cidrs = cidrs
            except Exception:
                pass

    def lookup(self, ip_str: str) -> dict:
        try:
            ip_obj = ipaddress.ip_address(ip_str)
        except Exception:
            return {
                "cc": "INVALID",
                "country": "Invalid IP",
                "cidr": "",
                "is_public": False,
                "is_non_us": False,
                "is_blocked_region": False,
                "block_category": "",
            }

        if (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_link_local
            or ip_obj.is_multicast
            or ip_obj.is_unspecified
        ):
            return {
                "cc": "LAN",
                "country": "Local/Private Network",
                "cidr": "",
                "is_public": False,
                "is_non_us": False,
                "is_blocked_region": False,
                "block_category": "",
            }

        ip_int = int(ip_obj)
        cc = ""
        cidr = ""
        if ip_obj.version == 4 and self.v4_starts:
            idx = bisect.bisect_right(self.v4_starts, ip_int) - 1
            if idx >= 0 and ip_int <= self.v4_ends[idx]:
                cc = self.v4_ccs[idx]
                cidr = self.v4_cidrs[idx]
        elif ip_obj.version == 6 and self.v6_starts:
            idx = bisect.bisect_right(self.v6_starts, ip_int) - 1
            if idx >= 0 and ip_int <= self.v6_ends[idx]:
                cc = self.v6_ccs[idx]
                cidr = self.v6_cidrs[idx]

        if not cc:
            return {
                "cc": "UNALLOCATED",
                "country": "Unallocated/Unknown RIR Block",
                "cidr": "",
                "is_public": True,
                "is_non_us": False,
                "is_blocked_region": False,
                "block_category": "",
            }

        is_us = cc in US_JURISDICTION_CODES
        is_blocked = cc in ALL_BLOCKED_COUNTRY_CODES
        return {
            "cc": cc,
            "country": get_country_name(cc),
            "cidr": cidr,
            "is_public": True,
            "is_non_us": not is_us,
            "is_blocked_region": is_blocked,
            "block_category": get_block_category_for_country(cc, is_domain=False) if is_blocked else "",
        }


def parse_rfc2253_dn(dn_line: str) -> dict[str, str]:
    """Parse OpenSSL `subject=...` or `issuer=...` in RFC2253 format into key->value dict."""
    prefix_stripped = re.sub(r"^(?:subject|issuer)\s*=\s*", "", dn_line.strip())
    if not prefix_stripped:
        return {}
    out = {}
    parts = re.split(r"(?<!\\),", prefix_stripped)
    for part in parts:
        if "=" not in part:
            continue
        k, v = part.split("=", 1)
        k = k.strip().upper()
        v = v.strip().replace(r"\,", ",").replace(r"\+", "+").replace(r"\"", '"')
        if k and v and k not in out:
            out[k] = v
    return out


def is_dummy_cert_domain(name: str, subject_dn: dict[str, str]) -> bool:
    if not name:
        return True
    low = name.strip().lower()
    if low in DUMMY_CERT_NAMES or low.endswith(".invalid") or low.endswith(".local"):
        return True
    ou = subject_dn.get("OU", "").lower()
    if "no sni provided" in ou:
        return True
    # Reject raw IP addresses pretending to be CNs
    try:
        ipaddress.ip_address(low)
        return True
    except ValueError:
        pass
    return False


class OpenSSLCertInspector:
    """
    Inspects TLS/HTTPS X.509 certificates on remote sites by IP using `openssl s_client`
    and `openssl x509`, with persistent disk caching and self-probe suppression.
    """

    POS_TTL = 86400.0   # 24h cache for valid certificates
    NEG_TTL = 3600.0    # 1h cache for IPs without TLS on probed port

    def __init__(self, persist_cache: bool = True):
        self.persist_cache = persist_cache
        self._lock = threading.Lock()
        self._ip_locks: dict[str, threading.Lock] = {}
        self._cache: dict[str, dict] = {}
        self._inflight: set[str] = set()
        self._active_probes: dict[tuple[str, int], float] = {}
        self._probe_pids: dict[int, float] = {}
        self._dirty_count = 0
        if persist_cache:
            self._load_cache()

    def _load_cache(self):
        for p in CERT_CACHE_PATHS:
            if os.path.exists(p):
                try:
                    with open(p, "r") as f:
                        data = json.load(f)
                    if isinstance(data, dict):
                        with self._lock:
                            self._cache.update(data)
                        break
                except Exception:
                    pass

    def save_cache(self):
        if not self.persist_cache:
            return
        with self._lock:
            # Keep most recent 4000 entries
            if len(self._cache) > 4000:
                sorted_items = sorted(
                    self._cache.items(),
                    key=lambda kv: kv[1].get("ts", 0),
                    reverse=True,
                )[:3500]
                self._cache = dict(sorted_items)
            payload = json.dumps(self._cache, indent=2)

        target_paths = list(CERT_CACHE_PATHS)
        if os.geteuid() != 0:
            user_cache = os.path.join(os.path.expanduser("~"), ".cache", "securepc", "openssl-cert-cache.json")
            target_paths = [user_cache]

        for p in target_paths:
            try:
                parent_d = os.path.dirname(p)
                os.makedirs(parent_d, mode=0o750, exist_ok=True)
                tmp_p = f"{p}.tmp.{os.getpid()}"
                with open(tmp_p, "w", encoding="utf-8") as f:
                    f.write(payload)
                os.chmod(tmp_p, 0o644 if os.geteuid() == 0 else 0o600)
                os.replace(tmp_p, p)
            except Exception:
                pass

    def is_active_probe(self, dst_ip: str, dst_port: int | str) -> bool:
        """Return True if SecurePC itself is currently (or within last 4s) probing dst_ip:dst_port via OpenSSL."""
        try:
            p_int = int(dst_port)
        except Exception:
            p_int = 0
        now = time.time()
        with self._lock:
            ts = self._active_probes.get((dst_ip, p_int), 0.0)
            if now - ts < 4.5:
                return True
            # Cleanup stale entries occasionally
            if len(self._active_probes) > 256:
                self._active_probes = {
                    k: t for k, t in self._active_probes.items() if now - t < 10.0
                }
        return False

    def is_probe_pid(self, pid: int) -> bool:
        if pid <= 0:
            return False
        now = time.time()
        with self._lock:
            ts = self._probe_pids.get(pid, 0.0)
            if now - ts < 8.0:
                return True
            if len(self._probe_pids) > 512:
                self._probe_pids = {
                    k: t for k, t in self._probe_pids.items() if now - t < 15.0
                }
        return False

    def cache_size(self) -> int:
        with self._lock:
            return sum(1 for v in self._cache.values() if v.get("has_cert"))

    def _run_openssl_once(self, ip_str: str, port: int, servername: str = "", timeout_s: float = 2.2) -> Optional[dict]:
        target = f"[{ip_str}]:{port}" if ":" in ip_str else f"{ip_str}:{port}"
        cmd = [
            "openssl",
            "s_client",
            "-connect",
            target,
            "-verify_quiet",
        ]
        if servername:
            cmd.extend(["-servername", servername])
        else:
            cmd.append("-noservername")

        now = time.time()
        with self._lock:
            self._active_probes[(ip_str, port)] = now

        try:
            proc = subprocess.Popen(
                cmd,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
            )
            with self._lock:
                self._probe_pids[proc.pid] = time.time()
            try:
                stdout_data, _ = proc.communicate(timeout=timeout_s)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.communicate()
                return None
            finally:
                with self._lock:
                    self._active_probes[(ip_str, port)] = time.time()
                    self._probe_pids[proc.pid] = time.time()
        except Exception:
            return None

        m_pem = re.search(
            r"(-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----)",
            stdout_data or "",
            re.DOTALL,
        )
        if not m_pem:
            return None

        pem = m_pem.group(1)
        try:
            x509 = subprocess.run(
                [
                    "openssl",
                    "x509",
                    "-noout",
                    "-subject",
                    "-issuer",
                    "-ext",
                    "subjectAltName",
                    "-dates",
                    "-nameopt",
                    "RFC2253",
                ],
                input=pem,
                capture_output=True,
                text=True,
                timeout=1.5,
            )
            if x509.returncode != 0:
                return None
            out = x509.stdout
        except Exception:
            return None

        subj_dn = {}
        issuer_dn = {}
        sans = []
        not_after = ""

        for line in out.splitlines():
            ls = line.strip()
            if ls.startswith("subject="):
                subj_dn = parse_rfc2253_dn(ls)
            elif ls.startswith("issuer="):
                issuer_dn = parse_rfc2253_dn(ls)
            elif ls.startswith("notAfter="):
                not_after = ls.split("=", 1)[1].strip()
            elif "DNS:" in ls:
                for tok in ls.split(","):
                    tok = tok.strip()
                    if tok.startswith("DNS:"):
                        dname = tok[4:].strip().lower()
                        if dname and not is_dummy_cert_domain(dname, subj_dn) and dname not in sans:
                            sans.append(dname)

        cn = subj_dn.get("CN", "").strip().lower()
        if is_dummy_cert_domain(cn, subj_dn):
            cn = ""

        if not cn and not sans:
            return None

        # Choose primary domain from certificate
        primary = ""
        if servername:
            sn_low = servername.lower()
            for san in sans:
                if san == sn_low:
                    primary = san
                    break
            if not primary:
                for san in sans:
                    if san.startswith("*.") and sn_low.endswith(san[1:]):
                        primary = sn_low
                        break
        if not primary:
            # Prefer non-wildcard SAN first, then CN, then wildcard-stripped SAN
            for san in sans:
                if not san.startswith("*."):
                    primary = san
                    break
        if not primary and cn and not cn.startswith("*."):
            primary = cn
        if not primary and sans:
            primary = sans[0]
        if not primary:
            primary = cn

        subj_c = subj_dn.get("C", "").strip().upper()
        if len(subj_c) != 2 or not subj_c.isalpha():
            subj_c = ""

        return {
            "has_cert": True,
            "ip": ip_str,
            "port": port,
            "sni_used": servername,
            "primary_domain": primary,
            "cn": cn,
            "sans": sans[:15],
            "subject_org": subj_dn.get("O", ""),
            "subject_country": subj_c,
            "issuer_cn": issuer_dn.get("CN", ""),
            "issuer_org": issuer_dn.get("O", ""),
            "not_after": not_after,
            "ts": time.time(),
        }

    def inspect_ip(
        self,
        ip_str: str,
        port: int | str = 443,
        sni_hint: str = "",
        timeout_s: float = 2.2,
        force_refresh: bool = False,
    ) -> dict:
        """
        Inspect the TLS certificate on `ip_str` using OpenSSL.
        1. Tries target TLS port (or 443 if connection was on HTTP/UDP/non-TLS port).
        2. Connects directly by IP (`-noservername`) to reveal the host's default X.509 cert.
        3. If `-noservername` returns no valid cert (e.g. SNI-strict CDN returning `invalid2.invalid`)
           and `sni_hint` is available, retries with `-servername <sni_hint>`.
        """
        try:
            p_int = int(port)
        except Exception:
            p_int = 443

        clean_sni = clean_hostname_token(sni_hint)
        if is_generic_ptr_or_placeholder(clean_sni):
            clean_sni = ""

        # Candidate ports to probe with OpenSSL
        ports_to_try = []
        if p_int in TLS_COMMON_PORTS:
            ports_to_try.append(p_int)
        if 443 not in ports_to_try:
            ports_to_try.append(443)

        cache_key = f"{ip_str}:{ports_to_try[0]}:{clean_sni}"
        ip_only_key = f"{ip_str}:{ports_to_try[0]}:"
        now = time.time()

        with self._lock:
            ip_lock = self._ip_locks.get(ip_str)
            if ip_lock is None:
                ip_lock = threading.Lock()
                if len(self._ip_locks) > 2048:
                    self._ip_locks.clear()
                self._ip_locks[ip_str] = ip_lock

        with ip_lock:
            now = time.time()
            if not force_refresh:
                with self._lock:
                    for ck in (cache_key, ip_only_key):
                        cached = self._cache.get(ck)
                        if cached:
                            ttl = self.POS_TTL if cached.get("has_cert") else self.NEG_TTL
                            if now - cached.get("ts", 0) < ttl:
                                if cached.get("has_cert") or ck == cache_key:
                                    return cached

            result = None
            for probe_port in ports_to_try:
                # Step A: Direct IP OpenSSL inspection (-noservername) to uncover domain from IP alone
                result = self._run_openssl_once(ip_str, probe_port, servername="", timeout_s=timeout_s)
                if result and result.get("has_cert"):
                    # If we also have a specific SNI hint not matching the default cert, check if SNI cert gives exact vhost
                    if clean_sni and clean_sni != result.get("primary_domain") and clean_sni not in result.get("sans", []):
                        vhost_res = self._run_openssl_once(ip_str, probe_port, servername=clean_sni, timeout_s=timeout_s)
                        if vhost_res and vhost_res.get("has_cert"):
                            result = vhost_res
                    break
                # Step B: SNI-assisted OpenSSL inspection when server requires SNI (e.g. Cloudflare/Google/Fastly)
                if clean_sni:
                    result = self._run_openssl_once(ip_str, probe_port, servername=clean_sni, timeout_s=timeout_s)
                    if result and result.get("has_cert"):
                        break

            if not result:
                result = {
                    "has_cert": False,
                    "ip": ip_str,
                    "port": ports_to_try[0],
                    "sni_used": clean_sni,
                    "primary_domain": "",
                    "cn": "",
                    "sans": [],
                    "subject_org": "",
                    "subject_country": "",
                    "issuer_cn": "",
                    "issuer_org": "",
                    "not_after": "",
                    "ts": now,
                }

            with self._lock:
                self._cache[cache_key] = result
                if not result.get("sni_used"):
                    self._cache[ip_only_key] = result
                self._dirty_count += 1
                should_save = result.get("has_cert", False) or self._dirty_count >= 10
                if should_save:
                    self._dirty_count = 0

            if should_save:
                self.save_cache()

        return result


def format_cert_summary(cert_info: dict) -> str:
    if not cert_info or not cert_info.get("has_cert"):
        return "no-tls-cert"
    parts = []
    if cert_info.get("cn"):
        parts.append(f"CN={cert_info['cn']}")
    sans = cert_info.get("sans") or []
    if sans:
        shown = ",".join(sans[:3])
        if len(sans) > 3:
            shown += f",+{len(sans) - 3}"
        parts.append(f"SAN={shown}")
    if cert_info.get("subject_org"):
        parts.append(f"O={cert_info['subject_org']}")
    if cert_info.get("subject_country"):
        parts.append(f"C={cert_info['subject_country']}")
    return "; ".join(parts) if parts else "tls-cert"


def evaluate_traffic_destination(
    geo_db: GeoIPDatabase,
    cert_inspector: OpenSSLCertInspector,
    dst_ip: str,
    dst_port: int | str,
    proto: str = "TCP",
    fallback_domain: str = "",
    sni_or_dns_hint: str = "",
    category: str = "",
    allow_live_openssl: bool = True,
) -> dict:
    """
    Full attribution & Non-US classification for an outbound or blocked connection:
      1. Looks up IP in Worldwide RIR GeoIP table.
      2. Probes remote IP with OpenSSL (`s_client` + `x509`) when safe (never sends packets
         to blocked CN/RU/IR/Middle-East IPs).
      3. Combines OpenSSL certificate domains, SNI/DNS hints, PTR, and GeoIP to determine
         the authoritative domain and whether the destination IP or domain is outside the US.
    """
    geo = geo_db.lookup(dst_ip)
    ip_cc = geo["cc"]
    ip_country = geo["country"]

    # Check category overrides from iptables block chains
    cat_u = (category or "").upper()
    if "BEIJING" in cat_u or "ALIYUNCS" in cat_u or "CN" in cat_u:
        if ip_cc in ("UNALLOCATED", "US"):
            # Could be a DNS query to 8.8.8.8 for a .cn domain blocked by SECUREPC_DOMAINS!
            pass
    cert_info = {"has_cert": False}
    can_probe_tls = (
        allow_live_openssl
        and geo["is_public"]
        and not geo["is_blocked_region"]
        and not cat_u.startswith(("CN", "RU", "IR", "ME", "BEIJING", "ALIYUNCS"))
        and str(dst_port) not in ("53", "5353")
    )

    hint_for_sni = sni_or_dns_hint or (
        "" if is_generic_ptr_or_placeholder(fallback_domain) else clean_hostname_token(fallback_domain)
    )

    if can_probe_tls:
        cert_info = cert_inspector.inspect_ip(
            ip_str=dst_ip,
            port=dst_port,
            sni_hint=hint_for_sni,
        )

    cert_dom = cert_info.get("primary_domain", "") if cert_info else ""
    cert_cn = cert_info.get("cn", "") if cert_info else ""
    cert_sans = cert_info.get("sans", []) if cert_info else []
    cert_subj_c = cert_info.get("subject_country", "") if cert_info else ""
    cert_org = cert_info.get("subject_org", "") if cert_info else ""

    # Determine best display domain
    clean_hint = clean_hostname_token(sni_or_dns_hint)
    if clean_hint and cert_dom and clean_hint != cert_dom:
        best_domain = f"{clean_hint} [cert:{cert_dom}]"
    elif clean_hint:
        best_domain = clean_hint
    elif cert_dom:
        if fallback_domain and not is_generic_ptr_or_placeholder(fallback_domain) and clean_hostname_token(fallback_domain) != cert_dom:
            best_domain = f"{cert_dom} ({fallback_domain})"
        else:
            best_domain = f"{cert_dom} [openssl-cert]"
    else:
        best_domain = fallback_domain or "unresolved-public-ip"

    # Check domain-level country indicators across hint, fallback, and OpenSSL cert
    domain_cc = ""
    domain_cc_source = ""
    candidate_domains = [clean_hint, cert_dom, cert_cn, clean_hostname_token(fallback_domain)]
    if len(cert_sans) <= 8:
        candidate_domains.extend(cert_sans)

    for cand in candidate_domains:
        if not cand:
            continue
        dcc = extract_domain_country(cand)
        if dcc and dcc not in US_JURISDICTION_CODES:
            domain_cc = dcc
            domain_cc_source = f"domain:{cand}"
            break

    # Also check iptables DPI category for blocked DNS queries (e.g. querying 8.8.8.8 for yandex.ru or gov.ir)
    cat_cc = ""
    if "BEIJING" in cat_u or "ALIYUNCS" in cat_u or "CN" in cat_u:
        cat_cc = "CN"
    elif "RU" in cat_u:
        cat_cc = "RU"
    elif "IR" in cat_u:
        cat_cc = "IR"
    elif "ME" in cat_u:
        cat_cc = domain_cc if domain_cc in BLOCKED_MIDDLE_EAST_CODES else (ip_cc if ip_cc in BLOCKED_MIDDLE_EAST_CODES else "ME")

    # Determine Non-US status and effective country
    reasons = []
    effective_cc = ip_cc

    if geo["is_public"] and ip_cc not in US_JURISDICTION_CODES and ip_cc not in ("LAN", "INVALID", "UNALLOCATED"):
        reasons.append(f"IP-GeoIP={ip_cc}({geo['cidr']})")

    if domain_cc and domain_cc not in US_JURISDICTION_CODES:
        reasons.append(f"Domain-TLD={domain_cc}({domain_cc_source})")
        if effective_cc in US_JURISDICTION_CODES or effective_cc in ("UNALLOCATED", "LAN"):
            effective_cc = domain_cc

    if cert_subj_c and cert_subj_c not in US_JURISDICTION_CODES:
        reasons.append(f"Cert-Subject-C={cert_subj_c}")
        if effective_cc in US_JURISDICTION_CODES or effective_cc in ("UNALLOCATED", "LAN"):
            effective_cc = cert_subj_c

    if cat_cc and cat_cc not in US_JURISDICTION_CODES:
        if not reasons:
            reasons.append(f"Firewall-DPI={cat_cc}")
        if effective_cc in US_JURISDICTION_CODES or effective_cc in ("UNALLOCATED", "LAN"):
            effective_cc = cat_cc

    is_non_us = len(reasons) > 0
    if effective_cc == "ME":
        effective_country = "Middle East"
    else:
        effective_country = get_country_name(effective_cc)

    if is_non_us and ip_cc in US_JURISDICTION_CODES and effective_cc != ip_cc:
        country_label = f"{effective_cc} ({effective_country} via US-IP)"
    elif is_non_us and not geo["is_public"]:
        country_label = f"{effective_cc} ({effective_country} via DNS)"
    elif geo["is_public"]:
        country_label = f"{effective_cc} ({effective_country})"
    else:
        country_label = "LAN (Local)"

    if is_non_us and not geo["is_public"] and best_domain in ("private-lan.local", "localhost", "local-network"):
        best_domain = f"blocked-{effective_cc.lower()}-domain (DNS via {dst_ip})"

    is_blocked_region = (
        effective_cc in ALL_BLOCKED_COUNTRY_CODES
        or ip_cc in ALL_BLOCKED_COUNTRY_CODES
        or domain_cc in ALL_BLOCKED_COUNTRY_CODES
        or bool(cat_cc)
    )

    return {
        "ip": dst_ip,
        "port": dst_port,
        "ip_cc": ip_cc,
        "ip_country": ip_country,
        "geoip_cidr": geo["cidr"],
        "effective_cc": effective_cc,
        "effective_country": effective_country,
        "country_label": country_label,
        "is_public": geo["is_public"],
        "is_non_us": is_non_us,
        "is_blocked_region": is_blocked_region,
        "non_us_reasons": reasons,
        "best_domain": best_domain,
        "cert": cert_info,
        "cert_summary": format_cert_summary(cert_info),
        "cert_org": cert_org,
        "cert_subject_country": cert_subj_c,
    }


def cli_main():
    print_securepc_intro_banner()
    print()
    if len(sys.argv) < 2:
        print("Usage: securepc_geo_cert.py <IP> [PORT] [OPTIONAL_SNI_HOSTNAME]")
        sys.exit(1)

    target_ip = sys.argv[1].strip()
    target_port = int(sys.argv[2]) if len(sys.argv) >= 3 and sys.argv[2].isdigit() else 443
    sni_hint = sys.argv[3].strip() if len(sys.argv) >= 4 else ""

    geo_db = GeoIPDatabase()
    inspector = OpenSSLCertInspector(persist_cache=True)

    # Reverse DNS PTR check
    ptr_host = ""
    try:
        import socket
        old_to = socket.getdefaulttimeout()
        socket.setdefaulttimeout(1.5)
        try:
            ptr_host, _, _ = socket.gethostbyaddr(target_ip)
        finally:
            socket.setdefaulttimeout(old_to)
    except Exception:
        pass

    res = evaluate_traffic_destination(
        geo_db=geo_db,
        cert_inspector=inspector,
        dst_ip=target_ip,
        dst_port=target_port,
        proto="TCP",
        fallback_domain=ptr_host,
        sni_or_dns_hint=sni_hint,
        allow_live_openssl=True,
    )

    cert = res["cert"] or {}
    if res["is_blocked_region"]:
        policy = "BLOCKED & ALERTED (China / Russia / Iran / Middle East)"
    elif res["is_non_us"]:
        policy = "NON-US FLAGGED (Logged & Flagged on First Login)"
    elif res["is_public"]:
        policy = "US ALLOWED (United States)"
    else:
        policy = "LOCAL / PRIVATE NETWORK"

    print("================================================================================")
    print(f" SecurePC GeoIP & OpenSSL Certificate Inspection — {target_ip}:{target_port}")
    print("================================================================================")
    print(f"  IP Address:          {target_ip}")
    print(f"  Port:                {target_port}/TCP")
    print(f"  Inspector PID/PPID:  PID={os.getpid()} PPID={os.getppid()}")
    print(f"  RIR GeoIP Country:   {res['ip_cc']} — {res['ip_country']}")
    print(f"  Matched RIR CIDR:    {res['geoip_cidr'] or 'N/A'}")
    print(f"  Reverse DNS (PTR):   {ptr_host or 'None'}")
    print(f"  OpenSSL Cert Found:  {'YES' if cert.get('has_cert') else 'NO (or blocked/non-TLS port)'}")
    if cert.get("has_cert"):
        print(f"  Cert Primary Domain: {cert.get('primary_domain') or 'N/A'}")
        print(f"  Cert Subject CN:     {cert.get('cn') or 'N/A'}")
        print(f"  Cert Subject Org:    {cert.get('subject_org') or 'N/A'}")
        print(f"  Cert Subject C=:     {cert.get('subject_country') or 'N/A'}")
        print(f"  Cert SANs (DNS):     {', '.join(cert.get('sans', [])) or 'None'}")
        print(f"  Cert Issuer:         {cert.get('issuer_cn') or ''} ({cert.get('issuer_org') or 'N/A'})")
        print(f"  Cert Expires:        {cert.get('not_after') or 'N/A'}")
    print("--------------------------------------------------------------------------------")
    print(f"  Attributed Domain:   {res['best_domain']}")
    print(f"  Effective Country:   {res['country_label']}")
    print(f"  Outside US?:         {'YES (' + ', '.join(res['non_us_reasons']) + ')' if res['is_non_us'] else 'NO'}")
    print(f"  SecurePC Policy:     {policy}")
    print("================================================================================")


if __name__ == "__main__":
    cli_main()

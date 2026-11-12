#!/usr/bin/env python3
"""
SecurePC — OS-Level Browser DNS-over-HTTPS (DoH) & ECH Policy Manager
Author:  CROW Innovations (https://crowinnovations.com)
License: GNU General Public License v3.0 (GPL-3.0)
GitHub:  https://github.com/CROWInnovations/SecurePC

Prevents browsers (Firefox, Firefox-ESR, Google Chrome, Chromium, Brave, Edge)
from bypassing system-level domain blocking via internal DNS-over-HTTPS (DoH),
built-in async stub resolvers, or Encrypted ClientHello (ECH).
Non-destructively merges Firefox policies and uses dedicated Chromium drop-ins
so `uninstall` restores the system cleanly.
"""

import json
import os
import sys

CHROMIUM_POLICY_DIRS = [
    "/etc/chromium/policies/managed",
    "/etc/chromium-browser/policies/managed",
    "/etc/opt/chrome/policies/managed",
    "/etc/brave/policies/managed",
    "/etc/opt/edge/policies/managed",
]

CHROMIUM_DROPIN_NAME = "securepc-dns.json"
CHROMIUM_PAYLOAD = {
    "DnsOverHttpsMode": "off",
    "BuiltInDnsClientEnabled": False,
    "EncryptedClientHelloEnabled": False,
}

FIREFOX_POLICY_PATH = "/etc/firefox/policies/policies.json"
FIREFOX_BACKUP_PATH = "/etc/firefox/policies/.policies.json.securepc-orig"
FIREFOX_ESR_DIR = "/etc/firefox-esr"
FIREFOX_ESR_DROPIN = "/etc/firefox-esr/securepc-dns.js"

FIREFOX_ESR_JS = """// Managed by SecurePC — Lock off DoH & ECH so system domain blocking cannot be bypassed
lockPref("network.trr.mode", 5);
lockPref("network.dns.echconfig.enabled", false);
lockPref("network.dns.http3_echconfig.enabled", false);
"""


def write_atomic(path: str, content: str, mode: int = 0o644) -> None:
    parent = os.path.dirname(path)
    os.makedirs(parent, mode=0o755, exist_ok=True)
    tmp = f"{path}.tmp.{os.getpid()}"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(content)
    os.chmod(tmp, mode)
    try:
        os.chown(tmp, 0, 0)
    except PermissionError:
        pass
    os.replace(tmp, path)


def apply_policies() -> list[str]:
    applied = []

    # 1. Chromium / Chrome / Brave / Edge managed policy drop-ins
    payload_str = json.dumps(CHROMIUM_PAYLOAD, indent=2) + "\n"
    for pdir in CHROMIUM_POLICY_DIRS:
        base_etc = "/" + pdir.strip("/").split("/")[0] + "/" + pdir.strip("/").split("/")[1]
        # Always configure standard Chromium & Chrome paths plus any installed browser trees
        if pdir in ("/etc/chromium/policies/managed", "/etc/opt/chrome/policies/managed") or os.path.isdir(base_etc):
            target = os.path.join(pdir, CHROMIUM_DROPIN_NAME)
            write_atomic(target, payload_str, 0o644)
            applied.append(target)

    # 2. Firefox /etc/firefox/policies/policies.json (never clobber distro /usr/share files)
    existing = {}
    had_existing = os.path.exists(FIREFOX_POLICY_PATH)
    if had_existing:
        try:
            with open(FIREFOX_POLICY_PATH, "r", encoding="utf-8") as f:
                loaded = json.load(f)
            if isinstance(loaded, dict):
                existing = loaded
        except Exception:
            existing = {}

    if had_existing and not os.path.exists(FIREFOX_BACKUP_PATH) and not existing.get("_securepc_created"):
        try:
            with open(FIREFOX_POLICY_PATH, "r", encoding="utf-8") as src:
                write_atomic(FIREFOX_BACKUP_PATH, src.read(), 0o600)
        except Exception:
            pass

    if not had_existing:
        existing["_securepc_created"] = True

    policies = existing.setdefault("policies", {})
    if not isinstance(policies, dict):
        policies = {}
        existing["policies"] = policies

    policies["DNSOverHTTPS"] = {
        "Enabled": False,
        "Locked": True,
    }
    prefs = policies.setdefault("Preferences", {})
    if isinstance(prefs, dict):
        prefs["network.trr.mode"] = {"Value": 5, "Status": "locked"}
        prefs["network.dns.echconfig.enabled"] = {"Value": False, "Status": "locked"}
        prefs["network.dns.http3_echconfig.enabled"] = {"Value": False, "Status": "locked"}

    write_atomic(FIREFOX_POLICY_PATH, json.dumps(existing, indent=2) + "\n", 0o644)
    applied.append(FIREFOX_POLICY_PATH)

    # 3. Debian / Kali / Ubuntu ESR preference lock drop-in
    if os.path.isdir(FIREFOX_ESR_DIR):
        write_atomic(FIREFOX_ESR_DROPIN, FIREFOX_ESR_JS, 0o644)
        applied.append(FIREFOX_ESR_DROPIN)

    return applied


def remove_policies(dry_run: bool = False) -> list[str]:
    removed = []
    for pdir in CHROMIUM_POLICY_DIRS:
        target = os.path.join(pdir, CHROMIUM_DROPIN_NAME)
        if os.path.exists(target):
            if not dry_run:
                os.remove(target)
            removed.append(target)

    if os.path.exists(FIREFOX_ESR_DROPIN):
        if not dry_run:
            os.remove(FIREFOX_ESR_DROPIN)
        removed.append(FIREFOX_ESR_DROPIN)

    if os.path.exists(FIREFOX_BACKUP_PATH):
        if not dry_run:
            os.replace(FIREFOX_BACKUP_PATH, FIREFOX_POLICY_PATH)
            os.chmod(FIREFOX_POLICY_PATH, 0o644)
        removed.append(f"{FIREFOX_POLICY_PATH} (restored prior backup)")
    elif os.path.exists(FIREFOX_POLICY_PATH):
        try:
            with open(FIREFOX_POLICY_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            data = {}
        if isinstance(data, dict) and data.get("_securepc_created"):
            if not dry_run:
                os.remove(FIREFOX_POLICY_PATH)
            removed.append(FIREFOX_POLICY_PATH)

    return removed


def status_policies() -> dict:
    active_files = []
    for pdir in CHROMIUM_POLICY_DIRS:
        target = os.path.join(pdir, CHROMIUM_DROPIN_NAME)
        if os.path.exists(target):
            active_files.append(target)
    if os.path.exists(FIREFOX_POLICY_PATH):
        active_files.append(FIREFOX_POLICY_PATH)
    if os.path.exists(FIREFOX_ESR_DROPIN):
        active_files.append(FIREFOX_ESR_DROPIN)
    return {"active": len(active_files) > 0, "files": active_files}


def main() -> int:
    action = sys.argv[1] if len(sys.argv) > 1 else "status"
    dry_run = "--dry-run" in sys.argv[2:]
    if action == "apply":
        paths = apply_policies()
        for p in paths:
            print(f"  + Browser DoH/ECH policy enforced: {p}")
        return 0
    if action == "remove":
        paths = remove_policies(dry_run=dry_run)
        for p in paths:
            prefix = "[dry-run] " if dry_run else ""
            print(f"  - {prefix}Removed browser policy: {p}")
        return 0
    if action == "status":
        st = status_policies()
        print(json.dumps(st))
        return 0
    sys.stderr.write("Usage: securepc-browser-policy.py {apply|remove [--dry-run]|status}\n")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

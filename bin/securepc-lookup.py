#!/usr/bin/env python3
"""
SecurePC — Program & Domain Attribution Lookup (securepc-lookup.py)
Author:  CROW Innovations (https://crowinnovations.com)
License: GNU General Public License v3.0 (GPL-3.0)
GitHub:  https://github.com/CROWInnovations/SecurePC

Inspects SecurePC logs to attribute exactly which program, binary, PID,
command line, and systemd service or container called out to a domain or IP,
and explains what the connection is for.
"""

import sys
import os
import re
import subprocess

KNOWN_PURPOSES = {
    "chronyd": "Linux Network Time Protocol (NTP) system service. Synchronizes the local system clock against public pool NTP servers (UDP port 123).",
    "systemd-timesyncd": "Systemd SNTP client daemon. Synchronizes system time with upstream NTP servers.",
    "systemd-resolved": "Systemd local stub DNS resolver service.",
    "dockerd": "Docker container virtualization daemon. Manages container engines, bridge networks, and image pulls.",
    "docker-proxy": "Docker container network proxy. Forwards network connections between host interfaces and containerized apps.",
    "python3": "Python 3 runtime environment executing local scripts or services.",
    "NetworkManager": "Core Linux networking service handling link configuration, connectivity checks, and DHCP.",
    "sshd": "OpenSSH secure shell daemon handling encrypted remote administration sessions.",
    "curl": "Command-line HTTP/HTTPS transfer client.",
    "wget": "Command-line network file downloader.",
    "firefox": "Mozilla Firefox web browser.",
    "firefox-esr": "Mozilla Firefox Extended Support Release web browser.",
    "chromium": "Chromium web browser.",
    "google": "Google Cloud / public web infrastructure services.",
}

def is_kernel_comm(comm: str) -> bool:
    if not comm:
        return True
    c = comm.lower()
    return (
        c.startswith("irq/")
        or c.startswith("ksoftirqd")
        or c.startswith("kworker")
        or c.startswith("rcu_")
        or c.startswith("migration/")
        or c in ("<idle>", "<...>", "unknown")
    )

def parse_line(line: str) -> dict:
    rec = {}
    ts_m = re.match(r"^\[([^\]]+)\]", line)
    if ts_m:
        rec["timestamp"] = ts_m.group(1)

    for field, pat in [
        ("status", r"STATUS=([^\s]+)"),
        ("country", r"COUNTRY=\"([^\"]+)\""),
        ("proto", r"PROTO=([^\s]+)"),
        ("port", r"PORT=([^\s]+)"),
        ("src", r"SRC=([^\s]+)"),
        ("dst_ip", r"OUTBOUND_IP=([^:\s]+)"),
        ("dst", r"DST=([^\s]+)"),
        ("domain", r"DOMAIN=\"([^\"]+)\""),
        ("cert", r"OPENSSL_CERT=\"([^\"]+)\""),
        ("pid", r"PID=([^\s|]+)"),
        ("ppid", r"PPID=([^\s|]+)"),
        ("user", r"USER=([^\s|]+)"),
        ("service", r"SERVICE=([^\s|]+)"),
        ("software", r"SOFTWARE=([^\s|]+)"),
        ("binary", r"BINARY=([^\s|]+)"),
        ("cmd", r"CMD=\"([^\"]+)\""),
        ("note", r"NOTE=([^\n\r]+)"),
    ]:
        m = re.search(pat, line)
        if m:
            rec[field] = m.group(1).strip()
    return rec

def grep_log_file(filepath: str, query: str, max_lines: int = 1000) -> list:
    if not os.path.exists(filepath) or os.path.getsize(filepath) == 0:
        return []
    try:
        # Use fast native grep to grab up to max_lines matches
        cmd = ["grep", "-i", "-F", query, filepath]
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        lines = []
        for line in p.stdout:
            lines.append(line)
            if len(lines) >= max_lines:
                p.kill()
                break
        p.stdout.close()
        p.wait()
        return lines
    except Exception:
        return []

def lookup_target(query: str):
    q = query.strip()
    if not q:
        print("Usage: securepc-ctl lookup <DOMAIN | IP | PROGRAM | PID>")
        return

    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    primary_logs = [
        "/var/log/securepc/outbound-internet.log",
        "/var/log/securepc/blocked-alerts.log",
        "/var/log/securepc/non-us-traffic.log",
        os.path.join(base_dir, "logs", "outbound-internet.log"),
        os.path.join(base_dir, "logs", "blocked-alerts.log"),
    ]

    raw_lines = []
    seen_inodes = set()
    for log_path in primary_logs:
        if os.path.exists(log_path):
            try:
                st = os.stat(log_path)
                ino = (st.st_dev, st.st_ino)
                if ino not in seen_inodes:
                    seen_inodes.add(ino)
                    raw_lines.extend(grep_log_file(log_path, q, max_lines=600))
            except Exception:
                pass

    # If nothing in outbound-internet, fallback to connections.log
    if not raw_lines:
        conn_log = "/var/log/securepc/connections.log"
        if os.path.exists(conn_log):
            raw_lines.extend(grep_log_file(conn_log, q, max_lines=400))

    if not raw_lines:
        print(f"\n[-] No records found matching '{q}' in SecurePC traffic logs.")
        print("    Tip: Try searching by IP address, domain keyword, or program name (e.g. 'chronyd', 'curl', 'firefox').\n")
        return

    parsed_records = [parse_line(l) for l in raw_lines if l.strip()]
    if not parsed_records:
        print(f"\n[-] Could not parse records for '{q}'.\n")
        return

    # Aggregate attribution
    binaries = []
    softwares = []
    cmds = []
    services = []
    users = []
    pids = []
    ppids = []
    domains = []
    destinations = []
    statuses = set()
    first_seen = parsed_records[0].get("timestamp", "Unknown")
    last_seen = parsed_records[-1].get("timestamp", "Unknown")

    for rec in parsed_records:
        bin_val = rec.get("binary", "")
        soft_val = rec.get("software", "")
        cmd_val = rec.get("cmd", "")
        svc_val = rec.get("service", "")
        usr_val = rec.get("user", "")
        pid_val = rec.get("pid", "")
        ppid_val = rec.get("ppid", "")
        dom_val = rec.get("domain", "")

        if bin_val and not is_kernel_comm(bin_val) and bin_val not in binaries:
            binaries.append(bin_val)
        if soft_val and not is_kernel_comm(soft_val) and soft_val not in softwares:
            softwares.append(soft_val)
        if cmd_val and not is_kernel_comm(cmd_val) and cmd_val not in cmds:
            cmds.append(cmd_val)
        if svc_val and svc_val not in ("unknown", "") and svc_val not in services:
            services.append(svc_val)
        if usr_val and usr_val not in ("unknown", "") and usr_val not in users:
            users.append(usr_val)
        if pid_val and pid_val not in ("0", "unknown", "") and pid_val not in pids:
            pids.append(pid_val)
        if ppid_val and ppid_val not in ("0", "unknown", "") and ppid_val not in ppids:
            ppids.append(ppid_val)
        if dom_val and dom_val not in ("unknown", "") and dom_val not in domains:
            domains.append(dom_val)

        if rec.get("dst_ip"):
            p_val = rec.get("port", "443")
            proto_val = rec.get("proto", "TCP")
            dest = f"{rec['dst_ip']}:{p_val} ({proto_val})"
            if dest not in destinations:
                destinations.append(dest)
        elif rec.get("dst") and rec["dst"] not in destinations:
            destinations.append(rec["dst"])

        if rec.get("status"):
            statuses.add(rec["status"])

    # If only kernel comms were recorded
    if not softwares:
        softwares = [r.get("software") for r in parsed_records if r.get("software") and r.get("software") != "unknown"]
    if not binaries:
        binaries = [r.get("binary") for r in parsed_records if r.get("binary") and r.get("binary") != "unknown"]

    # Deduplicate while preserving order
    softwares = list(dict.fromkeys(softwares))
    binaries = list(dict.fromkeys(binaries))
    services = list(dict.fromkeys(services))
    users = list(dict.fromkeys(users))
    pids = list(dict.fromkeys(pids))
    ppids = list(dict.fromkeys(ppids))
    domains = list(dict.fromkeys(domains))
    destinations = list(dict.fromkeys(destinations))

    # Determine purpose
    purpose_desc = "Outbound network connection initiated by local process."
    matched_app = None
    for s in softwares + [os.path.basename(b) for b in binaries]:
        base_s = s.split(".")[0]
        if s in KNOWN_PURPOSES:
            purpose_desc = KNOWN_PURPOSES[s]
            matched_app = s
            break
        elif base_s in KNOWN_PURPOSES:
            purpose_desc = KNOWN_PURPOSES[base_s]
            matched_app = base_s
            break

    # Check domain purpose if app not recognized
    if not matched_app:
        for d in domains:
            if "google" in d.lower() or "gstatic" in d.lower():
                purpose_desc = KNOWN_PURPOSES["google"]
                break

    # Formatting colors
    C_BLUE = "\033[1;34m"
    C_CYAN = "\033[1;36m"
    C_YELLOW = "\033[1;33m"
    C_GREEN = "\033[1;32m"
    C_WHITE = "\033[1;37m"
    C_RED = "\033[1;31m"
    C_RESET = "\033[0m"

    if os.environ.get("NO_COLOR"):
        C_BLUE = C_CYAN = C_YELLOW = C_GREEN = C_WHITE = C_RED = C_RESET = ""

    width = 115
    bar = "=" * width
    div = "-" * width

    print(f"\n{C_BLUE}{bar}{C_RESET}")
    print(f"{C_CYAN}  [*] SECUREPC ATTRIBUTION & PROGRAM IDENTIFICATION — QUERY: {q.upper()}{C_RESET}")
    print(f"{C_BLUE}{div}{C_RESET}")

    # Primary identification
    main_soft = ", ".join(softwares[:4]) if softwares else "Direct packet / Netfilter"
    main_bin = ", ".join(binaries[:3]) if binaries else "Kernel socket or transient connection"
    main_cmd = cmds[0] if cmds else "N/A"
    if len(main_cmd) > 105:
        main_cmd = main_cmd[:102] + "..."
    main_svc = ", ".join(services[:3]) if services else "User login session"
    main_usr = ", ".join(users[:3]) if users else "unknown"
    main_pid = ", ".join(pids[:6]) if pids else "N/A"
    main_ppid = ", ".join(ppids[:4]) if ppids else "N/A"

    print(f"  {C_YELLOW}Program / Software:{C_RESET} {C_WHITE}{main_soft}{C_RESET}")
    print(f"  {C_YELLOW}Exact Binary Path:{C_RESET}  {C_GREEN}{main_bin}{C_RESET}")
    print(f"  {C_YELLOW}Command Line Exec:{C_RESET}  {C_WHITE}\"{main_cmd}\"{C_RESET}")
    print(f"  {C_YELLOW}Service / Scope:{C_RESET}    {C_CYAN}{main_svc}{C_RESET}  |  {C_YELLOW}User:{C_RESET} {C_WHITE}{main_usr}{C_RESET}")
    print(f"  {C_YELLOW}Active PID(s):{C_RESET}      {C_WHITE}{main_pid}{C_RESET}  |  {C_YELLOW}Parent PPID:{C_RESET} {C_WHITE}{main_ppid}{C_RESET}")
    print(f"{C_BLUE}{div}{C_RESET}")

    # Connection targets and purpose
    main_dom = ", ".join(domains[:5]) if domains else q
    main_dst = ", ".join(destinations[:5]) if destinations else "N/A"
    status_str = ", ".join(statuses) if statuses else "RECORDED"

    print(f"  {C_YELLOW}Target Domain(s):{C_RESET}   {C_CYAN}{main_dom}{C_RESET}")
    print(f"  {C_YELLOW}Remote Endpoints:{C_RESET}   {C_WHITE}{main_dst}{C_RESET}")
    print(f"  {C_YELLOW}Traffic Policy:{C_RESET}     {C_GREEN if 'ALLOWED' in status_str else C_RED}{status_str}{C_RESET}  |  {C_YELLOW}Sampled Matches:{C_RESET} {C_WHITE}{len(parsed_records):,}{C_RESET}")
    print(f"  {C_YELLOW}Observation Window:{C_RESET} {C_WHITE}{first_seen}{C_RESET}  ->  {C_WHITE}{last_seen}{C_RESET}")
    print(f"{C_BLUE}{div}{C_RESET}")

    print(f"  {C_YELLOW}What It's For:{C_RESET}")
    print(f"  {C_WHITE}{purpose_desc}{C_RESET}")

    print(f"{C_BLUE}{bar}{C_RESET}\n")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: securepc-ctl lookup <DOMAIN | IP | PROGRAM | PID>")
        sys.exit(1)
    lookup_target(sys.argv[1])

![SecurePC Banner](./securepc_banner.jpg)

# SecurePC

Host-level network security, GeoIP traffic blocking, anti-DoH/DoT domain enforcement, and process-level (`PID`, `PPID`, `Port`, `Binary`) connection monitoring for Linux and Solaris/illumos.

## Features

- **Multi-Backend Kernel Firewall (`auto` detection)**: Uses native dual-stack `nftables` (`table inet securepc`) on modern Linux (Ubuntu, Linux Mint, Debian, Kali, Fedora, RHEL, Arch, openSUSE), falls back automatically to `iptables` + `ip6tables` + `ipset` on legacy kernels, and supports Solaris `pf` (`solaris_ipf`).
- **Regional & Domain Blocking**: Blocks inbound and outbound IPv4/IPv6 traffic associated with China (`.cn`, Beijing ASNs, `aliyuncs.com`), Russia (`.ru`, `.su`, `.рф`), Iran (`.ir`, `.ایران`), and 16 Middle East country allocations, plus custom admin blocklists.
- **Anti-Bypass Enforcement**: Blocks encrypted DNS bypasses (`TCP/UDP 853` DoT/DoQ and `TCP/UDP 443` to public DoH resolvers), applies Firefox & Chromium/Chrome/Brave/Edge policies (`DnsOverHttpsMode=off`, `EncryptedClientHelloEnabled=false`), and inspects outbound DNS QNAMEs, TLS `ClientHello` SNI, and HTTP `Host` headers via fail-safe `NFQUEUE`.
- **Worldwide GeoIP & OpenSSL X.509 Attribution**: Maps connections across ~264k IPv4 and ~71k IPv6 RIR intervals, inspects allowed remote TLS certificates by IP, flags Non-US traffic on login, and attributes sockets to exact local `PID`, `PPID`, user, service, and binary.
- **Hardened System Layout**: Installs root-owned binaries to `/usr/local/lib/securepc`, configuration to `/etc/securepc`, RIR lists to `/var/lib/securepc`, and `0750` audit logs to `/var/log/securepc` with early-boot `systemd` persistence (`Before=network-pre.target`).

## Install

Requires Linux (or Solaris 11.4), `python3` (standard library only), `openssl`, and `iproute2`.

```bash
git clone https://github.com/CROWInnovations/SecurePC.git
cd SecurePC
sudo ./install.sh
```

## Usage (`securepc-ctl`)

```bash
securepc-ctl doctor                 # Verify firewall, daemon, NFQUEUE, policies & permissions
securepc-ctl status                 # View active backend, set counters & service status
securepc-ctl outbound               # View recent outbound internet connections
securepc-ctl non-us                 # View flagged Non-US connections
securepc-ctl blocked                # View blocked connection attempts
securepc-ctl lookup <TARGET>        # Attribute traffic by domain, IP, program, or PID
securepc-ctl cert <IP> [PORT]       # Inspect RIR GeoIP & OpenSSL X.509 certificate for an IP
securepc-ctl banner                 # Preview interactive login summary

sudo securepc-ctl allow <CIDR>      # Add IP/CIDR to /etc/securepc/allowlist-ips.txt
sudo securepc-ctl block <TARGET>    # Block custom IP/CIDR or domain suffix
sudo securepc-ctl ack               # Clear unread alert queues
sudo securepc-ctl update-lists      # Refresh RIR GeoIP & ASN CIDR lists
sudo securepc-ctl reload            # Reload firewall rules, policies & daemon
```

## Configuration

Edit `/etc/securepc/securepc.conf` (and `/etc/securepc/{allowlist-ips,blocklist-ips,blocklist-domains}.txt`), then run `sudo securepc-ctl reload`:

- `FIREWALL_BACKEND="auto"` (`auto`, `nftables`, `iptables`, `solaris_ipf`)
- `OUTBOUND_BLOCK_ACTION="reject"` (`reject` or `drop`)
- `ENABLE_IPV6="1"`
- `BLOCK_DOH_DOT="1"`
- `ENFORCE_BROWSER_POLICIES="1"`
- `ENABLE_NFQUEUE_DPI="1"`
- `ENABLE_OPENSSL_PROBES="1"`
- `SANDBOX_LAN_ONLY_USERS=""`

## Uninstall

```bash
./uninstall.sh --dry-run            # Preview removal steps
sudo ./uninstall.sh                 # Interactive uninstall
sudo ./uninstall.sh --yes --purge   # Remove services, rules, policies, configs & logs
```

## License

Copyright (C) 2026 [CROW Innovations](https://crowinnovations.com). Licensed under the [GNU General Public License v3.0](./LICENSE).

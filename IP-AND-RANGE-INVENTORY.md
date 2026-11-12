# SecurePC — Associated IPs, CIDR Ranges & Domain Inventory

This document catalogs the IP addresses, CIDR blocks, Autonomous System Numbers (ASNs), and domain signatures blocked by the `SecurePC` custom `iptables` chain profile.

## Summary Statistics

| Category | Custom Chain | `ipset` Table (v4 / v6) | Explicit `iptables` CIDRs | Total IPv4 CIDRs | Total IPv6 CIDRs |
| :--- | :--- | :--- | ---: | ---: | ---: |
| **Beijing Networks & Cloud (`cn-beijing`)** | `SECUREPC_BEIJING` | `securepc_beijing` | 443 | 443 | — |
| **`aliyuncs.com` / Alibaba Cloud** | `SECUREPC_ALIYUNCS` | `securepc_aliyuncs` | 114 | 114 | — |
| **China (`CN`, `.cn`, `.中国`)** | `SECUREPC_CN` / `SECUREPC_DOMAINS` | `securepc_cn_all` / `securepc6_cn_all` | 85 | 5,377 | 2,036 |
| **Russia (`RU`, `.ru`, `.su`, `.рф`)** | `SECUREPC_RU` / `SECUREPC_DOMAINS` | `securepc_ru_all` / `securepc6_ru_all` | 136 | 8,690 | 2,167 |
| **Iran (`IR`, `.ir`, `.ایران`)** | `SECUREPC_IR` / `SECUREPC_DOMAINS` | `securepc_ir_all` / `securepc6_ir_all` | 54 | 1,652 | 574 |
| **Middle East (`AE,BH,CY,EG,IL,IQ,JO,KW,LB,OM,PS,QA,SA,SY,TR,YE`)** | `SECUREPC_ME` / `SECUREPC_DOMAINS` | `securepc_me_all` / `securepc6_me_all` | — | 6,152 | 2,411 |
| **Dynamic TLS Cert / SNI Blocklist** | `dyn_blk_v4` / `dyn_blk_v6` | `securepc_dyn_blk` / `securepc6_dyn_blk` (1h TTL) | — | Dynamic | Dynamic |
| **Protected RFC1918 LAN & Custom Allowlist** | `lan_v4` / `custom_allow_v4` | `/etc/securepc/allowlist-ips.txt` | — | Configurable | Configurable |
| **Worldwide RIR GeoIP Lookup Database** | `securepc-monitor.service` | `lists/world-geoip-v4.tsv` / `v6.tsv` | — | 263,868 | 70,950 |

---

## 1. Beijing Associated ASNs & Core CIDR Ranges (`lists/beijing-cidrs.txt`)

### Covered Beijing Autonomous System Numbers (ASNs)
- **`AS4808`** — China Unicom Beijing Province Network (`CHINA169-BJ`) — 1,511 BGP prefixes collapsed
- **`AS4847`** — China Networks Inter-Exchange / China Telecom Beijing (`CNIX-AP`) — 867 BGP prefixes collapsed
- **`AS56046`** — China Mobile Communications Corporation Beijing (`CMNET-BEIJING`)
- **`AS17816`** — China Unicom IP Network China169 Beijing — 117 BGP prefixes
- **`AS24444`** — Beijing Gehua CATV Network Co., Ltd. — 1,161 BGP prefixes
- **`AS4538`** — China Education and Research Network Center (`CERNET` National Center, Tsinghua Univ., Beijing) — 3,508 BGP prefixes
- **`AS7497`** — Computer Network Information Center, Chinese Academy of Sciences (`CSTNET`, Beijing) — 466 BGP prefixes
- **`AS131477` / `AS24151`** — China Internet Network Information Center (`CNNIC` `.cn` TLD Registry, Beijing) — 51 BGP prefixes
- **`AS55967` / `AS38365`** — Beijing Baidu Netcom Science and Technology Co., Ltd. — 162 BGP prefixes
- **`AS138699`** — Beijing Volcano Engine Technology / ByteDance Beijing — 21 BGP prefixes
- **`AS58461`** — China Telecom Beijing IDC Network — 366 BGP prefixes
- **`AS59028` & `AS37963` (`cn-beijing`)** — Alibaba Cloud Computing Beijing Region

### Key Beijing Supernet CIDR Ranges
| CIDR Range | Organization / Network |
| :--- | :--- |
| `39.96.0.0/13` | Alibaba Cloud `cn-beijing` Region (`AS37963`) |
| `59.110.0.0/16` | Alibaba Cloud `cn-beijing` OSS/ECS (`oss-cn-beijing.aliyuncs.com`) |
| `60.205.0.0/16` | Alibaba Cloud `cn-beijing` Region (`AS37963`) |
| `61.48.0.0/13` | China Unicom Beijing (`AS4808`) |
| `61.135.0.0/16` | China Unicom Beijing IDC (`AS4808`) |
| `61.148.0.0/15` | China Unicom Beijing (`AS4808`) |
| `101.200.0.0/15` | Alibaba Cloud `cn-beijing` Region (`AS37963`) |
| `106.37.0.0/16` | China Telecom Beijing (`AS4847`) |
| `106.38.0.0/15` | China Telecom Beijing (`AS4847`) |
| `106.120.0.0/16` | China Unicom Beijing (`AS4808`) |
| `111.13.0.0/16` | China Mobile Beijing (`AS56046`) |
| `111.192.0.0/11` | China Unicom Beijing (`AS4808`) |
| `114.112.0.0/14` | Beijing Telecom / IDC (`AS4847`) |
| `114.240.0.0/12` | China Unicom Beijing (`AS4808`) |
| `118.186.0.0/15` | Beijing Gehua CATV (`AS24444`) |
| `123.56.0.0/15` | Alibaba Cloud `cn-beijing` Region (`AS37963`) |
| `123.112.0.0/12` | China Unicom Beijing (`AS4808`) |
| `124.64.0.0/15` | China Unicom Beijing (`AS4808`) |
| `124.126.0.0/15` | China Telecom Beijing (`AS4847`) |
| `124.200.0.0/13` | China Telecom Beijing (`AS4847`) |
| `159.226.0.0/16` | Chinese Academy of Sciences CSTNET Beijing (`AS7497`) |
| `162.105.0.0/16` | Peking University CERNET Beijing (`AS4538`) |
| `166.111.0.0/16` | Tsinghua University CERNET Beijing (`AS4538`) |
| `182.92.0.0/16` | Alibaba Cloud `cn-beijing` Region (`AS37963`) |
| `202.96.0.0/18` | China Telecom Beijing (`AS4847`) |
| `202.106.0.0/16` | China Unicom Beijing DNS & Backbone (`AS4808`) |
| `202.108.0.0/16` | China Unicom Beijing IDC (`AS4808`) |
| `202.112.0.0/14` | CERNET National Center Beijing (`AS4538`) |
| `210.72.0.0/13` | CSTNET / CNNIC Beijing (`AS7497`) |
| `218.240.0.0/13` | China Telecom Beijing (`AS4847`) |
| `219.232.0.0/13` | Beijing Municipal Networks (`AS4847`) |
| `220.181.0.0/16` | China Telecom Beijing / Baidu Beijing (`AS4847`/`AS55967`) |
| `221.122.0.0/15` | China Unicom Beijing (`AS4808`) |
| `221.130.0.0/16` | China Mobile Beijing (`AS56046`) |
| `221.179.0.0/16` | China Mobile Beijing (`AS56046`) |
| `221.216.0.0/13` | China Unicom Beijing (`AS4808`) |
| `222.128.0.0/14` | China Unicom Beijing (`AS4808`) |

*(See [`lists/beijing-cidrs.txt`](./lists/beijing-cidrs.txt) for all 462 CIDR ranges.)*

---

## 2. `aliyuncs.com` / Alibaba Cloud Associated ASNs, IPs & Ranges (`lists/aliyuncs-cidrs.txt`)

### Covered Alibaba Cloud ASNs
- **`AS37963`** — Hangzhou Alibaba Advertising Co., Ltd. (`aliyuncs.com` Core Domestic Cloud) — 738 BGP prefixes
- **`AS45102`** — Alibaba (US) Technology Co., Ltd. (`aliyuncs.com` International / Global Cloud) — 1,171 BGP prefixes
- **`AS134963`** — Alibaba Cloud Singapore / APAC Infrastructure — 260 BGP prefixes
- **`AS24429`** — Taobao China / Alibaba Cloud Infrastructure — 647 BGP prefixes
- **`AS59028`** — Alibaba Cloud Computing Beijing

### Key `aliyuncs.com` CIDR Blocks & Resolved Endpoints
| CIDR / IP | Description / Resolved Endpoint |
| :--- | :--- |
| `106.15.148.44/32` (`106.14.0.0/15`) | `aliyuncs.com` / `www.aliyuncs.com` |
| `59.110.190.88/32` (`59.110.0.0/16`) | `oss-cn-beijing.aliyuncs.com` |
| `39.96.213.166/32`, `39.96.198.249/32` (`39.96.0.0/13`) | `dashscope.aliyuncs.com` (`cn-beijing`) |
| `8.130.0.0/16`, `8.134.0.0/15`, `8.136.0.0/13`, `8.144.0.0/13`, `8.152.0.0/15` | Alibaba Cloud Computing & DashScope (`AS37963`) |
| `8.208.0.0/12` | Alibaba Cloud International (`AS45102`) |
| `47.52.0.0/15`, `47.56.0.0/15`, `47.74.0.0/15`, `47.76.0.0/14`, `47.88.0.0/13` | Alibaba Cloud Global / US / HK (`*.aliyuncs.com`, `AS45102`) |
| `47.92.0.0/14`, `47.96.0.0/11` | Alibaba Cloud Core China (`*.aliyuncs.com`, `AS37963`) |
| `47.240.0.0/12` | Alibaba Cloud International (`modelscope.cn` / `*.aliyuncs.com`, `AS45102`) |
| `101.37.0.0/16`, `101.132.0.0/15`, `101.200.0.0/15` | Alibaba Cloud Shanghai & Beijing (`AS37963`) |
| `112.124.0.0/14`, `114.55.0.0/16`, `115.28.0.0/15`, `116.62.0.0/16` | Alibaba Cloud Hangzhou & Qingdao (`AS37963`) |
| `118.31.0.0/16`, `118.178.0.0/16`, `120.24.0.0/14`, `120.55.0.0/16`, `120.76.0.0/14` | Alibaba Cloud Shenzhen & Hangzhou (`AS37963`) |
| `121.40.0.0/14`, `121.196.0.0/15`, `139.196.0.0/16`, `139.224.0.0/16` | Alibaba Cloud East China (`AS37963`) |
| `140.205.0.0/16`, `203.107.0.0/16` | Alibaba Cloud Corevip, Alidns (`dns.alidns.com`), NTP (`ntp.aliyun.com`) |

*(See [`lists/aliyuncs-cidrs.txt`](./lists/aliyuncs-cidrs.txt) for all 116 collapsed CIDR blocks and [`lists/resolved-target-ips.txt`](./lists/resolved-target-ips.txt) for all live-resolved endpoint IPs.)*

---

## 3. `.cn` TLD Infrastructure & APNIC China CIDR Ranges (`lists/cn-cidrs.txt` & `lists/cn-major-cidrs.txt`)

### Authoritative `.cn` Root Nameservers (CNNIC)
- `203.119.25.0/24` (`203.119.25.1` — `a.dns.cn`)
- `203.119.26.0/24` (`203.119.26.1` — `b.dns.cn`)
- `203.119.27.0/24` (`203.119.27.1` — `c.dns.cn`)
- `203.119.28.0/24` (`203.119.28.1` — `d.dns.cn`)
- `203.119.29.0/24` (`203.119.29.1` — `e.dns.cn`)
- `195.219.8.226/32` (`f.dns.cn`)
- `218.241.97.0/24` (`218.241.97.14` — `ns.cnnic.cn`)

### Master Files Reference
- **Master Consolidated List**: [`lists/all-blocked-ips-and-ranges.txt`](./lists/all-blocked-ips-and-ranges.txt)
- **Full APNIC `.cn` CIDR Table (5,384 blocks)**: [`lists/cn-cidrs.txt`](./lists/cn-cidrs.txt)
- **Major `.cn` Backbone & Registry Table (85 blocks)**: [`lists/cn-major-cidrs.txt`](./lists/cn-major-cidrs.txt)
- **Live-Resolved Domain IPs (90 endpoints)**: [`lists/resolved-target-ips.txt`](./lists/resolved-target-ips.txt)
- **Blocked Domain Patterns**: [`lists/blocked-domains.txt`](./lists/blocked-domains.txt)

#!/usr/bin/env python3
"""
SecurePC — Authoritative IP, CIDR Range & Worldwide GeoIP Builder
Author:  CROW Innovations (https://crowinnovations.com)
License: GNU General Public License v3.0 (GPL-3.0)
GitHub:  https://github.com/CROWInnovations/SecurePC

Collects, validates, aggregates, and documents all IPv4/IPv6 addresses and CIDR blocks
associated with:
  1. HARD-BLOCKED REGIONS:
     - Beijing (ISPs, municipal networks, universities, data centers, cloud regions)
     - aliyuncs.com / Alibaba Cloud (AS37963, AS45102, AS134963, AS59028, AS24429 + live DNS)
     - .cn TLD & China National Allocations (CNNIC root DNS, major .cn domains, APNIC CN CIDRs)
     - .ru / .su / .рф TLD & Russian Federation Allocations (RIPE RU CIDRs & core ASNs)
     - .ir / .ایران TLD & Iran Allocations (RIPE IR CIDRs & Iranian telecom/cloud ASNs)
     - Middle East Allocations (AE, BH, CY, EG, IL, IQ, JO, KW, LB, OM, PS, QA, SA, SY, TR, YE)
  2. WORLDWIDE GEOIP & NON-US DETECTION TABLES:
     - United States CIDR lists (us-cidrs.txt, us-ipv6-cidrs.txt)
     - Flattened longest-prefix-match Worldwide RIR GeoIP tables (world-geoip-v4.tsv, world-geoip-v6.tsv)
       for microsecond country identification of all ~240 ISO-3166 countries/territories.
"""

import io
import ipaddress
import json
import os
import subprocess
import tarfile
import urllib.request
from datetime import datetime, timezone

import sys

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if "--lists-dir" in sys.argv:
    _idx = sys.argv.index("--lists-dir")
    LISTS_DIR = sys.argv[_idx + 1] if _idx + 1 < len(sys.argv) else os.path.join(BASE_DIR, "lists")
elif os.geteuid() == 0 and os.path.isdir("/var/lib/securepc"):
    LISTS_DIR = "/var/lib/securepc/lists"
else:
    LISTS_DIR = os.path.join(BASE_DIR, "lists")
CONF_DIR = "/etc/securepc" if os.path.isdir("/etc/securepc") else os.path.join(BASE_DIR, "etc")
os.makedirs(LISTS_DIR, exist_ok=True)

MIDDLE_EAST_COUNTRIES = {
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
}

# ASNs for Beijing networks
BEIJING_ASNS = {
    "AS4808": "China Unicom Beijing Province Network (CHINA169-BJ)",
    "AS4847": "China Networks Inter-Exchange / China Telecom Beijing (CNIX-AP)",
    "AS56046": "China Mobile Communications Corporation Beijing (CMNET-BEIJING)",
    "AS17816": "China Unicom IP Network China169 Beijing",
    "AS24444": "Beijing Gehua CATV Network Co., Ltd.",
    "AS4538": "China Education and Research Network Center (CERNET - Beijing)",
    "AS7497": "Computer Network Information Center, Chinese Academy of Sciences (CSTNET - Beijing)",
    "AS131477": "China Internet Network Information Center (CNNIC - Beijing)",
    "AS24151": "China Internet Network Information Center (CNNIC TLD Registry - Beijing)",
    "AS55967": "Beijing Baidu Netcom Science and Technology Co., Ltd.",
    "AS38365": "Beijing Baidu Netcom Science and Technology Co., Ltd. (Core)",
    "AS138699": "Beijing Volcano Engine Technology / ByteDance Beijing",
    "AS58461": "China Telecom Beijing IDC Network",
    "AS59028": "Alibaba Cloud Computing Ltd. (Beijing)",
}

# ASNs for Alibaba Cloud / aliyuncs.com
ALIYUNCS_ASNS = {
    "AS37963": "Hangzhou Alibaba Advertising Co., Ltd. (Alibaba Cloud China / aliyuncs.com Core)",
    "AS45102": "Alibaba (US) Technology Co., Ltd. (Alibaba Cloud Global / aliyuncs.com Intl)",
    "AS134963": "Alibaba Cloud Singapore / APAC Infrastructure",
    "AS59028": "Alibaba Cloud Computing Ltd. (Beijing Region)",
    "AS24429": "Taobao China / Alibaba Cloud Infrastructure",
}

# ASNs for Russian Federation (.ru) core networks, state telecoms & cloud providers
RU_ASNS = {
    "AS12389": "PJSC Rostelecom (Russian National Telecom Backbone)",
    "AS8359": "MTS PJSC (Mobile TeleSystems Russia)",
    "AS3216": "PJSC VimpelCom (Beeline Russia)",
    "AS31133": "PJSC MegaFon (Russia Backbone)",
    "AS13238": "Yandex LLC (Yandex Cloud & Core RU)",
    "AS47764": "VK Company / Mail.Ru LLC",
    "AS49505": "Selectel Ltd. (Moscow/St. Petersburg Data Centers)",
    "AS20485": "JSC TransTeleCom (TTK Russia Backbone)",
    "AS197695": "Domain Names Registrar REG.RU Ltd.",
    "AS25513": "PJSC Moscow City Telephone Network (MGTS)",
    "AS42610": "PJSC Rostelecom Moscow Broadband (NBN)",
}

# ASNs for Iran (.ir) national backbone, mobile operators & cloud providers
IR_ASNS = {
    "AS12880": "Information Technology Company (DCI / Iran National Backbone)",
    "AS48159": "Telecommunication Infrastructure Company (TIC Iran Gateway)",
    "AS58224": "Iran Telecommunication Company PJS (TCI)",
    "AS44244": "Iran Cell Service and Communication Company (Irancell)",
    "AS197207": "Mobile Communication Company of Iran PLC (MCCI)",
    "AS205588": "Noyan Abr Arvan Co. (ArvanCloud Iran)",
    "AS31549": "Aria Shatel PJSC (Iran)",
    "AS16322": "Pars Online PJS (Iran)",
}

BEIJING_DOMAINS = [
    "beijing.gov.cn",
    "www.beijing.gov.cn",
    "oss-cn-beijing.aliyuncs.com",
    "ecs.cn-beijing.aliyuncs.com",
    "rds.cn-beijing.aliyuncs.com",
    "slb.cn-beijing.aliyuncs.com",
    "cr.cn-beijing.aliyuncs.com",
    "registry.cn-beijing.aliyuncs.com",
    "log.cn-beijing.aliyuncs.com",
    "tsinghua.edu.cn",
    "www.tsinghua.edu.cn",
    "pku.edu.cn",
    "www.pku.edu.cn",
    "cas.cn",
    "www.cas.cn",
    "cnnic.cn",
    "www.cnnic.cn",
    "baidu.com",
]

ALIYUNCS_DOMAINS = [
    "aliyuncs.com",
    "www.aliyuncs.com",
    "aliyun.com",
    "www.aliyun.com",
    "oss-cn-beijing.aliyuncs.com",
    "oss-cn-hangzhou.aliyuncs.com",
    "oss-cn-shanghai.aliyuncs.com",
    "oss-cn-shenzhen.aliyuncs.com",
    "oss-cn-qingdao.aliyuncs.com",
    "oss-cn-zhangjiakou.aliyuncs.com",
    "oss-cn-chengdu.aliyuncs.com",
    "oss-cn-hongkong.aliyuncs.com",
    "oss-ap-southeast-1.aliyuncs.com",
    "oss-us-west-1.aliyuncs.com",
    "oss-us-east-1.aliyuncs.com",
    "ecs.aliyuncs.com",
    "ecs.cn-beijing.aliyuncs.com",
    "rds.aliyuncs.com",
    "slb.aliyuncs.com",
    "sts.aliyuncs.com",
    "ram.aliyuncs.com",
    "kms.aliyuncs.com",
    "log.aliyuncs.com",
    "dashscope.aliyuncs.com",
    "cr.cn-beijing.aliyuncs.com",
    "registry.cn-hangzhou.aliyuncs.com",
    "mirrors.aliyun.com",
    "ntp.aliyun.com",
    "dns.alidns.com",
]

CN_DOMAINS = [
    "a.dns.cn",
    "b.dns.cn",
    "c.dns.cn",
    "d.dns.cn",
    "e.dns.cn",
    "f.dns.cn",
    "g.dns.cn",
    "ns.cnnic.cn",
    "gov.cn",
    "www.gov.cn",
    "baidu.cn",
    "www.baidu.cn",
    "modelscope.cn",
    "www.modelscope.cn",
    "sina.com.cn",
    "www.sina.com.cn",
    "people.com.cn",
    "www.people.com.cn",
    "xinhuanet.com",
    "chinadaily.com.cn",
    "tsinghua.edu.cn",
    "pku.edu.cn",
    "cas.cn",
    "cnnic.cn",
    "aliyun.cn",
]

RU_DOMAINS = [
    "a.dns.ripn.net",
    "b.dns.ripn.net",
    "d.dns.ripn.net",
    "e.dns.ripn.net",
    "f.dns.ripn.net",
    "ya.ru",
    "yandex.ru",
    "www.yandex.ru",
    "mail.ru",
    "www.mail.ru",
    "vk.ru",
    "rambler.ru",
    "sberbank.ru",
    "rt.ru",
    "rostelecom.ru",
    "selectel.ru",
    "reg.ru",
    "timeweb.ru",
    "kaspersky.ru",
    "gosuslugi.ru",
    "kremlin.ru",
    "gov.ru",
    "mil.ru",
    "cbr.ru",
    "tass.ru",
    "ria.ru",
    "rbc.ru",
]

IR_DOMAINS = [
    "a.nic.ir",
    "b.nic.ir",
    "c.nic.ir",
    "d.nic.ir",
    "nic.ir",
    "irnic.ir",
    "gov.ir",
    "leader.ir",
    "president.ir",
    "irna.ir",
    "isna.ir",
    "mehrnews.com",
    "farsnews.ir",
    "aparat.com",
    "digikala.com",
    "arvancloud.ir",
]

FALLBACK_IR_ROOT_CIDRS = [
    ("193.189.122.0/23", "IRNIC .ir Root DNS & Registry"),
    ("2.144.0.0/14", "TCI Iran Telecommunication Backbone (AS58224)"),
    ("2.176.0.0/12", "TCI Iran Telecommunication Backbone (AS58224)"),
    ("5.22.0.0/17", "Iranian Allocation"),
    ("5.52.0.0/16", "DCI / TCI Iran (AS12880)"),
    ("5.106.0.0/16", "Irancell Mobile Iran (AS44244)"),
    ("5.112.0.0/13", "MCCI Mobile Iran (AS197207)"),
    ("5.120.0.0/13", "MCCI / Irancell Iran"),
    ("5.160.0.0/14", "Respina / Iran IDC"),
    ("5.200.0.0/14", "TCI Iran (AS58224)"),
    ("5.232.0.0/13", "Iranian ISP Allocations"),
    ("31.2.128.0/17", "Irancell Iran (AS44244)"),
    ("37.32.0.0/16", "ArvanCloud / Iran Data Centers"),
    ("37.98.0.0/16", "Irancell Iran (AS44244)"),
    ("37.156.0.0/16", "ParsOnline / Iran"),
    ("37.254.0.0/15", "TCI / MCCI Iran"),
    ("46.100.0.0/15", "Shatel / Iran ISP"),
    ("46.224.0.0/15", "TCI Iran"),
    ("78.38.0.0/15", "Asiatech / DCI Iran (AS12880)"),
    ("79.127.0.0/17", "DCI Iran (AS12880)"),
    ("80.191.0.0/16", "DCI Iran (AS12880)"),
    ("85.15.0.0/16", "Shatel Iran (AS31549)"),
    ("85.185.0.0/16", "DCI Iran (AS12880)"),
    ("89.196.0.0/15", "MCCI / TCI Iran"),
    ("91.98.0.0/15", "ParsOnline Iran (AS16322)"),
    ("91.251.0.0/16", "Iran Allocation"),
    ("93.112.0.0/12", "Iran Telecom / Mobile Allocations"),
    ("94.182.0.0/15", "Shatel / Asiatech Iran"),
    ("151.232.0.0/13", "TCI Iran National Allocation (AS58224)"),
    ("178.131.0.0/16", "TCI Iran"),
    ("185.143.232.0/22", "ArvanCloud CDN Iran (AS205588)"),
    ("188.158.0.0/15", "TCI Iran (AS58224)"),
    ("188.208.0.0/13", "Irancell / Shatel Iran"),
    ("217.218.0.0/15", "DCI / TIC Iran National Gateway (AS12880/AS48159)"),
]

FALLBACK_RU_ROOT_CIDRS = [
    ("193.232.128.0/24", "RIPN / TCInet .ru Root DNS a.dns.ripn.net"),
    ("194.85.252.0/23", "RIPN / TCInet .ru Root DNS b.dns.ripn.net"),
    ("194.190.124.0/24", "RIPN / TCInet .ru Root DNS d.dns.ripn.net"),
    ("193.232.142.0/24", "RIPN / TCInet .ru Root DNS e.dns.ripn.net"),
    ("193.232.156.0/24", "RIPN / TCInet .ru Root DNS f.dns.ripn.net"),
    ("5.45.192.0/18", "Yandex LLC Core RU (AS13238)"),
    ("5.255.192.0/18", "Yandex LLC Core RU (AS13238)"),
    ("37.9.64.0/18", "Yandex LLC RU (AS13238)"),
    ("37.140.128.0/18", "REG.RU Hosting Russia (AS197695)"),
    ("46.17.40.0/21", "Moscow Data Center Allocation"),
    ("46.36.216.0/21", "Russian Federation Allocation"),
    ("77.37.128.0/17", "Rostelecom Moscow (AS12389)"),
    ("77.88.0.0/18", "Yandex LLC DNS & Search RU (AS13238)"),
    ("78.106.0.0/15", "VimpelCom Beeline Russia (AS3216)"),
    ("79.104.0.0/15", "Rostelecom Russia (AS12389)"),
    ("79.137.128.0/17", "VK / Mail.Ru Russia (AS47764)"),
    ("80.240.208.0/20", "Rostelecom Russia (AS12389)"),
    ("81.19.64.0/19", "Rambler / Moscow IDC"),
    ("83.166.96.0/19", "MTS Russia (AS8359)"),
    ("83.220.224.0/19", "MegaFon Russia (AS31133)"),
    ("85.21.0.0/16", "VimpelCom Corbina Moscow (AS3216)"),
    ("85.26.160.0/19", "MegaFon Russia (AS31133)"),
    ("87.240.128.0/18", "VK / VKontakte Russia (AS47764)"),
    ("87.250.224.0/19", "Yandex LLC Russia (AS13238)"),
    ("89.108.64.0/18", "Agava / REG.RU Moscow"),
    ("89.175.0.0/16", "Rostelecom Russia (AS12389)"),
    ("90.154.0.0/15", "Rostelecom Russia (AS12389)"),
    ("91.108.4.0/22", "Russian Allocation"),
    ("92.53.64.0/18", "Timeweb St. Petersburg (AS9123)"),
    ("93.158.128.0/18", "Yandex LLC Russia (AS13238)"),
    ("94.19.0.0/16", "Rostelecom North-West Russia (AS12389)"),
    ("94.25.0.0/16", "MegaFon Russia (AS31133)"),
    ("94.100.176.0/20", "Mail.Ru / VK Russia (AS47764)"),
    ("95.30.0.0/15", "VimpelCom Russia (AS3216)"),
    ("95.108.128.0/17", "Yandex LLC Russia (AS13238)"),
    ("95.163.0.0/16", "VK / Mail.Ru Cloud Russia (AS47764)"),
    ("95.213.0.0/16", "Selectel Russia (AS49505)"),
    ("109.207.0.0/17", "Rostelecom Russia (AS12389)"),
    ("176.59.0.0/16", "Tele2 / Rostelecom Russia"),
    ("178.154.128.0/17", "Yandex Cloud Russia (AS13238)"),
    ("178.248.232.0/21", "Selectel Russia (AS49505)"),
    ("185.71.76.0/22", "VK Russia (AS47764)"),
    ("188.43.0.0/16", "Rostelecom Russia (AS12389)"),
    ("188.120.224.0/19", "FirstVDS / Moscow IDC"),
    ("188.170.0.0/16", "Yota / MegaFon Russia (AS31133)"),
    ("195.208.0.0/17", "RELARN / RIPN Russian Academic & TLD Network"),
    ("212.192.0.0/16", "Russian Science & Academic Network"),
    ("213.59.0.0/16", "Rostelecom Russia (AS12389)"),
    ("213.87.0.0/16", "MTS Russia (AS8359)"),
    ("213.180.192.0/19", "Yandex LLC Core Russia (AS13238)"),
    ("217.20.144.0/20", "Odnoklassniki / VK Russia (AS47764)"),
    ("217.69.128.0/20", "Mail.Ru Core Russia (AS47764)"),
    ("217.106.0.0/15", "Rostelecom Russia (AS12389)"),
]

FALLBACK_BEIJING_CIDRS = [
    ("61.48.0.0/13", "China Unicom Beijing (AS4808)"),
    ("61.135.0.0/16", "China Unicom Beijing IDC (AS4808)"),
    ("61.148.0.0/15", "China Unicom Beijing (AS4808)"),
    ("106.37.0.0/16", "China Telecom Beijing (AS4847)"),
    ("106.38.0.0/15", "China Telecom Beijing (AS4847)"),
    ("106.120.0.0/16", "China Unicom Beijing (AS4808)"),
    ("111.13.0.0/16", "China Mobile Beijing (AS56046)"),
    ("111.192.0.0/11", "China Unicom Beijing (AS4808)"),
    ("114.112.0.0/14", "Beijing Telecom / IDC (AS4847)"),
    ("114.240.0.0/12", "China Unicom Beijing (AS4808)"),
    ("118.186.0.0/15", "Beijing Gehua CATV (AS24444)"),
    ("119.253.0.0/16", "CNNIC / Beijing IDC"),
    ("123.112.0.0/12", "China Unicom Beijing (AS4808)"),
    ("124.64.0.0/15", "China Unicom Beijing (AS4808)"),
    ("124.126.0.0/15", "China Telecom Beijing (AS4847)"),
    ("124.193.0.0/16", "Beijing Telecom (AS4847)"),
    ("124.200.0.0/13", "China Telecom Beijing (AS4847)"),
    ("159.226.0.0/16", "Chinese Academy of Sciences CSTNET Beijing (AS7497)"),
    ("166.111.0.0/16", "Tsinghua University CERNET Beijing (AS4538)"),
    ("162.105.0.0/16", "Peking University CERNET Beijing (AS4538)"),
    ("202.96.0.0/18", "China Telecom Beijing (AS4847)"),
    ("202.106.0.0/16", "China Unicom Beijing (AS4808)"),
    ("202.108.0.0/16", "China Unicom Beijing IDC (AS4808)"),
    ("202.112.0.0/14", "CERNET National Center Beijing (AS4538)"),
    ("210.72.0.0/13", "CSTNET / CNNIC Beijing (AS7497)"),
    ("211.99.0.0/16", "China Unicom Beijing (AS4808)"),
    ("211.100.0.0/15", "China Telecom Beijing (AS4847)"),
    ("218.240.0.0/13", "China Telecom Beijing (AS4847)"),
    ("219.141.128.0/17", "China Telecom Beijing (AS4847)"),
    ("219.232.0.0/13", "Beijing Municipal Networks (AS4847)"),
    ("220.181.0.0/16", "China Telecom Beijing / Baidu Beijing (AS4847/AS55967)"),
    ("221.122.0.0/15", "China Unicom Beijing (AS4808)"),
    ("221.130.0.0/16", "China Mobile Beijing (AS56046)"),
    ("221.179.0.0/16", "China Mobile Beijing (AS56046)"),
    ("221.216.0.0/13", "China Unicom Beijing (AS4808)"),
    ("222.128.0.0/14", "China Unicom Beijing (AS4808)"),
    ("39.96.0.0/13", "Alibaba Cloud cn-beijing Region (AS37963)"),
    ("59.110.0.0/16", "Alibaba Cloud cn-beijing Region (AS37963)"),
    ("60.205.0.0/16", "Alibaba Cloud cn-beijing Region (AS37963)"),
    ("101.200.0.0/15", "Alibaba Cloud cn-beijing Region (AS37963)"),
    ("123.56.0.0/15", "Alibaba Cloud cn-beijing Region (AS37963)"),
    ("182.92.0.0/16", "Alibaba Cloud cn-beijing Region (AS37963)"),
]

FALLBACK_ALIYUNCS_CIDRS = [
    ("8.130.0.0/16", "Alibaba Cloud Computing (AS37963)"),
    ("8.134.0.0/15", "Alibaba Cloud Computing (AS37963)"),
    ("8.136.0.0/13", "Alibaba Cloud Computing (AS37963)"),
    ("8.144.0.0/13", "Alibaba Cloud Computing (AS37963)"),
    ("8.152.0.0/15", "Alibaba Cloud Computing / DashScope (AS37963)"),
    ("8.208.0.0/12", "Alibaba Cloud International (AS45102)"),
    ("39.96.0.0/13", "Alibaba Cloud cn-beijing / China (AS37963)"),
    ("39.104.0.0/14", "Alibaba Cloud China (AS37963)"),
    ("47.52.0.0/15", "Alibaba Cloud Hong Kong / APAC (AS45102)"),
    ("47.56.0.0/15", "Alibaba Cloud APAC (AS45102)"),
    ("47.74.0.0/15", "Alibaba Cloud Global (AS45102)"),
    ("47.76.0.0/14", "Alibaba Cloud Global (AS45102)"),
    ("47.88.0.0/13", "Alibaba Cloud US / Global (AS45102)"),
    ("47.92.0.0/14", "Alibaba Cloud cn-beijing / China (AS37963)"),
    ("47.96.0.0/11", "Alibaba Cloud Core China (AS37963)"),
    ("47.240.0.0/12", "Alibaba Cloud International (AS45102)"),
    ("59.110.0.0/16", "Alibaba Cloud cn-beijing OSS/ECS (AS37963)"),
    ("60.205.0.0/16", "Alibaba Cloud cn-beijing (AS37963)"),
    ("101.37.0.0/16", "Alibaba Cloud China (AS37963)"),
    ("101.132.0.0/15", "Alibaba Cloud Shanghai (AS37963)"),
    ("101.200.0.0/15", "Alibaba Cloud Beijing (AS37963)"),
    ("106.14.0.0/15", "Alibaba Cloud aliyuncs.com Core (AS37963)"),
    ("112.124.0.0/14", "Alibaba Cloud Hangzhou (AS37963)"),
    ("114.55.0.0/16", "Alibaba Cloud Hangzhou (AS37963)"),
    ("115.28.0.0/15", "Alibaba Cloud Qingdao (AS37963)"),
    ("116.62.0.0/16", "Alibaba Cloud Hangzhou (AS37963)"),
    ("118.31.0.0/16", "Alibaba Cloud China (AS37963)"),
    ("118.178.0.0/16", "Alibaba Cloud China (AS37963)"),
    ("120.24.0.0/14", "Alibaba Cloud Shenzhen (AS37963)"),
    ("120.55.0.0/16", "Alibaba Cloud Hangzhou (AS37963)"),
    ("120.76.0.0/14", "Alibaba Cloud Shenzhen (AS37963)"),
    ("121.40.0.0/14", "Alibaba Cloud Hangzhou (AS37963)"),
    ("121.196.0.0/15", "Alibaba Cloud Hangzhou (AS37963)"),
    ("123.56.0.0/15", "Alibaba Cloud Beijing (AS37963)"),
    ("139.196.0.0/16", "Alibaba Cloud Shanghai (AS37963)"),
    ("139.224.0.0/16", "Alibaba Cloud Shanghai (AS37963)"),
    ("140.205.0.0/16", "Alibaba / Aliyun Core DNS & CDN (AS37963)"),
    ("182.92.0.0/16", "Alibaba Cloud Beijing (AS37963)"),
    ("203.107.0.0/16", "Alibaba Cloud DNS / NTP Services (AS37963)"),
]

FALLBACK_CN_ROOT_CIDRS = [
    ("203.119.25.0/24", "CNNIC .cn Root Nameserver a.dns.cn"),
    ("203.119.26.0/24", "CNNIC .cn Root Nameserver b.dns.cn"),
    ("203.119.27.0/24", "CNNIC .cn Root Nameserver c.dns.cn"),
    ("203.119.28.0/24", "CNNIC .cn Root Nameserver d.dns.cn"),
    ("203.119.29.0/24", "CNNIC .cn Root Nameserver e.dns.cn"),
    ("195.219.8.226/32", "CNNIC .cn Root Nameserver f.dns.cn"),
    ("218.241.97.0/24", "CNNIC .cn Registry ns.cnnic.cn"),
    ("1.0.1.0/24", "APNIC China Telecom Allocation"),
    ("1.2.0.0/22", "APNIC China Allocation"),
    ("1.12.0.0/14", "APNIC China Allocation"),
    ("1.24.0.0/13", "APNIC China Unicom Allocation"),
    ("14.0.0.0/8", "China Telecom / China Backbone Allocations"),
    ("27.8.0.0/13", "China Unicom Allocation"),
    ("27.16.0.0/12", "China Telecom Allocation"),
    ("27.148.0.0/14", "China Telecom Allocation"),
    ("27.184.0.0/13", "China Unicom Allocation"),
    ("36.0.0.0/10", "China Telecom Allocation"),
    ("36.96.0.0/11", "China Mobile Allocation"),
    ("39.64.0.0/11", "China Unicom Allocation"),
    ("39.128.0.0/10", "China Mobile Allocation"),
    ("42.48.0.0/12", "China Telecom Allocation"),
    ("42.80.0.0/13", "China Unicom Allocation"),
    ("42.120.0.0/14", "Alibaba / China Allocation"),
    ("49.64.0.0/11", "China Telecom Allocation"),
    ("58.16.0.0/12", "China Unicom / Telecom Allocation"),
    ("58.32.0.0/11", "China Telecom Allocation"),
    ("58.192.0.0/11", "CERNET China Education Network"),
    ("58.240.0.0/12", "China Unicom Allocation"),
    ("59.32.0.0/11", "China Telecom Allocation"),
    ("59.64.0.0/13", "CERNET China Education Network"),
    ("60.0.0.0/11", "China Unicom Allocation"),
    ("60.160.0.0/11", "China Telecom Allocation"),
    ("101.64.0.0/11", "China Telecom / CERNET Allocation"),
    ("101.80.0.0/12", "China Telecom Allocation"),
    ("106.0.0.0/10", "China Telecom / Baidu / Aliyun Allocation"),
    ("110.64.0.0/13", "CERNET China Education Network"),
    ("110.80.0.0/13", "China Telecom Allocation"),
    ("111.0.0.0/10", "China Mobile National Allocation"),
    ("112.0.0.0/10", "China Mobile / Unicom Allocation"),
    ("113.0.0.0/11", "China Telecom Allocation"),
    ("113.64.0.0/10", "China Telecom Allocation"),
    ("114.80.0.0/12", "China Telecom Shanghai/National"),
    ("114.216.0.0/13", "China Telecom Allocation"),
    ("115.24.0.0/13", "CERNET / Aliyun China"),
    ("115.192.0.0/11", "China Telecom Allocation"),
    ("116.0.0.0/11", "China Telecom / Unicom Allocation"),
    ("117.8.0.0/13", "China Unicom Allocation"),
    ("117.64.0.0/11", "China Telecom Allocation"),
    ("117.128.0.0/10", "China Mobile Allocation"),
    ("119.0.0.0/11", "China Unicom / Telecom Allocation"),
    ("119.112.0.0/12", "China Unicom Allocation"),
    ("120.192.0.0/10", "China Mobile National Allocation"),
    ("121.0.0.0/12", "China Telecom Allocation"),
    ("121.16.0.0/12", "China Unicom Allocation"),
    ("122.64.0.0/11", "China Unicom Allocation"),
    ("123.128.0.0/11", "China Unicom Allocation"),
    ("125.32.0.0/12", "China Unicom Allocation"),
    ("125.64.0.0/11", "China Telecom Allocation"),
    ("175.0.0.0/12", "China Telecom Allocation"),
    ("180.96.0.0/11", "China Telecom Allocation"),
    ("180.152.0.0/13", "China Telecom Allocation"),
    ("182.128.0.0/11", "China Telecom Allocation"),
    ("183.0.0.0/10", "China Telecom National Allocation"),
    ("183.192.0.0/10", "China Mobile National Allocation"),
    ("218.0.0.0/11", "China Telecom / Unicom Allocation"),
    ("218.64.0.0/11", "China Telecom Allocation"),
    ("219.128.0.0/11", "China Telecom Allocation"),
    ("220.160.0.0/11", "China Telecom Allocation"),
    ("221.0.0.0/12", "China Unicom Allocation"),
    ("221.192.0.0/10", "China Unicom National Allocation"),
    ("222.64.0.0/11", "China Telecom Allocation"),
    ("223.64.0.0/11", "China Mobile National Allocation"),
]

PROTECTED_CIDRS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("8.8.8.8/32"),
    ipaddress.ip_network("8.8.4.4/32"),
    ipaddress.ip_network("1.1.1.1/32"),
    ipaddress.ip_network("1.0.0.1/32"),
]

PROTECTED_CIDRS_V6 = [
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("2001:4860:4860::8888/128"),
    ipaddress.ip_network("2001:4860:4860::8844/128"),
    ipaddress.ip_network("2606:4700:4700::1111/128"),
    ipaddress.ip_network("2606:4700:4700::1001/128"),
]

for fname in [
    os.path.join(CONF_DIR, "allowlist-ips.txt"),
]:
    if os.path.exists(fname):
        with open(fname, "r") as f:
            for line in f:
                line = line.split("#", 1)[0].strip()
                if not line:
                    continue
                token = line.split()[0]
                try:
                    n = ipaddress.ip_network(token, strict=False)
                    if n.version == 4:
                        PROTECTED_CIDRS.append(n)
                    else:
                        PROTECTED_CIDRS_V6.append(n)
                except ValueError:
                    pass


def is_protected(net: ipaddress.IPv4Network) -> bool:
    for p in PROTECTED_CIDRS:
        if net.overlaps(p):
            return True
    return False


def is_protected_v6(net: ipaddress.IPv6Network) -> bool:
    for p in PROTECTED_CIDRS_V6:
        if net.overlaps(p):
            return True
    return False


def fetch_ripe_asn_prefixes(asn: str) -> list[ipaddress.IPv4Network]:
    url = f"https://stat.ripe.net/data/announced-prefixes/data.json?resource={asn}"
    nets = []
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "SecurePC-Builder/2.0"})
        with urllib.request.urlopen(req, timeout=8) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            for item in data.get("data", {}).get("prefixes", []):
                prefix = item.get("prefix", "")
                if ":" in prefix:
                    continue
                try:
                    net = ipaddress.ip_network(prefix, strict=False)
                    if not is_protected(net):
                        nets.append(net)
                except ValueError:
                    pass
    except Exception as e:
        print(f"[WARN] RIPEstat fetch for {asn} returned error: {e}")
    return nets


def resolve_domains(domains: list[str]) -> dict[str, list[str]]:
    resolved = {}
    for dom in domains:
        ips = set()
        try:
            res = subprocess.run(
                ["getent", "ahostsv4", dom],
                capture_output=True,
                text=True,
                timeout=4,
            )
            for line in res.stdout.splitlines():
                parts = line.split()
                if parts:
                    ip_str = parts[0]
                    try:
                        net = ipaddress.ip_network(f"{ip_str}/32")
                        if not is_protected(net):
                            ips.add(ip_str)
                    except ValueError:
                        pass
        except Exception:
            pass
        if ips:
            resolved[dom] = sorted(ips)
    return resolved


def fetch_all_country_zones_v4() -> dict[str, list[ipaddress.IPv4Network]]:
    """Download all ~240 RIR country IPv4 CIDR zones in a single compressed archive."""
    url = "https://www.ipdeny.com/ipblocks/data/countries/all-zones.tar.gz"
    country_nets: dict[str, list[ipaddress.IPv4Network]] = {}
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "SecurePC-Builder/2.0"})
        with urllib.request.urlopen(req, timeout=25) as resp:
            raw = resp.read()
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as tf:
            for member in tf.getmembers():
                if not member.name.endswith(".zone"):
                    continue
                cc = os.path.basename(member.name)[:-5].upper()
                if cc == "ZZ":
                    # Skip IANA unallocated/superblock placeholder file
                    continue
                fobj = tf.extractfile(member)
                if not fobj:
                    continue
                nets = []
                for line in fobj.read().decode("utf-8", errors="replace").splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    try:
                        nets.append(ipaddress.ip_network(line, strict=False))
                    except ValueError:
                        pass
                if nets:
                    country_nets[cc] = nets
    except Exception as e:
        print(f"[WARN] Failed to fetch all-zones.tar.gz: {e}")
    return country_nets


def fetch_all_country_zones_v6() -> dict[str, list[ipaddress.IPv6Network]]:
    """Download all RIR country IPv6 CIDR zones in a single compressed archive."""
    url = "https://www.ipdeny.com/ipv6/ipaddresses/blocks/ipv6-all-zones.tar.gz"
    country_nets: dict[str, list[ipaddress.IPv6Network]] = {}
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "SecurePC-Builder/2.0"})
        with urllib.request.urlopen(req, timeout=25) as resp:
            raw = resp.read()
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as tf:
            for member in tf.getmembers():
                if not member.name.endswith(".zone"):
                    continue
                cc = os.path.basename(member.name)[:-5].upper()
                if cc == "ZZ":
                    continue
                fobj = tf.extractfile(member)
                if not fobj:
                    continue
                nets = []
                for line in fobj.read().decode("utf-8", errors="replace").splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    try:
                        nets.append(ipaddress.ip_network(line, strict=False))
                    except ValueError:
                        pass
                if nets:
                    country_nets[cc] = nets
    except Exception as e:
        print(f"[WARN] Failed to fetch ipv6-all-zones.tar.gz: {e}")
    return country_nets


def flatten_nested_cidr_intervals(country_nets: dict) -> list[tuple[int, int, str, str]]:
    """
    Flatten nested binary CIDR allocations across all countries into sorted, disjoint
    (start_int, end_int, country_code, cidr_str) segments where longest-prefix match wins
    and specific ISO countries take precedence over regional 'EU'/'AP' blocks.
    """
    by_range: dict[tuple[int, int], tuple[str, str]] = {}
    for cc, nets in country_nets.items():
        is_generic = cc in ("EU", "AP")
        for n in nets:
            s = int(n.network_address)
            e = int(n.broadcast_address)
            key = (s, e)
            if key not in by_range:
                by_range[key] = (cc, str(n))
            else:
                prev_cc, _ = by_range[key]
                if prev_cc in ("EU", "AP") and not is_generic:
                    by_range[key] = (cc, str(n))

    # Sort outer intervals before inner intervals: (start ASC, end DESC)
    raw_items = sorted(by_range.items(), key=lambda kv: (kv[0][0], -kv[0][1]))

    stack = []  # [cur_pos, end, cc, cidr_str]
    emitted: list[tuple[int, int, str, str]] = []

    def push_emitted(s_val: int, e_val: int, cc_val: str, cidr_val: str):
        if s_val > e_val:
            return
        if emitted and emitted[-1][2] == cc_val and emitted[-1][3] == cidr_val and emitted[-1][1] + 1 == s_val:
            prev_s, _, _, _ = emitted.pop()
            emitted.append((prev_s, e_val, cc_val, cidr_val))
        else:
            emitted.append((s_val, e_val, cc_val, cidr_val))

    for (s, e), (cc, cidr_s) in raw_items:
        while stack and stack[-1][1] < s:
            top_cur, top_end, top_cc, top_cidr = stack.pop()
            push_emitted(top_cur, top_end, top_cc, top_cidr)
            if stack:
                stack[-1][0] = max(stack[-1][0], top_end + 1)

        if stack:
            if stack[-1][0] < s:
                push_emitted(stack[-1][0], s - 1, stack[-1][2], stack[-1][3])
            stack[-1][0] = max(stack[-1][0], e + 1)

        stack.append([s, e, cc, cidr_s])

    while stack:
        top_cur, top_end, top_cc, top_cidr = stack.pop()
        push_emitted(top_cur, top_end, top_cc, top_cidr)
        if stack:
            stack[-1][0] = max(stack[-1][0], top_end + 1)

    return emitted


def collapse_and_limit(nets: list[ipaddress.IPv4Network]) -> list[ipaddress.IPv4Network]:
    cleaned = [n for n in nets if not is_protected(n)]
    return list(ipaddress.collapse_addresses(cleaned))


def collapse_v6(nets: list[ipaddress.IPv6Network]) -> list[ipaddress.IPv6Network]:
    cleaned = [n for n in nets if not is_protected_v6(n)]
    return list(ipaddress.collapse_addresses(cleaned))


def supernet_collapse(nets: list[ipaddress.IPv4Network]) -> list[ipaddress.IPv4Network]:
    collapsed = list(ipaddress.collapse_addresses([n for n in nets if not is_protected(n)]))
    if len(collapsed) <= 180:
        return collapsed
    promoted = set()
    for n in collapsed:
        if n.prefixlen > 16:
            cand = n.supernet(new_prefix=16)
            if not is_protected(cand):
                promoted.add(cand)
            else:
                promoted.add(n)
        else:
            promoted.add(n)
    return list(ipaddress.collapse_addresses(promoted))


def main():
    import sys
    script_dir = os.path.dirname(os.path.abspath(__file__))
    if script_dir not in sys.path:
        sys.path.insert(0, script_dir)
    try:
        from securepc_geo_cert import print_securepc_intro_banner
        print_securepc_intro_banner()
        print()
    except Exception:
        pass

    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    print("==> [1/8] Downloading Worldwide RIR Country CIDR Archives (IPv4 & IPv6)...")
    world_v4 = fetch_all_country_zones_v4()
    world_v6 = fetch_all_country_zones_v6()
    print(f"    Loaded {len(world_v4)} IPv4 country zones and {len(world_v6)} IPv6 country zones.")

    print("==> [2/8] Resolving target Beijing, aliyuncs.com, .cn, .ru, and .ir domains...")
    beijing_resolved = resolve_domains(BEIJING_DOMAINS)
    aliyun_resolved = resolve_domains(ALIYUNCS_DOMAINS)
    cn_resolved = resolve_domains(CN_DOMAINS)
    ru_resolved = resolve_domains(RU_DOMAINS)
    ir_resolved = resolve_domains(IR_DOMAINS)

    print("==> [3/8] Building Beijing & aliyuncs.com BGP prefix lists...")
    beijing_raw_nets = []
    beijing_annotations = {}
    for cidr, desc in FALLBACK_BEIJING_CIDRS:
        net = ipaddress.ip_network(cidr, strict=False)
        if not is_protected(net):
            beijing_raw_nets.append(net)
            beijing_annotations[str(net)] = desc
    for asn, desc in BEIJING_ASNS.items():
        fetched = fetch_ripe_asn_prefixes(asn)
        print(f"    {asn} ({desc}): {len(fetched)} prefixes")
        for n in fetched:
            beijing_raw_nets.append(n)
            beijing_annotations.setdefault(str(n), f"{desc} ({asn})")
    for dom, ips in beijing_resolved.items():
        for ip_s in ips:
            net = ipaddress.ip_network(f"{ip_s}/32")
            beijing_raw_nets.append(net)
            beijing_annotations[str(net)] = f"Resolved Beijing endpoint: {dom}"
    beijing_collapsed = supernet_collapse(beijing_raw_nets)

    aliyun_raw_nets = []
    aliyun_annotations = {}
    for cidr, desc in FALLBACK_ALIYUNCS_CIDRS:
        net = ipaddress.ip_network(cidr, strict=False)
        if not is_protected(net):
            aliyun_raw_nets.append(net)
            aliyun_annotations[str(net)] = desc
    for asn, desc in ALIYUNCS_ASNS.items():
        fetched = fetch_ripe_asn_prefixes(asn)
        print(f"    {asn} ({desc}): {len(fetched)} prefixes")
        for n in fetched:
            aliyun_raw_nets.append(n)
            aliyun_annotations.setdefault(str(n), f"{desc} ({asn})")
    for dom, ips in aliyun_resolved.items():
        for ip_s in ips:
            net = ipaddress.ip_network(f"{ip_s}/32")
            aliyun_raw_nets.append(net)
            aliyun_annotations[str(net)] = f"Resolved aliyuncs.com endpoint: {dom}"
    aliyun_collapsed = supernet_collapse(aliyun_raw_nets)

    print("==> [4/8] Building China (.cn) & Russia (.ru) complete CIDR lists...")
    cn_apnic_nets = list(world_v4.get("CN", []))
    cn_major_nets = []
    cn_major_annotations = {}
    for cidr, desc in FALLBACK_CN_ROOT_CIDRS:
        if "14.0.0.0/8" in cidr:
            for sub in ["14.16.0.0/12", "14.104.0.0/13", "14.144.0.0/12", "14.204.0.0/14"]:
                n = ipaddress.ip_network(sub, strict=False)
                if not is_protected(n):
                    cn_apnic_nets.append(n)
                    cn_major_nets.append(n)
                    cn_major_annotations[str(n)] = desc
        else:
            n = ipaddress.ip_network(cidr, strict=False)
            if not is_protected(n):
                cn_apnic_nets.append(n)
                cn_major_nets.append(n)
                cn_major_annotations[str(n)] = desc
    for dom, ips in cn_resolved.items():
        for ip_s in ips:
            n = ipaddress.ip_network(f"{ip_s}/32")
            if not is_protected(n):
                cn_apnic_nets.append(n)
                cn_major_nets.append(n)
                cn_major_annotations[str(n)] = f"Resolved .cn endpoint: {dom}"
    cn_all_collapsed = collapse_and_limit(cn_apnic_nets)
    cn_major_collapsed = collapse_and_limit(cn_major_nets)
    cn_v6_collapsed = collapse_v6(world_v6.get("CN", []))

    ru_ripe_nets = list(world_v4.get("RU", []))
    ru_major_nets = []
    ru_major_annotations = {}
    for cidr, desc in FALLBACK_RU_ROOT_CIDRS:
        n = ipaddress.ip_network(cidr, strict=False)
        if not is_protected(n):
            ru_ripe_nets.append(n)
            ru_major_nets.append(n)
            ru_major_annotations[str(n)] = desc
    for asn, desc in RU_ASNS.items():
        fetched = fetch_ripe_asn_prefixes(asn)
        print(f"    {asn} ({desc}): {len(fetched)} prefixes")
        for n in fetched:
            ru_ripe_nets.append(n)
            if n.prefixlen <= 16:
                ru_major_nets.append(n)
                ru_major_annotations.setdefault(str(n), f"{desc} ({asn})")
    for dom, ips in ru_resolved.items():
        for ip_s in ips:
            n = ipaddress.ip_network(f"{ip_s}/32")
            if not is_protected(n):
                ru_ripe_nets.append(n)
                ru_major_nets.append(n)
                ru_major_annotations[str(n)] = f"Resolved .ru endpoint: {dom}"
    ru_all_collapsed = collapse_and_limit(ru_ripe_nets)
    ru_major_collapsed = supernet_collapse(ru_major_nets)
    ru_v6_collapsed = collapse_v6(world_v6.get("RU", []))

    print("==> [5/8] Building Iran (.ir) & Middle East CIDR lists...")
    ir_ripe_nets = list(world_v4.get("IR", []))
    ir_major_nets = []
    ir_major_annotations = {}
    for cidr, desc in FALLBACK_IR_ROOT_CIDRS:
        n = ipaddress.ip_network(cidr, strict=False)
        if not is_protected(n):
            ir_ripe_nets.append(n)
            ir_major_nets.append(n)
            ir_major_annotations[str(n)] = desc
    for asn, desc in IR_ASNS.items():
        fetched = fetch_ripe_asn_prefixes(asn)
        print(f"    {asn} ({desc}): {len(fetched)} prefixes")
        for n in fetched:
            ir_ripe_nets.append(n)
            if n.prefixlen <= 16:
                ir_major_nets.append(n)
                ir_major_annotations.setdefault(str(n), f"{desc} ({asn})")
    for dom, ips in ir_resolved.items():
        for ip_s in ips:
            n = ipaddress.ip_network(f"{ip_s}/32")
            if not is_protected(n):
                ir_ripe_nets.append(n)
                ir_major_nets.append(n)
                ir_major_annotations[str(n)] = f"Resolved .ir endpoint: {dom}"
    ir_all_collapsed = collapse_and_limit(ir_ripe_nets)
    ir_major_collapsed = supernet_collapse(ir_major_nets)
    ir_v6_collapsed = collapse_v6(world_v6.get("IR", []))
    print(f"    Total Iran (.ir) CIDR blocks: {len(ir_all_collapsed)} (Major: {len(ir_major_collapsed)}, IPv6: {len(ir_v6_collapsed)})")

    # Middle East (16 countries: AE, BH, CY, EG, IL, IQ, JO, KW, LB, OM, PS, QA, SA, SY, TR, YE)
    me_raw_nets = []
    me_annotated_rows = []
    me_v6_raw = []
    for me_cc, me_name in sorted(MIDDLE_EAST_COUNTRIES.items()):
        c_nets = [n for n in world_v4.get(me_cc, []) if not is_protected(n)]
        c_collapsed = list(ipaddress.collapse_addresses(c_nets))
        for n in c_collapsed:
            me_raw_nets.append(n)
            me_annotated_rows.append((str(n), me_cc, me_name))
        me_v6_raw.extend(world_v6.get(me_cc, []))
    me_all_collapsed = collapse_and_limit(me_raw_nets)
    me_v6_collapsed = collapse_v6(me_v6_raw)
    print(f"    Total Middle East CIDR blocks: {len(me_all_collapsed)} across 16 countries (IPv6: {len(me_v6_collapsed)})")

    print("==> [6/8] Building United States & Worldwide Flattened GeoIP Tables...")
    us_v4_collapsed = list(ipaddress.collapse_addresses(world_v4.get("US", [])))
    us_v6_collapsed = list(ipaddress.collapse_addresses(world_v6.get("US", [])))

    flat_v4 = flatten_nested_cidr_intervals(world_v4)
    flat_v6 = flatten_nested_cidr_intervals(world_v6)
    print(f"    Flattened Worldwide GeoIP: {len(flat_v4)} disjoint IPv4 intervals, {len(flat_v6)} disjoint IPv6 intervals")

    print(f"==> [7/8] Writing CIDR & Worldwide GeoIP files to {LISTS_DIR}/...")

    with open(os.path.join(LISTS_DIR, "beijing-cidrs.txt"), "w") as f:
        f.write(f"# SecurePC — Beijing Associated IPv4 Addresses & CIDR Ranges\n# Generated: {now_str}\n# Total CIDR Blocks: {len(beijing_collapsed)}\n\n")
        for net in beijing_collapsed:
            f.write(f"{str(net):<20} # {beijing_annotations.get(str(net), 'Beijing ASN / Regional CIDR Allocation')}\n")

    with open(os.path.join(LISTS_DIR, "aliyuncs-cidrs.txt"), "w") as f:
        f.write(f"# SecurePC — aliyuncs.com / Alibaba Cloud Associated IPv4 Addresses & CIDR Ranges\n# Generated: {now_str}\n# Total CIDR Blocks: {len(aliyun_collapsed)}\n\n")
        for net in aliyun_collapsed:
            f.write(f"{str(net):<20} # {aliyun_annotations.get(str(net), 'Alibaba Cloud / aliyuncs.com ASN Allocation')}\n")

    with open(os.path.join(LISTS_DIR, "cn-major-cidrs.txt"), "w") as f:
        f.write(f"# SecurePC — Major .cn TLD Root DNS, Registries, and National Backbone CIDR Ranges\n# Generated: {now_str}\n# Total CIDR Blocks: {len(cn_major_collapsed)}\n\n")
        for net in cn_major_collapsed:
            f.write(f"{str(net):<20} # {cn_major_annotations.get(str(net), 'China (.cn) Backbone / Registry Allocation')}\n")

    with open(os.path.join(LISTS_DIR, "cn-cidrs.txt"), "w") as f:
        f.write(f"# SecurePC — Complete APNIC Delegated China (.cn) IPv4 CIDR Block List\n# Generated: {now_str}\n# Total CIDR Blocks: {len(cn_all_collapsed)}\n\n")
        for net in cn_all_collapsed:
            f.write(f"{net}\n")

    with open(os.path.join(LISTS_DIR, "cn-ipv6-cidrs.txt"), "w") as f:
        f.write(f"# SecurePC — China (.cn) IPv6 CIDR Block List ({len(cn_v6_collapsed)} blocks)\n")
        for net in cn_v6_collapsed:
            f.write(f"{net}\n")

    with open(os.path.join(LISTS_DIR, "ru-major-cidrs.txt"), "w") as f:
        f.write(f"# SecurePC — Major .ru TLD Root DNS, Registries, and Russian Backbone CIDR Ranges\n# Generated: {now_str}\n# Total CIDR Blocks: {len(ru_major_collapsed)}\n\n")
        for net in ru_major_collapsed:
            f.write(f"{str(net):<20} # {ru_major_annotations.get(str(net), 'Russian Federation (.ru) Backbone / ISP Allocation')}\n")

    with open(os.path.join(LISTS_DIR, "ru-cidrs.txt"), "w") as f:
        f.write(f"# SecurePC — Complete RIPE NCC Delegated Russian Federation (.ru) IPv4 CIDR Block List\n# Generated: {now_str}\n# Total CIDR Blocks: {len(ru_all_collapsed)}\n\n")
        for net in ru_all_collapsed:
            f.write(f"{net}\n")

    with open(os.path.join(LISTS_DIR, "ru-ipv6-cidrs.txt"), "w") as f:
        f.write(f"# SecurePC — Russia (.ru) IPv6 CIDR Block List ({len(ru_v6_collapsed)} blocks)\n")
        for net in ru_v6_collapsed:
            f.write(f"{net}\n")

    # Iran (.ir)
    with open(os.path.join(LISTS_DIR, "ir-major-cidrs.txt"), "w") as f:
        f.write(f"# SecurePC — Major Iran (.ir) Root DNS, National Gateway & Telecom Backbone CIDRs\n# Generated: {now_str}\n# Total CIDR Blocks: {len(ir_major_collapsed)}\n\n")
        for net in ir_major_collapsed:
            f.write(f"{str(net):<20} # {ir_major_annotations.get(str(net), 'Iran (.ir) Backbone / ISP Allocation')}\n")

    with open(os.path.join(LISTS_DIR, "ir-cidrs.txt"), "w") as f:
        f.write(f"# SecurePC — Complete RIPE NCC Delegated Iran (.ir) IPv4 CIDR Block List\n# Generated: {now_str}\n# Total CIDR Blocks: {len(ir_all_collapsed)}\n\n")
        for net in ir_all_collapsed:
            f.write(f"{net}\n")

    with open(os.path.join(LISTS_DIR, "ir-ipv6-cidrs.txt"), "w") as f:
        f.write(f"# SecurePC — Iran (.ir) IPv6 CIDR Block List ({len(ir_v6_collapsed)} blocks)\n")
        for net in ir_v6_collapsed:
            f.write(f"{net}\n")

    # Middle East (AE, BH, CY, EG, IL, IQ, JO, KW, LB, OM, PS, QA, SA, SY, TR, YE)
    with open(os.path.join(LISTS_DIR, "me-cidrs.txt"), "w") as f:
        f.write(f"# SecurePC — Complete Middle East IPv4 CIDR Block List (AE, BH, CY, EG, IL, IQ, JO, KW, LB, OM, PS, QA, SA, SY, TR, YE)\n")
        f.write(f"# Generated: {now_str}\n# Total CIDR Blocks: {len(me_all_collapsed)}\n\n")
        for net in me_all_collapsed:
            f.write(f"{net}\n")

    with open(os.path.join(LISTS_DIR, "me-annotated-cidrs.txt"), "w") as f:
        f.write(f"# SecurePC — Annotated Middle East Country IPv4 CIDR Allocations\n# Generated: {now_str}\n\n")
        for cidr_s, mcc, mname in me_annotated_rows:
            f.write(f"{cidr_s:<20} # [{mcc}] {mname}\n")

    with open(os.path.join(LISTS_DIR, "me-ipv6-cidrs.txt"), "w") as f:
        f.write(f"# SecurePC — Middle East IPv6 CIDR Block List ({len(me_v6_collapsed)} blocks)\n")
        for net in me_v6_collapsed:
            f.write(f"{net}\n")

    # United States & Worldwide GeoIP tables
    with open(os.path.join(LISTS_DIR, "us-cidrs.txt"), "w") as f:
        f.write(f"# SecurePC — United States (US) RIR Delegated IPv4 CIDR Allocations ({len(us_v4_collapsed)} blocks)\n# Generated: {now_str}\n\n")
        for net in us_v4_collapsed:
            f.write(f"{net}\n")

    with open(os.path.join(LISTS_DIR, "us-ipv6-cidrs.txt"), "w") as f:
        f.write(f"# SecurePC — United States (US) RIR Delegated IPv6 CIDR Allocations ({len(us_v6_collapsed)} blocks)\n# Generated: {now_str}\n\n")
        for net in us_v6_collapsed:
            f.write(f"{net}\n")

    with open(os.path.join(LISTS_DIR, "world-geoip-v4.tsv"), "w") as f:
        f.write(f"# SecurePC Worldwide Flattened RIR GeoIP IPv4 Table — Generated {now_str}\n")
        f.write("# start_int\tend_int\tcountry_code\tcidr\n")
        for s_int, e_int, cc, cidr_s in flat_v4:
            f.write(f"{s_int}\t{e_int}\t{cc}\t{cidr_s}\n")

    with open(os.path.join(LISTS_DIR, "world-geoip-v6.tsv"), "w") as f:
        f.write(f"# SecurePC Worldwide Flattened RIR GeoIP IPv6 Table — Generated {now_str}\n")
        f.write("# start_hex\tend_hex\tcountry_code\tcidr\n")
        for s_int, e_int, cc, cidr_s in flat_v6:
            f.write(f"{s_int:x}\t{e_int:x}\t{cc}\t{cidr_s}\n")

    # resolved-target-ips.txt
    with open(os.path.join(LISTS_DIR, "resolved-target-ips.txt"), "w") as f:
        f.write(f"# SecurePC — Live-Resolved IPv4 Addresses for Beijing, .cn, aliyuncs.com, .ru, and .ir Domains\n# Generated: {now_str}\n\n")
        for label, dmap in [
            ("BEIJING", beijing_resolved),
            ("ALIYUNCS", aliyun_resolved),
            ("CN-DOMAIN", cn_resolved),
            ("RU-DOMAIN", ru_resolved),
            ("IR-DOMAIN", ir_resolved),
        ]:
            f.write(f"# --- {label} ENDPOINTS ---\n")
            for dom, ips in sorted(dmap.items()):
                for ip_s in ips:
                    f.write(f"{ip_s}/32\t# [{label}] {dom}\n")
            f.write("\n")

    # blocked-domains.txt
    me_tlds = [f".{c.lower()}" for c in sorted(MIDDLE_EAST_COUNTRIES.keys())]
    with open(os.path.join(LISTS_DIR, "blocked-domains.txt"), "w") as f:
        f.write(f"# SecurePC — Blocked Domain Patterns & DNS/TLS/HTTP Signatures (CN, RU, IR, Middle East)\n# Generated: {now_str}\n\n")
        for pat in [
            ".cn", "*.cn", ".xn--fiqs8s", ".xn--fiqz9s",
            ".ru", "*.ru", ".su", "*.su", ".xn--p1ai", "*.xn--p1ai",
            ".ir", "*.ir", ".xn--mgba3a4f16a", "*.xn--mgba3a4f16a",
            "aliyuncs.com", "*.aliyuncs.com", "aliyun.com", "*.aliyun.com", "alidns.com", "*beijing*",
        ] + me_tlds + [f"*{t}" for t in me_tlds]:
            f.write(f"{pat}\n")
        for dom in sorted(set(BEIJING_DOMAINS + ALIYUNCS_DOMAINS + CN_DOMAINS + RU_DOMAINS + IR_DOMAINS)):
            f.write(f"{dom}\n")

    print("==> [8/8] Updating master consolidated blocklist all-blocked-ips-and-ranges.txt...")
    all_complete = collapse_and_limit(
        beijing_collapsed + aliyun_collapsed + cn_all_collapsed + ru_all_collapsed + ir_all_collapsed + me_all_collapsed
    )
    with open(os.path.join(LISTS_DIR, "all-blocked-ips-and-ranges.txt"), "w") as f:
        f.write(f"# ==============================================================================\n")
        f.write(f"# SecurePC — Master Consolidated List of Blocked IPs and IP Ranges\n")
        f.write(f"# Policy: Block China (.cn/Beijing/aliyuncs), Russia (.ru/.su), Iran (.ir), & Middle East\n")
        f.write(f"# Generated: {now_str}\n")
        f.write(f"# Complete Consolidated CIDR Blocks: {len(all_complete)}\n")
        f.write(f"# ==============================================================================\n\n")
        seen_ips = set()
        for cat, dmap in [
            ("BEIJING", beijing_resolved),
            ("ALIYUNCS", aliyun_resolved),
            ("CN-DOMAIN", cn_resolved),
            ("RU-DOMAIN", ru_resolved),
            ("IR-DOMAIN", ir_resolved),
        ]:
            for dom, ips in sorted(dmap.items()):
                for ip_s in ips:
                    seen_ips.add(ip_s)
                    f.write(f"{ip_s + '/32':<20} # [{cat}] {dom}\n")
        for net in all_complete:
            f.write(f"{net}\n")

    print("==> Successfully generated all SecurePC Blocklists & Worldwide GeoIP Tables:")
    print(f"    - Beijing CIDRs:       {len(beijing_collapsed)}")
    print(f"    - aliyuncs.com CIDRs:  {len(aliyun_collapsed)}")
    print(f"    - Full APNIC .cn:      {len(cn_all_collapsed)} (IPv6: {len(cn_v6_collapsed)})")
    print(f"    - Full RIPE .ru:       {len(ru_all_collapsed)} (IPv6: {len(ru_v6_collapsed)})")
    print(f"    - Full Iran .ir:       {len(ir_all_collapsed)} (IPv6: {len(ir_v6_collapsed)})")
    print(f"    - Full Middle East:    {len(me_all_collapsed)} (IPv6: {len(me_v6_collapsed)})")
    print(f"    - United States CIDRs: {len(us_v4_collapsed)} (IPv6: {len(us_v6_collapsed)})")
    print(f"    - World GeoIP v4/v6:   {len(flat_v4)} v4 intervals / {len(flat_v6)} v6 intervals")


if __name__ == "__main__":
    main()

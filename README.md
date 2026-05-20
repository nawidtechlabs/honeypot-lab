# Honeypot Lab — Live Threat Intelligence

## Overview
Live T-Pot honeypot deployed on a Vultr VPS (Ubuntu 22.04, 8GB RAM) collecting real attack data from threat actors worldwide. This project documents daily threat intelligence findings including IOC enrichment across Shodan, Censys, AFRINIC, and AbuseIPDB.

**222,000+ attacks captured in 3 days.**

## Infrastructure
- **Platform:** Vultr VPS — New Jersey
- **OS:** Ubuntu 22.04
- **Honeypot:** T-Pot CE (multi-honeypot platform)
- **RAM:** 8GB
- **Storage:** 160GB SSD

## Honeypot Services Running
| Honeypot | Purpose |
|---|---|
| Honeytrap | Generic port scanner detection |
| Cowrie | SSH/Telnet brute force capture |
| Dionaea | Malware and exploit capture |
| Sentrypeer | VoIP/SIP scanning detection |
| Mailoney | SMTP abuse detection |
| Heralding | Credential harvesting detection |

## Attack Summary — Day 3 (May 20, 2026)
- **Total Attacks:** 222,000+
- **Top Honeypot Hit:** Honeytrap — 195k hits
- **Top Attacking ASN:** AS49870 Alsycon B.V. — 178,498 hits
- **Active CVE:** CVE-2020-11 exploit attempts detected

## IOC Enrichment — Top Attacker
**IP:** 160.119.76.4
**Hits:** 146,549 in 24 hours
**ISP:** HostUS Solutions LLC
**ASN:** AS49870
**Location:** Netherlands
**OS:** CentOS Linux
**Open Ports:** 22/SSH, 80/HTTP, 443/HTTP
**AbuseIPDB:** 110 reports — 100% abuse confidence
**Cert:** Self-signed with placeholder values
**Verdict:** Rented VPS attack infrastructure

**Verified across:**
- Censys
- AFRINIC (official registry)
- AbuseIPDB

## Tools Used
- T-Pot CE
- Kibana / Elasticsearch
- Shodan
- Censys
- AFRINIC
- AbuseIPDB
- Talos Intelligence

## Next Steps
- Automate IOC enrichment with Python
- Deploy Galah LLM-powered honeypot
- Set up Wazuh for centralized log analysis
- Auto-report malicious infrastructure to hosting providers

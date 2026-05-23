# IR-2026-002 — SSH Intrusion from Moscow, Russia
**Date:** May 23, 2026  
**Analyst:** Nawid Farani, SOC Analyst  
**Target IP:** 81.211.72.167  
**Classification:** TLP:WHITE  

## Executive Summary
On May 23, 2026 at 06:10:56 UTC, a threat actor originating from IP address 81.211.72.167 successfully authenticated to the Cowrie SSH honeypot using credentials root/Test1234560. Following authentication, the attacker executed three reconnaissance commands to fingerprint the system before disconnecting. No malware was dropped and no C2 communication was observed. The attacker is attributed to a fixed-line business ethernet connection in Moscow, Russia operated by PJSC Vimpelcom via Golden Telecom. This IP has 42,353 abuse reports on AbuseIPDB with 100% confidence of malicious activity. Evidence was fully preserved prior to investigation with an intact chain of custody.

## Timeline
| Time (UTC) | Event |
|------------|-------|
| 06:10:56 | Successful SSH login as root using password Test1234560 |
| 06:11:00 | Command executed: whoami |
| 06:11:04 | Command executed: w |
| 06:11:07 | Command executed: top |
| 06:11:xx | Attacker disconnected |

## Credentials Used
- Username: root
- Password: Test1234560

## Post-Login Commands
- whoami — confirmed running as root
- w — enumerated logged in users
- top — surveyed running processes

## Threat Actor Enrichment

### Shodan
No results found. IP not indexed. Actively avoiding detection.

### Censys
- WHOIS Network: Golden Telecom P2P-MOSCOW-BC-NET
- WHOIS Organization: PJSC Vimpelcom
- Address: 8 Marta str 10 bld 14, 127083 Moscow, Russian Federation
- ASN: SOVAM-AS 3216 RU
- Location: Moscow, Russia
- Total Services: 0

### RIPE (Ground Truth)
- inetnum: 81.211.72.0 - 81.211.72.255
- netname: P2P-Moscow-BC-NET
- Organization: PJSC Vimpelcom
- Country: RU
- Abuse contact: abuse-b2b@beeline.ru

### AbuseIPDB
- Reports: 42,353
- Confidence: 100%
- ISP: Golden Telecom
- Usage Type: Fixed Line ISP
- Categories: Brute-Force, SSH, Web App Attack

## Splunk Analysis
- Cowrie events: 28
- Suricata events: 40
- Alert signatures: ET INFO SSH session in progress on Expected Port (7 hits)
- SSH client: libssh_0.9.6
- HASSH: f555226df1963d1d3c09daf865abdc9a

## C2 Analysis
No HTTP events detected for this IP in Suricata. No C2 communication observed. Reconnaissance-only intrusion.

## MITRE ATT&CK Mapping
| Technique | ID | Description |
|-----------|-----|-------------|
| Brute Force: Password Guessing | T1110.001 | SSH brute force using wordlist |
| Valid Accounts | T1078 | Authenticated as root |
| System Owner/User Discovery | T1033 | whoami command |
| System Network Connections Discovery | T1049 | w command |
| Process Discovery | T1057 | top command |

## Chain of Evidence
- Raw Cowrie logs: ~/ir_findings/81.211.72.167/cowrie.log (45KB)
- Raw Suricata logs: ~/ir_findings/81.211.72.167/suricata.log (38KB)
- Evidence preserved: 2026-05-23 06:23 UTC BEFORE investigation began
- Chain of custody: INTACT — no evidence gaps

## IOCs
- IP: 81.211.72.167
- SSH Client: libssh_0.9.6
- HASSH: f555226df1963d1d3c09daf865abdc9a
- Credentials: root / Test1234560
- ASN: AS3216 SOVAM-AS Russia

## Recommendations
1. Block 81.211.72.167 at perimeter firewall
2. Block ASN AS3216 if Russian traffic is not expected
3. Alert on HASSH f555226df1963d1d3c09daf865abdc9a
4. Disable root SSH login on all production systems
5. Enforce SSH key authentication, disable password auth
6. Report to abuse-b2b@beeline.ru and abuse@gldn.net

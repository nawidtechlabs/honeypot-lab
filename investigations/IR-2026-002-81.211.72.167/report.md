# IR-2026-002 - SSH Intrusion + Persistence - Moscow Russia

Report ID: IR-2026-002
Version: 2.1
Date: May 23, 2026
Analyst: Nawid Farani, SOC Analyst
Target IP: 81.211.72.167
Severity: HIGH
Status: CLOSED
Classification: TLP:WHITE

EXECUTIVE SUMMARY

On May 23, 2026, threat actor IP 81.211.72.167 successfully authenticated to the Cowrie SSH honeypot using credentials root/Test1234560. After initial reconnaissance the attacker returned 15 minutes later and planted a known malicious SSH public key in authorized_keys establishing a permanent backdoor. The key was physically recovered from the Cowrie downloads folder, verified via SHA256, and confirmed malicious by 33/61 VirusTotal vendors. This same key has been targeting systems globally since 2018. Attribution: Moscow Russia, Golden Telecom fixed-line ethernet, PJSC Vimpelcom, 42,353 AbuseIPDB reports, 100% confidence.

ATTACK TIMELINE

06:07:48 - Initial SSH connection - Recon
06:10:56 - Login SUCCESS root/Test1234560 - Initial Access
06:11:00 - Command whoami - Discovery
06:11:04 - Command w - Discovery
06:11:07 - Command top - Discovery
06:17:17 - Session closed
06:23:39 - ATTACKER RETURNED - Persistence
06:26:55 - FILE DOWNLOAD SSH public key planted - Persistence
06:27:00 - Command whoami - Discovery
06:27:02 - Command w - Discovery
06:27:04 - Command top - Discovery
06:33:15 - Third connection attempt
06:36:30 - Final session closed

PERSISTENCE MECHANISM CONFIRMED

File Type: OpenSSH RSA Public Key
SHA256: a8460f446be540410004b1a8db4083773fa46f7fe76fa84219c93daa1669f8f2
MD5: a420f7a60a40f3ff3a806a01feb1dfda
File Size: 389 bytes
Key Label: mdrfckr
VirusTotal: 33/61 vendors flagged Trojan and Miner
First Seen: 2018-07-05 Global campaign since 2018
Recovery: Physically recovered from Cowrie downloads folder

Key content verified by direct file read:
ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr

THREAT ACTOR ENRICHMENT

Shodan: No results actively avoiding detection
Censys: Golden Telecom P2P-MOSCOW-BC-NET PJSC Vimpelcom Moscow RU 0 services
RIPE: P2P-Moscow-BC-NET Country RU abuse-b2b@beeline.ru
AbuseIPDB: 42353 reports 100% confidence Fixed Line ISP

Four Source Verdict: Russian fixed-line business ethernet in Moscow. Not a VPS. Not a bot farm. Real endpoint deliberately avoiding Shodan detection. All four sources agree.

SPLUNK ANALYSIS

Cowrie Events: 28 total
session.params: 17
command.input: 6
session.closed: 3
session.connect: 2
session.file_download: 1
login.success: 1
login.failed: 1
log.closed: 2

Suricata Events: 40 total
ssh: 17
flow: 16
alert: 7

Alert Signature: ET INFO SSH session in progress on Expected Port 7 hits
SSH Client: libssh_0.9.6
HASSH: f555226df1963d1d3c09daf865abdc9a

MITRE ATT&CK MAPPING

T1110.001 - Brute Force Password Guessing - SSH brute force root/Test1234560
T1078 - Valid Accounts - Successful root login 06:10:56
T1033 - System Owner Discovery - whoami post-login
T1049 - Network Connections Discovery - w command
T1057 - Process Discovery - top command
T1098.004 - SSH Authorized Keys - mdrfckr key planted 06:26:55
T1496 - Resource Hijacking - VT miner family confirmed

CHAIN OF EVIDENCE

1. Raw Cowrie logs 45KB - Preserved 06:23 UTC before investigation - INTACT
2. Raw Suricata logs 38KB - Preserved 06:23 UTC before investigation - INTACT
3. Malicious SSH public key 389 bytes - Physically recovered Cowrie downloads - INTACT
4. VirusTotal analysis 33/61 flagged - External analysis completed - INTACT
5. Splunk events Cowrie and Suricata - Full session timeline documented - INTACT

Evidence Gaps: NONE - Chain of custody INTACT

INDICATORS OF COMPROMISE

IP: 81.211.72.167
ASN: AS3216 SOVAM-AS Russia
Credential: root / Test1234560
SSH Client: libssh_0.9.6
HASSH: f555226df1963d1d3c09daf865abdc9a
SHA256: a8460f446be540410004b1a8db4083773fa46f7fe76fa84219c93daa1669f8f2
Key Label: mdrfckr

RECOMMENDATIONS

CRITICAL - Search all authorized_keys for SSH key labeled mdrfckr
CRITICAL - Search for SHA256 a8460f446be540410004b1a8db4083773fa46f7fe76fa84219c93daa1669f8f2
HIGH - Block 81.211.72.167 at perimeter firewall
HIGH - Block ASN AS3216 if Russian traffic not expected
HIGH - Disable root SSH password authentication
HIGH - Enforce SSH key-only authentication
MEDIUM - Alert on HASSH f555226df1963d1d3c09daf865abdc9a
LOW - Report to abuse-b2b@beeline.ru and abuse@gldn.net

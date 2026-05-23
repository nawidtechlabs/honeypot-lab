# Splunk SPL Detection Queries
## Honeypot Threat Intelligence Lab
Analyst: Nawid Farani
Environment: T-Pot on Vultr VPS, Splunk Enterprise 10.2.3

## 1. All Successful Logins
index=main sourcetype=cowrie eventid="cowrie.login.success"
| stats count by src_ip username password
| sort -count

## 2. Dictionary Attack Detection
index=main sourcetype=cowrie eventid="cowrie.login.failed"
| stats count by src_ip
| where count > 100
| sort -count

## 3. Post Login Commands
index=main sourcetype=cowrie eventid="cowrie.command.input"
| table _time src_ip input
| sort _time

## 4. Malware Dropper Detection
index=main sourcetype=cowrie eventid="cowrie.command.input"
| search input="*wget*" OR input="*curl*" OR input="*chmod*" OR input="*/tmp/*"
| table _time src_ip input

## 5. Top Attacking IPs
index=main sourcetype=suricata
| stats count by src_ip
| sort -count
| head 10

## 6. Suricata Alert Signatures
index=main sourcetype=suricata event_type="alert"
| stats count by alert.signature
| sort -count

## 7. SSH Client Fingerprint HASSH
index=main sourcetype=suricata event_type="ssh"
| stats count by ssh.client.software_version ssh.client.hassh.hash
| sort -count

## 8. Attack Timeline
index=main sourcetype=suricata event_type="ssh"
| timechart span=1h count

## 9. IP Specific Investigation
index=main sourcetype=suricata src_ip="TARGET_IP"
| stats count by event_type

## 10. CVE Detection
index=main sourcetype=suricata event_type="alert"
| search alert.metadata.cve=*
| stats count by alert.metadata.cve alert.signature
| sort -count

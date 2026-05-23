# T-Pot Honeypot Setup Documentation

## Environment
- VPS Provider: Vultr
- OS: Ubuntu 22.04 LTS
- RAM: 8GB
- Storage: 160GB SSD
- Honeypot: T-Pot 24.04.1

## Honeypot Services Running
- Cowrie - SSH honeypot
- Suricata - IDS/IPS
- Honeytrap
- Dionaea
- Sentrypeer
- Tanner
- Redishoneypot
- ConPot
- Heralding
- H0neytr4p
- Ciscoasa
- Miniprint
- Honeyaml
- Mailoney
- Adbhoney

## SIEM
- Splunk Enterprise 10.2.3
- Cowrie logs: index=main sourcetype=cowrie
- Suricata logs: index=main sourcetype=suricata

## Stats After 72 Hours
- Total attacks: 222,000+
- Unique source IPs: hundreds
- Countries: Germany, Nether

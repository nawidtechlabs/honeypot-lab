import requests
import sys
import json
from datetime import datetime

ABUSEIPDB_KEY = "0134d028f510f03a8a5a8649597c60a496f6e992caa863bb17862d19d5430224e936207ce63ed478"
SHODAN_KEY = "BsweJIABpi5GU4lucBH9bn9aAt5Um8ms"
VIRUSTOTAL_KEY = "5a0098e8405645499255b9e4a9c485e20dae76dca35123e024ebf46c2c71a964"

def check_abuseipdb(ip):
    try:
        r = requests.get("https://api.abuseipdb.com/api/v2/check", headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"}, params={"ipAddress": ip, "maxAgeInDays": 90})
        d = r.json()["data"]
        return {"reports": d["totalReports"], "confidence": d["abuseConfidenceScore"], "country": d["countryCode"], "isp": d["isp"], "usage": d["usageType"]}
    except Exception as e:
        return {"error": str(e)}

def check_shodan(ip):
    try:
        r = requests.get(f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_KEY}")
        d = r.json()
        if "error" in d:
            return {"error": d["error"]}
        return {"org": d.get("org", "N/A"), "country": d.get("country_name", "N/A"), "city": d.get("city", "N/A"), "ports": d.get("ports", []), "tags": d.get("tags", [])}
    except Exception as e:
        return {"error": str(e)}

def check_virustotal(ip):
    try:
        r = requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}", headers={"x-apikey": VIRUSTOTAL_KEY})
        d = r.json()
        stats = d["data"]["attributes"]["last_analysis_stats"]
        return {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "country": d["data"]["attributes"].get("country", "N/A"),
            "owner": d["data"]["attributes"].get("as_owner", "N/A"),
            "asn": d["data"]["attributes"].get("asn", "N/A")
        }
    except Exception as e:
        return {"error": str(e)}

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 enrich.py <IP>")
        sys.exit(1)
    ip = sys.argv[1]
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    print(f"\n{'='*50}")
    print(f"IP ENRICHMENT REPORT")
    print(f"Target: {ip}")
    print(f"Time:   {timestamp}")
    print(f"{'='*50}")
    print("\nQuerying AbuseIPDB...")
    abuse = check_abuseipdb(ip)
    print("Querying Shodan...")
    shodan = check_shodan(ip)
    print("Querying VirusTotal...")
    vt = check_virustotal(ip)
    print(f"\nABUSEIPDB")
    print(f"---------")
    if "error" in abuse:
        print(f"Error: {abuse['error']}")
    else:
        print(f"Reports:    {abuse['reports']}")
        print(f"Confidence: {abuse['confidence']}%")
        print(f"Country:    {abuse['country']}")
        print(f"ISP:        {abuse['isp']}")
        print(f"Usage:      {abuse['usage']}")
    print(f"\nSHODAN")
    print(f"------")
    if "error" in shodan:
        print(f"Result: {shodan['error']}")
    else:
        print(f"Org:     {shodan['org']}")
        print(f"Country: {shodan['country']}")
        print(f"City:    {shodan['city']}")
        print(f"Ports:   {shodan['ports']}")
        print(f"Tags:    {shodan['tags']}")
    print(f"\nVIRUSTOTAL")
    print(f"----------")
    if "error" in vt:
        print(f"Error: {vt['error']}")
    else:
        print(f"Malicious:  {vt['malicious']} vendors")
        print(f"Suspicious: {vt['suspicious']} vendors")
        print(f"Harmless:   {vt['harmless']} vendors")
        print(f"Country:    {vt['country']}")
        print(f"Owner:      {vt['owner']}")
        print(f"ASN:        {vt['asn']}")
    if "error" not in abuse:
        c = abuse.get("confidence", 0)
        if c >= 80:
            verdict = "MALICIOUS"
        elif c >= 30:
            verdict = "SUSPICIOUS"
        else:
            verdict = "CLEAN"
    else:
        verdict = "UNKNOWN"
    print(f"\nVERDICT: {verdict}")
    print(f"{'='*50}\n")
    filename = f"enrichment_{ip}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
    with open(filename, "w") as f:
        json.dump({"ip": ip, "timestamp": timestamp, "abuseipdb": abuse, "shodan": shodan, "virustotal": vt, "verdict": verdict}, f, indent=2)
    print(f"Report saved: {filename}\n")

if __name__ == "__main__":
    main()
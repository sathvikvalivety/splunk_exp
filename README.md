# Splunk Security Projects: Threat Intel Lookup & Incident Investigation Dashboard

This repository contains the complete implementation and deployment files for two Splunk security projects:

1. **Threat Intel Lookup Enrichment**
2. **Basic Incident Investigation Dashboard (4-Panel)**

---

## Quick Access
- **Splunk Web URL**: [http://localhost:8000](http://localhost:8000)
- **Dashboard Direct Link**: [http://localhost:8000/en-US/app/search/incident_investigation](http://localhost:8000/en-US/app/search/incident_investigation)
- **Credentials**: `sathvik` / `Sathvik@007`

---

## Directory Structure
```
e:\pdfs\notes\4-1\dscc\lab\
├── README.md                                          # Master documentation
├── scripts\
│   └── setup_projects.ps1                             # End-to-end automation script
├── threat_intel_enrichment\
│   ├── README.md                                      # Threat intel documentation & SPL queries
│   └── threat_intel_malicious_ips.csv                 # Malicious IP lookup table
└── incident_dashboard\
    ├── README.md                                      # Dashboard documentation & panel breakdown
    └── incident_investigation.xml                     # Dashboard Simple XML definition
```

---

## Project 1: Threat Intel Lookup Enrichment

### Lookup Table: `threat_intel_malicious_ips.csv`
- Placed in `C:\Program Files\Splunk\etc\apps\search\lookups\threat_intel_malicious_ips.csv`
- Fields: `ip`, `threat_source`, `threat_category`, `confidence_score`, `description`
- Categories included: C2 Server, Cobalt Strike, Botnets (Mirai), Tor Exits, SSH Brute Force, Ransomware Distribution, Web App Scanners.

### Splunk Cross-Reference SPL Search:
```spl
sourcetype=firewall_traffic
| lookup threat_intel_malicious_ips.csv ip as src_ip OUTPUT threat_category, confidence_score, threat_source, description
| where isnotnull(threat_category)
| table _time, src_ip, dest_ip, dest_port, transport, action, threat_category, confidence_score, description
```

---

## Project 2: Basic Incident Investigation Dashboard

The dashboard consists of 4 distinct visualization panels:

1. **Top Failed Logins by Target User** (Bar Chart):
   ```spl
   sourcetype=incident:auth action="failure" | top limit=10 user
   ```
2. **Geolocations of Remote Connections** (Splunk Cluster Map):
   ```spl
   sourcetype=incident:auth | iplocation src_ip | where isnotnull(lat) AND isnotnull(lon) | geostats count by action
   ```
3. **Timeline of Events (Success vs Failure)** (Stacked Area Chart):
   ```spl
   sourcetype=incident:auth | timechart span=1h count by action
   ```
4. **Raw Error Codes Breakdown** (Heatmap Table):
   ```spl
   sourcetype=incident:auth action="failure" | stats count by error_code, error_description | sort - count | rename error_code as "Error Code", error_description as "Error Description", count as "Failure Count"
   ```

---

## Re-running Setup / Refreshing Data
To generate fresh traffic and reload lookups at any time:
```powershell
powershell -ExecutionPolicy Bypass -File "e:\pdfs\notes\4-1\dscc\lab\scripts\setup_projects.ps1"
```

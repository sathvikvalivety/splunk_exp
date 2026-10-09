# Splunk Security Projects & Labs

This repository contains the complete implementation, data ingestion scripts, and dashboard configurations for Splunk Security analytics experiments:

1. **Detect Suspicious Login Activity Dashboard (6-Panel SOC Center)** *(NEW)*
2. **Threat Intel Lookup Enrichment**
3. **Basic Incident Investigation Dashboard (4-Panel)**

---

## Quick Access & Credentials
- **Splunk Web URL**: [http://localhost:8000](http://localhost:8000)
- **Login Credentials**: `sathvik` / `Sathvik@007`
- **Dashboards**:
  - **Detect Suspicious Login Activity**: [http://localhost:8000/en-US/app/search/suspicious_login_activity](http://localhost:8000/en-US/app/search/suspicious_login_activity)
  - **Incident Investigation**: [http://localhost:8000/en-US/app/search/incident_investigation](http://localhost:8000/en-US/app/search/incident_investigation)

---

## Repository Directory Structure
```
e:\pdfs\notes\4-1\dscc\lab\
├── README.md                                          # Master documentation
├── scripts\
│   ├── deploy_suspicious_login_exp.ps1                # Automated generator & deployer for Suspicious Login Exp
│   └── setup_projects.ps1                             # Setup script for Threat Intel & Incident Investigation
├── suspicious_login_detection\
│   ├── README.md                                      # Comprehensive lab report, SPL queries, detection logic
│   ├── sample_auth_data.log                           # Raw generated multi-source auth logs
│   └── suspicious_login_activity.xml                  # 6-Panel Simple XML Dashboard definition
├── threat_intel_enrichment\
│   ├── README.md                                      # Threat intel documentation & SPL queries
│   └── threat_intel_malicious_ips.csv                 # Malicious IP lookup table
└── incident_dashboard\
    ├── README.md                                      # Dashboard documentation & panel breakdown
    └── incident_investigation.xml                     # 4-Panel Dashboard Simple XML definition
```

---

## Project 1: Detect Suspicious Login Activity (Account Compromise Detection)

### Detection Vectors Ingested & Simulated
- **Brute-Force Attacks**: High-volume failed password attempts from foreign IPs against `root`, `admin`, `sathvik`.
- **Account Takeover**: 10+ consecutive failures followed immediately by a successful authentication from the same attacker IP.
- **Impossible Travel**: Rapid consecutive logins for the same user account from distant countries within impossible flight timeframes (e.g. India $\rightarrow$ USA in 14 min).
- **Unusual Off-Hours Activity**: Critical administrative operations between 01:00 AM and 05:00 AM.
- **Heterogeneous Telemetry**: Normalized logs covering Windows Security Events (4624/4625), Linux OpenSSH, Cisco AnyConnect VPN, and Azure AD / AWS CloudTrail.

### Core Detection SPL Rules
- **Rule 1: Account Takeover (Success Following Multiple Failures)**
  ```spl
  (index=auth OR index=main) sourcetype=auth*
  | stats count(eval(action="failure")) as failures, count(eval(action="success")) as successes by user, src_ip
  | where failures >= 5 AND successes >= 1
  | sort - failures
  ```
- **Rule 2: High-Rate Brute Force**
  ```spl
  (index=auth OR index=main) sourcetype=auth* action="failure"
  | stats count as failed_attempts, dc(user) as targeted_users by src_ip
  | where failed_attempts >= 10
  | sort - failed_attempts
  ```

### Dashboard Panels (6 Panels + 4 KPI Cards)
1. **Total Activity & Compromise Indicators** (4 Single Value Metrics)
2. **Panel 1: Failed Logins Over Time** (Stacked Column Chart by Application)
3. **Panel 2: Top Attacking IPs** (Horizontal Bar Chart)
4. **Panel 3: Most Targeted User Accounts** (Pie Chart)
5. **Panel 4: CRITICAL ALERT - Successful Logins Following Failures** (Heatmap Alert Table)
6. **Panel 5: Global Geographic Login Map** (Interactive World Cluster Map using `iplocation` & `geostats`)
7. **Panel 6: Composite User Risk Matrix & Anomaly Scoring** (Risk Score Table)

---

## Project 2: Threat Intel Lookup Enrichment
Cross-references live network firewall traffic against threat intelligence lists (Emerging Threats, AbuseIPDB, C2 IP feeds).

```spl
sourcetype=firewall_traffic
| lookup threat_intel_malicious_ips.csv ip as src_ip OUTPUT threat_category, confidence_score, threat_source, description
| where isnotnull(threat_category)
| table _time, src_ip, dest_ip, dest_port, transport, action, threat_category, confidence_score, description
```

---

## Project 3: Basic Incident Investigation Dashboard (4-Panel)
1. Top Failed Logins by Target User (Bar Chart)
2. Geolocations of Remote Connections (`geostats` Cluster Map)
3. Timeline of Events (Stacked Area Chart)
4. Raw Error Codes Breakdown (Heatmap Table)

---

## Re-running Setup / Refreshing Data

- **To deploy/refresh the Suspicious Login Activity experiment**:
  ```powershell
  powershell -ExecutionPolicy Bypass -File "e:\pdfs\notes\4-1\dscc\lab\scripts\deploy_suspicious_login_exp.ps1"
  ```
- **To deploy/refresh Threat Intel & Incident Investigation**:
  ```powershell
  powershell -ExecutionPolicy Bypass -File "e:\pdfs\notes\4-1\dscc\lab\scripts\setup_projects.ps1"
  ```

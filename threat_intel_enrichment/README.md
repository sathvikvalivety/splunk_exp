# Threat Intel Lookup Enrichment in Splunk

## 1. Overview
This project enriches incoming network and firewall traffic logs with Threat Intelligence feeds (curated from **Emerging Threats** and **AbuseIPDB**). It allows Security Operations Center (SOC) analysts to immediately detect when an internal resource is communicating with or being probed by a known malicious IP (e.g. C2 servers, botnets, brute-force scanners, ransomware distribution hosts).

---

## 2. Threat Intel Dataset Structure
The lookup table `threat_intel_malicious_ips.csv` is deployed at `C:\Program Files\Splunk\etc\apps\search\lookups\threat_intel_malicious_ips.csv`.

| Field | Type | Description | Example |
| :--- | :--- | :--- | :--- |
| `ip` | String | Malicious IPv4 address (lookup key) | `185.220.101.5` |
| `threat_source` | String | Originating Threat Intel Feed | `EmergingThreats`, `AbuseIPDB` |
| `threat_category` | String | Classification of malicious activity | `Tor Exit Node / Scanner`, `Cobalt Strike C2`, `SSH Brute Force` |
| `confidence_score`| Integer | Threat confidence rating (0 - 100) | `95` |
| `description` | String | Contextual intelligence details | `Known Cobalt Strike Team Server beacon destination` |

---

## 3. Splunk Configuration

### `transforms.conf` Definition
Located at `C:\Program Files\Splunk\etc\apps\search\local\transforms.conf`:
```ini
[threat_intel_lookup]
filename = threat_intel_malicious_ips.csv
case_sensitive_match = false
```

---

## 4. Search Queries (SPL)

### Query 1: Cross-Reference Incoming Firewall Logs with Threat Intel
Cross-references inbound traffic with the malicious IP lookup table and filters only matched threats.
```spl
sourcetype=firewall_traffic
| lookup threat_intel_malicious_ips.csv ip as src_ip OUTPUT threat_category, confidence_score, threat_source, description
| where isnotnull(threat_category)
| table _time, src_ip, dest_ip, dest_port, transport, action, threat_category, confidence_score, description
```

### Query 2: Aggregated Threat Activity by Category and Actor
Summarizes incident volume, target destinations, and targeted ports grouped by threat category.
```spl
sourcetype=firewall_traffic
| lookup threat_intel_malicious_ips.csv ip as src_ip OUTPUT threat_category, confidence_score, threat_source
| where isnotnull(threat_category)
| stats count, earliest(_time) as first_seen, latest(_time) as last_seen, values(dest_ip) as targeted_internal_hosts, values(dest_port) as targeted_ports by src_ip, threat_category, confidence_score
| fieldformat first_seen=strftime(first_seen, "%Y-%m-%d %H:%M:%S")
| fieldformat last_seen=strftime(last_seen, "%Y-%m-%d %H:%M:%S")
| sort - count
```

### Query 3: High-Priority Ingress Alert (Allowed Malicious Traffic)
Filters for critical incidents where firewall action was `allowed` and confidence score is $\ge 80$.
```spl
sourcetype=firewall_traffic action="allowed"
| lookup threat_intel_malicious_ips.csv ip as src_ip OUTPUT threat_category, confidence_score, description
| where isnotnull(threat_category) AND confidence_score >= 80
| table _time, src_ip, dest_ip, dest_port, transport, action, threat_category, confidence_score, description
```

---

## 5. Verification & Testing
Run any of the queries above in **Splunk Web Search & Reporting**:
1. Open [http://localhost:8000](http://localhost:8000)
2. Log in with `sathvik` / `Sathvik@007`
3. Paste the SPL into Search and select time range **Last 24 hours** or **All time**.

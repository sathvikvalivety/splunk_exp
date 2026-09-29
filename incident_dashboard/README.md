# Incident Investigation Dashboard (4-Panel) in Splunk

## 1. Overview
The **Incident Investigation Dashboard** provides a SOC security monitoring interface that correlates authentication attempts, remote geographic origins, temporal patterns, and diagnostic error codes.

---

## 2. Dashboard Panel Specifications

| Panel # | Panel Name | Visualization | SPL Query | Purpose |
| :--- | :--- | :--- | :--- | :--- |
| **Panel 1** | **Top Failed Logins by Target User** | Bar Chart (`bar`) | `sourcetype=incident:auth action="failure" \| top limit=10 user` | Identifies brute force / credential stuffing targets (e.g. `administrator`, `root`, `admin`). |
| **Panel 2** | **Geolocations of Remote Connections** | Splunk Map (`map`) | `sourcetype=incident:auth \| iplocation src_ip \| where isnotnull(lat) AND isnotnull(lon) \| geostats count by action` | Visualizes source geographic locations worldwide via Splunk's built-in `iplocation` GeoIP database. |
| **Panel 3** | **Timeline of Events (Success vs Failure)** | Area Chart (`area`) | `sourcetype=incident:auth \| timechart span=1h count by action` | Shows authentication activity distribution and attack spikes over time. |
| **Panel 4** | **Raw Error Codes Breakdown** | Table (`table` with heatmap) | `sourcetype=incident:auth action="failure" \| stats count by error_code, error_description \| sort - count \| rename error_code as "Error Code", error_description as "Error Description", count as "Failure Count"` | Categorizes failure causes (e.g. `ERR_AUTH_001` Password mismatch, `ERR_AUTH_002` Account locked, `ERR_AUTH_004` Threat IP). |

---

## 3. How to View the Dashboard in Splunk Web
1. Open [http://localhost:8000](http://localhost:8000)
2. Login with credentials:
   - **Username**: `sathvik`
   - **Password**: `Sathvik@007`
3. Direct URL to Dashboard:
   - [http://localhost:8000/en-US/app/search/incident_investigation](http://localhost:8000/en-US/app/search/incident_investigation)
4. Or navigate in Splunk Web:
   - Click **Search & Reporting** app $\rightarrow$ Click **Dashboards** in the top navigation bar $\rightarrow$ Click **Incident Investigation Dashboard**.

---

## 4. Dashboard XML Source
The dashboard XML is deployed at:
`C:\Program Files\Splunk\etc\apps\search\local\data\ui\views\incident_investigation.xml`
and backed up locally at `incident_dashboard/incident_investigation.xml`.

# Experiment: Detect Suspicious Login Activity with Splunk

## 1. Experiment Overview & Objective
- **Objective**: Build an enterprise-grade Security Operations Center (SOC) Splunk dashboard that automatically detects and visualizes account compromise, brute-force attacks, impossible travel anomalies, credential stuffing, and unusual login patterns from heterogeneous authentication logs.
- **Direct Dashboard Link**: [http://localhost:8000/en-US/app/search/suspicious_login_activity](http://localhost:8000/en-US/app/search/suspicious_login_activity)
- **Splunk Credentials**: `sathvik` / `Sathvik@007`

---

## 2. Ingested Data Sources & Log Schemas

The experiment ingests normalized multi-source authentication telemetry into `index=auth` and `index=main` (`sourcetype=auth:unified`):

| Data Source | Native Format / Event ID | Key Extracted Fields | Purpose |
| :--- | :--- | :--- | :--- |
| **Windows Active Directory** | EventID 4624 (Success), 4625 (Failure) | `user`, `src_ip`, `logon_type`, `status_code`, `dest_host` | Track domain controller and RDP logon attempts. |
| **Linux Server Auth** | `sshd` log (`Failed password`, `Accepted publickey`) | `user`, `src_ip`, `dest_port`, `message`, `app=OpenSSH` | Detect automated SSH dictionary brute-force attacks. |
| **Enterprise VPN Gateway** | Cisco AnyConnect / OpenVPN logs | `user`, `src_ip`, `gateway`, `reason`, `app=VPN` | Monitor remote workforce access and gateway origins. |
| **Cloud IAM / SaaS** | Azure AD / AWS CloudTrail / Okta SSO | `user`, `src_ip`, `app`, `user_agent`, `mfa_status` | Identify cloud credential abuse and impossible travel. |

---

## 3. Simulated Attack Scenarios

The synthetic telemetry generator (`deploy_suspicious_login_exp.ps1`) injects 5 realistic cyberattack scenarios alongside normal baseline traffic:

1. **High-Volume SSH/RDP Brute Force**:
   - *Attacker IP*: `45.154.255.89` (Russia)
   - *Behavior*: 45 rapid consecutive login failures attempting common and admin usernames (`root`, `admin`, `administrator`, `sathvik`).
2. **Account Takeover (Success After Repeated Failures)**:
   - *Attacker IP*: `185.220.101.5` (Tor Exit Node / Germany) & `89.248.165.71` (Netherlands)
   - *Behavior*: 14 consecutive failures against user `sathvik` followed by 1 successful login (`EventID=4624`), indicating a cracked password.
   - *Cloud Behavior*: 11 failed attempts against `finance_user` followed by an `MFA_Bypassed` session establishment.
3. **Impossible Travel Anomaly**:
   - *Scenario A*: User `alice.w` logs in successfully from **Hyderabad, India** (`14.139.120.5`) and **14 minutes later** authenticates to AWS from **Seattle, USA** (`54.240.196.186`).
   - *Scenario B*: User `bob.k` authenticates from **Bengaluru, India** (`49.207.210.15`) and **18 minutes later** establishes a VPN session from **Tokyo, Japan** (`133.242.18.1`).
4. **Unusual Off-Hours Activity**:
   - Privileged administrative logons (`admin`, `sec_ops`) originating at **03:14 AM** and **03:42 AM** from foreign locations using CLI automation tools (`aws-cli/2.9.1`).
5. **Baseline Benign Traffic**:
   - Realistic workforce logons from trusted internal LANs (`192.168.1.0/24`, `10.10.5.0/24`) and Indian corporate public subnets.

---

## 4. Detection Rules & Production SPL Queries

### Detection Rule 1: Successful Login Following Repeated Failures (Account Compromise)
```spl
(index=auth OR index=main) sourcetype=auth*
| stats count(eval(action="failure")) as failures,
        count(eval(action="success")) as successes,
        values(app) as applications,
        latest(_time) as last_seen
        by user, src_ip
| where failures >= 5 AND successes >= 1
| eval last_seen=strftime(last_seen, "%Y-%m-%d %H:%M:%S")
| eval Threat_Level=case(
    failures >= 10, "CRITICAL: High Probability Account Compromise",
    failures >= 5, "HIGH: Password Guessing / Spray Success"
  )
| sort - failures
| rename user as "Target User", src_ip as "Attacking/Origin IP", failures as "Preceding Failures", successes as "Follow-up Successes", applications as "Targeted Service", last_seen as "Compromise Timestamp", Threat_Level as "Threat Severity"
```

### Detection Rule 2: High-Rate Brute Force Detection
```spl
(index=auth OR index=main) sourcetype=auth* action="failure"
| stats count as failed_attempts,
        dc(user) as targeted_users_count,
        values(app) as targeted_services
        by src_ip
| where failed_attempts >= 10
| sort - failed_attempts
```

### Detection Rule 3: Composite User Risk Scoring & Impossible Travel / Off-Hours Indicators
```spl
(index=auth OR index=main) sourcetype=auth* 
| eval hour=strftime(_time, "%H")
| eval is_off_hours=if(hour >= "01" AND hour <= "05", 1, 0)
| stats count(eval(action="failure")) as fail_cnt,
        count(eval(action="success")) as succ_cnt,
        dc(src_ip) as distinct_ips,
        sum(is_off_hours) as off_hours_logins,
        latest(_time) as latest_event
        by user
| eval risk_score = (fail_cnt * 2) + (if(succ_cnt > 0 AND fail_cnt >= 5, 50, 0)) + (distinct_ips * 10) + (off_hours_logins * 15)
| eval Risk_Category = case(
    risk_score >= 70, "HIGH RISK (Immediate Action Required)",
    risk_score >= 30, "MEDIUM RISK (Suspicious Activity)",
    true(), "LOW / NORMAL"
  )
| eval latest_event=strftime(latest_event, "%Y-%m-%d %H:%M:%S")
| sort - risk_score
```

---

## 5. Dashboard Panels Specification

The deployed dashboard `suspicious_login_activity.xml` contains the following sections:

1. **Executive KPI Cards**:
   - Total Authentication Events Processed
   - Total Failed Logins
   - Brute-Force Alert Triggers
   - Compromised Account Leads (Success After Failures)
2. **Panel 1: Failed Logins Over Time (Attack Volumetrics)**
   - *Visualization*: Stacked Column Chart grouped by application (`OpenSSH`, `Windows_RDP`, `Azure_AD_Portal`, `VPN`).
3. **Panel 2: Top Attacking IPs**
   - *Visualization*: Horizontal Bar Chart displaying top attacking source IPs ranked by failure volume and targeted user count.
4. **Panel 3: Most Targeted User Accounts**
   - *Visualization*: Donut / Pie Chart showing proportional distribution of attacks per username.
5. **Panel 4: CRITICAL ALERT — Successful Logins Following Failures**
   - *Visualization*: Interactive Heatmap Table highlighting confirmed account takeover leads.
6. **Panel 5: Global Geographic Login Map**
   - *Visualization*: Interactive World Cluster Map using `iplocation` and `geostats` to pinpoint malicious and legitimate activity hubs.
7. **Panel 6: High-Risk User Matrix & Behavioral Anomaly Scoring**
   - *Visualization*: Color-coded Risk Assessment Table calculating multi-factor risk scores based on failure spikes, off-hours activity, and multi-IP usage.

---

## 6. Verification & Demo Instructions

To run or re-test the entire setup:

```powershell
powershell -ExecutionPolicy Bypass -File "e:\pdfs\notes\4-1\dscc\lab\scripts\deploy_suspicious_login_exp.ps1"
```

1. Open **[http://localhost:8000](http://localhost:8000)** in your browser.
2. Sign in with username: `sathvik` and password: `Sathvik@007`.
3. Open **Dashboards** > **Detect Suspicious Login Activity Dashboard** or use the direct URL:
   `http://localhost:8000/en-US/app/search/suspicious_login_activity`
4. Use the dynamic **User Filter** and **Time Range** controls to drill down into specific user investigations (e.g. `sathvik`, `finance_user`, `alice.w`).

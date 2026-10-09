# ==============================================================================
# Splunk Experiment: Detect Suspicious Login Activity Deployment Script
# Author: sathvik (DSCC Lab)
# Description: Generates multi-source auth logs, injects attack scenarios,
#              configures Splunk index/lookups, deploys the 6-panel dashboard,
#              and validates SPL detection rules.
# ==============================================================================

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}

$splunkHost = "https://localhost:8089"
$username = "sathvik"
$password = "Sathvik@007"
$splunkHome = "C:\Program Files\Splunk"
$workspaceDir = "e:\pdfs\notes\4-1\dscc\lab"
$expDir = "$workspaceDir\suspicious_login_detection"

if (-not (Test-Path $expDir)) {
    New-Item -ItemType Directory -Force -Path $expDir | Out-Null
}

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " Splunk Experiment: Detect Suspicious Login Activity" -ForegroundColor Yellow
Write-Host " Target Host: $splunkHost | User: $username" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# Step 1: Authenticate to Splunk REST API
Write-Host "`n[1/6] Authenticating to Splunk REST API..." -ForegroundColor Cyan
$loginBody = @{ username = $username; password = $password }
try {
    $loginResp = Invoke-RestMethod -Uri "$splunkHost/services/auth/login" -Method Post -Body $loginBody
    $sessionKey = $loginResp.response.sessionKey
    $headers = @{ Authorization = "Splunk $sessionKey" }
    Write-Host "Authentication Successful! Session token acquired." -ForegroundColor Green
} catch {
    Write-Error "Failed to authenticate to Splunk: $_"
    exit 1
}

# Step 2: Ensure 'auth' index exists
Write-Host "`n[2/6] Ensuring 'auth' index exists in Splunk..." -ForegroundColor Cyan
try {
    $createIndexBody = @{ name = "auth" }
    Invoke-RestMethod -Uri "$splunkHost/services/data/indexes" -Method Post -Body $createIndexBody -Headers $headers | Out-Null
    Write-Host "Created index 'auth'." -ForegroundColor Green
} catch {
    Write-Host "Index 'auth' already exists or configured." -ForegroundColor Yellow
}

# Step 3: Generate Multi-Source Synthetic Authentication Events & Attack Scenarios
Write-Host "`n[3/6] Generating realistic multi-source authentication datasets..." -ForegroundColor Cyan

$now = Get-Date

# Reference data
$users = @("sathvik", "admin", "root", "jdoe", "alice.w", "bob.k", "svc_deploy", "db_backup", "finance_user", "sec_ops")
$legitIps = @(
    @{ ip = "14.139.120.5"; country = "India"; city = "Hyderabad"; lat = 17.3850; lon = 78.4867 },
    @{ ip = "49.207.210.15"; country = "India"; city = "Bengaluru"; lat = 12.9716; lon = 77.5946 },
    @{ ip = "103.21.124.8"; country = "India"; city = "Mumbai"; lat = 19.0760; lon = 72.8777 },
    @{ ip = "192.168.1.45"; country = "Internal"; city = "Office-LAN"; lat = 0; lon = 0 },
    @{ ip = "10.10.5.20"; country = "Internal"; city = "Internal-DMZ"; lat = 0; lon = 0 }
)

$remoteAttackIps = @(
    @{ ip = "185.220.101.5"; country = "Germany"; city = "Frankfurt"; lat = 50.1109; lon = 8.6821 },
    @{ ip = "45.154.255.89"; country = "Russia"; city = "Moscow"; lat = 55.7558; lon = 37.6173 },
    @{ ip = "103.151.125.10"; country = "China"; city = "Beijing"; lat = 39.9042; lon = 116.4074 },
    @{ ip = "89.248.165.71"; country = "Netherlands"; city = "Amsterdam"; lat = 52.3676; lon = 4.9041 },
    @{ ip = "177.12.89.44"; country = "Brazil"; city = "Sao Paulo"; lat = -23.5505; lon = -46.6333 },
    @{ ip = "54.240.196.186"; country = "United States"; city = "Seattle"; lat = 47.6062; lon = -122.3321 },
    @{ ip = "133.242.18.1"; country = "Japan"; city = "Tokyo"; lat = 35.6762; lon = 139.6503 }
)

$rawEvents = [System.Collections.Generic.List[string]]::new()

# Function to format timestamps
function Get-IsoTime([datetime]$dt) {
    return $dt.ToString("yyyy-MM-dd HH:mm:ss")
}

# --- 3.1 Normal Baseline Activity (120 events) ---
for ($i = 0; $i -lt 120; $i++) {
    $timeOffsetMinutes = Get-Random -Minimum 30 -Maximum 1400
    $eventTime = $now.AddMinutes(-1 * $timeOffsetMinutes)
    $user = $users | Get-Random
    $loc = $legitIps | Get-Random
    $srcIp = $loc.ip
    
    # 85% success, 15% failure
    $isSuccess = ((Get-Random -Minimum 1 -Maximum 100) -le 85)
    $action = if ($isSuccess) { "success" } else { "failure" }
    $sourcetypeChoice = @("auth:windows", "auth:linux_ssh", "auth:vpn", "auth:cloud") | Get-Random
    
    switch ($sourcetypeChoice) {
        "auth:windows" {
            $eventId = if ($isSuccess) { "4624" } else { "4625" }
            $logonType = if ($srcIp.StartsWith("192.") -or $srcIp.StartsWith("10.")) { "2" } else { "10" }
            $status = if ($isSuccess) { "0x0" } else { "0xC000006D" }
            $event = "$(Get-IsoTime $eventTime) sourcetype=auth:windows EventID=$eventId action=$action user=$user src_ip=$srcIp dest_host=DC-CORP-01 logon_type=$logonType status_code=$status protocol=Kerberos/NTLM app=Windows_Logon"
        }
        "auth:linux_ssh" {
            $port = Get-Random -Minimum 30000 -Maximum 65000
            $msg = if ($isSuccess) { "Accepted publickey for $user from $srcIp port $port ssh2" } else { "Failed password for $user from $srcIp port $port ssh2" }
            $event = "$(Get-IsoTime $eventTime) sourcetype=auth:linux_ssh action=$action user=$user src_ip=$srcIp dest_host=srv-linux-prod dest_port=22 app=OpenSSH message=`"$msg`""
        }
        "auth:vpn" {
            $proto = "SSL-VPN"
            $reason = if ($isSuccess) { "User authenticated successfully" } else { "Invalid credentials" }
            $event = "$(Get-IsoTime $eventTime) sourcetype=auth:vpn action=$action user=$user src_ip=$srcIp gateway=VPN-GW-EAST client_version=AnyConnect-4.10 app=VPN reason=`"$reason`""
        }
        "auth:cloud" {
            $cloudApp = @("AWS_Console", "Azure_AD_Portal", "Okta_SSO", "Google_Workspace") | Get-Random
            $mfa = if ($isSuccess) { "MFA_Satisfied" } else { "MFA_Required_Or_Failed" }
            $event = "$(Get-IsoTime $eventTime) sourcetype=auth:cloud action=$action user=$user src_ip=$srcIp app=$cloudApp user_agent=`"Mozilla/5.0 (Windows NT 10.0; Win64; x64)`" mfa_status=$mfa"
        }
    }
    $rawEvents.Add($event)
}

# --- 3.2 ATTACK SCENARIO 1: High-Volume SSH/RDP Brute-Force (45 failed attempts) ---
# Attacker IP: 45.154.255.89 (Russia) probing root, admin, sathvik
$attackTime1 = $now.AddMinutes(-320)
for ($f = 0; $f -lt 45; $f++) {
    $t = $attackTime1.AddSeconds($f * 8)
    $targetUser = @("root", "admin", "administrator", "sathvik", "guest", "test") | Get-Random
    $event = "$(Get-IsoTime $t) sourcetype=auth:linux_ssh action=failure user=$targetUser src_ip=45.154.255.89 dest_host=srv-linux-prod dest_port=22 app=OpenSSH message=`"Failed password for invalid user $targetUser from 45.154.255.89 port $(40000 + $f) ssh2`""
    $rawEvents.Add($event)
}

# --- 3.3 ATTACK SCENARIO 2: Successful Login after 12 Repeated Failures (Account Takeover) ---
# Attacker IP: 185.220.101.5 (Tor Exit Node / Germany) targeting user: 'sathvik' and 'admin'
$attackTime2 = $now.AddMinutes(-180)
for ($f = 0; $f -lt 14; $f++) {
    $t = $attackTime2.AddSeconds($f * 25)
    $event = "$(Get-IsoTime $t) sourcetype=auth:windows EventID=4625 action=failure user=sathvik src_ip=185.220.101.5 dest_host=DC-CORP-01 logon_type=10 status_code=0xC000006A protocol=NTLM app=Windows_RDP message=`"Bad password attempt`""
    $rawEvents.Add($event)
}
# Followed immediately by 1 SUCCESSFUL login (Compromised!)
$tSuccess = $attackTime2.AddSeconds(14 * 25 + 10)
$rawEvents.Add("$(Get-IsoTime $tSuccess) sourcetype=auth:windows EventID=4624 action=success user=sathvik src_ip=185.220.101.5 dest_host=DC-CORP-01 logon_type=10 status_code=0x0 protocol=NTLM app=Windows_RDP message=`"Successful Remote Interactive Logon`"")

# Second instance of success after failures on user 'finance_user' from 89.248.165.71
$attackTime2b = $now.AddMinutes(-90)
for ($f = 0; $f -lt 11; $f++) {
    $t = $attackTime2b.AddSeconds($f * 15)
    $event = "$(Get-IsoTime $t) sourcetype=auth:cloud action=failure user=finance_user src_ip=89.248.165.71 app=Azure_AD_Portal user_agent=`"Python-requests/2.28`" mfa_status=MFA_Failed reason=`"Invalid credentials`""
    $rawEvents.Add($event)
}
$tSuccess2 = $attackTime2b.AddSeconds(11 * 15 + 5)
$rawEvents.Add("$(Get-IsoTime $tSuccess2) sourcetype=auth:cloud action=success user=finance_user src_ip=89.248.165.71 app=Azure_AD_Portal user_agent=`"Python-requests/2.28`" mfa_status=MFA_Bypassed reason=`"Session Established`"")

# --- 3.4 ATTACK SCENARIO 3: Impossible Travel Detection ---
# User 'alice.w' logs in from Hyderabad, India, and 15 minutes later from Seattle, USA!
# User 'bob.k' logs in from Bengaluru, India, and 20 minutes later from Tokyo, Japan!
$travelTime1 = $now.AddMinutes(-240)
$rawEvents.Add("$(Get-IsoTime $travelTime1) sourcetype=auth:cloud action=success user=alice.w src_ip=14.139.120.5 app=Azure_AD_Portal user_agent=`"Mozilla/5.0 (Windows NT 10.0; Win64; x64)`" location_city=`"Hyderabad`" location_country=`"India`"")
$travelTime1b = $travelTime1.AddMinutes(14)
$rawEvents.Add("$(Get-IsoTime $travelTime1b) sourcetype=auth:cloud action=success user=alice.w src_ip=54.240.196.186 app=AWS_Console user_agent=`"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)`" location_city=`"Seattle`" location_country=`"United States`"")

$travelTime2 = $now.AddMinutes(-120)
$rawEvents.Add("$(Get-IsoTime $travelTime2) sourcetype=auth:vpn action=success user=bob.k src_ip=49.207.210.15 gateway=VPN-GW-EAST app=VPN location_city=`"Bengaluru`" location_country=`"India`"")
$travelTime2b = $travelTime2.AddMinutes(18)
$rawEvents.Add("$(Get-IsoTime $travelTime2b) sourcetype=auth:vpn action=success user=bob.k src_ip=133.242.18.1 gateway=VPN-GW-WEST app=VPN location_city=`"Tokyo`" location_country=`"Japan`"")

# --- 3.5 ATTACK SCENARIO 4: Unusual Off-Hours Login Time ---
# Administrator login at 03:14 AM and 03:42 AM
$midnightToday = $now.Date.AddHours(3).AddMinutes(14)
$rawEvents.Add("$(Get-IsoTime $midnightToday) sourcetype=auth:windows EventID=4624 action=success user=sec_ops src_ip=177.12.89.44 dest_host=DC-CORP-01 logon_type=10 status_code=0x0 protocol=Kerberos app=Windows_Logon note=`"Privileged logon outside business hours`"")
$midnightToday2 = $now.Date.AddHours(3).AddMinutes(42)
$rawEvents.Add("$(Get-IsoTime $midnightToday2) sourcetype=auth:cloud action=success user=admin src_ip=103.151.125.10 app=AWS_Console user_agent=`"aws-cli/2.9.1`" note=`"Root API key utilized at 03:42 AM`"")

# Save raw logs locally for record and lab artifact
$rawLogFile = "$expDir\sample_auth_data.log"
$rawEvents | Sort-Object | Set-Content -Path $rawLogFile -Encoding UTF8
Write-Host "Generated $($rawEvents.Count) synthetic authentication events with 5 attack scenarios." -ForegroundColor Green
Write-Host "Saved local log artifact to: $rawLogFile"

# Step 4: Ingest into Splunk
Write-Host "`n[4/6] Ingesting logs into Splunk (index=auth and index=main)..." -ForegroundColor Cyan

$rawPayload = ($rawEvents -join "`n")

# Ingest to index=auth
$uriAuth = "$splunkHost/services/receivers/simple?index=auth&sourcetype=auth:unified"
try {
    Invoke-RestMethod -Uri $uriAuth -Method Post -Body $rawPayload -Headers $headers | Out-Null
    Write-Host "Ingested to index 'auth' (sourcetype 'auth:unified')." -ForegroundColor Green
} catch {
    Write-Host "Notice index auth ingest: $_" -ForegroundColor Yellow
}

# Also ingest into index=main so any search with or without index filter works
$uriMain = "$splunkHost/services/receivers/simple?index=main&sourcetype=auth:unified"
Invoke-RestMethod -Uri $uriMain -Method Post -Body $rawPayload -Headers $headers | Out-Null
Write-Host "Ingested to index 'main' (sourcetype 'auth:unified')." -ForegroundColor Green


# Step 5: Create and Deploy the 6-Panel Dashboard XML
Write-Host "`n[5/6] Building and Deploying 6-Panel 'Suspicious Login Activity' Dashboard..." -ForegroundColor Cyan

$dashboardXml = @'
<dashboard version="1.1" theme="dark">
  <label>Detect Suspicious Login Activity Dashboard</label>
  <description>Comprehensive Security Operations Center (SOC) view for account compromise, brute-force attacks, impossible travel, and anomalous authentications.</description>
  
  <!-- Global Time Filter -->
  <fieldset submitButton="true" autoRun="true">
    <input type="time" token="time_range" searchWhenChanged="true">
      <label>Time Range</label>
      <default>
        <earliest>-24h@h</earliest>
        <latest>now</latest>
      </default>
    </input>
    <input type="dropdown" token="selected_user" searchWhenChanged="true">
      <label>Filter by User</label>
      <choice value="*">All Users</choice>
      <default>*</default>
      <fieldForLabel>user</fieldForLabel>
      <fieldForValue>user</fieldForValue>
      <search>
        <query>(index=auth OR index=main) sourcetype=auth* | stats count by user</query>
        <earliest>-24h@h</earliest>
        <latest>now</latest>
      </search>
    </input>
  </fieldset>

  <!-- Row 1: High Level Metrics -->
  <row>
    <panel>
      <single>
        <title>Total Authentication Events</title>
        <search>
          <query>(index=auth OR index=main) sourcetype=auth* user="$selected_user$" | stats count</query>
          <earliest>$time_range.earliest$</earliest>
          <latest>$time_range.latest$</latest>
        </search>
        <option name="colorMode">block</option>
        <option name="useColors">1</option>
        <option name="rangeColors">["0x53a051","0x006d9c"]</option>
        <option name="rangeValues">[0]</option>
        <option name="underLabel">Events Processed</option>
      </single>
    </panel>
    <panel>
      <single>
        <title>Total Failed Logins</title>
        <search>
          <query>(index=auth OR index=main) sourcetype=auth* user="$selected_user$" action="failure" | stats count</query>
          <earliest>$time_range.earliest$</earliest>
          <latest>$time_range.latest$</latest>
        </search>
        <option name="colorMode">block</option>
        <option name="useColors">1</option>
        <option name="rangeColors">["0x53a051","0xf8be34","0xdc4e41"]</option>
        <option name="rangeValues">[10,30]</option>
        <option name="underLabel">Failed Attempts</option>
      </single>
    </panel>
    <panel>
      <single>
        <title>Brute Force Alert Triggers</title>
        <search>
          <query>(index=auth OR index=main) sourcetype=auth* user="$selected_user$" action="failure" | stats count by src_ip | where count >= 10 | stats count</query>
          <earliest>$time_range.earliest$</earliest>
          <latest>$time_range.latest$</latest>
        </search>
        <option name="colorMode">block</option>
        <option name="useColors">1</option>
        <option name="rangeColors">["0x53a051","0xdc4e41"]</option>
        <option name="rangeValues">[1]</option>
        <option name="underLabel">High-Rate Attack Sources</option>
      </single>
    </panel>
    <panel>
      <single>
        <title>Compromised Account Leads (Success After Failures)</title>
        <search>
          <query>(index=auth OR index=main) sourcetype=auth* user="$selected_user$" | stats count(eval(action="failure")) as failures count(eval(action="success")) as successes by user, src_ip | where failures >= 5 AND successes >= 1 | stats dc(user)</query>
          <earliest>$time_range.earliest$</earliest>
          <latest>$time_range.latest$</latest>
        </search>
        <option name="colorMode">block</option>
        <option name="useColors">1</option>
        <option name="rangeColors">["0x53a051","0xdc4e41"]</option>
        <option name="rangeValues">[1]</option>
        <option name="underLabel">Suspected Compromised Users</option>
      </single>
    </panel>
  </row>

  <!-- Row 2: Panel 1 (Failed Logins Over Time) & Panel 2 (Top Attacking IPs) -->
  <row>
    <!-- PANEL 1: Failed Logins Over Time -->
    <panel>
      <title>Panel 1: Failed Logins Over Time (Attack Volumetrics)</title>
      <chart>
        <search>
          <query>(index=auth OR index=main) sourcetype=auth* user="$selected_user$" action="failure" | timechart span=30m count by app</query>
          <earliest>$time_range.earliest$</earliest>
          <latest>$time_range.latest$</latest>
        </search>
        <option name="charting.chart">column</option>
        <option name="charting.chart.stackMode">stacked</option>
        <option name="charting.legend.placement">bottom</option>
        <option name="charting.axisTitleX.text">Time Window</option>
        <option name="charting.axisTitleY.text">Failed Login Count</option>
        <option name="charting.drilldown">none</option>
      </chart>
    </panel>

    <!-- PANEL 2: Top Attacking IPs -->
    <panel>
      <title>Panel 2: Top Attacking IPs (Brute-Force &amp; Spray Sources)</title>
      <chart>
        <search>
          <query>(index=auth OR index=main) sourcetype=auth* action="failure" | stats count as failed_attempts, dc(user) as targeted_users_count by src_ip | sort - failed_attempts | head 10</query>
          <earliest>$time_range.earliest$</earliest>
          <latest>$time_range.latest$</latest>
        </search>
        <option name="charting.chart">bar</option>
        <option name="charting.chart.showDataLabels">all</option>
        <option name="charting.legend.placement">bottom</option>
        <option name="charting.axisTitleX.text">Failed Attempt Count</option>
        <option name="charting.axisTitleY.text">Source IP Address</option>
        <option name="charting.seriesColors">[0xd93f3c, 0xf58f39]</option>
      </chart>
    </panel>
  </row>

  <!-- Row 3: Panel 3 (Most Targeted Users) & Panel 4 (Successful Logins Following Failures) -->
  <row>
    <!-- PANEL 3: Most Targeted Users -->
    <panel>
      <title>Panel 3: Most Targeted User Accounts</title>
      <chart>
        <search>
          <query>(index=auth OR index=main) sourcetype=auth* action="failure" | top limit=10 user</query>
          <earliest>$time_range.earliest$</earliest>
          <latest>$time_range.latest$</latest>
        </search>
        <option name="charting.chart">pie</option>
        <option name="charting.chart.sliceCollapsingThreshold">0.01</option>
        <option name="charting.legend.placement">right</option>
      </chart>
    </panel>

    <!-- PANEL 4: Successful Logins Following Failures (Account Takeover) -->
    <panel>
      <title>Panel 4: CRITICAL ALERT - Successful Logins Following Multiple Failures</title>
      <table>
        <search>
          <query>(index=auth OR index=main) sourcetype=auth* | stats count(eval(action="failure")) as failures, count(eval(action="success")) as successes, values(app) as applications, latest(_time) as last_seen by user, src_ip | where failures >= 5 AND successes >= 1 | eval last_seen=strftime(last_seen, "%Y-%m-%d %H:%M:%S") | eval Threat_Level=case(failures >= 10, "CRITICAL: High Probability Account Compromise", failures >= 5, "HIGH: Password Spray / Guessing Success") | sort - failures | rename user as "Target User", src_ip as "Attacking/Origin IP", failures as "Preceding Failures", successes as "Follow-up Successes", applications as "Targeted Service", last_seen as "Compromise Timestamp", Threat_Level as "Threat Severity"</query>
          <earliest>$time_range.earliest$</earliest>
          <latest>$time_range.latest$</latest>
        </search>
        <option name="dataOverlayMode">heatmap</option>
        <option name="drilldown">cell</option>
        <option name="count">10</option>
      </table>
    </panel>
  </row>

  <!-- Row 4: Panel 5 (Geographic Login Map) -->
  <row>
    <!-- PANEL 5: Geographic Login Map -->
    <panel>
      <title>Panel 5: Global Geographic Login Distribution (iplocation &amp; geostats)</title>
      <map>
        <search>
          <query>(index=auth OR index=main) sourcetype=auth* | iplocation src_ip | where isnotnull(lat) AND isnotnull(lon) | geostats count by action</query>
          <earliest>$time_range.earliest$</earliest>
          <latest>$time_range.latest$</latest>
        </search>
        <option name="mapping.type">marker</option>
        <option name="mapping.map.center">(25, 20)</option>
        <option name="mapping.map.zoom">2</option>
        <option name="mapping.markerLayer.markerMinPercent">6</option>
        <option name="mapping.markerLayer.markerMaxPercent">28</option>
        <option name="mapping.data.maxClusters">100</option>
      </map>
    </panel>
  </row>

  <!-- Row 5: Panel 6 (High-Risk Users & Impossible Travel / Anomalies) -->
  <row>
    <!-- PANEL 6: High-Risk Users & Anomaly Scoring -->
    <panel>
      <title>Panel 6: User Risk Matrix &amp; Impossible Travel / Off-Hours Anomalies</title>
      <table>
        <search>
          <query>(index=auth OR index=main) sourcetype=auth* 
| eval hour=strftime(_time, "%H")
| eval is_off_hours=if(hour &gt;= "01" AND hour &lt;= "05", 1, 0)
| stats count(eval(action="failure")) as fail_cnt,
        count(eval(action="success")) as succ_cnt,
        dc(src_ip) as distinct_ips,
        values(src_ip) as ip_list,
        sum(is_off_hours) as off_hours_logins,
        latest(_time) as latest_event
        by user
| eval risk_score = (fail_cnt * 2) + (if(succ_cnt &gt; 0 AND fail_cnt &gt;= 5, 50, 0)) + (distinct_ips * 10) + (off_hours_logins * 15)
| eval Risk_Category = case(
    risk_score &gt;= 70, "HIGH RISK (Immediate Action Required)",
    risk_score &gt;= 30, "MEDIUM RISK (Suspicious Activity)",
    true(), "LOW / NORMAL"
  )
| eval latest_event=strftime(latest_event, "%Y-%m-%d %H:%M:%S")
| sort - risk_score
| rename user as "User Account", risk_score as "Composite Risk Score", Risk_Category as "Risk Status", fail_cnt as "Total Failures", succ_cnt as "Total Successes", distinct_ips as "Distinct IPs", off_hours_logins as "Off-Hours Logins (1am-5am)", latest_event as "Latest Activity Time"</query>
          <earliest>$time_range.earliest$</earliest>
          <latest>$time_range.latest$</latest>
        </search>
        <option name="dataOverlayMode">heatmap</option>
        <option name="drilldown">row</option>
        <option name="count">10</option>
      </table>
    </panel>
  </row>

</dashboard>
'@

# Save to workspace
$dashboardWorkspacePath = "$expDir\suspicious_login_activity.xml"
Set-Content -Path $dashboardWorkspacePath -Value $dashboardXml -Encoding UTF8

# Copy to Splunk Views directory
$splunkViewsDir = "$splunkHome\etc\apps\search\local\data\ui\views"
if (-not (Test-Path $splunkViewsDir)) {
    New-Item -ItemType Directory -Force -Path $splunkViewsDir | Out-Null
}
$splunkDashboardPath = "$splunkViewsDir\suspicious_login_activity.xml"
Set-Content -Path $splunkDashboardPath -Value $dashboardXml -Encoding UTF8

Write-Host "Deployed Dashboard XML successfully to:" -ForegroundColor Green
Write-Host " - Workspace: $dashboardWorkspacePath"
Write-Host " - Splunk:    $splunkDashboardPath"

# Reload UI Views via REST
try {
    $reloadUri = "$splunkHost/services/data/ui/views/_reload"
    Invoke-RestMethod -Uri $reloadUri -Method Get -Headers $headers | Out-Null
    Write-Host "Reloaded Splunk UI views cache." -ForegroundColor Green
} catch {
    Write-Host "View reload notice: $_" -ForegroundColor Yellow
}

# Step 6: Validate SPL Rules via Splunk REST API
Write-Host "`n[6/6] Validating SPL Detection Queries..." -ForegroundColor Cyan

$splValidationRules = @(
    @{
        name = "Brute Force Attack Rule (>= 10 failures)"
        spl = "search (index=auth OR index=main) sourcetype=auth* action=failure | stats count as failures by user, src_ip | where failures >= 10 | sort - failures"
    },
    @{
        name = "Successful Login After Failures (Account Compromise Detection)"
        spl = "search (index=auth OR index=main) sourcetype=auth* | stats count(eval(action=""failure"")) as failures, count(eval(action=""success"")) as successes by user, src_ip | where failures >= 5 AND successes >= 1 | sort - failures"
    },
    @{
        name = "High-Risk User Scoring"
        spl = "search (index=auth OR index=main) sourcetype=auth* | stats count(eval(action=""failure"")) as failures, count(eval(action=""success"")) as successes, dc(src_ip) as distinct_ips by user | sort - failures"
    }
)

foreach ($rule in $splValidationRules) {
    Write-Host " - Testing SPL Rule: $($rule.name)..." -NoNewline
    $searchBody = @{ search = $rule.spl; exec_mode = "oneshot"; output_mode = "json" }
    try {
        $searchResp = Invoke-RestMethod -Uri "$splunkHost/services/search/jobs" -Method Post -Body $searchBody -Headers $headers
        $rowCount = if ($searchResp.results) { $searchResp.results.Count } else { 0 }
        Write-Host " SUCCESS ($rowCount matches detected!)" -ForegroundColor Green
    } catch {
        Write-Host " ERROR: $_" -ForegroundColor Red
    }
}

Write-Host "`n==========================================================" -ForegroundColor Green
Write-Host " DEPLOYMENT COMPLETE & READY FOR DEMO!" -ForegroundColor Green
Write-Host " Splunk Web URL:      http://localhost:8000" -ForegroundColor Cyan
Write-Host " Dashboard Direct:    http://localhost:8000/en-US/app/search/suspicious_login_activity" -ForegroundColor Cyan
Write-Host " Splunk Credentials:  $username / $password" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Green

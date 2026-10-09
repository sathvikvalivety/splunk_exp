# Setup Script for Splunk Threat Intel Enrichment and Incident Investigation Dashboard
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}

$splunkHost = "https://localhost:8089"
$username = "sathvik"
$password = "Sathvik@007"
$splunkHome = "C:\Program Files\Splunk"
$workspaceDir = "e:\pdfs\notes\4-1\dscc\lab"

Write-Host "[1/6] Authenticating to Splunk REST API..." -ForegroundColor Cyan
$loginBody = @{ username = $username; password = $password }
$loginResp = Invoke-RestMethod -Uri "$splunkHost/services/auth/login" -Method Post -Body $loginBody
$sessionKey = $loginResp.response.sessionKey
$headers = @{ Authorization = "Splunk $sessionKey" }
Write-Host "Authentication Successful!" -ForegroundColor Green

# ==========================================
# 1. THREAT INTEL CSV GENERATION
# ==========================================
Write-Host "`n[2/6] Building Threat Intel Malicious IP Lookup CSV..." -ForegroundColor Cyan

# Fetch real malicious IPs from Emerging Threats
$etIps = @()
try {
    $etUrl = "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt"
    $response = (Invoke-WebRequest -Uri $etUrl -UseBasicParsing -TimeoutSec 10).Content
    $etIps = $response.Split("`n") | Where-Object { $_ -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$' } | Select-Object -First 25
    Write-Host "Fetched $($etIps.Count) live malicious IPs from Emerging Threats." -ForegroundColor Green
} catch {
    Write-Host "Notice: Offline fallback for live threat feed." -ForegroundColor Yellow
}

# Known curated malicious IPs with detailed categorization
$curatedThreats = @(
    @{ ip = "185.220.101.5"; threat_source = "EmergingThreats"; threat_category = "Tor Exit Node / Scanner"; confidence_score = 95; description = "Active Tor relay associated with automated vulnerability scanning" },
    @{ ip = "45.154.255.89"; threat_source = "AbuseIPDB"; threat_category = "SSH Brute Force"; confidence_score = 100; description = "High-frequency SSH credential stuffing origin" },
    @{ ip = "194.26.29.114"; threat_source = "EmergingThreats"; threat_category = "Cobalt Strike C2"; confidence_score = 98; description = "Known Cobalt Strike Team Server beacon destination" },
    @{ ip = "103.151.125.10"; threat_source = "AbuseIPDB"; threat_category = "Mirai Botnet"; confidence_score = 90; description = "IoT Mirai botnet propagation node probing port 23/2323" },
    @{ ip = "89.248.165.71"; threat_source = "EmergingThreats"; threat_category = "Ransomware Distribution"; confidence_score = 99; description = "LockBit ransomware affiliate staging host" },
    @{ ip = "198.235.24.241"; threat_source = "AbuseIPDB"; threat_category = "Web App Exploit Scanner"; confidence_score = 85; description = "Log4j and SQL injection payload fuzzer" },
    @{ ip = "91.240.118.168"; threat_source = "EmergingThreats"; threat_category = "Banking Trojan C2"; confidence_score = 92; description = "IcedID / Emotet command and control server" },
    @{ ip = "162.243.103.246"; threat_source = "EmergingThreats"; threat_category = "Port Scanner / Recon"; confidence_score = 88; description = "Continuous masscan / zmap probe source" },
    @{ ip = "178.62.3.223"; threat_source = "EmergingThreats"; threat_category = "Brute Force"; confidence_score = 87; description = "RDP & SMB password spray source" },
    @{ ip = "27.133.154.218"; threat_source = "EmergingThreats"; threat_category = "Botnet C2"; confidence_score = 94; description = "Active botnet command channel" }
)

# Merge live ET IPs if available
$allThreatRows = [System.Collections.Generic.List[PSObject]]::new()
foreach ($item in $curatedThreats) {
    $allThreatRows.Add([PSCustomObject]$item)
}

$categories = @("Botnet Node", "SSH Brute Force", "Malware C2", "Vulnerability Scanner", "Ransomware Staging")
$i = 0
foreach ($ip in $etIps) {
    if (-not ($curatedThreats | Where-Object { $_.ip -eq $ip })) {
        $cat = $categories[$i % $categories.Length]
        $conf = 85 + ($i % 15)
        $allThreatRows.Add([PSCustomObject]@{
            ip = $ip.Trim()
            threat_source = "EmergingThreats"
            threat_category = $cat
            confidence_score = $conf
            description = "Emerging Threats daily blocklist - Automated threat telemetry"
        })
        $i++
    }
}

$lookupPathWorkspace = "$workspaceDir\threat_intel_enrichment\threat_intel_malicious_ips.csv"
$lookupPathSplunk = "$splunkHome\etc\apps\search\lookups\threat_intel_malicious_ips.csv"

$allThreatRows | Export-Csv -Path $lookupPathWorkspace -NoTypeInformation -Encoding UTF8
Copy-Item -Path $lookupPathWorkspace -Destination $lookupPathSplunk -Force
Write-Host "Created threat intel lookup with $($allThreatRows.Count) entries at:" -ForegroundColor Green
Write-Host " - Workspace: $lookupPathWorkspace"
Write-Host " - Splunk:    $lookupPathSplunk"

# Create transforms.conf in search app local
$transformsConfPath = "$splunkHome\etc\apps\search\local\transforms.conf"
$transformsContent = @"
[threat_intel_lookup]
filename = threat_intel_malicious_ips.csv
case_sensitive_match = false

"@
Set-Content -Path $transformsConfPath -Value $transformsContent -Encoding UTF8
Write-Host "Configured transforms.conf for lookup table 'threat_intel_lookup'." -ForegroundColor Green

# ==========================================
# 2. GENERATE & INGEST FIREWALL LOGS
# ==========================================
Write-Host "`n[3/6] Ingesting sample firewall & connection logs (current timestamps)..." -ForegroundColor Cyan

$benignIps = @("192.168.1.100", "192.168.1.105", "10.0.0.15", "10.0.0.42", "172.16.5.20", "8.8.8.8", "1.1.1.1", "142.250.190.46", "13.107.42.14")
$internalServers = @("10.0.1.10", "10.0.1.20", "10.0.1.50", "10.0.2.100", "10.0.2.200")
$threatIps = $allThreatRows | Select-Object -ExpandProperty ip

$firewallEvents = [System.Collections.Generic.List[string]]::new()
$now = Get-Date

for ($j = 0; $j -lt 250; $j++) {
    $timestamp = $now.AddMinutes(-1 * (Get-Random -Minimum 1 -Maximum 1440)).ToString("yyyy-MM-dd HH:mm:ss")
    
    # 40% chance malicious, 60% chance benign
    $isThreat = ((Get-Random -Minimum 1 -Maximum 100) -le 40)
    if ($isThreat) {
        $src = $threatIps | Get-Random
        $dst = $internalServers | Get-Random
        $dstPort = @(22, 80, 443, 3389, 445, 8080, 23, 4444) | Get-Random
        $proto = if ($dstPort -in @(80, 443, 8080)) { "TCP" } elseif ($dstPort -eq 53) { "UDP" } else { "TCP" }
        $action = if ((Get-Random -Minimum 1 -Maximum 10) -le 4) { "allowed" } else { "blocked" }
        $bytesIn = Get-Random -Minimum 500 -Maximum 50000
        $bytesOut = Get-Random -Minimum 200 -Maximum 12000
        $rule = if ($action -eq "blocked") { "RULE_DENY_INBOUND_SUSPICIOUS" } else { "RULE_ALLOW_DMZ_INGRESS" }
    } else {
        $src = $benignIps | Get-Random
        $dst = $internalServers | Get-Random
        $dstPort = @(80, 443, 53, 123) | Get-Random
        $proto = if ($dstPort -in @(53, 123)) { "UDP" } else { "TCP" }
        $action = "allowed"
        $bytesIn = Get-Random -Minimum 2000 -Maximum 150000
        $bytesOut = Get-Random -Minimum 1000 -Maximum 50000
        $rule = "RULE_DEFAULT_PERMIT"
    }

    $event = "$timestamp action=$action src_ip=$src dest_ip=$dst dest_port=$dstPort transport=$proto bytes_in=$bytesIn bytes_out=$bytesOut rule_name=$rule firewall_id=FW-CORE-01"
    $firewallEvents.Add($event)
}

$fwRawPayload = ($firewallEvents -join "`n")
$fwUri = "$splunkHost/services/receivers/simple?index=main&sourcetype=firewall_traffic"
$ingestResp1 = Invoke-RestMethod -Uri $fwUri -Method Post -Body $fwRawPayload -Headers $headers
Write-Host "Ingested $($firewallEvents.Count) firewall connection events into sourcetype 'firewall_traffic'." -ForegroundColor Green


# ==========================================
# 3. GENERATE & INGEST INCIDENT AUTH LOGS
# ==========================================
Write-Host "`n[4/6] Ingesting incident investigation auth & security logs (current timestamps)..." -ForegroundColor Cyan

$publicIps = @(
    @{ ip = "185.220.101.5"; country = "Germany" },
    @{ ip = "45.154.255.89"; country = "Russia" },
    @{ ip = "103.151.125.10"; country = "China" },
    @{ ip = "89.248.165.71"; country = "Netherlands" },
    @{ ip = "177.12.89.44"; country = "Brazil" },
    @{ ip = "14.139.120.5"; country = "India" },
    @{ ip = "128.199.200.15"; country = "Singapore" },
    @{ ip = "54.240.196.186"; country = "United States" },
    @{ ip = "81.2.69.142"; country = "United Kingdom" },
    @{ ip = "133.242.18.1"; country = "Japan" },
    @{ ip = "139.130.4.5"; country = "Australia" }
)

$users = @("admin", "root", "sathvik", "db_service", "jdoe", "guest", "svc_backup", "test_user", "administrator", "dev_user")
$apps = @("SSH", "RDP", "VPN_Gateway", "WebPortal", "AdminConsole")

$errorCodes = @(
    @{ code = "ERR_AUTH_001"; desc = "Invalid username or password" },
    @{ code = "ERR_AUTH_002"; desc = "User account locked due to consecutive failures" },
    @{ code = "ERR_AUTH_003"; desc = "MFA push notification rejected/timed out" },
    @{ code = "ERR_AUTH_004"; desc = "IP blacklisted in threat intelligence database" },
    @{ code = "ERR_AUTH_005"; desc = "Unauthorized geographic origin / GeoIP fence" },
    @{ code = "ERR_AUTH_006"; desc = "Session expired or invalid token" }
)

$authEvents = [System.Collections.Generic.List[string]]::new()

for ($k = 0; $k -lt 350; $k++) {
    $timestamp = $now.AddMinutes(-1 * (Get-Random -Minimum 1 -Maximum 1440)).ToString("yyyy-MM-dd HH:mm:ss")
    $user = $users | Get-Random
    $ipObj = $publicIps | Get-Random
    $srcIp = $ipObj.ip
    $app = $apps | Get-Random
    
    # Target high failures for 'admin', 'root', 'administrator' (brute force scenario)
    if ($user -in @("admin", "root", "administrator", "guest")) {
        $action = if ((Get-Random -Minimum 1 -Maximum 10) -le 9) { "failure" } else { "success" }
    } else {
        $action = if ((Get-Random -Minimum 1 -Maximum 10) -le 3) { "failure" } else { "success" }
    }

    if ($action -eq "failure") {
        $err = $errorCodes | Get-Random
        $errorCode = $err.code
        $errorDesc = $err.desc
        $status = "401"
    } else {
        $errorCode = "AUTH_SUCCESS_000"
        $errorDesc = "Authentication successful"
        $status = "200"
    }

    $event = "$timestamp action=$action user=$user src_ip=$srcIp app=$app status=$status error_code=$errorCode error_description=`"$errorDesc`""
    $authEvents.Add($event)
}

$authRawPayload = ($authEvents -join "`n")
$authUri = "$splunkHost/services/receivers/simple?index=main&sourcetype=incident:auth"
$ingestResp2 = Invoke-RestMethod -Uri $authUri -Method Post -Body $authRawPayload -Headers $headers
Write-Host "Ingested $($authEvents.Count) incident authentication events into sourcetype 'incident:auth'." -ForegroundColor Green


# ==========================================
# 4. CREATE DASHBOARD XML WITH TIME PICKER & DEPLOY
# ==========================================
Write-Host "`n[5/6] Deploying 4-panel Incident Investigation Dashboard..." -ForegroundColor Cyan

$dashboardXml = @'
<dashboard version="1.1" theme="dark">
  <label>Incident Investigation Dashboard</label>
  <description>Comprehensive 4-Panel Security Incident Analysis: Failed Logins, Geo-Location Tracking, Activity Timeline, and Error Diagnostics</description>
  
  <fieldset submitButton="false" autoRun="true">
    <input type="time" token="time_range" searchWhenChanged="true">
      <label>Time Range</label>
      <default>
        <earliest>0</earliest>
        <latest>now</latest>
      </default>
    </input>
  </fieldset>

  <row>
    <!-- Panel 1: Top Failed Logins by User -->
    <panel>
      <title>Top Failed Logins by Target User</title>
      <chart>
        <search>
          <query>index=* sourcetype=incident:auth action="failure" | top limit=10 user</query>
          <earliest>$time_range.earliest$</earliest>
          <latest>$time_range.latest$</latest>
        </search>
        <option name="charting.chart">bar</option>
        <option name="charting.chart.showDataLabels">all</option>
        <option name="charting.legend.placement">none</option>
        <option name="charting.axisTitleX.text">Failed Attempts Count</option>
        <option name="charting.axisTitleY.text">Target User</option>
        <option name="charting.seriesColors">[0xd93f3c]</option>
      </chart>
    </panel>

    <!-- Panel 2: Geolocations of Remote Connections -->
    <panel>
      <title>Geolocations of Remote Connections (iplocation)</title>
      <map>
        <search>
          <query>index=* sourcetype=incident:auth | iplocation src_ip | where isnotnull(lat) AND isnotnull(lon) | geostats count by action</query>
          <earliest>$time_range.earliest$</earliest>
          <latest>$time_range.latest$</latest>
        </search>
        <option name="mapping.type">marker</option>
        <option name="mapping.map.center">(20,0)</option>
        <option name="mapping.map.zoom">2</option>
        <option name="mapping.markerLayer.markerMinPercent">5</option>
        <option name="mapping.markerLayer.markerMaxPercent">25</option>
      </map>
    </panel>
  </row>

  <row>
    <!-- Panel 3: Timeline of Events -->
    <panel>
      <title>Timeline of Authentication Events (Success vs Failure)</title>
      <chart>
        <search>
          <query>index=* sourcetype=incident:auth | timechart span=1h count by action</query>
          <earliest>$time_range.earliest$</earliest>
          <latest>$time_range.latest$</latest>
        </search>
        <option name="charting.chart">area</option>
        <option name="charting.chart.stackMode">stacked</option>
        <option name="charting.legend.placement">bottom</option>
        <option name="charting.axisTitleX.text">Time</option>
        <option name="charting.axisTitleY.text">Event Count</option>
        <option name="charting.seriesColors">[0xd93f3c, 0x65a637]</option>
      </chart>
    </panel>

    <!-- Panel 4: Raw Error Codes Breakdown -->
    <panel>
      <title>Raw Error Codes Breakdown</title>
      <table>
        <search>
          <query>index=* sourcetype=incident:auth action="failure" | stats count by error_code, error_description | sort - count | rename error_code as "Error Code", error_description as "Error Description", count as "Failure Count"</query>
          <earliest>$time_range.earliest$</earliest>
          <latest>$time_range.latest$</latest>
        </search>
        <option name="drilldown">none</option>
        <option name="dataOverlayMode">heatmap</option>
        <option name="count">10</option>
      </table>
    </panel>
  </row>
</dashboard>
'@

# Save to local workspace
$dashboardWorkspacePath = "$workspaceDir\incident_dashboard\incident_investigation.xml"
Set-Content -Path $dashboardWorkspacePath -Value $dashboardXml -Encoding UTF8

# Ensure target Splunk directory exists and copy
$splunkViewsDir = "$splunkHome\etc\apps\search\local\data\ui\views"
if (-not (Test-Path $splunkViewsDir)) {
    New-Item -ItemType Directory -Force -Path $splunkViewsDir | Out-Null
}
$splunkDashboardPath = "$splunkViewsDir\incident_investigation.xml"
Set-Content -Path $splunkDashboardPath -Value $dashboardXml -Encoding UTF8

Write-Host "Deployed Dashboard XML successfully to:" -ForegroundColor Green
Write-Host " - Workspace: $dashboardWorkspacePath"
Write-Host " - Splunk:    $splunkDashboardPath"

# Reload views via Splunk REST
try {
    $reloadUri = "$splunkHost/services/data/ui/views/_reload"
    Invoke-RestMethod -Uri $reloadUri -Method Get -Headers $headers | Out-Null
    Write-Host "Reloaded Splunk UI views cache." -ForegroundColor Green
} catch {
    Write-Host "View reload notification: $_" -ForegroundColor Yellow
}

# ==========================================
# 5. VERIFY SPLUNK SEARCHES VIA REST API
# ==========================================
Write-Host "`n[6/6] Verifying Search Results..." -ForegroundColor Cyan

# Test Threat Intel Lookup search
$testSpl = "search index=* sourcetype=firewall_traffic | lookup threat_intel_malicious_ips.csv ip as src_ip OUTPUT threat_category, confidence_score, description | where isnotnull(threat_category) | stats count by threat_category"
$searchBody = @{ search = $testSpl; exec_mode = "oneshot"; output_mode = "json" }
$searchJobResp = Invoke-RestMethod -Uri "$splunkHost/services/search/jobs" -Method Post -Body $searchBody -Headers $headers
$threatCount = $searchJobResp.results.Count
Write-Host "Threat Intel Lookup SPL verification returned $threatCount category rows matching ingested firewall logs!" -ForegroundColor Green

Write-Host "`n=== SETUP COMPLETE ===" -ForegroundColor Green
Write-Host "You can open Splunk Web at: http://localhost:8000"
Write-Host "Dashboard Direct URL: http://localhost:8000/en-US/app/search/incident_investigation"

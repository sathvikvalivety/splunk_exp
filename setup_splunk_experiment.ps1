<#
.SYNOPSIS
Sets up a Splunk Brute Force Detection experiment.

.DESCRIPTION
This script creates a sample CSV log file, authenticates to a local Splunk instance,
uploads the data, and creates a dashboard for visualizing the brute force attempts.

.EXAMPLE
.\setup_splunk_experiment.ps1
#>

$SplunkHost = "https://localhost:8089"
$SplunkWeb = "http://localhost:8000"
$Username = "tejaswi"
$Password = "Teju@3026"
$App = "search"

# Ignore SSL warnings for self-signed Splunk certs
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

Write-Host "========================================" -ForegroundColor Cyan
Write-Host " Splunk Brute Force Experiment Setup" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

# 1. Create the CSV file
Write-Host "`n[*] Creating sample log file (login_logs.csv)..."
$csvContent = @"
_time,src_ip,user,action
2026-10-01 10:00:01,192.168.1.10,admin,failure
2026-10-01 10:00:05,192.168.1.10,admin,failure
2026-10-01 10:00:10,192.168.1.10,admin,failure
2026-10-01 10:00:15,192.168.1.10,admin,failure
2026-10-01 10:00:20,192.168.1.10,admin,failure
2026-10-01 10:00:25,192.168.1.10,admin,success
2026-10-01 10:05:01,192.168.1.20,user1,failure
2026-10-01 10:05:20,192.168.1.20,user1,failure
2026-10-01 10:06:00,192.168.1.20,user1,success
2026-10-01 10:10:01,192.168.1.30,user2,failure
"@

Set-Content -Path ".\login_logs.csv" -Value $csvContent
Write-Host "[+] login_logs.csv created successfully." -ForegroundColor Green

# 2. Authenticate to Splunk
Write-Host "`n[*] Authenticating to Splunk API at $SplunkHost..."
$loginBody = @{
    username = $Username
    password = $Password
}

try {
    $loginResponse = Invoke-RestMethod -Uri "$SplunkHost/services/auth/login?output_mode=json" -Method Post -Body $loginBody -ContentType "application/x-www-form-urlencoded"
    $sessionKey = $loginResponse.sessionKey
    Write-Host "[+] Authentication successful!" -ForegroundColor Green
} catch {
    Write-Host "[-] Failed to authenticate to Splunk. Ensure Splunk is running on localhost and credentials are correct." -ForegroundColor Red
    Write-Host $_.Exception.Message
    exit
}

$headers = @{
    "Authorization" = "Splunk $sessionKey"
}

# 3. Upload data
Write-Host "`n[*] Uploading data to Splunk (index=main)..."
try {
    $uploadUri = "$SplunkHost/services/receivers/simple?index=main&sourcetype=csv&output_mode=json"
    Invoke-RestMethod -Uri $uploadUri -Method Post -Headers $headers -Body $csvContent -ContentType "text/plain" | Out-Null
    Write-Host "[+] Data uploaded successfully!" -ForegroundColor Green
} catch {
    Write-Host "[-] Failed to upload data." -ForegroundColor Red
    Write-Host $_.Exception.Message
}

# 4. Create Dashboard
Write-Host "`n[*] Creating Dashboard 'Brute Force Detection'..."
$dashboardXml = @"
<dashboard>
  <label>Brute Force Detection Dashboard</label>
  <row>
    <panel>
      <title>Top Failed Login Sources</title>
      <chart>
        <search>
          <query>index=main action=failure | stats count by src_ip | sort -count</query>
          <earliest>0</earliest>
          <latest></latest>
        </search>
        <option name="charting.chart">bar</option>
      </chart>
    </panel>
    <panel>
      <title>Failed Logins by User</title>
      <chart>
        <search>
          <query>index=main action=failure | stats count by user | sort -count</query>
          <earliest>0</earliest>
          <latest></latest>
        </search>
        <option name="charting.chart">column</option>
      </chart>
    </panel>
    <panel>
      <title>Brute Force Alerts (&gt;= 5 failures)</title>
      <table>
        <search>
          <query>index=main action=failure | stats count by src_ip, user | where count &gt;= 5 | sort -count</query>
          <earliest>0</earliest>
          <latest></latest>
        </search>
      </table>
    </panel>
  </row>
</dashboard>
"@

$dashboardBody = @{
    name = "brute_force_detection"
    "eai:data" = $dashboardXml
}

try {
    $dashboardUri = "$SplunkHost/servicesNS/$Username/$App/data/ui/views"
    
    # Check if dashboard exists
    $checkDashboard = Invoke-WebRequest -Uri "$dashboardUri/brute_force_detection?output_mode=json" -Method Get -Headers $headers -ErrorAction SilentlyContinue
    if ($checkDashboard.StatusCode -eq 200) {
        Write-Host "[*] Dashboard exists, updating..."
        Invoke-RestMethod -Uri "$dashboardUri/brute_force_detection?output_mode=json" -Method Post -Headers $headers -Body $dashboardBody | Out-Null
    } else {
        Write-Host "[*] Dashboard does not exist, creating..."
        Invoke-RestMethod -Uri "$dashboardUri?output_mode=json" -Method Post -Headers $headers -Body $dashboardBody | Out-Null
    }
    Write-Host "[+] Dashboard created/updated successfully!" -ForegroundColor Green
} catch {
    Write-Host "[-] Failed to create Dashboard via API. You can manually create it in the UI." -ForegroundColor Yellow
    Write-Host $_.Exception.Message
}

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host " Setup Complete! Next Steps:" -ForegroundColor Green
Write-Host " 1. Open Splunk Web: $SplunkWeb"
Write-Host " 2. Navigate to 'Search & Reporting' app"
Write-Host " 3. Verify data by searching: index=main"
Write-Host " 4. Click on 'Dashboards' in the top menu to view the 'Brute Force Detection Dashboard'"
Write-Host "========================================" -ForegroundColor Cyan

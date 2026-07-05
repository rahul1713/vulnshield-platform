#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Installs the VulnShield Windows Agent.

.DESCRIPTION
    Downloads dependencies, configures the agent service, and registers with the platform.
    Hybrid design: Python handles HTTPS/mTLS communication; PowerShell collects inventory.

.PARAMETER ApiUrl
    VulnShield API Gateway URL (e.g. https://vulnshield.corp.local:8080/api/v1)

.PARAMETER ApiToken
    Agent registration token issued by the VulnShield admin console.

.PARAMETER EnableMtls
    Enable mutual TLS for agent communication.
#>
param(
    [Parameter(Mandatory = $true)]
    [string]$ApiUrl,

    [Parameter(Mandatory = $true)]
    [string]$ApiToken,

    [switch]$EnableMtls,

    [string]$InstallPath = "C:\Program Files\VulnShield",
    [string]$DataPath = "C:\ProgramData\VulnShield"
)

$ErrorActionPreference = "Stop"

Write-Host "=== VulnShield Windows Agent Installer ===" -ForegroundColor Cyan

# Create directories
$dirs = @(
    $InstallPath,
    "$DataPath\certs",
    "$DataPath\logs"
)
foreach ($dir in $dirs) {
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
}

# Copy agent files from script directory
$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Copy-Item "$scriptRoot\agent.py" -Destination $InstallPath -Force
Copy-Item "$scriptRoot\config.py" -Destination $InstallPath -Force
Copy-Item "$scriptRoot\collectors.ps1" -Destination $InstallPath -Force
Copy-Item "$scriptRoot\requirements.txt" -Destination $InstallPath -Force

# Install Python if not present
$python = Get-Command python -ErrorAction SilentlyContinue
if (-not $python) {
    Write-Host "Python not found. Install Python 3.12+ and re-run this script." -ForegroundColor Red
    exit 1
}

Write-Host "Installing Python dependencies..."
& python -m pip install -r "$InstallPath\requirements.txt" --quiet

# Write configuration
$envContent = @"
VULNSHIELD_API_URL=$ApiUrl
VULNSHIELD_API_TOKEN=$ApiToken
VULNSHIELD_HEARTBEAT_INTERVAL=300
VULNSHIELD_INVENTORY_INTERVAL=3600
VULNSHIELD_VERIFY_SSL=true
VULNSHIELD_MTLS_ENABLED=$($EnableMtls.IsPresent)
VULNSHIELD_LOG_LEVEL=INFO
"@
Set-Content -Path "$DataPath\agent.env" -Value $envContent -Encoding UTF8

# Copy mTLS certs if provided alongside installer
$certFiles = @("client.crt", "client.key", "ca.crt")
foreach ($cert in $certFiles) {
    $src = Join-Path $scriptRoot "certs\$cert"
    if (Test-Path $src) {
        Copy-Item $src -Destination "$DataPath\certs\$cert" -Force
        Write-Host "Installed certificate: $cert"
    }
}

# Register Windows service via NSSM or scheduled task fallback
$taskName = "VulnShieldAgent"
$action = New-ScheduledTaskAction -Execute "python.exe" -Argument "`"$InstallPath\agent.py`"" -WorkingDirectory $InstallPath
$trigger = New-ScheduledTaskTrigger -AtStartup
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Description "VulnShield endpoint inventory agent" | Out-Null

Start-ScheduledTask -TaskName $taskName

Write-Host ""
Write-Host "Installation complete!" -ForegroundColor Green
Write-Host "  Install path: $InstallPath"
Write-Host "  Config:       $DataPath\agent.env"
Write-Host "  Service:      Scheduled Task '$taskName'"
Write-Host ""
Write-Host "Test collection: python `"$InstallPath\agent.py`" collect"

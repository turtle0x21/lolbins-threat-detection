# Requires Administrator Rights
# This script configures Windows to log exact command line events instantly.
# This prevents race conditions in LOLBin detection.

Write-Host "==============================================="
Write-Host " Enabling Advanced Threat Detection Logging"
Write-Host "==============================================="

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "This script requires Administrator privileges!"
    Write-Host "Please close this window, right-click PowerShell, and 'Run as Administrator'."
    exit
}

Write-Host "`n[1/3] Enabling Process Creation Auditing (Event ID 4688)..."
# Audit Process Creation (Success)
auditpol /set /subcategory:"Process Creation" /success:enable /failure:disable | Out-Null

Write-Host "`n[2/3] Enabling Command-Line Auditing for 4688..."
# Include Command Line Data in Event 4688
$RegistryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
if (!(Test-Path $RegistryPath)) {
    New-Item -Path $RegistryPath -Force | Out-Null
}
Set-ItemProperty -Path $RegistryPath -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -Type DWord | Out-Null

Write-Host "`n[3/3] Enabling PowerShell Script Block Logging (Event ID 4104)..."
# PowerShell deep script block logging
$PsRegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
if (!(Test-Path $PsRegistryPath)) {
    New-Item -Path $PsRegistryPath -Force | Out-Null
}
Set-ItemProperty -Path $PsRegistryPath -Name "EnableScriptBlockLogging" -Value 1 -Type DWord | Out-Null
Set-ItemProperty -Path $PsRegistryPath -Name "EnableScriptBlockInvocationLogging" -Value 1 -Type DWord | Out-Null

Write-Host "`n[+] SUCCESS! Windows is now configured to track exact LOLBin commands natively."
Write-Host "    Your agent's Event Log scanner will now have 100% visibility."


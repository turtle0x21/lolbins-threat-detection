param([string]$TimeStr)

$ErrorActionPreference = 'SilentlyContinue'
$time = [datetime]::ParseExact($TimeStr, 'MM/dd/yyyy HH:mm:ss', $null)

# Stage 1: Process Creation Events (Security Log, Event ID 4688)
$events = Get-WinEvent -FilterHashtable @{LogName='Security';ID=4688;StartTime=$time} -ErrorAction SilentlyContinue
foreach ($evt in $events) {
    $parent = "Unknown"
    $cmd = "Unknown"
    if ($evt.Message -match 'Creator Process Name:\s+([^\r\n]+)') {
        $parent = $matches[1]
    }
    if ($evt.Message -match 'Process Command Line:\s+([^\r\n]+)') {
        $cmd = $matches[1]
    }
    if ($cmd -ne "Unknown") {
        Write-Output "$parent|||$cmd"
    }
}

# Stage 2: PowerShell Script Block Logging (Event ID 4104)
$psEvents = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational';ID=4104;StartTime=$time} -ErrorAction SilentlyContinue
foreach ($evt in $psEvents) {
    $sb = $evt.Properties[2].Value
    if ($sb) {
        $sb = $sb -replace "\r?\n", " "
        if ($sb.Length -gt 8000) { $sb = $sb.Substring(0, 8000) }
        Write-Output "PowerShell_Script|||$sb"
    }
}

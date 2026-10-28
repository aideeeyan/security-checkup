$ErrorActionPreference = "Stop"
$facts = [ordered]@{}
$unavailable = $null
. (Join-Path $PSScriptRoot "_common.ps1")
try {
  $deny = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name fDenyTSConnections -ErrorAction Stop
  $facts["rdpEnabled"] = ([int]$deny.fDenyTSConnections -eq 0)
  $ssh = Get-Service -Name sshd -ErrorAction SilentlyContinue
  $facts["sshEnabled"] = [bool]($null -ne $ssh -and [string]$ssh.Status -eq "Running")
  $facts["screenSharingEnabled"] = $null
} catch {
  $facts = [ordered]@{}
  $unavailable = Get-Unavailable $_
}
Write-Part $facts $unavailable

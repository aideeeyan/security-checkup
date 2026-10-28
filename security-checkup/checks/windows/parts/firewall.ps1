$ErrorActionPreference = "Stop"
$facts = [ordered]@{}
$unavailable = $null
. (Join-Path $PSScriptRoot "_common.ps1")
try {
  $profiles = @(Get-NetFirewallProfile -ErrorAction Stop)
  if ($profiles.Count -eq 0) { throw "no firewall profiles" }
  $all = $true
  foreach ($p in $profiles) { if ([string]$p.Enabled -ne "True") { $all = $false } }
  $facts["enabled"] = $all
} catch {
  $facts = [ordered]@{}
  $unavailable = Get-Unavailable $_
}
Write-Part $facts $unavailable

$ErrorActionPreference = "Stop"
$facts = [ordered]@{}
$unavailable = $null
. (Join-Path $PSScriptRoot "_common.ps1")
try {
  $re = "VPN|WireGuard|FortiClient|GlobalProtect|AnyConnect|Cisco Secure Client|Pulse Secure|Ivanti Secure|SonicWall|NetExtender|NordLayer|Zscaler|Tailscale|SoftEther|Check Point|Forticlient"
  $seen = @{}
  $out = @()
  foreach ($a in Get-Installed) {
    if ($a.Name -notmatch $re) { continue }
    if ($seen.ContainsKey($a.Name)) { continue }
    $seen[$a.Name] = $true
    $v = $a.Version; if (-not $v) { $v = $null }
    $out += [ordered]@{ name = $a.Name; version = $v }
  }
  $facts["products"] = [object[]]$out
} catch {
  $facts = [ordered]@{}
  $unavailable = Get-Unavailable $_
}
Write-Part $facts $unavailable

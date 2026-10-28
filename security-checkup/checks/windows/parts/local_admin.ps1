$ErrorActionPreference = "Stop"
$facts = [ordered]@{}
$unavailable = $null
. (Join-Path $PSScriptRoot "_common.ps1")
try {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  $is = $false
  foreach ($g in $id.Groups) { if ($g.Value -eq "S-1-5-32-544") { $is = $true } }
  $facts["isAdmin"] = $is
} catch {
  $facts = [ordered]@{}
  $unavailable = Get-Unavailable $_
}
Write-Part $facts $unavailable

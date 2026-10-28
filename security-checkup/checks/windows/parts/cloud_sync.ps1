$ErrorActionPreference = "Stop"
$facts = [ordered]@{}
$unavailable = $null
. (Join-Path $PSScriptRoot "_common.ps1")
try {
  $local = $env:LOCALAPPDATA
  $out = @()
  # OneDrive: an account is configured
  $od = $false
  foreach ($k in @(Get-ChildItem "HKCU:\Software\Microsoft\OneDrive\Accounts" -ErrorAction SilentlyContinue)) {
    $p = Get-ItemProperty -Path $k.PSPath -ErrorAction SilentlyContinue
    if ($p -and ($p.UserEmail -or $p.ConfiguredTenantId)) { $od = $true }
  }
  if ($od) { $out += "OneDrive" }
  # Google Drive: a signed-in account has a numeric folder
  $gd = $false
  if ($local -and (Test-Path (Join-Path $local "Google\DriveFS"))) {
    foreach ($d in @(Get-ChildItem (Join-Path $local "Google\DriveFS") -Directory -ErrorAction SilentlyContinue)) { if ($d.Name -match "^\d+$") { $gd = $true } }
  }
  if ($gd) { $out += "Google Drive" }
  if ($local -and (Test-Path (Join-Path $local "Dropbox\info.json"))) { $out += "Dropbox" }
  if ($local -and (Test-Path (Join-Path $local "Box\Box\data"))) { $out += "Box" }
  $icloudApp = $false
  foreach ($a in Get-Installed) { if ($a.Name -match "^iCloud$") { $icloudApp = $true } }
  if ($icloudApp -and $env:USERPROFILE -and (Test-Path (Join-Path $env:USERPROFILE "iCloudDrive"))) { $out += "iCloud Drive" }
  $facts["products"] = [object[]]$out
} catch {
  $facts = [ordered]@{}
  $unavailable = Get-Unavailable $_
}
Write-Part $facts $unavailable

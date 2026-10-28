$ErrorActionPreference = "Stop"
$facts = [ordered]@{}
$unavailable = $null
. (Join-Path $PSScriptRoot "_common.ps1")
try {
  $today = Get-Day (Get-Date)
  $products = @()
  $sc = $null
  try { $sc = @(Get-CimInstance -Namespace "root/SecurityCenter2" -ClassName AntiVirusProduct -ErrorAction Stop) } catch { $sc = $null }
  $mp = $null
  try { $mp = Get-MpComputerStatus -ErrorAction Stop } catch { $mp = $null }
  if ($null -ne $sc) {
    foreach ($p in $sc) {
      $st = [int64]$p.productState
      $products += [ordered]@{ name = [string]$p.displayName; enabled = (($st -band 0xF000) -eq 0x1000); upToDate = (($st -band 0x00F0) -eq 0) }
    }
  } elseif ($null -ne $mp) {
    $products += [ordered]@{ name = "Windows Defender"; enabled = [bool]($mp.AMServiceEnabled -and $mp.RealTimeProtectionEnabled); upToDate = $null }
  } else {
    throw "no antivirus information"
  }
  $d = Resolve-AvDates $products $mp $today
  $defUpdated = $d.definitionsUpdatedAt
  $scan = $d.lastScanAt
  $facts["products"] = [object[]]$products
  $facts["definitionsUpdatedAt"] = $defUpdated
  $facts["lastScanAt"] = $scan
} catch {
  $facts = [ordered]@{}
  $unavailable = Get-Unavailable $_
}
Write-Part $facts $unavailable

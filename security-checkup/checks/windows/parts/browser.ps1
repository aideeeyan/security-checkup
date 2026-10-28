$ErrorActionPreference = "Stop"
$facts = [ordered]@{}
$unavailable = $null
. (Join-Path $PSScriptRoot "_common.ps1")
try {
  $want = @(
    @{ Label = "Google Chrome"; Re = "^Google Chrome$" },
    @{ Label = "Microsoft Edge"; Re = "^Microsoft Edge$" },
    @{ Label = "Mozilla Firefox"; Re = "^Mozilla Firefox( |$)" }
  )
  $best = @{}
  foreach ($a in Get-Installed) {
    foreach ($w in $want) {
      if ($a.Name -match $w.Re -and $a.Version) {
        $cur = $best[$w.Label]
        $newer = $true
        if ($cur) { try { $newer = ([version]$a.Version -gt [version]$cur) } catch { $newer = $false } }
        if ($newer) { $best[$w.Label] = $a.Version }
      }
    }
  }
  $out = @()
  foreach ($w in $want) { if ($best.ContainsKey($w.Label)) { $out += [ordered]@{ name = $w.Label; version = $best[$w.Label] } } }
  $facts["browsers"] = [object[]]$out
} catch {
  $facts = [ordered]@{}
  $unavailable = Get-Unavailable $_
}
Write-Part $facts $unavailable

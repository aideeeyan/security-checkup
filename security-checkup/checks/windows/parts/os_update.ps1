$ErrorActionPreference = "Stop"
$facts = [ordered]@{}
$unavailable = $null
. (Join-Path $PSScriptRoot "_common.ps1")
try {
  $last = $null
  $pending = $null
  $defCat = "e0789628-ce08-4437-be74-2495b842f43b"
  try {
    $session = New-Object -ComObject Microsoft.Update.Session
    $searcher = $session.CreateUpdateSearcher()
    $total = $searcher.GetTotalHistoryCount()
    $take = [Math]::Min($total, 300)
    if ($take -gt 0) {
      foreach ($h in @($searcher.QueryHistory(0, $take))) {
        if ($h.Operation -ne 1 -or $h.ResultCode -ne 2) { continue }
        $isDef = $false
        foreach ($c in @($h.Categories)) { if ($c.CategoryID -eq $defCat) { $isDef = $true } }
        if ($isDef) { continue }
        if ($null -eq $last -or $h.Date -gt $last) { $last = $h.Date }
      }
    }
    # search only the locally cached catalog: no network access
    $searcher.Online = $false
    $res = $searcher.Search("IsInstalled=0 and IsHidden=0")
    $pending = [int]$res.Updates.Count
  } catch {
    if ($null -eq $last) { throw }
  }
  if ($null -eq $last) {
    foreach ($q in @(Get-CimInstance -ClassName Win32_QuickFixEngineering -ErrorAction SilentlyContinue)) {
      if ($q.InstalledOn -and ($null -eq $last -or $q.InstalledOn -gt $last)) { $last = $q.InstalledOn }
    }
  }
  $facts["lastInstalledAt"] = Get-Day $last
  $facts["pendingCount"] = $pending
} catch {
  $facts = [ordered]@{}
  $unavailable = Get-Unavailable $_
}
Write-Part $facts $unavailable

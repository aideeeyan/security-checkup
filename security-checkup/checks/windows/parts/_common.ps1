# Shared helpers for the parts (dot-sourced). Read-only; no localized strings are parsed.
function Get-Day($d) { if ($null -eq $d) { return $null }; try { return ([datetime]$d).ToString("yyyy-MM-dd", [Globalization.CultureInfo]::InvariantCulture) } catch { return $null } }

# Access denied is detected by exception type or HResult 0x80070005 (-2147024891), walking inner exceptions.
function Test-Denied($e) {
  $x = $e.Exception
  while ($null -ne $x) {
    if (($x -is [UnauthorizedAccessException]) -or ($x -is [System.Security.SecurityException]) -or ($x.HResult -eq -2147024891)) { return $true }
    $x = $x.InnerException
  }
  return $false
}
function Get-Unavailable($e) { if (Test-Denied $e) { return "needs_admin" } else { return "error" } }

function Write-Part($facts, $unavailable) {
  $json = ConvertTo-Json -InputObject ([ordered]@{ facts = $facts; unavailable = $unavailable }) -Depth 6 -Compress
  Write-Output ([regex]::Replace($json, "[^\x00-\x7e]", { param($m) "\u{0:x4}" -f [int][char]$m.Value }))
}

function Get-Installed() {
  $paths = @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*", "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*", "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*")
  $list = @()
  foreach ($p in $paths) {
    foreach ($k in @(Get-ItemProperty -Path $p -ErrorAction SilentlyContinue)) {
      if ($k.DisplayName) { $list += [pscustomobject]@{ Name = [string]$k.DisplayName; Version = [string]$k.DisplayVersion } }
    }
  }
  return $list
}

# Defender's own dates only describe the active product when Defender is the active one.
# $Products: items with name/enabled/upToDate. $Mp: object with AntivirusSignatureLastUpdated, QuickScanEndTime, FullScanEndTime (or $null).
function Resolve-AvDates($Products, $Mp, [string]$Today) {
  $defenderOn = $false
  foreach ($p in $Products) { if ($p.enabled -and $p.name -match "Defender") { $defenderOn = $true } }
  $defUpdated = $null
  $scan = $null
  if ($defenderOn) {
    if ($null -ne $Mp) {
      $defUpdated = Get-Day $Mp.AntivirusSignatureLastUpdated
      $dates = @()
      foreach ($n in @("QuickScanEndTime", "FullScanEndTime")) { if ($Mp.$n) { $dates += [datetime]$Mp.$n } }
      if ($dates.Count -gt 0) { $scan = Get-Day (($dates | Sort-Object -Descending)[0]) }
    }
  } else {
    foreach ($p in $Products) { if ($p.enabled -and $p.upToDate -eq $true) { $defUpdated = $Today } }
  }
  return [ordered]@{ definitionsUpdatedAt = $defUpdated; lastScanAt = $scan }
}

# System.Volume.BitLockerProtection (community-documented, not an official Microsoft table):
# 1 On, 2 Off, 3 Encrypting, 4 Decrypting, 5 Suspended, 6 On (locked), 8 Waiting for activation.
# Only 1 and 6 mean the data is protected now; the rest -> false. Anything else -> null.
function Convert-BitLockerState($v) {
  if ($null -eq $v) { return $null }
  switch ([int]$v) {
    { $_ -eq 1 -or $_ -eq 6 } { return $true }
    { $_ -in 2, 3, 4, 5, 8 } { return $false }
    default { return $null }
  }
}

# Screen lock from the power plan: the PC locks when it goes to sleep (STANDBYIDLE) and asks for the sign-in on wake (CONSOLELOCK).
# Turning the display off does not lock anything, so it is not used. $Plans: items with Idle (seconds, 0 = never, $null = unreadable) and Lock (0/1/$null).
# Takes the worst case of all readable plans (AC and battery): the longest wait, and the password only if every plan asks for it.
# Returns $null when a plan never sleeps (nothing locks) or nothing was readable.
function Get-SleepLock($Plans) {
  $max = 0
  $allLock = $true
  $n = 0
  foreach ($p in @($Plans)) {
    if ($null -eq $p.Idle) { continue }
    if ([int64]$p.Idle -le 0) { return $null }
    $n++
    if ([int64]$p.Idle -gt $max) { $max = [int64]$p.Idle }
    if ($p.Lock -ne 1) { $allLock = $false }
  }
  if ($n -eq 0) { return $null }
  return [pscustomobject]@{ Minutes = [Math]::Ceiling($max / 60.0); Password = $allLock }
}

# $Cands: items with Minutes and Password. $PowerReadable: whether the power plan could be read at all.
# Candidates that ask for the password win (shortest wait); otherwise the lock does not need a password. Nothing locks -> false, unless the power plan was unreadable -> unknown (null).
function Resolve-ScreenLock($Cands, [bool]$PowerReadable) {
  $c = @($Cands | Where-Object { $null -ne $_ })
  $withPw = @($c | Where-Object { $_.Password })
  $facts = [ordered]@{}
  if ($withPw.Count -gt 0) {
    $facts["timeoutMinutes"] = [int](($withPw | Sort-Object Minutes)[0].Minutes)
    $facts["requiresPassword"] = $true
  } elseif ($c.Count -gt 0) {
    $facts["timeoutMinutes"] = [int](($c | Sort-Object Minutes)[0].Minutes)
    $facts["requiresPassword"] = $false
  } else {
    $facts["timeoutMinutes"] = $null
    $facts["requiresPassword"] = $(if ($PowerReadable) { $false } else { $null })
  }
  return $facts
}

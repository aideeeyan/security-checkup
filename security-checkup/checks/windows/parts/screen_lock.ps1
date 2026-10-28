$ErrorActionPreference = "Stop"
$facts = [ordered]@{}
$unavailable = $null
. (Join-Path $PSScriptRoot "_common.ps1")
try {
  function Get-RegValue($path, $name) {
    try { $item = Get-ItemProperty -Path $path -Name $name -ErrorAction Stop; return $item.$name } catch { return $null }
  }
  function Get-PowerIndex($sub, $setting, $kind) {
    try {
      $o = & powercfg.exe ("/get" + $kind + "valueindex") SCHEME_CURRENT $sub $setting 2>$null
      foreach ($line in @($o)) { if ("$line" -match "0x([0-9a-fA-F]+)\s*$") { return [Convert]::ToInt64($Matches[1], 16) } }
    } catch { }
    return $null
  }
  $cands = @()
  # screen saver (user setting, then the policy copy which wins when present)
  $pol = "HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop"
  $usr = "HKCU:\Control Panel\Desktop"
  $active = Get-RegValue $pol "ScreenSaveActive"; if ($null -eq $active) { $active = Get-RegValue $usr "ScreenSaveActive" }
  $secs = Get-RegValue $pol "ScreenSaveTimeOut"; if ($null -eq $secs) { $secs = Get-RegValue $usr "ScreenSaveTimeOut" }
  $secure = Get-RegValue $pol "ScreenSaverIsSecure"; if ($null -eq $secure) { $secure = Get-RegValue $usr "ScreenSaverIsSecure" }
  if ("$active" -eq "1" -and "$secs" -match "^\d+$" -and [int]$secs -gt 0) {
    $cands += [pscustomobject]@{ Minutes = [Math]::Ceiling([int]$secs / 60.0); Password = ("$secure" -eq "1") }
  }
  # device policy: lock after inactivity (always asks for the password)
  $ina = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "InactivityTimeoutSecs"
  if ($null -ne $ina -and [int64]$ina -gt 0) {
    $cands += [pscustomobject]@{ Minutes = [Math]::Ceiling([int64]$ina / 60.0); Password = $true }
  }
  # sleep + sign-in required on wake (power plan, readable without admin). Display-off alone does not lock the PC.
  $plans = @()
  $readable = $false
  foreach ($kind in @("ac", "dc")) {
    $idle = Get-PowerIndex "SUB_SLEEP" "STANDBYIDLE" $kind
    $lock = Get-PowerIndex "SUB_NONE" "CONSOLELOCK" $kind
    if ($null -ne $idle) { $readable = $true }
    $plans += [pscustomobject]@{ Idle = $idle; Lock = $lock }
  }
  $sleep = Get-SleepLock $plans
  if ($null -ne $sleep) { $cands += $sleep }
  $f = Resolve-ScreenLock $cands $readable
  $facts["timeoutMinutes"] = $f["timeoutMinutes"]
  $facts["requiresPassword"] = $f["requiresPassword"]
} catch {
  $facts = [ordered]@{}
  $unavailable = Get-Unavailable $_
}
Write-Part $facts $unavailable

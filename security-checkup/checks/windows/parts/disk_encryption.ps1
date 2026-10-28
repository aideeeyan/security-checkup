$ErrorActionPreference = "Stop"
$facts = [ordered]@{}
$unavailable = $null
. (Join-Path $PSScriptRoot "_common.ps1")
try {
  $v = $null
  $shell = New-Object -ComObject Shell.Application
  $drive = $env:SystemDrive
  if (-not $drive) { $drive = "C:" }
  $ns = $shell.NameSpace($drive + "\")
  if ($null -ne $ns) { $v = $ns.Self.ExtendedProperty("System.Volume.BitLockerProtection") }
  $facts["encrypted"] = Convert-BitLockerState $v
  # no value (e.g. editions without BitLocker, or no handler): not supported, not an admin problem
  if ($null -eq $facts["encrypted"]) { $unavailable = "not_supported" }
} catch {
  $facts = [ordered]@{}
  $unavailable = Get-Unavailable $_
}
Write-Part $facts $unavailable

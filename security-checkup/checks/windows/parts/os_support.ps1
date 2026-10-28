$ErrorActionPreference = "Stop"
$facts = [ordered]@{}
$unavailable = $null
. (Join-Path $PSScriptRoot "_common.ps1")
try {
  $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
  $facts["name"] = [string]$os.Caption
  $facts["version"] = [string]$os.Version
  $facts["build"] = [string]$os.BuildNumber
} catch {
  $facts = [ordered]@{}
  $unavailable = Get-Unavailable $_
}
Write-Part $facts $unavailable

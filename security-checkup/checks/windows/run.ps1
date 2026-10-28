param(
  [Parameter(Position = 0)][string]$Command,
  [string]$Label,
  [string]$Checks,
  [string]$Out,
  [string]$Data,
  [string]$OutDir,
  [string]$PcsDir,
  [switch]$NoOpen
)
# Read-only diagnosis runner. Only writes the files the caller asks for (-Out / -OutDir) and the output folders of "paths".
$ErrorActionPreference = "Stop"
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$utf8 = New-Object System.Text.UTF8Encoding($false)
$ALL = @("antivirus", "disk_encryption", "os_update", "os_support", "firewall", "screen_lock", "local_admin", "remote_access", "vpn_client", "cloud_sync", "browser")

function Resolve-Full([string]$p) { return $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($p) }
function Write-Utf8([string]$path, [string]$text) {
  $dir = Split-Path -Parent $path
  if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
  [IO.File]::WriteAllText($path, $text, $utf8)
}
# JSON text -> JavaScript string literal for JSON.parse(...). The data is never placed into the page as a JS expression.
# ConvertTo-Json escapes \ " and control characters; < and U+2028/2029 are escaped explicitly (PS 5.1 and 7 differ).
function ConvertTo-JsLiteral([string]$text) {
  $lit = ConvertTo-Json -InputObject $text -Compress
  $lit = $lit.Replace("<", "\u003c").Replace([string][char]0x2028, "\u2028").Replace([string][char]0x2029, "\u2029")
  return $lit
}
function Get-Roots() {
  # Test override only (environment, like run.sh). Not a parameter, so the command line cannot move the output root.
  $docs = $env:SC_DOCS_ROOT
  if (-not $docs) { $docs = [Environment]::GetFolderPath("MyDocuments") }
  # "Security diagnosis" and "Employee PC results" folder names
  $root = Join-Path $docs ([regex]::Unescape('セキュリティ診断'))
  $emp = Join-Path $root ([regex]::Unescape('社員PC結果'))
  return @{ outputRoot = $root; employeeResults = $emp }
}

# Output guard: -Out / -OutDir must resolve inside the output root of "paths", so the auto-approved runner never writes elsewhere.
function Assert-InsideRoot([string]$p, [string]$name) {
  $root = [IO.Path]::GetFullPath((Get-Roots).outputRoot).TrimEnd('\') + '\'
  $full = [IO.Path]::GetFullPath((Resolve-Full $p))
  if (-not $full.StartsWith($root, [StringComparison]::OrdinalIgnoreCase) -or $full.Length -le $root.Length) { throw "$name must be inside the output folder" }
  return $full
}

switch ($Command) {
  "paths" {
    $r = Get-Roots
    foreach ($d in @($r.outputRoot, $r.employeeResults)) { if (-not (Test-Path -LiteralPath $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null } }
    Write-Output (ConvertTo-Json -InputObject ([ordered]@{ outputRoot = $r.outputRoot; employeeResults = $r.employeeResults }) -Compress)
  }
  "check" {
    if (-not $Label) { throw "-Label is required" }
    if (-not $Out) { throw "-Out is required" }
    $outFull = Assert-InsideRoot $Out "-Out"
    if (-not $outFull.EndsWith(".json", [StringComparison]::OrdinalIgnoreCase)) { throw "-Out must end with .json" }
    $ids = $ALL
    if ($Checks) { $ids = @($Checks -split "[,\s]+" | Where-Object { $_ }) }
    $parts = New-Object System.Collections.ArrayList
    foreach ($id in $ids) {
      $file = Join-Path $PSScriptRoot ("parts\" + $id + ".ps1")
      $json = $null
      if ($id -notmatch "^[a-z_]+$" -or -not (Test-Path -LiteralPath $file)) {
        $json = '{"facts":{},"unavailable":"not_supported"}'
      } else {
        try {
          $raw = (& $file | Out-String).Trim()
          $null = ConvertFrom-Json -InputObject $raw
          $json = $raw
        } catch {
          $json = '{"facts":{},"unavailable":"error"}'
        }
      }
      [void]$parts.Add(((ConvertTo-Json -InputObject $id -Compress) + ":" + $json))
    }
    $osVersion = ""
    try { $osVersion = [string](Get-CimInstance -ClassName Win32_OperatingSystem).Version } catch { }
    $today = (Get-Date).ToString("yyyy-MM-dd", [Globalization.CultureInfo]::InvariantCulture)
    $text = '{"version":1,"label":' + (ConvertTo-Json -InputObject $Label -Compress) + ',"checkedAt":"' + $today + '","os":"windows","osVersion":' +
      (ConvertTo-Json -InputObject $osVersion -Compress) + ',"checks":{' + ($parts -join ",") + "}}"
    $null = ConvertFrom-Json -InputObject $text
    Write-Utf8 $outFull $text
  }
  "report" {
    if (-not $Data) { throw "-Data is required" }
    if (-not $OutDir) { throw "-OutDir is required" }
    $skill = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $dest = Assert-InsideRoot $OutDir "-OutDir"
    if (-not (Test-Path -LiteralPath $dest)) { New-Item -ItemType Directory -Path $dest -Force | Out-Null }
    foreach ($f in @("baseline.js", "engine.js", "scenes.js", "report.html", "asklist.html", "pcs.html")) {
      Copy-Item -LiteralPath (Join-Path $skill ("report\" + $f)) -Destination (Join-Path $dest $f) -Force
    }
    $q = [IO.File]::ReadAllText((Join-Path $skill "questions\company.json"), [Text.Encoding]::UTF8).Trim()
    Write-Utf8 (Join-Path $dest "questions.js") ("window.SC_QUESTIONS = JSON.parse(" + (ConvertTo-JsLiteral $q) + ");`n")
    $d = [IO.File]::ReadAllText((Resolve-Full $Data), [Text.Encoding]::UTF8).Trim()
    $null = ConvertFrom-Json -InputObject $d
    # Employee result files: one JS string literal per *.json file, never parsed or run here. The page parses each one
    # inside its own try, so a broken or hostile file only counts as "unreadable". Always rewritten (no stale results).
    $items = New-Object System.Collections.ArrayList
    if ($PcsDir) {
      $pd = Resolve-Full $PcsDir
      if (-not (Test-Path -LiteralPath $pd -PathType Container)) { throw "pcs folder not found" }
      foreach ($file in @(Get-ChildItem -LiteralPath $pd -Filter "*.json" -File | Sort-Object Name)) {
        $body = "too large"
        if ($file.Length -le 1048576) {
          try { $body = [IO.File]::ReadAllText($file.FullName, [Text.Encoding]::UTF8).Trim() } catch { $body = "unreadable" }
        }
        [void]$items.Add((ConvertTo-JsLiteral $body))
      }
    }
    Write-Utf8 (Join-Path $dest "pcs.js") ("window.SC_PCS = [" + ($items -join ",`n") + "];`n")
    Write-Utf8 (Join-Path $dest "data.js") ("window.SC_DATA = JSON.parse(" + (ConvertTo-JsLiteral $d) + ");`n")
    if (-not $NoOpen) { Start-Process -FilePath (Join-Path $dest "report.html") }
    Write-Output (ConvertTo-Json -InputObject ([ordered]@{ report = (Join-Path $dest "report.html") }) -Compress)
  }
  default { throw "usage: run.ps1 paths | check -Label <name> -Checks <ids> -Out <file> | report -Data <diagnosis.json> -OutDir <folder> [-PcsDir <folder>] [-NoOpen]" }
}

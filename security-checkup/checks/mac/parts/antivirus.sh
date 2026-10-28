#!/bin/bash
. "$(dirname "$0")/_common.sh"
# XProtect (Apple's built-in) always runs on a Mac, so it is always listed. Third-party products are detected by app name in
# /Applications (installed; whether they are running or up to date cannot be read without admin, so upToDate is null).
# As on Windows, the built-in product's dates are only reported when it is the only product:
# with a third-party product present, definitionsUpdatedAt stays null (unknown) and the judgement is "わからない".
products='{"name":"XProtect","enabled":true,"upToDate":null}'
third=0
for app in "$SC_APPS_DIR"/*.app "$SC_HOME/Applications"/*.app; do
  [ -d "$app" ] || continue
  base=$(basename "$app" .app)
  low=$(sc_lower "$base")
  case "$low" in
    sophos*|norton*|eset*|"trend micro"*|trendmicro*|mcafee*|kaspersky*|bitdefender*|avast*|avg*|malwarebytes*|crowdstrike*|falcon*|sentinel*|"microsoft defender"*|"jamf protect"*|webroot*|intego*|clamxav*|symantec*|f-secure*|cylance*|"carbon black"*|cortex*)
      products="$products,{\"name\":$(sc_json_str "$base"),\"enabled\":true,\"upToDate\":null}"
      third=1 ;;
  esac
done
updated=""
if [ "$third" -eq 0 ]; then
  # Newer of: install history (XProtect* entries) and the modification day of XProtect.bundle's Info.plist.
  # From macOS 15 on, XProtect updates may no longer appear in the install history, so the bundle date is read too.
  sc_capture system_profiler SPInstallHistoryDataType -json
  hist=""
  if [ "$CAP_RC" -eq 0 ]; then
    hist=$(printf '%s\n' "$CAP_OUT" | sc_history_entries | sc_history_latest xprotect)
  fi
  bundle=$(sc_file_day "$SC_XPROTECT_INFO")
  updated="$hist"
  if [ -n "$bundle" ] && { [ -z "$updated" ] || [ "$bundle" \> "$updated" ]; }; then updated="$bundle"; fi
fi
sc_emit "{\"products\":[$products],\"definitionsUpdatedAt\":$(sc_json_str_or_null "$updated"),\"lastScanAt\":null}" ""
exit 0

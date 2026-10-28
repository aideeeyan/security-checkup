#!/bin/bash
. "$(dirname "$0")/_common.sh"
# Apps whose name looks like a VPN client (same list as Windows plus Mac-only ones). Version from Info.plist.
out=""
seen="|"
for app in "$SC_APPS_DIR"/*.app "$SC_HOME/Applications"/*.app; do
  [ -d "$app" ] || continue
  base=$(basename "$app" .app)
  low=$(sc_lower "$base")
  case "$low" in
    *vpn*|*wireguard*|*forticlient*|*globalprotect*|*anyconnect*|"cisco secure client"*|*"pulse secure"*|*"ivanti secure"*|*sonicwall*|*netextender*|*nordlayer*|*zscaler*|*tailscale*|*softether*|*"check point"*|tunnelblick*|viscosity*) ;;
    *) continue ;;
  esac
  case "$seen" in *"|$base|"*) continue ;; esac
  seen="$seen$base|"
  v=$(sc_app_version "$app")
  item="{\"name\":$(sc_json_str "$base"),\"version\":$(sc_json_str_or_null "$v")}"
  if [ -z "$out" ]; then out="$item"; else out="$out,$item"; fi
done
sc_emit "{\"products\":[$out]}" ""
exit 0

#!/bin/bash
. "$(dirname "$0")/_common.sh"
# Only services actually used for syncing (not merely installed). Signals (folder names only, no contents are read):
#  Google Drive / OneDrive / Box / Dropbox: ~/Library/CloudStorage/<Provider>-* (created when an account is signed in)
#  Dropbox (older client): ~/.dropbox/info.json    iCloud Drive: ~/Library/Mobile Documents/com~apple~CloudDocs
out=""
add() { if [ -z "$out" ]; then out="$(sc_json_str "$1")"; else out="$out,$(sc_json_str "$1")"; fi; }
cs="$SC_HOME/Library/CloudStorage"
has_dir() { # pattern prefix
  local d
  for d in "$cs"/$1; do [ -d "$d" ] && return 0; done
  return 1
}
if has_dir "GoogleDrive-*"; then add "Google Drive"; fi
if has_dir "OneDrive-*" || has_dir "OneDrive"; then add "OneDrive"; fi
if has_dir "Dropbox*" || [ -f "$SC_HOME/.dropbox/info.json" ]; then add "Dropbox"; fi
if has_dir "Box-*"; then add "Box"; fi
if [ -d "$SC_HOME/Library/Mobile Documents/com~apple~CloudDocs" ]; then add "iCloud Drive"; fi
sc_emit "{\"products\":[$out]}" ""
exit 0

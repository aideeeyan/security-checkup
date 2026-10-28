#!/bin/bash
# Shared helpers for the Mac parts (sourced). Bash 3.2 compatible. Read-only: no sudo, no writes, no network.
# Test overrides: SC_HOME (home folder), SC_APPS_DIR (/Applications), SC_SOCKETFILTERFW, SC_SAFARI_APP, SC_XPROTECT_INFO.

SC_HOME="${SC_HOME:-$HOME}"
SC_APPS_DIR="${SC_APPS_DIR:-/Applications}"
SC_SOCKETFILTERFW="${SC_SOCKETFILTERFW:-/usr/libexec/ApplicationFirewall/socketfilterfw}"
SC_XPROTECT_INFO="${SC_XPROTECT_INFO:-/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist}"
SC_SAFARI_APP="${SC_SAFARI_APP:-/System/Cryptexes/App/System/Applications/Safari.app}"

# JSON string with escaping (backslash, quote, control characters). Non-ASCII passes through as UTF-8.
sc_json_str() {
  printf '"'
  printf '%s' "$1" | LC_ALL=C tr '\000-\037' ' ' | LC_ALL=C sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' | tr -d '\n'
  printf '"'
}

# Prints a quoted string, or null when empty.
sc_json_str_or_null() {
  if [ -z "$1" ]; then printf 'null'; else sc_json_str "$1"; fi
}

# sc_emit '<facts object>' '<unavailable: empty = null>'
sc_emit() {
  if [ -n "$2" ]; then
    printf '{"facts":%s,"unavailable":"%s"}\n' "$1" "$2"
  else
    printf '{"facts":%s,"unavailable":null}\n' "$1"
  fi
}

# Runs a command, merging stderr (some tools log to stderr). Sets CAP_OUT and CAP_RC. 127 = command not found.
sc_capture() {
  CAP_OUT=$("$@" 2>&1)
  CAP_RC=$?
}

# Permission problem: the tool failed while not running as root, or it says so itself. Parts never use sudo.
# Decided from the exit status and the user id first; the message text is only a fallback for tools that exit 0.
sc_is_denied() {
  local uid low
  uid=$(id -u 2>/dev/null)
  low=$(printf '%s' "$CAP_OUT" | LC_ALL=C tr 'A-Z' 'a-z')
  if [ "$CAP_RC" -ne 0 ] && [ "$CAP_RC" -ne 127 ] && [ "$uid" != "0" ]; then
    case "$low" in
      *"not permitted"*|*"permission"*|*"privilege"*|*"administrator"*|*"authoriz"*|*"must be root"*|*"root"*|*"not allowed"*) return 0 ;;
    esac
  fi
  case "$low" in
    *"not permitted"*|*"requires admin"*|*"admin privileges"*|*"administrator privileges"*) return 0 ;;
  esac
  return 1
}

# After sc_capture failed: prints needs_admin / not_supported / error
sc_unavailable_for_capture() {
  if [ "$CAP_RC" -eq 127 ]; then printf 'not_supported'
  elif sc_is_denied; then printf 'needs_admin'
  else printf 'error'; fi
}

# YYYY-MM-DD from an ISO timestamp, or empty
sc_day() {
  local d="${1%%T*}"
  case "$d" in
    [0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]) printf '%s' "$d" ;;
  esac
}

# Reads "name<TAB>date" lines from system_profiler SPInstallHistoryDataType -json on stdin.
sc_history_entries() {
  awk '
    /^[ \t]*\{[ \t]*$/ { name = ""; date = ""; next }
    /"_name"/ { v = $0; sub(/^[^:]*:[ \t]*"/, "", v); sub(/",?[ \t]*$/, "", v); name = v; next }
    /"install_date"/ { v = $0; sub(/^[^:]*:[ \t]*"/, "", v); sub(/",?[ \t]*$/, "", v); date = v; next }
    /^[ \t]*\},?[ \t]*$/ { if (name != "") print name "\t" date; name = ""; date = "" }
  '
}

# Latest YYYY-MM-DD among history entries whose name matches the case pattern given as $1 (a shell case-pattern list via sc_name_matches_*)
# Usage: sc_history_latest <kind> < entries   (kind: os | xprotect)
sc_history_latest() {
  local kind="$1" name date day best="" tab
  tab=$(printf '\t')
  while IFS="$tab" read -r name date; do
    case "$kind" in
      os) case "$name" in macOS*|"OS X"*|"Mac OS X"*|"Security Update"*) ;; *) continue ;; esac ;;
      xprotect) case "$name" in XProtect*) ;; *) continue ;; esac ;;
    esac
    day=$(sc_day "$date")
    [ -n "$day" ] || continue
    if [ -z "$best" ] || [ "$day" \> "$best" ]; then best="$day"; fi
  done
  printf '%s' "$best"
}

# Modification day (YYYY-MM-DD) of a file via BSD stat; empty when stat is not the BSD one, the file is missing or the output is not a date.
sc_file_day() {
  local d
  [ -e "$1" ] || return 0
  d=$(stat -f %Sm -t %Y-%m-%d "$1" 2>/dev/null | head -n 1)
  sc_day "$d"
}

# Version of an app bundle (short version, then build version), or empty
sc_app_version() {
  local v
  v=$(defaults read "$1/Contents/Info" CFBundleShortVersionString 2>/dev/null)
  if [ -z "$v" ]; then v=$(defaults read "$1/Contents/Info" CFBundleVersion 2>/dev/null); fi
  printf '%s' "$v"
}

# Lowercase
sc_lower() { printf '%s' "$1" | LC_ALL=C tr 'A-Z' 'a-z'; }

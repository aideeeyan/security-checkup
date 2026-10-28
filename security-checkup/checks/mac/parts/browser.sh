#!/bin/bash
. "$(dirname "$0")/_common.sh"
# Chrome, Edge, Firefox in /Applications (or ~/Applications) and Safari (the system copy when not in /Applications).
out=""
add() { # label app-path
  local v item
  [ -d "$2" ] || return 0
  v=$(sc_app_version "$2")
  [ -n "$v" ] || return 0
  item="{\"name\":$(sc_json_str "$1"),\"version\":$(sc_json_str "$v")}"
  if [ -z "$out" ]; then out="$item"; else out="$out,$item"; fi
}
pick() { # label app-name
  if [ -d "$SC_APPS_DIR/$2" ]; then add "$1" "$SC_APPS_DIR/$2"
  elif [ -d "$SC_HOME/Applications/$2" ]; then add "$1" "$SC_HOME/Applications/$2"; fi
}
pick "Google Chrome" "Google Chrome.app"
pick "Microsoft Edge" "Microsoft Edge.app"
pick "Mozilla Firefox" "Firefox.app"
if [ -d "$SC_APPS_DIR/Safari.app" ]; then add "Safari" "$SC_APPS_DIR/Safari.app"; else add "Safari" "$SC_SAFARI_APP"; fi
sc_emit "{\"browsers\":[$out]}" ""
exit 0

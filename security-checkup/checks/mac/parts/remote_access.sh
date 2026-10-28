#!/bin/bash
. "$(dirname "$0")/_common.sh"
# launchctl print-disabled system lists only services whose default was overridden.
# New format: "label" => enabled|disabled. Old format: "label" => false|true (true = disabled). Not listed = default = off.
sc_capture launchctl print-disabled system
if [ "$CAP_RC" -ne 0 ]; then
  sc_emit '{}' "$(sc_unavailable_for_capture)"
  exit 0
fi
state_of() {
  local v
  v=$(printf '%s\n' "$CAP_OUT" | sed -n "s/.*\"$1\"[[:space:]]*=>[[:space:]]*\\([a-z]*\\).*/\\1/p" | head -n 1)
  case "$v" in
    enabled|false) printf 'true' ;;
    *) printf 'false' ;;
  esac
}
ssh=$(state_of "com.openssh.sshd")
scr=$(state_of "com.apple.screensharing")
sc_emit "{\"rdpEnabled\":null,\"sshEnabled\":$ssh,\"screenSharingEnabled\":$scr}" ""
exit 0

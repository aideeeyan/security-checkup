#!/bin/bash
. "$(dirname "$0")/_common.sh"
# sysadminctl -screenLock status logs to stderr: "screenLock delay is N seconds" / "... is immediate" / "screenLock is off".
# The delay is how long after the screen saver / display sleep the password is asked. The time until the screen saver or
# display sleep starts comes from the screen saver idle time and pmset displaysleep (both readable without admin).
# No lock (off, or no screen saver / display sleep to start it) -> timeoutMinutes null, requiresPassword false (never 0).
sc_capture sysadminctl -screenLock status
if [ "$CAP_RC" -ne 0 ] || sc_is_denied; then
  sc_emit '{}' "$(sc_unavailable_for_capture)"
  exit 0
fi
low=$(sc_lower "$CAP_OUT")
delay=""
case "$low" in
  *"screenlock is off"*|*"screenlock is disabled"*|*"screenlock is none"*) delay="off" ;;
  *"delay is immediate"*) delay=0 ;;
  *)
    n=$(printf '%s' "$low" | sed -n 's/.*delay is \([0-9][0-9]*\) second.*/\1/p' | head -n 1)
    if [ -n "$n" ]; then delay="$n"; fi ;;
esac
if [ -z "$delay" ]; then
  sc_emit '{}' "error"
  exit 0
fi
if [ "$delay" = "off" ]; then
  sc_emit '{"timeoutMinutes":null,"requiresPassword":false}' ""
  exit 0
fi
start=""
ss=$(defaults -currentHost read com.apple.screensaver idleTime 2>/dev/null)
case "$ss" in
  ''|*[!0-9]*) ;;
  *) if [ "$ss" -gt 0 ]; then start=$(( (ss + 59) / 60 )); fi ;;
esac
ds=$(pmset -g 2>/dev/null | awk '$1=="displaysleep"{print $2; exit}')
case "$ds" in
  ''|*[!0-9]*) ;;
  *) if [ "$ds" -gt 0 ]; then
       if [ -z "$start" ] || [ "$ds" -lt "$start" ]; then start="$ds"; fi
     fi ;;
esac
if [ -z "$start" ]; then
  sc_emit '{"timeoutMinutes":null,"requiresPassword":false}' ""
  exit 0
fi
total=$(( start + (delay + 59) / 60 ))
sc_emit "{\"timeoutMinutes\":$total,\"requiresPassword\":true}" ""
exit 0

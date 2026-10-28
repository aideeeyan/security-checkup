#!/bin/bash
. "$(dirname "$0")/_common.sh"
# socketfilterfw --getglobalstate prints "(State = N)": 0 off, 1 on, 2 block all incoming. Only the number is read.
sc_capture "$SC_SOCKETFILTERFW" --getglobalstate
if [ "$CAP_RC" -ne 0 ]; then
  sc_emit '{}' "$(sc_unavailable_for_capture)"
  exit 0
fi
state=$(printf '%s' "$CAP_OUT" | sed -n 's/.*State = \([0-9][0-9]*\).*/\1/p' | head -n 1)
case "$state" in
  0) sc_emit '{"enabled":false}' "" ;;
  1|2) sc_emit '{"enabled":true}' "" ;;
  *) sc_emit '{}' "error" ;;
esac
exit 0

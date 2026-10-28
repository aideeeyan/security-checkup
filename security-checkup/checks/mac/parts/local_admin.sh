#!/bin/bash
. "$(dirname "$0")/_common.sh"
# Member of the "admin" group of the current user (id -Gn). Whole-word match.
sc_capture id -Gn
if [ "$CAP_RC" -ne 0 ]; then
  sc_emit '{}' "$(sc_unavailable_for_capture)"
  exit 0
fi
is=false
for g in $CAP_OUT; do
  if [ "$g" = "admin" ]; then is=true; fi
done
sc_emit "{\"isAdmin\":$is}" ""
exit 0

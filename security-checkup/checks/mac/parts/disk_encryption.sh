#!/bin/bash
. "$(dirname "$0")/_common.sh"
# fdesetup status works without admin rights. Real outputs: "FileVault is On." / "FileVault is Off." /
# "FileVault is Off, but will be enabled after the next restart." / "FileVault is On." followed by "Encryption in progress: ..."
# (also "Decryption in progress"). Only a finished "On." counts as protected; Off (any variant) and in-progress -> false.
sc_capture fdesetup status
if [ "$CAP_RC" -ne 0 ]; then
  sc_emit '{}' "$(sc_unavailable_for_capture)"
  exit 0
fi
first=$(printf '%s\n' "$CAP_OUT" | head -n 1)
case "$CAP_OUT" in
  *"Encryption in progress"*|*"Decryption in progress"*) sc_emit '{"encrypted":false}' ""; exit 0 ;;
esac
case "$first" in
  "FileVault is On."*) sc_emit '{"encrypted":true}' "" ;;
  "FileVault is Off"*) sc_emit '{"encrypted":false}' "" ;;
  *)
    sc_emit '{"encrypted":null}' "not_supported" ;;
esac
exit 0

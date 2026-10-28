#!/bin/bash
. "$(dirname "$0")/_common.sh"
# Latest macOS / Security Update entry in the install history. Pending updates need the network (softwareupdate -l), so pendingCount is null.
sc_capture system_profiler SPInstallHistoryDataType -json
if [ "$CAP_RC" -ne 0 ]; then
  sc_emit '{}' "$(sc_unavailable_for_capture)"
  exit 0
fi
last=$(printf '%s\n' "$CAP_OUT" | sc_history_entries | sc_history_latest os)
sc_emit "{\"lastInstalledAt\":$(sc_json_str_or_null "$last"),\"pendingCount\":null}" ""
exit 0

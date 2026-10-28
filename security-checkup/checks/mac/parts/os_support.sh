#!/bin/bash
. "$(dirname "$0")/_common.sh"
ver=$(sw_vers -productVersion 2>/dev/null)
build=$(sw_vers -buildVersion 2>/dev/null)
if [ -z "$ver" ]; then
  sc_emit '{}' "error"
  exit 0
fi
sc_emit "{\"name\":\"macOS\",\"version\":$(sc_json_str "$ver"),\"build\":$(sc_json_str_or_null "$build")}" ""
exit 0

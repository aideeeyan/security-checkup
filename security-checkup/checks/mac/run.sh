#!/bin/bash
# Read-only diagnosis runner for macOS (bash 3.2). Only writes the files the caller asks for (--out / --outdir) and the folders of "paths".
#   run.sh paths
#   run.sh check --label <name> --checks <id,id,...> --out <file>
#   run.sh report --data <diagnosis.json> --outdir <folder> [--pcs-dir <folder>] [--no-open]
# Test overrides: SC_DOCS_ROOT (documents folder), SC_PARTS_DIR (parts folder).

HERE="$(cd "$(dirname "$0")" && pwd)"
SKILL="$(dirname "$(dirname "$HERE")")"
PARTS="${SC_PARTS_DIR:-$HERE/parts}"
ALL="antivirus disk_encryption os_update os_support firewall screen_lock local_admin remote_access vpn_client cloud_sync browser"

die() { printf '%s\n' "$1" >&2; exit 1; }
usage() { die "usage: run.sh paths | check --label <name> --checks <ids> --out <file> | report --data <diagnosis.json> --outdir <folder> [--pcs-dir <folder>] [--no-open]"; }

json_str() {
  printf '"'
  printf '%s' "$1" | LC_ALL=C tr '\000-\037' ' ' | LC_ALL=C sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' | tr -d '\n'
  printf '"'
}

# Strict, simple JSON shape check without a JSON parser: starts with "{", brackets and quotes are balanced and nested
# correctly, no stray text after the top-level value, no unterminated string. Reads stdin.
json_balanced() {
  LC_ALL=C awk '
    { text = text $0 "\n" }
    END {
      n = length(text); depth = 0; instr = 0; started = 0; done = 0
      for (i = 1; i <= n; i++) {
        c = substr(text, i, 1)
        if (instr) {
          if (c == "\\") { i++ }
          else if (c == "\"") { instr = 0 }
          continue
        }
        if (c == " " || c == "\n" || c == "\t" || c == "\r") continue
        if (done) exit 1
        if (c == "\"") { instr = 1; if (!started) exit 1; continue }
        if (c == "{" || c == "[") {
          if (!started && c != "{") exit 1
          started = 1; depth++; stack[depth] = c; continue
        }
        if (c == "}" || c == "]") {
          if (depth == 0) exit 1
          if ((c == "}" && stack[depth] != "{") || (c == "]" && stack[depth] != "[")) exit 1
          depth--
          if (depth == 0) done = 1
          continue
        }
        if (!started) exit 1
      }
      exit (done && !instr && depth == 0) ? 0 : 1
    }'
}

# A part result must be one line: {"facts":{...},"unavailable":null|"needs_admin"|"not_supported"|"error"}
valid_part() {
  local text="$1"
  case "$text" in
    *'
'*) return 1 ;;
  esac
  case "$text" in
    '{"facts":{'*) ;;
    *) return 1 ;;
  esac
  case "$text" in
    *'"unavailable":null}'|*'"unavailable":"needs_admin"}'|*'"unavailable":"not_supported"}'|*'"unavailable":"error"}') ;;
    *) return 1 ;;
  esac
  printf '%s' "$text" | json_balanced
}

# JSON text -> a JavaScript string literal for JSON.parse("..."): escapes \ " < (as \u003c), tab, CR, newline, U+2028, U+2029.
# The data is never placed into the page as a JS expression.
js_literal() {
  local tab cr
  tab=$(printf '\t')
  cr=$(printf '\r')
  printf '"'
  printf '%s' "$1" | LC_ALL=C sed \
    -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e 's/</\\u003c/g' \
    -e "s/$tab/\\\\t/g" -e "s/$cr/\\\\r/g" \
    -e "s/$(printf '\342\200\250')/\\\\u2028/g" -e "s/$(printf '\342\200\251')/\\\\u2029/g" |
    LC_ALL=C awk 'NR > 1 { printf "%s", "\\n" } { printf "%s", $0 }'
  printf '"'
}

roots() {
  local docs="${SC_DOCS_ROOT:-$HOME/Documents}"
  OUTPUT_ROOT="$docs/セキュリティ診断"
  EMP_RESULTS="$OUTPUT_ROOT/社員PC結果"
}

# Output guard: --out / --outdir must be absolute paths inside the output root of "paths" (no ".." parts),
# so the auto-approved runner can never write elsewhere.
inside_root() {
  roots
  case "$1" in
    /*) ;;
    *) return 1 ;;
  esac
  case "/$1/" in
    */../*|*/./*) return 1 ;;
  esac
  case "$1" in
    "$OUTPUT_ROOT"/?*) return 0 ;;
  esac
  return 1
}

cmd_paths() {
  roots
  mkdir -p "$OUTPUT_ROOT" "$EMP_RESULTS" || die "cannot create folders"
  printf '{"outputRoot":%s,"employeeResults":%s}\n' "$(json_str "$OUTPUT_ROOT")" "$(json_str "$EMP_RESULTS")"
}

cmd_check() {
  local seen="|" label="" checks="" out="" id file raw rc json parts="" osv today text dir
  while [ $# -gt 0 ]; do
    case "$1" in
      --label) [ $# -ge 2 ] || usage; label="$2"; shift 2 ;;
      --checks) [ $# -ge 2 ] || usage; checks="$2"; shift 2 ;;
      --out) [ $# -ge 2 ] || usage; out="$2"; shift 2 ;;
      *) usage ;;
    esac
  done
  [ -n "$label" ] || die "--label is required"
  [ -n "$out" ] || die "--out is required"
  inside_root "$out" || die "--out must be inside the output folder"
  case "$out" in *.json) ;; *) die "--out must end with .json" ;; esac
  if [ -z "$checks" ]; then checks="$ALL"; fi
  checks=$(printf '%s' "$checks" | tr ',' ' ')
  set -f
  for id in $checks; do
    case "$seen" in *"|$id|"*) continue ;; esac
    seen="$seen$id|"
    file="$PARTS/$id.sh"
    case "$id" in
      *[!a-z_]*) json='{"facts":{},"unavailable":"not_supported"}' ;;
      *)
        if [ ! -f "$file" ]; then
          json='{"facts":{},"unavailable":"not_supported"}'
        else
          raw=$(bash "$file" 2>/dev/null)
          rc=$?
          if [ "$rc" -eq 0 ] && valid_part "$raw"; then json="$raw"; else json='{"facts":{},"unavailable":"error"}'; fi
        fi ;;
    esac
    if [ -z "$parts" ]; then parts="\"$id\":$json"; else parts="$parts,\"$id\":$json"; fi
  done
  set +f
  osv=$(sw_vers -productVersion 2>/dev/null)
  today=$(date +%Y-%m-%d)
  text="{\"version\":1,\"label\":$(json_str "$label"),\"checkedAt\":\"$today\",\"os\":\"mac\",\"osVersion\":$(json_str "$osv"),\"checks\":{$parts}}"
  printf '%s' "$text" | json_balanced || die "internal error: invalid result"
  dir=$(dirname "$out")
  mkdir -p "$dir" || die "cannot create output folder"
  printf '%s\n' "$text" > "$out" || die "cannot write output file"
}

cmd_report() {
  local data="" outdir="" pcsdir="" noopen=0 f q d first size item
  while [ $# -gt 0 ]; do
    case "$1" in
      --data) [ $# -ge 2 ] || usage; data="$2"; shift 2 ;;
      --outdir) [ $# -ge 2 ] || usage; outdir="$2"; shift 2 ;;
      --pcs-dir) [ $# -ge 2 ] || usage; pcsdir="$2"; shift 2 ;;
      --no-open) noopen=1; shift ;;
      *) usage ;;
    esac
  done
  [ -n "$data" ] || die "--data is required"
  [ -n "$outdir" ] || die "--outdir is required"
  inside_root "$outdir" || die "--outdir must be inside the output folder"
  [ -f "$data" ] || die "data file not found"
  if [ -n "$pcsdir" ]; then [ -d "$pcsdir" ] || die "pcs folder not found"; fi
  d=$(cat "$data")
  printf '%s' "$d" | json_balanced || die "data is not valid JSON"
  mkdir -p "$outdir" || die "cannot create output folder"
  for f in baseline.js engine.js scenes.js report.html asklist.html pcs.html; do
    cp -f "$SKILL/report/$f" "$outdir/$f" || die "cannot copy $f"
  done
  q=$(cat "$SKILL/questions/company.json")
  printf 'window.SC_QUESTIONS = JSON.parse(%s);\n' "$(js_literal "$q")" > "$outdir/questions.js"
  printf 'window.SC_DATA = JSON.parse(%s);\n' "$(js_literal "$d")" > "$outdir/data.js"
  # Employee result files: one JS string literal per *.json file, never parsed or run here. The page parses each one
  # inside its own try, so a broken or hostile file only counts as "unreadable". Always rewritten (no stale results).
  {
    printf 'window.SC_PCS = ['
    first=1
    if [ -n "$pcsdir" ]; then
      for f in "$pcsdir"/*.json; do
        [ -f "$f" ] || continue
        size=$(wc -c < "$f" | tr -d ' ')
        if [ "${size:-0}" -gt 1048576 ]; then item=$(js_literal "too large"); else item=$(js_literal "$(cat "$f")"); fi
        if [ "$first" -eq 1 ]; then first=0; else printf ','; fi
        printf '\n%s' "$item"
      done
    fi
    printf '];\n'
  } > "$outdir/pcs.js"
  if [ "$noopen" -eq 0 ]; then open "$outdir/report.html" >/dev/null 2>&1; fi
  printf '{"report":%s}\n' "$(json_str "$outdir/report.html")"
}

case "$1" in
  paths) shift; cmd_paths "$@" ;;
  check) shift; cmd_check "$@" ;;
  report) shift; cmd_report "$@" ;;
  *) usage ;;
esac

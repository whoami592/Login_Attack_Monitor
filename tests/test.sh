#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf -- "$tmp"' EXIT
bash -n "$ROOT/monitor.sh"
bash "$ROOT/monitor.sh" demo --no-banner --output "$tmp/offline" > "$tmp/output"
grep -q 'Parsed failed events: 6 | accepted events: 2' "$tmp/output"
[[ $(grep -c '\[ALERT\]' "$tmp/output") == 2 ]]
if bash "$ROOT/monitor.sh" demo --threshold 0 >/dev/null 2>&1; then exit 1; fi
if bash "$ROOT/monitor.sh" scan --file "$tmp/missing" >/dev/null 2>&1; then exit 1; fi
mkdir "$tmp/live"
flags=()
if awk -W version 2>&1 | grep -qi mawk; then flags=(-W interactive); fi
# Expired failures must not contribute; a later burst must alert again.
{
 head -n 1 "$ROOT/examples/auth.log"
 head -n 1 "$ROOT/examples/auth.log"
 sleep 3
 head -n 1 "$ROOT/examples/auth.log"
 head -n 1 "$ROOT/examples/auth.log"
} | LAM_RUN="$tmp/live" awk "${flags[@]}" -v limit=2 -v window=1 -v live=1 -f "$ROOT/parser.awk" > "$tmp/live-output"
[[ $(grep -c REPEATED_FAILURES "$tmp/live/alerts.tsv") == 2 ]]
[[ $(wc -l < "$tmp/live/events.tsv") == 5 ]]
printf 'PASS: syntax, demo counts, IPv6, ignored duplicate/other-service lines, alerts, invalid arguments, missing file, live window expiry/rearm.\n'

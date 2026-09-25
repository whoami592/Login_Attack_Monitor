#!/usr/bin/env bash
# Coded by Cyber Security Engineer Mr Sabaz Ali Khan
set -euo pipefail
umask 077
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
usage() {
cat <<'HELP'
Login Attack Monitor 1.0
Coded by Cyber Security Engineer Mr Sabaz Ali Khan
Usage:
  bash monitor.sh demo
  bash monitor.sh scan --file /var/log/auth.log
  bash monitor.sh watch --file /var/log/auth.log
  bash monitor.sh journal
Options: --threshold N (default 5), --window SECONDS (default 300),
         --output DIRECTORY (default ./reports), --no-banner
scan: totals across entire input; no time filtering.
watch/journal: rolling window using local observation time, new entries only.
Supported events: OpenSSH Failed password/publickey and Accepted logins.
Ctrl+C stops monitoring. No firewall or account settings are changed.
HELP
}
mode=${1:---help}; shift || true
case "$mode" in -h|--help|help) usage; exit 0;; demo|scan|watch|journal) ;; *) usage >&2; exit 2;; esac
file= threshold=5 window=300 output=./reports banner=1
while (($#)); do
 case "$1" in
 --file|--threshold|--window|--output)
  (($# >= 2)) || { echo "Missing value: $1" >&2; exit 2; }
  case "$1" in --file) file=$2;; --threshold) threshold=$2;; --window) window=$2;; --output) output=$2;; esac
  shift 2;;
 --no-banner) banner=0; shift;;
 *) echo "Unknown option: $1" >&2; exit 2;;
 esac
done
for n in "$threshold" "$window"; do
 [[ $n =~ ^[1-9][0-9]{0,5}$ ]] || { echo 'Threshold/window must be integers 1..999999.' >&2; exit 2; }
done
for tool in awk mktemp date; do command -v "$tool" >/dev/null || { echo "Missing: $tool" >&2; exit 1; }; done
if [[ $mode == demo ]]; then file=$ROOT/examples/auth.log; fi
if [[ $mode != journal ]]; then
 [[ -n $file && -f $file && -r $file ]] || { echo 'Use --file with a readable regular log file (sudo may be needed).' >&2; exit 1; }
else
 command -v journalctl >/dev/null || { echo 'journalctl is unavailable.' >&2; exit 1; }
 [[ -z $file ]] || { echo '--file cannot be used with journal.' >&2; exit 2; }
fi
((banner == 0)) || cat -- "$ROOT/assets/banner.txt"
printf '\nLOGIN ATTACK MONITOR 1.0\nCoded by Cyber Security Engineer Mr Sabaz Ali Khan\n\n'
mkdir -p -- "$output"
run=$(mktemp -d -- "$output/run-XXXXXXXX")
run=$(cd -- "$run" && pwd)
printf 'Reports: %s\n' "$run"
printf 'Mode: %s\nThreshold: %s\nWindow seconds (live only): %s\nStarted UTC: %s\n' "$mode" "$threshold" "$window" "$(date -u +%FT%TZ)" > "$run/session.txt"
live=0
[[ $mode == watch || $mode == journal ]] && live=1
pid=
cleanup() { if [[ -n $pid ]]; then kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; fi; rm -f -- "$run/input.pipe"; }
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
if ((live)); then
 mkfifo -- "$run/input.pipe"
 if [[ $mode == watch ]]; then
  tail -n 0 -F -- "$file" > "$run/input.pipe" & pid=$!
 else
  # Filter the executable identifiers, covering sshd and split sshd-session.
  journalctl --quiet --no-pager -n 0 -f -o short-iso SYSLOG_IDENTIFIER=sshd SYSLOG_IDENTIFIER=sshd-session > "$run/input.pipe" & pid=$!
 fi
 file=$run/input.pipe
 echo 'Watching NEW events. Ctrl+C to stop. Live windows use observation time.'
else
 echo 'Offline scan: threshold applies to whole file, not a time window.'
fi
# Report path via environment avoids awk -v backslash interpretation in paths.
awk_flags=()
if awk -W version 2>&1 | grep -qi mawk; then awk_flags=(-W interactive); fi
LAM_RUN="$run" awk "${awk_flags[@]}" -v limit="$threshold" -v window="$window" -v live="$live" -f "$ROOT/parser.awk" < "$file"
if [[ -n $pid ]]; then
 wait "$pid" || { echo 'Log source failed. Check file/journal access.' >&2; exit 1; }
 pid=
fi
printf 'Finished. Reports: %s\n' "$run"

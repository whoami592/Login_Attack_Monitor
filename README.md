# Login Attack Monitor 1.0
Coded by Cyber Security Engineer Mr Sabaz Ali Khan

Terminal-based Bash + AWK OpenSSH login monitor with the requested Unicode banner.

## Requirements
Linux, Bash 4+, GNU coreutils, and mawk or GNU awk (systime and fflush).
No Python, pip, network connection, or third-party account is needed to run it.
Use a UTF-8 terminal; maximize the window for the wide banner, or use --no-banner.
Windows: run inside a Linux VM or WSL. This monitors Linux SSH logs, not Windows
Event Viewer, Facebook, or other online account logins. WSL demo works without SSH.

## Quick start
Extract the ZIP and open a terminal in Login_Attack_Monitor:

```bash
bash monitor.sh demo
bash monitor.sh --help
```
Demo uses fictional documentation addresses and creates two alerts: five failures
from 192.0.2.10, followed by an accepted login from that source.

## Real logs
```bash
sudo bash monitor.sh scan --file /var/log/auth.log
sudo bash monitor.sh watch --file /var/log/auth.log --threshold 5 --window 300
sudo bash monitor.sh journal --threshold 5 --window 300
```
On systems using /var/log/secure, pass that file instead. Choose one source to avoid
monitoring the same events twice. SSH must actually be running and logging.
Journal access may need sudo. An empty journal does not prove there were no attacks.
The monitor does not enable SSH or install/change services. Press Ctrl+C to stop.

## Detection semantics
- scan/demo counts the ENTIRE supplied file. It does not interpret historical dates.
- watch uses tail -n 0 -F, follows file rotation, and starts with NEW lines only.
- journal follows new sshd and sshd-session journal entries only.
- Live threshold: at least N failure records from the same source within the last
  W seconds of observation by this process, inclusive of the boundary. Clock changes,
  buffering and delayed log delivery can affect this; it is not event-time analysis.
- One repeated-failure alert per source until its active count falls below threshold
  when the next event for that source arrives. Continued attacks do not spam alerts.
- Accepted login after threshold failures triggers a REVIEW alert for that source.
  This does not prove compromise; shared IPs and legitimate mistakes can explain it.
- Password, publickey and keyboard-interactive/pam canonical Failed/Accepted records
  are supported. PAM authentication-failure and Invalid-user precursor lines are
  ignored to avoid double counting. Other services/formats and compressed logs are
  not supported. Counts are records, not necessarily unique login sessions.
- State resets at restart; no historical live catch-up or persistent alert state.

## Reports
Each invocation creates a private reports/run-XXXXXXXX directory:
- events.tsv: observation epoch, event, source, username and authentication method.
- alerts.tsv: review alerts and the count/scope that triggered them.
- summary.tsv: total failures per source (written on normal completion).
- session.txt: mode and parameters.
Live events/alerts are flushed as they arrive. On interruption use events.tsv and
alerts.tsv; the summary may be missing. No passwords or full raw log lines are copied.
Reports are local, contain sensitive login metadata, and grow until you stop the
process. No automatic report rotation/retention; archive or remove old runs yourself.
Source counters grow with unique sources; this is a small-host monitor, not a SIEM.
IPv4/IPv6 address tokens are preserved, not canonicalized or geolocated.

Change destination with --output /path/to/reports. Sudo creates root-owned reports.

## Troubleshooting
- Missing log: select /var/log/secure or use journal mode.
- No results: verify NEW canonical OpenSSH events reach the selected source.
- Permission denied: use sudo only for logs requiring it.
- Banner wrapping: enlarge terminal or add --no-banner.
- Run offline smoke and rolling-window checks: bash tests/test.sh

Use on systems you administer or are authorized to monitor. Alerts require human
review. The application never blocks IPs, changes firewalls, or sends reports.

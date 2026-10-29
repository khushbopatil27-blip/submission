# Log Analyzer - Automation Proof of Concept

A small, dependency-free Python tool that supports the secure IT operations workflow. It:

1. **Parses** a Linux auth log (`/var/log/auth.log`, Ubuntu/Debian/Kali syslog format).
2. **Stores** security events in a SQLite database (`events.db`) and summarises them with **SQL** queries.
3. **Detects** suspicious activity: brute-force attempts, successful login after failures, root login attempts, sudo failures, new accounts and privileged-group changes.
4. **Validates user access records** (a CSV export of accounts) against an approved-user list: unapproved accounts, excess privileges, dormant accounts, approved users with no account.
5. **Reports** a Markdown and JSON summary with severities (SEV-1 to SEV-4) that match the escalation matrix.

## Requirements
- Python 3.8 or newer (tested with 3.13). Standard library only - nothing to install.
- Read access to the log file. The script never modifies the log.

## Quick start (demo with included sample data)
```bash
cd automation
python3 log_analyzer.py \
  --log sample_data/auth.log --year 2026 \
  --users sample_data/system_users.csv \
  --approved sample_data/approved_users.csv \
  --today 2026-10-29 \
  --out reports
```
Output: report printed to the screen, plus `reports/summary_report.md`, `reports/summary_report.json` and `reports/events.db`.
The folder `reports/` already contains the output from the sample run.

**Exit code:** `0` = no SEV-1/SEV-2 findings, `1` = at least one SEV-1/SEV-2 finding (so a scheduler can alert), `2` = input error.

## Run on a real system
```bash
sudo python3 log_analyzer.py --log /var/log/auth.log --out /var/reports/daily
```
Add `--users` and `--approved` to also validate access records.

## Input formats
`system_users.csv` (export from the host or directory):
```
username,groups,status,last_login
alice,sudo;developers,active,2026-10-28
```
`approved_users.csv` (owned by the access-review process):
```
username,allowed_groups
alice,sudo;developers
```
Groups are separated by `;`. Dates use `YYYY-MM-DD`.

Quick way to build `system_users.csv` on Linux (example):
```bash
for u in $(awk -F: '$3>=1000 && $3<65000 {print $1}' /etc/passwd); do
  echo "$u,$(id -nG $u | tr ' ' ';'),active,$(lastlog -u $u | awk 'NR==2{print $4}')"
done
```
(Adjust the last-login column to your date format.)

## Options
| Option | Default | Meaning |
|---|---|---|
| `--log` | required | path to auth log |
| `--year` | current year | syslog lines have no year |
| `--users`, `--approved` | none | enable access validation (use both together) |
| `--threshold` | 5 | failed logins from one IP that count as brute force |
| `--window` | 10 | time window in minutes for the threshold |
| `--dormant-days` | 90 | days without login before an account is flagged |
| `--today` | now | reference date for dormant check (useful for reproducible demos) |
| `--out` | `reports` | output directory |

## Example SQL on the generated database
```bash
sqlite3 reports/events.db "SELECT ip, COUNT(*) FROM events WHERE type='failed_login' GROUP BY ip ORDER BY 2 DESC;"
sqlite3 reports/events.db "SELECT ts, user, ip FROM events WHERE type='success_login' ORDER BY ts;"
```

## Schedule daily (Linux cron)
```
15 6 * * * cd /opt/log_analyzer && python3 log_analyzer.py --log /var/log/auth.log --users /opt/exports/users.csv --approved /opt/exports/approved.csv --out /var/reports/$(date +\%F)
```
On Windows, run the same script via Task Scheduler with a copy of the exported log/CSV files (Windows Event Log parsing is a planned extension).

## What the sample data demonstrates
- IP `203.0.113.45` fails 7 times in under 20 seconds, then logs in as `ubuntu` -> SEV-2 "successful login after brute force".
- `tempsvc` is created and added to `sudo`, and is not on the approved list -> SEV-2/SEV-3.
- `bob` is in `sudo` but only approved for `developers` -> SEV-2 excess privileges.
- `dave` inactive 150 days; `erin` approved but has no account -> SEV-4 housekeeping.

(All IPs use documentation ranges reserved for examples; all names are fictional.)

## How it works (short)
`parse_log` matches lines with a syslog regular expression and event patterns -> `store_events` loads them into SQLite -> `sql_summaries` runs aggregate queries -> `detect` applies rules (sliding time window for brute force) -> `validate_access` compares account data with the approved list -> `build_report` writes the results.

## Limitations and next steps
- Only the Debian/Ubuntu `auth.log` format is parsed (RHEL uses `/var/log/secure`, similar format - patterns may need small tweaks).
- IPv6 addresses are parsed by a simple pattern; log rotation (`.gz`) is not handled.
- Windows Event Log (4624/4625/4720/4732) parsing, email/Slack alerting and a dashboard are natural next steps.
- Findings are indicators for human review, not proof of compromise.

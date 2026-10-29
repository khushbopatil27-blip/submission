#!/usr/bin/env python3
"""
log_analyzer.py - Linux auth-log parsing and user-access validation (proof of concept)

What it does
  1. Parses a Linux auth log (Ubuntu/Debian /var/log/auth.log, classic syslog format).
  2. Extracts security-relevant events into a SQLite database (so results can be queried with SQL):
       - failed SSH logins, successful SSH logins, invalid users
       - sudo command usage, new user / group changes
  3. Detects suspicious patterns:
       - brute force: >= N failed logins from one IP within a time window
       - successful login from an IP that previously had failures (possible compromise)
       - root login attempts, sudo failures, account creation / privilege group changes
  4. Optionally validates user access records (CSV export of accounts) against an approved list:
       - unapproved accounts, accounts with admin rights that should not have them,
         approved users missing, dormant accounts (no login for N days)
  5. Writes a summary report (Markdown + JSON) with severity ratings aligned to the escalation matrix.

Only the Python 3.8+ standard library is used. No network access, read-only on the log file.

Example
  python3 log_analyzer.py --log sample_data/auth.log --year 2026 \
      --users sample_data/system_users.csv --approved sample_data/approved_users.csv \
      --out reports
"""
import argparse
import csv
import json
import re
import sqlite3
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from pathlib import Path

# ---------------------------------------------------------------- parsing ---
LINE_RE = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+"
    r"(?P<proc>[\w\-./]+)(?:\[(?P<pid>\d+)\])?:\s+(?P<msg>.*)$"
)
PATTERNS = [
    ("failed_login", re.compile(
        r"Failed (?:password|publickey) for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+)")),
    ("invalid_user", re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+)")),
    ("success_login", re.compile(
        r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+)")),
    ("sudo_command", re.compile(
        r"(?P<user>\S+)\s*:\s*TTY=\S+\s*;\s*PWD=\S+\s*;\s*USER=(?P<target>\S+)\s*;\s*COMMAND=(?P<cmd>.+)$")),
    ("sudo_failure", re.compile(
        r"(?P<user>\S+)\s*:\s*\d+ incorrect password attempts?")),
    ("user_created", re.compile(r"new user: name=(?P<user>[^,\s]+)")),
    ("group_change", re.compile(
        r"add '(?P<user>[^']+)' to (?:shadow )?group '(?P<group>[^']+)'")),
]


def parse_line(line, year):
    """Return a dict for a relevant event, or None."""
    m = LINE_RE.match(line.strip())
    if not m:
        return None
    try:
        ts = datetime.strptime(f"{year} {re.sub(r'\s+', ' ', m.group('ts'))}", "%Y %b %d %H:%M:%S")
    except ValueError:
        return None
    msg = m.group("msg")
    for etype, rx in PATTERNS:
        hit = rx.search(msg)
        if hit:
            d = hit.groupdict()
            return {
                "ts": ts, "host": m.group("host"), "type": etype,
                "user": d.get("user"), "ip": d.get("ip"),
                "detail": d.get("cmd") or d.get("group") or d.get("target") or "",
            }
    return None


def parse_log(path, year):
    events, total, skipped = [], 0, 0
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if not line.strip():
                continue
            total += 1
            ev = parse_line(line, year)
            if ev:
                events.append(ev)
            else:
                skipped += 1
    return events, total, skipped


# ---------------------------------------------------------------- SQL ---
SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL, host TEXT, type TEXT NOT NULL,
  user TEXT, ip TEXT, detail TEXT
);
CREATE INDEX IF NOT EXISTS idx_type ON events(type);
CREATE INDEX IF NOT EXISTS idx_ip ON events(ip);
"""


def store_events(db_path, events):
    con = sqlite3.connect(db_path)
    con.executescript(SCHEMA)
    con.execute("DELETE FROM events")
    con.executemany(
        "INSERT INTO events (ts, host, type, user, ip, detail) VALUES (?,?,?,?,?,?)",
        [(e["ts"].isoformat(), e["host"], e["type"], e["user"], e["ip"], e["detail"]) for e in events],
    )
    con.commit()
    return con


def sql_summaries(con):
    """Example SQL queries used in the report."""
    top_ips = con.execute(
        "SELECT ip, COUNT(*) c FROM events WHERE type IN ('failed_login','invalid_user') "
        "GROUP BY ip ORDER BY c DESC LIMIT 5").fetchall()
    top_users = con.execute(
        "SELECT user, COUNT(*) c FROM events WHERE type='failed_login' "
        "GROUP BY user ORDER BY c DESC LIMIT 5").fetchall()
    by_type = con.execute(
        "SELECT type, COUNT(*) FROM events GROUP BY type ORDER BY 2 DESC").fetchall()
    return {"top_failed_ips": top_ips, "top_failed_users": top_users, "events_by_type": by_type}


# ---------------------------------------------------------------- detection ---
def detect(events, threshold, window_min):
    findings = []
    window = timedelta(minutes=window_min)

    # 1. Brute force: >= threshold failures from one IP inside the window
    fails = defaultdict(list)
    for e in events:
        if e["type"] in ("failed_login", "invalid_user") and e["ip"]:
            fails[e["ip"]].append(e["ts"])
    flagged_ips = {}
    for ip, times in fails.items():
        times.sort()
        start = 0
        for end in range(len(times)):
            while times[end] - times[start] > window:
                start += 1
            if end - start + 1 >= threshold:
                flagged_ips[ip] = (len(times), times[0], times[-1])
                break
    for ip, (cnt, first, last) in flagged_ips.items():
        findings.append({
            "severity": "SEV-3", "category": "Brute-force attempt",
            "detail": f"{cnt} failed logins from {ip} between {first:%H:%M:%S} and {last:%H:%M:%S}",
            "action": "Block IP at firewall / fail2ban; review targeted accounts"})

    # 2. Success after failures from the same IP = possible compromise
    for e in events:
        if e["type"] == "success_login" and e["ip"] in flagged_ips:
            prior = [t for t in fails[e["ip"]] if t <= e["ts"]]
            if prior:
                findings.append({
                    "severity": "SEV-2", "category": "Successful login after brute force",
                    "detail": f"User '{e['user']}' logged in from {e['ip']} at {e['ts']:%Y-%m-%d %H:%M:%S} "
                              f"after {len(prior)} failures",
                    "action": "Disable account, force password reset, isolate host, escalate to Security lead"})

    # 3. Root login attempts
    root_fail = [e for e in events if e["type"] == "failed_login" and e["user"] == "root"]
    if root_fail:
        findings.append({
            "severity": "SEV-4", "category": "Root login attempts",
            "detail": f"{len(root_fail)} failed root logins; ensure PermitRootLogin no",
            "action": "Verify sshd_config hardening"})

    # 4. sudo failures
    for e in events:
        if e["type"] == "sudo_failure":
            findings.append({
                "severity": "SEV-3", "category": "sudo failure",
                "detail": f"User '{e['user']}' had incorrect sudo password attempts at {e['ts']:%H:%M:%S}",
                "action": "Confirm with user; check for account misuse"})

    # 5. Account creation and privileged group changes
    for e in events:
        if e["type"] == "user_created":
            findings.append({
                "severity": "SEV-3", "category": "New account created",
                "detail": f"Account '{e['user']}' created at {e['ts']:%Y-%m-%d %H:%M:%S}",
                "action": "Verify a ticket/approval exists"})
        if e["type"] == "group_change" and e["detail"] in ("sudo", "adm", "root", "wheel"):
            findings.append({
                "severity": "SEV-2", "category": "Privileged group change",
                "detail": f"'{e['user']}' added to group '{e['detail']}' at {e['ts']:%Y-%m-%d %H:%M:%S}",
                "action": "Verify approval; revert if unauthorised"})
    return findings


# ---------------------------------------------------------------- access validation ---
def read_csv(path):
    with open(path, newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def validate_access(users_csv, approved_csv, dormant_days, today):
    users = read_csv(users_csv)
    approved = {r["username"].strip(): r for r in read_csv(approved_csv)}
    findings = []
    seen = set()
    for u in users:
        name = u["username"].strip()
        seen.add(name)
        groups = {g.strip() for g in u.get("groups", "").split(";") if g.strip()}
        active = u.get("status", "active").strip().lower() == "active"
        if name not in approved:
            findings.append({"severity": "SEV-2" if active else "SEV-4", "category": "Unapproved account",
                             "detail": f"'{name}' exists ({u.get('status','active')}) but is not on the approved list",
                             "action": "Disable and investigate; confirm ticket"})
            continue
        allowed_groups = {g.strip() for g in approved[name].get("allowed_groups", "").split(";") if g.strip()}
        extra = groups - allowed_groups
        if extra:
            sev = "SEV-2" if extra & {"sudo", "wheel", "Administrators", "root"} else "SEV-3"
            findings.append({"severity": sev, "category": "Excess privileges",
                             "detail": f"'{name}' is in unapproved group(s): {', '.join(sorted(extra))}",
                             "action": "Remove membership or document approved exception"})
        last = u.get("last_login", "").strip()
        if active and last:
            try:
                age = (today - datetime.strptime(last, "%Y-%m-%d")).days
                if age > dormant_days:
                    findings.append({"severity": "SEV-4", "category": "Dormant account",
                                     "detail": f"'{name}' has not logged in for {age} days",
                                     "action": "Disable per quarterly review"})
            except ValueError:
                findings.append({"severity": "SEV-4", "category": "Data quality",
                                 "detail": f"'{name}' has invalid last_login '{last}'", "action": "Fix record"})
    for name in approved:
        if name not in seen:
            findings.append({"severity": "SEV-4", "category": "Approved user missing",
                             "detail": f"'{name}' is approved but has no account", "action": "Check onboarding ticket"})
    return findings


# ---------------------------------------------------------------- reporting ---
SEV_ORDER = {"SEV-1": 1, "SEV-2": 2, "SEV-3": 3, "SEV-4": 4}


def build_report(meta, sql, log_findings, access_findings):
    allf = sorted(log_findings + access_findings, key=lambda f: SEV_ORDER[f["severity"]])
    sev_counts = Counter(f["severity"] for f in allf)
    lines = [
        "# Daily Security Log Summary",
        f"_Generated {meta['generated']} - source: `{meta['log']}`_",
        "",
        "## Overview",
        f"- Log lines read: **{meta['total']}**, security events extracted: **{meta['events']}**",
        "- Findings by severity: " + (", ".join(f"{k}: {sev_counts[k]}" for k in sorted(sev_counts, key=SEV_ORDER.get)) or "none"),
        "",
        "## Events by type",
        "| Type | Count |", "|---|---|",
    ] + [f"| {t} | {c} |" for t, c in sql["events_by_type"]] + [
        "",
        "## Top sources of failed logins",
        "| IP | Failures |", "|---|---|",
    ] + [f"| {ip} | {c} |" for ip, c in sql["top_failed_ips"]] + [
        "",
        "## Top targeted usernames",
        "| User | Failures |", "|---|---|",
    ] + [f"| {u} | {c} |" for u, c in sql["top_failed_users"]] + [
        "",
        "## Findings (sorted by severity)",
        "| Severity | Category | Detail | Recommended action |", "|---|---|---|---|",
    ] + [f"| {f['severity']} | {f['category']} | {f['detail']} | {f['action']} |" for f in allf]
    if not allf:
        lines.append("| - | No findings | - | - |")
    lines += ["", "_Severity levels follow the escalation matrix (SEV-1 critical ... SEV-4 low)._"]
    return "\n".join(lines) + "\n", allf, sev_counts


def main(argv=None):
    p = argparse.ArgumentParser(description="Parse Linux auth logs and validate user access records.")
    p.add_argument("--log", required=True, help="path to auth.log")
    p.add_argument("--year", type=int, default=datetime.now().year, help="year of log entries (syslog has none)")
    p.add_argument("--users", help="CSV export of system accounts (username,groups,status,last_login)")
    p.add_argument("--approved", help="CSV of approved users (username,allowed_groups)")
    p.add_argument("--threshold", type=int, default=5, help="failed logins from one IP to flag (default 5)")
    p.add_argument("--window", type=int, default=10, help="time window in minutes (default 10)")
    p.add_argument("--dormant-days", type=int, default=90, help="days of inactivity to flag (default 90)")
    p.add_argument("--today", help="reference date YYYY-MM-DD for dormant check (default: today)")
    p.add_argument("--out", default="reports", help="output directory (default ./reports)")
    a = p.parse_args(argv)

    log_path = Path(a.log)
    if not log_path.is_file():
        print(f"ERROR: log file not found: {log_path}", file=sys.stderr)
        return 2
    if bool(a.users) != bool(a.approved):
        print("ERROR: --users and --approved must be used together", file=sys.stderr)
        return 2

    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    events, total, _ = parse_log(log_path, a.year)
    con = store_events(out / "events.db", events)
    sql = sql_summaries(con)
    con.close()
    log_findings = detect(events, a.threshold, a.window)

    access_findings = []
    if a.users:
        for f in (a.users, a.approved):
            if not Path(f).is_file():
                print(f"ERROR: file not found: {f}", file=sys.stderr)
                return 2
        today = datetime.strptime(a.today, "%Y-%m-%d") if a.today else datetime.now()
        access_findings = validate_access(a.users, a.approved, a.dormant_days, today)

    meta = {"generated": datetime.now().strftime("%Y-%m-%d %H:%M"), "log": str(log_path),
            "total": total, "events": len(events)}
    md, allf, sev_counts = build_report(meta, sql, log_findings, access_findings)
    (out / "summary_report.md").write_text(md, encoding="utf-8")
    (out / "summary_report.json").write_text(
        json.dumps({"meta": meta, "severity_counts": sev_counts, "findings": allf}, indent=2), encoding="utf-8")

    print(md)
    print(f"Reports written to {out}/ (summary_report.md, summary_report.json, events.db)")
    # exit code 1 if SEV-1/SEV-2 findings so schedulers/CI can alert
    return 1 if (sev_counts.get("SEV-1") or sev_counts.get("SEV-2")) else 0


if __name__ == "__main__":
    sys.exit(main())

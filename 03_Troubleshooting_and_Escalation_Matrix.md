# Troubleshooting & Escalation Matrix

## 1. IT Support Ticket Process Map

```
 [User reports issue]
          |
          v
 [1. LOG TICKET] -- channel: portal / email / phone; unique ID assigned
          |
          v
 [2. TRIAGE (Service Desk, L1)]
     - Categorize: Hardware / Software / Access / Network / Security
     - Set priority (P1-P4)
     - Security indicators present? ---YES---> [SECURITY INCIDENT PROCESS, section 3]
          |NO
          v
 [3. L1 RESOLUTION] -- knowledge base, runbook, standard fixes
          |
     Resolved? --YES--> [6. CONFIRM WITH USER] --> [7. CLOSE + update KB]
          |NO (or SLA at 50%)
          v
 [4. L2 ESCALATION (Sysadmin / Specialist)] -- deeper diagnosis, remote access, config
          |
     Resolved? --YES--> [6. CONFIRM WITH USER] --> [7. CLOSE + update KB]
          |NO
          v
 [5. L3 ESCALATION (Vendor / Senior engineer / Manager)] -- root cause, vendor case, change request
          |
          v
 [6. CONFIRM WITH USER] --> [7. CLOSE + root-cause note + KB article]
```

### Priority & SLA table
| Priority | Definition | Example | Response | Resolution target |
|---|---|---|---|---|
| P1 Critical | Service down or security breach, many users affected | Server outage, ransomware | 15 min | 4 hours |
| P2 High | Major function degraded or one VIP/critical user blocked | VPN down for a team | 30 min | 8 hours |
| P3 Medium | Single user impacted, workaround exists | Printer, software error | 4 hours | 3 business days |
| P4 Low | Request or minor issue | New software request | 1 business day | 5 business days |

### Troubleshooting Quick Matrix
| Symptom | First checks (L1) | Escalate to L2 when |
|---|---|---|
| Cannot log in | Account locked/expired? Caps Lock, MFA device, password reset | Repeated lockouts, account suspected compromised -> Security |
| Slow computer | Disk space, running processes (`top` / Task Manager), pending updates, reboot | Persistent after cleanup, signs of malware |
| No network | Cable/Wi-Fi, IP (`ip a` / `ipconfig`), ping gateway & DNS | Multiple users affected, DHCP/DNS/switch fault |
| Linux service failing | `systemctl status <svc>`, `journalctl -u <svc> -n 50`, disk/memory | Config or dependency fault, repeated crash |
| Windows app crash | Event Viewer (Application log), update/reinstall, check disk | Reproducible across users, vendor bug |
| Disk almost full | `df -h` / `du -sh *`, clear temp/log rotation | Growth unexplained -> possible log flood/incident |
| Suspicious email | Do not open; report to security | Always forward to Security |

## 2. Escalation Rules
- **Time-based:** escalate to next level if no progress at 50% of the resolution target.
- **Impact-based:** more than 5 users or any critical system affected -> immediate L2 and notify manager.
- **Risk-based:** any security indicator -> immediate Security escalation regardless of priority.
- **Handover quality:** each escalation includes ticket ID, symptoms, steps already taken, logs/screenshots and business impact.

## 3. Security Incident Escalation Workflow

```
 [DETECTION] sources: daily log report, user report, AV/alert, audit
          |
          v
 [1. TRIAGE - Security analyst, within 15 min]
     Confirm: true incident or false positive?  --FALSE--> document, close
          | TRUE
          v
 [2. CLASSIFY SEVERITY]
     SEV-1 Critical | SEV-2 High | SEV-3 Medium | SEV-4 Low
          |
          v
 [3. CONTAIN] isolate host / disable account / block IP  (keep evidence, do not wipe)
          |
          v
 [4. NOTIFY / ESCALATE] per table below
          |
          v
 [5. ERADICATE & RECOVER] remove cause, patch, restore from clean backup, reset credentials
          |
          v
 [6. VERIFY] monitor 48-72h, confirm normal
          |
          v
 [7. POST-INCIDENT REVIEW] within 5 business days: timeline, root cause, actions, baseline update
```

### Severity & Notification Matrix
| Severity | Examples | Escalate to | Time | Actions |
|---|---|---|---|---|
| SEV-1 | Ransomware, confirmed data breach, domain admin compromise | Security lead -> IT Ops Manager -> Sponsor / management (and legal/DPO where personal data is involved) | Immediate (within 15 min) | Isolate, incident bridge call, preserve evidence |
| SEV-2 | Malware on one host, successful brute-force login, privilege escalation | Security lead, IT Ops Manager | Within 1 hour | Disable account, isolate host, reset credentials |
| SEV-3 | Repeated failed logins (>= 5 from one IP), policy violation, suspicious email clicked | Security analyst, sysadmin | Within 4 hours | Block IP, user coaching, monitor |
| SEV-4 | Single failed-login burst, minor policy deviation | Service desk ticket | Next business day | Log and trend |

### RACI for Incidents
| Activity | Service Desk | Sysadmin | Security | IT Manager |
|---|---|---|---|---|
| Detect & log | R | C | C | I |
| Triage & classify | C | C | R/A | I |
| Contain | I | R | A | I |
| Communicate to management | I | I | R | A |
| Recover | I | R | A | I |
| Post-incident review | C | C | R | A |

*R = Responsible, A = Accountable, C = Consulted, I = Informed.*

### Data-breach note
If personal data is affected, involve the data-protection officer immediately; under GDPR the supervisory authority must be notified within 72 hours of becoming aware of a breach where required.

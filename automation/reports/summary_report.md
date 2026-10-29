# Daily Security Log Summary
_Generated 2026-10-29 14:44 - source: `sample_data\auth.log`_

## Overview
- Log lines read: **19**, security events extracted: **18**
- Findings by severity: SEV-2: 5, SEV-3: 3, SEV-4: 3

## Events by type
| Type | Count |
|---|---|
| failed_login | 8 |
| success_login | 4 |
| invalid_user | 2 |
| group_change | 1 |
| sudo_command | 1 |
| sudo_failure | 1 |
| user_created | 1 |

## Top sources of failed logins
| IP | Failures |
|---|---|
| 203.0.113.45 | 7 |
| 192.0.2.77 | 2 |
| 198.51.100.22 | 1 |

## Top targeted usernames
| User | Failures |
|---|---|
| ubuntu | 2 |
| root | 2 |
| test | 1 |
| oracle | 1 |
| bob | 1 |

## Findings (sorted by severity)
| Severity | Category | Detail | Recommended action |
|---|---|---|---|
| SEV-2 | Successful login after brute force | User 'ubuntu' logged in from 203.0.113.45 at 2026-10-28 02:14:22 after 7 failures | Disable account, force password reset, isolate host, escalate to Security lead |
| SEV-2 | Privileged group change | 'tempsvc' added to group 'sudo' at 2026-10-28 11:20:05 | Verify approval; revert if unauthorised |
| SEV-2 | Excess privileges | 'bob' is in unapproved group(s): sudo | Remove membership or document approved exception |
| SEV-2 | Unapproved account | 'ubuntu' exists (active) but is not on the approved list | Disable and investigate; confirm ticket |
| SEV-2 | Unapproved account | 'tempsvc' exists (active) but is not on the approved list | Disable and investigate; confirm ticket |
| SEV-3 | Brute-force attempt | 7 failed logins from 203.0.113.45 between 02:14:01 and 02:14:18 | Block IP at firewall / fail2ban; review targeted accounts |
| SEV-3 | sudo failure | User 'bob' had incorrect sudo password attempts at 10:01:03 | Confirm with user; check for account misuse |
| SEV-3 | New account created | Account 'tempsvc' created at 2026-10-28 11:20:00 | Verify a ticket/approval exists |
| SEV-4 | Root login attempts | 2 failed root logins; ensure PermitRootLogin no | Verify sshd_config hardening |
| SEV-4 | Dormant account | 'dave' has not logged in for 150 days | Disable per quarterly review |
| SEV-4 | Approved user missing | 'erin' is approved but has no account | Check onboarding ticket |

_Severity levels follow the escalation matrix (SEV-1 critical ... SEV-4 low)._

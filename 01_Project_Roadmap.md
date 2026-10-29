# Project Management & Leadership Roadmap

## 1. Project Charter

| Item | Detail |
|---|---|
| Project name | Secure & Automated IT Operations Workflow |
| Sponsor | IT Operations Manager / Head of IT |
| Project lead | IT Project Lead (author of this plan) |
| Duration | 4 weeks (20 working days) |
| Team | Onboarded IT team members (support, sysadmin, junior security) |
| Purpose | Improve daily IT operations, system documentation and task tracking; establish a secure baseline for Linux (Kali/Ubuntu) and Windows; deliver an automated log-monitoring pipeline. |

**Objectives**
1. Standardize daily IT operations through a shared task board, runbooks and a ticket workflow.
2. Publish and apply a security baseline for Linux and Windows hosts.
3. Deploy a proof-of-concept Python log-parsing and access-validation pipeline that produces daily summary reports.
4. Establish measurable KPIs and a reporting cadence.

**In scope:** workflow design, documentation, baseline policies, log-parsing automation, team training, KPI tracking.
**Out of scope:** procurement of new tooling (e.g. a full SIEM), network redesign, production changes without change approval.

**Success criteria:** all four objectives delivered by end of Week 4; baseline audit completed on at least 90% of in-scope hosts; every team member trained on the ticket and escalation process.

## 2. Four-Week Implementation Plan

### Week 1 - Discovery & Foundations
| Day | Activity | Owner | Output |
|---|---|---|---|
| 1 | Kick-off, goals, roles, tool access | Project lead | Charter signed off |
| 1-2 | Asset & system inventory (hosts, OS, owners) | Sysadmin | Inventory sheet |
| 2-3 | Set up task board (Kanban: Backlog / Doing / Blocked / Review / Done) and ticket categories | Project lead + Support | Live board |
| 3-4 | Documentation standard: template for runbooks, naming, version control (Git/wiki) | All | Doc template |
| 5 | Week 1 review, risk register v1 | Project lead | Risk register |

### Week 2 - Security Baseline & Process Design
| Day | Activity | Owner | Output |
|---|---|---|---|
| 6-7 | Draft hardening baselines (Linux & Windows) | Security / Sysadmin | Baseline policy v1 |
| 7-8 | Define troubleshooting and incident escalation matrix | Project lead + Security | Escalation matrix |
| 8-9 | Security awareness guide drafted and peer-reviewed | Security | Awareness guide |
| 10 | Review with sponsor; approve baseline | Sponsor | Approval |

### Week 3 - Implementation & Automation
| Day | Activity | Owner | Output |
|---|---|---|---|
| 11-12 | Run baseline audit on pilot hosts (2 Linux, 2 Windows) | Sysadmin | Audit findings |
| 12-14 | Deploy log-parsing script on pilot hosts; schedule via cron / Task Scheduler | Sysadmin | Daily report |
| 14 | Validate user access records vs approved list | Security | Access exceptions list |
| 15 | Awareness training session (60 min) + quiz | Security | Attendance log |

### Week 4 - Rollout, Measurement & Handover
| Day | Activity | Owner | Output |
|---|---|---|---|
| 16-17 | Extend baseline audit & automation to remaining hosts | Sysadmin | Coverage report |
| 18 | Tabletop exercise: simulated brute-force incident through escalation matrix | All | Lessons learned |
| 19 | KPI baseline vs. target review; finalize documentation | Project lead | KPI report |
| 20 | Final presentation, retrospective, handover and backlog for next phase | Project lead | Closure report |

### Milestones
| Milestone | Date | Gate |
|---|---|---|
| M1 Foundations ready | End Week 1 | Board, inventory, templates live |
| M2 Baseline approved | End Week 2 | Sponsor sign-off |
| M3 Pilot automation live | End Week 3 | Daily report generated on pilot hosts |
| M4 Closure | End Week 4 | KPI report and handover |

---

# Team Coordination Strategy

## Task Delegation
- **Ownership:** every task has exactly one named owner and a due date on the board.
- **Matching:** assign by skill and growth need: new members pair with a buddy for their first two weeks.
- **Definition of done:** output documented, peer-reviewed by one other member, linked on the board.
- **WIP limit:** max 3 items "Doing" per person to avoid overload.
- **Priority rule:** P1 security / outage > P2 blocked users > P3 planned project work > P4 improvements.

## Daily Sync Protocol (15 minutes, same time daily)
1. Yesterday: what was completed (one sentence each).
2. Today: top 1-3 tasks.
3. Blockers: raised immediately; resolved offline, not in the stand-up.
4. Security / incident watch: any alerts or anomalies from the daily log report.

Async fallback: written update in the team channel by a fixed time for anyone absent. Weekly: 30-minute review of KPIs, risks and the board. Decisions and actions are recorded in a shared log.

## Escalation Procedure (project/work blockers)
| Level | Trigger | Who | Time limit |
|---|---|---|---|
| L0 | Task blocked | Owner tries to resolve, asks buddy | 2 hours |
| L1 | Still blocked | Project lead | Same day |
| L2 | Cross-team / resource issue or schedule risk >2 days | IT Operations Manager | 1 business day |
| L3 | Security incident, data exposure, major outage | Security lead + Sponsor immediately | Immediate |

## Communication Rules
- Single source of truth: the task board and wiki; no decisions only in private chats.
- Use ticket IDs in every message about an issue.
- Urgent issues by phone/call, not just chat.
- Blameless retrospectives: focus on process, not people.

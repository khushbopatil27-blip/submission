# Secure & Automated IT Operations Workflow - Submission Package

| File | Deliverable |
|---|---|
| `Executive_Summary_Project_Proposal.pdf` | Executive summary & project proposal (2 pages): scope, risks/compliance, KPIs |
| `01_Project_Roadmap.md` | Project charter, 4-week timeline, team coordination strategy |
| `02_Security_Awareness_and_Baseline_Policy.md` | Security awareness guide, Linux (Ubuntu/Kali) and Windows baseline policy, audit schedule |
| `03_Troubleshooting_and_Escalation_Matrix.md` | Ticket and security-incident process maps, SLAs, escalation/RACI matrix |
| `automation/` | Python/SQL log-analysis proof of concept, `README.md` with run instructions, sample data and sample reports |

Quick run: `cd automation && python3 log_analyzer.py --log sample_data/auth.log --year 2026 --users sample_data/system_users.csv --approved sample_data/approved_users.csv --today 2026-10-29 --out reports`

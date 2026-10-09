# Security Monitor — Design Spec

**Date:** 2026-10-10
**Status:** Approved (section-by-section, via brainstorming session)
**Supersedes:** `security_monitor_v15.0.py`, `security_monitoring_system_v15.0.py` (both deleted)

## 1. Goal

Turn the existing v15.0 security monitor scripts into a professional, cross-platform (Windows + Linux), repo-ready tool that:

- Detects blacklisted software against the installed-software inventory.
- Optionally enforces (kill processes / stop services) — **opt-in only**.
- Emails SOC-style reports (configurable: always / on-violations / never).
- Runs as a one-file EXE (`security-monitor.exe`) from Windows Task Scheduler, or from cron on Linux.
- Ships with a clean README, build/scheduling scripts, tests, and a public GitHub repo.

## 2. Confirmed Decisions

| # | Decision | Choice |
|---|----------|--------|
| 1 | Base code | Fresh merged script of both v15.0 files; best parts of each |
| 2 | Platform support | Windows **and** Linux |
| 3 | Configuration | `config.ini` **plus** interactive `--setup` wizard; scheduled runs read file silently |
| 4 | Default behavior | **Report-only.** Enforcement requires `enforce = true` or `--enforce` |
| 5 | Git target | New **public** GitHub repo `security-monitor`, created via `gh` CLI, pushed |
| 6 | Distributable | PyInstaller **one-file** EXE; reproducible via included build script |
| 7 | Email behavior | `[email] mode = always \| violations \| never`, default `violations` |
| 8 | Default org name | `company_name = Cyber Sujon` |
| 9 | License | MIT |

## 3. Architecture & Repository Layout

Modular package; each module has one responsibility.

```
security-monitor/
├── security_monitor/          # Python package
│   ├── __init__.py            # __version__
│   ├── __main__.py            # python -m security_monitor
│   ├── cli.py                 # argparse: --setup, --enforce, --dry-run, --no-email,
│   │                          #          --verbose, --config, --test-email
│   ├── config.py              # config.ini load/save/validation + setup wizard
│   ├── scanner.py             # blacklist loading, matching, risk levels (pure logic)
│   ├── enforcement.py         # process/service termination (opt-in)
│   ├── reporter.py            # report text build, file save, retention purge
│   ├── emailer.py             # SMTP send + attachment + test-email
│   ├── sysinfo.py             # host/user/OS/CPU/RAM/disk/uptime collection
│   └── platforms.py           # OS adapters: Windows winreg / Linux dpkg+rpm
├── tests/                     # pytest for pure logic (no live SMTP/registry)
├── scripts/
│   ├── build.ps1              # PyInstaller onefile (Windows)
│   ├── build.sh               # PyInstaller onefile (Linux)
│   └── register-task.ps1      # Task Scheduler registration
├── blacklist_software.txt     # default blacklist (shipped, user-editable)
├── config.example.ini         # committed template; real config.ini gitignored
├── requirements.txt           # runtime: psutil
├── requirements-dev.txt       # pytest, pyinstaller
├── .gitignore
├── LICENSE                    # MIT
└── README.md
```

- Runtime artifacts created next to the EXE/script and **gitignored**: `config.ini`, `logs/`, `reports/`.
- Dependencies: **psutil only** (config via stdlib `configparser`; `python-dotenv`, `argparse`, `smtplib` are stdlib/existing).

## 4. Configuration

`config.ini` sections:

```ini
[email]
mode = violations          ; always | violations | never (default: violations)
sender = you@gmail.com
recipients = soc@example.com, boss@example.com   ; comma-separated, multiple
app_password =             ; provider app password, not the login password
smtp_server = smtp.gmail.com
smtp_port = 587

[org]
company_name = Cyber Sujon
department = SOC

[scan]
enforce = false            ; opt-in enforcement
retention_days = 30        ; purge old logs/reports after N days
blacklist_file = blacklist_software.txt
```

**`--setup` wizard:** prompts each field in order (Enter accepts default); validates as it goes; offers an end-of-wizard **send-test-email** step so bad credentials fail at setup, not during a scheduled run; writes `config.ini` only after validation. `--config <path>` supports multiple profiles.

**Validation:** port is int; `mode`/`enforce` enums; addresses contain `@`; `app_password` non-empty when `mode != never`.

**Missing config:** run prints "Run security-monitor --setup first" and exits `1` — never a half-configured silent run.

**Security note (documented in README):** app password stored plain-text; recommend NTFS ACLs / `chmod 600`. Credential-store integration explicitly out of scope.

## 5. Scanning & Platform Adapters

`platforms.py` interface: `list_installed_software() -> list[dict]` with keys `name, version, publisher, install_date, install_location`.

| OS | Source |
|----|--------|
| Windows | `winreg` — HKLM 64-bit, HKLM WOW6432Node, HKCU Uninstall keys |
| Linux | `dpkg-query -l` and/or `rpm -qa` — whichever exists; parses name/version/vendor |

`scanner.py` (pure, OS-independent):

- Loads blacklist from configured path; case-insensitive substring match against installed names.
- Risk levels `HIGH`/`MEDIUM`/`LOW` keyword lists defined once in `scanner.py`.
- Guardrails: blacklist terms shorter than 3 chars skipped; duplicate software across registry hives deduped; never crash on partial data.

`sysinfo.py`: same report fields as today; disk path correctly per-OS (`C:\` vs `/`).

## 6. Enforcement & Safety (opt-in)

Active only when `enforce = true` **or** `--enforce`; `--dry-run` forces report-only regardless (CLI wins).

Order: services first (Windows `psutil.win_service_iter()` + `sc stop` fallback; Linux `systemctl stop` when present), then processes (match name/exe/cmdline; `terminate()` → 5s → `kill()`).

Safety rules:

- **Protect-list** excludes critical processes even on blacklist match: `csrss`, `smss`, `wininit`, `services`, `lsass`, `systemd`, `init`, etc.
- **Self-protection:** monitor's own PID and children exempt (PyInstaller bootloader child must not be killed).
- Errors (AccessDenied, NoSuchProcess) logged, never crash the run.
- Enforcement counts feed the report summary.

**Exit codes:** `0` clean, `1` fatal error, `2` completed with violations found.

## 7. Reporting & Email

`reporter.py`:

- Plain-text report: org, host info, enforcement summary, violation details (name/risk/version/publisher/location/matched term), recommended actions.
- **Emoji stripped** from report file and email subject (plain ASCII subjects — avoids Outlook garbling); console output plain too.
- Saved to `reports/security_report_<timestamp>.txt`; logs to `logs/security_monitor_<timestamp>.log`.
- **Retention:** files older than `retention_days` purged each run.

`emailer.py` — driven by the `[email] mode` setting (referenced as "email mode" below):

| mode | behavior |
|------|----------|
| `always` | send every run, including clean status |
| `violations` (default) | send only if violations > 0 **or** enforcement acted **or** scan errored |
| `never` | no email; logs only |

- Report attached; multiple recipients comma-expanded.
- STARTTLS (587) default; `smtp_port = 465` switches to SMTPS automatically.
- SMTP failure never fails the scan (warning + exit code reflects scan only). `--test-email` sends a ping and exits non-zero on failure.

## 8. Build, Scheduling, Repo

**Build:** `build.ps1` / `build.sh` → PyInstaller `--onefile --name security-monitor`; console kept (visible for `--setup`); deps pinned in `requirements-dev.txt`.

**Windows scheduling:** `register-task.ps1` registers "Security Monitor Daily" (default 09:00, `-Time` param) running `security-monitor.exe --config <path>`, `/RU` current user (run whether logged on or not), `-RunLevel Highest` (needed for HKLM reads + termination). Prints verification line. README documents the manual GUI path too.

**Linux scheduling:** README cron example: `0 9 * * * /path/security-monitor --config ...`.

**Repo hygiene:**

- Delete both legacy scripts; `git init` on `main`; initial commit; `gh repo create security-monitor --public --source=. --push`.
- `.gitignore`: `config.ini`, `logs/`, `reports/`, `dist/`, `build/`, `*.spec`, `__pycache__/`, `.pytest_cache/`, `.venv/`.
- **README:** overview, install (pip / prebuilt EXE), `--setup` walkthrough incl. Gmail app-password steps, scheduling (Task Scheduler + cron), config reference table, CLI flags, exit codes, security notes, MIT license, authorized-use disclaimer.

## 9. Testing

`pytest` covering pure logic only (no live SMTP, no real registry/systemd):

- Config: parsing, validation rules, defaults, missing-field errors.
- Scanner: substring matching, short-term skip, dedupe, risk-level classification.
- Reporter: report content contains violations/summary; clean-report path; retention purge logic (tmp dirs).
- Emailer: message construction + recipient expansion (mock SMTP), mode gating (never/always/violations).
- CLI: exit codes 0/1/2, missing-config behavior.

Manual verification checklist (documented in plan): real `--setup` run, `--test-email`, dry-run scan on Windows, EXE build + Task Scheduler registration.

## 10. Out of Scope

- Credential stores (Windows Credential Manager / keyring).
- Notification backends beyond email (webhook/Slack).
- GUI beyond the console wizard.
- Non-`.deb`/`.rpm` Linux package formats (e.g., Alpine/apk) — adapter interface allows adding later.
- Code signing of the EXE.

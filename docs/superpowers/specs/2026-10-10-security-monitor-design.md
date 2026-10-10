# Security Monitor — Design Spec

**Date:** 2026-10-10 (rev. 2 — portable EXE installer/manager model)
**Status:** Revision in progress after user review of rev. 1
**Supersedes:** `security_monitor_v15.0.py`, `security_monitoring_system_v15.0.py` (both deleted)

## 1. Goal

Turn the existing v15.0 security monitor scripts into a professional, cross-platform (Windows + Linux) tool delivered as a **portable EXE that installs and manages itself**:

- Detects blacklisted software against the installed-software inventory.
- Optionally enforces (kill processes / stop services) — **opt-in only**.
- Emails SOC-style reports (configurable: always / on-violations / never).
- **Windows install flow:** running the portable EXE deploys a full copy to `C:\Security Monitor\`, registers a Task Scheduler task that scans **at every boot and every N hours**, and manages that task from an interactive menu (create / notify / overwrite / uninstall).
- **Linux flow:** script runs directly with a cron entry (documented in README).
- Ships with a clean README, build scripts, tests, and a public GitHub repo.

## 2. Confirmed Decisions

| # | Decision | Choice |
|---|----------|--------|
| 1 | Base code | Fresh merged script of both v15.0 files; best parts of each |
| 2 | Platform support | Windows **and** Linux (EXE/menu is Windows-only; Linux uses script + cron) |
| 3 | Configuration | `config.ini` **plus** interactive wizard; silent runs read the file |
| 4 | Default behavior | **Report-only.** Enforcement requires `enforce = true` or `--enforce` |
| 5 | Git target | New **public** GitHub repo `security-monitor`, created via `gh` CLI, pushed |
| 6 | Distributable | PyInstaller **one-file** EXE; reproducible via included build script |
| 7 | Email behavior | `[email] mode = always \| violations \| never`, default `violations` |
| 8 | Default org name | `company_name = Cyber Sujon` |
| 9 | License | MIT |
| 10 | Installed payload | EXE **self-copy**: `C:\Security Monitor\security-monitor.exe` + `config.ini` + `blacklist_software.txt` + `logs/` + `reports/` — no Python needed on target |
| 11 | Task trigger | **At boot + repetition every N hours** (`interval_hours`, default 4) |
| 12 | EXE interface | Full manager menu: Install/configure, Status, Change settings, Run scan now, Uninstall, Exit |

## 3. Architecture & Repository Layout

Modular package; each module has one responsibility.

```
security-monitor/
├── security_monitor/          # Python package
│   ├── __init__.py            # __version__
│   ├── __main__.py            # python -m security_monitor
│   ├── cli.py                 # mode dispatcher: menu (default interactive), --run (silent
│   │                          #   scan for the task), --setup, --status, --uninstall,
│   │                          #   --enforce/--dry-run/--no-email/--verbose/--config/--test-email
│   ├── menu.py                # interactive console manager (Windows)
│   ├── installer.py           # deploy/repair C:\Security Monitor self-copy, uninstall
│   ├── task.py                # Task Scheduler lifecycle: create/overwrite/query/delete
│   ├── config.py              # config.ini load/save/validation + setup wizard
│   ├── scanner.py             # blacklist loading, matching, risk levels (pure logic)
│   ├── enforcement.py         # process/service termination (opt-in)
│   ├── reporter.py            # report text build, file save, retention purge
│   ├── emailer.py             # SMTP send + attachment + test-email
│   ├── sysinfo.py             # host/user/OS/CPU/RAM/disk/uptime collection
│   └── platforms.py           # OS adapters: Windows winreg / Linux dpkg+rpm
├── tests/                     # pytest for pure logic (no live SMTP/registry/scheduler)
├── scripts/
│   ├── build.ps1              # PyInstaller onefile (Windows, uac_admin manifest)
│   └── build.sh               # PyInstaller onefile (Linux)
├── blacklist_software.txt     # default blacklist (shipped, user-editable)
├── config.example.ini         # committed template; real config.ini gitignored
├── requirements.txt           # runtime: psutil
├── requirements-dev.txt       # pytest, pyinstaller
├── .gitignore
├── LICENSE                    # MIT
└── README.md
```

- Runtime artifacts (`config.ini`, `logs/`, `reports/`) live **in `C:\Security Monitor\` on Windows after install** (or next to the script on Linux), and are gitignored.
- Dependencies: **psutil only** (stdlib `configparser`, `smtplib`, `argparse`).
- `scripts/register-task.ps1` from rev. 1 is **dropped** — task lifecycle moves into the EXE (`task.py`).

## 4. Operating Modes

| Mode | Invocation | Purpose |
|------|-----------|---------|
| **Menu** (default, Windows, interactive) | double-click portable EXE | manager: install / status / settings / scan now / uninstall. Once installed, the menu always operates on `C:\Security Monitor\` (its config, task, and logs) — whether launched from the portable copy or the installed one |
| **Silent scan** | task runs `C:\Security Monitor\security-monitor.exe --run` | scheduled scan; no prompts; console window never shown (task runs as SYSTEM) |
| **Setup wizard** | `--setup` | non-menu prompt-based config (also reachable from menu option 1) |
| **Headless flags** | `--run --enforce --config ...` | advanced/manual use, Linux cron |

If no arguments on a non-Windows OS: run a scan (menu doesn't exist there). Missing `config.ini` in silent mode: log error, exit `1`, never a half-configured run.

## 5. Windows Install & Task Lifecycle

**Install (menu option 1 / first run):**

1. Request admin (EXE built with `uac_admin` manifest — required for `C:\` write + task registration).
2. Create `C:\Security Monitor\`.
3. Run setup wizard (email fields, org, enforce, interval, email mode) → writes `config.ini` directly into `C:\Security Monitor\`.
4. Copy the portable EXE itself into it as `security-monitor.exe`, plus `blacklist_software.txt`.
5. Register the task (see below). Notify: `✔ Scheduled task "Security Monitor" created — runs at boot and every 4h.`

**Task definition (`task.py` — via `schtasks /Create /XML`, generated XML):**

- Name: `Security Monitor`.
- Principal: **`SYSTEM`, highest privileges** (always available at boot, no stored user password, full HKLM/process rights; report `username` shows `SYSTEM` for scheduled runs — documented).
- Trigger 1: `AtStartup`; Trigger 2: `Once` (today) with `Repetition/Interval = PTnH` (from `interval_hours`).
- Action: `C:\Security Monitor\security-monitor.exe --run`.
- No visible window (SYSTEM session).

**Status (menu option 2):** task present? next run time? config valid? last scan result (newest `reports/` file) + last exit code.

**Change settings (menu option 3):** edit config fields in-place; if `interval_hours` (or install path) changed → task XML regenerated and **re-registered** (`schtasks /Delete` + `/Create /XML` or `/Create /F` overwrite). Notify: `✔ Task "Security Monitor" updated.` If task missing → re-create it and say so.

**Already-installed check:** if task already exists on install attempt → notify `ℹ Task "Security Monitor" already exists — choose option 3 to update it.` (no silent duplicate).

**Uninstall (menu option 5):** delete task, confirm, then remove `C:\Security Monitor\` (portable EXE survives wherever it is). Notify each step.

**Linux:** no installer/task — `python -m security_monitor --run` + cron line in README (from rev. 1 §8).

## 6. Configuration

`config.ini` (in `C:\Security Monitor\` on Windows; beside script on Linux):

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
interval_hours = 4         ; task repetition (Windows); cron hint on Linux
retention_days = 30        ; purge old logs/reports after N days
blacklist_file = blacklist_software.txt
```

**Validation:** port is int; `mode`/`enforce` enums; `interval_hours` int 1–24; addresses contain `@`; `app_password` non-empty when `mode != never`. Setup wizard offers end-of-wizard **send-test-email** so bad credentials fail at setup, not at 3am. `--config <path>` supports multiple profiles.

**Security note (README):** app password stored plain-text in `C:\Security Monitor\config.ini` (ACL-recommended); credential stores out of scope.

## 7. Scanning & Platform Adapters

`platforms.py` interface: `list_installed_software() -> list[dict]` with keys `name, version, publisher, install_date, install_location`.

| OS | Source |
|----|--------|
| Windows | `winreg` — HKLM 64-bit, HKLM WOW6432Node, HKCU Uninstall keys |
| Linux | `dpkg-query -l` and/or `rpm -qa` — whichever exists; parses name/version/vendor |

`scanner.py` (pure, OS-independent):

- Loads blacklist from configured path; case-insensitive substring match against installed names.
- Risk levels `HIGH`/`MEDIUM`/`LOW` keyword lists defined once in `scanner.py`.
- Guardrails: blacklist terms shorter than 3 chars skipped; duplicates across registry hives deduped; never crash on partial data.

`sysinfo.py`: same report fields as today; disk path correctly per-OS (`C:\` vs `/`).

## 8. Enforcement & Safety (opt-in)

Active only when `enforce = true` **or** `--enforce`; `--dry-run` forces report-only regardless (CLI wins).

Order: services first (Windows `psutil.win_service_iter()` + `sc stop` fallback; Linux `systemctl stop` when present), then processes (match name/exe/cmdline; `terminate()` → 5s → `kill()`).

Safety rules:

- **Protect-list** excludes critical processes even on blacklist match: `csrss`, `smss`, `wininit`, `services`, `lsass`, `systemd`, `init`, etc.
- **Self-protection:** monitor's own PID and children exempt (PyInstaller bootloader child must not be killed).
- Errors (AccessDenied, NoSuchProcess) logged, never crash the run.
- Enforcement counts feed the report summary.

**Exit codes:** `0` clean, `1` fatal error, `2` completed with violations found.

## 9. Reporting & Email

`reporter.py`:

- Plain-text report: org, host info, enforcement summary, violation details (name/risk/version/publisher/location/matched term), recommended actions.
- **Emoji stripped** from report file and email subject (plain ASCII — avoids Outlook garbling).
- Saved to `reports/security_report_<timestamp>.txt`; logs to `logs/security_monitor_<timestamp>.log`.
- **Retention:** files older than `retention_days` purged each run.

`emailer.py` — `[email] mode`:

| mode | behavior |
|------|----------|
| `always` | send every run, including clean status |
| `violations` (default) | send only if violations > 0 **or** enforcement acted **or** scan errored |
| `never` | no email; logs only |

- Report attached; multiple recipients comma-expanded.
- STARTTLS (587) default; `smtp_port = 465` switches to SMTPS automatically.
- SMTP failure never fails the scan (warning only). `--test-email` sends a ping and exits non-zero on failure.

## 10. Build & Repo

**Build:** `build.ps1` → PyInstaller `--onefile --name security-monitor --uac-admin`; `build.sh` mirrors for Linux (no UAC). Console kept for menu; scheduled runs are windowless by virtue of the SYSTEM principal. Deps pinned in `requirements-dev.txt`.

**Repo hygiene:**

- Delete both legacy scripts; branch `main`; commit history grows from the rev. 1 spec commit; `gh repo create security-monitor --public --source=. --push`.
- `.gitignore`: `config.ini`, `logs/`, `reports/`, `dist/`, `build/`, `*.spec`, `__pycache__/`, `.pytest_cache/`, `.venv/`.
- **README:** overview, install (pip / prebuilt EXE), **menu walkthrough**, setup-wizard incl. Gmail app-password steps, what the task does (boot + interval, SYSTEM), Linux cron, config reference table, CLI flags, exit codes, security notes (SYSTEM context, plain-text password), MIT license, authorized-use disclaimer.

## 11. Testing

`pytest` covering pure logic only (no live SMTP/registry/scheduler):

- Config: parsing, validation rules, defaults, missing-field errors.
- Scanner: substring matching, short-term skip, dedupe, risk-level classification.
- Reporter: report content contains violations/summary; clean-report path; retention purge (tmp dirs).
- Emailer: message construction + recipient expansion (mock SMTP), mode gating (never/always/violations).
- Task XML: generated XML contains expected triggers/interval/action/principal (string/XML assertions, no actual registration).
- CLI/menu: exit codes 0/1/2, missing-config behavior, menu routing (non-interactive input piping).

Manual verification checklist (in implementation plan): real wizard run, `--test-email`, dry-run scan on Windows, EXE build, install → verify task in `schtasks /Query`, settings change → verify task overwritten, uninstall → task + folder gone.

## 12. Out of Scope

- Credential stores (Windows Credential Manager / keyring).
- Notification backends beyond email (webhook/Slack).
- GUI beyond the console menu/wizard.
- Non-`.deb`/`.rpm` Linux package formats — adapter interface allows adding later.
- Code signing of the EXE (documented as SmartScreen caveat in README).
- Remote/multi-machine deployment (single-host tool).

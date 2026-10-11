# Security Monitor

Blacklist-based software monitoring for Windows and Linux: detects unauthorized
programs, optionally terminates them, and emails SOC-style reports. On Windows it
ships as a portable EXE that installs itself, registers a Task Scheduler job
(at boot + every N hours), and manages that job from an interactive menu.

> For authorized systems only. Enforcement mode terminates processes and stops
> services — review the blacklist and defaults before enabling it.

## Features

- Installed-software inventory: Windows registry (HKLM/HKCU uninstall keys),
  Linux `dpkg`/`rpm`
- Case-insensitive blacklist matching with HIGH/MEDIUM/LOW risk classification
- **Report-only by default** — enforcement is opt-in (`enforce = true` / `--enforce`)
- Email reports: `always`, on `violations` (default), or `never`
- Portable Windows EXE: self-installs to `C:\Security Monitor\`, interactive menu
  for install / status / settings / scan-now / uninstall, task auto-overwrite on change
- Boot + interval scheduled scanning as SYSTEM, windowless
- Log/report retention cleanup, exit codes for automation (0/1/2)

## Requirements

- Python 3.10+ (source runs) **or** the built EXE (no Python needed)
- `psutil` (only runtime dependency)
- Windows 10/11 or a modern Linux (dpkg- or rpm-based)

## Quick start (Windows, EXE)

1. Build the EXE (or use a released build):
   ```powershell
   powershell -ExecutionPolicy Bypass -File scripts\build.ps1
   ```
2. Double-click `dist\security-monitor.exe` (accept the UAC prompt).
3. Choose `1) Install / configure`:
   - the setup wizard asks for **sender email, recipients, app password**,
     SMTP server/port, organization, enforcement, scan interval, retention
   - a **test email** is sent before anything is saved
   - files are copied to `C:\Security Monitor\` and the scheduled task
     `Security Monitor` is created — the menu confirms:
     `✔ Scheduled task "Security Monitor" created — runs at boot and every 4h.`
4. If the task already exists you are told:
   `ℹ Task "Security Monitor" already exists — choose option 3 to update it.`
5. Changing the interval (or re-creating a missing task) overwrites the task:
   `✔ Task "Security Monitor" updated.`

### Gmail app password

Google requires 2-Step Verification, then:
**Google Account → Security → 2-Step Verification → App passwords → Mail → Generate**.
Paste the 16-character password into `app_password`. Your normal login password
will not work.

### Menu reference

| Option | Action |
|--------|--------|
| 1 | Install / configure (wizard + task registration) |
| 2 | Status (config validity, task present, next/last run, last report) |
| 3 | Change settings (re-runs wizard; overwrites the task when the interval changed) |
| 4 | Run scan now |
| 5 | Uninstall (removes the task and `C:\Security Monitor\`) |
| 0 | Exit |

### The scheduled task

| Property | Value |
|----------|-------|
| Name | `Security Monitor` |
| Triggers | At system startup + repetition every `interval_hours` (default 4) |
| Runs as | `SYSTEM`, highest privileges, no visible window |
| Action | `C:\Security Monitor\security-monitor.exe --run --config "C:\Security Monitor\config.ini"` |

Verify manually: `schtasks /Query /TN "Security Monitor" /FO LIST /V`
(task status parsing assumes an English display language).

## CLI usage

```text
security-monitor                 # Windows: open menu; Linux: run a scan
security-monitor --run           # silent scan (what the task executes)
security-monitor --setup         # prompt-based configuration wizard
security-monitor --status        # config + task + last report overview
security-monitor --test-email    # send a test email (exit 1 on failure)
security-monitor --uninstall     # Windows: remove task + installed files (asks to confirm)
security-monitor --enforce       # enforcement for this run (the flag alone is enough; config enforce=true also works)
security-monitor --dry-run       # report-only, even if enforcement is enabled
security-monitor --no-email      # never send email for this run
security-monitor --verbose       # debug logging
security-monitor --config PATH   # use a specific config file (multiple profiles)
```

Exit codes: `0` clean run · `1` error (bad config, fatal failure) · `2` completed with violations.

## Configuration (`config.ini`)

Created by `--setup` / menu option 1. Template: [`config.example.ini`](config.example.ini).

| Key | Default | Description |
|-----|---------|-------------|
| `email.mode` | `violations` | `always` \| `violations` \| `never` |
| `email.sender` | — | From address |
| `email.recipients` | — | Comma-separated To addresses |
| `email.app_password` | — | Provider app password (never your login password) |
| `email.smtp_server` | `smtp.gmail.com` | SMTP host |
| `email.smtp_port` | `587` | `587` = STARTTLS, `465` = implicit SSL |
| `org.company_name` | `Cyber Sujon` | Report header |
| `org.department` | `SOC` | Report header |
| `scan.enforce` | `false` | Opt-in process/service termination |
| `scan.interval_hours` | `4` | Task repetition (1-24) |
| `scan.retention_days` | `30` | Purge logs/reports older than N days |
| `scan.blacklist_file` | `blacklist_software.txt` | One term per line, min 3 chars |

Relative paths resolve against the config file's folder.
Windows: `C:\Security Monitor\config.ini` · Linux: beside the script.

## Linux usage

```bash
python3 -m pip install -r requirements.txt
python3 -m security_monitor --setup
python3 -m security_monitor --run
```

Cron (daily 09:00):
```cron
0 9 * * * /usr/bin/python3 -m security_monitor --run --config "$HOME/.config/security-monitor/config.ini"
```

## Security notes

- The app password is stored in **plain text** in `config.ini`. Protect it:
  Windows `icacls` ACLs or `chmod 600 config.ini`. Credential stores are out of scope.
- Scheduled runs execute as **SYSTEM** — reports from task runs show `SYSTEM` as the username.
- Default is report-only. Enable `enforce` only where killing blacklisted
  software is desired; a protect-list shields critical system processes and the
  monitor itself.
- SmartScreen/Deflector may warn on unsigned EXEs (no code signing yet).
- Firewall/outbound: the tool needs SMTP egress (587/465).

## Development

```bash
python3 -m pip install -r requirements-dev.txt
python3 -m pytest -v
```

Layout: `security_monitor/` (package) · `tests/` (pytest suite) ·
`scripts/build.ps1|sh` (EXE) · `docs/superpowers/` (spec + plan).

## License

MIT — see [LICENSE](LICENSE).

# Security Monitor Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rebuild the two legacy v15.0 scripts into a professional, cross-platform `security-monitor` package whose portable Windows EXE installs itself to `C:\Security Monitor\`, registers/overwrites a boot+interval Task Scheduler task from an interactive menu, and scans blacklisted software with opt-in enforcement and configurable email reporting — shipped with tests, README, build scripts, and a public GitHub repo.

**Architecture:** Modular Python package (`security_monitor/`) with one-responsibility modules: config wizard/INI, pure scanner logic, per-OS software inventory adapters, opt-in enforcement, reporter, emailer, Task Scheduler XML lifecycle, installer, console menu, and a thin CLI dispatcher. PyInstaller onefile EXE (UAC manifest) doubles as installer, manager, and the scheduled scanner. Spec: `docs/superpowers/specs/2026-10-10-security-monitor-design.md` (rev. 2).

**Tech Stack:** Python ≥ 3.10 (local: 3.14.6), `psutil` (only runtime dep), stdlib `configparser`/`smtplib`/`argparse`, `pytest`, PyInstaller 6.x, `schtasks` (Windows task registration), `gh` CLI (repo push).

## Global Constraints

- Runtime dependencies: **`psutil` only** (no `python-dotenv`; config via stdlib `configparser`).
- Default config values: `mode = violations`, `enforce = false`, `interval_hours = 4`, `retention_days = 30`, `company_name = Cyber Sujon`, `department = SOC`, `smtp_server = smtp.gmail.com`, `smtp_port = 587`.
- Task name: `Security Monitor`. Install dir: `C:\Security Monitor`. Installed exe: `security-monitor.exe`.
- Exit codes: `0` clean, `1` fatal error, `2` completed with violations found.
- **No emoji** in report files or email subjects (plain ASCII). Console notifications keep `✔` / `ℹ` characters, exact strings from spec §5.
- Enforcement is opt-in only; `--dry-run` forces report-only even when `enforce = true`.
- Never commit: `config.ini`, `logs/`, `reports/`, `dist/`, `build/`, `*.spec`, secrets/app passwords.
- Windows-only modules (`task.py`, `installer.py`, `menu.py`) must import safely on Linux (guards are call-time, not import-time) so the full test suite passes on any OS.
- All commits use identity flags (no global git config on this machine):
  `git -c user.name="Sujon" -c user.email="sujon@users.noreply.github.com" commit -m "..."`
- Repo: public GitHub `security-monitor`, branch `main`, MIT license.
- Exact spec notification strings:
  - `✔ Scheduled task "Security Monitor" created — runs at boot and every {n}h.`
  - `ℹ Task "Security Monitor" already exists — choose option 3 to update it.`
  - `✔ Task "Security Monitor" updated.`

---

### Task 1: Repo scaffolding & legacy cleanup

**Files:**
- Create: `.gitignore`, `requirements.txt`, `requirements-dev.txt`, `LICENSE`, `config.example.ini`, `blacklist_software.txt`, `security_monitor/__init__.py`, `security_monitor/__main__.py`, `tests/__init__.py`
- Delete: `security_monitor_v15.0.py`, `security_monitoring_system_v15.0.py`

**Interfaces:**
- Produces: `security_monitor.__version__ == "1.0.0"`; repo-root `config.example.ini` and `blacklist_software.txt` (content is asserted equal to module constants by later tests); `python -m security_monitor` entry stub.

- [ ] **Step 1: Write scaffolding files**

`.gitignore`:
```gitignore
__pycache__/
*.py[cod]
.venv/
venv/
.pytest_cache/
dist/
build/
*.spec
config.ini
logs/
reports/
```

`requirements.txt`:
```text
psutil>=6.0
```

`requirements-dev.txt`:
```text
-r requirements.txt
pytest>=8.0
pyinstaller>=6.10
```

`security_monitor/__init__.py`:
```python
"""Security Monitor - blacklist software scanning, enforcement, and reporting."""

__version__ = "1.0.0"
```

`security_monitor/__main__.py`:
```python
import sys

from security_monitor.cli import main

if __name__ == "__main__":
    sys.exit(main())
```

`tests/__init__.py`: empty file.

`config.example.ini`:
```ini
# Security Monitor configuration - run 'security-monitor --setup' to create this file interactively
[email]
mode = violations
sender = sender@example.com
recipients = receiver@example.com
app_password =
smtp_server = smtp.gmail.com
smtp_port = 587

[org]
company_name = Cyber Sujon
department = SOC

[scan]
enforce = false
interval_hours = 4
retention_days = 30
blacklist_file = blacklist_software.txt
```

`blacklist_software.txt` (one term per line):
```text
nmap
wireshark
metasploit
burp suite
john the ripper
hashcat
aircrack
sqlmap
netcat
putty
teamviewer
anydesk
utorrent
bittorrent
limewire
kazaa
cheat engine
process hacker
keylogger
remote desktop
vnc
tor browser
proxifier
charles proxy
fiddler
```

`LICENSE`: standard MIT text with `Copyright (c) 2026 Cyber Sujon`.

- [ ] **Step 2: Delete legacy scripts**

Run:
```powershell
Remove-Item "security_monitor_v15.0.py", "security_monitoring_system_v15.0.py"
```

- [ ] **Step 3: Verify package imports**

Run: `python -c "import security_monitor; print(security_monitor.__version__)"`
Expected: `1.0.0`

(`python -m security_monitor` will fail until Task 12 — that's expected.)

- [ ] **Step 4: Commit**

```bash
git add -A
git -c user.name="Sujon" -c user.email="sujon@users.noreply.github.com" commit -m "chore: scaffold package, configs, and repo hygiene; remove legacy scripts"
```

---

### Task 2: Config module (`config.py`)

**Files:**
- Create: `security_monitor/config.py`
- Test: `tests/test_config.py`

**Interfaces:**
- Produces:
  - `class ConfigError(Exception)`
  - `@dataclass EmailConfig(mode, sender, recipients: list[str], app_password, smtp_server, smtp_port)`
  - `@dataclass OrgConfig(company_name, department)`
  - `@dataclass ScanConfig(enforce: bool, interval_hours: int, retention_days: int, blacklist_file: str)`
  - `@dataclass Config(email, org, scan)`
  - `DEFAULT_CONFIG_TEXT: str`, `validate_config(cfg) -> list[str]`, `load_config(path) -> Config` (raises `ConfigError`), `save_config(cfg, path) -> None` (mkdirs parents), `run_setup_wizard(config_path, *, input_fn=input, output_fn=print, test_email_fn=None) -> Config` (raises `ConfigError`).

- [ ] **Step 1: Write the failing tests**

`tests/test_config.py`:
```python
from pathlib import Path

import pytest

from security_monitor import config as cfgmod


def _valid_cfg() -> cfgmod.Config:
    cfg = cfgmod.Config()
    cfg.email.sender = "me@gmail.com"
    cfg.email.recipients = ["soc@example.com"]
    cfg.email.app_password = "abcd efgh ijkl mnop"
    return cfg


def test_example_file_matches_default_text():
    repo = Path(__file__).resolve().parent.parent
    example = (repo / "config.example.ini").read_text(encoding="utf-8")
    assert example.strip() == cfgmod.DEFAULT_CONFIG_TEXT.strip()


def test_save_and_load_roundtrip(tmp_path):
    path = tmp_path / "config.ini"
    cfg = _valid_cfg()
    cfg.scan.interval_hours = 6
    cfg.org.company_name = "Cyber Sujon"
    cfgmod.save_config(cfg, path)
    loaded = cfgmod.load_config(path)
    assert loaded.email.sender == "me@gmail.com"
    assert loaded.email.recipients == ["soc@example.com"]
    assert loaded.scan.interval_hours == 6
    assert loaded.org.company_name == "Cyber Sujon"


def test_load_missing_file_raises(tmp_path):
    with pytest.raises(cfgmod.ConfigError):
        cfgmod.load_config(tmp_path / "nope.ini")


def test_validate_defaults_to_valid():
    assert cfgmod.validate_config(_valid_cfg()) == []


def test_validate_rejects_bad_mode_and_interval():
    cfg = _valid_cfg()
    cfg.email.mode = "sometimes"
    cfg.scan.interval_hours = 99
    errors = cfgmod.validate_config(cfg)
    assert any("email.mode" in e for e in errors)
    assert any("interval_hours" in e for e in errors)


def test_validate_requires_credentials_when_emailing():
    cfg = cfgmod.Config()  # mode=violations, no sender/password
    errors = cfgmod.validate_config(cfg)
    assert any("sender" in e for e in errors)
    assert any("app_password" in e for e in errors)


def test_validate_never_mode_needs_no_credentials():
    cfg = cfgmod.Config()
    cfg.email.mode = "never"
    assert cfgmod.validate_config(cfg) == []


def test_load_invalid_file_raises(tmp_path):
    path = tmp_path / "config.ini"
    cfg = cfgmod.Config()  # mode=violations without credentials -> invalid
    cfgmod.save_config(cfg, path)
    with pytest.raises(cfgmod.ConfigError):
        cfgmod.load_config(path)


def test_wizard_writes_valid_config(tmp_path):
    answers = iter([
        "violations", "me@gmail.com", "a@b.com, c@d.com", "pw123",
        "smtp.gmail.com", "587", "Cyber Sujon", "SOC",
        "false", "4", "30", "blacklist_software.txt",
    ])
    out = []
    cfg = cfgmod.run_setup_wizard(
        tmp_path / "config.ini",
        input_fn=lambda: next(answers),
        output_fn=out.append,
        test_email_fn=lambda c: True,
    )
    assert (tmp_path / "config.ini").exists()
    assert cfg.email.sender == "me@gmail.com"
    assert cfg.email.recipients == ["a@b.com", "c@d.com"]
    assert any("Test email" in line for line in out)


def test_wizard_aborts_when_email_test_fails_and_user_declines(tmp_path):
    answers = iter([
        "violations", "me@gmail.com", "a@b.com", "pw123",
        "smtp.gmail.com", "587", "Cyber Sujon", "SOC",
        "false", "4", "30", "blacklist_software.txt",
        "n",  # "Save anyway?" -> no
    ])
    with pytest.raises(cfgmod.ConfigError):
        cfgmod.run_setup_wizard(
            tmp_path / "config.ini",
            input_fn=lambda: next(answers),
            output_fn=lambda *a, **k: None,
            test_email_fn=lambda c: False,
        )
    assert not (tmp_path / "config.ini").exists()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_config.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'security_monitor.config'`

- [ ] **Step 3: Write the implementation**

`security_monitor/config.py`:
```python
"""Configuration: config.ini load/save/validation and the interactive setup wizard."""

from __future__ import annotations

import configparser
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

VALID_MODES = ("always", "violations", "never")
VALID_ENFORCE = ("true", "false", "yes", "no", "1", "0")

DEFAULT_CONFIG_TEXT = """\
# Security Monitor configuration - run 'security-monitor --setup' to create this file interactively
[email]
mode = violations
sender = sender@example.com
recipients = receiver@example.com
app_password =
smtp_server = smtp.gmail.com
smtp_port = 587

[org]
company_name = Cyber Sujon
department = SOC

[scan]
enforce = false
interval_hours = 4
retention_days = 30
blacklist_file = blacklist_software.txt
"""


class ConfigError(Exception):
    """Raised when configuration is missing or invalid."""


@dataclass
class EmailConfig:
    mode: str = "violations"
    sender: str = ""
    recipients: list[str] = field(default_factory=list)
    app_password: str = ""
    smtp_server: str = "smtp.gmail.com"
    smtp_port: int = 587


@dataclass
class OrgConfig:
    company_name: str = "Cyber Sujon"
    department: str = "SOC"


@dataclass
class ScanConfig:
    enforce: bool = False
    interval_hours: int = 4
    retention_days: int = 30
    blacklist_file: str = "blacklist_software.txt"


@dataclass
class Config:
    email: EmailConfig = field(default_factory=EmailConfig)
    org: OrgConfig = field(default_factory=OrgConfig)
    scan: ScanConfig = field(default_factory=ScanConfig)


def _parse_bool(raw: str, default: bool) -> bool:
    value = raw.strip().lower()
    if value in ("true", "yes", "1"):
        return True
    if value in ("false", "no", "0"):
        return False
    return default


def validate_config(cfg: Config) -> list[str]:
    errors: list[str] = []
    if cfg.email.mode not in VALID_MODES:
        errors.append(f"email.mode must be one of: {', '.join(VALID_MODES)}")
    if not 1 <= cfg.scan.interval_hours <= 24:
        errors.append("scan.interval_hours must be between 1 and 24")
    if cfg.scan.retention_days < 1:
        errors.append("scan.retention_days must be at least 1")
    if not 1 <= cfg.email.smtp_port <= 65535:
        errors.append("email.smtp_port must be between 1 and 65535")
    if cfg.email.mode != "never":
        if "@" not in cfg.email.sender:
            errors.append("email.sender must be a valid email address")
        if not cfg.email.recipients:
            errors.append("email.recipients must contain at least one address")
        for recipient in cfg.email.recipients:
            if "@" not in recipient:
                errors.append(f"email.recipients contains invalid address: {recipient}")
        if not cfg.email.app_password:
            errors.append("email.app_password is required when mode is not 'never'")
    else:
        if cfg.email.sender and "@" not in cfg.email.sender:
            errors.append("email.sender must be a valid email address")
    if not cfg.scan.blacklist_file.strip():
        errors.append("scan.blacklist_file must not be empty")
    return errors


def load_config(path: str | Path) -> Config:
    config_path = Path(path)
    parser = configparser.ConfigParser()
    read = parser.read(config_path, encoding="utf-8")
    if not read:
        raise ConfigError(f"config not found: {config_path} - run --setup first")

    recipients_raw = parser.get("email", "recipients", fallback="")
    cfg = Config(
        email=EmailConfig(
            mode=parser.get("email", "mode", fallback="violations").strip().lower(),
            sender=parser.get("email", "sender", fallback="").strip(),
            recipients=[r.strip() for r in recipients_raw.split(",") if r.strip()],
            app_password=parser.get("email", "app_password", fallback=""),
            smtp_server=parser.get("email", "smtp_server", fallback="smtp.gmail.com").strip(),
            smtp_port=parser.getint("email", "smtp_port", fallback=587),
        ),
        org=OrgConfig(
            company_name=parser.get("org", "company_name", fallback="Cyber Sujon").strip(),
            department=parser.get("org", "department", fallback="SOC").strip(),
        ),
        scan=ScanConfig(
            enforce=_parse_bool(parser.get("scan", "enforce", fallback="false"), False),
            interval_hours=parser.getint("scan", "interval_hours", fallback=4),
            retention_days=parser.getint("scan", "retention_days", fallback=30),
            blacklist_file=parser.get("scan", "blacklist_file", fallback="blacklist_software.txt").strip(),
        ),
    )
    errors = validate_config(cfg)
    if errors:
        raise ConfigError(f"invalid config {config_path}: {'; '.join(errors)}")
    return cfg


def save_config(cfg: Config, path: str | Path) -> None:
    config_path = Path(path)
    config_path.parent.mkdir(parents=True, exist_ok=True)
    parser = configparser.ConfigParser()
    parser["email"] = {
        "mode": cfg.email.mode,
        "sender": cfg.email.sender,
        "recipients": ", ".join(cfg.email.recipients),
        "app_password": cfg.email.app_password,
        "smtp_server": cfg.email.smtp_server,
        "smtp_port": str(cfg.email.smtp_port),
    }
    parser["org"] = {
        "company_name": cfg.org.company_name,
        "department": cfg.org.department,
    }
    parser["scan"] = {
        "enforce": "true" if cfg.scan.enforce else "false",
        "interval_hours": str(cfg.scan.interval_hours),
        "retention_days": str(cfg.scan.retention_days),
        "blacklist_file": cfg.scan.blacklist_file,
    }
    with config_path.open("w", encoding="utf-8") as handle:
        handle.write("# Security Monitor configuration - run 'security-monitor --setup' to create this file interactively\n")
        parser.write(handle)


def _ask(
    input_fn: Callable[[], str],
    output_fn: Callable[..., None],
    label: str,
    default: str,
) -> str:
    if default:
        output_fn(f"{label} [{default}]")
    else:
        output_fn(f"{label}:")
    raw = input_fn().strip()
    return raw if raw else default


def run_setup_wizard(
    config_path: str | Path,
    *,
    input_fn: Callable[[], str] = input,
    output_fn: Callable[..., None] = print,
    test_email_fn: Callable[[Config], bool] | None = None,
) -> Config:
    config_path = Path(config_path)
    if config_path.exists():
        try:
            existing = load_config(config_path)
        except ConfigError:
            existing = Config()
    else:
        existing = Config()

    output_fn("--- Security Monitor setup ---")
    mode = _ask(input_fn, output_fn, "Email mode (always/violations/never)", existing.email.mode)
    sender = _ask(input_fn, output_fn, "Sender email address", existing.email.sender)
    recipients_raw = _ask(input_fn, output_fn, "Recipient addresses (comma-separated)", ", ".join(existing.email.recipients))
    app_password = _ask(input_fn, output_fn, "App password (not your login password)", existing.email.app_password)
    smtp_server = _ask(input_fn, output_fn, "SMTP server", existing.email.smtp_server)
    smtp_port_raw = _ask(input_fn, output_fn, "SMTP port", str(existing.email.smtp_port))
    company = _ask(input_fn, output_fn, "Organization name", existing.org.company_name)
    department = _ask(input_fn, output_fn, "Department", existing.org.department)
    enforce_raw = _ask(input_fn, output_fn, "Enable enforcement (true/false)", "true" if existing.scan.enforce else "false")
    interval_raw = _ask(input_fn, output_fn, "Scan interval hours (1-24)", str(existing.scan.interval_hours))
    retention_raw = _ask(input_fn, output_fn, "Report/log retention days", str(existing.scan.retention_days))
    blacklist = _ask(input_fn, output_fn, "Blacklist file", existing.scan.blacklist_file)

    try:
        smtp_port = int(smtp_port_raw)
        interval = int(interval_raw)
        retention = int(retention_raw)
    except ValueError as exc:
        raise ConfigError(f"setup failed: numeric field invalid ({exc})") from exc

    cfg = Config(
        email=EmailConfig(
            mode=mode.strip().lower(),
            sender=sender.strip(),
            recipients=[r.strip() for r in recipients_raw.split(",") if r.strip()],
            app_password=app_password,
            smtp_server=smtp_server.strip(),
            smtp_port=smtp_port,
        ),
        org=OrgConfig(company_name=company.strip(), department=department.strip()),
        scan=ScanConfig(
            enforce=_parse_bool(enforce_raw, False),
            interval_hours=interval,
            retention_days=retention,
            blacklist_file=blacklist.strip(),
        ),
    )

    errors = validate_config(cfg)
    if errors:
        for error in errors:
            output_fn(f"  ! {error}")
        raise ConfigError("setup validation failed - fix the fields above and rerun --setup")

    if test_email_fn is not None and cfg.email.mode != "never":
        output_fn("Sending test email...")
        try:
            ok = test_email_fn(cfg)
        except Exception as exc:  # noqa: BLE001 - wizard must never crash on SMTP errors
            output_fn(f"Test email failed: {exc}")
            ok = False
        if ok:
            output_fn("Test email sent successfully.")
        else:
            answer = _ask(input_fn, output_fn, "Test email failed. Save configuration anyway? (y/N)", "n")
            if answer.strip().lower() not in ("y", "yes"):
                raise ConfigError("setup aborted: test email failed and configuration was not saved")

    save_config(cfg, config_path)
    output_fn(f"Configuration saved to {config_path}")
    return cfg
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_config.py -v`
Expected: all PASS

- [ ] **Step 5: Commit**

```bash
git add security_monitor/config.py tests/test_config.py
git -c user.name="Sujon" -c user.email="sujon@users.noreply.github.com" commit -m "feat: config module with validation, persistence, and setup wizard"
```

---

### Task 3: Scanner module (`scanner.py`)

**Files:**
- Create: `security_monitor/scanner.py`
- Test: `tests/test_scanner.py`

**Interfaces:**
- Consumes: repo-root `blacklist_software.txt` (from Task 1).
- Produces: `MIN_TERM_LENGTH = 3`, `DEFAULT_BLACKLIST: list[str]`, `class ScannerError(Exception)`, `write_default_blacklist(path) -> Path`, `load_blacklist(path) -> list[str]` (lowercased, deduped, short terms dropped; raises `ScannerError` when missing), `risk_level(term) -> str` (`HIGH|MEDIUM|LOW`), `dedupe_software(software: list[dict]) -> list[dict]`, `match_violations(installed: list[dict], blacklist: list[str]) -> list[dict]` (keys: `name, version, publisher, install_date, install_location, matched_term, risk_level`).

- [ ] **Step 1: Write the failing tests**

`tests/test_scanner.py`:
```python
from pathlib import Path

import pytest

from security_monitor import scanner


def test_load_blacklist_skips_short_terms_and_dupes(tmp_path):
    path = tmp_path / "bl.txt"
    path.write_text("ab\nWireshark\nwireshark\nvnc\n", encoding="utf-8")
    assert scanner.load_blacklist(path) == ["wireshark", "vnc"]


def test_load_blacklist_missing_raises(tmp_path):
    with pytest.raises(scanner.ScannerError):
        scanner.load_blacklist(tmp_path / "missing.txt")


def test_write_default_blacklist_roundtrip(tmp_path):
    path = scanner.write_default_blacklist(tmp_path / "bl.txt")
    assert scanner.load_blacklist(path) == [t.lower() for t in scanner.DEFAULT_BLACKLIST]


def test_repo_blacklist_file_matches_defaults():
    repo = Path(__file__).resolve().parent.parent
    content = (repo / "blacklist_software.txt").read_text(encoding="utf-8")
    terms = [line.strip() for line in content.splitlines() if line.strip()]
    assert terms == scanner.DEFAULT_BLACKLIST


def test_risk_levels():
    assert scanner.risk_level("nmap") == "HIGH"
    assert scanner.risk_level("wireshark") == "MEDIUM"
    assert scanner.risk_level("utorrent") == "LOW"


def test_match_violations_finds_and_classifies():
    installed = [
        {"name": "Wireshark 4.2", "version": "4.2", "publisher": "WS",
         "install_date": "20240101", "install_location": "C:\\ws"},
    ]
    violations = scanner.match_violations(installed, ["wireshark", "vnc"])
    assert len(violations) == 1
    assert violations[0]["matched_term"] == "wireshark"
    assert violations[0]["risk_level"] == "MEDIUM"
    assert violations[0]["name"] == "Wireshark 4.2"


def test_match_violations_single_match_per_program():
    installed = [{"name": "Nmap Security Scanner", "version": "7", "publisher": "N",
                  "install_date": "?", "install_location": "?"}]
    violations = scanner.match_violations(installed, ["nmap", "map"])
    assert len(violations) == 1
    assert violations[0]["matched_term"] == "nmap"


def test_match_violations_no_match():
    assert scanner.match_violations([{"name": "Notepad++"}], ["vnc"]) == []


def test_dedupe_software_drops_same_name_version():
    same = {"name": "Putty", "version": "0.80"}
    other = {"name": "Putty", "version": "0.81"}
    result = scanner.dedupe_software([same, dict(same), other])
    assert result == [same, other]
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_scanner.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'security_monitor.scanner'`

- [ ] **Step 3: Write the implementation**

`security_monitor/scanner.py`:
```python
"""Blacklist loading, software matching, and risk classification (pure logic)."""

from __future__ import annotations

from pathlib import Path

MIN_TERM_LENGTH = 3

DEFAULT_BLACKLIST = [
    "nmap", "wireshark", "metasploit", "burp suite", "john the ripper",
    "hashcat", "aircrack", "sqlmap", "netcat", "putty", "teamviewer",
    "anydesk", "utorrent", "bittorrent", "limewire", "kazaa",
    "cheat engine", "process hacker", "keylogger", "remote desktop",
    "vnc", "tor browser", "proxifier", "charles proxy", "fiddler",
]

RISK_HIGH_TERMS = (
    "nmap", "metasploit", "burp suite", "john the ripper", "hashcat",
    "sqlmap", "cheat engine", "keylogger",
)
RISK_MEDIUM_TERMS = (
    "wireshark", "putty", "teamviewer", "anydesk", "process hacker",
    "vnc", "fiddler",
)


class ScannerError(Exception):
    """Raised when the blacklist cannot be loaded."""


def write_default_blacklist(path: str | Path) -> Path:
    blacklist_path = Path(path)
    blacklist_path.parent.mkdir(parents=True, exist_ok=True)
    blacklist_path.write_text("\n".join(DEFAULT_BLACKLIST) + "\n", encoding="utf-8")
    return blacklist_path


def load_blacklist(path: str | Path) -> list[str]:
    blacklist_path = Path(path)
    if not blacklist_path.exists():
        raise ScannerError(f"blacklist file not found: {blacklist_path}")
    terms: list[str] = []
    seen: set[str] = set()
    for line in blacklist_path.read_text(encoding="utf-8").splitlines():
        term = line.strip().lower()
        if len(term) >= MIN_TERM_LENGTH and term not in seen:
            seen.add(term)
            terms.append(term)
    return terms


def risk_level(term: str) -> str:
    lowered = term.lower()
    if any(risk in lowered for risk in RISK_HIGH_TERMS):
        return "HIGH"
    if any(risk in lowered for risk in RISK_MEDIUM_TERMS):
        return "MEDIUM"
    return "LOW"


def dedupe_software(software: list[dict]) -> list[dict]:
    seen: set[tuple[str, str]] = set()
    result: list[dict] = []
    for item in software:
        key = (str(item.get("name", "")).lower(), str(item.get("version", "")).lower())
        if key in seen:
            continue
        seen.add(key)
        result.append(item)
    return result


def match_violations(installed: list[dict], blacklist: list[str]) -> list[dict]:
    violations: list[dict] = []
    for software in installed:
        name = str(software.get("name") or "").lower()
        if not name:
            continue
        for term in blacklist:
            if term in name:
                violations.append(
                    {
                        "name": software.get("name", "Unknown"),
                        "version": software.get("version", "Unknown"),
                        "publisher": software.get("publisher", "Unknown"),
                        "install_date": software.get("install_date", "Unknown"),
                        "install_location": software.get("install_location", "Unknown"),
                        "matched_term": term,
                        "risk_level": risk_level(term),
                    }
                )
                break
    return violations
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_scanner.py -v`
Expected: all PASS

- [ ] **Step 5: Commit**

```bash
git add security_monitor/scanner.py tests/test_scanner.py
git -c user.name="Sujon" -c user.email="sujon@users.noreply.github.com" commit -m "feat: scanner module with blacklist loading, matching, and risk levels"
```

---

### Task 4: Platform adapters (`platforms.py`)

**Files:**
- Create: `security_monitor/platforms.py`
- Test: `tests/test_platforms.py`

**Interfaces:**
- Produces: `list_installed_software() -> list[dict]` (keys `name, version, publisher, install_date, install_location`; empty list on unsupported OS), `parse_dpkg_output(text) -> list[dict]`, `parse_rpm_output(text) -> list[dict]`.

- [ ] **Step 1: Write the failing tests**

`tests/test_platforms.py`:
```python
from security_monitor import platforms

REQUIRED_KEYS = {"name", "version", "publisher", "install_date", "install_location"}


def test_parse_dpkg_output_only_installed():
    text = (
        "bash\t5.1-2+deb12u1\tDebian Maintainer <maint@deb.org>\tinstall ok installed\n"
        "removed-pkg\t1.0\tX <x@x.com>\tdeinstall ok config-files\n"
        "half-installed\t2.0\tY <y@y.com>\tinstall ok half-configured\n"
    )
    result = platforms.parse_dpkg_output(text)
    assert len(result) == 1
    assert result[0]["name"] == "bash"
    assert result[0]["version"] == "5.1-2+deb12u1"
    assert "maint@deb.org" in result[0]["publisher"]
    assert REQUIRED_KEYS <= set(result[0])


def test_parse_dpkg_output_empty():
    assert platforms.parse_dpkg_output("") == []


def test_parse_rpm_output():
    text = "httpd\t2.4.57-1.el9\tRed Hat, Inc.\n"
    result = platforms.parse_rpm_output(text)
    assert len(result) == 1
    assert result[0]["name"] == "httpd"
    assert result[0]["version"] == "2.4.57-1.el9"
    assert result[0]["publisher"] == "Red Hat, Inc."
    assert REQUIRED_KEYS <= set(result[0])


def test_list_installed_software_returns_dicts_with_keys():
    result = platforms.list_installed_software()
    assert isinstance(result, list)
    for item in result:
        assert REQUIRED_KEYS <= set(item)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_platforms.py -v`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Write the implementation**

`security_monitor/platforms.py`:
```python
"""OS adapters: installed-software inventory (Windows registry, Linux dpkg/rpm)."""

from __future__ import annotations

import platform
import shutil
import subprocess

_REQUIRED = ("name", "version", "publisher", "install_date", "install_location")


def list_installed_software() -> list[dict]:
    system = platform.system()
    if system == "Windows":
        return _list_windows()
    if system == "Linux":
        return _list_linux()
    return []


def _list_windows() -> list[dict]:
    try:
        import winreg
    except ImportError:
        return []
    results: list[dict] = []
    registry_paths = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
    ]
    for hkey, subkey in registry_paths:
        try:
            with winreg.OpenKey(hkey, subkey) as root:
                for index in range(winreg.QueryInfoKey(root)[0]):
                    try:
                        with winreg.OpenKey(root, winreg.EnumKey(root, index)) as prog:
                            name = _reg_value(winreg, prog, "DisplayName")
                            if name == "Unknown":
                                continue
                            results.append(
                                {
                                    "name": name,
                                    "version": _reg_value(winreg, prog, "DisplayVersion"),
                                    "publisher": _reg_value(winreg, prog, "Publisher"),
                                    "install_date": _reg_value(winreg, prog, "InstallDate"),
                                    "install_location": _reg_value(winreg, prog, "InstallLocation"),
                                }
                            )
                    except OSError:
                        continue
        except OSError:
            continue
    return results


def _reg_value(winreg, key, value_name: str) -> str:
    try:
        raw = winreg.QueryValueEx(key, value_name)[0]
        text = str(raw).strip()
        return text if text else "Unknown"
    except (FileNotFoundError, OSError):
        return "Unknown"


def _list_linux() -> list[dict]:
    results: list[dict] = []
    if shutil.which("dpkg-query"):
        proc = subprocess.run(
            ["dpkg-query", "-W", "-f=${Package}\t${Version}\t${Maintainer}\t${Status}\n"],
            capture_output=True, text=True, check=False,
        )
        results.extend(parse_dpkg_output(proc.stdout))
    if not results and shutil.which("rpm"):
        proc = subprocess.run(
            ["rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\t%{VENDOR}\n"],
            capture_output=True, text=True, check=False,
        )
        results.extend(parse_rpm_output(proc.stdout))
    return results


def parse_dpkg_output(text: str) -> list[dict]:
    results: list[dict] = []
    for line in text.splitlines():
        parts = line.split("\t")
        if len(parts) < 4 or "installed" not in parts[3]:
            continue
        results.append(
            {
                "name": parts[0].strip(),
                "version": parts[1].strip() or "Unknown",
                "publisher": parts[2].strip() or "Unknown",
                "install_date": "Unknown",
                "install_location": "Unknown",
            }
        )
    return results


def parse_rpm_output(text: str) -> list[dict]:
    results: list[dict] = []
    for line in text.splitlines():
        parts = line.split("\t")
        if len(parts) < 2 or not parts[0].strip():
            continue
        results.append(
            {
                "name": parts[0].strip(),
                "version": parts[1].strip() or "Unknown",
                "publisher": (parts[2].strip() if len(parts) > 2 and parts[2].strip() else "Unknown"),
                "install_date": "Unknown",
                "install_location": "Unknown",
            }
        )
    return results
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_platforms.py -v`
Expected: all PASS (registry test runs real read-only scan on Windows; on Linux returns dpkg list or `[]`)

- [ ] **Step 5: Commit**

```bash
git add security_monitor/platforms.py tests/test_platforms.py
git -c user.name="Sujon" -c user.email="sujon@users.noreply.github.com" commit -m "feat: cross-platform installed-software adapters (winreg/dpkg/rpm)"
```

---

### Task 5: System info (`sysinfo.py`)

**Files:**
- Create: `security_monitor/sysinfo.py`
- Test: `tests/test_sysinfo.py`

**Interfaces:**
- Produces: `collect_system_info() -> dict` with keys `hostname, fqdn, username, ip_address, os_info, cpu_info, memory_total, memory_used, memory_available, memory_percent, domain, boot_time, uptime, disk_used, disk_total, scan_time`; returns `{}` on unexpected failure; never raises.

- [ ] **Step 1: Write the failing test**

`tests/test_sysinfo.py`:
```python
from security_monitor import sysinfo

EXPECTED_KEYS = [
    "hostname", "fqdn", "username", "ip_address", "os_info", "cpu_info",
    "memory_total", "memory_used", "memory_available", "memory_percent",
    "domain", "boot_time", "uptime", "disk_used", "disk_total", "scan_time",
]


def test_collect_system_info_has_all_keys():
    info = sysinfo.collect_system_info()
    for key in EXPECTED_KEYS:
        assert key in info, f"missing key: {key}"


def test_collect_system_info_never_raises(monkeypatch):
    monkeypatch.setattr(sysinfo.psutil, "boot_time", lambda: (_ for _ in ()).throw(RuntimeError("boom")))
    info = sysinfo.collect_system_info()
    assert info == {}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_sysinfo.py -v`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Write the implementation**

`security_monitor/sysinfo.py`:
```python
"""Host/user/OS/hardware information collection for reports."""

from __future__ import annotations

import getpass
import os
import platform
import socket
import time
from datetime import datetime

import psutil


def collect_system_info() -> dict:
    try:
        hostname = socket.gethostname()
        try:
            fqdn = socket.getfqdn()
        except OSError:
            fqdn = hostname
        try:
            username = getpass.getuser()
        except Exception:
            username = os.environ.get("USERNAME") or os.environ.get("USER") or "Unknown"

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.connect(("8.8.8.8", 80))
            ip_address = sock.getsockname()[0]
            sock.close()
        except OSError:
            ip_address = "Unable to determine"

        os_info = f"{platform.system()} {platform.release()} {platform.version()} ({platform.machine()})"

        cpu_count = psutil.cpu_count(logical=False) or psutil.cpu_count() or 1
        cpu_threads = psutil.cpu_count(logical=True) or cpu_count
        cpu_freq = psutil.cpu_freq()
        freq_text = f"{cpu_freq.current:.1f}MHz" if cpu_freq else "Unknown"
        cpu_info = f"{platform.processor()} ({cpu_count} cores, {cpu_threads} threads @ {freq_text})"

        memory = psutil.virtual_memory()

        boot_time = datetime.fromtimestamp(psutil.boot_time()).strftime("%Y-%m-%d %H:%M:%S")
        uptime_seconds = time.time() - psutil.boot_time()
        uptime = (
            f"{int(uptime_seconds // 86400)} days, "
            f"{int((uptime_seconds % 86400) // 3600)}:{int((uptime_seconds % 3600) // 60):02d}:00"
        )

        disk_path = os.environ.get("SystemDrive", "C:") + "\\" if platform.system() == "Windows" else "/"
        disk = psutil.disk_usage(disk_path)

        domain = os.environ.get("USERDOMAIN", "N/A")
        if domain == hostname:
            domain = "N/A"

        return {
            "hostname": hostname,
            "fqdn": fqdn,
            "username": username,
            "ip_address": ip_address,
            "os_info": os_info,
            "cpu_info": cpu_info,
            "memory_total": f"{memory.total / (1024 ** 3):.2f} GB",
            "memory_used": f"{memory.used / (1024 ** 3):.2f} GB",
            "memory_available": f"{memory.available / (1024 ** 3):.2f} GB",
            "memory_percent": f"{memory.percent:.1f}%",
            "domain": domain,
            "boot_time": boot_time,
            "uptime": uptime,
            "disk_used": f"{disk.used / (1024 ** 3):.2f} GB",
            "disk_total": f"{disk.total / (1024 ** 3):.2f} GB",
            "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }
    except Exception:
        return {}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_sysinfo.py -v`
Expected: all PASS

- [ ] **Step 5: Commit**

```bash
git add security_monitor/sysinfo.py tests/test_sysinfo.py
git -c user.name="Sujon" -c user.email="sujon@users.noreply.github.com" commit -m "feat: system information collection"
```

---

### Task 6: Enforcement (`enforcement.py`)

**Files:**
- Create: `security_monitor/enforcement.py`
- Test: `tests/test_enforcement.py`

**Interfaces:**
- Consumes: blacklist `list[str]` (from `scanner.load_blacklist`).
- Produces: `PROTECT_NAMES: frozenset[str]`, `is_protected(name) -> bool`, `process_matches(name, exe, cmdline, patterns) -> str | None`, `@dataclass EnforceResult(services_stopped: int = 0, processes_killed: int = 0)` with `.actioned` property, `enforce(blacklist, *, dry_run=False, logger=None) -> EnforceResult`, internal `_kill_matching_processes(patterns, dry_run, logger) -> int`, `_stop_matching_services(patterns, dry_run, logger) -> int`.

- [ ] **Step 1: Write the failing tests**

`tests/test_enforcement.py`:
```python
import logging
import os

from security_monitor import enforcement


class FakeProc:
    def __init__(self, info):
        self.info = info


def test_is_protected_names():
    assert enforcement.is_protected("csrss.exe")
    assert enforcement.is_protected("systemd")
    assert enforcement.is_protected("lsass")
    assert not enforcement.is_protected("Wireshark.exe")


def test_process_matches_returns_term():
    term = enforcement.process_matches(
        "Wireshark.exe", "C:\\Tools\\Wireshark\\Wireshark.exe", "", ["wireshark"]
    )
    assert term == "wireshark"


def test_process_matches_never_matches_protected():
    term = enforcement.process_matches(
        "lsass.exe", "C:\\Windows\\System32\\lsass.exe", "", ["lsass"]
    )
    assert term is None


def test_process_matches_checks_cmdline():
    term = enforcement.process_matches("python.exe", "", "python -m netcat.helper", ["netcat"])
    assert term == "netcat"


def test_enforce_empty_blacklist_returns_zero():
    result = enforcement.enforce([])
    assert result.services_stopped == 0
    assert result.processes_killed == 0
    assert not result.actioned


def test_kill_dry_run_logs_match_and_spares_protected(monkeypatch, caplog):
    fakes = [
        FakeProc({"pid": 999999999, "name": "Wireshark.exe", "exe": "C:\\ws\\Wireshark.exe", "cmdline": []}),
        FakeProc({"pid": 222, "name": "lsass.exe", "exe": "C:\\Windows\\lsass.exe", "cmdline": []}),
        FakeProc({"pid": os.getpid(), "name": "security-monitor.exe", "exe": "C:\\app\\security-monitor.exe", "cmdline": []}),
    ]
    monkeypatch.setattr(enforcement.psutil, "process_iter", lambda attrs: iter(fakes))
    logger = logging.getLogger("test_enforcement")
    with caplog.at_level(logging.INFO, logger="test_enforcement"):
        killed = enforcement._kill_matching_processes(["wireshark", "lsass"], dry_run=True, logger=logger)
    assert killed == 0
    text = caplog.text
    assert "[DRY-RUN] Would terminate" in text and "Wireshark.exe" in text
    assert "lsass.exe" not in text
    assert "security-monitor" not in text


def test_kill_skips_own_pid(monkeypatch, caplog):
    fakes = [FakeProc({"pid": os.getpid(), "name": "Wireshark.exe", "exe": "", "cmdline": []})]
    monkeypatch.setattr(enforcement.psutil, "process_iter", lambda attrs: iter(fakes))
    logger = logging.getLogger("test_enforcement")
    with caplog.at_level(logging.INFO, logger="test_enforcement"):
        enforcement._kill_matching_processes(["wireshark"], dry_run=True, logger=logger)
    assert "Would terminate" not in caplog.text
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_enforcement.py -v`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Write the implementation**

`security_monitor/enforcement.py`:
```python
"""Opt-in enforcement: stop matching services and terminate matching processes."""

from __future__ import annotations

import logging
import os
import platform
import subprocess
from dataclasses import dataclass
from pathlib import Path

import psutil

PROTECT_NAMES = frozenset(
    {
        "csrss", "csrss.exe", "smss", "smss.exe", "wininit", "wininit.exe",
        "winlogon", "winlogon.exe", "services", "services.exe", "lsass",
        "lsass.exe", "system", "registry", "idle", "init", "systemd",
        "kthreadd", "security-monitor.exe", "security-monitor",
    }
)


@dataclass
class EnforceResult:
    services_stopped: int = 0
    processes_killed: int = 0

    @property
    def actioned(self) -> bool:
        return self.services_stopped > 0 or self.processes_killed > 0


def is_protected(name: str) -> bool:
    return (name or "").strip().lower() in PROTECT_NAMES


def process_matches(name: str, exe: str, cmdline: str, patterns: list[str]) -> str | None:
    if is_protected(name) or is_protected(Path(exe).name if exe else ""):
        return None
    haystack = " ".join(part for part in (name or "", exe or "", cmdline or "") if part).lower()
    for pattern in patterns:
        if pattern in haystack:
            return pattern
    return None


def enforce(blacklist: list[str], *, dry_run: bool = False, logger: logging.Logger | None = None) -> EnforceResult:
    log = logger or logging.getLogger("security_monitor")
    result = EnforceResult()
    patterns = [p for p in blacklist if p]
    if not patterns:
        return result
    result.services_stopped = _stop_matching_services(patterns, dry_run, log)
    result.processes_killed = _kill_matching_processes(patterns, dry_run, log)
    log.info(
        "Enforcement finished: %d services stopped, %d processes terminated (dry_run=%s)",
        result.services_stopped, result.processes_killed, dry_run,
    )
    return result


def _stop_matching_services(patterns: list[str], dry_run: bool, log: logging.Logger) -> int:
    stopped = 0
    if platform.system() == "Windows":
        stopped += _stop_windows_services(patterns, dry_run, log)
    else:
        stopped += _stop_linux_services(patterns, dry_run, log)
    return stopped


def _stop_windows_services(patterns: list[str], dry_run: bool, log: logging.Logger) -> int:
    stopped = 0
    try:
        if not hasattr(psutil, "win_service_iter"):
            return 0
        for svc in psutil.win_service_iter():
            try:
                info = svc.as_dict()
            except Exception:
                info = {"name": getattr(svc, "name", ""), "display_name": getattr(svc, "display_name", "")}
            name = str(info.get("name") or "")
            display = str(info.get("display_name") or "")
            if is_protected(name) or is_protected(display):
                continue
            haystack = f"{name} {display}".lower()
            matched = next((p for p in patterns if p in haystack), None)
            if not matched:
                continue
            if dry_run:
                log.info("[DRY-RUN] Would stop service: %s (matched %r)", name or display, matched)
                continue
            try:
                svc.stop()
                stopped += 1
                log.warning("STOPPED SERVICE: %s (matched %r)", name or display, matched)
            except Exception as exc:
                log.error("Failed to stop service %s: %s", name, exc)
    except Exception as exc:
        log.debug("Windows service enumeration failed: %s", exc)
    return stopped


def _stop_linux_services(patterns: list[str], dry_run: bool, log: logging.Logger) -> int:
    stopped = 0
    try:
        proc = subprocess.run(
            ["systemctl", "list-units", "--type=service", "--state=running", "--no-pager", "--no-legend"],
            capture_output=True, text=True, check=False,
        )
    except FileNotFoundError:
        log.debug("systemctl not found; skipping service checks")
        return 0
    for line in proc.stdout.splitlines():
        parts = line.split()
        if not parts:
            continue
        unit = parts[0]
        if is_protected(unit):
            continue
        matched = next((p for p in patterns if p in unit.lower() or p in line.lower()), None)
        if not matched:
            continue
        if dry_run:
            log.info("[DRY-RUN] Would stop service unit: %s (matched %r)", unit, matched)
            continue
        stop = subprocess.run(["systemctl", "stop", unit], capture_output=True, text=True, check=False)
        if stop.returncode == 0:
            stopped += 1
            log.warning("STOPPED SERVICE UNIT: %s (matched %r)", unit, matched)
        else:
            log.error("Failed to stop unit %s: %s", unit, stop.stderr.strip())
    return stopped


def _kill_matching_processes(patterns: list[str], dry_run: bool, log: logging.Logger) -> int:
    killed = 0
    for proc in psutil.process_iter(["pid", "name", "exe", "cmdline"]):
        try:
            info = proc.info
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
        pid = info.get("pid")
        name = info.get("name") or ""
        exe = info.get("exe") or ""
        if pid is None or pid == os.getpid():
            continue
        cmdline = " ".join(info.get("cmdline") or [])
        matched = process_matches(name, exe, cmdline, patterns)
        if not matched:
            continue
        try:
            parent_pid = psutil.Process(pid).ppid()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            parent_pid = None
        if parent_pid == os.getpid():
            continue
        if dry_run:
            log.info("[DRY-RUN] Would terminate process: %s (PID %s) matched %r", name, pid, matched)
            continue
        try:
            target = psutil.Process(pid)
            target.terminate()
            try:
                target.wait(timeout=5)
            except psutil.TimeoutExpired:
                target.kill()
                target.wait(timeout=3)
            killed += 1
            log.warning("TERMINATED PROCESS: %s (PID %s) matched %r", name, pid, matched)
        except (psutil.NoSuchProcess, psutil.AccessDenied) as exc:
            log.error("Failed to terminate %s (PID %s): %s", name, pid, exc)
    return killed
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_enforcement.py -v`
Expected: all PASS (dry-run only; no real processes are killed)

- [ ] **Step 5: Commit**

```bash
git add security_monitor/enforcement.py tests/test_enforcement.py
git -c user.name="Sujon" -c user.email="sujon@users.noreply.github.com" commit -m "feat: opt-in enforcement with protect-list, dry-run, and self-pid exemption"
```

---

### Task 7: Reporter (`reporter.py`)

**Files:**
- Create: `security_monitor/reporter.py`
- Test: `tests/test_reporter.py`

**Interfaces:**
- Consumes: `config.Config`, `enforcement.EnforceResult`, `security_monitor.__version__`.
- Produces: `subject_for(violations: list[dict], hostname: str) -> str`, `build_report(cfg, system_info: dict, violations: list[dict], enforce_result: EnforceResult, timestamp: str) -> str`, `save_report(subject, body, reports_dir, timestamp) -> Path`, `purge_old_files(directory, retention_days) -> int`.

- [ ] **Step 1: Write the failing tests**

`tests/test_reporter.py`:
```python
import os
import time

from security_monitor import reporter
from security_monitor.config import Config
from security_monitor.enforcement import EnforceResult

VIOLATION = {
    "name": "Wireshark 4.2", "version": "4.2", "publisher": "WS",
    "install_date": "20240101", "install_location": "C:\\ws",
    "matched_term": "wireshark", "risk_level": "MEDIUM",
}
INFO = {"hostname": "DESKTOP-TEST", "username": "alice", "scan_time": "2026-10-10 09:00:00"}


def test_subject_alert_and_ok():
    assert reporter.subject_for([VIOLATION], "HOST1") == \
        "SECURITY ALERT: 1 violation(s) (0 high) - HOST1"
    assert reporter.subject_for([], "HOST1") == "SECURITY OK: no violations - HOST1"


def test_build_report_contains_violation_details():
    body = reporter.build_report(Config(), INFO, [VIOLATION], EnforceResult(processes_killed=2), "20261010_090000")
    assert "Wireshark 4.2" in body
    assert "MEDIUM RISK" in body
    assert "Matched   : wireshark" in body
    assert any("Processes terminated" in line and line.rstrip().endswith(": 2")
               for line in body.splitlines())
    assert "DESKTOP-TEST" in body
    assert "RECOMMENDED ACTIONS" in body
    assert not any(ch > "\u2500" for ch in body), "report must stay plain ASCII-ish (no emoji)"


def test_build_report_clean_status():
    body = reporter.build_report(Config(), INFO, [], EnforceResult(), "20261010_090000")
    assert "SYSTEM COMPLIANCE STATUS: CLEAN" in body
    assert "RECOMMENDED ACTIONS" not in body


def test_save_report_writes_subject_header(tmp_path):
    path = reporter.save_report("SUBJ", "BODY line", tmp_path, "20261010_090000")
    content = path.read_text(encoding="utf-8")
    assert path.name == "security_report_20261010_090000.txt"
    assert content == "Subject: SUBJ\n\nBODY line\n"


def test_purge_old_files(tmp_path):
    old = tmp_path / "old.txt"
    new = tmp_path / "new.txt"
    old.write_text("x", encoding="utf-8")
    new.write_text("y", encoding="utf-8")
    ancient = time.time() - 40 * 86400
    os.utime(old, (ancient, ancient))
    removed = reporter.purge_old_files(tmp_path, 30)
    assert removed == 1
    assert not old.exists() and new.exists()


def test_purge_missing_dir_is_safe(tmp_path):
    assert reporter.purge_old_files(tmp_path / "nope", 30) == 0
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_reporter.py -v`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Write the implementation**

`security_monitor/reporter.py`:
```python
"""Plain-ASCII report building, saving, and retention cleanup."""

from __future__ import annotations

import os
import time
from pathlib import Path

from security_monitor import __version__
from security_monitor.config import Config
from security_monitor.enforcement import EnforceResult

_RULE = "=" * 90


def subject_for(violations: list[dict], hostname: str) -> str:
    if violations:
        high = sum(1 for v in violations if v.get("risk_level") == "HIGH")
        return f"SECURITY ALERT: {len(violations)} violation(s) ({high} high) - {hostname}"
    return f"SECURITY OK: no violations - {hostname}"


def build_report(
    cfg: Config,
    system_info: dict,
    violations: list[dict],
    enforce_result: EnforceResult,
    timestamp: str,
) -> str:
    high = sum(1 for v in violations if v.get("risk_level") == "HIGH")
    medium = sum(1 for v in violations if v.get("risk_level") == "MEDIUM")
    low = sum(1 for v in violations if v.get("risk_level") == "LOW")

    lines = [
        f"SECURITY MONITORING REPORT v{__version__}",
        _RULE,
        "ORGANIZATION",
        f"  Company    : {cfg.org.company_name}",
        f"  Department : {cfg.org.department}",
        _RULE,
        "SYSTEM INFORMATION",
        f"  Hostname   : {system_info.get('hostname', 'Unknown')}",
        f"  FQDN       : {system_info.get('fqdn', 'Unknown')}",
        f"  Username   : {system_info.get('username', 'Unknown')}",
        f"  IP Address : {system_info.get('ip_address', 'Unknown')}",
        f"  OS         : {system_info.get('os_info', 'Unknown')}",
        f"  CPU        : {system_info.get('cpu_info', 'Unknown')}",
        f"  Memory     : {system_info.get('memory_total', 'Unknown')} total, "
        f"{system_info.get('memory_used', 'Unknown')} used, "
        f"{system_info.get('memory_available', 'Unknown')} available "
        f"({system_info.get('memory_percent', 'Unknown')} used)",
        f"  Domain     : {system_info.get('domain', 'N/A')}",
        f"  Boot Time  : {system_info.get('boot_time', 'Unknown')}",
        f"  Uptime     : {system_info.get('uptime', 'Unknown')}",
        f"  Disk       : {system_info.get('disk_used', 'Unknown')} used of "
        f"{system_info.get('disk_total', 'Unknown')}",
        f"  Scan Time  : {system_info.get('scan_time', 'Unknown')}",
        _RULE,
        "ENFORCEMENT SUMMARY",
        f"  Blacklisted software detected : {len(violations)}",
        f"  Processes terminated          : {enforce_result.processes_killed}",
        f"  Services stopped              : {enforce_result.services_stopped}",
        f"  High / Medium / Low risk      : {high} / {medium} / {low}",
        _RULE,
    ]

    if violations:
        lines.append("DETECTED UNAUTHORIZED SOFTWARE")
        for index, violation in enumerate(violations, 1):
            lines.append(f"  {index}. {violation['name']} [{violation['risk_level']} RISK]")
            lines.append(f"     Version   : {violation['version']}")
            lines.append(f"     Publisher : {violation['publisher']}")
            lines.append(f"     Installed : {violation['install_date']}")
            lines.append(f"     Location  : {violation['install_location']}")
            lines.append(f"     Matched   : {violation['matched_term']}")
        lines += [
            _RULE,
            "RECOMMENDED ACTIONS",
            "  1. Investigate unauthorized software installations immediately",
            "  2. Contact the user for an explanation of policy violations",
            "  3. Remove unauthorized software from the system",
            "  4. Review user access permissions and policies",
            "  5. Document the incident for compliance reporting",
            "  6. Consider additional security awareness training",
        ]
    else:
        lines += [
            "SYSTEM COMPLIANCE STATUS: CLEAN",
            _RULE,
            "No unauthorized software detected. System is compliant with security policies.",
        ]

    lines += ["", f"Generated by Security Monitor v{__version__} | PID {os.getpid()} | Report ID {timestamp}"]
    return "\n".join(lines)


def save_report(subject: str, body: str, reports_dir: str | Path, timestamp: str) -> Path:
    directory = Path(reports_dir)
    directory.mkdir(parents=True, exist_ok=True)
    report_path = directory / f"security_report_{timestamp}.txt"
    report_path.write_text(f"Subject: {subject}\n\n{body}\n", encoding="utf-8")
    return report_path


def purge_old_files(directory: str | Path, retention_days: int) -> int:
    target = Path(directory)
    if not target.exists():
        return 0
    cutoff = time.time() - retention_days * 86400
    removed = 0
    for entry in target.iterdir():
        if entry.is_file() and entry.stat().st_mtime < cutoff:
            try:
                entry.unlink()
                removed += 1
            except OSError:
                continue
    return removed
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_reporter.py -v`
Expected: all PASS

- [ ] **Step 5: Commit**

```bash
git add security_monitor/reporter.py tests/test_reporter.py
git -c user.name="Sujon" -c user.email="sujon@users.noreply.github.com" commit -m "feat: plain-ASCII report builder, saver, and retention purge"
```

---

### Task 8: Emailer (`emailer.py`)

**Files:**
- Create: `security_monitor/emailer.py`
- Test: `tests/test_emailer.py`

**Interfaces:**
- Consumes: `config.EmailConfig`.
- Produces: `class EmailError(Exception)`, `should_send(mode, violation_count, enforcement_taken, scan_errored) -> bool`, `build_message(email_cfg, subject, body, attachment_path=None) -> MIMEMultipart`, `send_report(email_cfg, subject, body, attachment_path=None) -> None` (raises `EmailError`), `send_test_email(email_cfg) -> None` (raises `EmailError`).

- [ ] **Step 1: Write the failing tests**

`tests/test_emailer.py`:
```python
import smtplib

import pytest

from security_monitor import emailer
from security_monitor.config import EmailConfig


def _cfg(port: int = 587) -> EmailConfig:
    return EmailConfig(
        mode="violations", sender="me@gmail.com",
        recipients=["a@b.com", "c@d.com"], app_password="secret",
        smtp_server="smtp.gmail.com", smtp_port=port,
    )


class FakeSMTP:
    instances: list = []

    def __init__(self, host, port, timeout=None):
        self.host, self.port, self.timeout = host, port, timeout
        self.started_tls = False
        self.logged_in = None
        self.sent = None
        FakeSMTP.instances.append(self)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def starttls(self):
        self.started_tls = True

    def login(self, user, password):
        self.logged_in = (user, password)

    def sendmail(self, sender, recipients, message):
        self.sent = (sender, recipients, message)


def test_should_send_matrix():
    assert emailer.should_send("never", 5, True, True) is False
    assert emailer.should_send("always", 0, False, False) is True
    assert emailer.should_send("violations", 0, False, False) is False
    assert emailer.should_send("violations", 1, False, False) is True
    assert emailer.should_send("violations", 0, True, False) is True
    assert emailer.should_send("violations", 0, False, True) is True


def test_build_message_headers_and_recipients():
    msg = emailer.build_message(_cfg(), "SUBJ", "BODY")
    assert msg["From"] == "me@gmail.com"
    assert msg["To"] == "a@b.com, c@d.com"
    assert msg["Subject"] == "SUBJ"


def test_build_message_with_attachment(tmp_path):
    attachment = tmp_path / "report.txt"
    attachment.write_text("data", encoding="utf-8")
    msg = emailer.build_message(_cfg(), "S", "B", attachment)
    assert len(msg.get_payload()) == 2


def test_send_report_uses_starttls_on_587(monkeypatch):
    FakeSMTP.instances.clear()
    monkeypatch.setattr(emailer.smtplib, "SMTP", FakeSMTP)
    emailer.send_report(_cfg(587), "S", "B")
    instance = FakeSMTP.instances[-1]
    assert instance.port == 587
    assert instance.started_tls is True
    assert instance.logged_in == ("me@gmail.com", "secret")
    assert instance.sent[0] == "me@gmail.com"
    assert instance.sent[1] == ["a@b.com", "c@d.com"]


def test_send_report_uses_ssl_on_465(monkeypatch):
    FakeSMTP.instances.clear()
    monkeypatch.setattr(emailer.smtplib, "SMTP_SSL", FakeSMTP)
    emailer.send_report(_cfg(465), "S", "B")
    instance = FakeSMTP.instances[-1]
    assert instance.port == 465
    assert instance.started_tls is False  # implicit TLS, no starttls call


def test_send_report_auth_failure_raises(monkeypatch):
    class AuthFailSMTP(FakeSMTP):
        def login(self, user, password):
            raise smtplib.SMTPAuthenticationError(535, b"bad credentials")

    monkeypatch.setattr(emailer.smtplib, "SMTP", AuthFailSMTP)
    with pytest.raises(emailer.EmailError, match="authentication"):
        emailer.send_report(_cfg(), "S", "B")


def test_send_report_no_recipients_raises():
    cfg = _cfg()
    cfg.recipients = []
    with pytest.raises(emailer.EmailError):
        emailer.send_report(cfg, "S", "B")


def test_send_test_email_subject(monkeypatch):
    FakeSMTP.instances.clear()
    monkeypatch.setattr(emailer.smtplib, "SMTP", FakeSMTP)
    emailer.send_test_email(_cfg())
    sent_message = FakeSMTP.instances[-1].sent[2]
    assert "Security Monitor test email" in sent_message
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_emailer.py -v`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Write the implementation**

`security_monitor/emailer.py`:
```python
"""SMTP email delivery: report sending, attachments, and test emails."""

from __future__ import annotations

import smtplib
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path

from security_monitor.config import EmailConfig


class EmailError(Exception):
    """Raised when an email cannot be delivered."""


def should_send(mode: str, violation_count: int, enforcement_taken: bool, scan_errored: bool) -> bool:
    if mode == "never":
        return False
    if mode == "always":
        return True
    return violation_count > 0 or enforcement_taken or scan_errored


def build_message(
    email_cfg: EmailConfig,
    subject: str,
    body: str,
    attachment_path: str | Path | None = None,
) -> MIMEMultipart:
    msg = MIMEMultipart()
    msg["From"] = email_cfg.sender
    msg["To"] = ", ".join(email_cfg.recipients)
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))

    if attachment_path is not None:
        path = Path(attachment_path)
        if path.exists():
            part = MIMEBase("application", "octet-stream")
            part.set_payload(path.read_bytes())
            encoders.encode_base64(part)
            part.add_header("Content-Disposition", f"attachment; filename={path.name}")
            msg.attach(part)
    return msg


def send_report(
    email_cfg: EmailConfig,
    subject: str,
    body: str,
    attachment_path: str | Path | None = None,
) -> None:
    _transmit(email_cfg, build_message(email_cfg, subject, body, attachment_path))


def send_test_email(email_cfg: EmailConfig) -> None:
    body = "If you receive this email, the Security Monitor SMTP configuration is correct."
    _transmit(email_cfg, build_message(email_cfg, "Security Monitor test email", body))


def _transmit(email_cfg: EmailConfig, msg: MIMEMultipart) -> None:
    if not email_cfg.recipients:
        raise EmailError("no recipients configured")
    if not email_cfg.sender:
        raise EmailError("no sender configured")

    try:
        if email_cfg.smtp_port == 465:
            with smtplib.SMTP_SSL(email_cfg.smtp_server, email_cfg.smtp_port, timeout=30) as server:
                server.login(email_cfg.sender, email_cfg.app_password)
                server.sendmail(email_cfg.sender, email_cfg.recipients, msg.as_string())
        else:
            with smtplib.SMTP(email_cfg.smtp_server, email_cfg.smtp_port, timeout=30) as server:
                server.starttls()
                server.login(email_cfg.sender, email_cfg.app_password)
                server.sendmail(email_cfg.sender, email_cfg.recipients, msg.as_string())
    except smtplib.SMTPAuthenticationError as exc:
        raise EmailError("SMTP authentication failed - check sender address and app password") from exc
    except smtplib.SMTPException as exc:
        raise EmailError(f"SMTP error: {exc}") from exc
    except OSError as exc:
        raise EmailError(f"cannot reach {email_cfg.smtp_server}:{email_cfg.smtp_port} - {exc}") from exc
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_emailer.py -v`
Expected: all PASS

- [ ] **Step 5: Commit**

```bash
git add security_monitor/emailer.py tests/test_emailer.py
git -c user.name="Sujon" -c user.email="sujon@users.noreply.github.com" commit -m "feat: emailer with mode gating, attachments, STARTTLS/SSL, and test email"
```

---

### Task 9: Task Scheduler module (`task.py`)

**Files:**
- Create: `security_monitor/task.py`
- Test: `tests/test_task.py`

**Interfaces:**
- Produces (Windows-only at call time; imports safely everywhere):
  - `TASK_NAME = "Security Monitor"`
  - `class TaskError(Exception)`
  - `build_task_xml(exe_path: str, interval_hours: int) -> str` (boot trigger + `PTnH` repetition, SYSTEM principal `S-1-5-18` + `ServiceAccount` + `HighestAvailable`, action `"<exe>" --run --config "<exe_dir>\config.ini"`, `<Hidden>true</Hidden>`)
  - `register_task(exe_path, interval_hours, task_name=TASK_NAME, runner=subprocess.run) -> None` (writes temp UTF-16 XML, `schtasks /Create /TN <name> /XML <file> /F`; raises `TaskError`)
  - `task_exists(task_name=TASK_NAME, runner=subprocess.run) -> bool`
  - `delete_task(task_name=TASK_NAME, runner=subprocess.run) -> bool`
  - `task_details(task_name=TASK_NAME, runner=subprocess.run) -> dict` (`next_run`, `last_run`, `last_result` keys; `{}` if absent — English-locale parse, documented caveat)

- [ ] **Step 1: Write the failing tests**

`tests/test_task.py`:
```python
import subprocess

import pytest

from security_monitor import task


def test_xml_contains_triggers_principal_and_action():
    xml = task.build_task_xml(r"C:\Security Monitor\security-monitor.exe", 4)
    assert "<BootTrigger>" in xml
    assert "<Interval>PT4H</Interval>" in xml
    assert "<UserId>S-1-5-18</UserId>" in xml
    assert "<LogonType>ServiceAccount</LogonType>" in xml
    assert "<RunLevel>HighestAvailable</RunLevel>" in xml
    assert "<Hidden>true</Hidden>" in xml
    assert "security-monitor.exe" in xml
    assert "--run --config" in xml
    assert "config.ini" in xml


def test_xml_interval_12h():
    xml = task.build_task_xml(r"C:\Security Monitor\security-monitor.exe", 12)
    assert "<Interval>PT12H</Interval>" in xml


def test_register_task_invokes_schtasks_with_xml():
    calls = []

    def fake_runner(cmd, **kwargs):
        calls.append((cmd, kwargs))
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    task.register_task(r"C:\Security Monitor\security-monitor.exe", 4, runner=fake_runner)
    cmd, kwargs = calls[0]
    assert cmd[0] == "schtasks"
    assert cmd[1:4] == ["/Create", "/TN", "Security Monitor"]
    assert "/XML" in cmd
    assert "/F" in cmd
    assert kwargs.get("capture_output") is True


def test_register_task_failure_raises():
    def fake_runner(cmd, **kwargs):
        return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="boom")

    with pytest.raises(task.TaskError, match="boom"):
        task.register_task(r"C:\x\security-monitor.exe", 4, runner=fake_runner)


def test_task_exists_true_and_false():
    ok = lambda cmd, **kw: subprocess.CompletedProcess(cmd, 0)
    missing = lambda cmd, **kw: subprocess.CompletedProcess(cmd, 1)
    assert task.task_exists(runner=ok) is True
    assert task.task_exists(runner=missing) is False


def test_delete_task_uses_delete_command():
    calls = []

    def fake_runner(cmd, **kw):
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 0)

    assert task.delete_task(runner=fake_runner) is True
    assert calls[0][:2] == ["schtasks", "/Delete"]
    assert "/F" in calls[0]


def test_task_details_parses_list_output():
    stdout = (
        "HostName:                  HOST\n"
        "TaskName:                  \\Security Monitor\n"
        "Next Run Time:             10/11/2026 9:00:00 AM\n"
        "Last Run Time:             10/10/2026 7:00:00 AM\n"
        "Last Result:               0\n"
    )

    def fake_runner(cmd, **kw):
        return subprocess.CompletedProcess(cmd, 0, stdout=stdout, stderr="")

    details = task.task_details(runner=fake_runner)
    assert details["next_run"] == "10/11/2026 9:00:00 AM"
    assert details["last_result"] == "0"


def test_task_details_empty_when_absent():
    def fake_runner(cmd, **kw):
        return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="")

    assert task.task_details(runner=fake_runner) == {}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_task.py -v`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Write the implementation**

`security_monitor/task.py`:
```python
"""Windows Task Scheduler lifecycle: build XML, register, query, delete."""

from __future__ import annotations

import os
import subprocess
import tempfile
from datetime import datetime
from pathlib import Path
from xml.sax.saxutils import escape as xml_escape

TASK_NAME = "Security Monitor"

_DETAIL_KEYS = {
    "next run time": "next_run",
    "last run time": "last_run",
    "last result": "last_result",
}


class TaskError(Exception):
    """Raised when a schtasks operation fails."""


def build_task_xml(exe_path: str, interval_hours: int) -> str:
    exe = xml_escape(str(exe_path))
    config = xml_escape(str(Path(exe_path).parent / "config.ini"))
    start_boundary = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
    return f"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>Security Monitor - scans for blacklisted software at boot and every {interval_hours}h.</Description>
    <Author>Cyber Sujon</Author>
    <URI>\\Security Monitor</URI>
  </RegistrationInfo>
  <Triggers>
    <BootTrigger>
      <Enabled>true</Enabled>
    </BootTrigger>
    <TimeTrigger>
      <StartBoundary>{start_boundary}</StartBoundary>
      <Repetition>
        <Interval>PT{interval_hours}H</Interval>
        <StopAtDurationEnd>false</StopAtDurationEnd>
      </Repetition>
      <Enabled>true</Enabled>
    </TimeTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>
      <LogonType>ServiceAccount</LogonType>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <StartWhenAvailable>true</StartWhenAvailable>
    <ExecutionTimeLimit>PT1H</ExecutionTimeLimit>
    <AllowHardTerminate>true</AllowHardTerminate>
    <Hidden>true</Hidden>
    <Enabled>true</Enabled>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{exe}</Command>
      <Arguments>--run --config &quot;{config}&quot;</Arguments>
      <WorkingDirectory>{xml_escape(str(Path(exe_path).parent))}</WorkingDirectory>
    </Exec>
  </Actions>
</Task>
"""


def _run(runner, cmd: list[str]) -> subprocess.CompletedProcess:
    return runner(cmd, capture_output=True, text=True)


def register_task(
    exe_path: str,
    interval_hours: int,
    task_name: str = TASK_NAME,
    runner=subprocess.run,
) -> None:
    xml = build_task_xml(exe_path, interval_hours)
    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(
            "w", suffix=".xml", delete=False, encoding="utf-16"
        ) as handle:
            handle.write(xml)
            tmp_path = handle.name
        result = _run(runner, ["schtasks", "/Create", "/TN", task_name, "/XML", tmp_path, "/F"])
        if result.returncode != 0:
            detail = (result.stderr or result.stdout or "").strip() or "schtasks /Create failed"
            raise TaskError(detail)
    finally:
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
            except OSError:
                pass


def task_exists(task_name: str = TASK_NAME, runner=subprocess.run) -> bool:
    result = _run(runner, ["schtasks", "/Query", "/TN", task_name])
    return result.returncode == 0


def delete_task(task_name: str = TASK_NAME, runner=subprocess.run) -> bool:
    result = _run(runner, ["schtasks", "/Delete", "/TN", task_name, "/F"])
    return result.returncode == 0


def task_details(task_name: str = TASK_NAME, runner=subprocess.run) -> dict:
    if not task_exists(task_name, runner=runner):
        return {}
    result = _run(runner, ["schtasks", "/Query", "/TN", task_name, "/FO", "LIST", "/V"])
    if result.returncode != 0:
        return {}
    details: dict = {}
    for line in (result.stdout or "").splitlines():
        key, sep, value = line.partition(":")
        if not sep:
            continue
        mapped = _DETAIL_KEYS.get(key.strip().lower())
        if mapped:
            details[mapped] = value.strip()
    return details
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_task.py -v`
Expected: all PASS (all runner-injected; no real schtasks call)

- [ ] **Step 5: Commit**

```bash
git add security_monitor/task.py tests/test_task.py
git -c user.name="Sujon" -c user.email="sujon@users.noreply.github.com" commit -m "feat: task scheduler module with XML builder, register/query/delete"
```

---

### Task 10: Installer (`installer.py`)

**Files:**
- Create: `security_monitor/installer.py`
- Test: `tests/test_installer.py`

**Interfaces:**
- Consumes: `scanner.write_default_blacklist`.
- Produces: `DEFAULT_INSTALL_DIR = Path(r"C:\Security Monitor")`, `EXE_NAME = "security-monitor.exe"`, `is_installed(install_dir) -> bool`, `install(source_exe, install_dir, cfg_path=None, blacklist_src=None) -> Path`, `remove_install_dir(install_dir) -> bool`.

- [ ] **Step 1: Write the failing tests**

`tests/test_installer.py`:
```python
from security_monitor import installer


def test_install_copies_exe_config_and_creates_dirs(tmp_path):
    source = tmp_path / "portable.exe"
    source.write_bytes(b"fake-exe")
    cfg = tmp_path / "config.ini"
    cfg.write_text("[email]\nmode = never\n", encoding="utf-8")
    target = tmp_path / "Security Monitor"

    result = installer.install(source, target, cfg_path=cfg)

    assert result == target
    assert (target / "security-monitor.exe").read_bytes() == b"fake-exe"
    assert (target / "config.ini").exists()
    assert (target / "blacklist_software.txt").exists()
    assert (target / "logs").is_dir()
    assert (target / "reports").is_dir()


def test_install_writes_default_blacklist_without_source(tmp_path):
    source = tmp_path / "portable.exe"
    source.write_bytes(b"x")
    target = tmp_path / "install"
    installer.install(source, target)
    content = (target / "blacklist_software.txt").read_text(encoding="utf-8")
    assert "wireshark" in content


def test_install_when_source_is_already_installed_copy(tmp_path):
    target = tmp_path / "install"
    target.mkdir()
    exe = target / "security-monitor.exe"
    exe.write_bytes(b"already")
    installer.install(exe, target)  # must not crash copying onto itself
    assert exe.read_bytes() == b"already"


def test_is_installed(tmp_path):
    target = tmp_path / "install"
    assert installer.is_installed(target) is False
    target.mkdir()
    (target / "security-monitor.exe").write_bytes(b"x")
    assert installer.is_installed(target) is True


def test_remove_install_dir(tmp_path):
    source = tmp_path / "s.exe"
    source.write_bytes(b"x")
    target = tmp_path / "install"
    installer.install(source, target)
    assert installer.remove_install_dir(target) is True
    assert not target.exists()
    assert installer.remove_install_dir(target) is False  # already gone
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_installer.py -v`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Write the implementation**

`security_monitor/installer.py`:
```python
"""Deploy/repair/remove the C:\\Security Monitor installation."""

from __future__ import annotations

import shutil
from pathlib import Path

from security_monitor.scanner import write_default_blacklist

DEFAULT_INSTALL_DIR = Path(r"C:\Security Monitor")
EXE_NAME = "security-monitor.exe"


def is_installed(install_dir: str | Path) -> bool:
    return (Path(install_dir) / EXE_NAME).exists()


def install(
    source_exe: str | Path,
    install_dir: str | Path,
    cfg_path: str | Path | None = None,
    blacklist_src: str | Path | None = None,
) -> Path:
    target = Path(install_dir)
    target.mkdir(parents=True, exist_ok=True)

    source = Path(source_exe)
    destination_exe = target / EXE_NAME
    if source.resolve() != destination_exe.resolve():
        shutil.copy2(source, destination_exe)

    if cfg_path is not None:
        cfg_source = Path(cfg_path)
        cfg_dest = target / "config.ini"
        if cfg_source.exists() and cfg_source.resolve() != cfg_dest.resolve():
            shutil.copy2(cfg_source, cfg_dest)

    blacklist = target / "blacklist_software.txt"
    if not blacklist.exists():
        if blacklist_src is not None and Path(blacklist_src).exists():
            shutil.copy2(blacklist_src, blacklist)
        else:
            write_default_blacklist(blacklist)

    (target / "logs").mkdir(exist_ok=True)
    (target / "reports").mkdir(exist_ok=True)
    return target


def remove_install_dir(install_dir: str | Path) -> bool:
    target = Path(install_dir)
    if not target.exists():
        return False
    shutil.rmtree(target, ignore_errors=True)
    return not target.exists()
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_installer.py -v`
Expected: all PASS

- [ ] **Step 5: Commit**

```bash
git add security_monitor/installer.py tests/test_installer.py
git -c user.name="Sujon" -c user.email="sujon@users.noreply.github.com" commit -m "feat: installer for C:\\Security Monitor deploy and removal"
```

---

### Task 11: Menu (`menu.py`)

**Files:**
- Create: `security_monitor/menu.py`
- Test: `tests/test_menu.py`

**Interfaces:**
- Consumes: `config` (`load_config`, `run_setup_wizard`, `Config`, `ConfigError`), `task` (`task_exists`, `register_task`, `delete_task`, `TASK_NAME`), `installer` (`install`, `is_installed`, `remove_install_dir`, `DEFAULT_INSTALL_DIR`), `cli.status_text` (lazy import).
- Produces: `run_menu(*, install_dir=DEFAULT_INSTALL_DIR, input_fn=input, output_fn=print) -> int`, `portable_exe_path() -> Path | None`, menu option handlers `_opt_install/_opt_status/_opt_settings/_opt_scan/_opt_uninstall`.

- [ ] **Step 1: Write the failing tests**

`tests/test_menu.py`:
```python
from pathlib import Path

from security_monitor import menu
from security_monitor.config import Config, save_config


def run_menu_scripted(monkeypatch, inputs, install_dir=Path("C:/Security Monitor"), **stubs):
    """Run the menu with scripted input; monkeypatch module-level dependencies; return (exit_code, output)."""
    for name, value in stubs.items():
        monkeypatch.setattr(menu, name, value)
    answers = iter(inputs)
    out: list[str] = []
    code = menu.run_menu(
        install_dir=install_dir,
        input_fn=lambda: next(answers),
        output_fn=out.append,
    )
    return code, "\n".join(out)


def test_menu_exit(monkeypatch):
    code, out = run_menu_scripted(monkeypatch, ["0"])
    assert code == 0
    assert "Goodbye." in out
    assert "1) Install / configure" in out


def test_menu_install_notifies_existing_task(monkeypatch):
    code, out = run_menu_scripted(
        monkeypatch, ["1", "0"],
        task_exists=lambda **kw: True,
        is_installed=lambda d: True,
    )
    assert 'ℹ Task "Security Monitor" already exists — choose option 3 to update it.' in out


def test_menu_install_creates_task_and_notifies(monkeypatch, tmp_path):
    registered = {}

    def fake_register(exe, hours, **kw):
        registered["exe"] = exe
        registered["hours"] = hours

    cfg = Config()
    code, out = run_menu_scripted(
        monkeypatch, ["1", "y", "0"],
        install_dir=tmp_path / "Security Monitor",
        task_exists=lambda **kw: False,
        is_installed=lambda d: False,
        run_setup_wizard=lambda *a, **k: cfg,
        portable_exe_path=lambda: Path("C:/dl/security-monitor.exe"),
        install=lambda src, dst, **kw: Path(dst),
        register_task=fake_register,
    )
    assert '✔ Scheduled task "Security Monitor" created — runs at boot and every 4h.' in out
    assert registered["hours"] == 4
    assert registered["exe"].endswith("security-monitor.exe")


def test_menu_install_cancelled_when_declined(monkeypatch):
    registered = []
    code, out = run_menu_scripted(
        monkeypatch, ["1", "n", "0"],
        task_exists=lambda **kw: False,
        is_installed=lambda d: False,
        register_task=lambda *a, **k: registered.append(a),
    )
    assert "Install cancelled." in out
    assert registered == []


def test_menu_settings_updates_task_when_interval_changes(monkeypatch, tmp_path):
    install_dir = tmp_path / "Security Monitor"
    install_dir.mkdir()
    cfg = Config()
    save_config(cfg, install_dir / "config.ini")  # invalid on load -> falls back to defaults (interval 4)

    calls = {"deleted": False, "hours": None}

    def fake_register(exe, hours, **kw):
        calls["hours"] = hours

    new_cfg = Config()
    new_cfg.scan.interval_hours = 8

    code, out = run_menu_scripted(
        monkeypatch, ["3", "0"],
        install_dir=install_dir,
        task_exists=lambda **kw: True,
        run_setup_wizard=lambda *a, **k: new_cfg,
        delete_task=lambda **kw: calls.__setitem__("deleted", True),
        register_task=fake_register,
    )
    assert '✔ Task "Security Monitor" updated.' in out
    assert calls["deleted"] is True
    assert calls["hours"] == 8


def test_menu_settings_uninstalled(monkeypatch, tmp_path):
    code, out = run_menu_scripted(
        monkeypatch, ["3", "0"],
        install_dir=tmp_path,  # no config.ini inside
    )
    assert "Not installed yet" in out


def test_menu_uninstall_removes_task_and_dir(monkeypatch, tmp_path):
    calls = {"deleted": False, "removed": False}

    def fake_delete(**kw):
        calls["deleted"] = True
        return True

    def fake_remove(path):
        calls["removed"] = True
        return True

    code, out = run_menu_scripted(
        monkeypatch, ["5", "y", "0"],
        install_dir=tmp_path,
        task_exists=lambda **kw: True,
        delete_task=fake_delete,
        remove_install_dir=fake_remove,
    )
    assert '✔ Scheduled task "Security Monitor" removed.' in out
    assert calls["deleted"] and calls["removed"]
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_menu.py -v`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Write the implementation**

`security_monitor/menu.py`:
```python
"""Interactive console manager: install, status, settings, scan now, uninstall."""

from __future__ import annotations

import sys
from pathlib import Path

from security_monitor.config import Config, ConfigError, load_config, run_setup_wizard
from security_monitor.installer import (
    DEFAULT_INSTALL_DIR,
    install,
    is_installed,
    remove_install_dir,
)
from security_monitor.task import (
    TASK_NAME,
    delete_task,
    register_task,
    task_exists,
)

MENU_TEXT = """
Security Monitor
================
1) Install / configure
2) Status
3) Change settings (updates scheduled task)
4) Run scan now
5) Uninstall
0) Exit
"""

CREATED_MSG = f'✔ Scheduled task "{TASK_NAME}" created — runs at boot and every {{interval}}h.'
EXISTS_MSG = f'ℹ Task "{TASK_NAME}" already exists — choose option 3 to update it.'
UPDATED_MSG = f'✔ Task "{TASK_NAME}" updated.'
REMOVED_MSG = f'✔ Scheduled task "{TASK_NAME}" removed.'


def portable_exe_path() -> Path | None:
    if getattr(sys, "frozen", False):
        return Path(sys.executable)
    return None


def _ask_choice(input_fn, output_fn) -> str:
    output_fn("Select an option: ")
    return input_fn().strip()


def _confirm(input_fn, output_fn, question: str) -> bool:
    output_fn(f"{question} [y/N]: ")
    return input_fn().strip().lower() in ("y", "yes")


def _test_email_adapter(cfg: Config) -> bool:
    from security_monitor.emailer import EmailError, send_test_email

    try:
        send_test_email(cfg.email)
        return True
    except EmailError:
        return False


def _created_message(interval_hours: int) -> str:
    return CREATED_MSG.format(interval=interval_hours)


def run_menu(
    *,
    install_dir: Path = DEFAULT_INSTALL_DIR,
    input_fn=input,
    output_fn=print,
) -> int:
    while True:
        output_fn(MENU_TEXT)
        choice = _ask_choice(input_fn, output_fn)
        if choice == "0":
            output_fn("Goodbye.")
            return 0
        if choice == "1":
            _opt_install(Path(install_dir), input_fn, output_fn)
        elif choice == "2":
            _opt_status(Path(install_dir), input_fn, output_fn)
        elif choice == "3":
            _opt_settings(Path(install_dir), input_fn, output_fn)
        elif choice == "4":
            _opt_scan(Path(install_dir), input_fn, output_fn)
        elif choice == "5":
            _opt_uninstall(Path(install_dir), input_fn, output_fn)
        else:
            output_fn("Unknown option - try again.")


def _opt_install(install_dir: Path, input_fn, output_fn) -> None:
    if task_exists() and is_installed(install_dir):
        output_fn(EXISTS_MSG)
        return
    if not _confirm(input_fn, output_fn, f"Install Security Monitor to {install_dir}?"):
        output_fn("Install cancelled.")
        return

    cfg_path = install_dir / "config.ini"
    try:
        if cfg_path.exists() and not _confirm(
            input_fn, output_fn, "Existing configuration found. Re-run setup wizard?"
        ):
            cfg = load_config(cfg_path)
        else:
            cfg = run_setup_wizard(
                cfg_path,
                input_fn=input_fn,
                output_fn=output_fn,
                test_email_fn=_test_email_adapter,
            )
    except ConfigError as exc:
        output_fn(f"Setup failed: {exc}")
        return

    source = portable_exe_path()
    if source is None:
        output_fn("Build the EXE first (scripts/build.ps1) - source runs cannot install.")
        return

    install(source, install_dir)
    register_task(str(install_dir / "security-monitor.exe"), cfg.scan.interval_hours)
    output_fn(_created_message(cfg.scan.interval_hours))


def _opt_status(install_dir: Path, input_fn, output_fn) -> None:
    from security_monitor.cli import status_text

    output_fn(status_text(install_dir / "config.ini"))


def _opt_settings(install_dir: Path, input_fn, output_fn) -> None:
    cfg_path = install_dir / "config.ini"
    if not cfg_path.exists():
        output_fn("Not installed yet - use option 1 first.")
        return

    try:
        old_cfg = load_config(cfg_path)
    except ConfigError:
        old_cfg = Config()

    try:
        cfg = run_setup_wizard(
            cfg_path,
            input_fn=input_fn,
            output_fn=output_fn,
            test_email_fn=_test_email_adapter,
        )
    except ConfigError as exc:
        output_fn(f"Setup failed: {exc}")
        return

    exe = str(install_dir / "security-monitor.exe")
    if not task_exists():
        if not is_installed(install_dir):
            output_fn("Installed copy missing - use option 1 to install.")
            return
        register_task(exe, cfg.scan.interval_hours)
        output_fn(_created_message(cfg.scan.interval_hours))
    elif cfg.scan.interval_hours != old_cfg.scan.interval_hours:
        delete_task()
        register_task(exe, cfg.scan.interval_hours)
        output_fn(UPDATED_MSG)
    else:
        output_fn("Settings saved. Scheduled task unchanged.")


def _opt_scan(install_dir: Path, input_fn, output_fn) -> None:
    from security_monitor import cli

    output_fn("Running scan...")
    code = cli.main(["--run", "--config", str(install_dir / "config.ini")])
    messages = {
        0: "Scan complete - no violations.",
        1: "Scan failed - check logs.",
        2: "Scan complete - violations found (see reports).",
    }
    output_fn(messages.get(code, f"Scan exited with code {code}."))


def _opt_uninstall(install_dir: Path, input_fn, output_fn) -> None:
    if not _confirm(
        input_fn, output_fn, f'This removes the scheduled task and "{install_dir}". Continue?'
    ):
        output_fn("Uninstall cancelled.")
        return
    if task_exists():
        delete_task()
        output_fn(REMOVED_MSG)
    else:
        output_fn("ℹ No scheduled task to remove.")
    if remove_install_dir(install_dir):
        output_fn(f"✔ Removed {install_dir}")
    else:
        output_fn(f"ℹ Could not fully remove {install_dir} (files in use) - delete it manually after reboot.")
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_menu.py -v`
Expected: all PASS

- [ ] **Step 5: Commit**

```bash
git add security_monitor/menu.py tests/test_menu.py
git -c user.name="Sujon" -c user.email="sujon@users.noreply.github.com" commit -m "feat: interactive menu with install/status/settings/scan/uninstall notifications"
```

---

### Task 12: CLI & scan pipeline (`cli.py`)

**Files:**
- Create: `security_monitor/cli.py`
- Modify: `security_monitor/__main__.py` (already references `cli.main`)
- Test: `tests/test_cli.py`

**Interfaces:**
- Consumes: every module from Tasks 2-11.
- Produces:
  - `EXIT_OK = 0`, `EXIT_ERROR = 1`, `EXIT_VIOLATIONS = 2`
  - `build_parser() -> argparse.ArgumentParser` (flags: `--run --setup --status --uninstall --test-email --enforce --dry-run --no-email --verbose --config`)
  - `main(argv: list[str] | None = None) -> int` — no mode flag on Windows → menu; elsewhere → scan
  - `resolve_config_path(arg: str | None) -> Path` (explicit → else first existing of `C:\Security Monitor\config.ini` / `config.ini` on Windows, else `config.ini`)
  - `status_text(config_path: Path) -> str`
  - `cmd_run(args) -> int`, `cmd_setup(args)`, `cmd_test_email(args)`, `cmd_status(args)`, `cmd_uninstall(args)`

- [ ] **Step 1: Write the failing tests**

`tests/test_cli.py`:
```python
from pathlib import Path

from security_monitor import cli, config as cfgmod


def _write_config(tmp_path: Path, blacklist_terms: str, installed: list[dict], monkeypatch) -> Path:
    cfg = cfgmod.Config()
    cfg.email.mode = "never"
    (tmp_path / "blacklist_software.txt").write_text(blacklist_terms, encoding="utf-8")
    path = tmp_path / "config.ini"
    cfgmod.save_config(cfg, path)
    monkeypatch.setattr(cli, "list_installed_software", lambda: installed)
    return path


def test_run_with_missing_config_returns_1(tmp_path, capsys):
    code = cli.main(["--run", "--config", str(tmp_path / "nope.ini")])
    assert code == cli.EXIT_ERROR
    assert "--setup" in capsys.readouterr().out


def test_run_with_violations_returns_2_and_writes_report(tmp_path, monkeypatch):
    path = _write_config(
        tmp_path, "wireshark\n",
        [{"name": "Wireshark 4.2", "version": "4.2", "publisher": "WS",
          "install_date": "20240101", "install_location": "C:\\ws"}],
        monkeypatch,
    )
    code = cli.main(["--run", "--config", str(path)])
    assert code == cli.EXIT_VIOLATIONS
    reports = list((tmp_path / "reports").glob("security_report_*.txt"))
    assert len(reports) == 1
    assert "Wireshark" in reports[0].read_text(encoding="utf-8")


def test_run_clean_returns_0(tmp_path, monkeypatch):
    path = _write_config(tmp_path, "wireshark\n", [], monkeypatch)
    code = cli.main(["--run", "--config", str(path)])
    assert code == cli.EXIT_OK


def test_status_returns_0(tmp_path, monkeypatch, capsys):
    path = _write_config(tmp_path, "wireshark\n", [], monkeypatch)
    monkeypatch.setattr(cli, "task_exists", lambda **kw: False)
    code = cli.main(["--status", "--config", str(path)])
    assert code == cli.EXIT_OK
    out = capsys.readouterr().out
    assert "Scheduled task" in out
    assert "Configuration" in out


def test_test_email_failure_returns_1(tmp_path, monkeypatch, capsys):
    path = _write_config(tmp_path, "wireshark\n", [], monkeypatch)

    def boom(cfg):
        raise cli.EmailError("SMTP auth failed")

    monkeypatch.setattr(cli, "send_test_email", boom)
    code = cli.main(["--test-email", "--config", str(path)])
    assert code == cli.EXIT_ERROR
    assert "failed" in capsys.readouterr().out.lower()


def test_parser_defaults():
    args = cli.build_parser().parse_args([])
    assert args.run is False
    assert args.enforce is False
    assert args.dry_run is False
    assert args.no_email is False
    assert args.verbose is False
    assert args.config is None
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_cli.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'security_monitor.cli'`

- [ ] **Step 3: Write the implementation**

`security_monitor/cli.py`:
```python
"""CLI dispatcher: menu (default on Windows), silent scan, setup, status, uninstall."""

from __future__ import annotations

import argparse
import logging
import socket
import sys
from datetime import datetime
from pathlib import Path

from security_monitor.config import (
    Config,
    ConfigError,
    load_config,
    run_setup_wizard,
)
from security_monitor.emailer import (
    EmailError,
    send_report,
    send_test_email,
    should_send,
)
from security_monitor.enforcement import EnforceResult, enforce
from security_monitor.platforms import list_installed_software
from security_monitor.reporter import (
    build_report,
    purge_old_files,
    save_report,
    subject_for,
)
from security_monitor.scanner import (
    ScannerError,
    dedupe_software,
    load_blacklist,
    match_violations,
)
from security_monitor.sysinfo import collect_system_info
from security_monitor.task import TASK_NAME, task_details, task_exists

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_VIOLATIONS = 2

WINDOWS_INSTALL_CONFIG = Path(r"C:\Security Monitor\config.ini")


def resolve_config_path(arg: str | None) -> Path:
    if arg:
        return Path(arg)
    if sys.platform == "win32":
        for candidate in (WINDOWS_INSTALL_CONFIG, Path("config.ini")):
            if candidate.exists():
                return candidate
        return WINDOWS_INSTALL_CONFIG
    return Path("config.ini")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="security-monitor",
        description="Security Monitor - blacklist software scanning, opt-in enforcement, and email reporting",
    )
    parser.add_argument("--run", action="store_true", help="silent scan (used by the scheduled task)")
    parser.add_argument("--setup", action="store_true", help="interactive setup wizard")
    parser.add_argument("--status", action="store_true", help="show configuration and task status")
    parser.add_argument("--uninstall", action="store_true", help="remove the scheduled task and installed files (Windows)")
    parser.add_argument("--test-email", action="store_true", help="send a test email and exit")
    parser.add_argument("--enforce", action="store_true", help="enable enforcement for this run")
    parser.add_argument("--dry-run", action="store_true", help="report-only even if enforcement is enabled")
    parser.add_argument("--no-email", action="store_true", help="do not send email for this run")
    parser.add_argument("--verbose", action="store_true", help="debug-level logging")
    parser.add_argument("--config", default=None, help="path to config.ini")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.setup:
            return cmd_setup(args)
        if args.test_email:
            return cmd_test_email(args)
        if args.status:
            return cmd_status(args)
        if args.uninstall:
            return cmd_uninstall(args)
        if args.run:
            return cmd_run(args)
        if sys.platform == "win32":
            from security_monitor.menu import run_menu

            return run_menu()
        return cmd_run(args)
    except KeyboardInterrupt:
        print("\nInterrupted.")
        return EXIT_ERROR


def cmd_setup(args) -> int:
    config_path = resolve_config_path(args.config)
    try:
        run_setup_wizard(config_path, test_email_fn=_wizard_test_email)
    except ConfigError as exc:
        print(f"Setup failed: {exc}")
        return EXIT_ERROR
    print("Setup complete.")
    if sys.platform == "win32":
        print("Run security-monitor with no arguments to open the menu (install / status / settings).")
    return EXIT_OK


def _wizard_test_email(cfg: Config) -> bool:
    try:
        send_test_email(cfg.email)
    except EmailError as exc:
        print(f"Test email failed: {exc}")
        return False
    return True


def cmd_test_email(args) -> int:
    config_path = resolve_config_path(args.config)
    try:
        cfg = load_config(config_path)
    except ConfigError as exc:
        print(f"Error: {exc}")
        return EXIT_ERROR
    try:
        send_test_email(cfg.email)
    except EmailError as exc:
        print(f"Test email failed: {exc}")
        return EXIT_ERROR
    print("Test email sent successfully.")
    return EXIT_OK


def status_text(config_path: Path) -> str:
    lines = [f"Configuration : {config_path}"]
    try:
        load_config(config_path)
        lines.append("  status      : valid")
    except ConfigError as exc:
        lines.append(f"  status      : missing/invalid ({exc})")

    if sys.platform == "win32":
        if task_exists():
            lines.append(f'Scheduled task: present "{TASK_NAME}"')
            details = task_details()
            if details:
                lines.append(f"  next run    : {details.get('next_run', 'unknown')}")
                lines.append(f"  last run    : {details.get('last_run', 'unknown')}")
                lines.append(f"  last result : {details.get('last_result', 'unknown')}")
        else:
            lines.append("Scheduled task: not found")

    reports_dir = config_path.parent / "reports"
    reports = (
        sorted(reports_dir.glob("security_report_*.txt"), key=lambda p: p.stat().st_mtime, reverse=True)
        if reports_dir.exists()
        else []
    )
    lines.append(f"Last report   : {reports[0].name}" if reports else "Last report   : none")
    return "\n".join(lines)


def cmd_status(args) -> int:
    print(status_text(resolve_config_path(args.config)))
    return EXIT_OK


def cmd_uninstall(args) -> int:
    if sys.platform != "win32":
        print("Uninstall is only available on Windows.")
        return EXIT_ERROR
    from security_monitor.installer import DEFAULT_INSTALL_DIR, remove_install_dir

    answer = input(f'Delete scheduled task and remove "{DEFAULT_INSTALL_DIR}"? [y/N]: ')
    if answer.strip().lower() not in ("y", "yes"):
        print("Aborted.")
        return EXIT_OK
    if task_exists():
        from security_monitor.task import delete_task

        delete_task()
        print(f'✔ Scheduled task "{TASK_NAME}" removed.')
    else:
        print("ℹ No scheduled task to remove.")
    if remove_install_dir(DEFAULT_INSTALL_DIR):
        print(f"✔ Removed {DEFAULT_INSTALL_DIR}")
    else:
        print(f"ℹ Could not fully remove {DEFAULT_INSTALL_DIR} (files in use) - delete manually after reboot.")
    return EXIT_OK


def _setup_logging(config_path: Path, verbose: bool) -> logging.Logger:
    logs_dir = config_path.parent / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("security_monitor")
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    logger.handlers.clear()
    formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    file_handler = logging.FileHandler(logs_dir / f"security_monitor_{timestamp}.log", encoding="utf-8")
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)
    return logger


def cmd_run(args) -> int:
    config_path = resolve_config_path(args.config)
    try:
        cfg = load_config(config_path)
    except ConfigError as exc:
        logging.getLogger("security_monitor").error("%s", exc)
        print(f"Error: {exc}")
        print("Run 'security-monitor --setup' first.")
        return EXIT_ERROR

    log = _setup_logging(config_path, args.verbose)
    log.info("Security Monitor scan starting (config=%s)", config_path)
    try:
        return _scan(cfg, config_path, args, log)
    except ScannerError as exc:
        log.error("%s", exc)
        return EXIT_ERROR
    except Exception as exc:  # noqa: BLE001 - top-level run guard for scheduled executions
        log.exception("Fatal error during scan")
        _notify_error(cfg, args, exc)
        return EXIT_ERROR


def _scan(cfg: Config, config_path: Path, args, log: logging.Logger) -> int:
    blacklist_path = Path(cfg.scan.blacklist_file)
    if not blacklist_path.is_absolute():
        blacklist_path = config_path.parent / blacklist_path
    blacklist = load_blacklist(blacklist_path)
    log.info("Loaded %d blacklist terms", len(blacklist))

    installed = dedupe_software(list_installed_software())
    log.info("Found %d installed software entries", len(installed))

    violations = match_violations(installed, blacklist)
    if violations:
        log.warning("Detected %d violation(s)", len(violations))

    enforce_result = EnforceResult()
    if cfg.scan.enforce or args.enforce:
        enforce_result = enforce(blacklist, dry_run=args.dry_run, logger=log)
    elif not args.dry_run:
        log.info("Enforcement disabled (report-only mode)")

    system_info = collect_system_info()
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    hostname = system_info.get("hostname", "Unknown")

    subject = subject_for(violations, hostname)
    body = build_report(cfg, system_info, violations, enforce_result, timestamp)

    reports_dir = config_path.parent / "reports"
    logs_dir = config_path.parent / "logs"
    report_path = save_report(subject, body, reports_dir, timestamp)
    purge_old_files(reports_dir, cfg.scan.retention_days)
    purge_old_files(logs_dir, cfg.scan.retention_days)

    email_state = None
    if not args.no_email and should_send(cfg.email.mode, len(violations), enforce_result.actioned, False):
        try:
            send_report(cfg.email, subject, body, report_path)
            email_state = "sent"
            log.info("Email report sent to %s", ", ".join(cfg.email.recipients))
        except EmailError as exc:
            email_state = f"failed ({exc})"
            log.warning("Email failed: %s", exc)

    print("=" * 60)
    print("SCAN SUMMARY")
    print(f"  Installed software scanned : {len(installed)}")
    print(f"  Violations found           : {len(violations)}")
    print(f"  Processes terminated       : {enforce_result.processes_killed}")
    print(f"  Services stopped           : {enforce_result.services_stopped}")
    if email_state is not None:
        print(f"  Email report               : {email_state}")
    print("=" * 60)

    return EXIT_VIOLATIONS if violations else EXIT_OK


def _notify_error(cfg: Config, args, exc: Exception) -> None:
    if args.no_email:
        return
    try:
        if should_send(cfg.email.mode, 0, False, True):
            subject = f"SECURITY MONITOR ERROR - {socket.gethostname()}"
            send_report(cfg.email, subject, f"Security Monitor run failed.\n\nError: {exc}")
    except EmailError:
        pass
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_cli.py -v`
Expected: all PASS

- [ ] **Step 5: Run the whole suite**

Run: `python -m pytest -v`
Expected: all PASS (every test file)

- [ ] **Step 6: Commit**

```bash
git add security_monitor/cli.py tests/test_cli.py
git -c user.name="Sujon" -c user.email="sujon@users.noreply.github.com" commit -m "feat: CLI dispatcher with scan pipeline, exit codes, and status text"
```

---

### Task 13: Build scripts & EXE smoke test

**Files:**
- Create: `scripts/build.ps1`, `scripts/build.sh`

**Interfaces:**
- Consumes: `requirements-dev.txt` (Task 1), `security_monitor/__main__.py` (entry).
- Produces: `dist/security-monitor.exe` (Windows, UAC admin manifest) / `dist/security-monitor` (Linux).

- [ ] **Step 1: Write build scripts**

`scripts/build.ps1`:
```powershell
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

python -m pip install --quiet -r requirements-dev.txt
if ($LASTEXITCODE -ne 0) { throw "pip install failed" }

python -m PyInstaller --onefile --clean --noconfirm --uac-admin --name security-monitor --paths $Root (Join-Path $Root "security_monitor\__main__.py")
if ($LASTEXITCODE -ne 0) { throw "PyInstaller build failed" }

Write-Host "Built: $Root\dist\security-monitor.exe"
```

`scripts/build.sh`:
```bash
#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

python3 -m pip install --quiet -r requirements-dev.txt
python3 -m PyInstaller --onefile --clean --noconfirm --name security-monitor --paths . security_monitor/__main__.py
echo "Built: dist/security-monitor"
```

- [ ] **Step 2: Make the shell script executable and build on Windows**

Run: `powershell -ExecutionPolicy Bypass -File scripts\build.ps1`
Expected: prints `Built: ...\dist\security-monitor.exe` (PyInstaller downloads/uses pinned deps; takes 1-3 minutes)

- [ ] **Step 3: Smoke-test the EXE**

Run: `& .\dist\security-monitor.exe --help`
Expected: UAC elevation prompt (manifest requires admin) → help text listing all flags → exit code 0.

Verify: `echo $LASTEXITCODE` → `0`.

- [ ] **Step 4: Smoke-test silent mode without config**

Run: `& .\dist\security-monitor.exe --run --config C:\nonexistent\config.ini`
Expected: `Error: config not found...` + `Run 'security-monitor --setup' first.` → exit code `1`.

- [ ] **Step 5: Commit**

```bash
git add scripts/build.ps1 scripts/build.sh
git -c user.name="Sujon" -c user.email="sujon@users.noreply.github.com" commit -m "build: PyInstaller onefile build scripts with UAC manifest"
```

(`dist/`, `build/`, `*.spec` are gitignored — not committed.)

---

### Task 14: README

**Files:**
- Create: `README.md`

**Interfaces:**
- Consumes: all modules, CLI flags, menu options, config keys, exit codes from prior tasks.
- Produces: complete user + developer documentation.

- [ ] **Step 1: Write the README**

`README.md`:
```markdown
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
```

- [ ] **Step 2: Commit**

```bash
git add README.md
git -c user.name="Sujon" -c user.email="sujon@users.noreply.github.com" commit -m "docs: README with setup walkthrough, menu/task/config reference, and security notes"
```

---

### Task 15: Full verification

**Files:** none (verification only)

- [ ] **Step 1: Full test suite**

Run: `python -m pytest -v`
Expected: every test PASS, no warnings that indicate API misuse.

- [ ] **Step 2: Syntax/compile check of the package**

Run: `python -m compileall -q security_monitor`
Expected: no output (success).

- [ ] **Step 3: EXE rebuild + flag smoke tests**

Run:
```powershell
powershell -ExecutionPolicy Bypass -File scripts\build.ps1
& .\dist\security-monitor.exe --help
echo $LASTEXITCODE   # expect 0
```

- [ ] **Step 4: Manual verification checklist (requires user + admin)**

- [ ] `--setup` / menu wizard completes; test email arrives (Gmail app password).
- [ ] Menu option 1 installs to `C:\Security Monitor\` and reports `✔ Scheduled task "Security Monitor" created — runs at boot and every 4h.`
- [ ] `schtasks /Query /TN "Security Monitor" /FO LIST /V` shows the task (boot trigger + repetition, SYSTEM).
- [ ] Menu option 2 shows status incl. next/last run.
- [ ] Change interval via option 3 → `✔ Task "Security Monitor" updated.` and `schtasks` shows the new interval.
- [ ] Menu option 4 runs a scan; a `security_report_*.txt` appears in `C:\Security Monitor\reports\`.
- [ ] With violations present (temporarily add a term matching installed software) and `mode = violations`, menu option 4 reports "violations found" and an alert email arrives.
- [ ] `& .\dist\security-monitor.exe --run --config "C:\Security Monitor\config.ini"; echo $LASTEXITCODE` → `2` when violations exist, `0` when clean.
- [ ] Reboot → task runs automatically (check `logs\security_monitor_*.log`).
- [ ] Menu option 5 uninstall → task gone, folder removed (or reported as in-use).
- [ ] Re-run installer → `ℹ Task "Security Monitor" already exists — choose option 3 to update it.`

- [ ] **Step 5: Commit anything re-fixed**

```bash
git add -A
git -c user.name="Sujon" -c user.email="sujon@users.noreply.github.com" commit -m "chore: verification fixes (if any)"
```
(If nothing changed, skip this commit.)

---

### Task 16: GitHub repo creation & push

**Files:** none (remote setup)

- [ ] **Step 1: Install and authenticate the GitHub CLI**

Run:
```powershell
winget install --id GitHub.cli -e
```
Then in a **new** shell:
```powershell
gh auth login
```
(Follow the interactive flow: GitHub.com → HTTPS → login via browser.)

Verify: `gh auth status` → shows logged in.

If `winget` is unavailable: install from `https://cli.github.com/` and re-open the shell.

- [ ] **Step 2: Review what will be pushed**

Run:
```powershell
git status --short
git log --oneline -10
git ls-files
```
Expected: working tree clean; `config.ini`, `logs/`, `reports/`, `dist/`, `build/`, `*.spec` **not** tracked; history is the scaffolding→README commits plus spec commits.

- [ ] **Step 3: Create the public repo and push**

Run:
```powershell
gh repo create security-monitor --public --source=. --push
```
Expected: creates `github.com/<you>/security-monitor`, adds `origin`, pushes `main`.

- [ ] **Step 4: Verify the remote**

Run:
```powershell
gh repo view --json name,visibility,url -q '.url + " (" + .visibility + ")"'
git status -sb
```
Expected: URL printed, visibility `PUBLIC`, branch tracking `origin/main`, clean.

---

## Self-Review Notes

- **Spec coverage:** config+wizard (T2), scanner/platforms (T3-4), sysinfo (T5), enforcement opt-in/protect-list/self-pid (T6), reporter+retention+ASCII (T7), email modes/465-SSL/test-email (T8), task XML boot+PTnH+SYSTEM+overwrite (T9), installer self-copy to `C:\Security Monitor` (T10), menu with exact notification strings (T11), CLI exit codes 0/1/2 + missing-config behavior (T12), UAC onefile builds (T13), README incl. cron/security notes (T14), manual checklist from spec §11 (T15), public `security-monitor` push (T16). Legacy scripts deleted in T1.
- **Placeholders:** none — every step carries complete code/commands.
- **Type consistency:** `EmailConfig/ScanConfig/OrgConfig/Config` used identically across T2/T7/T8/T11/T12; `EnforceResult(services_stopped, processes_killed)` consistent T6→T7→T12; `task_exists/register_task/delete_task/task_details` runner kwarg consistent T9→T12; `load_blacklist/match_violations/dedupe_software` return shapes T3→T12; `should_send/send_report/send_test_email/EmailError` T8→T11→T12; menu monkeypatch names match imported names in `menu.py`.

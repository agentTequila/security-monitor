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
    try:
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
    except (configparser.Error, ValueError) as exc:
        raise ConfigError(f"invalid config {config_path}: {exc}") from exc
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

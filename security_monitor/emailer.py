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

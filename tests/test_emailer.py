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

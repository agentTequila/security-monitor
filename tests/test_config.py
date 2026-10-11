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
    cfg.org.company_name = "agentTequila"
    cfgmod.save_config(cfg, path)
    loaded = cfgmod.load_config(path)
    assert loaded.email.sender == "me@gmail.com"
    assert loaded.email.recipients == ["soc@example.com"]
    assert loaded.scan.interval_hours == 6
    assert loaded.org.company_name == "agentTequila"


def test_save_and_load_roundtrip_with_percent_in_password(tmp_path):
    path = tmp_path / "config.ini"
    cfg = _valid_cfg()
    cfg.email.app_password = "ab%cd ef%gh"
    cfg.email.smtp_port = 465
    cfgmod.save_config(cfg, path)
    loaded = cfgmod.load_config(path)
    assert loaded.email.app_password == "ab%cd ef%gh"
    assert loaded.email.smtp_port == 465


def test_load_missing_file_raises(tmp_path):
    with pytest.raises(cfgmod.ConfigError):
        cfgmod.load_config(tmp_path / "nope.ini")


def test_load_missing_section_header_raises(tmp_path):
    path = tmp_path / "config.ini"
    path.write_text("mode = violations\n", encoding="utf-8")
    with pytest.raises(cfgmod.ConfigError):
        cfgmod.load_config(path)


def test_load_non_integer_smtp_port_raises(tmp_path):
    path = tmp_path / "config.ini"
    path.write_text(
        "[email]\nmode = violations\nsender = me@gmail.com\n"
        "recipients = a@b.com\napp_password = pw\nsmtp_port = abc\n",
        encoding="utf-8",
    )
    with pytest.raises(cfgmod.ConfigError):
        cfgmod.load_config(path)


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
        "smtp.gmail.com", "587", "agentTequila", "SOC",
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
        "smtp.gmail.com", "587", "agentTequila", "SOC",
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

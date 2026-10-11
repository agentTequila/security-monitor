from pathlib import Path

from security_monitor import cli, config as cfgmod


def _write_config(
    tmp_path: Path,
    blacklist_terms: str,
    installed: list[dict],
    monkeypatch,
    *,
    enforce: bool = False,
    email_mode: str = "never",
) -> Path:
    cfg = cfgmod.Config()
    cfg.email.mode = email_mode
    cfg.scan.enforce = enforce
    (tmp_path / "blacklist_software.txt").write_text(blacklist_terms, encoding="utf-8")
    path = tmp_path / "config.ini"
    cfgmod.save_config(cfg, path)
    monkeypatch.setattr(cli, "list_installed_software", lambda: installed)
    return path


WIRESHARK_ENTRY = {
    "name": "Wireshark 4.2",
    "version": "4.2",
    "publisher": "WS",
    "install_date": "20240101",
    "install_location": "C:\\ws",
}


def _fake_enforce(recorder: list):
    def fake_enforce(blacklist, *, dry_run=False, logger=None):
        recorder.append(dry_run)
        return cli.EnforceResult()

    return fake_enforce


def _fake_send(recorder: list):
    def fake_send(*args, **kwargs):
        recorder.append(args)

    return fake_send


def _patch_enforcement(monkeypatch) -> list:
    recorder: list = []
    monkeypatch.setattr(cli, "enforce", _fake_enforce(recorder))
    return recorder


def _patch_email(monkeypatch) -> list:
    recorder: list = []
    monkeypatch.setattr(cli, "send_report", _fake_send(recorder))
    return recorder


def test_default_run_never_calls_enforce(tmp_path, monkeypatch):
    path = _write_config(tmp_path, "wireshark\n", [WIRESHARK_ENTRY], monkeypatch, enforce=False)
    enforce_rec = _patch_enforcement(monkeypatch)
    send_rec = _patch_email(monkeypatch)
    code = cli.main(["--run", "--config", str(path)])
    assert enforce_rec == []
    assert code == cli.EXIT_VIOLATIONS
    assert send_rec == []


def test_config_enforce_enables_live_mode(tmp_path, monkeypatch):
    path = _write_config(tmp_path, "wireshark\n", [WIRESHARK_ENTRY], monkeypatch, enforce=True)
    enforce_rec = _patch_enforcement(monkeypatch)
    _patch_email(monkeypatch)
    code = cli.main(["--run", "--config", str(path)])
    assert enforce_rec == [False]
    assert code == cli.EXIT_VIOLATIONS


def test_dry_run_flag_overrides_config_enforce(tmp_path, monkeypatch):
    path = _write_config(tmp_path, "wireshark\n", [WIRESHARK_ENTRY], monkeypatch, enforce=True)
    enforce_rec = _patch_enforcement(monkeypatch)
    _patch_email(monkeypatch)
    code = cli.main(["--run", "--dry-run", "--config", str(path)])
    assert enforce_rec == [True]
    assert code == cli.EXIT_VIOLATIONS


def test_enforce_flag_enables_without_config(tmp_path, monkeypatch):
    path = _write_config(tmp_path, "wireshark\n", [WIRESHARK_ENTRY], monkeypatch, enforce=False)
    enforce_rec = _patch_enforcement(monkeypatch)
    _patch_email(monkeypatch)
    code = cli.main(["--run", "--enforce", "--config", str(path)])
    assert enforce_rec == [False]
    assert code == cli.EXIT_VIOLATIONS


def test_email_never_mode_skips_send(tmp_path, monkeypatch):
    path = _write_config(tmp_path, "wireshark\n", [WIRESHARK_ENTRY], monkeypatch, email_mode="never")
    _patch_enforcement(monkeypatch)
    send_rec = _patch_email(monkeypatch)
    code = cli.main(["--run", "--config", str(path)])
    assert send_rec == []
    assert code == cli.EXIT_VIOLATIONS


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

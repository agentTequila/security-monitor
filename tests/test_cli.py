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

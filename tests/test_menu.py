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

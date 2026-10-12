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
    TaskError,
    delete_task,
    register_task,
    task_exists,
)

MENU_TEXT = """
    ______
   /      \\
  |  \\  /  |
  |   \\/   |
   \\      /
    '----'
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
        try:
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
        except (KeyboardInterrupt, EOFError):
            output_fn("\nGoodbye.")
            return 0
        except (TaskError, OSError) as exc:
            output_fn(f"Error: {exc}")


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

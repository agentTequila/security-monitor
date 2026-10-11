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
EXIT_FATAL = EXIT_ERROR
EXIT_VIOLATIONS = 2

WINDOWS_INSTALL_CONFIG = Path(r"C:\Security Monitor\config.ini")


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:  # usage errors are fatal, not "violations"
        self.print_usage(sys.stderr)
        self.exit(EXIT_FATAL, f"{self.prog}: error: {message}\n")


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
    parser = _Parser(
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
    try:
        args = build_parser().parse_args(argv)
    except SystemExit as exc:  # argparse usage/--help exits become return codes
        code = exc.code
        return code if isinstance(code, int) else EXIT_FATAL
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

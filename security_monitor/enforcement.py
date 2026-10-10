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


def _identifier_protected(identifier: str) -> bool:
    hay = (identifier or "").strip().lower()
    if not hay:
        return False
    if hay in PROTECT_NAMES:
        return True
    return any(hay.startswith(p + "-") or hay.startswith(p + ".") for p in PROTECT_NAMES)


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


def _stop_matching_services(patterns: list[str], dry_run: bool, logger: logging.Logger) -> int:
    log = logger
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
            if _identifier_protected(name) or _identifier_protected(display):
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
        if _identifier_protected(unit):
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


def _kill_matching_processes(patterns: list[str], dry_run: bool, logger: logging.Logger) -> int:
    log = logger
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
                try:
                    target.wait(timeout=3)
                except psutil.TimeoutExpired:
                    log.error("Process %s (PID %s) did not exit after kill", name, pid)
                    continue
            killed += 1
            log.warning("TERMINATED PROCESS: %s (PID %s) matched %r", name, pid, matched)
        except (psutil.NoSuchProcess, psutil.AccessDenied) as exc:
            log.error("Failed to terminate %s (PID %s): %s", name, pid, exc)
    return killed

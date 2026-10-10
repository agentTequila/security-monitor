import logging
import os

from security_monitor import enforcement


class FakeProc:
    def __init__(self, info):
        self.info = info


def test_is_protected_names():
    assert enforcement.is_protected("csrss.exe")
    assert enforcement.is_protected("systemd")
    assert enforcement.is_protected("lsass")
    assert not enforcement.is_protected("Wireshark.exe")


def test_process_matches_returns_term():
    term = enforcement.process_matches(
        "Wireshark.exe", "C:\\Tools\\Wireshark\\Wireshark.exe", "", ["wireshark"]
    )
    assert term == "wireshark"


def test_process_matches_never_matches_protected():
    term = enforcement.process_matches(
        "lsass.exe", "C:\\Windows\\System32\\lsass.exe", "", ["lsass"]
    )
    assert term is None


def test_process_matches_checks_cmdline():
    term = enforcement.process_matches("python.exe", "", "python -m netcat.helper", ["netcat"])
    assert term == "netcat"


def test_enforce_empty_blacklist_returns_zero():
    result = enforcement.enforce([])
    assert result.services_stopped == 0
    assert result.processes_killed == 0
    assert not result.actioned


def test_kill_dry_run_logs_match_and_spares_protected(monkeypatch, caplog):
    fakes = [
        FakeProc({"pid": 999999999, "name": "Wireshark.exe", "exe": "C:\\ws\\Wireshark.exe", "cmdline": []}),
        FakeProc({"pid": 222, "name": "lsass.exe", "exe": "C:\\Windows\\lsass.exe", "cmdline": []}),
        FakeProc({"pid": os.getpid(), "name": "security-monitor.exe", "exe": "C:\\app\\security-monitor.exe", "cmdline": []}),
    ]
    monkeypatch.setattr(enforcement.psutil, "process_iter", lambda attrs: iter(fakes))
    logger = logging.getLogger("test_enforcement")
    with caplog.at_level(logging.INFO, logger="test_enforcement"):
        killed = enforcement._kill_matching_processes(["wireshark", "lsass"], dry_run=True, logger=logger)
    assert killed == 0
    text = caplog.text
    assert "[DRY-RUN] Would terminate" in text and "Wireshark.exe" in text
    assert "lsass.exe" not in text
    assert "security-monitor" not in text


def test_kill_skips_own_pid(monkeypatch, caplog):
    fakes = [FakeProc({"pid": os.getpid(), "name": "Wireshark.exe", "exe": "", "cmdline": []})]
    monkeypatch.setattr(enforcement.psutil, "process_iter", lambda attrs: iter(fakes))
    logger = logging.getLogger("test_enforcement")
    with caplog.at_level(logging.INFO, logger="test_enforcement"):
        enforcement._kill_matching_processes(["wireshark"], dry_run=True, logger=logger)
    assert "Would terminate" not in caplog.text


def test_kill_timeout_after_kill_does_not_raise_and_not_counted(monkeypatch):
    fakes = [FakeProc({"pid": 999999999, "name": "Wireshark.exe", "exe": "C:\\ws\\Wireshark.exe", "cmdline": []})]

    class AlwaysTimeoutProc:
        def __init__(self, pid):
            self.pid = pid

        def ppid(self):
            return 1

        def terminate(self):
            pass

        def kill(self):
            pass

        def wait(self, timeout=None):
            raise enforcement.psutil.TimeoutExpired(timeout)

    monkeypatch.setattr(enforcement.psutil, "process_iter", lambda attrs: iter(fakes))
    monkeypatch.setattr(enforcement.psutil, "Process", AlwaysTimeoutProc)
    logger = logging.getLogger("test_enforcement")
    killed = enforcement._kill_matching_processes(["wireshark"], dry_run=False, logger=logger)
    assert killed == 0


def test_linux_protected_units_never_stopped(monkeypatch):
    stop_calls = []

    class FakeCompleted:
        def __init__(self, stdout=""):
            self.stdout = stdout
            self.stderr = ""
            self.returncode = 0

    def fake_run(cmd, **kwargs):
        if cmd[:2] == ["systemctl", "list-units"]:
            return FakeCompleted(
                "  systemd-journald.service loaded active running System Journal Service\n"
            )
        if cmd[:2] == ["systemctl", "stop"]:
            stop_calls.append(list(cmd))
            return FakeCompleted()
        return FakeCompleted()

    monkeypatch.setattr(enforcement.platform, "system", lambda: "Linux")
    monkeypatch.setattr(enforcement.subprocess, "run", fake_run)
    logger = logging.getLogger("test_enforcement")
    stopped = enforcement._stop_matching_services(["system"], dry_run=False, logger=logger)
    assert stopped == 0
    assert stop_calls == []


def test_windows_protected_service_never_stopped(monkeypatch):
    stop_calls = []

    class FakeService:
        def as_dict(self):
            return {"name": "systemd-junk", "display_name": "Systemd Junk"}

        def stop(self):
            stop_calls.append("stop")

    monkeypatch.setattr(enforcement.platform, "system", lambda: "Windows")
    monkeypatch.setattr(enforcement.psutil, "win_service_iter", lambda: [FakeService()])
    logger = logging.getLogger("test_enforcement")
    stopped = enforcement._stop_matching_services(["system"], dry_run=False, logger=logger)
    assert stopped == 0
    assert stop_calls == []

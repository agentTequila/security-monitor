import os
import time

from security_monitor import reporter
from security_monitor.config import Config
from security_monitor.enforcement import EnforceResult

VIOLATION = {
    "name": "Wireshark 4.2", "version": "4.2", "publisher": "WS",
    "install_date": "20240101", "install_location": "C:\\ws",
    "matched_term": "wireshark", "risk_level": "MEDIUM",
}
INFO = {"hostname": "DESKTOP-TEST", "username": "alice", "scan_time": "2026-10-10 09:00:00"}


def test_subject_alert_and_ok():
    assert reporter.subject_for([VIOLATION], "HOST1") == \
        "SECURITY ALERT: 1 violation(s) (0 high) - HOST1"
    assert reporter.subject_for([], "HOST1") == "SECURITY OK: no violations - HOST1"


def test_build_report_contains_violation_details():
    body = reporter.build_report(Config(), INFO, [VIOLATION], EnforceResult(processes_killed=2), "20261010_090000")
    assert "Wireshark 4.2" in body
    assert "MEDIUM RISK" in body
    assert "Matched   : wireshark" in body
    assert any("Processes terminated" in line and line.rstrip().endswith(": 2")
               for line in body.splitlines())
    assert "DESKTOP-TEST" in body
    assert "RECOMMENDED ACTIONS" in body
    assert not any(ch > "\u2500" for ch in body), "report must stay plain ASCII-ish (no emoji)"


def test_build_report_clean_status():
    body = reporter.build_report(Config(), INFO, [], EnforceResult(), "20261010_090000")
    assert "SYSTEM COMPLIANCE STATUS: CLEAN" in body
    assert "RECOMMENDED ACTIONS" not in body


def test_save_report_writes_subject_header(tmp_path):
    path = reporter.save_report("SUBJ", "BODY line", tmp_path, "20261010_090000")
    content = path.read_text(encoding="utf-8")
    assert path.name == "security_report_20261010_090000.txt"
    assert content == "Subject: SUBJ\n\nBODY line\n"


def test_purge_old_files(tmp_path):
    old = tmp_path / "old.txt"
    new = tmp_path / "new.txt"
    old.write_text("x", encoding="utf-8")
    new.write_text("y", encoding="utf-8")
    ancient = time.time() - 40 * 86400
    os.utime(old, (ancient, ancient))
    removed = reporter.purge_old_files(tmp_path, 30)
    assert removed == 1
    assert not old.exists() and new.exists()


def test_purge_missing_dir_is_safe(tmp_path):
    assert reporter.purge_old_files(tmp_path / "nope", 30) == 0

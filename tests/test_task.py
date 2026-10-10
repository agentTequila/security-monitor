import subprocess

import pytest

from security_monitor import task


def test_xml_contains_triggers_principal_and_action():
    xml = task.build_task_xml(r"C:\Security Monitor\security-monitor.exe", 4)
    assert "<BootTrigger>" in xml
    assert "<Interval>PT4H</Interval>" in xml
    assert "<UserId>S-1-5-18</UserId>" in xml
    assert "<LogonType>ServiceAccount</LogonType>" in xml
    assert "<RunLevel>HighestAvailable</RunLevel>" in xml
    assert "<Hidden>true</Hidden>" in xml
    assert "security-monitor.exe" in xml
    assert "--run --config" in xml
    assert "config.ini" in xml


def test_xml_interval_12h():
    xml = task.build_task_xml(r"C:\Security Monitor\security-monitor.exe", 12)
    assert "<Interval>PT12H</Interval>" in xml


def test_register_task_invokes_schtasks_with_xml():
    calls = []

    def fake_runner(cmd, **kwargs):
        calls.append((cmd, kwargs))
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    task.register_task(r"C:\Security Monitor\security-monitor.exe", 4, runner=fake_runner)
    cmd, kwargs = calls[0]
    assert cmd[0] == "schtasks"
    assert cmd[1:4] == ["/Create", "/TN", "Security Monitor"]
    assert "/XML" in cmd
    assert "/F" in cmd
    assert kwargs.get("capture_output") is True


def test_register_task_failure_raises():
    def fake_runner(cmd, **kwargs):
        return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="boom")

    with pytest.raises(task.TaskError, match="boom"):
        task.register_task(r"C:\x\security-monitor.exe", 4, runner=fake_runner)


def test_task_exists_true_and_false():
    ok = lambda cmd, **kw: subprocess.CompletedProcess(cmd, 0)
    missing = lambda cmd, **kw: subprocess.CompletedProcess(cmd, 1)
    assert task.task_exists(runner=ok) is True
    assert task.task_exists(runner=missing) is False


def test_delete_task_uses_delete_command():
    calls = []

    def fake_runner(cmd, **kw):
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 0)

    assert task.delete_task(runner=fake_runner) is True
    assert calls[0][:2] == ["schtasks", "/Delete"]
    assert "/F" in calls[0]


def test_task_details_parses_list_output():
    stdout = (
        "HostName:                  HOST\n"
        "TaskName:                  \\Security Monitor\n"
        "Next Run Time:             10/11/2026 9:00:00 AM\n"
        "Last Run Time:             10/10/2026 7:00:00 AM\n"
        "Last Result:               0\n"
    )

    def fake_runner(cmd, **kw):
        return subprocess.CompletedProcess(cmd, 0, stdout=stdout, stderr="")

    details = task.task_details(runner=fake_runner)
    assert details["next_run"] == "10/11/2026 9:00:00 AM"
    assert details["last_result"] == "0"


def test_task_details_empty_when_absent():
    def fake_runner(cmd, **kw):
        return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="")

    assert task.task_details(runner=fake_runner) == {}

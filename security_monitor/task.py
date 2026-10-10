"""Windows Task Scheduler lifecycle: build XML, register, query, delete."""

from __future__ import annotations

import os
import subprocess
import tempfile
from datetime import datetime
from pathlib import Path
from xml.sax.saxutils import escape as xml_escape

TASK_NAME = "Security Monitor"

_DETAIL_KEYS = {
    "next run time": "next_run",
    "last run time": "last_run",
    "last result": "last_result",
}


class TaskError(Exception):
    """Raised when a schtasks operation fails."""


def build_task_xml(exe_path: str, interval_hours: int) -> str:
    exe = xml_escape(str(exe_path))
    config = xml_escape(str(Path(exe_path).parent / "config.ini"))
    start_boundary = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
    return f"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>Security Monitor - scans for blacklisted software at boot and every {interval_hours}h.</Description>
    <Author>Cyber Sujon</Author>
    <URI>\\Security Monitor</URI>
  </RegistrationInfo>
  <Triggers>
    <BootTrigger>
      <Enabled>true</Enabled>
    </BootTrigger>
    <TimeTrigger>
      <StartBoundary>{start_boundary}</StartBoundary>
      <Repetition>
        <Interval>PT{interval_hours}H</Interval>
        <StopAtDurationEnd>false</StopAtDurationEnd>
      </Repetition>
      <Enabled>true</Enabled>
    </TimeTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>
      <LogonType>ServiceAccount</LogonType>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <StartWhenAvailable>true</StartWhenAvailable>
    <ExecutionTimeLimit>PT1H</ExecutionTimeLimit>
    <AllowHardTerminate>true</AllowHardTerminate>
    <Hidden>true</Hidden>
    <Enabled>true</Enabled>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{exe}</Command>
      <Arguments>--run --config &quot;{config}&quot;</Arguments>
      <WorkingDirectory>{xml_escape(str(Path(exe_path).parent))}</WorkingDirectory>
    </Exec>
  </Actions>
</Task>
"""


def _run(runner, cmd: list[str]) -> subprocess.CompletedProcess:
    return runner(cmd, capture_output=True, text=True)


def register_task(
    exe_path: str,
    interval_hours: int,
    task_name: str = TASK_NAME,
    runner=subprocess.run,
) -> None:
    xml = build_task_xml(exe_path, interval_hours)
    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(
            "w", suffix=".xml", delete=False, encoding="utf-16"
        ) as handle:
            handle.write(xml)
            tmp_path = handle.name
        result = _run(runner, ["schtasks", "/Create", "/TN", task_name, "/XML", tmp_path, "/F"])
        if result.returncode != 0:
            detail = (result.stderr or result.stdout or "").strip() or "schtasks /Create failed"
            raise TaskError(detail)
    finally:
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
            except OSError:
                pass


def task_exists(task_name: str = TASK_NAME, runner=subprocess.run) -> bool:
    result = _run(runner, ["schtasks", "/Query", "/TN", task_name])
    return result.returncode == 0


def delete_task(task_name: str = TASK_NAME, runner=subprocess.run) -> bool:
    result = _run(runner, ["schtasks", "/Delete", "/TN", task_name, "/F"])
    return result.returncode == 0


def task_details(task_name: str = TASK_NAME, runner=subprocess.run) -> dict:
    """Query a task's details.

    Caveat: parses the English-locale labels of ``schtasks /Query /V``
    (e.g. "Next Run Time", "Last Run Time", "Last Result"). On systems
    with a non-English UI the lookup misses, so the corresponding keys
    are absent from the returned dict; an absent task returns ``{}``.
    """
    if not task_exists(task_name, runner=runner):
        return {}
    result = _run(runner, ["schtasks", "/Query", "/TN", task_name, "/FO", "LIST", "/V"])
    if result.returncode != 0:
        return {}
    details: dict = {}
    for line in (result.stdout or "").splitlines():
        key, sep, value = line.partition(":")
        if not sep:
            continue
        mapped = _DETAIL_KEYS.get(key.strip().lower())
        if mapped:
            details[mapped] = value.strip()
    return details

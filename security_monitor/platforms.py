"""OS adapters: installed-software inventory (Windows registry, Linux dpkg/rpm)."""

from __future__ import annotations

import platform
import shutil
import subprocess

_REQUIRED = ("name", "version", "publisher", "install_date", "install_location")


def list_installed_software() -> list[dict]:
    system = platform.system()
    if system == "Windows":
        return _list_windows()
    if system == "Linux":
        return _list_linux()
    return []


def _list_windows() -> list[dict]:
    try:
        import winreg
    except ImportError:
        return []
    results: list[dict] = []
    registry_paths = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
    ]
    for hkey, subkey in registry_paths:
        try:
            with winreg.OpenKey(hkey, subkey) as root:
                for index in range(winreg.QueryInfoKey(root)[0]):
                    try:
                        with winreg.OpenKey(root, winreg.EnumKey(root, index)) as prog:
                            name = _reg_value(winreg, prog, "DisplayName")
                            if name == "Unknown":
                                continue
                            results.append(
                                {
                                    "name": name,
                                    "version": _reg_value(winreg, prog, "DisplayVersion"),
                                    "publisher": _reg_value(winreg, prog, "Publisher"),
                                    "install_date": _reg_value(winreg, prog, "InstallDate"),
                                    "install_location": _reg_value(winreg, prog, "InstallLocation"),
                                }
                            )
                    except OSError:
                        continue
        except OSError:
            continue
    return results


def _reg_value(winreg, key, value_name: str) -> str:
    try:
        raw = winreg.QueryValueEx(key, value_name)[0]
        text = str(raw).strip()
        return text if text else "Unknown"
    except (FileNotFoundError, OSError):
        return "Unknown"


def _list_linux() -> list[dict]:
    results: list[dict] = []
    if shutil.which("dpkg-query"):
        proc = subprocess.run(
            ["dpkg-query", "-W", "-f=${Package}\t${Version}\t${Maintainer}\t${Status}\n"],
            capture_output=True, text=True, check=False,
        )
        results.extend(parse_dpkg_output(proc.stdout))
    if not results and shutil.which("rpm"):
        proc = subprocess.run(
            ["rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\t%{VENDOR}\n"],
            capture_output=True, text=True, check=False,
        )
        results.extend(parse_rpm_output(proc.stdout))
    return results


def parse_dpkg_output(text: str) -> list[dict]:
    results: list[dict] = []
    for line in text.splitlines():
        parts = line.split("\t")
        if len(parts) < 4 or "installed" not in parts[3]:
            continue
        results.append(
            {
                "name": parts[0].strip(),
                "version": parts[1].strip() or "Unknown",
                "publisher": parts[2].strip() or "Unknown",
                "install_date": "Unknown",
                "install_location": "Unknown",
            }
        )
    return results


def parse_rpm_output(text: str) -> list[dict]:
    results: list[dict] = []
    for line in text.splitlines():
        parts = line.split("\t")
        if len(parts) < 2 or not parts[0].strip():
            continue
        results.append(
            {
                "name": parts[0].strip(),
                "version": parts[1].strip() or "Unknown",
                "publisher": (parts[2].strip() if len(parts) > 2 and parts[2].strip() else "Unknown"),
                "install_date": "Unknown",
                "install_location": "Unknown",
            }
        )
    return results

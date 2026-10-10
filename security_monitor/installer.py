"""Deploy/repair/remove the C:\\Security Monitor installation."""

from __future__ import annotations

import shutil
from pathlib import Path

from security_monitor.scanner import write_default_blacklist

DEFAULT_INSTALL_DIR = Path(r"C:\Security Monitor")
EXE_NAME = "security-monitor.exe"


def is_installed(install_dir: str | Path) -> bool:
    return (Path(install_dir) / EXE_NAME).exists()


def install(
    source_exe: str | Path,
    install_dir: str | Path,
    cfg_path: str | Path | None = None,
    blacklist_src: str | Path | None = None,
) -> Path:
    target = Path(install_dir)
    target.mkdir(parents=True, exist_ok=True)

    source = Path(source_exe)
    destination_exe = target / EXE_NAME
    if source.resolve() != destination_exe.resolve():
        shutil.copy2(source, destination_exe)

    if cfg_path is not None:
        cfg_source = Path(cfg_path)
        cfg_dest = target / "config.ini"
        if cfg_source.exists() and cfg_source.resolve() != cfg_dest.resolve():
            shutil.copy2(cfg_source, cfg_dest)

    blacklist = target / "blacklist_software.txt"
    if not blacklist.exists():
        if blacklist_src is not None and Path(blacklist_src).exists():
            shutil.copy2(blacklist_src, blacklist)
        else:
            write_default_blacklist(blacklist)

    (target / "logs").mkdir(exist_ok=True)
    (target / "reports").mkdir(exist_ok=True)
    return target


def remove_install_dir(install_dir: str | Path) -> bool:
    target = Path(install_dir)
    if not target.exists():
        return False
    shutil.rmtree(target, ignore_errors=True)
    return not target.exists()

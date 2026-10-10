"""Host/user/OS/hardware information collection for reports."""

from __future__ import annotations

import getpass
import os
import platform
import socket
import time
from datetime import datetime

import psutil


def _format_uptime(boot_time: float, now: float) -> str:
    total_seconds = max(int(now - boot_time), 0)
    days, rem = divmod(total_seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, seconds = divmod(rem, 60)
    return f"{days} days, {hours}:{minutes:02d}:{seconds:02d}"


def collect_system_info() -> dict:
    try:
        hostname = socket.gethostname()
        try:
            fqdn = socket.getfqdn()
        except OSError:
            fqdn = hostname
        try:
            username = getpass.getuser()
        except Exception:
            username = os.environ.get("USERNAME") or os.environ.get("USER") or "Unknown"

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                sock.connect(("8.8.8.8", 80))
                ip_address = sock.getsockname()[0]
            finally:
                sock.close()
        except OSError:
            ip_address = "Unable to determine"

        os_info = f"{platform.system()} {platform.release()} {platform.version()} ({platform.machine()})"

        cpu_count = psutil.cpu_count(logical=False) or psutil.cpu_count() or 1
        cpu_threads = psutil.cpu_count(logical=True) or cpu_count
        cpu_freq = psutil.cpu_freq()
        freq_text = f"{cpu_freq.current:.1f}MHz" if cpu_freq else "Unknown"
        cpu_info = f"{platform.processor()} ({cpu_count} cores, {cpu_threads} threads @ {freq_text})"

        memory = psutil.virtual_memory()

        boot_time = datetime.fromtimestamp(psutil.boot_time()).strftime("%Y-%m-%d %H:%M:%S")
        uptime = _format_uptime(psutil.boot_time(), time.time())

        disk_path = os.environ.get("SystemDrive", "C:") + "\\" if platform.system() == "Windows" else "/"
        disk = psutil.disk_usage(disk_path)

        domain = os.environ.get("USERDOMAIN", "N/A")
        if domain == hostname:
            domain = "N/A"

        return {
            "hostname": hostname,
            "fqdn": fqdn,
            "username": username,
            "ip_address": ip_address,
            "os_info": os_info,
            "cpu_info": cpu_info,
            "memory_total": f"{memory.total / (1024 ** 3):.2f} GB",
            "memory_used": f"{memory.used / (1024 ** 3):.2f} GB",
            "memory_available": f"{memory.available / (1024 ** 3):.2f} GB",
            "memory_percent": f"{memory.percent:.1f}%",
            "domain": domain,
            "boot_time": boot_time,
            "uptime": uptime,
            "disk_used": f"{disk.used / (1024 ** 3):.2f} GB",
            "disk_total": f"{disk.total / (1024 ** 3):.2f} GB",
            "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }
    except Exception:
        return {}

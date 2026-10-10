from security_monitor import sysinfo

EXPECTED_KEYS = [
    "hostname", "fqdn", "username", "ip_address", "os_info", "cpu_info",
    "memory_total", "memory_used", "memory_available", "memory_percent",
    "domain", "boot_time", "uptime", "disk_used", "disk_total", "scan_time",
]


def test_collect_system_info_has_all_keys():
    info = sysinfo.collect_system_info()
    for key in EXPECTED_KEYS:
        assert key in info, f"missing key: {key}"


def test_collect_system_info_never_raises(monkeypatch):
    monkeypatch.setattr(sysinfo.psutil, "boot_time", lambda: (_ for _ in ()).throw(RuntimeError("boom")))
    info = sysinfo.collect_system_info()
    assert info == {}

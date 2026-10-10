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


def test_format_uptime_includes_real_seconds():
    assert sysinfo._format_uptime(1000.0, 1000.0 + 3661) == "0 days, 1:01:01"


def test_ip_lookup_error_returns_fallback_and_closes_socket(monkeypatch):
    closed = []

    class ExplodingSocket:
        def connect(self, address):
            raise OSError("network unreachable")

        def close(self):
            closed.append(True)

    monkeypatch.setattr(sysinfo.socket, "socket", lambda *args, **kwargs: ExplodingSocket())
    info = sysinfo.collect_system_info()
    assert info["ip_address"] == "Unable to determine"
    assert closed == [True]

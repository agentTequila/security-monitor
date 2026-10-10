from security_monitor import installer


def test_install_copies_exe_config_and_creates_dirs(tmp_path):
    source = tmp_path / "portable.exe"
    source.write_bytes(b"fake-exe")
    cfg = tmp_path / "config.ini"
    cfg.write_text("[email]\nmode = never\n", encoding="utf-8")
    target = tmp_path / "Security Monitor"

    result = installer.install(source, target, cfg_path=cfg)

    assert result == target
    assert (target / "security-monitor.exe").read_bytes() == b"fake-exe"
    assert (target / "config.ini").exists()
    assert (target / "blacklist_software.txt").exists()
    assert (target / "logs").is_dir()
    assert (target / "reports").is_dir()


def test_install_writes_default_blacklist_without_source(tmp_path):
    source = tmp_path / "portable.exe"
    source.write_bytes(b"x")
    target = tmp_path / "install"
    installer.install(source, target)
    content = (target / "blacklist_software.txt").read_text(encoding="utf-8")
    assert "wireshark" in content


def test_install_when_source_is_already_installed_copy(tmp_path):
    target = tmp_path / "install"
    target.mkdir()
    exe = target / "security-monitor.exe"
    exe.write_bytes(b"already")
    installer.install(exe, target)  # must not crash copying onto itself
    assert exe.read_bytes() == b"already"


def test_is_installed(tmp_path):
    target = tmp_path / "install"
    assert installer.is_installed(target) is False
    target.mkdir()
    (target / "security-monitor.exe").write_bytes(b"x")
    assert installer.is_installed(target) is True


def test_remove_install_dir(tmp_path):
    source = tmp_path / "s.exe"
    source.write_bytes(b"x")
    target = tmp_path / "install"
    installer.install(source, target)
    assert installer.remove_install_dir(target) is True
    assert not target.exists()
    assert installer.remove_install_dir(target) is False  # already gone


def test_install_does_not_clobber_existing_config(tmp_path):
    source = tmp_path / "portable.exe"
    source.write_bytes(b"x")
    first = tmp_path / "first.ini"
    first.write_text("[email]\nsender = a@example.com\n", encoding="utf-8")
    second = tmp_path / "second.ini"
    second.write_text("[email]\nsender = other@example.com\n", encoding="utf-8")
    target = tmp_path / "install"

    installer.install(source, target, cfg_path=first)
    installer.install(source, target, cfg_path=second)

    deployed = (target / "config.ini").read_text(encoding="utf-8")
    assert deployed == first.read_text(encoding="utf-8")

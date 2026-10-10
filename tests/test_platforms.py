from security_monitor import platforms

REQUIRED_KEYS = {"name", "version", "publisher", "install_date", "install_location"}


def test_parse_dpkg_output_only_installed():
    text = (
        "bash\t5.1-2+deb12u1\tDebian Maintainer <maint@deb.org>\tinstall ok installed\n"
        "removed-pkg\t1.0\tX <x@x.com>\tdeinstall ok config-files\n"
        "half-installed\t2.0\tY <y@y.com>\tinstall ok half-configured\n"
    )
    result = platforms.parse_dpkg_output(text)
    assert len(result) == 1
    assert result[0]["name"] == "bash"
    assert result[0]["version"] == "5.1-2+deb12u1"
    assert "maint@deb.org" in result[0]["publisher"]
    assert REQUIRED_KEYS <= set(result[0])


def test_parse_dpkg_output_empty():
    assert platforms.parse_dpkg_output("") == []


def test_parse_rpm_output():
    text = "httpd\t2.4.57-1.el9\tRed Hat, Inc.\n"
    result = platforms.parse_rpm_output(text)
    assert len(result) == 1
    assert result[0]["name"] == "httpd"
    assert result[0]["version"] == "2.4.57-1.el9"
    assert result[0]["publisher"] == "Red Hat, Inc."
    assert REQUIRED_KEYS <= set(result[0])


def test_list_installed_software_returns_dicts_with_keys():
    result = platforms.list_installed_software()
    assert isinstance(result, list)
    for item in result:
        assert REQUIRED_KEYS <= set(item)

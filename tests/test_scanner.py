from pathlib import Path

import pytest

from security_monitor import scanner


def test_load_blacklist_skips_short_terms_and_dupes(tmp_path):
    path = tmp_path / "bl.txt"
    path.write_text("ab\nWireshark\nwireshark\nvnc\n", encoding="utf-8")
    assert scanner.load_blacklist(path) == ["wireshark", "vnc"]


def test_load_blacklist_missing_raises(tmp_path):
    with pytest.raises(scanner.ScannerError):
        scanner.load_blacklist(tmp_path / "missing.txt")


def test_write_default_blacklist_roundtrip(tmp_path):
    path = scanner.write_default_blacklist(tmp_path / "bl.txt")
    assert scanner.load_blacklist(path) == [t.lower() for t in scanner.DEFAULT_BLACKLIST]


def test_repo_blacklist_file_matches_defaults():
    repo = Path(__file__).resolve().parent.parent
    content = (repo / "blacklist_software.txt").read_text(encoding="utf-8")
    terms = [line.strip() for line in content.splitlines() if line.strip()]
    assert terms == scanner.DEFAULT_BLACKLIST


def test_risk_levels():
    assert scanner.risk_level("nmap") == "HIGH"
    assert scanner.risk_level("wireshark") == "MEDIUM"
    assert scanner.risk_level("utorrent") == "LOW"


def test_match_violations_finds_and_classifies():
    installed = [
        {"name": "Wireshark 4.2", "version": "4.2", "publisher": "WS",
         "install_date": "20240101", "install_location": "C:\\ws"},
    ]
    violations = scanner.match_violations(installed, ["wireshark", "vnc"])
    assert len(violations) == 1
    assert violations[0]["matched_term"] == "wireshark"
    assert violations[0]["risk_level"] == "MEDIUM"
    assert violations[0]["name"] == "Wireshark 4.2"


def test_match_violations_single_match_per_program():
    installed = [{"name": "Nmap Security Scanner", "version": "7", "publisher": "N",
                  "install_date": "?", "install_location": "?"}]
    violations = scanner.match_violations(installed, ["nmap", "map"])
    assert len(violations) == 1
    assert violations[0]["matched_term"] == "nmap"


def test_match_violations_no_match():
    assert scanner.match_violations([{"name": "Notepad++"}], ["vnc"]) == []


def test_dedupe_software_drops_same_name_version():
    same = {"name": "Putty", "version": "0.80"}
    other = {"name": "Putty", "version": "0.81"}
    result = scanner.dedupe_software([same, dict(same), other])
    assert result == [same, other]

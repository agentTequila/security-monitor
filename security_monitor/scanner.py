"""Blacklist loading, software matching, and risk classification (pure logic)."""

from __future__ import annotations

from pathlib import Path

MIN_TERM_LENGTH = 3

DEFAULT_BLACKLIST = [
    "nmap", "wireshark", "metasploit", "burp suite", "john the ripper",
    "hashcat", "aircrack", "sqlmap", "netcat", "putty", "teamviewer",
    "anydesk", "utorrent", "bittorrent", "limewire", "kazaa",
    "cheat engine", "process hacker", "keylogger", "remote desktop",
    "vnc", "tor browser", "proxifier", "charles proxy", "fiddler",
]

RISK_HIGH_TERMS = (
    "nmap", "metasploit", "burp suite", "john the ripper", "hashcat",
    "sqlmap", "cheat engine", "keylogger",
)
RISK_MEDIUM_TERMS = (
    "wireshark", "putty", "teamviewer", "anydesk", "process hacker",
    "vnc", "fiddler",
)


class ScannerError(Exception):
    """Raised when the blacklist cannot be loaded."""


def write_default_blacklist(path: str | Path) -> Path:
    blacklist_path = Path(path)
    blacklist_path.parent.mkdir(parents=True, exist_ok=True)
    blacklist_path.write_text("\n".join(DEFAULT_BLACKLIST) + "\n", encoding="utf-8")
    return blacklist_path


def load_blacklist(path: str | Path) -> list[str]:
    blacklist_path = Path(path)
    if not blacklist_path.exists():
        raise ScannerError(f"blacklist file not found: {blacklist_path}")
    terms: list[str] = []
    seen: set[str] = set()
    for line in blacklist_path.read_text(encoding="utf-8").splitlines():
        term = line.strip().lower()
        if len(term) >= MIN_TERM_LENGTH and term not in seen:
            seen.add(term)
            terms.append(term)
    return terms


def risk_level(term: str) -> str:
    lowered = term.lower()
    if any(risk in lowered for risk in RISK_HIGH_TERMS):
        return "HIGH"
    if any(risk in lowered for risk in RISK_MEDIUM_TERMS):
        return "MEDIUM"
    return "LOW"


def dedupe_software(software: list[dict]) -> list[dict]:
    seen: set[tuple[str, str]] = set()
    result: list[dict] = []
    for item in software:
        key = (str(item.get("name", "")).lower(), str(item.get("version", "")).lower())
        if key in seen:
            continue
        seen.add(key)
        result.append(item)
    return result


def match_violations(installed: list[dict], blacklist: list[str]) -> list[dict]:
    violations: list[dict] = []
    for software in installed:
        name = str(software.get("name") or "").lower()
        if not name:
            continue
        for term in blacklist:
            if term in name:
                violations.append(
                    {
                        "name": software.get("name", "Unknown"),
                        "version": software.get("version", "Unknown"),
                        "publisher": software.get("publisher", "Unknown"),
                        "install_date": software.get("install_date", "Unknown"),
                        "install_location": software.get("install_location", "Unknown"),
                        "matched_term": term,
                        "risk_level": risk_level(term),
                    }
                )
                break
    return violations

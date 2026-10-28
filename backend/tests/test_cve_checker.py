"""Tests du recoupement CVE via OSV (lot 2, 2026-10-28).

Aucun appel reseau reel : request_fn injectee. Les formats OSV verifies en
direct le 2026-10-28 : requete simple -> enregistrement complet (severity,
affected, ranges), querybatch -> id+modified seulement (d'ou le choix de la
requete simple, parallele).
"""
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.cve_checker import (
    canonical_cve_id,
    check_packages_cve,
    cvss_to_severity,
    detect_ecosystem,
    group_vulns_by_cve,
)
from core.models import DetectionSource, Severity
from core.package_scanner import InstalledPackage


class _Resp:
    def __init__(self, data):
        self._data = data

    def json(self):
        return self._data


def _fake_osv(mapping):
    def request_fn(url, payload, timeout):
        name = payload["package"]["name"]
        return _Resp({"vulns": mapping.get(name, [])})

    return request_fn


def test_detect_ecosystem_debian_and_ubuntu_lts():
    with tempfile.NamedTemporaryFile("w", delete=False) as fh:
        fh.write('ID=debian\nVERSION_ID="12"\n')
        deb = fh.name
    with tempfile.NamedTemporaryFile("w", delete=False) as fh:
        fh.write('ID=ubuntu\nVERSION_ID="24.04"\n')
        ubu = fh.name
    with tempfile.NamedTemporaryFile("w", delete=False) as fh:
        fh.write('ID=ubuntu\nVERSION_ID="23.10"\n')
        ubu_nonlts = fh.name
    assert detect_ecosystem(deb) == "Debian:12"
    assert detect_ecosystem(ubu) == "Ubuntu:24.04:LTS"
    assert detect_ecosystem(ubu_nonlts) == "Ubuntu:23.10"
    assert detect_ecosystem("/nonexistent/os-release") is None


def test_cvss_mapping():
    assert cvss_to_severity(9.8) == Severity.CRITICAL
    assert cvss_to_severity(7.5) == Severity.HIGH
    assert cvss_to_severity(5.0) == Severity.MEDIUM
    assert cvss_to_severity(2.0) == Severity.LOW
    assert cvss_to_severity(None) == Severity.MEDIUM


def test_canonical_cve_prefers_upstream():
    vuln = {"id": "UBUNTU-CVE-2024-11053", "upstream": ["CVE-2024-11053"]}
    assert canonical_cve_id(vuln) == "CVE-2024-11053"
    assert canonical_cve_id({"id": "DEBIAN-CVE-2024-13176"}) == "DEBIAN-CVE-2024-13176"


def test_group_by_cve_dedupes_packages_and_sorts_by_severity():
    curl = InstalledPackage(name="curl", version="8.5.0-2ubuntu10.4")
    libcurl = InstalledPackage(name="libcurl4", version="8.5.0-2ubuntu10.4")
    vuln = {
        "id": "UBUNTU-CVE-2025-0167",
        "upstream": ["CVE-2025-0167"],
        "summary": "curl flaw",
        "severity": [{"type": "CVSS_V3", "score": "9.8"}],
        "affected": [
            {
                "package": {"ecosystem": "Ubuntu:24.04:LTS"},
                "ranges": [{"events": [{"introduced": "0"}, {"fixed": "8.5.0-2ubuntu10.8"}]}],
            }
        ],
    }
    low = {
        "id": "UBUNTU-CVE-2024-0001",
        "summary": "low flaw",
        "severity": [{"type": "CVSS_V3", "score": "2.1"}],
        "affected": [],
    }
    threats = group_vulns_by_cve(
        [(curl, vuln), (libcurl, vuln), (curl, low)], "Ubuntu:24.04:LTS"
    )
    # Un seul CVE-2025-0167 malgre 2 paquets, en premier (CRITICAL).
    assert len(threats) == 2
    assert threats[0].details["cve_id"] == "CVE-2025-0167"
    assert threats[0].severity == Severity.CRITICAL
    assert threats[0].source == DetectionSource.CVE
    assert threats[0].path == "cve:CVE-2025-0167"
    assert len(threats[0].details["packages"]) == 2
    assert threats[0].details["fixed_version"] == "8.5.0-2ubuntu10.8"
    assert threats[1].severity == Severity.LOW


def test_check_packages_cve_uses_request_fn_and_reports_failures():
    pkgs = [
        InstalledPackage(name="curl", version="8.5.0-2ubuntu10.4"),
        InstalledPackage(name="boom", version="1.0"),
    ]

    def request_fn(url, payload, timeout):
        if payload["package"]["name"] == "boom":
            raise RuntimeError("reseau coupe")
        return _Resp(
            {
                "vulns": [
                    {
                        "id": "UBUNTU-CVE-2025-0167",
                        "upstream": ["CVE-2025-0167"],
                        "severity": [{"type": "CVSS_V3", "score": "7.0"}],
                        "affected": [],
                    }
                ]
            }
        )

    result = check_packages_cve(
        pkgs, ecosystem="Ubuntu:24.04:LTS", max_workers=2, request_fn=request_fn
    )
    assert len(result.threats) == 1
    assert result.queried == 2
    assert result.failed == 1
    assert result.errors and "1 paquet(s) non interroge(s)" in result.errors[0]


def test_check_packages_cve_unsupported_os():
    result = check_packages_cve([], ecosystem=None, os_release_path="/nonexistent/os-release")
    assert result.threats == []
    assert result.errors and "non supporte" in result.errors[0]

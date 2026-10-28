"""Recoupement paquets installes <-> CVE via OSV.dev (section 4.1).

Design valide le 2026-10-28 avec 4 sources concordantes (code local,
documentation OSV, DeepSeek via TokenHarbor, GPT via Groq) :
- Requete simple POST https://api.osv.dev/v1/query par paquet : contrairement
  a /v1/querybatch (qui ne renvoie que id+modified), la requete simple
  renvoie l'enregistrement complet (severite, details, ranges, fixed).
  Avec la version fournie, OSV ne renvoie que les vulns affectant cette
  version : aucune comparaison de ranges cote client n'est necessaire.
- Ecosysteme : "Debian:<majeur>" (ex. Debian:12) ou "Ubuntu:<version>:LTS"
  pour les LTS (annee paire, mois 04) ; tout autre OS -> non supporte, pour
  eviter les faux positifs d'un ecosysteme applique a la mauvaise distro.
- Regroupement par CVE (une menace par CVE, paquets affectes imbriques),
  trie par severite decroissante puis identifiant : un meme CVE ne doit pas
  etre rapporte une fois par paquet binaire.
- Opt-in : cve_enabled=False par defaut. L'envoi de l'inventaire
  (noms+versions) a un service cloud ne doit pas etre implicite.
- Resilience : un echec reseau par paquet est compte, puis resume en une
  erreur de scan ; il ne fait jamais echouer le scan ni perdre les menaces
  d'integrite deja trouvees.
"""

from __future__ import annotations

import logging
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass

from core.models import DetectionSource, Severity, Threat

log = logging.getLogger(__name__)

OSV_QUERY_URL = "https://api.osv.dev/v1/query"
OSV_VULN_URL = "https://osv.dev/vulnerability/"
MAX_CVE_THREATS = 500
DEFAULT_WORKERS = 8
DEFAULT_TIMEOUT_S = 15

try:
    import requests

    REQUESTS_AVAILABLE = True
except ImportError:  # pragma: no cover - requests est dans requirements.txt
    requests = None  # type: ignore
    REQUESTS_AVAILABLE = False


@dataclass
class CveResult:
    threats: list[Threat]
    errors: list[str]
    queried: int
    failed: int


def parse_os_release(path: str = "/etc/os-release") -> dict[str, str]:
    """Lit /etc/os-release en dict (valeurs dequotees)."""
    values: dict[str, str] = {}
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or "=" not in line or line.startswith("#"):
                    continue
                key, value = line.split("=", 1)
                values[key.strip()] = value.strip().strip('"').strip("'")
    except OSError:
        pass
    return values


def detect_ecosystem(os_release_path: str = "/etc/os-release") -> str | None:
    """Ecosysteme OSV pour l'hote, ou None si non supporte.

    Debian -> "Debian:<majeur>" ; Ubuntu LTS -> "Ubuntu:<version>:LTS"
    (les LTS Ubuntu sont les versions d'avril des annees paires) ;
    Ubuntu non-LTS -> "Ubuntu:<version>" sans suffixe.
    """
    info = parse_os_release(os_release_path)
    distro = info.get("ID", "").lower()
    version = info.get("VERSION_ID", "")
    if not version:
        return None
    if distro == "debian":
        return f"Debian:{version.split('.')[0]}"
    if distro == "ubuntu":
        parts = version.split(".")
        is_lts = len(parts) == 2 and parts[1] == "04" and parts[0].isdigit() and int(parts[0]) % 2 == 0
        return f"Ubuntu:{version}:LTS" if is_lts else f"Ubuntu:{version}"
    return None


def cvss_to_severity(score: float | None) -> Severity:
    if score is None:
        return Severity.MEDIUM
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score > 0:
        return Severity.LOW
    return Severity.MEDIUM


def _best_cvss_score(vuln: dict) -> float | None:
    best: float | None = None
    for entry in vuln.get("severity") or []:
        try:
            score = float(entry.get("score"))
        except (TypeError, ValueError):
            continue
        if best is None or score > best:
            best = score
    return best


def canonical_cve_id(vuln: dict) -> str:
    """CVE upstream si present (Ubuntu), sinon l'identifiant OSV lui-meme."""
    for alias in vuln.get("upstream") or []:
        if isinstance(alias, str) and alias.startswith("CVE-"):
            return alias
    for alias in vuln.get("aliases") or []:
        if isinstance(alias, str) and alias.startswith("CVE-"):
            return alias
    return str(vuln.get("id", "CVE-unknown"))


def fixed_version_for_ecosystem(vuln: dict, ecosystem: str) -> str | None:
    for affected in vuln.get("affected") or []:
        pkg = affected.get("package") or {}
        if pkg.get("ecosystem") != ecosystem:
            continue
        for rng in affected.get("ranges") or []:
            for event in rng.get("events") or []:
                if "fixed" in event:
                    return str(event["fixed"])
    return None


def group_vulns_by_cve(
    findings: list[tuple[object, dict]], ecosystem: str
) -> list[Threat]:
    """Regroupe les vulns OSV par CVE canonique en menaces Malryx.

    findings : liste de (paquet, enregistrement OSV). Le paquet n'est utilise
    que via ses attributs .name/.version (duck typing, pour les tests).
    """
    grouped: dict[str, dict] = {}
    for pkg, vuln in findings:
        cve_id = canonical_cve_id(vuln)
        score = _best_cvss_score(vuln)
        entry = grouped.setdefault(
            cve_id,
            {
                "osv_id": str(vuln.get("id", cve_id)),
                "summary": (vuln.get("summary") or vuln.get("details") or "")[:300],
                "score": score,
                "fixed": fixed_version_for_ecosystem(vuln, ecosystem),
                "packages": {},
            },
        )
        if score is not None and (entry["score"] is None or score > entry["score"]):
            entry["score"] = score
        if not entry["summary"]:
            entry["summary"] = (vuln.get("summary") or vuln.get("details") or "")[:300]
        if entry["fixed"] is None:
            entry["fixed"] = fixed_version_for_ecosystem(vuln, ecosystem)
        entry["packages"][getattr(pkg, "name")] = getattr(pkg, "version")

    severity_rank = {
        Severity.CRITICAL: 4,
        Severity.HIGH: 3,
        Severity.MEDIUM: 2,
        Severity.LOW: 1,
        Severity.CLEAN: 0,
    }
    threats: list[Threat] = []
    for cve_id, entry in grouped.items():
        severity = cvss_to_severity(entry["score"])
        packages = [
            {"name": name, "version": version}
            for name, version in sorted(entry["packages"].items())
        ]
        threats.append(
            Threat(
                path=f"cve:{cve_id}",
                name=f"Vulnerabilite {cve_id} ({len(packages)} paquet(s) affecte(s))",
                severity=severity,
                source=DetectionSource.CVE,
                details={
                    "cve_id": cve_id,
                    "osv_id": entry["osv_id"],
                    "osv_url": OSV_VULN_URL + entry["osv_id"],
                    "summary": entry["summary"],
                    "cvss_score": entry["score"],
                    "fixed_version": entry["fixed"],
                    "packages": packages,
                },
            )
        )
    threats.sort(key=lambda t: (-severity_rank[t.severity], t.details["cve_id"]))
    return threats


def query_package_cve(package, ecosystem: str, timeout: int = DEFAULT_TIMEOUT_S, request_fn=None) -> list[dict]:
    """Interroge OSV pour un paquet ; renvoie la liste des vulns completes."""
    if not REQUESTS_AVAILABLE and request_fn is None:
        raise RuntimeError("module requests absent")
    payload = {
        "package": {"name": package.name, "ecosystem": ecosystem},
        "version": package.version,
    }
    if request_fn is not None:
        response = request_fn(OSV_QUERY_URL, payload, timeout)
        data = response.json() if hasattr(response, "json") else response
    else:
        resp = requests.post(OSV_QUERY_URL, json=payload, timeout=timeout)  # type: ignore
        if resp.status_code != 200:
            raise RuntimeError(f"OSV HTTP {resp.status_code}")
        data = resp.json()
    return list(data.get("vulns") or [])


def check_packages_cve(
    packages,
    ecosystem: str | None = None,
    max_workers: int = DEFAULT_WORKERS,
    request_fn=None,
    os_release_path: str = "/etc/os-release",
) -> CveResult:
    """Verifie une liste de paquets contre OSV, en parallele.

    Retourne (menaces regroupees par CVE, erreurs resumees, nb interroges,
    nb en echec). N'eleve jamais d'exception pour un paquet isole.
    """
    if ecosystem is None:
        ecosystem = detect_ecosystem(os_release_path)
    if ecosystem is None:
        return CveResult(
            threats=[],
            errors=["verification CVE ignoree : systeme d'exploitation non supporte par OSV"],
            queried=0,
            failed=0,
        )
    if not REQUESTS_AVAILABLE and request_fn is None:
        return CveResult(
            threats=[],
            errors=["verification CVE ignoree : module requests absent"],
            queried=0,
            failed=0,
        )

    findings: list[tuple[object, dict]] = []
    failed = 0
    with ThreadPoolExecutor(max_workers=max(1, max_workers)) as pool:
        futures = {
            pool.submit(query_package_cve, pkg, ecosystem, DEFAULT_TIMEOUT_S, request_fn): pkg
            for pkg in packages
        }
        for future in as_completed(futures):
            pkg = futures[future]
            try:
                for vuln in future.result():
                    findings.append((pkg, vuln))
            except Exception as exc:
                failed += 1
                log.debug("OSV %s : %s", pkg.name, exc)

    threats = group_vulns_by_cve(findings, ecosystem)
    errors: list[str] = []
    if failed:
        errors.append(
            f"verification CVE : {failed} paquet(s) non interroge(s) (reseau/OSV), "
            "les autres resultats restent valides"
        )
    if len(threats) > MAX_CVE_THREATS:
        errors.append(
            f"verification CVE : {len(threats) - MAX_CVE_THREATS} menace(s) CVE "
            "supplementaire(s) non affichee(s) (plafond de 500)"
        )
        threats = threats[:MAX_CVE_THREATS]
    return CveResult(threats=threats, errors=errors, queried=len(packages), failed=failed)

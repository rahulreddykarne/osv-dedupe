"""Known-advisory deduplication for PyPI security findings.

Queries public advisory sources (OSV always, NVD optionally) and scores whether
a finding overlaps an already-published vulnerability for the same PyPI
package/version. Failures are non-fatal: if OSV/NVD are unavailable, callers get
an empty match list.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Any

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger(__name__)

_OSV_QUERY = "https://api.osv.dev/v1/query"
_NVD_QUERY = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_TIMEOUT = 12
_CWE_RE = re.compile(r"CWE[-_ ]?(\d+)", re.IGNORECASE)
_ADVISORY_CACHE: dict[tuple[str, str, bool], list[dict[str, Any]]] = {}
_MAX_CACHE_SIZE = 512


@dataclass(frozen=True)
class AdvisoryMatch:
    """A scored overlap between a finding and a published advisory."""

    source: str
    advisory_id: str
    url: str
    confidence: float
    reason: str
    aliases: tuple[str, ...] = ()
    cwes: tuple[str, ...] = ()
    summary: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "id": self.advisory_id,
            "url": self.url,
            "confidence": round(self.confidence, 2),
            "reason": self.reason,
            "aliases": list(self.aliases),
            "cwes": list(self.cwes),
            "summary": self.summary[:500],
        }


def find_known_advisory_matches(
    package: str,
    version: str,
    finding: dict[str, Any],
    *,
    session: requests.Session | None = None,
    min_confidence: float = 0.70,
    include_nvd: bool = False,
    limit: int = 3,
) -> list[dict[str, Any]]:
    """Return known advisory matches for a single finding, best match first.

    Parameters
    ----------
    package, version:
        PyPI package name and the affected version.
    finding:
        A finding dict. Recognised keys: ``cwe`` (e.g. ``"CWE-22"``), ``path``
        or ``filename``, and ``stage2.function_name`` — all optional and used
        only to strengthen scoring.
    session:
        Optional pre-configured :class:`requests.Session`.
    min_confidence:
        Only matches at or above this confidence (0.0–1.0) are returned. A
        match >= 0.70 is generally strong enough to treat a finding as already
        reported.
    include_nvd:
        Also query NVD by keyword (slower, noisier). OSV is always queried.
    limit:
        Maximum number of matches to return.
    """
    if not package:
        return []
    sess = session or _build_session()
    cwe = _normalize_cwe(finding.get("cwe"))
    cache_key = (package.lower(), version, bool(include_nvd))
    if cache_key not in _ADVISORY_CACHE:
        if len(_ADVISORY_CACHE) >= _MAX_CACHE_SIZE:
            _ADVISORY_CACHE.pop(next(iter(_ADVISORY_CACHE)))
        nvd = _query_nvd(sess, package) if include_nvd else []
        _ADVISORY_CACHE[cache_key] = [*_query_osv(sess, package, version), *nvd]
    advisories = _ADVISORY_CACHE[cache_key]
    matches: list[AdvisoryMatch] = []
    for advisory in advisories:
        match = _score_advisory(advisory, package, cwe, finding)
        if match and match.confidence >= min_confidence:
            matches.append(match)
    matches.sort(key=lambda item: item.confidence, reverse=True)
    return [item.to_dict() for item in matches[:limit]]


def clear_cache() -> None:
    """Clear the in-process advisory cache."""
    _ADVISORY_CACHE.clear()


def _build_session() -> requests.Session:
    sess = requests.Session()
    retry = Retry(total=1, backoff_factor=0.4, status_forcelist=[429, 500, 502, 503, 504])
    sess.mount("https://", HTTPAdapter(max_retries=retry))
    sess.headers.update({"User-Agent": "osv-dedupe/0.1"})
    return sess


def _query_osv(sess: requests.Session, package: str, version: str) -> list[dict[str, Any]]:
    body: dict[str, Any] = {"package": {"name": package, "ecosystem": "PyPI"}}
    if version:
        body["version"] = version
    try:
        resp = sess.post(_OSV_QUERY, json=body, timeout=_TIMEOUT)
        resp.raise_for_status()
        vulns = resp.json().get("vulns") or []
        return [{"source": "OSV", **vuln} for vuln in vulns if isinstance(vuln, dict)]
    except Exception as exc:  # noqa: BLE001 - network failures are non-fatal
        logger.debug("OSV dedup query failed for %s==%s: %s", package, version, exc)
        return []


def _query_nvd(sess: requests.Session, package: str) -> list[dict[str, Any]]:
    try:
        resp = sess.get(_NVD_QUERY, params={"keywordSearch": package}, timeout=_TIMEOUT)
        resp.raise_for_status()
        rows = resp.json().get("vulnerabilities") or []
    except Exception as exc:  # noqa: BLE001 - network failures are non-fatal
        logger.debug("NVD dedup query failed for %s: %s", package, exc)
        return []
    advisories: list[dict[str, Any]] = []
    package_lower = package.lower()
    for row in rows[:20]:
        cve = (row or {}).get("cve") or {}
        if not isinstance(cve, dict):
            continue
        text = _nvd_text(cve)
        if package_lower not in text.lower():
            continue
        advisories.append({"source": "NVD", **cve})
    return advisories


def _score_advisory(
    advisory: dict[str, Any],
    package: str,
    cwe: str,
    finding: dict[str, Any],
) -> AdvisoryMatch | None:
    source = str(advisory.get("source") or "advisory")
    advisory_id = str(advisory.get("id") or advisory.get("cveMetadata", {}).get("cveId") or "")
    aliases = tuple(str(alias) for alias in (advisory.get("aliases") or []) if alias)
    text = _advisory_text(advisory)
    cwes = tuple(sorted(_extract_cwes(advisory, text)))

    score = 0.0
    reasons: list[str] = []
    if source == "OSV":
        score += 0.45
        reasons.append("OSV returned this advisory for the package/version query")
    elif source == "NVD":
        score += 0.30
        reasons.append("NVD keyword search returned this advisory for the package")
    if package.lower() in text.lower():
        score += 0.15
        reasons.append("package name appears in advisory text")
    if cwe and cwe in cwes:
        score += 0.25
        reasons.append(f"CWE overlaps ({cwe})")
    elif cwe:
        score -= 0.10
        reasons.append(f"CWE differs from finding ({cwe})")
    if _finding_location_hint(finding, text):
        score += 0.10
        reasons.append("finding path/function hint appears in advisory text")

    if not advisory_id and aliases:
        advisory_id = aliases[0]
    if not advisory_id:
        return None
    url = _advisory_url(source, advisory_id, aliases)
    return AdvisoryMatch(
        source=source,
        advisory_id=advisory_id,
        url=url,
        confidence=max(0.0, min(1.0, score)),
        reason="; ".join(reasons),
        aliases=aliases,
        cwes=cwes,
        summary=_summary(advisory, text),
    )


def _advisory_text(advisory: dict[str, Any]) -> str:
    if advisory.get("source") == "NVD":
        return _nvd_text(advisory)
    parts = [
        str(advisory.get("summary") or ""),
        str(advisory.get("details") or ""),
        " ".join(str(alias) for alias in (advisory.get("aliases") or [])),
    ]
    for affected in advisory.get("affected") or []:
        if isinstance(affected, dict):
            pkg = affected.get("package") or {}
            parts.append(str(pkg.get("name") or ""))
            parts.append(str(pkg.get("ecosystem") or ""))
            parts.extend(str(item) for item in (affected.get("versions") or [])[:8])
    return "\n".join(parts)


def _nvd_text(cve: dict[str, Any]) -> str:
    descriptions = cve.get("descriptions") or []
    metrics = cve.get("metrics") or {}
    weaknesses = cve.get("weaknesses") or []
    refs = cve.get("references") or {}
    parts = [str(cve.get("id") or "")]
    parts.extend(str(item.get("value") or "") for item in descriptions if isinstance(item, dict))
    parts.append(str(metrics))
    parts.append(str(weaknesses))
    parts.append(str(refs))
    return "\n".join(parts)


def _extract_cwes(advisory: dict[str, Any], text: str) -> set[str]:
    cwes = {_normalize_cwe(match.group(0)) for match in _CWE_RE.finditer(text)}
    for weakness in advisory.get("weaknesses") or []:
        for desc in (weakness or {}).get("description") or []:
            cwes.add(_normalize_cwe((desc or {}).get("value")))
    return {cwe for cwe in cwes if cwe}


def _normalize_cwe(value: Any) -> str:
    text = str(value or "")
    match = _CWE_RE.search(text)
    return f"CWE-{match.group(1)}" if match else ""


def _finding_location_hint(finding: dict[str, Any], advisory_text: str) -> bool:
    haystack = advisory_text.lower()
    path = str(finding.get("path") or finding.get("filename") or "").replace("\\", "/").lower()
    function = str((finding.get("stage2") or {}).get("function_name") or "").lower()
    hints = [part for part in (path.rsplit("/", 1)[-1], function) if len(part) >= 4]
    return any(hint in haystack for hint in hints)


def _summary(advisory: dict[str, Any], text: str) -> str:
    if advisory.get("summary"):
        return str(advisory.get("summary") or "")
    for line in text.splitlines():
        line = line.strip()
        if len(line) > 30 and not line.startswith("{"):
            return line
    return ""


def _advisory_url(source: str, advisory_id: str, aliases: tuple[str, ...]) -> str:
    if source == "OSV":
        return f"https://osv.dev/vulnerability/{advisory_id}"
    cve_id = advisory_id if advisory_id.startswith("CVE-") else next(
        (a for a in aliases if a.startswith("CVE-")), advisory_id
    )
    return f"https://nvd.nist.gov/vuln/detail/{cve_id}"

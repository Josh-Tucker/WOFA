"""
MSRC CVRF API collector.

Fetches monthly security update documents from the Microsoft Security Response Center
and extracts per-OS-version patch and CVE data.

CVRF field reference:
  ProductTree.FullProductName[]  — {ProductID, Value (product name)}
  Vulnerability[].CVE            — CVE identifier
  Vulnerability[].Threats[]      — Type 0 = exploitability, Type 3 = severity
  Vulnerability[].CVSSScoreSets[]— BaseScore per ProductID
  Vulnerability[].Remediations[] — Type 1 = Vendor Fix (the patch KB)
    .Description.Value           — KB article number (e.g. "5050009")
    .FixedBuild                  — OS build string (e.g. "10.0.26100.3775")
    .URL                         — support.microsoft.com link
    .Supercedence                — KB this update supersedes
    .SubType                     — e.g. "Security Update"
"""

import json
import logging
import time
from collections import Counter
from datetime import datetime
from pathlib import Path

import requests

import config

logger = logging.getLogger(__name__)

_HEADERS = {
    "Accept": "application/json",
    "User-Agent": config.USER_AGENT,
}

# Threat type codes
_THREAT_EXPLOITABILITY = 0
_THREAT_SEVERITY = 3

# Remediation type codes
# Microsoft uses Type 2 ("Mitigation" in CVRF spec) for Windows security patches,
# with SubType="Security Update". Type 6 (Rollup) is the cumulative update.
_REM_SECURITY_UPDATE = 2
_REM_ROLLUP = 6

# Exploitability descriptions that mean actively exploited
_EXPLOITED_PHRASES = {"Exploitation Detected"}


# ---------------------------------------------------------------------------
# Cache helpers
# ---------------------------------------------------------------------------


def _cache_path(name: str) -> Path:
    return Path(config.CACHE_DIR) / "msrc" / name


def _read_cache(path: Path, max_age_hours: float):
    if path.exists():
        age = (time.time() - path.stat().st_mtime) / 3600
        if age < max_age_hours:
            return json.loads(path.read_text())
    return None


def _write_cache(path: Path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data))


# ---------------------------------------------------------------------------
# API fetchers
# ---------------------------------------------------------------------------


def get_updates_index() -> list[dict]:
    """
    Return a list of {id, date} for all monthly MSRC updates, newest first.
    'date' is an ISO-format string.
    """
    cache = _cache_path("index.json")
    cached = _read_cache(cache, config.CACHE_TTL_INDEX_HOURS)
    if cached:
        return cached

    logger.info("Fetching MSRC updates index")
    resp = requests.get(
        f"{config.MSRC_API_BASE}/updates",
        headers=_HEADERS,
        timeout=30,
    )
    resp.raise_for_status()

    updates = []
    for item in resp.json().get("value", []):
        uid = item.get("ID")
        date_str = item.get("InitialReleaseDate", "")
        if not uid or not date_str:
            continue
        try:
            date = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
            updates.append({"id": uid, "date": date.isoformat()})
        except ValueError:
            logger.warning("Unparseable date for update %s: %s", uid, date_str)

    updates.sort(key=lambda x: x["date"], reverse=True)
    _write_cache(cache, updates)
    return updates


def get_cvrf_document(update_id: str) -> dict:
    """Fetch the CVRF JSON document for a given update ID (e.g. '2025-Mar')."""
    cache = _cache_path(f"{update_id}.json")
    cached = _read_cache(cache, config.CACHE_TTL_CVRF_HOURS)
    if cached:
        logger.debug("Cache hit: CVRF %s", update_id)
        return cached

    logger.info("Fetching CVRF document: %s", update_id)
    resp = requests.get(
        f"{config.MSRC_API_BASE}/cvrf/{update_id}",
        headers=_HEADERS,
        timeout=60,
    )
    resp.raise_for_status()
    data = resp.json()
    _write_cache(cache, data)
    return data


# ---------------------------------------------------------------------------
# CVRF parsing
# ---------------------------------------------------------------------------


def _product_map(cvrf_doc: dict) -> dict[str, str]:
    """Return {ProductID: product_name} from a CVRF document."""
    return {
        p["ProductID"]: p["Value"]
        for p in cvrf_doc.get("ProductTree", {}).get("FullProductName", [])
    }


def _matching_pids(product_map: dict, patterns: list[str]) -> set[str]:
    """Return ProductIDs whose names match any of the given substrings (case-insensitive)."""
    lowered = [p.lower() for p in patterns]
    return {pid for pid, name in product_map.items() if any(pat in name.lower() for pat in lowered)}


def _find_main_kb(cvrf_doc: dict, target_pids: set[str]) -> tuple[str | None, dict]:
    """
    Find the primary security update KB for the given product IDs.

    Returns (kb_number, {fixed_build, url, supersedes}) or (None, {}).

    Microsoft CVRF uses:
      Type 2, SubType "Security Update" — monthly security patch (has FixedBuild)
      Type 6                            — cumulative rollup (no FixedBuild in CVRF)

    Strategy: prefer Type 2 "Security Update" KBs (they carry FixedBuild and
    Supercedence). Fall back to Type 6 rollups if none found.
    The KB referenced by the most CVEs is selected as the primary update.
    """
    sec_counter: Counter = Counter()
    sec_details: dict[str, dict] = {}
    rollup_counter: Counter = Counter()
    rollup_details: dict[str, dict] = {}

    for vuln in cvrf_doc.get("Vulnerability", []):
        for rem in vuln.get("Remediations", []):
            rem_type = rem.get("Type")
            if rem_type not in (_REM_SECURITY_UPDATE, _REM_ROLLUP):
                continue
            rem_pids = set(rem.get("ProductID", []))
            if not (rem_pids & target_pids):
                continue
            kb = rem.get("Description", {}).get("Value", "")
            if not (kb and kb.isdigit() and 6 <= len(kb) <= 8):
                continue

            details = {
                "fixed_build": rem.get("FixedBuild"),
                "url": f"https://support.microsoft.com/help/{kb}",
                "supersedes": rem.get("Supercedence"),
            }

            if rem_type == _REM_SECURITY_UPDATE and rem.get("SubType") == "Security Update":
                sec_counter[kb] += 1
                if kb not in sec_details:
                    sec_details[kb] = details
            elif rem_type == _REM_ROLLUP:
                rollup_counter[kb] += 1
                if kb not in rollup_details:
                    rollup_details[kb] = details

    if sec_counter:
        main_kb, _ = sec_counter.most_common(1)[0]
        return main_kb, sec_details[main_kb]

    if rollup_counter:
        main_kb, _ = rollup_counter.most_common(1)[0]
        return main_kb, rollup_details[main_kb]

    return None, {}


def extract_os_releases(cvrf_doc: dict, os_version_configs: list[dict]) -> dict[str, dict]:
    """
    Extract security release data per OS version from a CVRF document.

    Returns {short_name: release_data} where release_data is:
      {
        doc_title:    str,
        release_date: str (ISO),
        kb_article:   str,
        fixed_build:  str | None,
        support_url:  str,
        supersedes:   str | None,
        cves:         {cve_id: {severity, cvss_score, actively_exploited, in_kev, nist_url}},
      }

    OS versions with no matching KB in this document are omitted.
    """
    pmap = _product_map(cvrf_doc)

    date_raw = cvrf_doc.get("DocumentTracking", {}).get("InitialReleaseDate", "")
    try:
        release_date = datetime.fromisoformat(date_raw.replace("Z", "+00:00"))
        release_date_iso = release_date.date().isoformat()
    except (ValueError, AttributeError):
        release_date_iso = None

    doc_title = cvrf_doc.get("DocumentTitle", {}).get("Value", "")

    results = {}

    for os_cfg in os_version_configs:
        sname = os_cfg["short_name"]
        target_pids = _matching_pids(pmap, os_cfg["product_patterns"])
        if not target_pids:
            continue

        kb, kb_detail = _find_main_kb(cvrf_doc, target_pids)
        if not kb:
            continue

        cves: dict[str, dict] = {}

        for vuln in cvrf_doc.get("Vulnerability", []):
            cve_id = vuln.get("CVE")
            if not cve_id:
                continue

            # Determine whether this CVE touches our target products
            affected: set[str] = set()
            for rem in vuln.get("Remediations", []):
                affected.update(rem.get("ProductID", []))
            for threat in vuln.get("Threats", []):
                affected.update(threat.get("ProductID", []))

            if not (affected & target_pids):
                continue

            # Severity — Threat type 3; prefer a product-specific match
            severity = None
            for threat in vuln.get("Threats", []):
                if threat.get("Type") != _THREAT_SEVERITY:
                    continue
                pids = set(threat.get("ProductID", []))
                if not pids or (pids & target_pids):
                    val = threat.get("Description", {}).get("Value")
                    if val:
                        severity = val
                        break

            # Exploitation — Threat type 0
            actively_exploited = False
            for threat in vuln.get("Threats", []):
                if threat.get("Type") != _THREAT_EXPLOITABILITY:
                    continue
                desc = threat.get("Description", {}).get("Value", "")
                if desc in _EXPLOITED_PHRASES:
                    actively_exploited = True
                    break

            # CVSS base score — prefer a product-specific entry
            cvss_score = None
            for ss in vuln.get("CVSSScoreSets", []):
                pids = set(ss.get("ProductID", []))
                if not pids or (pids & target_pids):
                    cvss_score = ss.get("BaseScore")
                    if cvss_score is not None:
                        break

            cves[cve_id] = {
                "severity": severity,
                "cvss_score": cvss_score,
                "actively_exploited": actively_exploited,
                "in_kev": False,  # Filled by merge processor
                "nist_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            }

        results[sname] = {
            "doc_title": doc_title,
            "release_date": release_date_iso,
            "kb_article": kb,
            "fixed_build": kb_detail.get("fixed_build"),
            "support_url": kb_detail.get("url"),
            "supersedes": kb_detail.get("supersedes"),
            "cves": cves,
        }

    return results

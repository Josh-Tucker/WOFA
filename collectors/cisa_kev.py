"""
CISA Known Exploited Vulnerabilities (KEV) collector.

Fetches the public CISA KEV JSON feed and returns the set of CVE IDs
that are known to be actively exploited in the wild.

Feed URL: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
"""

import json
import logging
import time
from pathlib import Path

import requests

import config

logger = logging.getLogger(__name__)

_HEADERS = {"User-Agent": config.USER_AGENT}


def _cache_path() -> Path:
    return Path(config.CACHE_DIR) / "cisa_kev.json"


def get_kev_cve_ids() -> set[str]:
    """
    Return the set of all CVE IDs currently listed in the CISA KEV catalog.
    Results are cached locally for config.CACHE_TTL_KEV_HOURS hours.
    """
    cache = _cache_path()

    if cache.exists():
        age = (time.time() - cache.stat().st_mtime) / 3600
        if age < config.CACHE_TTL_KEV_HOURS:
            logger.debug("Cache hit: CISA KEV")
            data = json.loads(cache.read_text())
            return set(data)

    logger.info("Fetching CISA KEV feed")
    resp = requests.get(config.CISA_KEV_URL, headers=_HEADERS, timeout=30)
    resp.raise_for_status()

    cve_ids = [
        entry["cveID"] for entry in resp.json().get("vulnerabilities", []) if entry.get("cveID")
    ]

    cache.parent.mkdir(parents=True, exist_ok=True)
    cache.write_text(json.dumps(cve_ids))
    logger.info("CISA KEV: %d CVEs loaded", len(cve_ids))

    return set(cve_ids)

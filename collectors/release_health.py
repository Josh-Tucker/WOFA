"""
Windows Release Health collector.

Scrapes Microsoft's Windows release health pages to obtain:
1. GA version list — used to distinguish stable builds from Insider Preview.
2. Full release history — security and non-security (preview) builds per version.

Pages:
  - Windows 11: learn.microsoft.com/en-us/windows/release-health/windows11-release-information
  - Windows 10: learn.microsoft.com/en-us/windows/release-health/release-information
"""

import json
import logging
import re
import time
from pathlib import Path

import requests
from bs4 import BeautifulSoup

import config

logger = logging.getLogger(__name__)

_HEADERS = {"User-Agent": config.USER_AGENT}

# Matches "Version 26H1 (OS build 28000)" in section headings
_RE_VERSION_HEADER = re.compile(r"Version\s+(\w+)\s*\(OS build", re.IGNORECASE)
# Extracts week letter from update type, e.g. "2026-03 D" → "D"
_RE_WEEK = re.compile(r"\s+([A-Z]+)$")


def _cache_path(os_group: str) -> Path:
    slug = os_group.lower().replace(" ", "_")
    return Path(config.CACHE_DIR) / "release_health" / f"{slug}.json"


def _read_cache(path: Path) -> dict | None:
    if path.exists():
        age = (time.time() - path.stat().st_mtime) / 3600
        if age < config.CACHE_TTL_RELEASE_HEALTH_HOURS:
            return json.loads(path.read_text())
    return None


def _write_cache(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data))


def _parse_release_table(table) -> list[dict]:
    """Parse one per-version release history table into a list of release dicts."""
    # Resolve headers from <thead> or the first <tr>
    header_cells = table.select("thead th") or table.select("thead td")
    if not header_cells:
        first_row = table.find("tr")
        header_cells = first_row.find_all(["th", "td"]) if first_row else []
    headers = [c.get_text(strip=True).lower() for c in header_cells]

    def _col(*keywords: str) -> int | None:
        for i, h in enumerate(headers):
            if all(kw in h for kw in keywords):
                return i
        return None

    # Release history tables always have a "servicing option" column.
    # Hotpatch calendar tables have "month" instead — skip those.
    if not any("servicing" in h for h in headers):
        return []
    if any("month" in h for h in headers):
        return []

    type_col = _col("update", "type")
    date_col = _col("availability")
    build_col = _col("build")
    kb_col = _col("kb")

    if date_col is None or build_col is None:
        return []

    def _get(cells: list, idx: int | None) -> str:
        return cells[idx].get_text(strip=True) if idx is not None and idx < len(cells) else ""

    releases = []
    for row in table.select("tbody tr") or table.find_all("tr")[1:]:
        cells = row.find_all(["td", "th"])
        if not cells:
            continue

        availability_date = _get(cells, date_col)
        build = _get(cells, build_col)
        update_type = _get(cells, type_col) if type_col is not None else ""

        # Skip rows without a valid ISO date or build
        if not re.match(r"\d{4}-\d{2}-\d{2}", availability_date) or not build:
            continue

        # KB article
        kb_number = ""
        kb_url = ""
        if kb_col is not None and kb_col < len(cells):
            kb_cell = cells[kb_col]
            kb_link = kb_cell.find("a")
            if kb_link:
                m = re.search(r"KB(\d+)", kb_link.get_text(strip=True), re.IGNORECASE)
                if m:
                    kb_number = m.group(1)
                href = kb_link.get("href", "")
                if href.startswith("http"):
                    kb_url = href
                elif href:
                    kb_url = f"https://support.microsoft.com{href}"

        # Week letter from update_type
        week = ""
        m = _RE_WEEK.search(update_type)
        if m:
            week = m.group(1)

        releases.append(
            {
                "update_type": update_type,
                "availability_date": availability_date,
                "build": build,
                "kb_number": kb_number,
                "kb_url": kb_url,
                "week": week,
            }
        )

    return releases


def _parse_all_from_soup(soup: BeautifulSoup) -> dict:
    """
    Parse everything from a release health page soup in one pass. Returns:
      {
        "ga_versions":     [str, ...]            — version labels in GA
        "release_history": {label: [release, ...]} — per-version build history
      }
    """
    # ---- GA versions (current versions by servicing option table) ----
    ga_versions: set[str] = set()
    for table in soup.find_all("table"):
        hcells = table.select("thead th") or table.select("thead td")
        if not hcells:
            fr = table.find("tr")
            hcells = fr.find_all(["th", "td"]) if fr else []
        hdrs = [c.get_text(strip=True).lower() for c in hcells]

        if "version" not in hdrs or not any("servicing" in h for h in hdrs):
            continue
        version_idx = next(i for i, h in enumerate(hdrs) if h == "version")
        servicing_idx = next(i for i, h in enumerate(hdrs) if "servicing" in h)

        for row in table.find_all("tr"):
            cells = row.find_all(["td", "th"])
            if len(cells) <= max(version_idx, servicing_idx):
                continue
            if "general availability" not in cells[servicing_idx].get_text(strip=True).lower():
                continue
            version_text = cells[version_idx].get_text(strip=True)
            m = re.search(r"\b(\d+H\d+)\b", version_text, re.IGNORECASE)
            if m:
                ga_versions.add(m.group(1).upper())

    # ---- Release history (per-version tables) ----
    release_history: dict[str, list] = {}

    def _add_releases(version_label: str, releases: list) -> None:
        if not releases:
            return
        if version_label not in release_history:
            release_history[version_label] = releases
        else:
            existing = {
                (r["availability_date"], r["build"]) for r in release_history[version_label]
            }
            for rel in releases:
                if (rel["availability_date"], rel["build"]) not in existing:
                    release_history[version_label].append(rel)

    # Each version's history is preceded by a text node matching the version header pattern.
    for text_node in soup.find_all(string=_RE_VERSION_HEADER):
        m = _RE_VERSION_HEADER.search(str(text_node))
        if not m:
            continue
        version_label = m.group(1).upper()

        # Microsoft Docs uses <details>/<summary> collapsible sections.
        # If the text node is inside a <summary>, the table is a sibling inside <details>.
        details_el = text_node.parent
        while details_el and details_el.name != "details":
            details_el = details_el.parent
        if details_el:
            for table in details_el.find_all("table"):
                releases = _parse_release_table(table)
                _add_releases(version_label, releases)
            continue

        # Fallback: walk up to the nearest block element and search next siblings.
        block = text_node.parent
        while block and block.name not in ("p", "h2", "h3", "h4", "h5", "div", "section", "li"):
            block = block.parent
        if block is None:
            continue

        for sib in block.next_siblings:
            if not hasattr(sib, "name"):
                continue
            if sib.name == "table":
                releases = _parse_release_table(sib)
                _add_releases(version_label, releases)
                break
            elif sib.name in ("h2", "h3", "h4", "h5"):
                break

    logger.debug(
        "Parsed %d GA versions, %d version histories from page",
        len(ga_versions),
        len(release_history),
    )
    return {"ga_versions": sorted(ga_versions), "release_history": release_history}


def _get_page_data(os_group: str) -> dict:
    """Fetch (or return cached) parsed data for the given OS group's release health page."""
    cache = _cache_path(os_group)
    cached = _read_cache(cache)
    if cached is not None:
        logger.debug("Cache hit: release_health/%s", os_group)
        return cached

    url = config.RELEASE_HEALTH_URLS.get(os_group)
    if not url:
        return {"ga_versions": [], "release_history": {}}

    try:
        logger.info("Fetching release health page: %s", url)
        resp = requests.get(url, headers=_HEADERS, timeout=30)
        resp.raise_for_status()
        soup = BeautifulSoup(resp.text, "lxml")
        data = _parse_all_from_soup(soup)
    except Exception as exc:
        logger.warning("Could not fetch release health for %s: %s", os_group, exc)
        if cache.exists():
            return json.loads(cache.read_text())
        return {"ga_versions": [], "release_history": {}}

    _write_cache(cache, data)
    logger.info("GA versions for %s: %s", os_group, data["ga_versions"])
    return data


def get_ga_versions(os_group: str) -> set[str]:
    """Return the set of GA version labels for the given OS group (e.g. 'Windows 11')."""
    return set(_get_page_data(os_group).get("ga_versions", []))


def get_release_history(os_group: str) -> dict[str, list[dict]]:
    """
    Return the full release history for all versions of the given OS group.
    Dict is keyed by version label (e.g. '24H2') → list of release dicts, newest first.

    Each release dict has: update_type, availability_date, build, kb_number, kb_url, week.
    """
    history = _get_page_data(os_group).get("release_history", {})
    # Ensure sorted newest-first within each version
    for _label, releases in history.items():
        releases.sort(key=lambda r: r["availability_date"], reverse=True)
    return history

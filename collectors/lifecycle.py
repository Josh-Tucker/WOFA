"""
Microsoft lifecycle collector.

Scrapes Microsoft lifecycle pages to get end-of-servicing dates for each
Windows version. Results are cached to avoid repeated HTTP requests.

Page structure (learn.microsoft.com/en-us/lifecycle/products/...):
  - table.table with thead/tbody
  - Dates are in <local-time datetime="YYYY-MM-DDT..."> elements
  - Client OS pages (Win10/11): first <th> is "Version", rows are per release
  - Server pages: first <th> is "Listing", one row per product with
    Mainstream End Date and Extended End Date columns
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

# Lifecycle page URLs per client OS group, keyed by edition type then OS group.
_CLIENT_LIFECYCLE_URLS: dict[str, dict[str, str]] = {
    "HomePro": {
        "Windows 10": "https://learn.microsoft.com/en-us/lifecycle/products/windows-10-home-and-pro",
        "Windows 11": "https://learn.microsoft.com/en-us/lifecycle/products/windows-11-home-and-pro",
    },
    "EnterpriseEducation": {
        "Windows 10": "https://learn.microsoft.com/en-us/lifecycle/products/windows-10-enterprise-and-education",
        "Windows 11": "https://learn.microsoft.com/en-us/lifecycle/products/windows-11-enterprise-and-education",
    },
}


def _server_lifecycle_url(year: str) -> str:
    return f"https://learn.microsoft.com/en-us/lifecycle/products/windows-server-{year}"


def _cache_path(slug: str) -> Path:
    return Path(config.CACHE_DIR) / "lifecycle" / f"{slug}.json"


def _read_cache(path: Path) -> dict | None:
    if path.exists():
        age = (time.time() - path.stat().st_mtime) / 3600
        if age < config.CACHE_TTL_LIFECYCLE_HOURS:
            return json.loads(path.read_text())
    return None


def _write_cache(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data))


def _parse_date(cell) -> str | None:
    """Extract YYYY-MM-DD from a <local-time datetime="..."> element in a table cell."""
    lt = cell.find("local-time")
    if lt and lt.get("datetime"):
        return lt["datetime"][:10]
    return None


def _scrape_lifecycle_page(url: str) -> dict[str, str]:
    """
    Fetch and parse a Microsoft lifecycle page.

    Returns a dict mapping:
      - Client OS: version label (e.g. "24H2") -> end date (YYYY-MM-DD)
      - Server: product name (e.g. "Windows Server 2022") -> extended end date
    """
    logger.info("Fetching lifecycle page: %s", url)
    resp = requests.get(url, headers=_HEADERS, timeout=30)
    resp.raise_for_status()

    soup = BeautifulSoup(resp.text, "lxml")
    result: dict[str, str] = {}

    for table in soup.select("table.table"):
        headers = [th.get_text(strip=True) for th in table.select("thead th")]
        if not headers:
            continue

        first_col = headers[0].lower()

        if first_col == "version":
            # Client OS release table: Version | Start Date | End Date
            for row in table.select("tbody tr"):
                cells = row.find_all("td")
                if len(cells) < 2:
                    continue
                version_text = cells[0].get_text(strip=True)
                m = re.search(r"\b(\d+H\d+)\b", version_text, re.IGNORECASE)
                if not m:
                    continue
                label = m.group(1).upper()
                end_date = _parse_date(cells[-1])
                if end_date:
                    result[label] = end_date

        elif first_col == "listing":
            # Server table: Listing | Start Date | Mainstream End Date | Extended End Date
            # Use Extended End Date (last column) — that's when security updates end.
            for row in table.select("tbody tr"):
                cells = row.find_all("td")
                if len(cells) < 2:
                    continue
                listing = cells[0].get_text(strip=True)
                end_date = _parse_date(cells[-1])
                if end_date:
                    result[listing] = end_date

    if not result:
        logger.warning("No lifecycle dates parsed from %s", url)

    return result


def _get_dates_for_url(url: str) -> dict[str, str]:
    """Return cached lifecycle dates for a URL, fetching if stale."""
    slug = url.rstrip("/").split("/")[-1]
    cache = _cache_path(slug)

    cached = _read_cache(cache)
    if cached is not None:
        logger.debug("Cache hit: lifecycle/%s", slug)
        return cached

    dates = _scrape_lifecycle_page(url)
    _write_cache(cache, dates)
    return dates


def get_support_end_dates(os_cfg: dict) -> dict[str, str | None]:
    """
    Return end-of-servicing dates for the given OS version config as a dict:

      {
        "HomePro":             "YYYY-MM-DD" | None,
        "EnterpriseEducation": "YYYY-MM-DD" | None,
      }

    For Windows 10/11, both keys are populated from their respective lifecycle pages.
    For Windows Server, HomePro is None and EnterpriseEducation holds the Extended End Date
    (the date when security updates cease).
    """
    group = os_cfg.get("group", "")
    version_label = os_cfg.get("version_label", "")
    os_name = os_cfg.get("name", "")

    result: dict[str, str | None] = {"HomePro": None, "EnterpriseEducation": None}

    try:
        if group in _CLIENT_LIFECYCLE_URLS["HomePro"]:
            for edition, url_map in _CLIENT_LIFECYCLE_URLS.items():
                url = url_map.get(group)
                if url:
                    dates = _get_dates_for_url(url)
                    result[edition] = dates.get(version_label.upper())

        elif group == "Windows Server":
            url = _server_lifecycle_url(version_label)
            dates = _get_dates_for_url(url)
            # Match our product name against listing names in the scraped table
            end_date = None
            for listing, date in dates.items():
                if os_name.lower() in listing.lower() or listing.lower() in os_name.lower():
                    end_date = date
                    break
            # Fallback: single-row server pages have exactly one entry
            if end_date is None and len(dates) == 1:
                end_date = next(iter(dates.values()))
            result["EnterpriseEducation"] = end_date

    except Exception as exc:
        logger.warning("Could not fetch lifecycle dates for %s: %s", os_name, exc)

    return result

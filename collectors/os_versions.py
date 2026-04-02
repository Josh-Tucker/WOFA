"""
Dynamic Windows OS version discovery.

Derives the list of currently-tracked Windows versions by parsing product names
from the latest MSRC CVRF document. Any version Microsoft is actively patching
appears automatically — no manual config required.
"""

import logging
import re

logger = logging.getLogger(__name__)

# Product name substrings that should be skipped
_SKIP_PATTERNS = [
    "windows rt",
    "windows iot",
    "windows embedded",
    "ltsc",
    "ltsb",
    "server core",
    "nano server",
    "azure",
    "mariner",
]

_RE_CLIENT = re.compile(r"^Windows (10|11) Version (\w+)", re.IGNORECASE)
_RE_SERVER = re.compile(r"^Windows Server (\d{4})(\s*$|\s+\()", re.IGNORECASE)


def _parse(product_name: str) -> dict | None:
    """Parse a CVRF product name into an OS version config dict, or None if not tracked."""
    lower = product_name.lower()
    if any(skip in lower for skip in _SKIP_PATTERNS):
        return None

    m = _RE_CLIENT.match(product_name)
    if m:
        win_ver = m.group(1)   # "10" or "11"
        release = m.group(2)   # "24H2", "22H2", etc.
        display = f"Windows {win_ver} {release}"
        return {
            "name": display,
            "short_name": f"win{win_ver}_{release.lower()}",
            "group": f"Windows {win_ver}",
            "version_label": release,
            "product_patterns": [f"Windows {win_ver} Version {release}"],
        }

    m = _RE_SERVER.match(product_name)
    if m:
        year = m.group(1)
        display = f"Windows Server {year}"
        return {
            "name": display,
            "short_name": f"winserver_{year}",
            "group": "Windows Server",
            "version_label": year,
            "product_patterns": [f"Windows Server {year}"],
        }

    return None


def _sort_key(os_cfg: dict) -> tuple:
    group_order = {"Windows 11": 0, "Windows 10": 1, "Windows Server": 2}
    label = os_cfg["version_label"]

    # "24H2" → (-24, -2) for descending order within group
    m = re.match(r"(\d+)H(\d+)$", label, re.IGNORECASE)
    if m:
        return (group_order.get(os_cfg["group"], 9), -int(m.group(1)), -int(m.group(2)))

    # Year-based labels (Server 2025, 2022, …) → descending
    try:
        return (group_order.get(os_cfg["group"], 9), -int(label), 0)
    except ValueError:
        return (group_order.get(os_cfg["group"], 9), 0, 0)


def from_cvrf_document(cvrf_doc: dict) -> list[dict]:
    """
    Return a deduplicated, sorted list of OS version config dicts derived
    from the ProductTree of a CVRF document.

    Each dict has: name, short_name, group, version_label, product_patterns.
    """
    products = cvrf_doc.get("ProductTree", {}).get("FullProductName", [])
    seen: set[str] = set()
    result = []

    for p in products:
        parsed = _parse(p.get("Value", ""))
        if parsed and parsed["name"] not in seen:
            seen.add(parsed["name"])
            result.append(parsed)

    result.sort(key=_sort_key)
    logger.debug("Discovered %d OS versions from CVRF ProductTree", len(result))
    return result

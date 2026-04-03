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
        win_ver = m.group(1)  # "10" or "11"
        release = m.group(2)  # "24H2", "22H2", etc.
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
    # Insider builds sort after stable versions within the same group
    insider_penalty = 1 if os_cfg.get("is_insider") else 0

    # "24H2" → (-24, -2) for descending order within group
    m = re.match(r"(\d+)H(\d+)$", label, re.IGNORECASE)
    if m:
        return (
            group_order.get(os_cfg["group"], 9),
            insider_penalty,
            -int(m.group(1)),
            -int(m.group(2)),
        )

    # Year-based labels (Server 2025, 2022, …) → descending
    try:
        return (group_order.get(os_cfg["group"], 9), insider_penalty, -int(label), 0)
    except ValueError:
        return (group_order.get(os_cfg["group"], 9), insider_penalty, 0, 0)


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


def mark_insider_builds(os_configs: list[dict], ga_versions_by_group: dict[str, set[str]]) -> None:
    """
    Annotate each OS config dict in-place with ``is_insider: bool``.

    A version is considered an Insider / pre-release build when ALL of:
      - Its group has a known set of GA versions (from the Release Health page)
      - Its version label is NOT in that set
      - Its version label uses the YYHx format AND its year number is strictly
        greater than the highest year seen in the GA set

    The third condition is critical: old EOL versions (e.g. Windows 10 1607,
    Windows 11 21H2) are no longer listed on the release health page but are
    clearly not Insider builds. Only versions with a *higher* year than any
    current GA release are treated as pre-release.

    Windows Server versions (and any group with no release health URL) are never
    marked as Insider.
    """
    _re_yyh = re.compile(r"^(\d+)H\d+$", re.IGNORECASE)

    for cfg in os_configs:
        group = cfg.get("group", "")
        label = cfg.get("version_label", "").upper()
        ga_set = ga_versions_by_group.get(group)

        if ga_set is None:
            cfg["is_insider"] = False
            continue

        if label in ga_set:
            cfg["is_insider"] = False
            continue

        # Not in the GA set.  Could be old/EOL or a genuine Insider build.
        # Only YYHx-format labels can be Insider; old "1607"-style labels never are.
        m_label = _re_yyh.match(label)
        if not m_label:
            cfg["is_insider"] = False
            continue

        label_year = int(m_label.group(1))

        # Find the highest year among current GA versions
        max_ga_year = 0
        for ga_label in ga_set:
            m_ga = _re_yyh.match(ga_label)
            if m_ga:
                max_ga_year = max(max_ga_year, int(m_ga.group(1)))

        # Insider only if the version year is strictly newer than all GA versions
        cfg["is_insider"] = label_year > max_ga_year

"""
Static site generator.

Renders Jinja2 templates against feed data and writes HTML files to the output directory.
"""

import logging
import re
from collections import defaultdict
from datetime import date, datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

import config

logger = logging.getLogger(__name__)

TEMPLATES_DIR = Path("templates")
OUTPUT_DIR = Path(config.OUTPUT_DIR)


def _slug(os_name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", os_name.lower()).strip("-")


def _nav_groups(os_versions: list[dict]) -> list[dict]:
    """
    Build grouped nav structure from the flat OS versions list.
    Returns [{"name": "Windows 11", "versions": [os_entry, ...]}, ...]
    preserving config order.
    """
    groups: dict[str, list] = {}
    for os in os_versions:
        group = os.get("group", os["OSVersion"])
        groups.setdefault(group, []).append(os)
    return [{"name": name, "versions": versions} for name, versions in groups.items()]


def _format_timestamp(iso: str) -> str:
    try:
        dt = datetime.fromisoformat(iso)
        return dt.strftime("%d %b %Y %H:%M UTC")
    except (ValueError, TypeError):
        return iso or ""


def _age_days(date_str: str | None) -> int | None:
    """Days since a YYYY-MM-DD date string."""
    if not date_str:
        return None
    try:
        return (date.today() - date.fromisoformat(date_str)).days
    except ValueError:
        return None


def _kb_from_update_name(update_name: str) -> str:
    match = re.search(r"KB(\d+)", update_name or "")
    return match.group(1) if match else ""


def _release_label(update_name: str) -> str:
    """
    Extract the month/year portion from a full UpdateName.
    "Windows 11 24H2 - March 2026 Security Update (KB5079473)"
    → "March 2026 Security Update"
    """
    # Strip OS prefix (everything up to and including " - ")
    if " - " in update_name:
        update_name = update_name.split(" - ", 1)[1]
    # Strip trailing KB reference
    return re.sub(r"\s*\(KB\d+\)\s*$", "", update_name).strip()


def _group_cves(cves: dict) -> list[dict]:
    """
    Group CVEs by their CVE-YEAR-NNxx prefix for display.
    e.g. CVE-2026-21510 and CVE-2026-21513 → group 'CVE-2026-21xx'
    """
    groups: dict[str, list] = defaultdict(list)
    for cve_id, data in sorted(cves.items()):
        m = re.match(r"(CVE-\d{4}-\d{2})", cve_id)
        key = f"{m.group(1)}xx" if m else "other"
        groups[key].append({"id": cve_id, **data})
    return [{"name": k, "cves": v} for k, v in sorted(groups.items())]


def _recommendation(exploited: list, kev_count: int, cve_count: int) -> str:
    if kev_count:
        return "Update immediately — contains known-exploited vulnerabilities (CISA KEV)"
    if exploited:
        return "Update immediately — actively exploited vulnerabilities present"
    if cve_count:
        return "Update to stay secure — security fixes available"
    return "Update recommended — may include unpublished security improvements"


def _summary(exploited: list, cve_count: int) -> str:
    n = len(exploited)
    if n:
        return f"Contains {n} actively exploited {'vulnerability' if n == 1 else 'vulnerabilities'}"
    if cve_count:
        return f"Addresses {cve_count} security {'issue' if cve_count == 1 else 'issues'}"
    return "Maintenance update with no published CVE entries"


def _risk_level(exploited: list, kev_count: int) -> str:
    """'critical', 'high', or ''"""
    if kev_count:
        return "critical"
    if exploited:
        return "high"
    return ""


def _enrich_release(rel: dict, is_latest: bool) -> dict:
    """Add computed display fields to a release dict."""
    cves = rel.get("CVEs", {})
    exploited = rel.get("ActivelyExploitedCVEs", [])
    kev_count = sum(1 for d in cves.values() if d.get("in_kev"))
    cve_count = rel.get("UniqueCVEsCount", 0)
    kb = _kb_from_update_name(rel.get("UpdateName", ""))

    return {
        **rel,
        "kb": kb,
        "release_label": _release_label(rel.get("UpdateName", "")),
        "age_days": _age_days(rel.get("ReleaseDate")),
        "kev_count": kev_count,
        "cve_groups": _group_cves(cves),
        "recommendation": _recommendation(exploited, kev_count, cve_count),
        "summary": _summary(exploited, cve_count),
        "risk_level": _risk_level(exploited, kev_count),
        "is_latest": is_latest,
    }


def _enrich_os(os_entry: dict) -> dict:
    """Enrich all releases in an OS entry with computed display fields."""
    releases = os_entry.get("SecurityReleases", [])
    enriched = [_enrich_release(r, i == 0) for i, r in enumerate(releases)]
    return {**os_entry, "SecurityReleases": enriched}


def _patch_tuesday_summary(os_versions: list[dict]) -> dict | None:
    """
    Build a summary of the most recent Patch Tuesday across all OS versions.
    Uses the latest release date that appears in any OS version's releases.
    """
    latest_date = None
    for os_entry in os_versions:
        releases = os_entry.get("SecurityReleases", [])
        if releases:
            d = releases[0].get("ReleaseDate")  # sorted newest first
            if d and (latest_date is None or d > latest_date):
                latest_date = d

    if not latest_date:
        return None

    rows = []
    all_exploited: set[str] = set()
    total_cves = 0
    total_kev = 0

    for os_entry in os_versions:
        for rel in os_entry.get("SecurityReleases", []):
            if rel.get("ReleaseDate") == latest_date:
                rows.append(
                    {
                        "os_name": os_entry["OSVersion"],
                        "slug": os_entry["slug"],
                        **rel,
                    }
                )
                total_cves += rel.get("UniqueCVEsCount", 0)
                all_exploited.update(rel.get("ActivelyExploitedCVEs", []))
                total_kev += rel.get("kev_count", 0)
                break

    if not rows:
        return None

    try:
        month_label = date.fromisoformat(latest_date).strftime("%B %Y")
    except ValueError:
        month_label = latest_date

    return {
        "date": latest_date,
        "month_label": month_label,
        "rows": rows,
        "total_cves": total_cves,
        "exploited_cves": sorted(all_exploited),
        "total_exploited": len(all_exploited),
        "total_kev": total_kev,
        "versions_updated": len(rows),
    }


def _recent_releases(os_versions: list[dict], limit: int = 30) -> list[dict]:
    rows = []
    for os_entry in os_versions:
        for rel in os_entry.get("SecurityReleases", []):
            rows.append(
                {
                    "os_name": os_entry["OSVersion"],
                    "kb": _kb_from_update_name(rel.get("UpdateName", "")),
                    **rel,
                }
            )
    rows.sort(key=lambda r: r.get("ReleaseDate") or "", reverse=True)
    return rows[:limit]


def build_cve_index(os_versions: list[dict]) -> dict:
    """
    Build a flat CVE index for client-side search.
    Returns { cve_id: { severity, cvss_score, actively_exploited, in_kev, affected: [...] } }
    where each affected entry is one OS version + KB release.
    """
    index: dict[str, dict] = {}
    for os_entry in os_versions:
        os_name = os_entry["OSVersion"]
        slug = os_entry["slug"]
        for rel in os_entry.get("SecurityReleases", []):
            for cve_id, cve_data in (rel.get("CVEs") or {}).items():
                if cve_id not in index:
                    index[cve_id] = {
                        "severity": cve_data.get("severity"),
                        "cvss_score": cve_data.get("cvss_score"),
                        "actively_exploited": bool(cve_data.get("actively_exploited")),
                        "in_kev": bool(cve_data.get("in_kev")),
                        "affected": [],
                    }
                entry = index[cve_id]
                if cve_data.get("actively_exploited"):
                    entry["actively_exploited"] = True
                if cve_data.get("in_kev"):
                    entry["in_kev"] = True
                entry["affected"].append(
                    {
                        "os": os_name,
                        "slug": slug,
                        "kb": rel.get("kb", ""),
                        "release_date": rel.get("ReleaseDate"),
                        "security_info": rel.get("SecurityInfo"),
                        "product_version": rel.get("ProductVersion"),
                    }
                )
    for entry in index.values():
        entry["affected"].sort(key=lambda x: x.get("release_date") or "", reverse=True)
    return index


def generate(feed: dict) -> None:
    """Render all site pages from the feed dict and write to output/."""
    import json
    from urllib.parse import quote_plus

    env = Environment(
        loader=FileSystemLoader(str(TEMPLATES_DIR)),
        autoescape=select_autoescape(["html"]),
    )
    env.filters["urlencode"] = quote_plus

    last_check = _format_timestamp(feed.get("LastCheck", ""))

    os_versions = []
    for os_entry in feed.get("OSVersions", []):
        enriched = _enrich_os(os_entry)
        os_versions.append(
            {
                **enriched,
                "slug": _slug(os_entry["OSVersion"]),
                "group": os_entry.get("Group", os_entry["OSVersion"]),
                "version_label": os_entry.get("VersionLabel", os_entry["OSVersion"]),
            }
        )

    nav_groups = _nav_groups(os_versions)

    base_ctx = {
        "os_versions": os_versions,
        "nav_groups": nav_groups,
        "last_check": last_check,
        "site_url": config.SITE_URL,
    }

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    tmpl = env.get_template("index.html")
    html = tmpl.render(
        **base_ctx,
        current_slug=None,
        recent_releases=_recent_releases(os_versions),
        patch_tuesday=_patch_tuesday_summary(os_versions),
    )
    (OUTPUT_DIR / "index.html").write_text(html)
    logger.info("Written output/index.html")

    tmpl = env.get_template("os_version.html")
    for os_entry in os_versions:
        html = tmpl.render(**base_ctx, os=os_entry, current_slug=os_entry["slug"])
        page_path = OUTPUT_DIR / f"{os_entry['slug']}.html"
        page_path.write_text(html)
        logger.info("Written output/%s.html", os_entry["slug"])

    cve_index = build_cve_index(os_versions)
    index_path = OUTPUT_DIR / "v1" / "cve_index.json"
    index_path.parent.mkdir(parents=True, exist_ok=True)
    index_path.write_text(json.dumps(cve_index, ensure_ascii=False))
    logger.info("Written output/v1/cve_index.json (%d CVEs)", len(cve_index))

    tmpl = env.get_template("cve_search.html")
    html = tmpl.render(**base_ctx, current_slug="cve-search")
    (OUTPUT_DIR / "cve-search.html").write_text(html)
    logger.info("Written output/cve-search.html")

    tmpl = env.get_template("resources.html")
    html = tmpl.render(**base_ctx, current_slug="resources")
    (OUTPUT_DIR / "resources.html").write_text(html)
    logger.info("Written output/resources.html")

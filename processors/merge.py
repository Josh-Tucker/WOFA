"""
Feed merge processor.

Combines data from MSRC CVRF and CISA KEV into the WOFA feed structure.
Produces both a v2 feed (full CVE detail) and a v1 feed (summary only).
"""

import logging
from datetime import datetime, date, timezone, timedelta

import config
from collectors import msrc, cisa_kev, os_versions as os_versions_collector

logger = logging.getLogger(__name__)


def _months_to_fetch(n: int) -> list[str]:
    """
    Return the last n monthly MSRC update IDs that exist in the index.
    Also includes any out-of-band IDs (e.g. '2025-Mar-B') within the same window.
    """
    all_updates = msrc.get_updates_index()
    cutoff = (datetime.now(timezone.utc) - timedelta(days=n * 31)).isoformat()

    # Filter to updates within the window and exclude very old Azure Linux-only docs
    recent = [
        u for u in all_updates
        if u["date"] >= cutoff
        # Skip the ancient "Mariner Release Notes" entries that predate 2017 Windows CVRF
        and u["date"] >= "2017-01-01"
    ]
    return [u["id"] for u in recent]


def _build_update_name(os_name: str, doc_title: str, kb: str) -> str:
    """Construct a human-readable update name."""
    # doc_title is like "March 2025 Security Updates"
    # Produce: "Windows 11 24H2 - March 2025 Security Update (KB5050009)"
    month_part = doc_title.replace(" Security Updates", "").strip()
    return f"{os_name} - {month_part} Security Update (KB{kb})"


def build_feed() -> dict:
    """
    Build and return the feed dict.
    """
    # --- Collect KEV CVE IDs ---
    try:
        kev_ids = cisa_kev.get_kev_cve_ids()
    except Exception as exc:
        logger.warning("Could not fetch CISA KEV (proceeding without): %s", exc)
        kev_ids = set()

    # --- Collect MSRC data across recent months ---
    update_ids = _months_to_fetch(config.MONTHS_TO_FETCH)
    logger.info("Processing %d MSRC monthly releases", len(update_ids))

    # Derive OS version list from the most recent available CVRF document
    os_version_configs: list[dict] = []
    for uid in update_ids:
        try:
            doc = msrc.get_cvrf_document(uid)
            os_version_configs = os_versions_collector.from_cvrf_document(doc)
            if os_version_configs:
                logger.info(
                    "Tracking %d OS versions (discovered from %s): %s",
                    len(os_version_configs),
                    uid,
                    ", ".join(c["name"] for c in os_version_configs),
                )
                break
        except Exception as exc:
            logger.warning("Skipping %s for OS version discovery: %s", uid, exc)

    if not os_version_configs:
        raise RuntimeError("Could not discover any OS versions from CVRF documents")

    # {short_name: [release_dict, ...]}  — accumulate across months
    releases_by_os: dict[str, list[dict]] = {
        os_cfg["short_name"]: [] for os_cfg in os_version_configs
    }

    for uid in update_ids:
        try:
            cvrf_doc = msrc.get_cvrf_document(uid)
        except Exception as exc:
            logger.warning("Skipping %s (fetch error: %s)", uid, exc)
            continue

        extracted = msrc.extract_os_releases(cvrf_doc, os_version_configs)

        for sname, rel in extracted.items():
            # Cross-reference CVEs with KEV
            for cve_id, cve_data in rel["cves"].items():
                if cve_id in kev_ids:
                    cve_data["in_kev"] = True
                    cve_data["actively_exploited"] = True  # KEV implies exploitation

            releases_by_os[sname].append(rel)

    # --- Build per-OS-version output ---
    os_version_entries = []

    os_cfg_by_sname = {os["short_name"]: os for os in os_version_configs}

    for sname, releases in releases_by_os.items():
        if not releases:
            logger.info("No releases found for %s in the last %d months", sname, config.MONTHS_TO_FETCH)
            continue

        os_cfg = os_cfg_by_sname[sname]
        os_name = os_cfg["name"]

        # Sort newest first
        releases.sort(key=lambda r: r["release_date"] or "", reverse=True)

        # Calculate DaysSincePreviousRelease
        for i, rel in enumerate(releases):
            if i < len(releases) - 1 and rel["release_date"] and releases[i + 1]["release_date"]:
                try:
                    curr = date.fromisoformat(rel["release_date"])
                    prev = date.fromisoformat(releases[i + 1]["release_date"])
                    rel["days_since_previous"] = (curr - prev).days
                except ValueError:
                    rel["days_since_previous"] = None
            else:
                rel["days_since_previous"] = None

        security_releases = []
        for rel in releases:
            cves = rel["cves"]
            exploited = sorted(
                cve_id for cve_id, d in cves.items() if d.get("actively_exploited")
            )
            security_releases.append({
                "UpdateName": _build_update_name(os_name, rel["doc_title"], rel["kb_article"]),
                "ReleaseDate": rel["release_date"],
                "ProductVersion": rel["fixed_build"],
                "SecurityInfo": rel["support_url"],
                "CVEs": cves,
                "ActivelyExploitedCVEs": exploited,
                "UniqueCVEsCount": len(cves),
                "DaysSincePreviousRelease": rel["days_since_previous"],
                "Supersedes": rel["supersedes"],
            })

        latest = security_releases[0] if security_releases else {}

        os_version_entries.append({
            "OSVersion": os_name,
            "Group": os_cfg["group"],
            "VersionLabel": os_cfg["version_label"],
            "Latest": {
                "UpdateName": latest.get("UpdateName"),
                "ProductVersion": latest.get("ProductVersion"),
                "ReleaseDate": latest.get("ReleaseDate"),
                "SecurityInfo": latest.get("SecurityInfo"),
                "ActivelyExploitedCVEs": latest.get("ActivelyExploitedCVEs", []),
                "UniqueCVEsCount": latest.get("UniqueCVEsCount", 0),
            },
            "SecurityReleases": security_releases,
        })

    return {
        "Version": "1.0",
        "OSVersions": os_version_entries,
    }

"""
Feed merge processor.

Combines data from MSRC CVRF and CISA KEV into the WOFA feed structure.
"""

import logging
import re
from datetime import date, datetime, timedelta, timezone

import config
from collectors import cisa_kev, lifecycle, msrc, release_health
from collectors import os_versions as os_versions_collector

logger = logging.getLogger(__name__)

# Regular Patch Tuesday IDs are exactly "YYYY-Mon" (e.g. "2025-Mar").
# Out-of-band releases append a letter suffix, e.g. "2025-Mar-B".
_RE_PATCH_TUESDAY_ID = re.compile(r"^\d{4}-[A-Za-z]{3}$")


def _is_patch_tuesday(update_id: str) -> bool:
    return bool(_RE_PATCH_TUESDAY_ID.match(update_id))


def _months_to_fetch(n: int) -> list[str]:
    """
    Return the last n monthly MSRC update IDs that exist in the index.
    Also includes any out-of-band IDs (e.g. '2025-Mar-B') within the same window.
    """
    all_updates = msrc.get_updates_index()
    cutoff = (datetime.now(timezone.utc) - timedelta(days=n * 31)).isoformat()

    # Filter to updates within the window and exclude very old Azure Linux-only docs
    recent = [
        u
        for u in all_updates
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


def _oob_update_name(os_name: str, update_type: str, kb: str) -> str:
    """Construct update name for an OOB release from release health data."""
    # update_type like "2026-03 OOB" → "Windows 11 24H2 - March 2026 Out-of-Band (KB5085516)"
    try:
        ym = update_type.split()[0]
        year, month = ym.split("-")
        month_name = datetime.strptime(month, "%m").strftime("%B")
        label = f"{month_name} {year}"
    except Exception:
        label = update_type
    suffix = f" (KB{kb})" if kb else ""
    return f"{os_name} - {label} Out-of-Band{suffix}"


def _normalize_build(build: str | None) -> str:
    """Strip '10.0.' prefix so MSRC and release health builds can be compared."""
    return (build or "").removeprefix("10.0.")


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

    # --- Fetch release health data (GA versions + build history) ---
    groups_with_release_health = set(config.RELEASE_HEALTH_URLS.keys())
    ga_versions_by_group: dict[str, set[str]] = {}
    release_history_by_group: dict[str, dict[str, list]] = {}
    for group in groups_with_release_health:
        ga = release_health.get_ga_versions(group)
        if ga:
            ga_versions_by_group[group] = ga
        history = release_health.get_release_history(group)
        if history:
            release_history_by_group[group] = history

    os_versions_collector.mark_insider_builds(os_version_configs, ga_versions_by_group)

    if not config.INCLUDE_INSIDER_BUILDS:
        before = len(os_version_configs)
        os_version_configs = [c for c in os_version_configs if not c.get("is_insider")]
        logger.info(
            "Excluded %d Insider builds (INCLUDE_INSIDER_BUILDS=False)",
            before - len(os_version_configs),
        )

    # Re-sort after marking (insider penalty applied in sort key)
    os_version_configs.sort(key=os_versions_collector._sort_key)

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
        patch_tuesday = _is_patch_tuesday(uid)

        for sname, rel in extracted.items():
            rel["patch_tuesday_release"] = patch_tuesday
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
            logger.info(
                "No releases found for %s in the last %d months", sname, config.MONTHS_TO_FETCH
            )
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
            exploited = sorted(cve_id for cve_id, d in cves.items() if d.get("actively_exploited"))
            security_releases.append(
                {
                    "UpdateName": _build_update_name(os_name, rel["doc_title"], rel["kb_article"]),
                    "ReleaseDate": rel["release_date"],
                    "ProductVersion": rel["fixed_build"],
                    "SecurityInfo": rel["support_url"],
                    "CVEs": cves,
                    "ActivelyExploitedCVEs": exploited,
                    "UniqueCVEsCount": len(cves),
                    "DaysSincePreviousRelease": rel["days_since_previous"],
                    "Supersedes": rel["supersedes"],
                    "PatchTuesdayRelease": rel["patch_tuesday_release"],
                }
            )

        # Inject OOB releases from release health page not already covered by MSRC CVRF.
        # OOBs are cumulative so knowing if a machine is on an OOB build matters for vuln status.
        is_insider = os_cfg.get("is_insider", False)
        group = os_cfg["group"]
        version_label = os_cfg["version_label"].upper()
        version_history = release_history_by_group.get(group, {}).get(version_label, [])

        if not is_insider:
            existing_builds = {_normalize_build(r["ProductVersion"]) for r in security_releases}
            for rh_rel in version_history:
                if rh_rel.get("week") != "OOB":
                    continue
                short = _normalize_build(rh_rel["build"])
                if short in existing_builds:
                    continue
                kb = rh_rel.get("kb_number", "")
                raw_build = rh_rel["build"]
                # Release health page omits the "10.0." prefix; add it for consistency with MSRC data
                build = f"10.0.{raw_build}" if re.match(r"^\d{5}\.\d+$", raw_build) else raw_build
                security_releases.append(
                    {
                        "UpdateName": _oob_update_name(os_name, rh_rel["update_type"], kb),
                        "ReleaseDate": rh_rel["availability_date"],
                        "ProductVersion": build,
                        "SecurityInfo": rh_rel.get("kb_url") or None,
                        "CVEs": {},
                        "ActivelyExploitedCVEs": [],
                        "UniqueCVEsCount": 0,
                        "DaysSincePreviousRelease": None,
                        "Supersedes": None,
                        "PatchTuesdayRelease": False,
                    }
                )
                existing_builds.add(short)

            # Re-sort and recalculate gaps after OOB injection
            security_releases.sort(key=lambda r: r["ReleaseDate"] or "", reverse=True)
            for i, rel in enumerate(security_releases):
                prev_rel = security_releases[i + 1] if i + 1 < len(security_releases) else None
                if prev_rel and rel["ReleaseDate"] and prev_rel["ReleaseDate"]:
                    try:
                        curr = date.fromisoformat(rel["ReleaseDate"])
                        prev = date.fromisoformat(prev_rel["ReleaseDate"])
                        rel["DaysSincePreviousRelease"] = (curr - prev).days
                    except ValueError:
                        rel["DaysSincePreviousRelease"] = None
                else:
                    rel["DaysSincePreviousRelease"] = None

        latest = security_releases[0] if security_releases else {}

        # Build NonSecurityReleases: D/C week previews for stable; all entries for Insider.
        non_security_releases = []
        for rel in version_history:
            week = rel.get("week", "")
            include = is_insider or week in ("D", "C")
            if not include:
                continue
            entry = {
                "UpdateType": rel["update_type"],
                "ReleaseDate": rel["availability_date"],
                "ProductVersion": rel["build"],
                "KB": rel["kb_number"],
                "SecurityInfo": rel["kb_url"] or None,
            }
            non_security_releases.append(entry)

        os_version_entries.append(
            {
                "OSVersion": os_name,
                "Group": os_cfg["group"],
                "VersionLabel": os_cfg["version_label"],
                "IsInsider": is_insider,
                "SupportEndDate": lifecycle.get_support_end_dates(os_cfg),
                "Latest": {
                    "UpdateName": latest.get("UpdateName"),
                    "ProductVersion": latest.get("ProductVersion"),
                    "ReleaseDate": latest.get("ReleaseDate"),
                    "SecurityInfo": latest.get("SecurityInfo"),
                    "ActivelyExploitedCVEs": latest.get("ActivelyExploitedCVEs", []),
                    "UniqueCVEsCount": latest.get("UniqueCVEsCount", 0),
                },
                "SecurityReleases": security_releases,
                "NonSecurityReleases": non_security_releases,
            }
        )

    return {
        "Version": "1.0",
        "OSVersions": os_version_entries,
    }

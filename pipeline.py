#!/usr/bin/env python3
"""
WOFA Pipeline — entry point.

Fetches Windows security update data from public sources and writes:
  output/v1/windows_data_feed.json  — full feed with CVE severity/exploitation data
  output/metadata.json              — hash + timestamp
  output/windows_release_feed.rss   — RSS feed (latest release per OS version)

Usage:
  python pipeline.py
"""

import hashlib
import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

from processors import merge, rss, site

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger("wofa.pipeline")

OUTPUT = Path("output")


def _write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False))
    logger.info("Written %s", path)


def main() -> None:
    logger.info("WOFA pipeline starting")

    # Build feed
    feed = merge.build_feed()

    # Compute a stable hash of the content (before adding timestamp)
    canonical = json.dumps(feed, sort_keys=True, ensure_ascii=False)
    feed_hash = hashlib.sha256(canonical.encode()).hexdigest()
    timestamp = datetime.now(timezone.utc).isoformat()

    feed["UpdateHash"] = feed_hash
    feed["LastCheck"] = timestamp

    _write_json(OUTPUT / "v1" / "windows_data_feed.json", feed)

    # Metadata summary
    total_cves = sum(
        r["UniqueCVEsCount"]
        for os_entry in feed.get("OSVersions", [])
        for r in os_entry.get("SecurityReleases", [])
    )
    total_exploited = sum(
        len(r["ActivelyExploitedCVEs"])
        for os_entry in feed.get("OSVersions", [])
        for r in os_entry.get("SecurityReleases", [])
    )
    metadata = {
        "UpdateHash": feed_hash,
        "LastCheck": timestamp,
        "OSVersionsTracked": len(feed.get("OSVersions", [])),
        "TotalSecurityReleases": sum(
            len(os_entry.get("SecurityReleases", []))
            for os_entry in feed.get("OSVersions", [])
        ),
        "TotalCVEsTracked": total_cves,
        "TotalActivelyExploited": total_exploited,
    }
    _write_json(OUTPUT / "metadata.json", metadata)

    # RSS
    try:
        rss_content = rss.generate_rss(feed)
        rss_path = OUTPUT / "windows_release_feed.rss"
        rss_path.write_text(rss_content)
        logger.info("Written %s", rss_path)
    except Exception as exc:
        logger.warning("RSS generation failed (non-fatal): %s", exc)

    # Static site
    try:
        site.generate(feed)
    except Exception as exc:
        logger.warning("Site generation failed (non-fatal): %s", exc)

    logger.info(
        "Pipeline complete — hash=%s  OS versions=%d  CVEs=%d  exploited=%d",
        feed_hash[:12],
        metadata["OSVersionsTracked"],
        total_cves,
        total_exploited,
    )


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
    except Exception:
        logger.exception("Pipeline failed")
        sys.exit(1)

"""
RSS feed generator.

Produces an RSS 2.0 feed from the WOFA v2 feed data, with one entry
per OS version's latest release. Uses feedgen.
"""

import contextlib
import logging
from datetime import datetime, timezone

from feedgen.feed import FeedGenerator

logger = logging.getLogger(__name__)

FEED_TITLE = "WOFA — Windows Security Updates"
FEED_LINK = "https://github.com/wofa/wofa"
FEED_DESCRIPTION = (
    "Windows cumulative security update feed tracking CVEs, "
    "exploited vulnerabilities, and patch details per OS version."
)


def generate_rss(v2_feed: dict) -> str:
    """
    Generate an RSS feed string from a v2 feed dict.
    Each OS version's latest security release becomes one RSS entry.
    """
    fg = FeedGenerator()
    fg.id(FEED_LINK)
    fg.title(FEED_TITLE)
    fg.link(href=FEED_LINK, rel="alternate")
    fg.description(FEED_DESCRIPTION)
    fg.language("en")
    fg.lastBuildDate(datetime.now(timezone.utc))

    for os_entry in v2_feed.get("OSVersions", []):
        releases = os_entry.get("SecurityReleases", [])
        if not releases:
            continue

        latest = releases[0]
        update_name = latest.get("UpdateName", os_entry["OSVersion"])
        release_date_str = latest.get("ReleaseDate")
        security_info = latest.get("SecurityInfo", "")
        exploited = latest.get("ActivelyExploitedCVEs", [])
        cve_count = latest.get("UniqueCVEsCount", 0)
        product_version = latest.get("ProductVersion", "")

        # Parse release date
        pub_date = None
        if release_date_str:
            with contextlib.suppress(ValueError):
                pub_date = datetime.fromisoformat(release_date_str).replace(tzinfo=timezone.utc)

        # Build description
        lines = [f"<p><strong>{update_name}</strong></p>"]
        if product_version:
            lines.append(f"<p>Build: {product_version}</p>")
        lines.append(f"<p>CVEs addressed: {cve_count}</p>")
        if exploited:
            lines.append(
                f"<p><strong>Actively exploited CVEs ({len(exploited)}):</strong> "
                + ", ".join(exploited[:10])
                + ("…" if len(exploited) > 10 else "")
                + "</p>"
            )
        if security_info:
            lines.append(f'<p><a href="{security_info}">KB article</a></p>')

        fe = fg.add_entry()
        fe.id(security_info or f"{FEED_LINK}/{update_name}")
        fe.title(update_name)
        fe.link(href=security_info or FEED_LINK)
        fe.description("".join(lines))
        if pub_date:
            fe.pubDate(pub_date)

    return fg.rss_str(pretty=True).decode("utf-8")

"""
Central configuration for WOFA pipeline.
"""

# How many months of MSRC history to include in the feed
MONTHS_TO_FETCH = 12

# Output directory for generated feed files
OUTPUT_DIR = "output"

# Cache directory for downloaded CVRF documents (avoids re-fetching on repeated runs)
CACHE_DIR = ".cache"

# Cache TTL in hours (CVRF docs are immutable once published; index refreshes more often)
CACHE_TTL_CVRF_HOURS = 168   # 7 days — monthly docs don't change
CACHE_TTL_INDEX_HOURS = 1    # Index may add new entries (out-of-band releases)
CACHE_TTL_KEV_HOURS = 6      # CISA updates KEV a few times per week

MSRC_API_BASE = "https://api.msrc.microsoft.com/cvrf/v3.0"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

USER_AGENT = "WOFA/1.0 (+https://github.com/wofa/wofa)"

# Windows OS versions to track.
# product_patterns are substrings matched against CVRF ProductTree names.
# All patterns are case-insensitive. Multiple patterns are OR'd.
OS_VERSIONS = [
    {
        "name": "Windows 11 24H2",
        "short_name": "win11_24h2",
        "group": "Windows 11",
        "version_label": "24H2",
        "product_patterns": ["Windows 11 Version 24H2"],
    },
    {
        "name": "Windows 11 23H2",
        "short_name": "win11_23h2",
        "group": "Windows 11",
        "version_label": "23H2",
        "product_patterns": ["Windows 11 Version 23H2"],
    },
    {
        "name": "Windows 10 22H2",
        "short_name": "win10_22h2",
        "group": "Windows 10",
        "version_label": "22H2",
        "product_patterns": ["Windows 10 Version 22H2"],
    },
    {
        "name": "Windows Server 2025",
        "short_name": "winserver_2025",
        "group": "Windows Server",
        "version_label": "2025",
        "product_patterns": ["Windows Server 2025"],
    },
    {
        "name": "Windows Server 2022",
        "short_name": "winserver_2022",
        "group": "Windows Server",
        "version_label": "2022",
        "product_patterns": ["Windows Server 2022"],
    },
    {
        "name": "Windows Server 2019",
        "short_name": "winserver_2019",
        "group": "Windows Server",
        "version_label": "2019",
        "product_patterns": ["Windows Server 2019"],
    },
]

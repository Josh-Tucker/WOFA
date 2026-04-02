"""
Central configuration for WOFA pipeline.
"""

# How many months of MSRC history to include in the feed
MONTHS_TO_FETCH = 12

# Public URL of the deployed site (no trailing slash).
# Used in code examples and feed endpoint references.
SITE_URL = "https://wofa.jtucker.me.uk"

# Output directory for generated feed files
OUTPUT_DIR = "output"

# Cache directory for downloaded CVRF documents (avoids re-fetching on repeated runs)
CACHE_DIR = ".cache"

# Cache TTL in hours (CVRF docs are immutable once published; index refreshes more often)
CACHE_TTL_CVRF_HOURS = 168  # 7 days — monthly docs don't change
CACHE_TTL_INDEX_HOURS = 1  # Index may add new entries (out-of-band releases)
CACHE_TTL_KEV_HOURS = 6  # CISA updates KEV a few times per week
CACHE_TTL_LIFECYCLE_HOURS = 168  # 7 days — lifecycle dates rarely change

MSRC_API_BASE = "https://api.msrc.microsoft.com/cvrf/v3.0"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

USER_AGENT = "WOFA/1.0 (+https://github.com/wofa/wofa)"

# OS versions are discovered automatically from the MSRC CVRF ProductTree.
# See collectors/os_versions.py — any version Microsoft is actively patching
# will be included without manual config changes.

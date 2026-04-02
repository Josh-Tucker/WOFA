# WOFA — Windows Organized Feed for Admins

Aggregates Windows cumulative security update data from public sources ([MSRC CVRF API](https://api.msrc.microsoft.com/cvrf/v3.0) and [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)) and produces machine-readable feeds for system administrators and MDM tooling.

**Outputs:**

| File | Description |
|---|---|
| `output/v1/windows_data_feed.json` | Full feed — CVE severity, exploitation status, patch details per OS version |
| `output/metadata.json` | Summary stats and SHA-256 hash of the feed |
| `output/windows_release_feed.rss` | RSS feed — latest release per OS version |
| `output/*.html` | Static site for browsing the data |

OS versions are discovered automatically from the MSRC ProductTree — no manual config needed when Microsoft adds a new version.

---

## Development setup

### Prerequisites

- Python 3.10+
- A virtual environment tool (`venv` is fine)

### 1. Clone and create a venv

```sh
git clone <repo-url>
cd wofa
python3 -m venv .venv
source .venv/bin/activate
```

### 2. Install dependencies

```sh
pip install -r requirements.txt
pip install ruff pre-commit
```

### 3. Install git hooks

```sh
pre-commit install
```

This installs a pre-commit hook that runs ruff lint and format checks automatically on every `git commit`.

---

## Running the pipeline

```sh
python pipeline.py
```

Output is written to `./output/`. The pipeline caches downloaded CVRF documents in `.cache/` to avoid re-fetching on repeated runs (TTL: 7 days for monthly docs, 1 hour for the index, 6 hours for CISA KEV).

To force a fresh fetch, delete the cache:

```sh
rm -rf .cache/
```

---

## Linting and formatting

Linting and formatting are handled by [ruff](https://docs.astral.sh/ruff/). Configuration lives in `pyproject.toml`.

**Check for lint issues:**

```sh
ruff check .
```

**Auto-fix lint issues:**

```sh
ruff check --fix .
```

**Check formatting:**

```sh
ruff format --check .
```

**Apply formatting:**

```sh
ruff format .
```

**Run both in one go:**

```sh
ruff check --fix . && ruff format .
```

The pre-commit hook runs `ruff check --fix` and `ruff format` automatically before each commit. To run all hooks manually against staged files:

```sh
pre-commit run
```

Or against all files:

```sh
pre-commit run --all-files
```

---

## Configuration

Key settings in `config.py`:

| Variable | Default | Description |
|---|---|---|
| `MONTHS_TO_FETCH` | `12` | How many months of MSRC history to include |
| `SITE_URL` | `https://wofa.example.com` | Public URL used in feed references |
| `OUTPUT_DIR` | `output` | Where generated files are written |
| `CACHE_DIR` | `.cache` | Where downloaded CVRF docs are cached |
| `CACHE_TTL_CVRF_HOURS` | `168` | CVRF doc cache TTL (7 days) |
| `CACHE_TTL_INDEX_HOURS` | `1` | MSRC index cache TTL |
| `CACHE_TTL_KEV_HOURS` | `6` | CISA KEV cache TTL |

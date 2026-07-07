"""EPSS and CISA KEV enrichment clients with in-process caching.

Both sources are fully public and keyless:
- EPSS (FIRST.org): daily exploitation probability per CVE
  https://www.first.org/epss/api
- CISA KEV: the Known Exploited Vulnerabilities catalog
  https://www.cisa.gov/known-exploited-vulnerabilities-catalog

Enrichment is best-effort: fetch failures are logged and swallowed so the
tool layer always gets a dict back (possibly empty), never an exception.
"""

import logging
import time

import httpx

from . import http_client

EPSS_API_URL = "https://api.first.org/data/v1/epss"
KEV_CATALOG_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)

EPSS_BATCH_SIZE = 100
EPSS_TTL_SECONDS = 24 * 3600  # EPSS scores update daily
KEV_TTL_SECONDS = 6 * 3600

logger = logging.getLogger(__name__)

# Caches: cve -> (fetched_at, (score, percentile) | None for a known miss);
# KEV catalog -> [fetched_at, {cveID: {...}}] when populated
_epss_cache: dict[str, tuple[float, tuple[float, float] | None]] = {}
_kev_cache: list = []


class EnrichmentError(Exception):
    """Raised when an enrichment API returns an error or unexpected response."""


def clear_cache() -> None:
    """Reset all caches (used by tests)."""
    _epss_cache.clear()
    _kev_cache.clear()


async def _get_json(url: str, timeout: float = 30.0) -> dict:
    """GET a URL and return parsed JSON, raising EnrichmentError on failure."""
    headers = {"Accept": "application/json"}
    try:
        client = http_client.get_client()
        response = await client.get(url, headers=headers, timeout=timeout)
    except httpx.HTTPError as exc:
        raise EnrichmentError(f"Enrichment request failed: {exc}") from exc

    if response.status_code != 200:
        raise EnrichmentError(f"Enrichment API returned HTTP {response.status_code}")

    try:
        return response.json()
    except ValueError as exc:
        raise EnrichmentError("Enrichment API returned invalid JSON") from exc


async def fetch_kev() -> dict[str, dict]:
    """Fetch the CISA KEV catalog keyed by CVE ID.

    Returns {} on failure — enrichment must never break a search.
    """
    now = time.monotonic()
    if _kev_cache and now - _kev_cache[0] < KEV_TTL_SECONDS:
        return _kev_cache[1]

    try:
        data = await _get_json(KEV_CATALOG_URL, timeout=60.0)
    except EnrichmentError as exc:
        logger.warning("KEV catalog fetch failed: %s", exc)
        return {}

    catalog: dict[str, dict] = {}
    for entry in data.get("vulnerabilities", []):
        cve_id = entry.get("cveID")
        if not cve_id:
            continue
        catalog[cve_id] = {
            "date_added": entry.get("dateAdded"),
            "due_date": entry.get("dueDate"),
            "ransomware_use": entry.get("knownRansomwareCampaignUse"),
        }

    _kev_cache[:] = [now, catalog]
    return catalog


async def fetch_epss(cves: list[str]) -> dict[str, tuple[float, float]]:
    """Fetch EPSS (score, percentile) for the given CVEs, batching and caching.

    CVEs unknown to EPSS are absent from the result (and negatively cached so
    they are not re-requested within the TTL). Partial results are returned
    when some batches fail.
    """
    now = time.monotonic()
    results: dict[str, tuple[float, float]] = {}
    uncached: list[str] = []
    seen: set[str] = set()

    for cve in cves:
        if not cve or cve in seen:
            continue
        seen.add(cve)
        cached = _epss_cache.get(cve)
        if cached and now - cached[0] < EPSS_TTL_SECONDS:
            if cached[1] is not None:
                results[cve] = cached[1]
        else:
            uncached.append(cve)

    for start in range(0, len(uncached), EPSS_BATCH_SIZE):
        batch = uncached[start : start + EPSS_BATCH_SIZE]
        try:
            data = await _get_json(f"{EPSS_API_URL}?cve={','.join(batch)}")
        except EnrichmentError as exc:
            logger.warning("EPSS fetch failed for batch of %d CVEs: %s", len(batch), exc)
            continue

        fetched: dict[str, tuple[float, float]] = {}
        for entry in data.get("data", []):
            cve = entry.get("cve")
            try:
                score = float(entry["epss"])
                percentile = float(entry["percentile"])
            except (KeyError, TypeError, ValueError):
                continue
            if cve:
                fetched[cve] = (score, percentile)

        for cve in batch:
            # Absent CVEs are cached as misses so repeat calls stay cache-only
            _epss_cache[cve] = (now, fetched.get(cve))
            if cve in fetched:
                results[cve] = fetched[cve]

    return results

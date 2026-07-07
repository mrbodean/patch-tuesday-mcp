"""MSRC CVRF v3 API client with in-process caching.

The MSRC Security Update Guide CVRF API is public and requires no authentication:
https://github.com/microsoft/MSRC-Microsoft-Security-Updates-API
"""

import asyncio
import time
from datetime import datetime

import httpx

from .. import telemetry
from ..models.vulnerability import MonthlyRelease, parse_cvrf, parse_release_date
from . import http_client

MSRC_API_BASE = "https://api.msrc.microsoft.com/cvrf/v3.0"

# Monthly docs can receive revisions; refresh recent months hourly. Older
# months change rarely and are cached until evicted.
RECENT_MONTH_TTL_SECONDS = 3600
INDEX_TTL_SECONDS = 3600
RECENT_MONTHS_WITH_TTL = 2

# The MSRC index spans 125+ months, each a multi-MB document that parses to
# even more; unbounded caches would OOM a small container if someone iterates
# months. Full parses (with descriptions/FAQs) are the big ones; slim parses
# are kept longer because chain walking scans up to 24 months.
MAX_FULL_MONTHS_CACHED = 6
MAX_SLIM_MONTHS_CACHED = 40

# Bound concurrent upstream fetch+parse work (each doc is multi-MB)
FETCH_CONCURRENCY = 3

_MONTH_ABBRS = [
    "Jan",
    "Feb",
    "Mar",
    "Apr",
    "May",
    "Jun",
    "Jul",
    "Aug",
    "Sep",
    "Oct",
    "Nov",
    "Dec",
]

# Caches: month_id -> (fetched_at, MonthlyRelease); index -> (fetched_at, entries)
_month_cache: dict[str, tuple[float, MonthlyRelease]] = {}
# Slim parses (no descriptions/FAQs) kept separately so chain walking across
# many months stays within the container memory budget
_slim_month_cache: dict[str, tuple[float, MonthlyRelease]] = {}
_index_cache: list = []  # [fetched_at, entries] when populated

# Single-flight: concurrent cold requests for the same month fetch it once
_month_locks: dict[str, asyncio.Lock] = {}
_fetch_semaphore: asyncio.Semaphore | None = None
_semaphore_loop: asyncio.AbstractEventLoop | None = None


class MsrcApiError(Exception):
    """Raised when the MSRC API returns an error or unexpected response."""


def clear_cache() -> None:
    """Reset all caches (used by tests)."""
    global _fetch_semaphore, _semaphore_loop
    _month_cache.clear()
    _slim_month_cache.clear()
    _index_cache.clear()
    _month_locks.clear()
    _fetch_semaphore = None
    _semaphore_loop = None


def _get_fetch_semaphore() -> asyncio.Semaphore:
    """Lazily create the fetch semaphore on the running loop."""
    global _fetch_semaphore, _semaphore_loop
    loop = asyncio.get_running_loop()
    if _fetch_semaphore is None or _semaphore_loop is not loop:
        _fetch_semaphore = asyncio.Semaphore(FETCH_CONCURRENCY)
        _semaphore_loop = loop
    return _fetch_semaphore


def normalize_month_id(month: str) -> str | None:
    """Normalize month input to the MSRC ID format.

    Accepts "2026-Jun", "2026-06", or "2026-6"; returns "2026-Jun".
    Returns None when the input cannot be parsed.
    """
    month = month.strip()
    parts = month.split("-")
    if len(parts) != 2:
        return None
    year, month_part = parts
    if not (year.isdigit() and len(year) == 4):
        return None

    if month_part.isdigit():
        month_num = int(month_part)
        if not 1 <= month_num <= 12:
            return None
        return f"{year}-{_MONTH_ABBRS[month_num - 1]}"

    month_title = month_part.capitalize()
    if month_title in _MONTH_ABBRS:
        return f"{year}-{month_title}"
    return None


async def _get_json(url: str, timeout: float = 60.0) -> dict:
    """GET a URL and return parsed JSON, raising MsrcApiError on failure."""
    headers = {"Accept": "application/json"}
    try:
        client = http_client.get_client()
        response = await client.get(url, headers=headers, timeout=timeout)
    except httpx.HTTPError as exc:
        raise MsrcApiError(f"MSRC API request failed: {exc}") from exc

    if response.status_code == 404:
        raise MsrcApiError("not found")
    if response.status_code != 200:
        raise MsrcApiError(f"MSRC API returned HTTP {response.status_code}")

    try:
        return response.json()
    except ValueError as exc:
        raise MsrcApiError("MSRC API returned invalid JSON") from exc


async def fetch_update_index() -> list[dict]:
    """Fetch the list of monthly security update documents.

    Returns entries sorted newest-first, filtered to security update releases
    (the raw index also contains Mariner/Azure Linux release-notes documents).
    """
    now = time.monotonic()
    if _index_cache and now - _index_cache[0] < INDEX_TTL_SECONDS:
        return _index_cache[1]

    data = await _get_json(f"{MSRC_API_BASE}/updates", timeout=30.0)
    entries = []
    for item in data.get("value", []):
        title = item.get("DocumentTitle") or ""
        if "Security Updates" not in title:
            continue
        entries.append(
            {
                "id": item.get("ID"),
                "title": title,
                "initial_release_date": item.get("InitialReleaseDate"),
                "current_release_date": item.get("CurrentReleaseDate"),
            }
        )

    entries.sort(
        key=lambda e: parse_release_date(e["initial_release_date"]) or datetime.min,
        reverse=True,
    )

    _index_cache[:] = [now, entries]
    return entries


async def get_latest_month_id() -> str:
    """Return the ID of the most recent monthly security update release."""
    entries = await fetch_update_index()
    if not entries:
        raise MsrcApiError("MSRC update index returned no security update documents")
    return entries[0]["id"]


async def _cached_month(month_id: str, slim: bool, now: float) -> MonthlyRelease | None:
    """Return a cached parse if present and fresh enough, else None."""
    caches = [_month_cache, _slim_month_cache] if slim else [_month_cache]
    for cache in caches:
        cached = cache.get(month_id)
        if cached:
            fetched_at, release = cached
            if not await _is_recent_month(month_id) or now - fetched_at < RECENT_MONTH_TTL_SECONDS:
                return release
    return None


def _evict_oldest(cache: dict[str, tuple[float, MonthlyRelease]], max_entries: int) -> None:
    while len(cache) > max_entries:
        oldest = min(cache, key=lambda k: cache[k][0])
        del cache[oldest]


async def fetch_month(month_id: str, slim: bool = False) -> MonthlyRelease:
    """Fetch and parse a monthly CVRF document, using the cache when possible.

    slim=True skips descriptions/FAQs (for chain walking across many months).
    A cached full parse can satisfy a slim request, but never the reverse.
    """
    cached = await _cached_month(month_id, slim, time.monotonic())
    if cached is not None:
        return cached

    lock = _month_locks.setdefault(month_id, asyncio.Lock())
    async with lock:
        # Another task may have fetched while we waited on the lock
        cached = await _cached_month(month_id, slim, time.monotonic())
        if cached is not None:
            return cached

        start = time.perf_counter()
        async with _get_fetch_semaphore():
            doc = await _get_json(f"{MSRC_API_BASE}/cvrf/{month_id}", timeout=120.0)
            release = parse_cvrf(doc, include_text=not slim)
        telemetry.track_event(
            "msrc_fetch",
            {
                "month": month_id,
                "slim": slim,
                "duration_ms": round((time.perf_counter() - start) * 1000, 1),
            },
        )
        cache = _slim_month_cache if slim else _month_cache
        cache[month_id] = (time.monotonic(), release)
        _evict_oldest(cache, MAX_SLIM_MONTHS_CACHED if slim else MAX_FULL_MONTHS_CACHED)
        return release


async def _is_recent_month(month_id: str) -> bool:
    """Whether a month is recent enough that revisions are likely."""
    try:
        entries = await fetch_update_index()
    except MsrcApiError:
        return True  # be conservative: treat as recent so it gets refreshed
    recent_ids = [e["id"] for e in entries[:RECENT_MONTHS_WITH_TTL]]
    return month_id in recent_ids


async def find_month_for_cve(cve_id: str) -> str | None:
    """Find which monthly document contains a CVE. Returns None when unknown."""
    try:
        data = await _get_json(f"{MSRC_API_BASE}/updates('{cve_id}')", timeout=30.0)
    except MsrcApiError as exc:
        if "not found" in str(exc):
            return None
        raise
    values = data.get("value", [])
    if not values:
        return None
    return values[0].get("ID")

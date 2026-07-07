"""Tests for the MSRC API client (mocked HTTP)."""

import asyncio
import json
from pathlib import Path

import pytest

from patch_tuesday_mcp.feeds import msrc_api
from patch_tuesday_mcp.feeds.msrc_api import (
    MsrcApiError,
    clear_cache,
    fetch_month,
    fetch_update_index,
    find_month_for_cve,
    get_latest_month_id,
    normalize_month_id,
)

FIXTURE = Path(__file__).parent / "fixtures" / "cvrf_sample.json"

INDEX_RESPONSE = {
    "value": [
        {
            "ID": "2026-May",
            "DocumentTitle": "May 2026 Security Updates",
            "InitialReleaseDate": "2026-05-12T07:00:00Z",
            "CurrentReleaseDate": "2026-06-01T07:00:00Z",
        },
        {
            "ID": "2000-Feb",
            "DocumentTitle": "Mariner Release Notes",
            "InitialReleaseDate": "2000-02-02T00:00:00Z",
            "CurrentReleaseDate": "2026-02-19T01:07:19Z",
        },
        {
            "ID": "2026-Jun",
            "DocumentTitle": "June 2026 Security Updates",
            "InitialReleaseDate": "2026-06-09T07:00:00Z",
            "CurrentReleaseDate": "2026-07-07T07:00:00Z",
        },
    ]
}


@pytest.fixture(autouse=True)
def reset_cache():
    clear_cache()
    yield
    clear_cache()


@pytest.fixture
def mock_api(monkeypatch):
    """Patch _get_json with canned responses and record calls."""
    calls = []

    with open(FIXTURE, encoding="utf-8") as f:
        cvrf_doc = json.load(f)

    async def fake_get_json(url, timeout=60.0):
        calls.append(url)
        if url.endswith("/updates"):
            return INDEX_RESPONSE
        if "/updates('CVE-2026-41108')" in url:
            return {"value": [{"ID": "2026-Jun"}]}
        if "/updates('CVE-1900-00000')" in url:
            raise MsrcApiError("not found")
        if url.endswith("/cvrf/2026-Jun"):
            return cvrf_doc
        raise MsrcApiError(f"unexpected URL in test: {url}")

    monkeypatch.setattr(msrc_api, "_get_json", fake_get_json)
    return calls


def test_normalize_month_id():
    assert normalize_month_id("2026-Jun") == "2026-Jun"
    assert normalize_month_id("2026-jun") == "2026-Jun"
    assert normalize_month_id("2026-06") == "2026-Jun"
    assert normalize_month_id("2026-6") == "2026-Jun"
    assert normalize_month_id("2026-13") is None
    assert normalize_month_id("junk") is None
    assert normalize_month_id("2026-Junk") is None
    assert normalize_month_id("26-06") is None


async def test_fetch_update_index_filters_and_sorts(mock_api):
    entries = await fetch_update_index()
    assert [e["id"] for e in entries] == ["2026-Jun", "2026-May"]
    assert all("Security Updates" in e["title"] for e in entries)


async def test_index_is_cached(mock_api):
    await fetch_update_index()
    await fetch_update_index()
    index_calls = [c for c in mock_api if c.endswith("/updates")]
    assert len(index_calls) == 1


async def test_get_latest_month_id(mock_api):
    assert await get_latest_month_id() == "2026-Jun"


async def test_fetch_month_parses_and_caches(mock_api):
    release = await fetch_month("2026-Jun")
    assert release.id == "2026-Jun"
    assert len(release.vulnerabilities) == 6

    await fetch_month("2026-Jun")
    doc_calls = [c for c in mock_api if c.endswith("/cvrf/2026-Jun")]
    assert len(doc_calls) == 1, "second fetch should hit the cache"


async def test_find_month_for_cve(mock_api):
    assert await find_month_for_cve("CVE-2026-41108") == "2026-Jun"
    assert await find_month_for_cve("CVE-1900-00000") is None


async def test_slim_fetch_skips_text_and_caches_separately(mock_api):
    slim = await fetch_month("2026-Jun", slim=True)
    assert all(v.description == "" for v in slim.vulnerabilities)
    assert all(v.faqs == [] for v in slim.vulnerabilities)

    # A slim entry must NOT satisfy a full request
    full = await fetch_month("2026-Jun")
    assert any(v.description for v in full.vulnerabilities)
    doc_calls = [c for c in mock_api if c.endswith("/cvrf/2026-Jun")]
    assert len(doc_calls) == 2, "full fetch after slim requires a re-fetch"

    # ...but a full entry satisfies later slim requests
    again = await fetch_month("2026-Jun", slim=True)
    assert again is full
    doc_calls = [c for c in mock_api if c.endswith("/cvrf/2026-Jun")]
    assert len(doc_calls) == 2, "slim request after full parse hits the full cache"


async def test_index_sort_handles_missing_dates(monkeypatch):
    """An index entry without a release date must not break sorting."""
    index = {
        "value": [
            {
                "ID": "0000-Bad",
                "DocumentTitle": "Broken Security Updates",
                "InitialReleaseDate": None,
                "CurrentReleaseDate": None,
            },
            {
                "ID": "2026-Jun",
                "DocumentTitle": "June 2026 Security Updates",
                "InitialReleaseDate": "2026-06-09T07:00:00Z",
                "CurrentReleaseDate": "2026-07-07T07:00:00Z",
            },
        ]
    }

    async def fake_get_json(url, timeout=60.0):
        return index

    monkeypatch.setattr(msrc_api, "_get_json", fake_get_json)
    entries = await fetch_update_index()
    assert [e["id"] for e in entries] == ["2026-Jun", "0000-Bad"]


async def test_full_month_cache_is_bounded(monkeypatch):
    monkeypatch.setattr(msrc_api, "MAX_FULL_MONTHS_CACHED", 2)

    with open(FIXTURE, encoding="utf-8") as f:
        cvrf_doc = json.load(f)

    async def fake_get_json(url, timeout=60.0):
        if url.endswith("/updates"):
            return {"value": []}
        return cvrf_doc

    monkeypatch.setattr(msrc_api, "_get_json", fake_get_json)
    for month_id in ["2026-Jan", "2026-Feb", "2026-Mar"]:
        await fetch_month(month_id)

    assert set(msrc_api._month_cache) == {"2026-Feb", "2026-Mar"}, (
        "oldest entry is evicted once the cap is reached"
    )


async def test_concurrent_fetch_month_is_single_flight(monkeypatch):
    """Concurrent cold requests for the same month fetch the document once."""
    calls = []

    with open(FIXTURE, encoding="utf-8") as f:
        cvrf_doc = json.load(f)

    async def fake_get_json(url, timeout=60.0):
        calls.append(url)
        if url.endswith("/updates"):
            return {"value": []}
        await asyncio.sleep(0.01)  # let the other tasks pile up on the lock
        return cvrf_doc

    monkeypatch.setattr(msrc_api, "_get_json", fake_get_json)
    releases = await asyncio.gather(*(fetch_month("2026-Jun") for _ in range(5)))

    doc_calls = [c for c in calls if c.endswith("/cvrf/2026-Jun")]
    assert len(doc_calls) == 1
    assert all(r is releases[0] for r in releases)

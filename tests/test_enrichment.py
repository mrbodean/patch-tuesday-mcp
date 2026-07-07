"""Tests for the EPSS / CISA KEV enrichment clients (mocked HTTP)."""

import pytest

from patch_tuesday_mcp.feeds import enrichment
from patch_tuesday_mcp.feeds.enrichment import (
    EnrichmentError,
    clear_cache,
    fetch_epss,
    fetch_kev,
)

KEV_RESPONSE = {
    "catalogVersion": "2026.07.07",
    "count": 2,
    "vulnerabilities": [
        {
            "cveID": "CVE-2026-99999",
            "vendorProject": "Microsoft",
            "dateAdded": "2026-06-15",
            "dueDate": "2026-07-06",
            "knownRansomwareCampaignUse": "Known",
            "shortDescription": "Synthetic exploited vulnerability.",
        },
        {
            "cveID": "CVE-2026-12345",
            "vendorProject": "Microsoft",
            "dateAdded": "2026-05-01",
            "dueDate": "2026-05-22",
            "knownRansomwareCampaignUse": "Unknown",
            "shortDescription": "Another one.",
        },
    ],
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

    async def fake_get_json(url, timeout=30.0):
        calls.append(url)
        if "api.first.org" in url:
            cves = url.split("cve=")[1].split(",")
            return {
                "status": "OK",
                # EPSS doesn't know CVE-2026-99999; scores are strings
                "data": [
                    {"cve": c, "epss": "0.500000000", "percentile": "0.900000000"}
                    for c in cves
                    if c != "CVE-2026-99999"
                ],
            }
        if "cisa.gov" in url:
            return KEV_RESPONSE
        raise EnrichmentError(f"unexpected URL in test: {url}")

    monkeypatch.setattr(enrichment, "_get_json", fake_get_json)
    return calls


async def test_epss_batching_and_string_parsing(mock_api):
    cves = [f"CVE-2026-{10000 + i}" for i in range(150)]
    result = await fetch_epss(cves)

    epss_calls = [c for c in mock_api if "api.first.org" in c]
    assert len(epss_calls) == 2, "150 CVEs should need two batches of <=100"
    assert len(epss_calls[0].split(",")) == 100
    assert len(epss_calls[1].split(",")) == 50

    assert len(result) == 150
    score, percentile = result["CVE-2026-10000"]
    assert isinstance(score, float) and score == 0.5
    assert isinstance(percentile, float) and percentile == 0.9


async def test_epss_caching_no_new_requests(mock_api):
    # CVE-2026-99999 is unknown to EPSS: the miss must be cached too
    cves = ["CVE-2026-41108", "CVE-2026-99999"]
    first = await fetch_epss(cves)
    assert "CVE-2026-41108" in first
    assert "CVE-2026-99999" not in first

    second = await fetch_epss(cves)
    assert second == first
    epss_calls = [c for c in mock_api if "api.first.org" in c]
    assert len(epss_calls) == 1, "second call must be served from the cache"


async def test_kev_caching_and_parse(mock_api):
    catalog = await fetch_kev()
    assert catalog["CVE-2026-99999"] == {
        "date_added": "2026-06-15",
        "due_date": "2026-07-06",
        "ransomware_use": "Known",
    }
    assert set(catalog) == {"CVE-2026-99999", "CVE-2026-12345"}

    await fetch_kev()
    kev_calls = [c for c in mock_api if "cisa.gov" in c]
    assert len(kev_calls) == 1, "catalog is cached within the TTL"


async def test_fetch_failures_return_empty(monkeypatch):
    async def failing_get_json(url, timeout=30.0):
        raise EnrichmentError("boom")

    monkeypatch.setattr(enrichment, "_get_json", failing_get_json)
    assert await fetch_kev() == {}
    assert await fetch_epss(["CVE-2026-41108"]) == {}


async def test_epss_partial_batch_failure(monkeypatch):
    """A failing batch is skipped; other batches still return results."""
    calls = []

    async def flaky_get_json(url, timeout=30.0):
        calls.append(url)
        if len(calls) == 1:
            raise EnrichmentError("boom")
        cves = url.split("cve=")[1].split(",")
        return {
            "status": "OK",
            "data": [{"cve": c, "epss": "0.1", "percentile": "0.2"} for c in cves],
        }

    monkeypatch.setattr(enrichment, "_get_json", flaky_get_json)
    cves = [f"CVE-2026-{10000 + i}" for i in range(150)]
    result = await fetch_epss(cves)
    assert len(result) == 50, "second batch should still be returned"

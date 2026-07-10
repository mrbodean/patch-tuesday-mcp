# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Product profile / watchlist filtering (Epic 1)** — `msrc_search` gains
  additive, backward-compatible filters to scope results to the products an
  organization runs: `product_profile="<name>"` (built-in `identity-core` /
  `endpoint` / `server-infrastructure`, extensible via a local JSON file at
  `MSRC_PROFILES_PATH`) plus ad-hoc `products=[...]` and `product_families=[...]`
  lists. A vulnerability is kept if it matches **any** listed product or family
  (union). Matching is entirely local — profile contents are never sent to
  MSRC, FIRST.org, CISA, or telemetry (telemetry records only which parameters
  were used, never their values). An unknown profile, or a missing/invalid
  `MSRC_PROFILES_PATH`, returns a clear `invalid_input` error instead of falling
  back to a broad, unscoped result. Ships a companion `patch-tuesday-triage`
  agent skill documenting the watchlists and the monthly triage workflow (no new
  MCP tool); a portable, server-independent copy lives under `skills/` for
  standalone deployment. Default behavior is unchanged when no profile/product
  filter is supplied.
- **HTTP self-host hardening (Epic 9)** — the HTTP transport now supports a
  configurable CORS allowlist (`MCP_CORS_ORIGINS`, comma-separated; defaults to
  the permissive `*` for local dev) and trusted-proxy client-IP handling for
  rate limiting (`MCP_TRUST_X_FORWARDED_FOR`, default `true`;
  `MCP_TRUSTED_PROXIES`, comma-separated proxy allowlist). When directly exposed,
  set `MCP_TRUST_X_FORWARDED_FOR=false` so a spoofed `X-Forwarded-For` header
  cannot evade or poison the per-IP limiter; behind a proxy, list the proxy IPs
  so the real client is resolved by unwinding trusted hops. README gains a
  "Hardening a public HTTP deployment" section recommending an authenticated
  front door, restricted CORS, and correct proxy trust. Rate limiting and body
  size caps remain enabled by default, and `stdio` mode is entirely unaffected.
- **Historical trend search (Epic 4)** — `msrc_search` now aggregates across a
  range of released months without adding a new tool: `months_back=N` searches
  the N most recent released months, or `start_month`/`end_month` define an
  inclusive range. The response carries a `range`, `months_searched`, an
  aggregated `total_found`/`vulnerabilities`, and a per-month `trend` (total,
  by-severity, exploited, publicly_disclosed, KEV counts). All existing filters
  (query, product, severity, exploited, publicly_disclosed, KEV, EPSS, CVSS, and
  CVSS-vector fields) apply across the range, and `format`/`include_stats`/
  `include_freshness`/`force_refresh` work in trend mode too. Ranges are capped
  at 12 months (an over-cap request returns an `invalid_input` error) and reuse
  the existing MSRC cache and fetch-concurrency controls. Default single-month
  behavior is unchanged when no range parameter is supplied.
- **Cache controls & enrichment freshness (Epic 8)** — `msrc_search` now accepts
  `force_refresh=True` to bypass the in-process caches for a request and re-fetch
  the MSRC document, EPSS scores, and CISA KEV catalog from source (only the data
  needed for the request is refreshed; unrelated cached months are left intact).
  A new `include_freshness=True` flag (implied by `force_refresh`) adds a
  `freshness` block reporting the cache age and TTL of the MSRC document and the
  EPSS/KEV enrichment. Freshness helpers were added to the feeds layer
  (`msrc_api.month_freshness`, `enrichment.kev_freshness`,
  `enrichment.epss_freshness`).
- **Briefing / report mode (Epic 5)** — `msrc_search` now accepts
  `format="markdown"` or `format="csv"` (default `"json"`) on monthly/filtered
  searches, plus an optional `report="triage"` profile. Markdown renders a
  prioritized executive summary and triage table; CSV returns a spreadsheet-ready
  export under a `csv` key with a stable `columns` list. Both render from the
  same urgency ranking (KEV/exploited → EPSS → severity → CVSS) and are additive:
  the JSON `vulnerabilities` list is always included and `format="json"` output
  is unchanged. Rendering lives in a new `tools/formatters.py` module.
- **Mitigations & workarounds (Epic 3)** — `msrc_search` now accepts
  `include_guidance=True` on CVE lookups, which adds a `guidance` list to the
  detail output containing any Microsoft-provided mitigations, workarounds, and
  will-not-fix advisories (each with `type`, `description`, and optional `url`).
  Non-vendor-fix CVRF remediations (types 0/1/4) are parsed into a new
  `GuidanceEntry` model; advisory text is HTML-stripped and de-duplicated across
  products. Vendor-fix KB remediations (type 2) continue to populate
  `kb_articles` unchanged, and guidance is omitted from default/summary output
  to keep responses lean.
- **CVSS exposure filters (Epic 2)** — `msrc_search` now accepts `attack_vector`
  (N/A/L/P), `privileges_required` (N/L/H), `user_interaction` (N/R), and
  `scope` (U/C) filters that match the parsed CVSS v3.x base vector. This makes
  it possible to isolate, for example, network-reachable zero-click Critical
  CVEs (`attack_vector=N`, `privileges_required=N`, `user_interaction=N`).
  Entries without a parseable CVSS vector are excluded from vector-filtered
  results, and matching summaries surface a structured `cvss` object broken out
  from the raw vector string.
- **Reference links (Epic 7)** — every CVE detail now includes a `references`
  block of ready-to-open links: MSRC update guide, NVD, the FIRST.org EPSS API,
  and the CISA KEV catalog (the KEV link is included only when the CVE is
  KEV-listed). Links are constructed deterministically with no extra network
  calls.

### Notes

- All additions are fully backward compatible: the new parameters are optional
  and existing calls, output fields, and result ordering are unchanged.
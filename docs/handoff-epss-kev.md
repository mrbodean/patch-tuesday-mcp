# Implementation Handoff: EPSS + CISA KEV Enrichment + Supersedence Chains (v0.2.0)

You are implementing planned features in **patch-tuesday-mcp**, an MCP (Model
Context Protocol) server that exposes Microsoft Patch Tuesday / MSRC Security
Update Guide data to AI assistants. Read this entire document before writing
code. All design decisions have already been made — follow them; do not
redesign the architecture.

## Mission

Add three capabilities to the existing `msrc_search` tool:

1. **EPSS** (Exploit Prediction Scoring System, FIRST.org) — a daily-updated
   probability (0–1) that a CVE will be exploited in the next 30 days.
2. **CISA KEV** (Known Exploited Vulnerabilities catalog) — the authoritative
   list of CVEs confirmed exploited in the wild, with federal remediation due
   dates.
3. **Supersedence chain walking** — for a KB lookup, walk the
   "this KB replaces that KB" links Microsoft publishes in CVRF remediation
   data, so an AI assistant never recommends an obsolete patch.

Purpose: sharper patch prioritization. MSRC severity says "Critical"; EPSS and
KEV say "this one, tonight"; the supersedence chain says "and install *this*
KB, not the stale one you found."

## Hard constraints — read twice

- **No API keys, no accounts, no sign-ups.** Both EPSS and KEV are fully
  public, keyless data sources. There is nothing to register for. Do NOT
  attempt to sign up for anything, do NOT add API-key configuration, do NOT
  browse to any registration page. The zero-key architecture is a core product
  feature.
- **Keep the single consolidated tool.** Do not add new MCP tools. EPSS/KEV
  surface as new fields and filter parameters on the existing `msrc_search`.
- **Graceful degradation is mandatory.** If EPSS or KEV fetches fail, the tool
  must still return complete MSRC results (just without enrichment fields).
  Enrichment failures must never produce a tool error.
- **Do not break stdio mode**, the rate-limit middleware, or telemetry.
- Match existing code style: async httpx, module-level caches with
  `clear_cache()` for tests, structured error dicts, ruff line-length 100,
  Python 3.11+, pydantic v2.

## Repo tour

```
src/patch_tuesday_mcp/
├── server.py                 # FastMCP app; update the `instructions` string
├── telemetry.py              # leave unchanged
├── feeds/msrc_api.py         # MSRC client — mirror its caching/error patterns
├── middleware/rate_limit.py  # leave unchanged
├── models/vulnerability.py   # Vulnerability + MonthlyRelease models; sort logic
└── tools/search.py           # msrc_search tool: filters, fast paths, docstring
tests/
├── fixtures/cvrf_sample.json # truncated real CVRF doc (6 CVEs incl. synthetic
│                             #   exploited CVE-2026-99999)
├── test_models.py / test_feeds.py / test_tools.py / test_middleware.py
```

Conventions to copy from `feeds/msrc_api.py`: module-level cache dicts,
`clear_cache()`, a private `_get_json(url, timeout)` helper that raises a
module exception, TTL via `time.monotonic()`.

## Data source specs

### EPSS

- Endpoint: `GET https://api.first.org/data/v1/epss?cve=CVE-A,CVE-B,...`
- Batch: up to **100 CVE IDs per request**, comma-separated.
- Response shape:
  ```json
  {"status": "OK", "data": [
    {"cve": "CVE-2026-41108", "epss": "0.923110000", "percentile": "0.999130000", "date": "2026-07-07"}
  ]}
  ```
- `epss` and `percentile` are **strings** — parse to float.
- CVEs unknown to EPSS are simply absent from `data` — treat as no score.
- Updated daily; cache per-CVE for 24 h.

### CISA KEV

- Single JSON document (~1 MB):
  `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`
- Response shape (relevant fields):
  ```json
  {"catalogVersion": "...", "count": 1200, "vulnerabilities": [
    {"cveID": "CVE-2026-12345", "vendorProject": "Microsoft",
     "dateAdded": "2026-06-15", "dueDate": "2026-07-06",
     "knownRansomwareCampaignUse": "Known", "shortDescription": "..."}
  ]}
  ```
- Cache the whole parsed catalog (dict keyed by `cveID`) with a 6 h TTL.

## Design (follow exactly)

### 1. New module: `src/patch_tuesday_mcp/feeds/enrichment.py`

```python
class EnrichmentError(Exception): ...

async def fetch_kev() -> dict[str, dict]          # cveID -> {date_added, due_date, ransomware_use}
async def fetch_epss(cves: list[str]) -> dict[str, tuple[float, float]]  # cve -> (score, percentile)
def clear_cache() -> None
```

- `fetch_epss` batches in chunks of 100, consults a per-CVE 24 h cache first,
  and only requests uncached CVEs.
- Both functions **catch their own HTTP errors, log a warning, and return `{}`**
  (or partial results) — they never raise into the tool layer.

### 2. Model changes: `models/vulnerability.py`

Add optional fields to `Vulnerability`:

```python
epss_score: float | None = None
epss_percentile: float | None = None
kev: dict | None = None   # {"date_added": ..., "due_date": ..., "ransomware_use": ...}
```

- `to_summary_dict()`: include `epss_score` and `kev: true` (boolean presence
  flag only — keep summaries compact) when set.
- `to_detail_dict()`: include `epss_score`, `epss_percentile`, and the full
  `kev` dict when set.
- `MonthlyRelease.stats()`: add a top-level `"kev": <count>` alongside
  `"exploited"`.
- Update the sort key (`_month_sort_key`) to the new urgency tiers:
  1. on KEV **or** MSRC-exploited first
  2. then EPSS score descending (missing = 0)
  3. then severity rank (Critical > Important > Moderate > Low)
  4. then max CVSS descending, then CVE id for stability

### 3. Tool changes: `tools/search.py`

- New parameters on `msrc_search` (and `_search_impl`):
  - `kev: bool | None = None` — filter to CVEs on/off the KEV catalog
  - `min_epss: float | None = None` — minimum EPSS score (0–1)
- Enrichment flow inside `_search_impl`, after fetching the month and **before**
  filtering/sorting:
  1. `kev_map = await fetch_kev()` — attach to matching vulns
  2. `epss_map = await fetch_epss([v.cve for v in release.vulnerabilities])`
     — attach scores
  - Enrich the **whole month**, not just the returned page, so sorting and
    filtering are consistent. EPSS for a 1,200-CVE month is ≤ 12 batched
    requests on first call, then cached.
  - Also enrich the single result in the `cve=` fast path, and results in the
    `kb=` fast path.
- Update the tool docstring (it is the LLM-facing usage guide — document both
  new params and give example use lines like "Find KEV-listed CVEs this month
  (kev=True)" and "High exploitation probability (min_epss=0.5)").
- Add `kev`/`min_epss` to the filters-applied summary.

### 4. Supersedence chain walk (Tier B — explicit links only)

Background: every `KbArticle` already carries `supercedence` (the KB it
replaces) and `fixed_build`, parsed from CVRF `Remediations`. A chain is the
transitive walk backward through those links: Jun CU → May CU → Apr CU → …
Each hop lives in a *different* monthly document, so walking requires fetching
multiple months.

**Scope guard: implement ONLY Microsoft-stated links.** Do NOT infer
supersedence from dates, update types, or product heuristics — incorrectly
telling a user a patch is superseded is worse than saying nothing. (Heuristic
inference is a deliberately deferred future feature; see README roadmap.)

Behavior:

- New parameter on `msrc_search`: `include_chain: bool = False`. Only
  meaningful together with `kb=`; ignored otherwise (note this in the
  docstring).
- When set, the KB fast-path response gains:
  ```json
  "supersedence_chain": [
    {"kb": "5094123", "month": "2026-Jun", "supersedes": "5087538", "source": "microsoft"},
    {"kb": "5087538", "month": "2026-May", "supersedes": "5079421", "source": "microsoft"}
  ],
  "chain_complete": true
  ```
  Ordered newest → oldest, starting from the queried KB.
- Walk algorithm: for the current KB, collect the distinct `supercedence`
  values across its remediation entries (a KB can list different predecessors
  for different product groups). Strip non-digit values. If more than one
  distinct predecessor exists, follow the most frequent one and record the
  rest in an `other_predecessors` list on that hop. Locate the predecessor KB
  by scanning monthly docs (see caps below), read *its* supercedence, repeat.
- Termination: stop on (a) empty/non-numeric supercedence, (b) predecessor not
  found within the scan window, (c) a repeated KB (cycle guard — keep a seen
  set), or (d) the depth cap. Set `chain_complete: false` plus a short
  `chain_note` string for cases (b) and (d).
- Caps (module constants): `CHAIN_MAX_DEPTH = 12`, `CHAIN_SCAN_MONTHS = 24`.

**Memory guard — slim month cache.** Parsed months currently retain
descriptions and FAQs (heavy). Chain walking may touch up to 24 months, which
would blow past the 0.5 GiB container. Required change in
`feeds/msrc_api.py` + `models/vulnerability.py`:

- `parse_cvrf(doc, include_text: bool = True)` — when False, skip
  `description` and `faqs` assignment.
- `fetch_month(month_id, slim: bool = False)` — slim results go in a separate
  `_slim_month_cache` (same TTL rules). A full parse for a month may satisfy a
  slim request, but never the reverse.
- Chain walking uses `slim=True` for every month except the queried KB's own
  month. Normal search paths are unchanged (full parse).

### 5. Server: `server.py`

Update the `instructions` string to briefly mention KEV, EPSS, and
`include_chain` for supersedence chains.

### 6. Version + docs

- Bump version to `0.2.0` in `pyproject.toml` and `src/patch_tuesday_mcp/__init__.py`.
- README: move EPSS, KEV, and supersedence chains out of the Roadmap section
  (leave the "possible future add-on" subsection about *inferred* supersedence
  untouched); add them to the Features bullet and the comparison table row
  "What do I patch first?" (now: exploited/KEV → EPSS → severity → CVSS). Add
  prompt examples ("Which of this month's CVEs are on the CISA KEV list?",
  "Show me CVEs with EPSS above 50%", "Is KB5087538 superseded by anything
  newer?").

## Testing requirements

New file `tests/test_enrichment.py` plus updates to `test_tools.py` /
`test_models.py`. Monkeypatch `enrichment._get_json` (mirror how
`tests/test_feeds.py` patches `msrc_api._get_json`). Required cases:

1. EPSS batching: >100 CVEs → multiple requests; string scores parsed to float
2. EPSS caching: second call for same CVEs makes no new requests
3. KEV caching + parse: catalog fetched once within TTL, keyed by cveID
4. `kev=True` / `kev=False` filters
5. `min_epss` filter
6. Sort order: KEV/exploited tier first, then EPSS descending within tier
7. Summary dict has `epss_score` + `kev: true`; detail dict has full kev dict
8. **Degradation**: both enrichment fetches raising/failing → `msrc_search`
   still returns normal MSRC results with no enrichment fields and no error
9. Stats include `kev` count

Supersedence chain cases (build small synthetic monthly docs inline — three
fake months where KB-C supersedes KB-B supersedes KB-A):

10. Happy path: 3-hop chain, ordered newest → oldest, `chain_complete: true`
11. Depth cap and cycle guard both terminate with `chain_complete: false` +
    `chain_note`
12. Predecessor not found in scan window → truncated chain, no error
13. Multiple distinct predecessors → most frequent followed,
    `other_predecessors` recorded
14. Slim cache: months fetched with `slim=True` have empty
    `description`/`faqs`; full and slim caches are independent
15. `include_chain=True` without `kb=` is ignored (no error, no chain key)

All 42 existing tests must still pass unchanged (except where sort-order
assertions legitimately change — update those deliberately, not incidentally).

## Acceptance checklist

- [ ] `python -m pytest` — all green
- [ ] `uvx ruff check src/ tests/` — clean
- [ ] Live smoke test (real APIs):
      `msrc_search(month="2026-06", kev=True)` returns only KEV-listed CVEs;
      `msrc_search(min_epss=0.5, month="2026-06")` returns non-empty, sorted by
      EPSS; a `cve=` detail lookup shows `epss_score`/`epss_percentile`;
      `msrc_search(kb="<a June 2026 cumulative-update KB>", include_chain=True)`
      returns a multi-hop chain with months attributed to each hop
- [ ] No new required configuration of any kind (env vars, keys, accounts)
- [ ] stdio mode still starts: `python -m patch_tuesday_mcp.server`
- [ ] README + docstring + instructions updated; version bumped to 0.2.0

## Deployment (after user approval)

```bash
docker build -t xxbutler21xx/patch-tuesday-mcp:0.2.0 -t xxbutler21xx/patch-tuesday-mcp:latest .
docker push xxbutler21xx/patch-tuesday-mcp:0.2.0
docker push xxbutler21xx/patch-tuesday-mcp:latest
az containerapp update --name patch-tuesday-mcp --resource-group patch-tuesday-rg \
  --image docker.io/xxbutler21xx/patch-tuesday-mcp:0.2.0
```

Live endpoint to re-verify afterwards:
`https://patch-tuesday-mcp.happyrock-b60185ec.eastus.azurecontainerapps.io/mcp`

## Out of scope

- Any additional data sources (Shodan, VirusTotal, NVD, OSV, etc.) — scope
  discipline is a product feature; this server is release-centric, not a
  general CVE aggregator
- New MCP tools, auth, API keys, or account creation of any kind
- **Inferred supersedence** (date/product heuristics for missing links, a
  precomputed KB graph, hotpatch classification) — explicitly deferred; see
  the "possible future add-on" note in the README roadmap. Chains in this
  release use only Microsoft-stated `Supercedence` values.
- Cross-month keyword search (separate roadmap item)
- PyPI publishing (user handles releases)

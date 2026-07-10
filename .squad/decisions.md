# Squad Decisions

## Active Decisions

### 2026-07-09 — Epic 1 (Product Profile / Watchlist) delivered
Implemented the design decided earlier. New local module `tools/profiles.py`
holds built-in profiles (`identity-core`, `endpoint`, `server-infrastructure`)
and a loader that merges a `MSRC_PROFILES_PATH` JSON override over them, with
strict validation (missing file / bad JSON / wrong shape / empty entry →
`ProfileError`). `msrc_search` gains `product_profile` + `products` +
`product_families`, threaded through `_search_impl` → `_filter_vulnerabilities`
(new `product_terms`/`family_terms` union block: keep a vuln if it matches ANY
product term OR ANY family term) and through `_trend_search`. Profile resolution
happens before the trend dispatch so it applies to both single-month and trend
paths. Privacy: only the profile NAME (and generic param keys) reach
`filters_applied`; telemetry logs only parameter keys, so expanded contents /
custom watchlists never leave the host. Unknown/invalid profile returns
`invalid_input` (empty `vulnerabilities`, no broad fallback — AC4). Generic
list filters are the upstream-friendly hook; named profiles + the companion
`.copilot/skills/patch-tuesday-triage/SKILL.md` (watchlists + triage workflow,
no new tool) stay local. A portable, server-independent copy of the skill also
lives under top-level `skills/` (with `skills/README.md` documenting standalone
deployment) so it can be included in the upstream PR — `.copilot/` is excluded
from upstream, so that dir alone would never reach the maintainer. 173 offline
tests pass + 1 live smoke. Branch `feat/epic-1-product-profiles`.

### 2026-07-09 — Epic 9 (HTTP Self-Host Hardening) delivered
Hardened the HTTP transport without touching stdio. CORS is now an allowlist via
`MCP_CORS_ORIGINS` (comma-separated; default `*` preserved for local-dev
backward compat, but README strongly steers public deploys to an explicit list).
Client-IP resolution in `RateLimitMiddleware` is now configurable:
`trust_x_forwarded_for` (env `MCP_TRUST_X_FORWARDED_FOR`, default true =
previous behavior) and `trusted_proxies` (env `MCP_TRUSTED_PROXIES`). Resolution
logic: trust off → direct peer only; trust on + no allowlist → right-most XFF
hop (old behavior); trust on + allowlist → honor XFF only if the direct peer is
a known proxy, then unwind trusted hops right-to-left to the real client. Added
a README "Hardening a public HTTP deployment" section documenting the
authenticated-front-door pattern (this server ships no built-in auth by design),
restricted CORS, and correct proxy trust. Rate-limit + body caps stay on by
default. Server helpers `_cors_origins`/`_trusted_proxies`/`_env_flag` are unit
tested; middleware gains XFF-ignored / trusted-proxy-unwind / untrusted-peer
tests. Branch `feat/epic-9-http-hardening`.

### 2026-07-09 — Epic 1 (Product Profile / Watchlist) design: tool param + companion skill
Decided (not yet implemented — after Epic 9) how Epic 1 should be built for AI-agent
consumption. Split into two complementary layers rather than one:
- **Deterministic filtering stays a `msrc_search` parameter**, not pure LLM/skill
  reasoning. Set-membership matching over `affected_products`/`product_families`
  must be code to satisfy AC1 (only matching vulns returned) and avoid hallucinated/
  missed matches. Keeps the single-tool philosophy.
- **Generic hook for upstream:** list-based `product_families=[...]` / `products=[...]`
  filters (and/or a resolved `product_profile` name). Backward-compatible, additive.
- **Named profiles + triage workflow become an agent Skill** (local): the skill file
  stores watchlists (e.g. `identity-core = Windows Server, Exchange, Entra, Intune,
  Defender, Azure, Edge`) and the triage procedure, and instructs the agent to expand
  a profile into concrete family filters and call `msrc_search`. Adds NO new tool.
- **Privacy:** watchlist contents live only in the local skill/config file; the agent
  expands them into local filters; telemetry stays coarse (never logs filter values or
  profile contents), satisfying FR4/AC3.
Rationale: skills = procedural knowledge/orchestration; tools = deterministic capability.
Filtering is set math (tool); "which families matter for identity triage" is judgment (skill).

### 2026-07-09 — Squad formed per PRD §8
Team assembled around `patch-tuesday-mcp-enhancements-PRD.md`: Ada (Lead/Architect),
Guido (Python/MCP Backend), Sentinel (Security Data/Vuln Domain), Verity (QA/Test),
Hatch (DevEx/Packaging), plus Scribe (logger) and Ralph (monitor).
Trade-off: role-based names mapped to Squad base roles (lead/backend/security/tester/devops)
for self-documenting charters over custom naming.

### 2026-07-09 — Fork, don't fan out tools
This repo is a fork of jonnybottles/patch-tuesday-mcp. Enhancements add optional,
backward-compatible parameters to the single `msrc_search` tool — never new tools.
Organization-specific product profiles/watchlists stay local and never go upstream
or into telemetry.

### 2026-07-09 — Epics tracked as GitHub issues #1–#9
The nine PRD epics are filed as issues in the fork (Epic N = issue #N) with
priority/lane labels and squad-member assignment labels. Upstream PRs will be
split out per epic when ready; internal PRs land against the fork's `main` first.

### 2026-07-09 — Phase 1 delivered (Epic 2 + Epic 7), PR #10
CVSS vector breakdown and generated reference links shipped on branch
`feat/phase-1-cvss-references`. Decision: require an explicit `CVSS:3.x` prefix
to parse a vector (MSRC always provides one) so v2/v4/ambiguous inputs fail open
to `None`; malformed individual metrics are dropped, never raised. CVSS exposure
and references are opt-in for summaries to keep broad results lean.
### 2026-07-09 — Epic 4 (Historical Trend Search) delivered
Added `months_back` / `start_month` / `end_month` to `msrc_search`, routed to a
new `_trend_search` helper. Trend mode aggregates matches across *released*
months (pre-Patch-Tuesday months excluded via `patch_tuesday_utc <= now`),
returns `range` + `months_searched` + per-month `trend` (compact compute_stats:
total, by_severity, exploited, publicly_disclosed, kev), and a combined
sorted/paginated `vulnerabilities` list. All existing filters + vector filters
apply; `format`/`include_stats`/`freshness`/`force_refresh` supported in trend
mode (freshness.msrc is a per-month list). 12-month cap → invalid_input;
`months_back` and start/end are mutually exclusive; months fetched via
`asyncio.gather` over the existing cache + FETCH_CONCURRENCY semaphore. Response
shape is distinct from single-month (range/trend vs month) so default behavior
is unchanged. Verified live (9 smoke tests). Branch `feat/epic-4-trend-search`.

### 2026-07-09 — Epic 8 (Cache Controls + Enrichment Freshness) delivered
Added `force_refresh` (bypass in-process MSRC/EPSS/KEV caches for the request,
re-fetch from source; unrelated cached months untouched) and `include_freshness`
(implied by `force_refresh`) which adds a `freshness` block: `msrc` (month cache
age + TTL), `epss` (oldest age across requested CVEs, TTL, covered/requested),
`kev` (catalog age + TTL). Age is derived from the stored monotonic fetch time
(no wall clock needed). Freshness is opt-in so default response shape is
unchanged. Threaded `force_refresh` through the monthly search plus the cve/kb
fast paths and `_enrich`. Verified live (force_refresh + freshness, 8 smoke
tests). Branch `feat/epic-8-cache-controls`.

### 2026-07-09 — Epic 5 (Briefing / Report Mode) delivered
Added `format="markdown"|"csv"` (default `json`) + optional `report="triage"` to
`msrc_search` monthly/filtered searches. Rendering lives in a new
`tools/formatters.py` (chose a single formatter module over a `reports/` package
for simplicity). Output is additive — the JSON `vulnerabilities` list is always
present and `format="json"` is byte-for-byte unchanged. Markdown = exec summary
(counts over the full matched set) + prioritized table of the page; CSV =
`csv` string + stable `columns` list. Both mirror the urgency sort
(KEV/exploited → EPSS → severity → CVSS) and share `prioritization_rationale`.
Table respects `limit` while `total_found` reflects the full count. Verified
live (7 smoke tests). Branch `feat/epic-5-report-mode`.

### 2026-07-09 — Phase 2 started: Epic 3 (Mitigations & Workarounds)
Added `GuidanceEntry` model and `include_guidance` flag on `msrc_search` CVE
detail. Non-vendor-fix CVRF remediations (workaround=0, mitigation=1,
will_not_fix=4) are parsed, HTML-stripped, de-duplicated; vendor-fix (type 2)
KBs remain in `kb_articles`. Guidance is opt-in and skipped on slim parses to
keep summaries and supersedence walking lean. Verified live against June 2026
(HTTP.sys, DHCP Client mitigations). Branch `feat/phase-2-guidance`.

### 2026-07-09 — Phase 1 shipped (Epic 2 + Epic 7) and documented
CVSS vector breakdown (parsed `cvss` object + `attack_vector`/`privileges_required`/
`user_interaction`/`scope` filters) and generated reference links (MSRC/NVD/EPSS/KEV)
delivered on `feat/phase-1-cvss-references` (internal PR #10). Verified live against the
June 2026 release. User-facing docs updated: README (What It Does, comparison table,
Features blurb, Prompt Examples), new CHANGELOG.md, and PRD epic status markers.

## Governance

- All meaningful changes require team consensus
- Document architectural decisions here
- Keep history focused on work, decisions focused on direction

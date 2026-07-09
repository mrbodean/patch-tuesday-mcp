# Patch Tuesday Triage Accelerator for MCP

**Author role:** Lead / Architect  
**Date:** 2026-07-09  
**Status:** Draft PRD for new project kickoff  
**Upstream project:** [`jonnybottles/patch-tuesday-mcp`](https://github.com/jonnybottles/patch-tuesday-mcp)  
**Upstream snapshot reviewed:** current source exposing one consolidated Python FastMCP tool, `msrc_search`

## 1. Title & Overview

**Project name suggestion:** Patch Tuesday Triage Accelerator for MCP

This project extends `patch-tuesday-mcp`, a Python 3.11+ MCP server that queries the public Microsoft MSRC Security Update Guide CVRF v3 API through one consolidated tool, `msrc_search`, and enriches results with FIRST.org EPSS and CISA KEV. The goal is to improve monthly security and identity operations triage without breaking the upstream design principles: keyless/no-account operation, a lean single-tool surface, privacy-preserving local context, stdio + HTTP transport parity, and bounded context returned to MCP clients.

The work is intentionally split into two lanes:

| Lane | Purpose | Examples |
|---|---|---|
| **Upstream PR contributions** | Generic improvements that benefit all users and preserve the single `msrc_search` interface. | CVSS vector parsing, mitigation/workaround parsing, month-range trend search, report output, reference links, cache freshness, HTTP hardening knobs. |
| **Local wrapper / extension** | Organization-specific behavior that should not be pushed upstream by default. | Product profiles/watchlists for Windows Server, Exchange, Entra, Intune, Defender, Azure, and Edge; local scoring preferences; Squad briefing prompt defaults. |

## 2. Goals & Non-Goals

### Goals

1. Preserve the upstream philosophy: **one consolidated tool, not many specialized tools**.
2. Add analyst-grade filters and output modes to `msrc_search` while keeping default responses compact.
3. Improve triage quality by exposing CVSS vector components, mitigations/workarounds, historical trends, and briefing-ready exports.
4. Keep all organization-specific product relevance and watchlist data local; do not send inventory or internal priorities upstream.
5. Maintain keyless operation against public data sources: MSRC CVRF v3, FIRST.org EPSS, and CISA KEV.
6. Keep stdio and HTTP behavior functionally equivalent.
7. Package the enhancement so users can choose between upstream-compatible PRs and a local wrapper that composes with the upstream package.

### Non-Goals

1. Do **not** split the server into many MCP tools.
2. Do **not** add default NVD or commercial threat-intelligence fan-out.
3. Do **not** ingest, store, or transmit organization inventory to the public upstream server.
4. Do **not** require Microsoft Graph, Azure subscriptions, Entra tenant access, API keys, or accounts.
5. Do **not** replace vulnerability management platforms; this is a Patch Tuesday triage accelerator.
6. Do **not** change the default `msrc_search` behavior in a way that breaks existing clients.

## 3. Personas & Use Cases

### Primary Persona: Security / Identity Practitioner

A Microsoft security and identity practitioner responsible for monthly Patch Tuesday triage across Windows Server, Exchange, Microsoft Entra, Intune, Microsoft Defender, Azure services, and Edge. They need to quickly identify vulnerabilities that affect identity infrastructure, device compliance posture, Conditional Access assumptions, privileged access workstations, Exchange hybrid dependencies, and internet-exposed Microsoft workloads.

### Supporting Personas

| Persona | Need |
|---|---|
| Patch triage lead | Produces a monthly remediation briefing for CAB or security leadership. |
| Identity governance engineer | Understands whether vulnerabilities create risk to authentication, Conditional Access, device trust, or privileged access workflows. |
| Intune / endpoint administrator | Filters updates relevant to managed endpoints, Windows Server, Edge, and Defender. |
| Security operations analyst | Prioritizes exploited, KEV-listed, high-EPSS, network-reachable, no-user-interaction vulnerabilities. |
| MCP platform operator | Self-hosts the server over HTTP and needs safe defaults behind a reverse proxy. |

### Representative Use Cases

1. **Monthly identity/security briefing:** "Show this month's Critical/Important Microsoft CVEs relevant to Windows Server, Exchange, Entra, Intune, Defender, Azure, and Edge, prioritized by KEV, exploitation, EPSS, and CVSS."
2. **Conditional Access risk assessment:** "Find network-reachable vulnerabilities requiring no privileges and no user interaction that could affect identity or device-trust assumptions."
3. **Intune remediation planning:** "Create a CSV of relevant CVEs, affected product families, KBs, supersedence, and mitigation guidance for endpoint teams."
4. **Exchange / hybrid operations triage:** "Search the last six months for Exchange or HTTP.sys issues, including KEV trend and public exploitation status."
5. **Self-hosted MCP deployment:** "Expose Patch Tuesday triage over HTTP behind an authenticated front door with CORS restrictions and trusted-proxy behavior."

## 4. Scope — Epics & Requirements

### Priority Summary

| Epic | Priority | Lane | Effort | Dependencies |
|---|---:|---|---:|---|
| 1. Product profile / watchlist filtering | P0 | Local wrapper first; optional upstream hooks | M | Existing product filtering in `tools/search.py` |
| 2. CVSS vector breakdown | P0 | Upstream PR | S/M | Existing `cvss_vector` in `models/vulnerability.py` |
| 3. Mitigations & workarounds | P0 | Upstream PR | M | CVRF remediation parsing in `models/vulnerability.py` |
| 4. Historical trend search | P1 | Upstream PR | M/L | Month index/cache in `feeds/msrc_api.py` |
| 5. Briefing/report mode | P1 | Upstream PR | M | Stable result model and sorting |
| 6. MCP prompt/resource template | P2 | Upstream PR or local wrapper | S | FastMCP prompt/resource support |
| 7. Generated reference links | P1 | Upstream PR | S | Vulnerability output model |
| 8. Cache controls/freshness | P1 | Upstream PR | S/M | Existing MSRC/enrichment caches |
| 9. HTTP self-host hardening | P2 | Upstream PR | S/M | HTTP mode in `server.py` |

### Epic 1 — Product Profile / Watchlist Filtering

**Priority:** P0  
**Lane:** Local wrapper / extension first; upstream should only receive generic hooks if accepted.  
**Effort:** M  
**Primary touchpoints:** `tools/search.py::msrc_search`, `tools/search.py::_search_impl`, `tools/search.py::_filter_vulnerabilities`, `models/vulnerability.py::Vulnerability.to_summary_dict`, local wrapper package config loader.

#### Functional Requirements

1. Add support for a local product profile containing product and family matchers.
2. Support profiles for Microsoft families relevant to identity/security triage:
   - Windows Server
   - Exchange
   - Microsoft Entra
   - Intune
   - Microsoft Defender
   - Azure
   - Microsoft Edge
3. Profiles must support product-name partial matches and product-family matches.
4. Profile matching must happen locally and must not transmit profile contents to MSRC, FIRST.org, CISA, or telemetry.
5. The local wrapper should expose profile filtering through the same conceptual `msrc_search` interface, not a new family of tools.
6. If upstream accepts a generic `product_profile` parameter, it must be optional and backward compatible.

#### Acceptance Criteria

- **Given** a local profile with `families = ["Windows", "Azure"]` and `products = ["Microsoft Exchange Server"]`, **when** `msrc_search(product_profile="identity-core")` runs, **then** results only include vulnerabilities whose `affected_products` or `product_families` match the profile.
- **Given** no profile is supplied, **when** existing clients call `msrc_search`, **then** behavior is unchanged.
- **Given** telemetry is enabled, **when** a profile search runs, **then** telemetry records only non-sensitive filter metadata and never the local profile contents.
- **Given** a profile path is missing or invalid, **when** the wrapper starts, **then** it returns a clear local configuration error without falling back to broad inventory disclosure.

#### Sequencing

Implement after Epic 2 establishes richer exposure metadata, but before final briefing templates. Keep this as a wrapper until upstream maintainers state a preference for profile hooks.

### Epic 2 — CVSS Vector Breakdown

**Priority:** P0  
**Lane:** Upstream PR  
**Effort:** S/M  
**Primary touchpoints:** `models/vulnerability.py::Vulnerability`, `models/vulnerability.py::_parse_vulnerability`, `models/vulnerability.py::to_summary_dict`, `models/vulnerability.py::to_detail_dict`, `tools/search.py::msrc_search`, `tools/search.py::_search_impl`, `tools/search.py::_filter_vulnerabilities`.

#### Functional Requirements

1. Parse the existing `cvss_vector` value into a structured object.
2. Support CVSS v3.x vector components at minimum:
   - `attack_vector`
   - `attack_complexity`
   - `privileges_required`
   - `user_interaction`
   - `scope`
   - `confidentiality`
   - `integrity`
   - `availability`
3. Expose optional filters on `msrc_search`:
   - `attack_vector`
   - `privileges_required`
   - `user_interaction`
   - optionally `scope`
4. Include a compact `cvss` or `exposure` object in detail output and, when requested, summary output.
5. Handle malformed or missing vectors without failing the search.

#### Acceptance Criteria

- **Given** a vulnerability with `cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"`, **when** parsed, **then** the detail output includes `attack_vector = "N"`, `privileges_required = "N"`, and `user_interaction = "N"`.
- **Given** `attack_vector="N"` and `privileges_required="N"`, **when** a monthly search runs, **then** only matching vulnerabilities are returned.
- **Given** a malformed vector, **when** parsing runs, **then** the raw `cvss_vector` remains available and no exception escapes.
- **Given** no vector filters are supplied, **when** existing clients call `msrc_search`, **then** response shape remains backward compatible except for additive fields.

#### Sequencing

This is the cleanest first upstream PR. It is self-contained, leverages existing stored data, and improves triage without new network calls.

### Epic 3 — Mitigations & Workarounds

**Priority:** P0  
**Lane:** Upstream PR  
**Effort:** M  
**Primary touchpoints:** `models/vulnerability.py` constants for CVRF remediation types, `models/vulnerability.py::_parse_vulnerability`, `models/vulnerability.py::Vulnerability`, `models/vulnerability.py::to_detail_dict`, `tools/search.py::msrc_search`.

#### Functional Requirements

1. Retain non-KB remediation and advisory text from CVRF `Remediations`, not only vendor-fix KB entries.
2. Add a model such as `GuidanceEntry` or `RemediationGuidance` for mitigation/workaround/advisory entries.
3. Add `include_guidance: bool = False` to `msrc_search`.
4. Include guidance in CVE detail responses when `include_guidance=True`.
5. Keep default summary output lean by omitting large guidance text unless requested.
6. Preserve existing `kb_articles` behavior for vendor-fix remediation type 2.

#### Acceptance Criteria

- **Given** MSRC provides mitigation or workaround text for a CVE, **when** `msrc_search(cve="...", include_guidance=True)` runs, **then** the detail output includes that guidance with type/title/url when available.
- **Given** `include_guidance=False`, **when** a broad monthly search runs, **then** large advisory text is not included.
- **Given** an entry has KB remediation and non-KB guidance, **when** parsed, **then** KBs remain in `kb_articles` and guidance is represented separately.
- **Given** slim parsing is used for supersedence chain walking, **when** `include_text=False`, **then** guidance can be skipped to maintain memory bounds.

#### Sequencing

Implement after Epic 2 or in parallel if a second engineer is available. It touches the same model code, so coordinate to avoid merge conflicts.

### Epic 4 — Historical Trend Search

**Priority:** P1  
**Lane:** Upstream PR  
**Effort:** M/L  
**Primary touchpoints:** `tools/search.py::msrc_search`, `tools/search.py::_search_impl`, `tools/search.py::_filter_vulnerabilities`, `feeds/msrc_api.py::fetch_update_index`, `feeds/msrc_api.py::fetch_month`, `models/vulnerability.py::compute_stats`.

#### Functional Requirements

1. Add multi-month search parameters without creating a new tool:
   - `months_back`
   - `start_month`
   - `end_month`
2. Return aggregate trend statistics by month.
3. Support existing filters across the selected range: query, product, severity, exploited, publicly_disclosed, KEV, EPSS, CVSS, and CVSS-vector fields.
4. Enforce a safe maximum range by default, such as 12 months unless explicitly configured otherwise.
5. Use existing cache and concurrency controls in `feeds/msrc_api.py` to avoid unbounded upstream fan-out.
6. Keep default single-month behavior unchanged.

#### Acceptance Criteria

- **Given** `query="HTTP.sys"` and `months_back=6`, **when** the tool runs, **then** it returns matching vulnerabilities across six released months plus per-month counts.
- **Given** `kev=True` and `start_month="2026-Jan"` / `end_month="2026-Jun"`, **when** the tool runs, **then** it returns KEV trend counts by month and matching CVEs.
- **Given** no range parameters are supplied, **when** clients call `msrc_search`, **then** only the default month is searched.
- **Given** a range exceeds the configured cap, **when** the search runs, **then** the tool returns an `invalid_input` error explaining the maximum range.

#### Sequencing

Depends on Epic 2 for exposure-aware trend filters. Prefer after Epic 3 so trend output can optionally summarize guidance availability.

### Epic 5 — Briefing / Report Mode

**Priority:** P1  
**Lane:** Upstream PR  
**Effort:** M  
**Primary touchpoints:** `tools/search.py::msrc_search`, `tools/search.py::_search_impl`, `models/vulnerability.py::to_summary_dict`, new formatter module such as `tools/formatters.py` or `reports/triage.py`.

#### Functional Requirements

1. Add output controls while preserving default JSON:
   - `format: "json" | "markdown" | "csv"`
   - optionally `report: "triage"`
2. Generate a prioritized triage table including:
   - CVE
   - title
   - product families
   - affected products or compact count
   - impact
   - severity
   - CVSS score and exposure fields
   - EPSS score
   - KEV status and due date
   - exploited/publicly disclosed status
   - KBs
   - MSRC link
   - prioritization rationale
3. Keep machine-readable JSON as the default and most complete representation.
4. For CSV, return a string payload plus metadata indicating column order.
5. For Markdown, return a concise monthly briefing suitable for a ticket, PRD appendix, or CAB deck source.

#### Acceptance Criteria

- **Given** `report="triage"` and `format="markdown"`, **when** a monthly profile search runs, **then** output includes a prioritized Markdown table and executive summary.
- **Given** `format="csv"`, **when** the tool runs, **then** output can be saved as valid CSV with stable column names.
- **Given** no format is specified, **when** existing clients call `msrc_search`, **then** JSON output remains unchanged.
- **Given** result count exceeds `limit`, **when** report mode runs, **then** it respects `limit` and indicates `total_found`.

#### Sequencing

Can follow Epic 2 and precede Epic 4. Trend report mode should be added once Epic 4 lands.

### Epic 6 — MCP Prompt / Resource: Monthly Patch Tuesday Triage Template

**Priority:** P2  
**Lane:** Upstream PR if lightweight; local wrapper otherwise  
**Effort:** S  
**Primary touchpoints:** `server.py` FastMCP registration, possible new module `prompts.py` or `resources.py`, README documentation.

#### Functional Requirements

1. Provide a prompt/resource template for "Monthly Patch Tuesday identity/security triage."
2. The template should instruct clients to call the single `msrc_search` tool with appropriate filters instead of introducing new tools.
3. Include analyst workflow sections: zero-days, KEV, network/no-auth/no-UI, identity-adjacent products, endpoint/Intune, and briefing output.
4. Keep organization-specific profile names out of upstream; local wrapper can prefill defaults.

#### Acceptance Criteria

- **Given** an MCP client lists prompts/resources, **when** the triage template is selected, **then** it guides the user through a single-tool workflow.
- **Given** upstream declines prompt/resource additions, **when** local wrapper is installed, **then** the same template is available locally.

#### Sequencing

Implement after the core parameters stabilize so the template does not churn.

### Epic 7 — Generated Reference Links

**Priority:** P1  
**Lane:** Upstream PR  
**Effort:** S  
**Primary touchpoints:** `models/vulnerability.py::Vulnerability.url`, `models/vulnerability.py::to_summary_dict`, `models/vulnerability.py::to_detail_dict`, `feeds/enrichment.py`.

#### Functional Requirements

1. Generate deterministic reference links without calling additional APIs:
   - MSRC Update Guide vulnerability page
   - NVD CVE page
   - FIRST EPSS API or web reference
   - CISA KEV catalog reference when KEV data is present
2. Add links as additive fields such as `references`.
3. Do not fetch NVD or other threat-intelligence data by default.

#### Acceptance Criteria

- **Given** a CVE result, **when** detail output is requested, **then** references include MSRC and NVD links.
- **Given** a CVE is KEV-listed, **when** detail output is requested, **then** references include a CISA KEV catalog link or source URL.
- **Given** broad summary output, **when** references are included, **then** they do not significantly increase context size.

#### Sequencing

Can ship with Epic 2 because both are additive model output changes.

### Epic 8 — Cache Controls and Enrichment Freshness

**Priority:** P1  
**Lane:** Upstream PR  
**Effort:** S/M  
**Primary touchpoints:** `feeds/msrc_api.py::clear_cache`, `feeds/msrc_api.py::fetch_month`, `feeds/enrichment.py::clear_cache`, `feeds/enrichment.py::fetch_epss`, `feeds/enrichment.py::fetch_kev`, `tools/search.py::msrc_search`.

#### Functional Requirements

1. Add `force_refresh: bool = False` to bypass in-process caches for the current request.
2. Expose freshness metadata:
   - MSRC document fetched time or cache age
   - EPSS cache age / TTL
   - KEV cache age / TTL
3. Keep cache controls local to the process; do not require external storage.
4. Avoid clearing unrelated caches unless `force_refresh` explicitly requires it.

#### Acceptance Criteria

- **Given** `force_refresh=True`, **when** a month search runs, **then** MSRC and enrichment data are refreshed for the relevant request where practical.
- **Given** normal cached operation, **when** output is returned, **then** optional metadata can show enrichment freshness.
- **Given** enrichment fetch fails, **when** the tool runs, **then** best-effort behavior remains: search succeeds and freshness indicates missing/stale enrichment.

#### Sequencing

Implement before trend search reaches larger ranges so cache behavior is visible and debuggable.

### Epic 9 — HTTP Self-Host Hardening

**Priority:** P2  
**Lane:** Upstream PR  
**Effort:** S/M  
**Primary touchpoints:** `server.py::main`, `middleware/rate_limit.py`, `middleware/body_limit.py`, README deployment docs, possibly new middleware for trusted proxy handling.

#### Functional Requirements

1. Replace hard-coded permissive CORS with configurable allowlist:
   - `MCP_CORS_ORIGINS`
   - default remains safe for local dev, but docs must distinguish public deployment.
2. Add trusted-proxy configuration for client IP handling:
   - `MCP_TRUSTED_PROXIES`
   - `MCP_TRUST_X_FORWARDED_FOR`
3. Document front-door authentication patterns for public HTTP hosting.
4. Keep stdio mode unaffected.
5. Keep rate limiting and body size limits enabled by default for HTTP.

#### Acceptance Criteria

- **Given** `MCP_CORS_ORIGINS="https://example.com"`, **when** HTTP mode starts, **then** only that origin is allowed.
- **Given** no CORS env var is set, **when** HTTP mode starts, **then** behavior is documented and compatible with current local usage.
- **Given** the server is behind a trusted reverse proxy, **when** configured, **then** rate limiting uses the intended client IP.
- **Given** deployment docs are read, **when** a user exposes HTTP publicly, **then** the docs clearly recommend an authenticated front door.

#### Sequencing

Ship after core tool enhancements unless a deployment need makes it urgent. This is important but not on the critical path for local stdio users.

## 5. Non-Functional Requirements

| Area | Requirement |
|---|---|
| Performance | Default `msrc_search` must remain lean. Broad searches should not include guidance text, long product lists, or references unless requested. Multi-month searches must enforce range caps and use existing `FETCH_CONCURRENCY` patterns. |
| Privacy | Product profiles, local priorities, and any customer-specific watchlists stay local. Telemetry must never include profile contents, organization inventory, tenant identifiers, hostnames, or user data. |
| Telemetry | Continue opt-in behavior through existing telemetry patterns. Add only coarse event metadata such as feature flags used and result counts. |
| Keyless operation | No API keys, accounts, Microsoft tenant permissions, or NVD keys are required. |
| Backward compatibility | `msrc_search` remains the single tool. Existing parameters and default JSON output remain valid. New fields and parameters are additive. |
| Test coverage | Use pytest for unit tests around parsing, filtering, formatting, cache controls, and error handling. Add fixtures for CVRF snippets with CVSS, remediations, and multi-month aggregation. |
| Linting | Maintain ruff compatibility and existing project style. |
| Python support | Preserve Python 3.11+ support. |
| Packaging | Preserve uv/uvx workflows and PyPI packaging. Local wrapper should also support uvx. |
| Docker | Docker image behavior must match stdio/HTTP behavior. HTTP hardening env vars must be documented for containers. |
| Transport parity | stdio and HTTP expose the same tool schema and results. |
| Resilience | Enrichment remains best effort. MSRC failures return structured `error_kind` values instead of uncaught exceptions. |

## 6. Proposed Architecture / Approach

### Preserve "One Tool" by Adding Optional Parameters

The upstream server already centralizes behavior in:

- `server.py` — FastMCP server registration and HTTP/stdio startup.
- `tools/search.py::msrc_search` — public tool schema.
- `tools/search.py::_search_impl` — main orchestration.
- `tools/search.py::_filter_vulnerabilities` — in-memory filtering.
- `models/vulnerability.py::Vulnerability` — normalized CVE model and output shaping.
- `models/vulnerability.py::_parse_vulnerability` — CVRF vulnerability parsing.
- `feeds/msrc_api.py` — MSRC index/month fetch, cache, and default month logic.
- `feeds/enrichment.py` — EPSS and KEV enrichment cache/fetch.

Enhancements should add optional parameters to `msrc_search` rather than new tools. The key rule: broad results remain compact; detail/report modes can opt into larger fields.

### Suggested Upstream Module Changes

| Concern | Suggested approach |
|---|---|
| CVSS vector parsing | Add `parse_cvss_vector(vector: str) -> dict` in `models/vulnerability.py` or a small `models/cvss.py`; store parsed fields on `Vulnerability`. |
| Guidance parsing | Add `GuidanceEntry` model and retain non-type-2 CVRF remediations when `include_text=True`. |
| Report output | Add formatter helpers in `tools/formatters.py` to keep `tools/search.py` from becoming too large. |
| Trend search | Add month-range resolution helper in `feeds/msrc_api.py`; orchestrate in `tools/search.py`. |
| References | Add generated `references` property/method on `Vulnerability`. |
| Cache freshness | Track cache timestamps in fetch helpers and expose optional metadata. |
| HTTP hardening | Make CORS and proxy behavior configurable in `server.py`; add middleware only if Starlette/FastMCP does not already provide it. |

### Local Wrapper Package

The local wrapper should depend on upstream `patch-tuesday-mcp` instead of forking unless upstream PRs are rejected or delayed. It can:

1. Import and reuse upstream parsing/search logic where stable.
2. Provide a local config loader.
3. Register one compatible `msrc_search` tool that forwards to upstream and post-filters/profile-ranks locally.
4. Ship Squad-specific prompts/resources without forcing them upstream.

### Product Profile Config Format

Profile files must be local and uncommitted. Support JSON or TOML; TOML is friendlier for hand-edited configuration.

Example `patch_profiles.toml`:

```toml
[profiles.identity_security]
description = "Identity and security operations Patch Tuesday watchlist"
families = [
  "Windows",
  "Azure",
  "Microsoft Edge",
]
products = [
  "Windows Server",
  "Microsoft Exchange Server",
  "Microsoft Entra",
  "Microsoft Intune",
  "Microsoft Defender",
  "Azure Arc",
]
tags = [
  "HTTP.sys",
  "Kerberos",
  "LDAP",
  "Active Directory",
]

[profiles.identity_security.weights]
kev = 100
exploited = 90
attack_vector_network = 25
privileges_required_none = 20
user_interaction_none = 15
```

Recommended local paths:

- Environment variable: `PATCH_TUESDAY_PROFILE_PATH`
- Default user config path if no env var is set.
- Never commit customer profiles to the repo.

## 7. Milestones / Phased Delivery

### Phase 1 — P0 Upstream Foundation

**Scope:**

1. Epic 2: CVSS vector parsing and filters.
2. Epic 7: Generated reference links.
3. Initial report-mode skeleton if low-risk, limited to JSON additive fields or Markdown formatter behind `format`.

**Exit Criteria:**

- Upstream PR submitted for CVSS parsing and filters.
- Tests cover valid, missing, and malformed CVSS vectors.
- Existing `msrc_search` calls remain backward compatible.

### Phase 2 — P0/P1 Triage Depth

**Scope:**

1. Epic 3: Mitigations and workarounds with `include_guidance`.
2. Epic 5: Briefing/report mode for Markdown and CSV.
3. Epic 8: Cache freshness metadata and `force_refresh`.

**Exit Criteria:**

- CVE detail mode can include guidance without bloating default results.
- Markdown triage report includes prioritization rationale.
- Cache/enrichment freshness is visible in output when requested.

### Phase 3 — P1/P2 Trend and Local Relevance

**Scope:**

1. Epic 4: Historical trend search.
2. Epic 1: Local product profile wrapper.
3. Epic 6: Monthly triage MCP prompt/resource, local first if upstream support is uncertain.

**Exit Criteria:**

- Six-month trend searches work with bounded range and stable stats.
- Local profile file filters and prioritizes without upstream inventory disclosure.
- Monthly identity/security triage workflow is documented and usable.

### Phase 4 — P2 Self-Hosted Operations

**Scope:**

1. Epic 9: HTTP self-host hardening.
2. Docker documentation for CORS, reverse proxy, auth front door, rate limiting, and body limits.
3. End-to-end stdio/HTTP parity validation.

**Exit Criteria:**

- HTTP mode supports CORS allowlist and trusted-proxy configuration.
- README/deployment docs include safe public-hosting guidance.
- Container smoke tests pass.

## 8. Suggested Squad Team

Keep the team small enough to move fast: 4-5 delivery roles plus Scribe.

| Role | Primary Responsibilities | Why This Role Is Needed |
|---|---|---|
| Lead / Architect | Own scope, upstream-vs-wrapper decisions, sequencing, privacy boundaries, and PR review gates. | Prevents tool sprawl and keeps design aligned to upstream principles. |
| Python / MCP Backend Engineer | Implement `msrc_search` schema changes, parsing, filtering, report formatters, and FastMCP prompt/resource registration. | Most work is Python/FastMCP code in `tools/search.py`, `models/vulnerability.py`, and `server.py`. |
| Security Data / Vulnerability Domain Specialist | Validate CVSS semantics, MSRC CVRF remediation types, KEV/EPSS interpretation, and triage prioritization rationale. | Ensures outputs are analytically correct for patch operations. |
| QA / Test Engineer | Build pytest fixtures, regression tests, transport parity tests, CSV/Markdown formatter tests, and cache behavior tests. | Backward compatibility and parsing edge cases are the main delivery risks. |
| DevEx / Packaging Engineer | Own uv/uvx, PyPI packaging, Docker, README examples, environment variables, and local wrapper installation. | Keeps adoption simple and preserves keyless setup. |
| Scribe | Capture decisions, phase outcomes, accepted trade-offs, and release notes. | Maintains project memory and avoids repeating architecture debates. |

## 9. Risks & Open Questions

| Risk / Question | Impact | Mitigation |
|---|---|---|
| MSRC CVRF schema inconsistencies | Guidance/remediation parsing may be incomplete or inconsistent by product/month. | Use defensive parsing, fixtures from multiple months, and preserve raw fields where helpful. |
| Upstream maintainer acceptance | Some parameters may be considered too broad for upstream. | Submit small PRs: CVSS first, references second, guidance third. Keep product profiles local unless invited upstream. |
| Fork vs PR decision | A long-lived fork increases maintenance cost. | Prefer wrapper + upstream PRs. Fork only for unreconcilable changes that are essential. |
| Cache freshness ambiguity | Analysts may not know if EPSS/KEV data is stale. | Add freshness metadata and `force_refresh`. |
| Multi-month performance | Trend searches could fetch many multi-MB CVRF documents. | Enforce range caps, reuse `FETCH_CONCURRENCY`, and keep slim/full cache separation. |
| Context bloat | Guidance, affected products, and reports can exceed MCP client context budgets. | Default to compact summaries; require explicit `include_guidance`, `format`, and `report`. |
| CVSS version differences | CVSS v2/v4 vectors may appear or differ from v3 semantics. | Parse v3 first, preserve raw vector, and fail open with no filter match only when specific vector filters require parsed values. |
| HTTP public exposure | MCP over HTTP without auth can expose public-data query capability but still create abuse surface. | Keep rate/body limits, add CORS allowlists, trusted proxy config, and front-door auth guidance. |
| Licensing | Upstream appears MIT-licensed; wrapper must preserve notices. | Verify license before packaging and include attribution. |
| Product profile naming | Microsoft product names shift over time, e.g., Entra branding and Defender naming. | Keep profiles editable and avoid hard-coded assumptions where possible. |

## 10. Acceptance / Definition of Done

The overall project is done when:

1. `msrc_search` remains the only vulnerability-search MCP tool.
2. Existing calls to `msrc_search` continue to work without parameter changes.
3. CVSS vector components are parsed, filterable, and tested.
4. Mitigation/workaround guidance is available only when requested.
5. Multi-month trend search supports bounded ranges with per-month stats.
6. Markdown and CSV triage outputs are stable, documented, and tested.
7. Product profile filtering works locally from an uncommitted JSON/TOML file and does not transmit profile details upstream.
8. Generated reference links are present without default NVD/threat-intel API fan-out.
9. Cache freshness and `force_refresh` behavior are documented and tested.
10. HTTP mode supports configurable CORS and trusted-proxy behavior, with front-door auth guidance.
11. pytest and ruff pass on the changed code.
12. uv/uvx, PyPI packaging, and Docker usage remain documented.
13. stdio and HTTP transports expose the same schema and behavior.
14. Upstream PRs are split into reviewable units, and local-wrapper-only decisions are documented.
15. A new Squad team can pick up this PRD, create issues by epic, and execute the phased plan without redoing the architecture work.

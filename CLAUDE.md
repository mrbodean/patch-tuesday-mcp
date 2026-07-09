# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

**patch-tuesday-mcp** is a Python MCP server exposing a single tool, `msrc_search`, that queries the public MSRC CVRF v3 API (Microsoft Patch Tuesday security updates), enriched with FIRST.org EPSS scores and the CISA KEV catalog. No API keys anywhere. Ships two ways: a PyPI package (stdio transport for local MCP clients) and a Docker image running HTTP transport on Azure Container Apps.

## Commands

```bash
pip install -e ".[dev]"       # or: uv pip install -e ".[dev]" (repo .venv is uv-managed, has no pip)
pytest                        # offline suite — mocked feeds, fast, no network
pytest --run-live             # additionally runs tests/test_live_smoke.py against real MSRC/EPSS/KEV APIs
pytest tests/test_tools.py    # single file
ruff check .                  # lint (line-length 100, rules E/F/I/W)
```

On Windows in this repo use `.venv/Scripts/python -m pytest` etc. — the venv was created by uv and `pip` is not installed in it.

## Architecture

- `src/patch_tuesday_mcp/server.py` — FastMCP app + `main()`. stdio by default; `MCP_TRANSPORT=http` wraps the ASGI app in middleware (innermost→outermost: rate limit → body limit → CORS) and serves `/mcp` + `/health`.
- `tools/search.py` — the single `msrc_search` tool and all its routing: CVE fast path (cross-month lookup), KB fast path (with optional supersedence chain walk), single-month filtered search, and historical trend search (`months_back` / `start_month`+`end_month`, capped at `MAX_TREND_MONTHS = 12`).
- `tools/formatters.py` — optional `format="markdown"|"csv"` triage renderings; JSON is always included and unchanged.
- `feeds/msrc_api.py` — MSRC index + monthly CVRF fetch with in-process TTL caches (`MAX_FULL_MONTHS_CACHED = 6`, 40 slim), per-month asyncio locks, `FETCH_CONCURRENCY = 3` semaphore, `force_refresh` bypass, freshness metadata.
- `feeds/enrichment.py` — KEV catalog + batched EPSS fetches, cached; failures return empty ({}) — enrichment must never break a search.
- `models/vulnerability.py` — CVRF parsing into `Vulnerability`; numeric CVRF enums are documented constants (remediation types: 0=workaround, 1=mitigation, 2=vendor fix/KB, 4=will-not-fix). `to_summary_dict()` vs `to_detail_dict()` control output size; new fields are opt-in flags.
- `models/cvss.py` — lenient CVSS v3.x vector parser; fails open to `None`, never raises.
- `middleware/` — per-IP token-bucket rate limit (X-Forwarded-For handling configurable via `MCP_TRUST_X_FORWARDED_FOR` / `MCP_TRUSTED_PROXIES`), request body cap.
- `telemetry.py` — optional App Insights events (tool_call, msrc_fetch, http_request); no-op unless `APPLICATIONINSIGHTS_CONNECTION_STRING` is set.

## Key Constraints

- **Single tool by design.** New capabilities hang off `msrc_search` parameters, never new tools — keeps client tool selection lean.
- **Default output shape is a compatibility contract.** All new response fields/behaviors must be opt-in (parameter-gated); default JSON must not change.
- **Fail open on data quality.** Bad CVSS vectors, missing enrichment, malformed CVRF fragments must degrade gracefully (skip/None), never raise into a search.
- **Slim vs full parses.** `fetch_month(slim=True)` skips descriptions/FAQs/guidance (used for supersedence chain walking). The `query` filter matches description text, so filtered searches and trend search need **full** parses.
- **Memory envelope.** The hosted container is 0.25 vCPU / 0.5 GiB. A cold 12-month trend query measured ~77 MiB peak / ~16 s (2026-07) — fine, but keep this budget in mind when growing caches or ranges.
- **Live tests are opt-in.** Anything hitting real APIs belongs in `tests/test_live_smoke.py` behind the `--run-live` flag (see `tests/conftest.py`).

## Release & Deployment

- **Hosted endpoint** (public, no auth — owner's explicit choice): `https://patch-tuesday-mcp.happyrock-b60185ec.eastus.azurecontainerapps.io/mcp` (+ `/health`, which reports the running version).
- **Deploy flow**: bump `version` in **both** `pyproject.toml` and `src/patch_tuesday_mcp/__init__.py` → `docker build -t docker.io/xxbutler21xx/patch-tuesday-mcp:<version> .` → push → `az containerapp update -n patch-tuesday-mcp -g patch-tuesday-rg --image docker.io/xxbutler21xx/patch-tuesday-mcp:<version>`. An unchanged image ref does not roll a new revision; ACA may briefly serve the draining old revision after update.
- **PyPI**: publishing is automated — creating a GitHub release triggers `.github/workflows/publish.yml` (trusted publishing). `workflow_dispatch` publishes to TestPyPI instead.
- Pushing directly to `main` on origin is permission-gated for automated sessions.

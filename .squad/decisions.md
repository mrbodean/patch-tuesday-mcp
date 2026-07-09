# Squad Decisions

## Active Decisions

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

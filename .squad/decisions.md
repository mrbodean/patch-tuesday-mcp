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

## Governance

- All meaningful changes require team consensus
- Document architectural decisions here
- Keep history focused on work, decisions focused on direction

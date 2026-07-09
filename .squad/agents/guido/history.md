# Guido — History

- 2026-07-09: Joined squad as Python / MCP Backend Engineer. Owns `msrc_search`
  schema changes, CVRF/CVSS parsing, filters, and report formatters.
- 2026-07-09: Delivered Phase 1 (branch `feat/phase-1-cvss-references`, PR #10).
  Epic 2 — `models/cvss.py` + `parse_cvss_vector`, `Vulnerability.cvss`, and
  `attack_vector`/`privileges_required`/`user_interaction`/`scope` filters.
  Epic 7 — `Vulnerability.references()` (MSRC/NVD/EPSS/KEV). Additive, backward
  compatible; 106 tests pass (84 baseline + 22 new), ruff clean.

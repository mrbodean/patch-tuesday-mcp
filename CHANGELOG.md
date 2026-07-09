# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

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

- Both additions are fully backward compatible: the new parameters are optional
  and existing calls, output fields, and result ordering are unchanged.

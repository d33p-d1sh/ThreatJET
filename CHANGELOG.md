# Changelog

Notable changes are recorded here. Version numbers follow the version embedded
in the standalone `ThreatJET.ps1` build. A version in source code is **not**
necessarily a published GitHub Release.

## [Unreleased]

### Added
- GitHub Actions syntax checks, Pester smoke tests, and advisory
  PSScriptAnalyzer diagnostics.
- Security disclosure policy, contributing guide, issue and pull-request
  templates, and a release checklist.
- README project branding and documentation navigation.

### Changed
- Standardize `ThreatJET` capitalization across the standalone filename, public command names, generated report paths, documentation, assets, and CI tests.
- Rename the canonical entrypoint to `ThreatJET.ps1` (update hardcoded file paths when upgrading).
- README configuration example aligned with the current standalone script
  (`CollectorVersion` / `CorrelationVersion` 2.4.0; `SchemaVersion` 1.6).

## [2.5.1] — source version, not yet tagged as a GitHub Release

- Adopt the uploaded standalone v2.5.1 assessment build as the repository source.
- Improve AD/host correlation, finding deduplication, CVE certainty reporting, and
  remediation mapping compared with the previous v2.4.0 source.
- Correct `PORT-001` bind classification: specific-interface listeners are not
  loopback-only, and listener presence is not proof of remote reachability.
- Make `LOCAL-019` autologon remediation checks secret-safe: inspect the registry
  value **name**, never print `DefaultPassword` contents.
- Add offline Pester regression tests for bind scope, deduplication, and guarded
  remediation command generation.
- Update README configuration examples to source version 2.5.1 and schema 1.7.

## [2.4.0] — source version, not yet tagged as a GitHub Release

- Standalone PowerShell 5.1+ assessment with LDAP/ADSI collection,
  misconfiguration findings, attack-path correlation, offline CVE matching,
  reporting, and guarded remediation guidance.
- See the [README](README.md) for the current feature set and limitations.

> Historical release notes will be expanded as versioned releases are
> published. This changelog does not imply that older versions were released
> on GitHub.

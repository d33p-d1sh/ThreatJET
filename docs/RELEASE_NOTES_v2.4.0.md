# Draft release notes — ThreatJET v2.4.0

> **DRAFT — not a published release.** Publish only after the release checklist
> and disposable-lab validation are complete.

## Overview

ThreatJET (Jumbo Evaluation Toolkit) is a read-only, RSAT-free PowerShell
security assessment toolkit for Active Directory and Windows hosts. It collects
configuration through LDAP/ADSI, identifies potential misconfigurations and
attack paths toward Tier 0, correlates installed software against an offline
CVE database, and produces an interactive HTML report with guarded remediation
guidance.

## Included files

- `ThreatJET.ps1` — standalone assessment tool, compatible with Windows
  PowerShell 5.1+.
- `Build-TJETCveDatabase.ps1` — optional offline CVE database builder for
  locally downloaded cvelistV5 data, with optional KEV/EPSS enrichment.
- `README.md` — requirements, examples, output schema, findings catalogue,
  limitations, and operational cautions.
- `LICENSE` — MIT license.

## Key capabilities

- RSAT-free Active Directory assessment with read-only collection.
- Local Windows host checks and software inventory.
- Potential attack-path correlation and Tier 0 analysis.
- Version-aware offline CVE matching with affected/unaffected exceptions.
- HTML and structured CSV/JSON reporting.
- Guarded remediation suggestions intended for human review.

## Important cautions

- **Authorized use only.** Directory enumeration can create load; coordinate
  production assessments and consider off-peak operation.
- **Treat output as sensitive.** Reports and inventories may disclose a
  detailed map of domain privileges and configurations.
- **No finding is proof of exploitation.** Verify results and coverage in
  context. CVE matches are leads for investigation.
- **Remediation is not automated.** Generated commands are guarded and
  require change-control review.
- **One domain per run.** Assess additional domains separately.

## Validation required before publication

See [RELEASE_CHECKLIST.md](RELEASE_CHECKLIST.md). In particular, confirm that
GitHub Actions passes, run a disposable lab with known weaknesses, review
the CVE builder and remediation output, and generate SHA-256 checksums for
the exact assets you publish.

This draft is based on the version declared in the current standalone script.
It is not a claim that all capabilities have passed independent validation.

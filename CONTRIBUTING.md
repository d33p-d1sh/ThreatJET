# Contributing to ThreatJET

Thanks for helping improve ThreatJET. The goal is an auditable, **read-only**
Active Directory and Windows security assessment tool that works without RSAT
or network access to external services on the assessment host.

## Before contributing

- For bugs and feature ideas, open a GitHub Issue using the relevant template.
- For security vulnerabilities, follow [SECURITY.md](SECURITY.md) instead of
  posting details publicly.
- Check existing issues and pull requests before starting larger work.
- Keep the single-file `ThreatJET.ps1` distribution usable on Windows
  PowerShell **5.1+**. Avoid new runtime dependencies unless explicitly justified.
- Preserve collection as read-only. Any remediation guidance must be guarded
  (`-WhatIf` or commented out) and never executed automatically.

## Local validation

Use a disposable Windows lab, not a production domain, for behavioral testing.

```powershell
# Requires Pester 5.5 or later:
Install-Module Pester -MinimumVersion 5.5.0 -Scope CurrentUser -Force
Invoke-Pester -Path .\tests -CI

# Optional linting:
Install-Module PSScriptAnalyzer -Scope CurrentUser -Force
Invoke-ScriptAnalyzer -Path .\ThreatJET.ps1
Invoke-ScriptAnalyzer -Path .\Build-TJETCveDatabase.ps1
```

GitHub Actions checks syntax on Windows PowerShell 5.1 and PowerShell 7,
runs focused Pester tests on Windows, and publishes lint diagnostics. Lint
warnings are initially advisory while an existing baseline is reviewed.

These are **smoke/regression checks**, not proof of accurate AD findings or
safety under production load. Validate collection coverage, expected
detections, and false positives against intentionally configured test cases.

## Pull requests

1. Fork the repository and create a branch for one focused change.
2. Explain the problem, the change, and any compatibility considerations.
3. Include tests or a reproducible manual validation procedure.
4. Update documentation and the changelog when behavior changes.
5. Ensure no sensitive hostnames, domains, usernames, IP addresses,
   credentials, or real assessment artifacts appear in commits or screenshots.

For issue reports, use fictitious examples such as `example.test` and
`DC01.example.test`. Redact environment-specific details before posting.

## Coding conventions

- Target PowerShell 5.1 compatibility and preserve the RSAT-free path.
- Prefer small, testable functions and explicit error handling.
- Avoid unnecessary collection, side effects, and network calls.
- Treat CVE matches as leads requiring validation, not confirmed exploitation.
- Do not silently change finding IDs or output schemas without documenting
  migration/compatibility impact.

## Licensing

By contributing, you agree that your contributions will be distributed under
the repository's [MIT license](LICENSE).

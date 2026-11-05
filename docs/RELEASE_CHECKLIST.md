# ThreatJET release checklist

Use this checklist before publishing a GitHub Release. The current standalone
script declares **2.4.0**, but that does not itself create a tagged release.

## Verification

- [ ] GitHub Actions syntax jobs pass for Windows PowerShell 5.1 and PowerShell 7.
- [ ] Pester smoke tests pass on Windows.
- [ ] Review advisory PSScriptAnalyzer findings and resolve high-impact issues.
- [ ] Validate real assessment behavior in a disposable AD lab with known findings.
- [ ] Verify collection coverage, false positives, attack-path output, and report UI.
- [ ] Verify generated remediation remains guarded and never executes automatically.
- [ ] Validate the CVE builder with small synthetic CVE records and known unaffected cases.
- [ ] Confirm no secrets, real assessment data, internal hosts, or sensitive files
      are present anywhere in the git history or release assets.
- [ ] Confirm README, changelog, script header, and config versions agree.

## Prepare release

- [ ] Choose version tag (e.g. `v2.4.0`) after the verification above.
- [ ] Draft release notes describing notable changes, compatibility, and limitations.
- [ ] Include `ThreatJET.ps1` and `Build-TJETCveDatabase.ps1` as standalone assets
      if you want one-click downloads; GitHub's source archive is also available.
- [ ] Generate and publish SHA-256 checksums for each downloadable asset.
- [ ] Mark the release as pre-release if testing is incomplete.
- [ ] Publish using GitHub's **Releases → Draft a new release** page.
- [ ] Confirm downloads and documentation links work after publishing.

## Repository administration (maintainer)

- [ ] Add repository topics and polish the About description.
- [ ] Enable private vulnerability reporting and applicable secret scanning.
- [ ] After CI passes, configure a `main` ruleset requiring PR review and
      successful syntax/Pester checks (with an emergency recovery path).
- [ ] Upload the 1280×640 social preview in Settings → General.
- [ ] Add real **sanitized** HTML-report screenshots only after generating them
      in a disposable lab; never use real customer assessment data.

**Note:** A GitHub Release, repository topics, social preview, and repository
security/ruleset settings require GitHub repository settings or Releases
permissions and are not changed by committing this checklist.

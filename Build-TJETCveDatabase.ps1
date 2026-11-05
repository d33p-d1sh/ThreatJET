# SPDX-License-Identifier: MIT
# ThreatJET - Build-TJETCveDatabase.ps1
# Copyright (c) 2026 Melvin Salyers (d33p-d1sh) - https://github.com/d33p-d1sh/ThreatJet
# Licensed under the MIT License; see LICENSE in the project repository.

<#
.SYNOPSIS
    Builds a ThreatJET-format CVE database (CSV) from a local copy of MITRE's cvelistV5,
    optionally enriched with CISA KEV and FIRST EPSS.
.DESCRIPTION
    ThreatJET's offline CVE scan (-IncludeCVEScan) reads a module-free CSV with these
    columns (all but the first four are optional):

        cve_id, product_name, vendor_name, vulnerable_spec, unaffected_spec,
        cvss, cvss_vector, kev, epss

    Spec grammar (both vulnerable_spec and unaffected_spec):
        "Ver: X to <Y"   -> range  [X, Y)   (X inclusive, Y exclusive)
        "Ver: X"         -> exact version X

    A row carries EITHER a vulnerable_spec (an affected range/version) OR an unaffected_spec
    (a version explicitly NOT affected, e.g. a fixed release inside an affected range). The
    scanner suppresses a match when the installed version satisfies an unaffected_spec, so a
    patched version inside an affected range is not falsely flagged.

        cvss         best base score (v3.1 > v3.0 > v4.0 > v2.0)
        cvss_vector  the vector string for that score
        kev          "TRUE" if the CVE is in CISA's Known Exploited Vulnerabilities catalog
        epss         FIRST EPSS probability (0..1) that the CVE will be exploited

    THIS RUNS ON YOUR WORKSTATION, not on an assessment target. No module dependencies;
    works on Windows PowerShell 5.1 and PowerShell 7. All three feeds are local files, so the
    assessment host never needs internet access.

    GET THE FEEDS (all optional except cvelistV5):
        # cvelistV5 (required):
        git clone --depth 1 https://github.com/CVEProject/cvelistV5.git
        #   or a nightly release bundle from its Releases page.
        # CISA KEV (optional):
        #   https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
        # FIRST EPSS (optional, daily CSV, gz-decompressed):
        #   https://epss.cyentia.com/epss_scores-current.csv.gz

.PARAMETER CveListPath
    Path to the cvelistV5 checkout root or its "cves" subfolder.
.PARAMETER OutputPath
    Where to write the CSV. Default .\cves.csv in the current directory.
.PARAMETER KevPath
    Optional path to CISA's known_exploited_vulnerabilities.json. Stamps kev=TRUE on matches.
.PARAMETER EpssPath
    Optional path to the FIRST EPSS CSV (decompressed). Stamps the epss score per CVE.
.PARAMETER MinCvss
    Skip records whose best CVSS base score is below this (0 = keep all). KEV-listed CVEs are
    always kept regardless of this threshold.
.PARAMETER IncludeNoVersion
    Also emit a row for an affected product that lists no usable version. These match at LOW
    confidence in ThreatJET. Off by default.
.PARAMETER Limit
    Stop after processing this many CVE files (quick test run). 0 = no limit.
.EXAMPLE
    .\Build-TJETCveDatabase.ps1 -CveListPath C:\src\cvelistV5 -OutputPath C:\Security\cves.csv
.EXAMPLE
    # High-and-above, enriched with KEV and EPSS:
    .\Build-TJETCveDatabase.ps1 -CveListPath C:\src\cvelistV5 -OutputPath C:\Security\cves.csv `
        -MinCvss 7 -KevPath C:\feeds\known_exploited_vulnerabilities.json -EpssPath C:\feeds\epss_scores-current.csv
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$CveListPath,

    [string]$OutputPath = (Join-Path (Get-Location) 'cves.csv'),

    [string]$KevPath,

    [string]$EpssPath,

    [ValidateRange(0, 10)]
    [double]$MinCvss = 0,

    [switch]$IncludeNoVersion,

    [int]$Limit = 0
)

$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------- locate cves/ ---
$cvesDir =
    if (Test-Path (Join-Path $CveListPath 'cves')) { Join-Path $CveListPath 'cves' }
    elseif ((Split-Path $CveListPath -Leaf) -eq 'cves') { $CveListPath }
    else { $CveListPath }

if (-not (Test-Path $cvesDir)) {
    throw "Could not find a CVE record folder under '$CveListPath'. Point -CveListPath at the cvelistV5 checkout root or its 'cves' folder."
}

# ---------------------------------------------------- optional KEV / EPSS feeds ---
$kevSet = @{}
if ($KevPath) {
    if (-not (Test-Path $KevPath)) { throw "KEV file not found: $KevPath" }
    $kevJson = Get-Content -LiteralPath $KevPath -Raw | ConvertFrom-Json
    foreach ($v in @($kevJson.vulnerabilities)) {
        $id = "$($v.cveID)".Trim().ToUpperInvariant()
        if ($id) { $kevSet[$id] = $true }
    }
    Write-Host "KEV catalog: $($kevSet.Count) known-exploited CVE(s) loaded." -ForegroundColor Cyan
}

$epssMap = @{}
if ($EpssPath) {
    if (-not (Test-Path $EpssPath)) { throw "EPSS file not found: $EpssPath" }
    # EPSS CSV: an optional '#model_version...' comment line, then a 'cve,epss,percentile' header.
    foreach ($line in [System.IO.File]::ReadLines($EpssPath)) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        if ($line[0] -eq '#') { continue }
        $parts = $line.Split(',')
        if ($parts.Count -lt 2) { continue }
        $id = $parts[0].Trim().ToUpperInvariant()
        if ($id -like 'CVE-*') { $epssMap[$id] = $parts[1].Trim() }
    }
    Write-Host "EPSS: $($epssMap.Count) score(s) loaded." -ForegroundColor Cyan
}

Write-Host "Scanning $cvesDir for CVE records..." -ForegroundColor Cyan

# --------------------------------------------------------------------- helpers ---

function ConvertTo-CsvField {
    param([string]$Value)
    if ($null -eq $Value) { return '""' }
    return '"' + ($Value -replace '"', '""') + '"'
}

# Best CVSS base score + vector. Priority v3.1 > v3.0 > v4.0 > v2.0; highest score within it.
function Get-BestCvssInfo {
    param($MetricsArrays)

    $byVer = @{ '31' = (New-Object System.Collections.Generic.List[object]);
               '30' = (New-Object System.Collections.Generic.List[object]);
               '40' = (New-Object System.Collections.Generic.List[object]);
               '20' = (New-Object System.Collections.Generic.List[object]) }

    foreach ($metrics in $MetricsArrays) {
        if (-not $metrics) { continue }
        foreach ($m in @($metrics)) {
            if ($m.cvssV3_1 -and $null -ne $m.cvssV3_1.baseScore) { $byVer['31'].Add([pscustomobject]@{ Score = [double]$m.cvssV3_1.baseScore; Vector = "$($m.cvssV3_1.vectorString)" }) }
            if ($m.cvssV3_0 -and $null -ne $m.cvssV3_0.baseScore) { $byVer['30'].Add([pscustomobject]@{ Score = [double]$m.cvssV3_0.baseScore; Vector = "$($m.cvssV3_0.vectorString)" }) }
            if ($m.cvssV4_0 -and $null -ne $m.cvssV4_0.baseScore) { $byVer['40'].Add([pscustomobject]@{ Score = [double]$m.cvssV4_0.baseScore; Vector = "$($m.cvssV4_0.vectorString)" }) }
            if ($m.cvssV2_0 -and $null -ne $m.cvssV2_0.baseScore) { $byVer['20'].Add([pscustomobject]@{ Score = [double]$m.cvssV2_0.baseScore; Vector = "$($m.cvssV2_0.vectorString)" }) }
        }
    }

    foreach ($pref in '31','30','40','20') {
        if ($byVer[$pref].Count -gt 0) {
            return ($byVer[$pref] | Sort-Object -Property Score -Descending | Select-Object -First 1)
        }
    }
    return $null
}

# Turn one affected-product entry into affected and unaffected spec lists.
# A version token is only useful to the scanner if it IS a numeric version with up to four parts
# (e.g. "1.2.3", "10.0.19041.1234"). Microsoft and browser CVEs in cvelistV5 routinely put
# platform names in the version field ("Windows 10 for 32-bit Systems") and non-numeric
# bounds in lessThan ("publication", "unspecified"). Emitting those as specs produces rows
# the scanner can never confirm -- every match comes back Unknown -- which is exactly the
# noise that buried the real results. So a spec is written ONLY when every version token in
# it is numerically comparable; anything else is dropped here rather than poisoning the DB.
function Test-ComparableVersionToken {
    param([string]$Token)
    if ([string]::IsNullOrWhiteSpace($Token)) { return $false }
    $value = $Token.Trim()
    # Match the entire token: '1.2-beta', '1.2.*' and '1.2.3.4.5' are not
    # safely comparable by the scanner's numeric System.Version logic.
    if ($value -notmatch '^\d+(?:\.\d+){0,3}$') { return $false }
    if ($value -notmatch '\.') { $value += '.0' }
    $parsed = $null
    return [version]::TryParse($value, [ref]$parsed)
}

function Get-ProductSpecs {
    param($Affected)

    $aff   = New-Object System.Collections.Generic.List[string]
    $unaff = New-Object System.Collections.Generic.List[string]
    $emittedAff = $false
    $hasUnversionedAffected = $false

    foreach ($v in @($Affected.versions)) {
        if (-not $v) { continue }

        $status = "$($v.status)"
        # A missing status must not be silently interpreted as affected.
        if ($status -ne 'affected' -and $status -ne 'unaffected') { continue }

        # CVE 5 'changes' can flip affected/unaffected status inside a range.
        # Until these transitions are modeled, skip the entry rather than
        # asserting that the entire original range is vulnerable.
        if ($v.changes -and @($v.changes).Count -gt 0) { continue }

        $isUnaffected = ($status -eq 'unaffected')
        # Assign directly: PowerShell pipeline enumeration would turn an empty List into $null.
        if ($isUnaffected) { $target = $unaff } else { $target = $aff }
        $ver = "$($v.version)".Trim()
        $lt  = "$($v.lessThan)".Trim()
        $lte = "$($v.lessThanOrEqual)".Trim()

        if ($lt) {
            # Range needs BOTH a comparable lower bound and a comparable upper bound.
            if ((Test-ComparableVersionToken $ver) -and (Test-ComparableVersionToken $lt)) {
                $target.Add("Ver: $ver to <$lt")
                if (-not $isUnaffected) { $emittedAff = $true }
            }
        }
        elseif ($lte) {
            if ((Test-ComparableVersionToken $ver) -and (Test-ComparableVersionToken $lte)) {
                $target.Add("Ver: $ver to <$lte")
                $target.Add("Ver: $lte")
                if (-not $isUnaffected) { $emittedAff = $true }
            }
        }
        elseif ((Test-ComparableVersionToken $ver) -and $ver -ne '*' -and $ver -ne 'n/a' -and $ver -ne 'unspecified') {
            $target.Add("Ver: $ver")
            if (-not $isUnaffected) { $emittedAff = $true }
        }
        elseif (-not $isUnaffected) {
            $hasUnversionedAffected = $true
        }
    }

    # Optional low-confidence rows for explicitly affected wildcard/non-numeric
    # versions or an affected default with no usable version ranges.
    if ($IncludeNoVersion -and ($hasUnversionedAffected -or
        (-not $emittedAff -and $Affected.defaultStatus -eq 'affected'))) {
        $aff.Add('')
    }

    return [pscustomobject]@{ Affected = $aff; Unaffected = $unaff }
}

# ------------------------------------------------------------------ enumerate ---
$files = [System.IO.Directory]::EnumerateFiles($cvesDir, 'CVE-*.json', [System.IO.SearchOption]::AllDirectories)

$writer = New-Object System.IO.StreamWriter($OutputPath, $false, [System.Text.UTF8Encoding]::new($false))
$writer.WriteLine('cve_id,product_name,vendor_name,vulnerable_spec,unaffected_spec,cvss,cvss_vector,kev,epss')

$processed = 0
$rows      = 0
$skippedRejected = 0
$skippedError    = 0
$kevStamped = 0

try {
    foreach ($file in $files) {

        if ($Limit -gt 0 -and $processed -ge $Limit) { break }
        $processed++

        if (($processed % 5000) -eq 0) {
            Write-Host ("  processed {0:N0} records, wrote {1:N0} rows..." -f $processed, $rows) -ForegroundColor DarkGray
        }

        try {
            $json = Get-Content -LiteralPath $file -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        }
        catch {
            $skippedError++
            Write-Verbose "Could not parse '$file': $($_.Exception.Message)"
            continue
        }

        if (-not $json) { continue }

        # One malformed or oddly-shaped record must never abort a 250k-file build. Wrap the
        # whole per-record projection so a null property chain (a record missing cna, metrics,
        # affected, versions, etc.) skips that record -- counted in $skippedError -- instead of
        # terminating the run under $ErrorActionPreference = 'Stop'.
        try {

        $cveId = "$($json.cveMetadata.cveId)".Trim()
        if (-not $cveId) { continue }
        if ("$($json.cveMetadata.state)" -eq 'REJECTED') { $skippedRejected++; continue }

        $cna = $json.containers.cna
        if (-not $cna) { continue }

        $adpMetrics = @()
        if ($json.containers.adp) {
            foreach ($adp in @($json.containers.adp)) { if ($adp.metrics) { $adpMetrics += ,$adp.metrics } }
        }
        $cvssInfo   = Get-BestCvssInfo -MetricsArrays (@(,$cna.metrics) + $adpMetrics)
        $cvss       = if ($cvssInfo) { $cvssInfo.Score } else { $null }
        $cvssVector = if ($cvssInfo) { "$($cvssInfo.Vector)" } else { '' }

        $cveUpper  = $cveId.ToUpperInvariant()
        $isKev     = $kevSet.ContainsKey($cveUpper)
        $kevField  = if ($isKev) { 'TRUE' } else { '' }
        $epssField = if ($epssMap.ContainsKey($cveUpper)) { $epssMap[$cveUpper] } else { '' }

        # MinCvss filters by score, but a KEV-listed CVE is always kept (known exploited
        # outranks a low or missing base score).
        if ($MinCvss -gt 0 -and -not $isKev) {
            if ($null -eq $cvss -or $cvss -lt $MinCvss) { continue }
        }
        $cvssField = if ($null -ne $cvss) { "$cvss" } else { '' }

        $affectedAll = @()
        if ($cna.affected) { $affectedAll += @($cna.affected) }
        if ($json.containers.adp) {
            foreach ($adp in @($json.containers.adp)) { if ($adp.affected) { $affectedAll += @($adp.affected) } }
        }

        foreach ($aff in $affectedAll) {
            if (-not $aff) { continue }

            $product = "$($aff.product)".Trim()
            $vendor  = "$($aff.vendor)".Trim()
            if ([string]::IsNullOrWhiteSpace($product) -or $product -eq '*' -or $product -eq 'n/a') { continue }
            if ([string]::IsNullOrWhiteSpace($vendor)) { $vendor = 'n/a' }

            $specs = Get-ProductSpecs -Affected $aff
            if ($specs.Affected.Count -eq 0) { continue }   # nothing vulnerable to record

            # Affected rows, then any unaffected (fixed/exception) rows for the same product.
            $toWrite = New-Object System.Collections.Generic.List[object]
            foreach ($s in $specs.Affected)   { $toWrite.Add([pscustomobject]@{ V = $s;  U = '' }) }
            foreach ($s in $specs.Unaffected) { $toWrite.Add([pscustomobject]@{ V = ''; U = $s }) }

            foreach ($row in $toWrite) {
                $writer.WriteLine( (@(
                    (ConvertTo-CsvField $cveId),
                    (ConvertTo-CsvField $product),
                    (ConvertTo-CsvField $vendor),
                    (ConvertTo-CsvField $row.V),
                    (ConvertTo-CsvField $row.U),
                    (ConvertTo-CsvField $cvssField),
                    (ConvertTo-CsvField $cvssVector),
                    (ConvertTo-CsvField $kevField),
                    (ConvertTo-CsvField $epssField)
                ) -join ',') )
                $rows++
                if ($isKev) { $kevStamped++ }
            }
        }

        }
        catch {
            # Skip this record and keep going; a handful of malformed records in cvelistV5
            # should not cost the whole database.
            $skippedError++
            Write-Verbose "Skipped CVE record '$file': $($_.Exception.Message)"
            continue
        }
    }
}
finally {
    $writer.Flush()
    $writer.Dispose()
}

Write-Host ''
Write-Host ("Done. {0:N0} CVE record(s) processed, {1:N0} rejected, {2:N0} skipped on error." -f $processed, $skippedRejected, $skippedError) -ForegroundColor Green
Write-Host ("Wrote {0:N0} product/version row(s) to:" -f $rows) -ForegroundColor Green
if ($kevSet.Count -gt 0) { Write-Host ("  {0:N0} output row(s) flagged KEV (known exploited)." -f $kevStamped) -ForegroundColor Yellow }
Write-Host "    $OutputPath"
Write-Host ''
Write-Host "Point ThreatJET at it:" -ForegroundColor Gray
Write-Host "    Invoke-ThreatJETAssessment -IncludeCVEScan -CVEDatabasePath '$OutputPath'" -ForegroundColor White
# Offline regression tests for the reviewed v2.5.1 source.
BeforeAll {
    . (Join-Path $PSScriptRoot '..\ThreatJET.ps1')

    function New-SyntheticPortRecord {
        param([string]$Address, [int]$Port = 3389, [string]$Protocol = 'TCP', [bool]$BoundToAll = $false)
        [PSCustomObject]@{
            Check = 'OpenPort'; Scanned_Host = 'TEST-DC'
            Port_Number = $Port; Port_Protocol = $Protocol
            Port_LocalAddress = $Address; Port_BoundToAll = $BoundToAll
            Port_Process = 'synthetic-service'; Port_PID = 1234
        }
    }
}

Describe 'ThreatJET listener binding classification' {
    It 'treats an IPv4 specific-interface listener as network-scope, not loopback' {
        $binding = Get-TJETPortBindScope -LocalAddress '192.168.30.10'
        $binding.Kind | Should -Be 'Specific'
        $binding.LoopbackOnly | Should -BeFalse
        $binding.Scope | Should -Match 'specific interface 192.168.30.10'
        $binding.Scope | Should -Match 'firewall reachability not verified'
    }

    It 'recognizes IPv4 and IPv6 loopback listeners' {
        (Get-TJETPortBindScope -LocalAddress '127.0.0.1').LoopbackOnly | Should -BeTrue
        (Get-TJETPortBindScope -LocalAddress '127.12.0.4').LoopbackOnly | Should -BeTrue
        (Get-TJETPortBindScope -LocalAddress '::1').LoopbackOnly | Should -BeTrue
        (Get-TJETPortBindScope -LocalAddress '::ffff:127.0.0.1').LoopbackOnly | Should -BeTrue
    }

    It 'does not confuse IPv6 wildcard and a specific IPv6 interface' {
        (Get-TJETPortBindScope -LocalAddress '::').Kind | Should -Be 'Wildcard'
        (Get-TJETPortBindScope -LocalAddress 'fe80::1234').Kind | Should -Be 'Specific'
        (Get-TJETPortBindScope -LocalAddress '').Kind | Should -Be 'Unknown'
    }

    It 'does not let an inconsistent bound-to-all flag override a known loopback address' {
        (Get-TJETPortBindScope -LocalAddress '127.0.0.1' -BoundToAll $true).LoopbackOnly | Should -BeTrue
    }

    It 'reports a specific-interface RDP listener without downgrading it to Low' {
        $context = [PSCustomObject]@{ Data = [PSCustomObject]@{ LocalHost = @((New-SyntheticPortRecord -Address '192.168.30.10')) } }
        $findings = @(Invoke-ExposureFindings -Context $context | Where-Object { $_.Finding_ID -eq 'PORT-001' })
        $findings.Count | Should -Be 1
        $findings[0].Severity | Should -Be 'High'
        $findings[0].Evidence | Should -Match 'specific interface 192.168.30.10'
        $findings[0].Evidence | Should -Not -Match 'loopback only|network-reachable'
    }

    It 'downgrades a truly loopback-only RDP listener' {
        $context = [PSCustomObject]@{ Data = [PSCustomObject]@{ LocalHost = @((New-SyntheticPortRecord -Address '127.0.0.1')) } }
        $findings = @(Invoke-ExposureFindings -Context $context | Where-Object { $_.Finding_ID -eq 'PORT-001' })
        $findings.Count | Should -Be 1
        $findings[0].Severity | Should -Be 'Low'
    }

    It 'deduplicates IPv4/IPv6 listeners and prefers wildcard scope over loopback' {
        $ports = @(
            (New-SyntheticPortRecord -Address '127.0.0.1')
            (New-SyntheticPortRecord -Address '192.168.30.10')
            (New-SyntheticPortRecord -Address '0.0.0.0' -BoundToAll $true)
            (New-SyntheticPortRecord -Address '::' -BoundToAll $true)
        )
        $context = [PSCustomObject]@{ Data = [PSCustomObject]@{ LocalHost = $ports } }
        $findings = @(Invoke-ExposureFindings -Context $context | Where-Object { $_.Finding_ID -eq 'PORT-001' })
        $findings.Count | Should -Be 1
        $findings[0].Severity | Should -Be 'High'
        $findings[0].Evidence | Should -Match 'all local interfaces'
        $findings[0].Evidence | Should -Match '192.168.30.10'
    }

    It 'prefers a specific-interface listener over loopback when no wildcard exists' {
        $ports = @(
            (New-SyntheticPortRecord -Address '127.0.0.1')
            (New-SyntheticPortRecord -Address '192.168.30.10')
        )
        $context = [PSCustomObject]@{ Data = [PSCustomObject]@{ LocalHost = $ports } }
        $findings = @(Invoke-ExposureFindings -Context $context | Where-Object { $_.Finding_ID -eq 'PORT-001' })
        $findings.Count | Should -Be 1
        $findings[0].Severity | Should -Be 'High'
        $findings[0].Evidence | Should -Match 'specific interface 192.168.30.10'
    }
}

Describe 'ThreatJET credential-safe remediation generation' {
    It 'never prints the Winlogon DefaultPassword value in its review command' {
        $result = Get-TJETRemediationCommand -FindingId 'LOCAL-019' -Target 'TEST-DC\HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\DefaultPassword'
        $result.HasCommand | Should -BeTrue
        $result.Command | Should -Match 'DefaultPasswordPresent'
        $result.Command | Should -Not -Match 'Get-ItemProperty|Get-ItemPropertyValue|reg query'
        $result.Command | Should -Match 'Remove-ItemProperty.*-WhatIf'
    }

    It 'keeps UAC remediation mapped to the actual UAC setting' {
        $lua = Get-TJETRemediationCommand -FindingId 'LOCAL-008' -Target 'TEST-DC\EnableLUA'
        $filter = Get-TJETRemediationCommand -FindingId 'LOCAL-008' -Target 'TEST-DC\FilterAdministratorToken'
        $lua.Command | Should -Match '-Name EnableLUA'
        $filter.Command | Should -Match '-Name FilterAdministratorToken'
        $lua.Command | Should -Not -Match 'LocalAccountTokenFilterPolicy'
        $filter.Command | Should -Not -Match 'LocalAccountTokenFilterPolicy'
    }
}

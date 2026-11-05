# Pester 5.x regression smoke tests. No AD connection or external feeds required.
BeforeAll {
    . (Join-Path $PSScriptRoot '..\ThreatJET.ps1')
}

Describe 'ThreatJET read-only helper functions' {
    Context 'UAC bit decoding' {
        It 'recognizes account-disabled bit' {
            Test-TJETUacFlag -UacValue 0x0002 -Flag Disabled | Should -BeTrue
        }

        It 'does not conflate disabled and password-never-expires' {
            Test-TJETUacFlag -UacValue 0x10000 -Flag Disabled | Should -BeFalse
            Test-TJETUacFlag -UacValue 0x10000 -Flag PasswordNeverExpires | Should -BeTrue
        }

        It 'recognizes no-preauth independently' {
            Test-TJETUacFlag -UacValue 0x400000 -Flag NoPreAuth | Should -BeTrue
        }
    }

    Context 'AD file time conversion' {
        It 'returns null for never-set sentinels' {
            ConvertFrom-TJETFileTime -Value 0 | Should -BeNullOrEmpty
            ConvertFrom-TJETFileTime -Value ([long]::MaxValue) | Should -BeNullOrEmpty
        }

        It 'converts a known UTC timestamp' {
            $utc = [datetime]::SpecifyKind([datetime]'2025-01-01T00:00:00', [DateTimeKind]::Utc)
            $actual = ConvertFrom-TJETFileTime -Value ($utc.ToFileTimeUtc())
            $actual.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss') | Should -Be '2025-01-01T00:00:00'
        }

        It 'rejects malformed values safely' {
            ConvertFrom-TJETFileTime -Value 'not-a-filetime' | Should -BeNullOrEmpty
        }
    }

    Context 'ADSI property accessor' {
        It 'reads a case-normalized property' {
            Get-TJETLdapProperty -Record @{ samaccountname = 'example.user' } -Name 'sAMAccountName' | Should -Be 'example.user'
        }

        It 'uses a default for missing attributes' {
            Get-TJETLdapProperty -Record @{} -Name 'missing' -Default 'fallback' | Should -Be 'fallback'
        }
    }

    Context 'CSV value normalization' {
        It 'handles common boolean strings' {
            ConvertTo-Bool -Value 'yes' | Should -BeTrue
            ConvertTo-Bool -Value 'false' | Should -BeFalse
        }

        It 'uses an explicit default for invalid integers' {
            ConvertTo-Int -Value 'invalid' -Default 42 | Should -Be 42
            ConvertTo-Int -Value '17' -Default 42 | Should -Be 17
        }
    }
}

Describe 'Windows PowerShell 5.1 banner encoding' {
    It 'stores the standalone script as UTF-8 with BOM so Unicode banner glyphs survive loading' {
        $path = Join-Path $PSScriptRoot '..\ThreatJET.ps1'
        $bytes = [System.IO.File]::ReadAllBytes($path)
        $bytes.Length | Should -BeGreaterThan 3
        $bytes[0] | Should -Be 0xEF
        $bytes[1] | Should -Be 0xBB
        $bytes[2] | Should -Be 0xBF
    }
}

Describe 'ThreatJET canonical naming' {
    It 'loads the canonical entrypoint and public commands' {
        $scriptPath = Join-Path $PSScriptRoot '..\ThreatJET.ps1'
        (Test-Path -LiteralPath $scriptPath) | Should -BeTrue
        (Get-Command Invoke-ThreatJETAssessment -ErrorAction Stop).Name | Should -Be 'Invoke-ThreatJETAssessment'
        (Get-Command New-ThreatJETReport -ErrorAction Stop).Name | Should -Be 'New-ThreatJETReport'
    }

    It 'uses canonical output and suppression filenames' {
        $scriptPath = Join-Path $PSScriptRoot '..\ThreatJET.ps1'
        $source = [System.IO.File]::ReadAllText($scriptPath)
        $source.Contains('ThreatJET_Report.html') | Should -BeTrue
        $source.Contains('ThreatJET.Suppressions.json') | Should -BeTrue
    }
}

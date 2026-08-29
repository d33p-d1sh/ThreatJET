#requires -Version 5.1

<#
    ThreatJET - Jumbo Evaluation Tool - single-file build
    Version 2.1.2   Generated 2026-08-29 03:12

    Load it by dot-sourcing, then run the menu:
        . .\ThreatJet_Standalone.ps1
        Show-TJETMenu
#>

# ==========================================================================
# SOURCE: Private\ADSI-Helpers.ps1
# ==========================================================================
function Get-TJETDirectoryContext {
<#
.SYNOPSIS
    Establishes an LDAP connection to the current domain using System.DirectoryServices,
    with no dependency on the ActiveDirectory RSAT module.
.DESCRIPTION
    Returns a context object carrying the root DSE, default naming context, domain/forest
    DNs, and a factory for DirectorySearcher instances bound to a chosen naming context.
    Every ADSI collector starts by calling this.

    Binding is done with the implicit credentials of the running process against a
    serverless LDAP path ("LDAP://<dnc>"), so the domain controller is located
    automatically. The caller may override the server/credentials for offline or
    cross-domain use.

    This is the single point where directory access is configured, so behaviour (paging,
    referral chasing, timeouts) is consistent across all collectors.
#>
    [CmdletBinding()]
    param(
        # Optional explicit DC. Defaults to serverless binding (DC locator).
        [string]$Server,

        # Optional alternate credentials.
        [System.Management.Automation.PSCredential]$Credential
    )

    # Build the base LDAP path. Serverless (LDAP://) lets the DC locator choose.
    $prefix = if ($Server) { "LDAP://$Server" } else { 'LDAP:/' }

    try {
        # RootDSE exposes the naming contexts without us hard-coding the domain.
        $rootDsePath = "$prefix/RootDSE"

        $rootDse = if ($Credential) {
            New-Object System.DirectoryServices.DirectoryEntry(
                $rootDsePath, $Credential.UserName, $Credential.GetNetworkCredential().Password)
        }
        else {
            New-Object System.DirectoryServices.DirectoryEntry($rootDsePath)
        }

        $defaultNC     = "$($rootDse.Properties['defaultNamingContext'].Value)"
        $configNC      = "$($rootDse.Properties['configurationNamingContext'].Value)"
        $schemaNC      = "$($rootDse.Properties['schemaNamingContext'].Value)"
        $rootDomainNC  = "$($rootDse.Properties['rootDomainNamingContext'].Value)"
        $dnsHostName   = "$($rootDse.Properties['dnsHostName'].Value)"
    }
    catch {
        throw "Could not bind to the directory via ADSI: $($_.Exception.Message). " +
              "Confirm this host can reach a domain controller."
    }

    if ([string]::IsNullOrWhiteSpace($defaultNC)) {
        throw 'ADSI bind succeeded but returned no default naming context. Is this host domain-joined?'
    }

    $context = [PSCustomObject]@{
        Server            = $Server
        Credential        = $Credential
        Prefix            = $prefix
        DefaultNC         = $defaultNC
        ConfigurationNC   = $configNC
        SchemaNC          = $schemaNC
        RootDomainNC      = $rootDomainNC
        DomainController  = $dnsHostName
        DomainDNS         = ($defaultNC -replace 'DC=', '' -replace ',', '.')
    }

    # Factory: build a DirectorySearcher rooted at a naming context (defaults to domain).
    $context | Add-Member -MemberType ScriptMethod -Name NewSearcher -Value {
        param(
            [string]$Filter = '(objectClass=*)',
            [string[]]$Properties = @(),
            [string]$SearchRoot,
            [string]$Scope = 'Subtree'
        )

        $root = if ($SearchRoot) { $SearchRoot } else { $this.DefaultNC }
        $path = "$($this.Prefix)/$root"

        $entry = if ($this.Credential) {
            New-Object System.DirectoryServices.DirectoryEntry(
                $path, $this.Credential.UserName, $this.Credential.GetNetworkCredential().Password)
        }
        else {
            New-Object System.DirectoryServices.DirectoryEntry($path)
        }

        $searcher = New-Object System.DirectoryServices.DirectorySearcher($entry)
        $searcher.Filter    = $Filter
        $searcher.PageSize  = 1000            # page automatically past the 1000-object cap
        $searcher.SearchScope = $Scope
        $searcher.ReferralChasing = 'All'

        foreach ($prop in $Properties) {
            if ($prop) { [void]$searcher.PropertiesToLoad.Add($prop) }
        }

        return $searcher
    }

    return $context
}


function Convert-TJETSearchResult {
<#
.SYNOPSIS
    Flattens a System.DirectoryServices.SearchResult into an ordered hashtable of simple
    values, so ADSI results can flow into the same audit-record pipeline the AD-module
    collectors used.
.DESCRIPTION
    ADSI returns every attribute as a ResultPropertyValueCollection (an array), with
    binary blobs for objectSid/objectGUID and FILETIME integers for dates. This converts:
      - single-valued attributes to scalars
      - multi-valued attributes to a "; "-joined string, plus a _Count companion
      - objectSid            -> S-1-5-... string
      - objectGUID           -> GUID string
      - pwdLastSet and other AD FILETIME values -> ISO-8601 (handled by callers via
        ConvertFrom-TJETFileTime; left raw here so callers decide which are dates)
    Attribute names are preserved verbatim (lowercase, as LDAP returns them).
#>
    param(
        [System.DirectoryServices.SearchResult]$Result
    )

    $record = [ordered]@{}

    foreach ($name in $Result.Properties.PropertyNames) {

        $values = $Result.Properties[$name]

        if ($null -eq $values -or $values.Count -eq 0) {
            $record[$name] = ''
            continue
        }

        # Binary identity attributes need explicit conversion.
        if ($name -eq 'objectsid') {
            try {
                $record['objectsid'] = (New-Object System.Security.Principal.SecurityIdentifier($values[0], 0)).Value
            }
            catch { $record['objectsid'] = '' }
            continue
        }

        if ($name -eq 'objectguid') {
            try {
                $record['objectguid'] = ([guid]$values[0]).ToString()
            }
            catch { $record['objectguid'] = '' }
            continue
        }

        if ($name -eq 'sidhistory') {
            $sids = foreach ($raw in $values) {
                try { (New-Object System.Security.Principal.SecurityIdentifier($raw, 0)).Value } catch { }
            }
            $record['sidhistory'] = ($sids -join ';')
            continue
        }

        # Multi-valued -> joined string + count. Single-valued -> scalar.
        if ($values.Count -gt 1) {
            $flat = foreach ($v in $values) { "$v" }
            $record[$name] = ($flat -join '; ')
            $record["${name}_Count"] = $values.Count
        }
        else {
            $record[$name] = $values[0]
        }
    }

    return $record
}


function ConvertFrom-TJETFileTime {
<#
.SYNOPSIS
    Converts an AD FILETIME / Integer8 value to a DateTime (or $null), safely.
.DESCRIPTION
    pwdLastSet, lastLogonTimestamp, accountExpires and similar come back as 64-bit
    FILETIME integers. 0 and 0x7FFFFFFFFFFFFFFF both mean "never/not set". This returns a
    DateTime for real values and $null otherwise, so callers never crash on the sentinels.
#>
    param($Value)

    if ($null -eq $Value) { return $null }

    $long = 0L
    if (-not [long]::TryParse("$Value", [ref]$long)) { return $null }

    if ($long -le 0 -or $long -eq [long]::MaxValue) { return $null }

    try {
        return [DateTime]::FromFileTimeUtc($long)
    }
    catch {
        return $null
    }
}


function Test-TJETUacFlag {
<#
.SYNOPSIS
    Tests a userAccountControl bit, replacing the friendly boolean properties the AD
    module synthesised (Enabled, PasswordNeverExpires, etc).
.DESCRIPTION
    ADSI returns the raw userAccountControl integer; the AD module decoded it into named
    booleans. This exposes the same information by name so collectors read intent, not
    magic numbers.

    Common flags:
        ACCOUNTDISABLE          0x0002
        DONT_REQUIRE_PREAUTH    0x400000
        PASSWD_NOTREQD          0x0020
        DONT_EXPIRE_PASSWORD    0x10000
        TRUSTED_FOR_DELEGATION  0x80000
        TRUSTED_TO_AUTH_FOR_DELEGATION 0x1000000 (constrained w/ protocol transition)
        WORKSTATION_TRUST_ACCOUNT 0x1000
        SERVER_TRUST_ACCOUNT      0x2000
#>
    param(
        [int]$UacValue,
        [ValidateSet('Disabled','NoPreAuth','PasswordNotRequired','PasswordNeverExpires',
                     'TrustedForDelegation','TrustedToAuthForDelegation',
                     'WorkstationTrust','ServerTrust')]
        [string]$Flag
    )

    $bits = @{
        Disabled                   = 0x0002
        PasswordNotRequired        = 0x0020
        WorkstationTrust           = 0x1000
        ServerTrust                = 0x2000
        PasswordNeverExpires       = 0x10000
        TrustedForDelegation       = 0x80000
        NoPreAuth                  = 0x400000
        TrustedToAuthForDelegation = 0x1000000
    }

    return (($UacValue -band $bits[$Flag]) -ne 0)
}


function Get-TJETLdapProperty {
<#
.SYNOPSIS
    Reads a single attribute value from a flattened ADSI record, with a default.
.DESCRIPTION
    Convenience accessor: ADSI attribute names are lowercase and may be absent. This
    returns the value or a supplied default, so collectors don't repeat null checks.
#>
    param(
        [hashtable]$Record,
        [string]$Name,
        $Default = ''
    )

    $key = $Name.ToLower()
    if ($Record.Contains($key) -and $null -ne $Record[$key] -and "$($Record[$key])" -ne '') {
        return $Record[$key]
    }
    return $Default
}


function Get-TJETInventoryObject {
<#
.SYNOPSIS
    Generic ADSI object fetcher for the inventory's RSAT-free fallback path.
.DESCRIPTION
    Returns flattened records (via Convert-TJETSearchResult) for every object matching an
    LDAP filter under a naming context, requesting all attributes. This is the ADSI
    equivalent of "Get-AD<Type> -Filter * -Properties *" for inventory purposes: it does
    not decode UAC bits or derive risk flags (the assessment collectors do that) -- the
    inventory just wants a faithful attribute dump, which ConvertTo-InventoryRecord then
    flattens to CSV.

    Requesting all attributes is done by loading no specific PropertiesToLoad, which makes
    DirectorySearcher return every populated attribute on each object.
#>
    param(
        $Context,
        [string]$Filter = '(objectClass=*)',
        [string]$SearchRoot,
        [string]$Scope = 'Subtree'
    )

    $root = if ($SearchRoot) { $SearchRoot } else { $Context.DefaultNC }

    # Empty PropertiesToLoad => return all populated attributes.
    $searcher = $Context.NewSearcher($Filter, @(), $root, $Scope)

    # Inventory can be large; keep server-side sorting off and rely on paging.
    $results = $searcher.FindAll()

    foreach ($result in $results) {
        $flat = Convert-TJETSearchResult $result
        [PSCustomObject]$flat
    }

    $results.Dispose()
    $searcher.Dispose()
}


# ==========================================================================
# SOURCE: Private\Build-TJETGraph.ps1
# ==========================================================================
function Build-TJETGraph {
<#
.SYNOPSIS
    Builds an in-memory directed graph of principals and the control edges between them.
.DESCRIPTION
    This is the attack-path model. It is the same idea as BloodHound -- nodes are
    security principals and objects, edges are "this can take control of that" -- but
    built from the CSVs this framework already collects, in memory, without Neo4j.

    HONEST SCOPE: this does not collect sessions (SharpHound's HasSession/LoggedOn),
    so it will not find the "user is logged onto a box a lower-privileged user can
    compromise" class of path. It models the ACL/membership/delegation control plane,
    which is where most durable privilege-escalation paths live and where remediation
    is possible. For session-based paths, export the edge list (Export-TJETGraphEdges)
    and load it into BloodHound alongside SharpHound session data.

    Edge types produced:
        MemberOf              principal -> group it belongs to
        GenericAll / GenericWrite / WriteDacl / WriteOwner / WriteProperty
                              trustee -> object it can control (from the ACL audit)
        ForceChangePassword   trustee -> user whose password it can reset
        AddSelf               trustee -> group it can add itself to
        AllowedToDelegate     principal -> delegation target
        Owns                  owner -> object

    Returns a graph object: Nodes (hashtable by identity key) and Edges (list).
#>
    [CmdletBinding()]
    param($Context)

    $nodes = @{}
    $edges = New-Object System.Collections.Generic.List[object]

    function Add-Node {
        param([string]$Key, [string]$Name, [string]$Type, [bool]$IsTier0)

        if ([string]::IsNullOrWhiteSpace($Key)) { return }

        if (-not $nodes.ContainsKey($Key)) {
            $nodes[$Key] = [PSCustomObject]@{
                Key     = $Key
                Name    = $Name
                Type    = $Type
                IsTier0 = $IsTier0
            }
        }
        elseif ($IsTier0 -and -not $nodes[$Key].IsTier0) {
            $nodes[$Key].IsTier0 = $true
        }
    }

    function Add-Edge {
        param([string]$From, [string]$To, [string]$Type)

        if ([string]::IsNullOrWhiteSpace($From) -or [string]::IsNullOrWhiteSpace($To)) { return }
        if ($From -eq $To) { return }

        $edges.Add([PSCustomObject]@{ From = $From; To = $To; Type = $Type })
    }

    # Identity keys use SID where available. Everything referenced only by name (a
    # MemberOf value, an ACL target or trustee name) must resolve to the SAME node as
    # the object that owns that SID -- otherwise the ACL edge "jdoe -> Domain Admins"
    # points at a NAME:DOMAIN ADMINS node while membership uses the SID:...-512 node,
    # and the path never connects. $nameIndex maps an upper-cased name to the SID key.
    $nameIndex = @{}

    function Get-Key {
        param($Sid, $Name)
        if ($Sid) { return "SID:$Sid" }
        if ($Name) {
            $upper = $Name.ToUpper()
            if ($nameIndex.ContainsKey($upper)) { return $nameIndex[$upper] }
            return "NAME:$upper"
        }
        return $null
    }

    function Register-Name {
        param($Sid, $Name)
        if ($Sid -and $Name) {
            $nameIndex[$Name.ToUpper()] = "SID:$Sid"
            # An ACL ObjectName is a CN; index the leaf of any DN form too.
            if ($Name -match '^CN=([^,]+),') { $nameIndex[$Matches[1].ToUpper()] = "SID:$Sid" }
        }
    }

    # ------------------------------------------------------ Name index (first) ---
    # Build the name -> SID map BEFORE any edges, so name-only references resolve to
    # the canonical SID-keyed node.
    foreach ($user in $Context.Data.Users)     { Register-Name $user.ObjectSID $user.SamAccountName }
    foreach ($group in $Context.Data.Groups)   { Register-Name $group.ObjectSID $group.Name }
    foreach ($computer in $Context.Data.Computers) { Register-Name $computer.ObjectSID $computer.Name }

    # ------------------------------------------------------------------ Nodes ---
    foreach ($user in $Context.Data.Users) {
        $key = Get-Key $user.ObjectSID $user.SamAccountName
        Add-Node -Key $key -Name $user.SamAccountName -Type 'User' `
            -IsTier0 ([bool]($Context.IsPrivilegedSid($user.ObjectSID)))
    }

    foreach ($group in $Context.Data.Groups) {
        $key = Get-Key $group.ObjectSID $group.Name
        Add-Node -Key $key -Name $group.Name -Type 'Group' `
            -IsTier0 ([bool](ConvertTo-Bool $group.Is_Tier0))
    }

    foreach ($computer in $Context.Data.Computers) {
        $key = Get-Key $computer.ObjectSID $computer.Name
        Add-Node -Key $key -Name $computer.Name -Type 'Computer' -IsTier0 $false
    }

    # ------------------------------------------------------------ MemberOf edges ---
    # A member can act within the group, so control flows member -> group.
    foreach ($user in $Context.Data.Users) {
        $from = Get-Key $user.ObjectSID $user.SamAccountName
        foreach ($groupName in (@($user.MemberOf_Values -split ';') | Where-Object { $_ })) {
            $to = Get-Key $null $groupName
            Add-Node -Key $to -Name $groupName -Type 'Group' -IsTier0 $false
            Add-Edge -From $from -To $to -Type 'MemberOf'
        }
    }

    foreach ($group in $Context.Data.Groups) {
        $from = Get-Key $group.ObjectSID $group.Name
        foreach ($parentName in (@($group.MemberOf_Values -split ';') | Where-Object { $_ })) {
            $to = Get-Key $null $parentName
            Add-Node -Key $to -Name $parentName -Type 'Group' -IsTier0 $false
            Add-Edge -From $from -To $to -Type 'MemberOf'
        }
    }

    # --------------------------------------------------------------- ACL edges ---
    foreach ($acl in $Context.Data.ACLs) {

        if ($acl.AccessType -and $acl.AccessType -ne 'Allow') { continue }

        # [FIX] Infrastructure trustees (SYSTEM, SELF, Creator Owner) hold broad rights
        # on nearly every object by design. Without this filter -- which the ACL
        # DETECTOR has but the graph builder was missing -- they became graph nodes
        # with edges straight to Tier 0 and were reported as attack paths.
        if (Test-TJETInfrastructureTrustee -TrusteeSid $acl.TrusteeSID -TrusteeName $acl.Trustee) {
            continue
        }

        $classification = Test-TJETDangerousRight -Rights $acl.Rights -ObjectType $acl.ObjectType
        if (-not $classification.IsDangerous) { continue }

        $from = Get-Key $acl.TrusteeSID $acl.Trustee
        $to   = Get-Key $null $acl.ObjectName

        Add-Node -Key $from -Name $acl.Trustee   -Type 'Principal' -IsTier0 ([bool]($Context.IsPrivilegedSid($acl.TrusteeSID)))
        Add-Node -Key $to   -Name $acl.ObjectName -Type 'Object'   -IsTier0 ([bool]($Context.IsPrivilegedGuid($acl.ObjectGUID)))

        $edgeType = switch -Regex ($classification.RightName) {
            'GenericAll'            { 'GenericAll'; break }
            'WriteDacl'             { 'WriteDacl'; break }
            'WriteOwner'            { 'WriteOwner'; break }
            'GenericWrite'          { 'GenericWrite'; break }
            'password'              { 'ForceChangePassword'; break }
            'Self-Membership'       { 'AddSelf'; break }
            'member'               { 'AddMember'; break }
            default                 { 'WriteProperty' }
        }

        Add-Edge -From $from -To $to -Type $edgeType
    }

    return [PSCustomObject]@{
        Nodes = $nodes
        Edges = $edges
    }
}


function Find-TJETAttackPathInternal {
<#
.SYNOPSIS
    Finds shortest control paths from non-privileged principals to Tier 0.
.DESCRIPTION
    Breadth-first search over the control graph. For every non-Tier 0 node that can
    reach a Tier 0 node, returns the shortest path as an ordered list of hops. BFS
    yields shortest paths first, which are the ones worth remediating.

    Reachability is capped (MaxPaths, MaxDepth) so a dense graph cannot run away.
.PARAMETER Graph
    Output of Build-TJETGraph.
.PARAMETER MaxPaths
    Stop after this many distinct paths. Default 500.
.PARAMETER MaxDepth
    Do not explore paths longer than this many hops. Default 8.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Graph,
        [int]$MaxPaths = 500,
        [int]$MaxDepth = 8
    )

    # Adjacency list.
    $adjacency = @{}

    foreach ($edge in $Graph.Edges) {
        if (-not $adjacency.ContainsKey($edge.From)) {
            $adjacency[$edge.From] = New-Object System.Collections.Generic.List[object]
        }
        $adjacency[$edge.From].Add($edge)
    }

    $paths   = New-Object System.Collections.Generic.List[object]
    $sources = $Graph.Nodes.Values | Where-Object { -not $_.IsTier0 -and $adjacency.ContainsKey($_.Key) }

    foreach ($source in $sources) {

        if ($paths.Count -ge $MaxPaths) { break }

        # BFS from this source. Queue holds (nodeKey, pathEdges).
        $queue   = New-Object System.Collections.Generic.Queue[object]
        $visited = @{}

        $queue.Enqueue([PSCustomObject]@{ Node = $source.Key; Path = @() })
        $visited[$source.Key] = $true

        while ($queue.Count -gt 0) {

            $current = $queue.Dequeue()

            if ($current.Path.Count -ge $MaxDepth) { continue }
            if (-not $adjacency.ContainsKey($current.Node)) { continue }

            foreach ($edge in $adjacency[$current.Node]) {

                if ($visited.ContainsKey($edge.To)) { continue }

                $newPath = @($current.Path) + $edge
                $target  = $Graph.Nodes[$edge.To]

                if ($target -and $target.IsTier0) {

                    $paths.Add([PSCustomObject]@{
                        Source     = $source.Name
                        SourceType = $source.Type
                        Target     = $target.Name
                        Hops       = $newPath.Count
                        Path       = $newPath
                    })

                    if ($paths.Count -ge $MaxPaths) { break }

                    # Found Tier 0 from this source; shortest path recorded, move on.
                    continue
                }

                $visited[$edge.To] = $true
                $queue.Enqueue([PSCustomObject]@{ Node = $edge.To; Path = $newPath })
            }

            if ($paths.Count -ge $MaxPaths) { break }
        }
    }

    return $paths
}


function Format-TJETPath {
<#
.SYNOPSIS
    Renders a path object as a readable arrow chain for evidence text.
.EXAMPLE
    jdoe -[GenericAll]-> HELPDESK -[MemberOf]-> Domain Admins
#>
    param($PathResult, $Graph)

    $segments = New-Object System.Collections.Generic.List[string]
    $segments.Add($PathResult.Source)

    foreach ($edge in $PathResult.Path) {
        $toNode = $Graph.Nodes[$edge.To]
        $toName = if ($toNode) { $toNode.Name } else { $edge.To }
        $segments.Add("-[$($edge.Type)]-> $toName")
    }

    return ($segments -join ' ')
}


# ==========================================================================
# SOURCE: Private\Config.ps1
# ==========================================================================
$script:TJETConfig = @{
    
    CollectorVersion = "2.1.2"

    CorrelationVersion = "2.1.2"

    SchemaVersion = "1.2"

    # Filesystem credential datamining is OFF by default: it reads file contents and can
    # be slow on a large disk. Enable via -DataminePasswords on the orchestrator.
    EnableFilesystemCredentialScan = $false

    # Offline CVE scan database (built by the user from MITRE cvelistV5). The scan is
    # opt-in via -IncludeCVEScan and degrades gracefully if this path is absent.
    CVEDatabasePath = "C:\Security\cves.db"


    # Password policy assumptions

    PrivilegedPasswordBaselineLength = 14


    # Risk thresholds

    KrbtgtWarningDays = 365

    KrbtgtCriticalDays = 730


    MachineAccountQuotaThreshold = 0


    # Output

    Encoding = "UTF8"

}

# ==========================================================================
# SOURCE: Private\ConvertTo-InventoryRecord.ps1
# ==========================================================================
function ConvertTo-InventoryRecord {
<#
.SYNOPSIS
    Flattens an AD object into a single CSV-safe row containing every property.
.DESCRIPTION
    Export-Csv calls ToString() on complex values, which turns a multi-valued attribute
    into the useless literal "Microsoft.ActiveDirectory.Management.ADPropertyValue-
    Collection" and a byte array into "System.Byte[]". This flattens properly:

        multi-valued  ->  joined with " | " (a delimiter that does not occur in DNs)
        SID / GUID    ->  string form
        byte[]        ->  base64, or a length marker for large blobs
        DateTime      ->  round-trip ISO 8601 (sortable, unambiguous)
        empty         ->  empty string rather than the word "null"

    A companion _Count column is added for multi-valued attributes so a spreadsheet can
    sort by "users with the most group memberships" without parsing the joined string.

    Large binary attributes are summarised rather than dumped: nTSecurityDescriptor and
    similar would otherwise bloat the CSV to hundreds of megabytes with data that is
    unreadable in that form. ACLs are exported separately by Collect-ACLs.
.PARAMETER Object
    The AD object to flatten.
.PARAMETER MaxBinaryBytes
    Binary values longer than this are replaced with a size marker. Default 256.
#>
    [CmdletBinding()]
    param(
        # [FIX] Was Mandatory without AllowNull, so a single null element anywhere in
        # the pipeline aborted the binding with
        # "Cannot bind argument to parameter 'Object' because it is null" and the
        # whole CSV for that object type was lost. Some AD queries legitimately emit
        # a null alongside real results; skip it rather than failing the export.
        [Parameter(ValueFromPipeline)]
        [AllowNull()]
        $Object,

        [int]$MaxBinaryBytes = 256
    )

    process {

        if ($null -eq $Object) { return }

        $record = [ordered]@{}

        # Properties that are large binary blobs with no value in a flat CSV.
        $skipBinary = @(
            'nTSecurityDescriptor'
            'msExchSafeSendersHash'
            'msExchBlockedSendersHash'
            'msExchSafeRecipientsHash'
            'replUpToDateVector'
            'repsFrom'
            'repsTo'
            'dSASignature'
            'auditingPolicy'
            'msDS-GenerationId'
            'schemaInfo'
            'thumbnailPhoto'
            'jpegPhoto'
            'userCertificate'
            'userSMIMECertificate'
            'msPKIAccountCredentials'
            'msPKIDPAPIMasterKeys'
            'msPKIRoamingTimeStamp'
        )

        foreach ($property in ($Object.PSObject.Properties | Sort-Object Name)) {

            $name  = $property.Name
            $value = $property.Value

            if ($name -in $skipBinary) {
                $record[$name] = if ($value) { '(binary omitted)' } else { '' }
                continue
            }

            if ($null -eq $value) {
                $record[$name] = ''
                continue
            }

            # --- byte arrays -------------------------------------------------
            if ($value -is [byte[]]) {

                if ($value.Length -gt $MaxBinaryBytes) {
                    $record[$name] = "(binary, $($value.Length) bytes)"
                }
                else {
                    $record[$name] = [Convert]::ToBase64String($value)
                }
                continue
            }

            # --- single scalar types that must not be enumerated -------------
            if ($value -is [string] -or $value -is [datetime] -or $value -is [bool] -or
                $value -is [int] -or $value -is [long] -or $value -is [guid]) {

                if ($value -is [datetime]) {
                    $record[$name] = $value.ToString('o')
                }
                else {
                    $record[$name] = "$value"
                }
                continue
            }

            # --- multi-valued -------------------------------------------------
            if ($value -is [System.Collections.IEnumerable]) {

                $items = New-Object System.Collections.Generic.List[string]

                foreach ($item in $value) {

                    if ($null -eq $item) { continue }

                    if ($item -is [byte[]]) {
                        $items.Add("(binary, $($item.Length) bytes)")
                    }
                    elseif ($item -is [datetime]) {
                        $items.Add($item.ToString('o'))
                    }
                    else {
                        $items.Add("$item")
                    }
                }

                $record[$name]          = ($items -join ' | ')
                $record["${name}_Count"] = $items.Count
                continue
            }

            # --- everything else (SID, GUID, ADPropertyValue, enums) ----------
            $record[$name] = "$value"
        }

        [PSCustomObject]$record
    }
}


function Export-TJETRelationship {
<#
.SYNOPSIS
    Writes a normalised (one row per value) CSV for a multi-valued attribute.
.DESCRIPTION
    The main inventory CSVs join multi-valued attributes into one cell, which is
    convenient to read but useless for pivoting or joining. This emits the same data in
    normalised form -- one row per source/value pair -- so the output can be loaded into
    a spreadsheet, database or graph tool directly.

    Example: REL_Group_Members.csv is a proper edge list, so
    "which groups is this user in, transitively" becomes a join rather than a parse.
.PARAMETER Objects
    Source objects.
.PARAMETER Property
    The multi-valued property to expand.
.PARAMETER SourceIdProperty
    Property identifying the source object (typically DistinguishedName).
.PARAMETER SourceNameProperty
    Human-readable name of the source object.
.PARAMETER ValueColumnName
    Column name for the expanded value.
.PARAMETER Path
    Full path of the CSV to write.
#>
    [CmdletBinding()]
    param(
        [object[]]$Objects,
        [Parameter(Mandatory)][string]$Property,
        [string]$SourceIdProperty   = 'DistinguishedName',
        [string]$SourceNameProperty = 'Name',
        [Parameter(Mandatory)][string]$ValueColumnName,
        [Parameter(Mandatory)][string]$Path
    )

    $rows = New-Object System.Collections.Generic.List[object]

    foreach ($object in $Objects) {

        # Property access must work for BOTH shapes the inventory can produce:
        #   - AD module objects: property is $Property (e.g. 'Member') holding an array.
        #   - ADSI records: property name is lowercase ('member') and multi-valued
        #     attributes arrive as a single "; "-joined string from Convert-TJETSearchResult.
        # Resolve the property name case-insensitively, then split a joined string back
        # into individual values so the edge list is correct either way.
        # Some AD-module property names differ from their LDAP attribute name by more
        # than case, so a case-insensitive match is not enough for the ADSI shape.
        # This maps the RSAT name to the LDAP name(s) it could appear as.
        $ldapAliases = @{
            'ServicePrincipalNames'                      = @('serviceprincipalname')
            'SIDHistory'                                 = @('sidhistory')
            'msDS-AllowedToDelegateTo'                   = @('msds-allowedtodelegateto')
            'PrincipalsAllowedToRetrieveManagedPassword' = @('retrieval_principals','msds-groupmsamembership')
        }

        $candidates = @($Property, $Property.ToLower())
        if ($ldapAliases.ContainsKey($Property)) { $candidates += $ldapAliases[$Property] }

        $propName = $Property
        $matchedProp = $object.PSObject.Properties.Name |
            Where-Object { $candidates -contains $_ -or $candidates -contains $_.ToLower() } |
            Select-Object -First 1
        if ($matchedProp) { $propName = $matchedProp }

        $values = $object.$propName

        if ($null -eq $values) { continue }

        # Normalise to a list of individual values. A joined ADSI string ("a; b; c")
        # becomes three values; a real array passes through unchanged.
        $valueList = if ($values -is [string] -and $values -match '; ') {
            $values -split '; '
        }
        else {
            @($values)
        }

        foreach ($value in $valueList) {

            if ($null -eq $value -or "$value" -eq '') { continue }

            $row = [ordered]@{
                Source_Name = "$($object.$SourceNameProperty)"
                Source_DN   = "$($object.$SourceIdProperty)"
            }

            $row[$ValueColumnName] = "$value"

            # Split a DN into its leaf name so the edge list is readable without
            # post-processing.
            if ("$value" -match '^CN=([^,]+),') {
                $row["${ValueColumnName}_Name"] = $Matches[1]
            }
            else {
                $row["${ValueColumnName}_Name"] = "$value"
            }

            $rows.Add([PSCustomObject]$row)
        }
    }

    if ($rows.Count -gt 0) {
        $rows | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
    }

    return $rows.Count
}


# ==========================================================================
# SOURCE: Private\FindingFactory.ps1
# ==========================================================================
function New-Finding {

    [CmdletBinding()]

    param(

        [Parameter(Mandatory)]
        [string]
        $Finding_ID,


        # [FIX] Was optional with no default. A finding with an empty Severity
        # sorts unpredictably in Export-Findings and renders without a CSS class.
        [Parameter(Mandatory)]
        [ValidateSet(
            "Critical",
            "High",
            "Medium",
            "Low",
            "Info"
        )]
        [string]
        $Severity,


        [ValidateSet(
            "High",
            "Medium",
            "Low"
        )]
        [string]
        $Confidence = "Medium",


        [Parameter(Mandatory)]
        [string]
        $Category,


        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]
        $Target,


        [string]
        $Target_GUID = "N/A",


        [Parameter(Mandatory)]
        [string]
        $Finding,


        [string]
        $Evidence,


        [string]
        $Recommendation
    )


        # [FIX] A mandatory [string]$Target rejects an empty value, which threw
    # "Cannot bind argument to parameter 'Target' because it is an empty string"
    # and aborted an ENTIRE detector because one source row lacked a name.
    # Substitute a visible placeholder so the finding is still reported and the
    # data-quality problem is obvious in the report.
    if ([string]::IsNullOrWhiteSpace($Target)) {
        $Target = '(unnamed object - source row incomplete)'   # lint:allow-param-assign
    }

[PSCustomObject]@{

        Finding_ID =
            $Finding_ID


        Assessment_Date =
            (Get-Date -Format "yyyy-MM-dd")


        Severity =
            $Severity


        Confidence =
            $Confidence


        Category =
            $Category


        Target =
            $Target


        Target_GUID =
            $Target_GUID


        Finding =
            $Finding


        Evidence =
            $Evidence


        Recommendation =
            $Recommendation


        Collector_Version =
            $script:TJETConfig.CollectorVersion


        Correlation_Version =
            $script:TJETConfig.CorrelationVersion


        Schema_Version =
            $script:TJETConfig.SchemaVersion

    }

}

# ==========================================================================
# SOURCE: Private\Get-TJETFindingMetadata.ps1
# ==========================================================================
function Get-TJETFindingMetadata {
<#
.SYNOPSIS
    Returns MITRE ATT&CK mapping and blue-team detection guidance for a finding ID.
.DESCRIPTION
    This is what makes the assessment a PURPLE team exercise rather than a red team
    report. Every finding carries three things:

        Attack_Technique    what an operator would do with it (red)
        MITRE_Technique     the ATT&CK ID, so it maps to an existing detection programme
        Detection_Guidance  what the defender should hunt for (blue)

    Detection guidance names concrete telemetry -- Windows Security event IDs, the
    relevant object class, and what "normal" looks like -- so a SOC can build or verify
    a rule rather than being told a vulnerability exists.

    Held as a single table keyed by Finding_ID and applied at export time. Detectors
    therefore need no changes when the mapping is refined, and the mapping cannot drift
    out of sync between detectors emitting the same ID.

    Event ID reference used throughout:
        4662  operation on an AD object (needs SACL; carries the property GUID)
        4670  permissions on an object were changed
        4728/4732/4756  member added to a global/local/universal group
        4738  user account changed
        4742  computer account changed
        4768/4769  Kerberos TGT / service ticket requested
        5136  a directory service object was modified
        5137/5141  directory object created / deleted
.PARAMETER FindingId
    The Finding_ID to look up.
.OUTPUTS
    PSCustomObject with Attack_Technique, MITRE_Technique and Detection_Guidance.
    Unknown IDs return a safe placeholder rather than throwing.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$FindingId
    )

    if ($null -eq $script:TJETFindingMetadata) {

        $script:TJETFindingMetadata = @{

            # ---------------------------------------------------------- Domain ---
            'DOM-001' = @{
                Attack = 'Golden Ticket forgery using the krbtgt key.'
                Mitre  = 'T1558.001 - Steal or Forge Kerberos Tickets: Golden Ticket'
                Detect = 'Hunt for 4769 requests with anomalous ticket lifetimes or encryption downgrade (RC4 where AES is standard). Alert on 4768 for accounts that do not exist. Baseline krbtgt PasswordLastSet and alert on unexpected change.'
            }
            'DOM-004' = @{
                Attack = 'SID history injection across the trust to impersonate a privileged principal.'
                Mitre  = 'T1134.005 - Access Token Manipulation: SID-History Injection'
                Detect = 'Alert on 4662 and 5136 modifying sIDHistory. Monitor 4769 for cross-realm referrals from the trusted domain. Any sIDHistory outside an active migration window is suspect.'
            }
            'DOM-005' = @{
                Attack = 'Any authenticated user creates a computer account, enabling RBCD and shadow-credential chains.'
                Mitre  = 'T1078.002 - Valid Accounts: Domain Accounts'
                Detect = 'Alert on 4741 (computer account created) where the creator is not a member of the delegated machine-join group. In a hardened domain this should be near zero.'
            }
            'DOM-006' = @{
                Attack = 'Password spraying against principals covered by the weaker policy.'
                Mitre  = 'T1110.003 - Brute Force: Password Spraying'
                Detect = 'Correlate 4771/4625 failures across many accounts from one source within a short window. Alert on 5136 changes to msDS-PasswordSettings objects.'
            }

            # -------------------------------------------------------- Identity ---
            'ID-001' = @{
                Attack = 'Kerberoasting: request a service ticket and crack it offline.'
                Mitre  = 'T1558.003 - Steal or Forge Kerberos Tickets: Kerberoasting'
                Detect = 'Alert on 4769 with RC4 encryption (0x17) where AES is the norm, especially several distinct SPNs requested by one principal in a short window. Honeypot SPN accounts detect this with near-zero false positives.'
            }
            'ID-002' = @{
                Attack = 'Impersonate users to the configured target services via S4U2Proxy.'
                Mitre  = 'T1550.003 - Use Alternate Authentication Material: Pass the Ticket'
                Detect = 'Alert on 4769 containing S4U2Proxy indicators, and on 5136 changes to msDS-AllowedToDelegateTo.'
            }
            'ID-004' = @{
                Attack = 'Harvest cached TGTs of every principal that authenticates to the account.'
                Mitre  = 'T1558 - Steal or Forge Kerberos Tickets'
                Detect = 'Alert on 4738 where TRUSTED_FOR_DELEGATION is set. Watch for coercion patterns (unexpected machine authentication) preceding delegation abuse.'
            }
            'ID-005' = @{
                Attack = 'Privilege inherited invisibly through SIDHistory, bypassing group membership review.'
                Mitre  = 'T1134.005 - Access Token Manipulation: SID-History Injection'
                Detect = 'Alert on any 5136 or 4662 write to sIDHistory. Outside a migration this is almost always malicious. Audit existing values against migration records.'
            }
            'ID-006' = @{
                Attack = 'Reuse of a dormant administrative account, unlikely to be noticed by its owner.'
                Mitre  = 'T1078.002 - Valid Accounts: Domain Accounts'
                Detect = 'Alert on 4624/4768 for accounts with no logon in 90+ days, especially privileged ones. First use after long dormancy is high signal.'
            }
            'ID-007' = @{
                Attack = 'AS-REP roasting: request an AS-REP without credentials and crack it offline.'
                Mitre  = 'T1558.004 - Steal or Forge Kerberos Tickets: AS-REP Roasting'
                Detect = 'Alert on 4768 where pre-authentication was not required, particularly several accounts enumerated from one source. Alert on 4738 setting DONT_REQ_PREAUTH.'
            }
            'ID-008' = @{
                Attack = 'Shadow credentials: authenticate as the account using an attacker-controlled certificate.'
                Mitre  = 'T1556.007 - Modify Authentication Process: Hybrid Identity'
                Detect = 'Alert on 5136 writes to msDS-KeyCredentialLink where the writer is not the account itself or the device-registration service. Correlate with 4768 using certificate pre-authentication.'
            }
            'ID-009' = @{
                Attack = 'Indefinite credential lifetime increases the window for offline cracking and reuse.'
                Mitre  = 'T1078.002 - Valid Accounts: Domain Accounts'
                Detect = 'Alert on 4738 setting DONT_EXPIRE_PASSWORD on a privileged account. Report periodically on privileged accounts with password age over policy.'
            }
            'ID-010' = @{
                Attack = 'Authenticate with a blank password.'
                Mitre  = 'T1078.002 - Valid Accounts: Domain Accounts'
                Detect = 'Alert on 4738 setting PASSWD_NOTREQD. Review 4624 logon history for the account -- prior use may indicate existing compromise.'
            }
            'ID-011' = @{
                Attack = 'Password spraying or offline cracking against privileged accounts held to a weak baseline.'
                Mitre  = 'T1110.003 - Brute Force: Password Spraying'
                Detect = 'Correlate 4771/4625 across privileged accounts. Alert on any authentication failure burst targeting Tier 0 identities.'
            }

            # -------------------------------------------------- Infrastructure ---
            'INF-001' = @{
                Attack = 'Coerce a domain controller to authenticate, then extract its TGT from the host cache.'
                Mitre  = 'T1187 - Forced Authentication'
                Detect = 'Alert on 4742 setting TRUSTED_FOR_DELEGATION. Monitor for coercion (unexpected DC authentication to a member server) via 4624 type 3 from DC machine accounts.'
            }
            'INF-002' = @{
                Attack = 'Resource-based constrained delegation abuse to impersonate any user to the host.'
                Mitre  = 'T1134.001 - Access Token Manipulation: Token Impersonation/Theft'
                Detect = 'Alert on 5136 writes to msDS-AllowedToActOnBehalfOfOtherIdentity. Legitimate changes are rare and planned; treat unexpected ones as compromise.'
            }
            'INF-003' = @{
                Attack = 'Reuse of a shared local administrator password for lateral movement.'
                Mitre  = 'T1078.003 - Valid Accounts: Local Accounts'
                Detect = 'Hunt for 4624 type 3 logons using the same local account across multiple hosts. Alert on 4662 reads of LAPS password attributes by non-help-desk principals.'
            }
            'INF-004' = @{
                Attack = 'Exploitation of unpatched vulnerabilities and forced use of legacy authentication protocols.'
                Mitre  = 'T1210 - Exploitation of Remote Services'
                Detect = 'Alert on NTLMv1 or SMBv1 negotiation. Monitor 4624 with LmPackageName set to NTLM V1 -- legacy operating systems are usually the source.'
            }
            'INF-005' = @{
                Attack = 'Shadow credentials on a computer object, enabling authentication as the machine.'
                Mitre  = 'T1556.007 - Modify Authentication Process: Hybrid Identity'
                Detect = 'Alert on 5136 writes to msDS-KeyCredentialLink on computer objects. On a domain controller treat as domain compromise until disproven.'
            }

            # ---------------------------------------------------------- Policy ---
            'GPO-001' = @{
                Attack = 'Modify a GPO to execute code on every machine it applies to.'
                Mitre  = 'T1484.001 - Domain or Tenant Policy Modification: Group Policy Modification'
                Detect = 'Alert on 5136 changes to groupPolicyContainer objects and on versionNumber increments outside change windows. Monitor SYSVOL file writes, particularly to scripts and scheduled-task XML.'
            }
            'GPO-002' = @{
                Attack = 'Write GPO content directly in SYSVOL, bypassing directory-level delegation.'
                Mitre  = 'T1484.001 - Domain or Tenant Policy Modification: Group Policy Modification'
                Detect = 'Enable file-system auditing on the SYSVOL Policies folder and alert on 4663 writes by principals outside the GPO administration group.'
            }
            'GPO-003' = @{
                Attack = 'Grant privileged user rights (for example SeBackupPrivilege, which permits reading NTDS.dit) to controlled principals.'
                Mitre  = 'T1484.001 - Domain or Tenant Policy Modification: Group Policy Modification'
                Detect = 'Alert on 4704 (user right assigned) and on GPO edits touching User Rights Assignment. Baseline which policies legitimately grant these rights.'
            }

            # ------------------------------------------------------- Privilege ---
            'GRP-001' = @{
                Attack = 'Add a member to an unmonitored privileged group to obtain quiet, persistent privilege.'
                Mitre  = 'T1098 - Account Manipulation'
                Detect = 'Alert on 4728/4732/4756 for any privileged group, and treat additions to a normally empty group as high signal.'
            }
            'GRP-002' = @{
                Attack = 'Unowned privileged groups escape periodic access review.'
                Mitre  = 'T1098 - Account Manipulation'
                Detect = 'Report group membership deltas periodically; without a named owner there is nobody to attest to the membership.'
            }
            'GRP-003' = @{
                Attack = 'Nested membership grants Tier 0 privilege to principals a direct membership review will not show.'
                Mitre  = 'T1098 - Account Manipulation'
                Detect = 'Alert on 4728/4756 where the member added is itself a group. Compute and report effective (transitive) Tier 0 membership, not direct membership.'
            }

            # ------------------------------------------------ Service accounts ---
            'GMSA-001' = @{
                Attack = 'Retrieve the managed password and authenticate as the service account.'
                Mitre  = 'T1078.002 - Valid Accounts: Domain Accounts'
                Detect = 'Alert on 4662 reads of msDS-ManagedPassword by any principal other than the authorised host group. This read is rare and highly specific.'
            }

            'LOCAL-012' = @{
                Attack = 'Replace the binary a privileged scheduled task executes from a user-writable directory.'
                Mitre  = 'T1053.005 - Scheduled Task/Job: Scheduled Task'
                Detect = 'Alert on 4698 (task created) and 4702 (task updated). Monitor writes to task action binaries. A task running as SYSTEM from outside %ProgramFiles% or %SystemRoot% is inherently suspect.'
            }

            'LOCAL-013' = @{
                Attack = 'Plant a DLL or executable in a writable directory that a privileged process resolves by unqualified name.'
                Mitre  = 'T1574.001 - Hijack Execution Flow: DLL Search Order Hijacking'
                Detect = 'Enable file auditing on writable roots and alert on 4663 DLL/EXE creation. Sysmon event 7 (image loaded) from a user-writable path into a SYSTEM process is high signal.'
            }

            'LOCAL-014' = @{
                Attack = 'Read plaintext credentials out of PowerShell console history.'
                Mitre  = 'T1552.001 - Unsecured Credentials: Credentials In Files'
                Detect = 'Alert on 4663 reads of ConsoleHost_history.txt by a principal other than its owner. Enable PowerShell script block logging (4104) to see the commands as they run rather than after.'
            }

            'LOCAL-015' = @{
                Attack = 'Recover the local administrator password from a deployment answer file.'
                Mitre  = 'T1552.001 - Unsecured Credentials: Credentials In Files'
                Detect = 'Alert on any read of Unattend.xml or sysprep files post-deployment. These should not exist on a live host at all, so presence alone is the detection.'
            }

            'LOCAL-016' = @{
                Attack = 'Reuse cloud credential files to pivot beyond the host into the tenant or account.'
                Mitre  = 'T1552.001 - Unsecured Credentials: Credentials In Files'
                Detect = 'Alert on access to .aws/credentials, .azure token caches and gcloud credential stores by non-owner principals. Correlate with cloud-side sign-in logs from unexpected source addresses.'
            }

            'LOCAL-017' = @{
                Attack = 'Use an unencrypted SSH private key to authenticate to every host that trusts it.'
                Mitre  = 'T1552.004 - Unsecured Credentials: Private Keys'
                Detect = 'Alert on reads of id_rsa/id_ed25519 by non-owner principals. On the SSH server side, monitor for the same key authenticating from a new source host.'
            }

            'LOCAL-018' = @{
                Attack = 'Harvest saved session hosts, usernames and stored passwords from PuTTY, WinSCP and RDP history.'
                Mitre  = 'T1552.002 - Unsecured Credentials: Credentials in Registry'
                Detect = 'Alert on reads of the PuTTY/WinSCP session registry keys. WinSCP passwords are obfuscated, not encrypted, so a read is equivalent to a disclosure.'
            }

            'LOCAL-019' = @{
                Attack = 'Read VNC, SNMP or autologon credentials directly from the registry.'
                Mitre  = 'T1552.002 - Unsecured Credentials: Credentials in Registry'
                Detect = 'Alert on 4657 (registry value modified) and on reads of Winlogon DefaultPassword and VNC password keys. These values are obfuscated with published, reversible schemes.'
            }

            'LOCAL-020' = @{
                Attack = 'Trigger a SYSTEM shell from the logon screen via an accessibility binary debugger, without authenticating.'
                Mitre  = 'T1546.008 - Event Triggered Execution: Accessibility Features'
                Detect = 'Alert on ANY write to Image File Execution Options for sethc.exe, utilman.exe or osk.exe (event 4657). Legitimate debugger entries on these binaries are essentially nonexistent - this is one of the highest-signal host detections available.'
            }

            'LOCAL-021' = @{
                Attack = 'Inject a malicious update package over cleartext WSUS and execute as SYSTEM.'
                Mitre  = 'T1557 - Adversary-in-the-Middle'
                Detect = 'Alert on WSUS policy pointing at http://. Monitor for unexpected update installations (event 19/20 in WindowsUpdateClient) and for ARP/DNS anomalies on the update path.'
            }

            'LOCAL-022' = @{
                Attack = 'Attack the RDP service directly, without the pre-authentication barrier NLA provides.'
                Mitre  = 'T1021.001 - Remote Services: Remote Desktop Protocol'
                Detect = 'Alert on 4625 bursts against RDP and on 4624 type 10 logons from unexpected sources. Without NLA there is no pre-auth gate, so connection attempts reach more of the stack.'
            }

            'LOCAL-023' = @{
                Attack = 'Disable endpoint protection so tooling runs unimpeded.'
                Mitre  = 'T1562.001 - Impair Defenses: Disable or Modify Tools'
                Detect = 'Alert on Defender events 5001 (real-time protection disabled) and 5010/5012. Tamper protection being off is a precondition worth alerting on by itself.'
            }

            'LOCAL-024' = @{
                Attack = 'Reach services on the host that a firewall profile would otherwise block.'
                Mitre  = 'T1562.004 - Impair Defenses: Disable or Modify System Firewall'
                Detect = 'Alert on 4950 (firewall setting changed) and on profile state transitions to off. A disabled profile on a mobile host is especially notable.'
            }

            'LOCAL-025' = @{
                Attack = 'Exploit spooler vulnerabilities, or coerce machine authentication for relay.'
                Mitre  = 'T1068 - Exploitation for Privilege Escalation'
                Detect = 'Alert on spooler service starts on hosts that do not print, and on unexpected outbound SMB from the machine account (coercion). Disabling the spooler on servers removes the surface entirely.'
            }

            'LOCAL-026' = @{
                Attack = 'Stage tooling on, or harvest data from, a writable non-administrative share.'
                Mitre  = 'T1039 - Data from Network Shared Drive'
                Detect = 'Alert on 5140/5145 (share accessed, with the requested permissions). Writable shares reachable by Everyone or Authenticated Users deserve standing alerts.'
            }

            'LOCAL-027' = @{
                Attack = 'Compromise any local administrator account to obtain SYSTEM on the host.'
                Mitre  = 'T1078.003 - Valid Accounts: Local Accounts'
                Detect = 'Alert on 4732 (member added to a local group) for Administrators. Baseline the expected membership and treat every addition as reportable.'
            }

            'PORT-001' = @{
                Attack = 'Connect to the exposed service and attack it directly - brute force, exploit, relay, or sniff cleartext credentials.'
                Mitre  = 'T1046 - Network Service Discovery'
                Detect = 'Alert on unexpected listeners via periodic port baselining. Flag new externally-bound services (5156 with the Windows Filtering Platform), and legacy-cleartext protocols (Telnet/FTP) at the network layer.'
            }

            'PATCH-001' = @{
                Attack = 'Exploit any vulnerability fixed since the host''s last update.'
                Mitre  = 'T1203 - Exploitation for Client Execution'
                Detect = 'Report patch age from your patch-management system rather than per host. A host that stops checking in to WSUS/Windows Update is the signal - alert on update-agent failures.'
            }

            'CRED-002' = @{
                Attack = 'Read the credential straight out of a file and authenticate as that principal - no exploitation required.'
                Mitre  = 'T1552.001 - Unsecured Credentials: Credentials In Files'
                Detect = 'Alert on 4663 reads of known credential files (web.config, .kdbx, id_rsa, .env) by unexpected principals. Deploy a canary credential file and alert on any access to it.'
            }

            'CVE-001' = @{
                Attack = 'Exploit the matched CVE against the installed, unpatched software.'
                Mitre  = 'T1203 - Exploitation for Client Execution'
                Detect = 'This is inventory-versus-database matching, not live exploitation. Feed the CVE matches into your patch-prioritisation process and confirm exploitability before acting - a present CVE is not proof the vulnerable code path is reachable.'
            }

            'PROC-001' = @{
                Attack = 'Run or replace a process executing from a user-writable location, or masquerade with an unsigned binary.'
                Mitre  = 'T1543 - Create or Modify System Process'
                Detect = 'Alert on process creation (4688 with command line) where the image path is under Users, Temp, AppData or ProgramData, and on unsigned binaries in service context. Sysmon event 1 with signature status is ideal.'
            }

            'ADCS-001' = @{
                Attack = 'Enrol a certificate as an arbitrary principal (including a Domain Admin) via an ESC1 template, then authenticate with it (PKINIT/Schannel).'
                Mitre  = 'T1649 - Steal or Forge Authentication Certificates'
                Detect = 'Alert on certificate requests where the requester and the subject differ, on Certificate Services event 4886/4887 with unusual SANs, and on 4768 (TGT) authentications using a certificate. Tools: enable CA request auditing and monitor for Certify/Certipy patterns.'
            }

            'ADCS-002' = @{
                Attack = 'Enrol an Any-Purpose or no-EKU certificate as a low-privileged user and use it for client authentication.'
                Mitre  = 'T1649 - Steal or Forge Authentication Certificates'
                Detect = 'As ESC1: monitor certificate issuance for templates with no EKU constraint and correlate certificate-based logons (4768 with certificate info) against the enrolling principal.'
            }

            'ADCS-003' = @{
                Attack = 'Use an Enrollment Agent certificate to enrol on behalf of other users, obtaining auth certificates for higher-privileged principals.'
                Mitre  = 'T1649 - Steal or Forge Authentication Certificates'
                Detect = 'Monitor issuance of Enrollment Agent certificates and any on-behalf-of enrolment. Restrict enrollment-agent templates tightly and enable CA enrollment-agent restrictions.'
            }

            'ADCS-004' = @{
                Attack = 'Reconfigure a template you have write access to (enable enrollee-supplies-subject, add a client-auth EKU, drop approval) to manufacture an ESC1, then abuse it.'
                Mitre  = 'T1649 - Steal or Forge Authentication Certificates'
                Detect = 'Alert on 5136 modifications to pKICertificateTemplate objects under the Configuration NC. Template changes are rare and administrative -- treat any unexpected one as an incident.'
            }

            'ADCS-005' = @{
                Attack = 'Specify an arbitrary SAN on any request (ESC6) or relay machine/user NTLM to HTTP web enrollment (ESC8) to obtain a certificate as a privileged principal.'
                Mitre  = 'T1649 - Steal or Forge Authentication Certificates'
                Detect = 'ESC6/ESC8 are on-box: audit EDITF_ATTRIBUTESUBJECTALTNAME on the CA and watch for web-enrollment (certsrv) HTTP authentication. Enforce EPA/HTTPS and disable HTTP enrollment. Monitor for relayed machine-account certificate requests.'
            }

            'ADCS-006' = @{
                Attack = 'Enrol an authentication certificate through an over-permissioned template as a stepping stone or for persistence.'
                Mitre  = 'T1649 - Steal or Forge Authentication Certificates'
                Detect = 'Review which groups can enrol for authentication-capable templates; alert on enrolment by principals outside the intended group.'
            }

            # ---------------------------------------------- Credential exposure ---
            'CRED-001' = @{
                Attack = 'Read the credential straight out of the directory attribute and authenticate as that principal -- no cracking, no exploitation.'
                Mitre  = 'T1552.001 - Unsecured Credentials: Credentials In Files'
                Detect = 'Alert on 4662 reads of userPassword/unixUserPassword. Periodically scan description, info, comment and extensionAttribute* for assignment patterns. Any authenticated user can read these attributes by default, so exposure is domain-wide and leaves no distinctive access trail.'
            }

            # ----------------------------------------------- Assessment context ---
            'LOCAL-000' = @{
                Attack = 'Context only - records that the assessment ran with local administrator rights.'
                Mitre  = 'N/A - informational'
                Detect = 'No detection applies. Re-run as a standard user to enumerate escalation routes from an unprivileged perspective.'
            }

            # ----------------------------------------------------- Attack path ---
            'PATH-001' = @{
                Attack = 'Abuse the delegated right to add a member, reset a password, or rewrite the ACL of a Tier 0 object.'
                Mitre  = 'T1222.001 - File and Directory Permissions Modification: Windows'
                Detect = 'Alert on 4662 against Tier 0 objects (requires a SACL on those objects) and 4670 permission changes. Alert on 4728/4732 for Tier 0 groups.'
            }
            'PATH-002' = @{
                Attack = 'Persist by writing an ACE to AdminSDHolder; SDProp stamps it onto every protected object hourly.'
                Mitre  = 'T1098 - Account Manipulation'
                Detect = 'Alert on ANY 5136 or 4670 against CN=AdminSDHolder,CN=System. Legitimate changes are extremely rare -- this is one of the highest-value single detections in Active Directory.'
            }
            'PATH-003' = @{
                Attack = 'A single delegation replicated across all protected objects, typically via AdminSDHolder.'
                Mitre  = 'T1098 - Account Manipulation'
                Detect = 'Monitor AdminSDHolder as for PATH-002. Periodically diff the ACLs of adminCount=1 objects -- they should be uniform and match a known-good baseline.'
            }
            'PATH-GRAPH' = @{
                Attack = 'Chain multiple control relationships (membership, delegated ACLs, delegation) to walk from a low-privileged principal to Tier 0.'
                Mitre  = 'T1078 - Valid Accounts / T1098 - Account Manipulation'
                Detect = 'No single event covers a chain. Monitor the individual edge types (4728/4732 group changes, 5136/4670 ACL changes) and correlate. BloodHound-style periodic graph analysis is the intended detection.'
            }

            # -------------------------------------------- Local privilege esc ---
            'LOCAL-001' = @{
                Attack = 'Plant an executable at an unquoted, space-delimited path segment so it runs in the service context.'
                Mitre  = 'T1574.009 - Hijack Execution Flow: Path Interception by Unquoted Path'
                Detect = 'Alert on 4697/7045 (service install) and on file creation in service binary paths. Baseline service PathName values.'
            }
            'LOCAL-002' = @{
                Attack = 'Replace or plant the service binary a non-admin can write, gaining the service account context.'
                Mitre  = 'T1574.010 - Hijack Execution Flow: Services File Permissions Weakness'
                Detect = 'Alert on 7045/7040 (service change) and on writes to service binary directories by non-administrators (4663).'
            }
            'LOCAL-003' = @{
                Attack = 'Install a crafted MSI that executes as SYSTEM via AlwaysInstallElevated.'
                Mitre  = 'T1548.002 - Abuse Elevation Control Mechanism: Bypass User Account Control'
                Detect = 'Alert on MSI installs (1040/1042 MsiInstaller) initiated by standard users. The registry values themselves should be baselined at zero.'
            }
            'LOCAL-004' = @{
                Attack = 'Plant a DLL or shadowing executable in a writable PATH directory to hijack name resolution.'
                Mitre  = 'T1574.007 - Hijack Execution Flow: Path Interception by PATH Environment Variable'
                Detect = 'Alert on file creation in PATH directories. Baseline the system PATH and its directory ACLs.'
            }
            'LOCAL-005' = @{
                Attack = 'Replace an autorun target in a writable location to execute on the next logon.'
                Mitre  = 'T1547.001 - Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder'
                Detect = 'Alert on 4657 changes to Run/RunOnce keys and on writes to Startup folders. Baseline autorun entries.'
            }
            'LOCAL-006' = @{
                Attack = 'Recover a plaintext or reversibly-encrypted credential from unattend/GPP files or the registry.'
                Mitre  = 'T1552.001 - Unsecured Credentials: Credentials In Files'
                Detect = 'Alert on reads of unattend.xml/Groups.xml and on 4663 access to those paths. GPP passwords were patched by MS14-025 but files persist.'
            }
            'LOCAL-007' = @{
                Attack = 'Abuse a held token privilege (SeImpersonate, SeBackup, SeDebug) to escalate to SYSTEM or read protected material.'
                Mitre  = 'T1134 - Access Token Manipulation'
                Detect = 'Alert on 4672 (special privileges assigned) for non-administrative logons, and on 4703 token-privilege adjustments.'
            }
            'LOCAL-008' = @{
                Attack = 'Operate with a full administrator token because UAC is weakened or disabled.'
                Mitre  = 'T1548.002 - Abuse Elevation Control Mechanism: Bypass User Account Control'
                Detect = 'Baseline EnableLUA and FilterAdministratorToken; alert on 4657 changes to those values.'
            }
            'LOCAL-009' = @{
                Attack = 'Recover cleartext credentials from LSASS because WDigest is enabled or LSA protection is off.'
                Mitre  = 'T1003.001 - OS Credential Dumping: LSASS Memory'
                Detect = 'Alert on 4657 changes to UseLogonCredential/RunAsPPL and on 10 (Sysmon) process access to lsass.exe.'
            }
            'LOCAL-010' = @{
                Attack = 'Relay an unsigned SMB session to authenticate elsewhere as the victim.'
                Mitre  = 'T1557.001 - Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay'
                Detect = 'Baseline RequireSecuritySignature=1. Monitor for NTLM authentication from unexpected relays.'
            }
            'LOCAL-011' = @{
                Attack = 'Exploit SMBv1, or use PowerShell v2 to bypass AMSI and script-block logging.'
                Mitre  = 'T1210 - Exploitation of Remote Services / T1059.001 - PowerShell'
                Detect = 'Alert on SMBv1 negotiation and on 400 (Engine v2.0) PowerShell engine-start events.'
            }

            # placeholder-terminator
        }
    }

    $entry = $script:TJETFindingMetadata[$FindingId]

    if ($null -eq $entry) {
        return [PSCustomObject]@{
            Attack_Technique   = 'Not mapped'
            MITRE_Technique    = 'Not mapped'
            Detection_Guidance = 'No detection guidance recorded for this finding ID.'
        }
    }

    return [PSCustomObject]@{
        Attack_Technique   = $entry.Attack
        MITRE_Technique    = $entry.Mitre
        Detection_Guidance = $entry.Detect
    }
}


# ==========================================================================
# SOURCE: Private\Get-TJETRemediation.ps1
# ==========================================================================
function Get-TJETRemediation {
<#
.SYNOPSIS
    Returns concrete, ordered remediation steps for a finding ID.
.DESCRIPTION
    The "how to fix it" half of the deliverable. Where Get-TJETFindingMetadata gives the
    attack and detection view, this gives the defender a numbered procedure -- specific
    cmdlets, GUI paths and operational cautions -- rather than a one-line "restrict this".

    Steps are written to be pasted into a change ticket. Where an action is destructive
    or has a common failure mode (rotating krbtgt, enabling SID filtering), the caution
    is part of the steps, not a footnote.

    Held as one table keyed by Finding_ID and applied at export, for the same reason as
    the ATT&CK metadata: single source of truth, no drift between detectors.
.PARAMETER FindingId
    The Finding_ID to look up.
.OUTPUTS
    [string] newline-joined numbered steps, or a safe placeholder for unknown IDs.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$FindingId
    )

    if ($null -eq $script:TJETRemediation) {

        $script:TJETRemediation = @{

            # ------------------------------------------------------------ Domain ---
            'DOM-001' = @(
                'Rotate the krbtgt password twice, allowing a full replication cycle (10+ hours) between rotations.'
                'Use the Microsoft New-KrbtgtKeys.ps1 script, or reset via Set-ADAccountPassword on the krbtgt account.'
                'CAUTION: rotating twice in quick succession invalidates all Kerberos tickets and causes a domain-wide outage. Wait for replication between resets.'
                'Schedule krbtgt rotation at least twice a year thereafter.'
            )
            'DOM-004' = @(
                'Confirm the trust genuinely requires SID history to function (rare outside an active migration).'
                'Enable SID filtering: netdom trust <TrustingDomain> /domain:<TrustedDomain> /quarantine:yes'
                'For a forest trust use /enablesidhistory:no instead of quarantine.'
                'TEST FIRST in a maintenance window: quarantine breaks access that legitimately depends on SIDHistory.'
            )
            'DOM-005' = @(
                'Set the machine account quota to zero: Set-ADDomain -Identity <domain> -Replace @{"ms-DS-MachineAccountQuota"=0}'
                'Delegate machine-join rights to a controlled group via the Delegation of Control wizard on the target OU.'
                'Audit existing computer accounts created by non-administrators (ms-DS-CreatorSID) for ones that should not exist.'
            )
            'DOM-006' = @(
                'Open Active Directory Administrative Center > Password Settings Container and edit the PSO.'
                'Raise MinPasswordLength and enable complexity to at least the domain default.'
                'If the PSO is scoped to privileged principals, either strengthen it or rescope it away from them.'
                'Verify precedence: a lower Precedence number wins where multiple PSOs apply.'
            )

            # ---------------------------------------------------------- Identity ---
            'ID-001' = @(
                'Identify the service behind the SPN and migrate it to a group managed service account (gMSA): New-ADServiceAccount, then Install-ADServiceAccount on the host.'
                'If a gMSA is not possible, set a 25+ character random password on the account.'
                'Remove the SPN if the account no longer runs a service: setspn -D <spn> <account>'
                'Set msDS-SupportedEncryptionTypes to AES-only to remove the RC4 crackable ticket.'
            )
            'ID-002' = @(
                'Review whether the account genuinely needs to delegate to its configured services.'
                'Prefer resource-based constrained delegation, set on the RESOURCE (Set-ADComputer -PrincipalsAllowedToDelegateToAccount), so control stays with the resource owner.'
                'Remove the delegation if unused: Set-ADUser <acct> -Clear "msDS-AllowedToDelegateTo"'
            )
            'ID-004' = @(
                'Remove unconstrained delegation: Set-ADAccountControl <acct> -TrustedForDelegation $false'
                'Replace with resource-based constrained delegation where delegation is genuinely required.'
                'Add sensitive/privileged accounts to the Protected Users group so their TGTs cannot be delegated.'
            )
            'ID-005' = @(
                'If a migration is complete, clear SIDHistory: use the ADMT cleanup, or Set-ADUser <acct> -Remove @{sIDHistory="<sid>"} (requires appropriate rights).'
                'If a Tier 0 SID appears with no migration to explain it, treat it as active compromise: preserve evidence and investigate before clearing.'
                'Enable auditing on writes to sIDHistory (event 5136) so future additions alert.'
            )
            'ID-006' = @(
                'Confirm the account is genuinely unused against non-replicated lastLogon on each DC, not just lastLogonTimestamp.'
                'Disable the account: Disable-ADAccount <acct>'
                'After a retention window with no impact, delete it.'
                'For service identities, migrate to a gMSA rather than leaving a dormant standing account.'
            )
            'ID-007' = @(
                'Remove the do-not-require-preauth flag: Set-ADAccountControl <acct> -DoesNotRequirePreAuth $false'
                'If a legacy application requires it, isolate the account and enforce a long random password.'
                'Monitor event 4768 for AS-REP requests against the account.'
            )
            'ID-008' = @(
                'Inspect msDS-KeyCredentialLink and confirm each entry maps to an expected Windows Hello or device registration.'
                'Remove unrecognised entries: Set-ADUser <acct> -Clear "msDS-KeyCredentialLink" (clears all -- re-add legitimate ones).'
                'On privileged accounts, treat an unexplained entry as compromise and investigate.'
            )
            'ID-009' = @(
                'Remove the never-expire flag: Set-ADUser <acct> -PasswordNeverExpires $false'
                'Reset the password to bring it under the current policy.'
                'For service accounts, migrate to a gMSA so rotation is automatic.'
            )
            'ID-010' = @(
                'Clear the password-not-required flag: Set-ADAccountControl <acct> -PasswordNotRequired $false'
                'Immediately set a compliant password.'
                'Review event 4624 logon history for the account -- prior use may indicate existing compromise.'
            )
            'ID-011' = @(
                'Create or assign a strong PSO to privileged accounts or their groups via the Password Settings Container.'
                'Set a MinPasswordLength meeting the privileged baseline (default 14; adjust in Config.ps1).'
                'Verify the PSO actually applies: Get-ADUserResultantPasswordPolicy <acct>'
            )

            # -------------------------------------------------- Infrastructure ---
            'INF-001' = @(
                'Remove unconstrained delegation from the host: Set-ADAccountControl <computer> -TrustedForDelegation $false'
                'Use resource-based constrained delegation where delegation is required.'
                'Add high-value accounts to Protected Users so their TGTs are never cached on the host.'
            )
            'INF-002' = @(
                'Confirm the RBCD configuration is intended: Get-ADComputer <host> -Properties PrincipalsAllowedToDelegateToAccount'
                'Remove it if unexpected: Set-ADComputer <host> -Clear "msDS-AllowedToActOnBehalfOfOtherIdentity"'
                'Treat unexplained RBCD as a compromise indicator and investigate who wrote the attribute (event 5136).'
            )
            'INF-003' = @(
                'Deploy Windows LAPS: Set-LapsADComputerSelfPermission and configure the LAPS policy via GPO or Intune.'
                'Confirm coverage: Get-LapsADPassword <computer> should return a managed password.'
                'Remove any standing local administrator accounts with shared passwords.'
            )
            'INF-004' = @(
                'Plan migration off the unsupported operating system.'
                'Where migration is not immediately possible, isolate the host at the network layer and disable legacy protocols (SMBv1, NTLMv1).'
                'Document the exception with an owner and a decommission date.'
            )
            'INF-005' = @(
                'Inspect msDS-KeyCredentialLink on the computer object and confirm the entry is an expected device registration.'
                'Remove unrecognised entries.'
                'On a domain controller, treat any unexpected entry as domain compromise until proven otherwise.'
            )

            # ------------------------------------------------------------ Policy ---
            'GPO-001' = @(
                'Open Group Policy Management > the GPO > Delegation tab.'
                'Remove edit rights from the broad principal; restrict to Domain Admins or a dedicated GPO-admin group.'
                'Audit the GPO version history for unexpected recent edits (event 5136 on the groupPolicyContainer).'
            )
            'GPO-002' = @(
                'Restore default permissions on the GPO SYSVOL folder: the policy folder under \\<domain>\SYSVOL\<domain>\Policies\{GUID}.'
                'Remove Modify/Write for principals outside the GPO administration group.'
                'Enable file-system auditing on the Policies folder to catch future changes (event 4663).'
            )
            'GPO-003' = @(
                'Open the GPO > Computer Configuration > Policies > Windows Settings > Security Settings > User Rights Assignment.'
                'Confirm each privileged right (SeDebugPrivilege, SeBackupPrivilege, etc.) is granted only to the intended administrative tier.'
                'Remove grants to broad or non-administrative principals.'
            )

            # --------------------------------------------------------- Privilege ---
            'GRP-001' = @(
                'Confirm the group is genuinely unused (no members, not referenced by policy or applications).'
                'Delete it: Remove-ADGroup <group>'
                'If it must remain, enable membership-change auditing (events 4728/4732/4756).'
            )
            'GRP-002' = @(
                'Assign an accountable owner: Set-ADGroup <group> -ManagedBy <owner>'
                'Include the group in the periodic privileged-access review.'
            )
            'GRP-003' = @(
                'Flatten the nesting so Tier 0 membership is explicit: remove the Tier 0 group from the outer group.'
                'Re-grant access directly where it was genuinely needed.'
                'Alert on future nesting changes (events 4728/4756 where the member added is a group).'
            )

            # ------------------------------------------------ Service accounts ---
            'GMSA-001' = @(
                'Restrict retrieval to the specific host group that runs the service: Set-ADServiceAccount <gmsa> -PrincipalsAllowedToRetrieveManagedPassword <hostgroup>'
                'Confirm the change: Get-ADServiceAccount <gmsa> -Properties PrincipalsAllowedToRetrieveManagedPassword'
                'Alert on event 4662 reads of msDS-ManagedPassword by principals outside that group.'
            )

            # ----------------------------------------------------- Attack path ---
            'PATH-001' = @(
                'Identify the delegated ACE: the trustee and right are in the finding evidence.'
                'Confirm no automation depends on it, then remove it via the object Security tab or dsacls.'
                'Audit how it was granted -- the same delegation pattern is usually present on other objects.'
            )
            'LOCAL-012' = @(
                'Identify the task: Get-ScheduledTask | Where-Object TaskName -eq <name> | Select-Object -ExpandProperty Actions'
                'Move the task binary into a directory only administrators can write to (%ProgramFiles% or %SystemRoot%).'
                'If the binary must stay put, correct the directory ACL: icacls <dir> /remove:g BUILTIN\Users Everyone'
                'Confirm the task still runs after the change, then re-run the assessment to verify the finding clears.'
            )

            'LOCAL-013' = @(
                'Identify who can write to the directory: icacls <dir>'
                'Remove write access for standard users: icacls <dir> /remove:g BUILTIN\Users Everyone Authenticated Users'
                'If the directory is in the system PATH and does not need to be, remove it from the PATH variable.'
                'Prefer fully qualified paths in service and task definitions so search order cannot be abused.'
            )

            'LOCAL-014' = @(
                'Review the file before deleting it - it shows which credentials were exposed and need rotating.'
                'Rotate every credential that appeared in the history.'
                'Clear the file: Remove-Item (Get-PSReadlineOption).HistorySavePath'
                'Reduce future exposure: Set-PSReadLineOption -HistorySaveStyle SaveNothing, or enforce it via profile policy.'
                'Teach the use of Get-Credential and SecureString instead of plaintext -Password arguments.'
            )

            'LOCAL-015' = @(
                'Read the file to identify the exposed account and password.'
                'Rotate that password everywhere it was used - answer-file passwords are usually the local administrator and usually reused across the image.'
                'Delete the file: Remove-Item <path> -Force'
                'Fix the imaging pipeline so answer files are removed at the end of deployment. This is an image defect, not a host defect, so every machine built from that image is affected.'
            )

            'LOCAL-016' = @(
                'Identify the credential and its scope in the cloud provider console.'
                'Revoke or rotate the key or token at the provider, not just on the host - deleting the file does not invalidate the credential.'
                'Remove the file if the workflow does not need it.'
                'Move to short-lived credentials: instance or managed identities, SSO, or federated tokens instead of long-lived key files.'
            )

            'LOCAL-017' = @(
                'Determine which hosts trust the key by checking authorized_keys on likely targets.'
                'Rotate the key pair and remove the old public key from every authorized_keys file that holds it.'
                'Protect new keys with a passphrase, or move to certificate-based SSH auth with short lifetimes.'
                'Restrict the .ssh directory ACL to the owning user only.'
            )

            'LOCAL-018' = @(
                'Review the saved sessions for stored passwords and note the hosts and usernames they disclose.'
                'Rotate any password stored by WinSCP - its storage is reversible obfuscation, so treat it as plaintext.'
                'Delete unneeded sessions from the registry key named in the finding.'
                'Configure the client not to save passwords, and prefer key-based authentication.'
            )

            'LOCAL-019' = @(
                'Read the value to identify the exposed credential, then rotate it.'
                'Remove the registry value: Remove-ItemProperty -Path <key> -Name <value>'
                'For autologon, also clear AutoAdminLogon and DefaultUserName, and remove the requirement for autologon if possible.'
                'For SNMP, replace community strings with SNMPv3 authentication or disable the service.'
            )

            'LOCAL-020' = @(
                'Treat this as a likely compromise, not a misconfiguration - this key has almost no legitimate use.'
                'Capture the debugger value for the investigation before removing it.'
                'Remove the Image File Execution Options key for the affected binary, including subkeys.'
                'Verify the on-disk accessibility binaries are the genuine Microsoft-signed files (sfc /scannow).'
                'Investigate how the key was written, and check every other host for the same key.'
            )

            'LOCAL-021' = @(
                'Reconfigure WSUS to use HTTPS and deploy the WSUS server certificate to clients.'
                'Set the WUServer and WUStatusServer policy values to the https URL.'
                'Enable SSL on the WSUS server itself (IIS binding plus WSUSUtil configuressl).'
                'Until fixed, treat any host on an untrusted network segment as exposed to update injection.'
            )

            'LOCAL-022' = @(
                'Enable NLA by setting UserAuthentication to 1 under the RDP-Tcp WinStation key.'
                'Enforce it by GPO: Computer Configuration > Administrative Templates > Windows Components > Remote Desktop Services > Require user authentication using NLA.'
                'Confirm legacy clients that cannot do NLA are upgraded or explicitly exempted.'
                'If RDP is not needed on this host, disable it entirely instead.'
            )

            'LOCAL-023' = @(
                'Re-enable real-time protection: Set-MpPreference -DisableRealtimeMonitoring 0'
                'Enable tamper protection via Intune or the Windows Security app so an administrator process cannot silently disable Defender again.'
                'Investigate WHY it was disabled - deliberate disabling is a standard post-compromise step and is rarely accidental.'
                'Enforce protection state by policy so a local change is reverted.'
            )

            'LOCAL-024' = @(
                'Re-enable the profile: Set-NetFirewallProfile -Profile <name> -Enabled True'
                'Enforce firewall state via GPO so local changes cannot disable it.'
                'Review the rules that were in place - a disabled profile sometimes hides a permissive rule set that also needs cleaning.'
                'Investigate the change: event 4950 records firewall setting modifications.'
            )

            'LOCAL-025' = @(
                'If the host does not print, disable the service: Stop-Service Spooler then Set-Service Spooler -StartupType Disabled'
                'On domain controllers, disabling the spooler is a standard hardening step and also removes a coercion primitive.'
                'If the spooler is required, ensure the host is fully patched for PrintNightmare-class issues and restrict Point and Print via policy.'
                'Set RestrictDriverInstallationToAdministrators to 1.'
            )

            'LOCAL-026' = @(
                'Review both share and NTFS permissions: Get-SmbShareAccess -Name <share>'
                'Remove Everyone and Authenticated Users from share permissions where present.'
                'Apply least privilege at the NTFS layer as well - share permissions alone are not sufficient.'
                'Remove the share entirely if it is no longer used.'
            )

            'LOCAL-027' = @(
                'Confirm whether the account genuinely requires local administrator rights.'
                'Remove it if not: Remove-LocalGroupMember -Group Administrators -Member <name>'
                'Where local admin is required for a role, manage it centrally via a group and LAPS rather than per-host additions.'
                'Baseline the expected membership and alert on event 4732 additions.'
            )

            'PORT-001' = @(
                'Confirm the service on this port is required on this host.'
                'If it is not needed, disable the owning service or stop the process bound to the port.'
                'If it is needed, restrict it with the Windows Firewall to only the source networks that require it.'
                'Require encrypted, authenticated access - replace Telnet with SSH, FTP with SFTP/FTPS, LDAP with LDAPS.'
                'For SMB/RDP/WinRM, ensure signing/NLA/HTTPS are enforced and the service is not reachable from untrusted networks.'
            )

            'PATCH-001' = @(
                'Apply all outstanding operating-system and security updates.'
                'Confirm the host is pointed at a working WSUS server or Windows Update and is checking in.'
                'Investigate why it fell behind - a host that stopped patching often stopped reporting too.'
                'Establish a monthly patch cycle and monitor patch age centrally rather than per host.'
            )

            'CRED-002' = @(
                'Open the file and identify the exposed credential (the finding gives the file and line, not the value).'
                'Rotate the exposed credential before removing it - deleting the file does not invalidate a known secret.'
                'Remove the secret from the file, and from source control if the file is tracked.'
                'Move the secret into a vault or use a managed identity, and reference it at runtime instead of storing it.'
                'Search the rest of the estate for the same value - credentials in files are usually reused.'
            )

            'CVE-001' = @(
                'Validate that this host is genuinely affected: confirm the vulnerable component is installed and the affected code path is actually in use.'
                'Check the specific CVE for a fixed version or vendor mitigation.'
                'Patch or upgrade the product above the affected version range.'
                'Where an immediate patch is not possible, apply the vendor''s documented mitigation and restrict access to the affected service.'
                'Re-run the scan after patching to confirm the match clears.'
            )

            'PROC-001' = @(
                'Identify the process and its parent: the finding gives the PID, path, command line and owner.'
                'Confirm whether the binary is legitimate - a signed vendor binary from Program Files is expected; an unsigned binary from a user-writable path is not.'
                'If malicious, isolate the host, capture the binary and command line for analysis, and terminate the process.'
                'If legitimate but poorly located, move it to a protected directory and restrict write access to that directory.'
                'Add application control (WDAC or AppLocker) to block execution from user-writable paths.'
            )

            'ADCS-001' = @(
                'Confirm the template is ESC1: enrollee supplies subject, a client-auth (or Any-Purpose) EKU, no manager approval, no RA signature, and low-privileged enrollment.'
                'Fix ANY one precondition to break the chain -- the strongest is removing ENROLLEE_SUPPLIES_SUBJECT (clear the CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT bit in msPKI-Certificate-Name-Flag).'
                'Alternatively require manager approval (set PEND_ALL_REQUESTS) or require an authorized signature (msPKI-RA-Signature >= 1).'
                'Restrict enrollment: remove Domain Users / Authenticated Users / Everyone from the template''s enrollment ACL and grant only the group that needs it.'
                'If the template is unused, unpublish it from every CA (remove it from the CA''s certificateTemplates) and consider deleting it.'
                'After remediation, re-run the assessment to confirm the finding clears.'
            )

            'ADCS-002' = @(
                'Constrain the template''s EKUs to the minimum required rather than leaving it Any-Purpose / no-EKU.'
                'Require manager approval or restrict enrollment to a trusted group.'
                'Unpublish the template if it is not needed.'
                'Re-run the assessment to verify.'
            )

            'ADCS-003' = @(
                'Restrict the Enrollment Agent template''s enrollment to a small, trusted administrative group.'
                'Enable enrollment-agent restrictions on the CA so agents can only enrol for specific templates and principals.'
                'Monitor for on-behalf-of enrolment.'
                'Unpublish if unused.'
            )

            'ADCS-004' = @(
                'Restrict write and full-control on the template to administrators only: remove any low-privileged principals from the DACL.'
                'Review and correct the template''s owner if it is not an administrative principal.'
                'Audit recent modifications to the template object (event 5136) for signs it was already tampered with.'
                'Re-run the assessment to confirm the write access is gone.'
            )

            'ADCS-005' = @(
                'On the CA host, check ESC6: certutil -getreg policy\EditFlags -- ensure EDITF_ATTRIBUTESUBJECTALTNAME is NOT set. If it is, remove it and restart certsvc.'
                'For ESC8, disable HTTP web enrollment, or enforce HTTPS and Extended Protection for Authentication on the certsrv endpoint.'
                'Enable the CA''s request auditing so certificate abuse is detectable.'
                'Run a dedicated ADCS audit tool (Certify/Certipy ''find'', or PSPKI) on the CA for the full on-box picture the directory cannot show.'
            )

            'ADCS-006' = @(
                'Review which principals can enrol for this authentication-capable template.'
                'Remove broad groups (Domain Users, Authenticated Users) from the enrollment ACL and grant only the intended group.'
                'Unpublish the template if it is unused.'
            )

            'CRED-001' = @(
                'Identify the exposed value: open the object in ADSI Edit or run Get-ADObject -Identity <DN> -Properties <attribute>.'
                'Treat the credential as compromised. Every authenticated user in the domain could read it, and that read leaves no distinctive audit trail.'
                'Rotate the credential FIRST, before clearing the attribute -- clearing it does not invalidate a password that is already known.'
                'Clear the attribute: Set-ADObject -Identity <DN> -Clear <attribute>'
                'If the value was in userPassword or unixUserPassword, confirm the account is not also using that password interactively.'
                'Search the rest of the directory for the same value pattern: the same password is usually parked in several places.'
                'Add a recurring check for credential patterns in description/info/comment fields so this does not silently return.'
            )

            'LOCAL-000' = @(
                'No remediation required - this finding records the context the assessment ran in.'
                'To enumerate privilege-escalation routes available to a standard user, re-run the assessment from a non-administrative account on the same host.'
            )

            'PATH-002' = @(
                'Clean AdminSDHolder FIRST: CN=AdminSDHolder,CN=System,<domain> -- remove the rogue ACE via the Security tab or dsacls.'
                'Then remove the copies SDProp stamped onto protected objects. Removing only the copies is futile -- SDProp restores them within the hour.'
                'Force an SDProp run to re-stamp the corrected ACL, or wait for the hourly cycle.'
                'Enable auditing on AdminSDHolder (event 5136) -- legitimate changes are extremely rare.'
            )
            'PATH-003' = @(
                'Treat as PATH-002: the uniform right across protected objects indicates AdminSDHolder propagation.'
                'Remediate at AdminSDHolder, not per object.'
                'Baseline the ACL of adminCount=1 objects and diff periodically -- they should be uniform and known-good.'
            )
            'PATH-GRAPH' = @(
                'Read the chain in the finding evidence from left (compromised principal) to right (Tier 0).'
                'Fix the weakest single hop rather than the endpoint: usually one delegated right or one group nesting mid-chain breaks the whole path.'
                'Re-run the assessment and confirm the path no longer appears.'
                'Re-run the assessment after remediation and confirm the path no longer appears in Attack_Paths.csv.'
            )

            # -------------------------------------------- Local privilege esc ---
            'LOCAL-001' = @(
                'Quote the service binary path: sc config <service> binPath= "\"C:\Path With Spaces\svc.exe\""'
                'Or move the binary to a path with no spaces.'
                'Verify no writable directory sits at an earlier path segment.'
            )
            'LOCAL-002' = @(
                'Correct the permissions on the service binary directory so non-administrators cannot write to it (remove Users/Authenticated Users Modify).'
                'Confirm the service account is least-privilege.'
                'Re-check with icacls on the binary and its parent directory.'
            )
            'LOCAL-003' = @(
                'Disable AlwaysInstallElevated in both hives: set the policy to Disabled under Computer and User Configuration > Administrative Templates > Windows Components > Windows Installer.'
                'Or delete the AlwaysInstallElevated value under HKLM and HKCU \SOFTWARE\Policies\Microsoft\Windows\Installer.'
                'This is a direct local-to-SYSTEM escalation -- prioritise it.'
            )
            'LOCAL-004' = @(
                'Remove the writable directory from the system %PATH%, or correct its permissions so standard users cannot write to it.'
                'Check for planted binaries or DLLs already present in the directory.'
            )
            'LOCAL-005' = @(
                'Correct permissions on the autorun target so it cannot be replaced by a non-administrator.'
                'Verify the autorun entry itself is expected; remove it if not.'
            )
            'LOCAL-006' = @(
                'Remove the credential-bearing file (unattend.xml, Groups.xml) from disk once provisioning is complete.'
                'Rotate any password that was stored in it -- assume it is compromised.'
                'For registry autologon, remove DefaultPassword and use a different logon mechanism.'
            )
            'LOCAL-007' = @(
                'Review why the current context holds this privilege; remove it if not required (User Rights Assignment via GPO or secpol.msc).'
                'For service accounts with SeImpersonate, ensure the service is patched against potato-family attacks and least-privilege.'
                'Add high-value interactive accounts to Protected Users.'
            )
            'LOCAL-008' = @(
                'Re-enable UAC: set EnableLUA=1 and FilterAdministratorToken=1 under HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System, then reboot.'
                'Enforce via GPO so the setting cannot drift.'
            )
            'LOCAL-009' = @(
                'Disable WDigest cleartext: set UseLogonCredential=0 under HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest.'
                'Enable LSA protection: set RunAsPPL=1 under HKLM\SYSTEM\CurrentControlSet\Control\Lsa, then reboot.'
                'Where hardware supports it, enable Credential Guard via GPO.'
            )
            'LOCAL-010' = @(
                'Require SMB signing: set RequireSecuritySignature=1 on LanmanServer (and the client) via GPO.'
                'Verify with Get-SmbServerConfiguration | Select RequireSecuritySignature.'
            )
            'LOCAL-011' = @(
                'Disable SMBv1: Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol'
                'Disable the PowerShell v2 engine: Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2'
                'Enforce both via GPO or Intune across the estate.'
            )
        }
    }

    $steps = $script:TJETRemediation[$FindingId]

    if ($null -eq $steps) {
        return 'No remediation steps recorded for this finding ID.'
    }

    $numbered = for ($i = 0; $i -lt $steps.Count; $i++) {
        "$($i + 1). $($steps[$i])"
    }

    return ($numbered -join ' | ')
}


# ==========================================================================
# SOURCE: Private\Get-TJETRightsClassification.ps1
# ==========================================================================
function Test-TJETInfrastructureTrustee {
<#
.SYNOPSIS
    True if a trustee is an infrastructure principal that should never be reported.
.DESCRIPTION
    SYSTEM and SELF hold broad rights on virtually every AD object by design. Reporting
    them is equivalent to reporting that Active Directory exists -- they accounted for
    45 of 75 PATH-001 findings in a real lab run.

    NOTE what is deliberately NOT excluded: Everyone, Authenticated Users, Domain Users
    and Domain Computers. Those hold BENIGN default rights (see
    Test-TJETDangerousRight) but a GenericAll or WriteDacl held by them is a genuine
    critical finding. They are filtered by RIGHT, not by identity.
#>
    [CmdletBinding()]
    param(
        [string]$TrusteeSid,
        [string]$TrusteeName
    )

    # S-1-5-18 Local System, S-1-5-10 Principal Self, S-1-3-0 Creator Owner,
    # S-1-5-9 Enterprise Domain Controllers, S-1-5-19/20 Local & Network Service.
    $infrastructureSids = @(
        'S-1-5-18'
        'S-1-5-10'
        'S-1-3-0'
        'S-1-5-9'
        'S-1-5-19'
        'S-1-5-20'
    )

    if ($TrusteeSid -and $infrastructureSids -contains $TrusteeSid) {
        return $true
    }

    # Fallback when the SID could not be resolved.
    if ($TrusteeName -match '(?i)\\(SYSTEM|SELF|CREATOR OWNER|ENTERPRISE DOMAIN CONTROLLERS|LOCAL SERVICE|NETWORK SERVICE)$') {
        return $true
    }

    if ($TrusteeName -match '(?i)^(NT AUTHORITY\\SYSTEM|NT AUTHORITY\\SELF|CREATOR OWNER)$') {
        return $true
    }

    return $false
}


function Test-TJETDangerousRight {
<#
.SYNOPSIS
    Classifies an ACE as a genuine escalation right or an AD default.
.DESCRIPTION
    An ACE is only meaningful in combination with its ObjectType GUID. Without that,
    the default "Change Password" right granted to Everyone on every user object is
    indistinguishable from DS-Replication-Get-Changes-All -- the DCSync right.

    Returns an object: IsDangerous, RightName, Reason.
.PARAMETER Rights
    The ActiveDirectoryRights string from the ACE.
.PARAMETER ObjectType
    The ObjectType GUID from the ACE. All-zeros means "applies to all", which for an
    ExtendedRight means ALL extended rights and is therefore dangerous.
#>
    [CmdletBinding()]
    param(
        [string]$Rights,
        [string]$ObjectType
    )

    $result = [PSCustomObject]@{
        IsDangerous = $false
        RightName   = ''
        Reason      = ''
    }

    if ([string]::IsNullOrWhiteSpace($Rights)) { return $result }

    $allObjects = '00000000-0000-0000-0000-000000000000'

    $guid = "$ObjectType".Trim().Trim('{','}').ToLower()

    # Full-control style rights are dangerous regardless of ObjectType.
    if ($Rights -match '(?i)GenericAll') {
        $result.IsDangerous = $true
        $result.RightName   = 'GenericAll'
        $result.Reason      = 'Full control over the object.'
        return $result
    }

    foreach ($pair in @(
            @{ Pattern = 'WriteDacl';    Name = 'WriteDacl';    Reason = 'Can rewrite the ACL and grant itself full control.' }
            @{ Pattern = 'WriteOwner';   Name = 'WriteOwner';   Reason = 'Can take ownership and then rewrite the ACL.' }
            @{ Pattern = 'GenericWrite'; Name = 'GenericWrite'; Reason = 'Can write object attributes, including membership and SPNs.' }
        )) {

        if ($Rights -match "(?i)$($pair.Pattern)") {
            $result.IsDangerous = $true
            $result.RightName   = $pair.Name
            $result.Reason      = $pair.Reason
            return $result
        }
    }

    # Extended rights are only dangerous for specific control-access GUIDs.
    $dangerousExtended = @{
        $allObjects                             = 'All extended rights'
        '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'  = 'DS-Replication-Get-Changes'
        '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'  = 'DS-Replication-Get-Changes-All (DCSync)'
        '89e95b76-444d-4c62-991a-0facbeda640c'  = 'DS-Replication-Get-Changes-In-Filtered-Set'
        '00299570-246d-11d0-a768-00aa006e0529'  = 'User-Force-Change-Password (password reset)'
        '45ec5156-db7e-47bb-b53f-dbeb2d03c40f'  = 'Reanimate-Tombstones'
        'bf9679c0-0de6-11d0-a285-00aa003049e2'  = 'Self-Membership (add self to group)'
    }

    if ($Rights -match '(?i)ExtendedRight') {

        if ($dangerousExtended.ContainsKey($guid)) {
            $result.IsDangerous = $true
            $result.RightName   = $dangerousExtended[$guid]
            $result.Reason      = "Control-access right: $($dangerousExtended[$guid])."
            return $result
        }

        # ab721a53-... is Change Password, granted to Everyone and Self by default.
        return $result
    }

    # WriteProperty is dangerous only against sensitive attributes, or against all.
    $sensitiveProperties = @{
        $allObjects                            = 'all properties'
        'bf9679c0-0de6-11d0-a285-00aa003049e2' = 'member (group membership)'
        'f3a64788-5306-11d1-a9c5-0000f80367c1' = 'servicePrincipalName'
        '5b47d60f-6090-40b2-9f37-2a4de88f3063' = 'msDS-KeyCredentialLink (shadow credentials)'
        '3f78c3e5-f79a-46bd-a0b8-9d18116ddc79' = 'msDS-AllowedToActOnBehalfOfOtherIdentity (RBCD)'
    }

    if ($Rights -match '(?i)WriteProperty' -and $sensitiveProperties.ContainsKey($guid)) {
        $result.IsDangerous = $true
        $result.RightName   = "WriteProperty on $($sensitiveProperties[$guid])"
        $result.Reason      = "Can modify $($sensitiveProperties[$guid])."
        return $result
    }

    return $result
}


# ==========================================================================
# SOURCE: Private\Get-TJETSchemaAttribute.ps1
# ==========================================================================
function Test-TJETSchemaAttribute {
<#
.SYNOPSIS
    Returns $true if an attribute exists in the current AD schema.
.DESCRIPTION
    Get-AD* throws "One or more properties are invalid" when asked for an attribute
    the schema does not contain, which aborts the whole collector. Several attributes
    this framework wants are schema-extension dependent and absent by default:

        ms-Mcs-AdmPwdExpirationTime      legacy Microsoft LAPS (schema extension)
        msLAPS-PasswordExpirationTime    Windows LAPS (Server 2019+ / patched)
        msDS-KeyCredentialLink           Server 2016+ forest schema

    Probing the schema once is far cheaper than losing an entire collector.

    Results are cached per session because the schema does not change mid-run.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Name
    )

    if ($null -eq $script:TJETSchemaCache) {
        $script:TJETSchemaCache = @{}
    }

    if ($script:TJETSchemaCache.ContainsKey($Name)) {
        return $script:TJETSchemaCache[$Name]
    }

    $exists = $false

    try {
        $schemaPath = (Get-ADRootDSE -ErrorAction Stop).schemaNamingContext

        $found = Get-ADObject -SearchBase $schemaPath `
            -LDAPFilter "(lDAPDisplayName=$Name)" `
            -ErrorAction Stop

        $exists = [bool]$found
    }
    catch {
        Write-Verbose "Schema probe failed for ${Name}: $($_.Exception.Message)"
        $exists = $false
    }

    $script:TJETSchemaCache[$Name] = $exists

    if (-not $exists) {
        Write-Verbose "Attribute '$Name' is not present in this schema; it will be skipped."
    }

    return $exists
}


function Get-TJETOptionalAttribute {
<#
.SYNOPSIS
    Filters a candidate attribute list down to those the schema actually contains.
.EXAMPLE
    $laps = Get-TJETOptionalAttribute 'ms-Mcs-AdmPwdExpirationTime','msLAPS-PasswordExpirationTime'
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string[]]$Name
    )

    $present = New-Object System.Collections.Generic.List[string]

    foreach ($attribute in $Name) {
        if (Test-TJETSchemaAttribute -Name $attribute) {
            $present.Add($attribute)
        }
    }

    return $present.ToArray()
}


# ==========================================================================
# SOURCE: Private\Helpers.ps1
# ==========================================================================
function ConvertTo-Bool {

    param(
        $Value
    )


    if ($null -eq $Value) {
        return $false
    }


    if ($Value -is [bool]) {
        return $Value
    }


    switch -Regex (
        $Value.ToString()
    ) {

        "^(true|1|yes)$" {
            return $true
        }

        default {
            return $false
        }

    }

}

function ConvertTo-Int {

    param(
        $Value,

        [int]
        $Default = 0
    )


    if ([string]::IsNullOrWhiteSpace(
        $Value
    )) {

        return $Default

    }


    try {

        return [int]$Value

    }

    catch {

        return $Default

    }

}

function Convert-ADObjectToAuditRecord {
<#
.SYNOPSIS
    Flattens an AD object into an ordered hashtable holding EVERY attribute.
.DESCRIPTION
    Collectors now request -Properties *, because operationally useful secrets turn up
    in unexpected places: plaintext passwords in description, info, comment or custom
    schema extensions; connection strings in notes fields. Curating the attribute list
    would discard exactly the data worth finding.

    Delegates the actual flattening to ConvertTo-InventoryRecord so the assessment CSVs
    and the inventory CSVs use identical rules -- arrays joined with " | " plus a
    _Count column, ISO 8601 dates, base64 for small binaries, size markers for large
    ones, and strings never enumerated into characters.

    Returns an ORDERED HASHTABLE (not a PSCustomObject) because collectors add derived
    fields with $record['Name'] = value after calling this.
#>
    param(
        [Parameter(Mandatory)]
        $Object
    )

    $flat = ConvertTo-InventoryRecord -Object $Object

    $record = [ordered]@{}

    foreach ($property in $flat.PSObject.Properties) {

        # Operational noise from the AD cmdlets' change-tracking, not directory data.
        if ($property.Name -match '^(PropertyNames|AddedProperties|RemovedProperties|ModifiedProperties|PropertyCount)$') {
            continue
        }

        $record[$property.Name] = $property.Value
    }

    return $record
}

# ==========================================================================
# SOURCE: Private\Import-AssessmentData.ps1
# ==========================================================================
function Import-AssessmentData {
<#
.SYNOPSIS
    Loads exported audit CSVs into a single data object.
.DESCRIPTION
    Each source is optional. A missing or empty file degrades only the detectors that
    depend on it; it never fails the run silently.

    Deliberately written without nested helper functions, conditional expressions near
    the object literal, or comments inside the literal. An earlier revision used all
    three and the Domain property came back null while every other property loaded --
    so this favours boring, explicit code over clever code.

    Row counts are logged at INFO so a run's output shows exactly what was loaded.
    "Domain=0" in that line is the signature of a missing or header-only manifest.
.OUTPUTS
    PSCustomObject with one property per source. Domain is a single row (or $null);
    all others are arrays.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    $sources = [ordered]@{
        Users           = 'AD_Users_Audit.csv'
        Computers       = 'AD_Computers_Audit.csv'
        Groups          = 'AD_Groups_Audit.csv'
        ACLs            = 'AD_ACL_Audit.csv'
        ServiceAccounts = 'AD_ServiceAccounts_Audit.csv'
        FGPP            = 'AD_FGPP_Audit.csv'
        GPOs            = 'AD_GPO_Audit.csv'
        Trusts          = 'AD_Trusts_Audit.csv'
        ADCS            = 'AD_ADCS_Audit.csv'
        LocalHost       = 'AD_LocalHost_Audit.csv'
        DomainRows      = 'AD_Domain_Summary.csv'
    }

    $loaded  = @{}
    $counts  = New-Object System.Collections.Generic.List[string]

    foreach ($key in $sources.Keys) {

        $file = $sources[$key]
        $full = Join-Path $Path $file
        $rows = @()

        if (Test-Path $full) {

            try {
                $rows = @(Import-Csv -Path $full -ErrorAction Stop)
            }
            catch {
                Write-TJETLog ERROR "Failed to read ${file}: $($_.Exception.Message)"
                $rows = @()
            }
        }
        else {
            Write-TJETLog WARNING "$key source not found: $file (dependent detectors will be skipped)"
        }

        $loaded[$key] = $rows
        $counts.Add("$key=$($rows.Count)")
    }

    Write-TJETLog INFO ("Loaded: " + ($counts -join ', '))

    $domainRow = $null

    if ($loaded['DomainRows'].Count -gt 0) {
        $domainRow = $loaded['DomainRows'][0]
    }
    else {
        Write-TJETLog WARNING 'AD_Domain_Summary.csv produced no rows. DOM-001, DOM-005 and ID-011 cannot fire.'
    }

    $result = [PSCustomObject]@{
        Users           = $loaded['Users']
        Computers       = $loaded['Computers']
        Groups          = $loaded['Groups']
        ACLs            = $loaded['ACLs']
        ServiceAccounts = $loaded['ServiceAccounts']
        FGPP            = $loaded['FGPP']
        GPOs            = $loaded['GPOs']
        Trusts          = $loaded['Trusts']
        ADCS            = $loaded['ADCS']
        LocalHost       = $loaded['LocalHost']
        Domain          = $domainRow
    }

    return $result
}


# ==========================================================================
# SOURCE: Private\Logging.ps1
# ==========================================================================
function Write-TJETLog {

    [CmdletBinding()]

    param(
        [ValidateSet(
            "INFO",
            "WARNING",
            "ERROR"
        )]
        [string]
        $Level = "INFO",

        [Parameter(Mandatory)]
        [string]
        $Message
    )


    $timestamp =
        Get-Date -Format "yyyy-MM-dd HH:mm:ss"


    switch ($Level) {

        "INFO" {

            Write-Host `
                "[$timestamp] [INFO] $Message" `
                -ForegroundColor Green

        }


        "WARNING" {

            Write-Warning `
                "[$timestamp] $Message"

        }


        "ERROR" {

            Write-Error `
                "[$timestamp] $Message"

        }

    }

}

# ==========================================================================
# SOURCE: Private\New-TJETContext.ps1
# ==========================================================================
function New-TJETContext {
<#
.SYNOPSIS
    Builds the correlation context: privileged SID and GUID indexes.
.DESCRIPTION
    [FIX] Uses ConvertTo-Bool rather than -eq "True" string comparison, so the
    privilege model does not silently empty itself if the CSV serialization changes.

    [FIX] Reads ObjectSID with a fallback to SID. The collectors emit both (SID is a
    passthrough of the raw AD attribute; ObjectSID is the explicit normalized string),
    and detectors key on ObjectSID.

    [FIX] Accounts flagged by AdminCount are now included in the privileged set.
    Previously only Potentially_Privileged_Direct counted, so an account whose group
    membership had been removed but which still carried adminCount=1 -- a classic
    residual-privilege case -- was invisible to every privileged-only detector.

    Maintaining BOTH a SID index and a GUID index is deliberate: ACL findings look up
    targets by ObjectGUID and trustees by SID. Keying one map by both is the defect
    that made PATH-002 dead code in an earlier revision.
#>
    param(
        $Data,
        [string]$OutputPath
    )

    $privSIDs  = @{}
    $privGUIDs = @{}

    function Add-Principal {
        param($Object)

        $sid = if ($Object.ObjectSID) { $Object.ObjectSID } else { $Object.SID }

        if ($sid)               { $privSIDs[$sid] = $true }
        if ($Object.ObjectGUID) { $privGUIDs[$Object.ObjectGUID] = $true }
    }

    foreach ($user in $Data.Users) {
        if ((ConvertTo-Bool $user.Potentially_Privileged_Direct) -or
            (ConvertTo-Bool $user.Has_AdminCount)) {
            Add-Principal $user
        }
    }

    foreach ($group in $Data.Groups) {
        if (ConvertTo-Bool $group.Is_Tier0) {
            Add-Principal $group
        }
    }

    $context = [PSCustomObject]@{
        Data            = $Data
        PrivilegedSIDs  = $privSIDs
        PrivilegedGUIDs = $privGUIDs
        OutputPath      = $OutputPath
    }

    # [FIX] PowerShell 5.1 throws "Index operation failed; the array index evaluated
    # to null" when a hashtable is indexed with $null. Real directory data routinely
    # yields a null SID or GUID (an unresolvable trustee, a missing column), which
    # previously aborted an entire detector mid-run. These methods make the lookup
    # null-safe so one bad row degrades one finding, not the whole detector.
    $context | Add-Member -MemberType ScriptMethod -Name IsPrivilegedSid -Value {
        param($Sid)
        if ([string]::IsNullOrWhiteSpace($Sid)) { return $false }

        # Collected Tier 0 groups/users (this domain).
        if ($this.PrivilegedSIDs[$Sid]) { return $true }

        # Well-known privileged SIDs by RID, regardless of whether the object was
        # collected. This is what catches forest-root groups (Enterprise Admins 519,
        # Schema Admins 518) that do not exist in a child domain's own group set but
        # still appear as trustees on its objects, plus the built-in Administrators
        # namespace. Test-Tier0Sid is the single source of truth for the RID set.
        if (Test-Tier0Sid $Sid) { return $true }

        # Built-in Administrators and Enterprise/Domain admins also surface as the
        # S-1-5-32-544 built-in and the forest-root 519/518; Test-Tier0Sid already
        # covers 544 and the domain-relative RIDs. Nothing more needed here.
        return $false
    }

    $context | Add-Member -MemberType ScriptMethod -Name IsPrivilegedGuid -Value {
        param($Guid)
        if ([string]::IsNullOrWhiteSpace($Guid)) { return $false }
        return [bool]$this.PrivilegedGUIDs[$Guid]
    }

    return $context
}


# ==========================================================================
# SOURCE: Private\PrincipalResolver.ps1
# ==========================================================================
function Resolve-PrincipalRiskContext {

    param(

        [string]
        $PrincipalName,


        [array]
        $Groups

    )


    $result =
    [PSCustomObject]@{

        Name =
            $PrincipalName


        SID =
            $null


        IsTier0 =
            $false


        Resolution =
            "Unknown"

    }



    if(
        [string]::IsNullOrWhiteSpace(
            $PrincipalName
        )
    ){

        return $result

    }



    $group =
        $Groups |
        Where-Object {

            $_.Name -eq $PrincipalName

        }



    if($group){

        $result.SID =
            $group.SID


        $result.IsTier0 =
            Test-Tier0Sid `
                $group.SID


        $result.Resolution =
            "SID"


        return $result

    }



    # fallback

    if(
        $PrincipalName -match
        "(Domain Admins|Enterprise Admins|Schema Admins|Administrators)"
    ){

        $result.IsTier0 =
            $true


        $result.Resolution =
            "NameHeuristic"

    }



    return $result

}

# ==========================================================================
# SOURCE: Private\Test-TJETPrerequisite.ps1
# ==========================================================================
function Test-TJETPrerequisite {
<#
.SYNOPSIS
    Verifies the environment can run a given stage, with actionable messages.
.DESCRIPTION
    Collection needs RSAT and a reachable domain. Correlation and reporting need
    neither -- they work offline from exported CSVs. Checking up front produces one
    clear message instead of a cascade of per-collector failures.
#>
    [CmdletBinding()]
    param(
        [ValidateSet('Collection', 'Offline')]
        [string]$Stage = 'Collection'
    )

    if ($Stage -eq 'Offline') { return $true }

    $ok = $true

    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        Write-TJETLog ERROR ('ActiveDirectory module not found. Install RSAT: ' +
            'Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0')
        $ok = $false
    }

    if (-not (Get-Module -ListAvailable -Name GroupPolicy)) {
        Write-TJETLog WARNING ('GroupPolicy module not found. GPO collection will be skipped. ' +
            'Install RSAT: Add-WindowsCapability -Online -Name Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0')
    }

    if ($ok) {
        try {
            Import-Module ActiveDirectory -ErrorAction Stop
            Get-ADDomain -ErrorAction Stop | Out-Null
        }
        catch {
            Write-TJETLog ERROR ("Cannot contact a domain controller: $($_.Exception.Message). " +
                'Run from a domain-joined machine with an account that has directory read access.')
            $ok = $false
        }
    }

    return $ok
}


# ==========================================================================
# SOURCE: Private\Tier0.ps1
# ==========================================================================
function Test-Tier0Sid {
<#
.SYNOPSIS
    Namespace-aware Tier 0 test for a single SID.
.DESCRIPTION
    Built-in groups use the CONSTANT S-1-5-32-* namespace; everything else is
    domain-relative S-1-5-21-<domain>-*. Matching a bare RID suffix such as
    '-(512|544)$' conflates the two and will false-positive on a domain SID whose
    RID happens to end in a well-known number.

    [FIX] Restored RIDs 502 (krbtgt) and 517 (Cert Publishers), and built-in 552
    (Replicator), which were dropped in this revision.
#>
    param(
        [string]$SID
    )

    if ([string]::IsNullOrWhiteSpace($SID)) { return $false }

    # Built-in domain (constant SIDs):
    # 544 Administrators, 548 Account Operators, 549 Server Operators,
    # 550 Print Operators, 551 Backup Operators, 552 Replicator
    if ($SID -match '^S-1-5-32-(\d+)$') {
        return ([int]$Matches[1] -in 544, 548, 549, 550, 551, 552)
    }

    # Domain-relative well-known RIDs:
    # 500 Administrator, 502 krbtgt, 512 Domain Admins, 516 Domain Controllers,
    # 517 Cert Publishers, 518 Schema Admins, 519 Enterprise Admins
    if ($SID -match '^S-1-5-21-.+-(\d+)$') {
        return ([int]$Matches[1] -in 500, 502, 512, 516, 517, 518, 519)
    }

    return $false
}

function Get-PrivilegedSidFromHistory {
<#
.SYNOPSIS
    Returns the first Tier 0 SID found in a SIDHistory value list, else $null.
.DESCRIPTION
    SIDHistory is multi-valued and serializes as a delimited string. This splits into
    WHOLE SIDs and tests each with Test-Tier0Sid, rather than running a RID-substring
    regex over the joined string (which would both false-positive and re-conflate the
    built-in and domain-relative namespaces).

    Test-Tier0Sid stays the single source of truth for what "Tier 0" means.
#>
    param(
        [string]$SidHistoryValues
    )

    if ([string]::IsNullOrWhiteSpace($SidHistoryValues)) { return $null }

    foreach ($sid in ($SidHistoryValues -split '[;,]\s*')) {

        $candidate = $sid.Trim()

        if ($candidate -and (Test-Tier0Sid $candidate)) { return $candidate }
    }

    return $null
}


# ==========================================================================
# SOURCE: Collectors\Collect-ACLs.ps1
# ==========================================================================
function Collect-ACLs {
<#
.SYNOPSIS
    Collects dangerous ACEs from AD objects -- via ADSI, no RSAT.
.DESCRIPTION
    [ADSI REWRITE] Replaces Get-Acl "AD:\<DN>" (which needs the AD: PSDrive from the
    ActiveDirectory module) with DirectoryEntry.ObjectSecurity, reading the
    nTSecurityDescriptor directly over LDAP. This is the highest-stakes conversion
    because PATH-001/002/003 depend on it, so the field contract is preserved EXACTLY:
        ObjectName, ObjectGUID, DistinguishedName, ObjectClass, ObjectOwner,
        Trustee, TrusteeSID, Rights, AccessType, IsInherited, ObjectType, InheritanceType

    The rule objects returned by GetAccessRules([SecurityIdentifier]) are
    ActiveDirectoryAccessRule instances -- the SAME type Get-Acl produced -- so
    .ActiveDirectoryRights, .ObjectType, .AccessControlType, .IsInherited and
    .InheritanceType all carry identical values. The only change is how we obtain them.

    Requesting the identity reference directly as a SID (via GetAccessRules with the
    SecurityIdentifier type) avoids the per-ACE .Translate() round trip the AD-module
    version needed, and guarantees TrusteeSID is always a real SID for the Tier 0 match.

    Deny ACEs are collected deliberately (AccessType preserved); correlation decides
    actionability.
.PARAMETER Mode
    Targeted (default) scans OUs, the domain head, adminCount=1 objects and AdminSDHolder.
    Full scans every object and is very slow on real estates.
#>
    [CmdletBinding()]
    param(
        [ValidateSet('Targeted', 'Full')]
        [string]$Mode = 'Targeted',

        [string]$Server,
        [System.Management.Automation.PSCredential]$Credential
    )

    $ctx = Get-TJETDirectoryContext -Server:$Server -Credential:$Credential

    $ldapFilter =
        if ($Mode -eq 'Full') {
            '(objectClass=*)'
        }
        else {
            '(|(objectClass=organizationalUnit)(objectClass=domain)(adminCount=1)(cn=AdminSDHolder))'
        }

    $dangerousRights = 'GenericAll|GenericWrite|WriteDacl|WriteOwner|WriteProperty|ExtendedRight'

    # Enumerate the target objects. We need the SD control flag so ObjectSecurity is
    # populated with the DACL.
    $searcher = $ctx.NewSearcher($ldapFilter, @('distinguishedName','objectGUID','objectClass','name'))
    $searcher.SecurityMasks = [System.DirectoryServices.SecurityMasks]::Dacl -bor [System.DirectoryServices.SecurityMasks]::Owner
    $results = $searcher.FindAll()

    foreach ($result in $results) {

        $dn   = "$($result.Properties['distinguishedname'][0])"
        $name = "$($result.Properties['name'][0])"
        $guid = if ($result.Properties['objectguid'].Count) { ([guid]$result.Properties['objectguid'][0]).ToString() } else { '' }

        # objectClass is multi-valued; the most-derived (last) is the meaningful one.
        $classValues = @($result.Properties['objectclass'])
        $objectClass = if ($classValues.Count) { "$($classValues[-1])" } else { '' }

        # Bind to the object to read its security descriptor.
        try {
            $entryPath = "$($ctx.Prefix)/$dn"
            $entry = if ($ctx.Credential) {
                New-Object System.DirectoryServices.DirectoryEntry($entryPath, $ctx.Credential.UserName, $ctx.Credential.GetNetworkCredential().Password)
            } else {
                New-Object System.DirectoryServices.DirectoryEntry($entryPath)
            }

            $security = $entry.ObjectSecurity
            if (-not $security) { continue }

            $owner = ''
            try { $owner = $security.GetOwner([System.Security.Principal.SecurityIdentifier]).Value } catch { }

            $rules = $security.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])
        }
        catch {
            Write-Verbose "ACL read failed for $dn : $($_.Exception.Message)"
            continue
        }

        foreach ($ace in $rules) {

            if ("$($ace.ActiveDirectoryRights)" -notmatch $dangerousRights) { continue }

            $trusteeSid = "$($ace.IdentityReference.Value)"

            # Resolve the SID to a friendly name for the Trustee column (best-effort).
            $trusteeName = $trusteeSid
            try {
                $trusteeName = (New-Object System.Security.Principal.SecurityIdentifier($trusteeSid)).Translate([System.Security.Principal.NTAccount]).Value
            }
            catch { }

            [PSCustomObject]@{
                ObjectName        = $name
                ObjectGUID        = $guid
                DistinguishedName = $dn
                ObjectClass       = $objectClass
                ObjectOwner       = $owner
                Trustee           = $trusteeName
                TrusteeSID        = $trusteeSid
                Rights            = "$($ace.ActiveDirectoryRights)"
                AccessType        = "$($ace.AccessControlType)"
                IsInherited       = $ace.IsInherited
                ObjectType        = "$($ace.ObjectType)"
                InheritanceType   = "$($ace.InheritanceType)"
                Schema_Version    = $script:TJETConfig.SchemaVersion
                Collector_Version = $script:TJETConfig.CollectorVersion
            }
        }
    }

    $results.Dispose()
    $searcher.Dispose()
}


# ==========================================================================
# SOURCE: Collectors\Collect-ADCS.ps1
# ==========================================================================
function Collect-ADCS {
<#
.SYNOPSIS
    Collects AD Certificate Services templates and CAs for ESC misconfiguration analysis
    -- via ADSI, no RSAT.
.DESCRIPTION
    Reads the objects an attacker abuses for certificate-based domain escalation:

      - Certificate templates: CN=Certificate Templates,CN=Public Key Services,CN=Services
        in the Configuration NC. Captures the flags, EKUs, enrollment-permission ACL and
        signature requirements that decide whether a template is ESC1/ESC2/ESC3-abusable.
      - Enrollment services (CAs): CN=Enrollment Services in the same container. Captures
        which templates each CA publishes and the CA's own flags (ESC6
        EDITF_ATTRIBUTESUBJECTALTNAME lives on the CA, not the template).

    Emits one record per template (Check='CertTemplate') and one per CA
    (Check='CertificateAuthority'), flat, so they travel in a dedicated
    AD_ADCS_Audit.csv and feed a single ESC detector. Detection only -- it reads
    configuration, never requests a certificate.

    Key attributes and why they matter:
      msPKI-Certificate-Name-Flag       bit 0x1 = ENROLLEE_SUPPLIES_SUBJECT (ESC1 core)
      msPKI-Enrollment-Flag             bit 0x2 = PEND_ALL_REQUESTS (manager approval);
                                        its ABSENCE is required for ESC1
      pKIExtendedKeyUsage               client-auth / smartcard-logon / Any-Purpose EKUs
                                        that make an issued cert usable for auth (ESC1/2)
      msPKI-RA-Signature                number of authorized signatures required; 0 means
                                        no co-sign, a precondition for abuse
      nTSecurityDescriptor              enrollment + write rights: who can enrol (ESC1),
                                        and who can EDIT the template (ESC4)
#>
    [CmdletBinding()]
    param(
        [string]$Server,
        [System.Management.Automation.PSCredential]$Credential
    )

    $ctx = Get-TJETDirectoryContext -Server:$Server -Credential:$Credential

    $pkiRoot = "CN=Public Key Services,CN=Services,$($ctx.ConfigurationNC)"

    # If ADCS is not deployed, the container is absent -- degrade quietly.
    try {
        $probe = $ctx.NewSearcher('(objectClass=pKIEnrollmentService)', @('cn'), "CN=Enrollment Services,$pkiRoot", 'Subtree')
        $anyCA = $probe.FindOne()
        $probe.Dispose()
    }
    catch {
        Write-TJETLog INFO 'ADCS not present (no Public Key Services container). Skipping certificate template collection.'
        return
    }

    if (-not $anyCA) {
        Write-TJETLog INFO 'ADCS schema present but no enrollment services (CAs) found. Skipping.'
        return
    }

    # Client-authentication EKUs that let an issued certificate authenticate as a user.
    # Any of these (or the absence of EKUs = "any purpose", or the Any-Purpose OID)
    # makes a template usable for logon.
    $authEkuOids = @{
        '1.3.6.1.5.5.7.3.2'       = 'Client Authentication'
        '1.3.6.1.5.2.3.4'         = 'PKINIT Client Authentication'
        '1.3.6.1.4.1.311.20.2.2'  = 'Smart Card Logon'
        '2.5.29.37.0'             = 'Any Purpose'
    }

    # SIDs/RIDs that represent a "low-privileged / broad" enrollee. If one of these can
    # enrol, and the template lets the enrollee supply the subject, that is ESC1.
    $broadEnrollSids = @(
        'S-1-1-0'        # Everyone
        'S-1-5-11'       # Authenticated Users
        'S-1-5-32-545'   # BUILTIN\Users
    )

    function Resolve-Sid {
        param([string]$Sid)
        if ([string]::IsNullOrWhiteSpace($Sid)) { return '' }
        try { return (New-Object System.Security.Principal.SecurityIdentifier($Sid)).Translate([System.Security.Principal.NTAccount]).Value }
        catch { return $Sid }
    }

    # Extract enrollment + write principals from a template's security descriptor.
    # Enrollment is granted via the "Certificate-Enrollment" extended right
    # (GUID 0e10c968-78fb-11d2-90d4-00c04f79dc55) or GenericAll/ExtendedRight.
    $enrollRightGuid = '0e10c968-78fb-11d2-90d4-00c04f79dc55'
    $autoenrollGuid  = 'a05b8cc2-17bc-4802-a710-e7c15ab866a2'

    function Get-TemplatePrincipals {
        param([string]$TemplateDN)

        $result = [PSCustomObject]@{
            EnrollSids    = New-Object System.Collections.Generic.List[string]
            WriteSids     = New-Object System.Collections.Generic.List[string]
            OwnerSid      = ''
        }

        try {
            $path = "$($ctx.Prefix)/$TemplateDN"
            $entry = if ($ctx.Credential) {
                New-Object System.DirectoryServices.DirectoryEntry($path, $ctx.Credential.UserName, $ctx.Credential.GetNetworkCredential().Password)
            } else {
                New-Object System.DirectoryServices.DirectoryEntry($path)
            }

            $sec = $entry.ObjectSecurity
            try { $result.OwnerSid = $sec.GetOwner([System.Security.Principal.SecurityIdentifier]).Value } catch { }

            foreach ($ace in $sec.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {

                if ("$($ace.AccessControlType)" -ne 'Allow') { continue }

                $sid    = "$($ace.IdentityReference.Value)"
                $rights = "$($ace.ActiveDirectoryRights)"
                $objType = "$($ace.ObjectType)"

                # Enrollment: the Certificate-Enrollment extended right, autoenroll, or a
                # blanket GenericAll/AllExtendedRights.
                if ($rights -match 'GenericAll' -or
                    ($rights -match 'ExtendedRight' -and ($objType -eq $enrollRightGuid -or $objType -eq $autoenrollGuid -or $objType -eq '00000000-0000-0000-0000-000000000000'))) {
                    $result.EnrollSids.Add($sid)
                }

                # Write/control over the template object itself (ESC4).
                if ($rights -match 'GenericAll|GenericWrite|WriteDacl|WriteOwner|WriteProperty') {
                    $result.WriteSids.Add($sid)
                }
            }
        }
        catch {
            Write-Verbose "Template SD read failed for $TemplateDN : $($_.Exception.Message)"
        }

        return $result
    }

    # ------------------------------------------------------ templates ---------
    $templateProps = @(
        'cn','displayName','distinguishedName','objectGUID',
        'msPKI-Certificate-Name-Flag','msPKI-Enrollment-Flag',
        'msPKI-RA-Signature','msPKI-Certificate-Application-Policy',
        'pKIExtendedKeyUsage','msPKI-Template-Schema-Version'
    )

    $tSearcher = $ctx.NewSearcher('(objectClass=pKICertificateTemplate)', $templateProps, "CN=Certificate Templates,$pkiRoot", 'Subtree')
    $templates = $tSearcher.FindAll()

    foreach ($result in $templates) {

        $flat = Convert-TJETSearchResult $result

        $dn          = Get-TJETLdapProperty $flat 'distinguishedname'
        $name        = Get-TJETLdapProperty $flat 'cn'
        $displayName = Get-TJETLdapProperty $flat 'displayname'

        $nameFlag       = [int](Get-TJETLdapProperty $flat 'mspki-certificate-name-flag' 0)
        $enrollFlag     = [int](Get-TJETLdapProperty $flat 'mspki-enrollment-flag' 0)
        $raSignature    = [int](Get-TJETLdapProperty $flat 'mspki-ra-signature' 0)

        # EKUs are in pKIExtendedKeyUsage and/or msPKI-Certificate-Application-Policy.
        $ekuRaw = @()
        $e1 = Get-TJETLdapProperty $flat 'pkiextendedkeyusage'
        $e2 = Get-TJETLdapProperty $flat 'mspki-certificate-application-policy'
        if ($e1) { $ekuRaw += ($e1 -split '; ') }
        if ($e2) { $ekuRaw += ($e2 -split '; ') }
        $ekuRaw = @($ekuRaw | Where-Object { $_ } | Select-Object -Unique)

        $enrolleeSuppliesSubject = (($nameFlag -band 0x1) -ne 0)     # ENROLLEE_SUPPLIES_SUBJECT
        $managerApproval         = (($enrollFlag -band 0x2) -ne 0)   # PEND_ALL_REQUESTS
        $noEkus                  = ($ekuRaw.Count -eq 0)

        $authEkuMatches = @($ekuRaw | Where-Object { $authEkuOids.ContainsKey($_) } |
            ForEach-Object { $authEkuOids[$_] })
        $hasAuthEku = ($authEkuMatches.Count -gt 0 -or $noEkus)   # no EKU == any purpose

        $principals = Get-TemplatePrincipals $dn

        $enrollNames = @($principals.EnrollSids | Select-Object -Unique | ForEach-Object { Resolve-Sid $_ })
        $writeNames  = @($principals.WriteSids  | Select-Object -Unique | ForEach-Object { Resolve-Sid $_ })

        $broadEnroll = [bool](@($principals.EnrollSids | Where-Object {
            $broadEnrollSids -contains $_ -or $_ -match '-513$'    # +Domain Users
        }).Count -gt 0)

        $broadWrite = [bool](@($principals.WriteSids | Where-Object {
            $broadEnrollSids -contains $_ -or $_ -match '-513$'
        }).Count -gt 0)

        [PSCustomObject]@{
            Check                       = 'CertTemplate'
            Category                    = 'ADCS'
            Item                        = $name
            Detail                      = $displayName
            DistinguishedName           = $dn
            Template_GUID               = Get-TJETLdapProperty $flat 'objectguid'
            SchemaVersion_Template      = [int](Get-TJETLdapProperty $flat 'mspki-template-schema-version' 0)
            Enrollee_Supplies_Subject   = $enrolleeSuppliesSubject
            Manager_Approval_Required   = $managerApproval
            RA_Signatures_Required      = $raSignature
            Has_Auth_EKU                = $hasAuthEku
            Auth_EKU_Names              = ($authEkuMatches -join '; ')
            No_EKU_Any_Purpose          = $noEkus
            All_EKUs                    = ($ekuRaw -join '; ')
            Enroll_Principals           = ($enrollNames -join '; ')
            Write_Principals            = ($writeNames -join '; ')
            Owner                       = (Resolve-Sid $principals.OwnerSid)
            Low_Priv_Can_Enroll         = $broadEnroll
            Low_Priv_Can_Write          = $broadWrite
            Scanned_By                  = "$env:USERDOMAIN\$env:USERNAME"
            Schema_Version              = $script:TJETConfig.SchemaVersion
            Collector_Version           = $script:TJETConfig.CollectorVersion
        }
    }

    $templates.Dispose()
    $tSearcher.Dispose()

    # ------------------------------------------------------ CAs ---------------
    $caProps = @('cn','distinguishedName','objectGUID','certificateTemplates','dNSHostName','flags')
    $caSearcher = $ctx.NewSearcher('(objectClass=pKIEnrollmentService)', $caProps, "CN=Enrollment Services,$pkiRoot", 'Subtree')
    $cas = $caSearcher.FindAll()

    foreach ($result in $cas) {

        $flat = Convert-TJETSearchResult $result
        $dn = Get-TJETLdapProperty $flat 'distinguishedname'

        $published = Get-TJETLdapProperty $flat 'certificatetemplates'
        $publishedList = if ($published) { @($published -split '; ') } else { @() }

        # ESC6 (EDITF_ATTRIBUTESUBJECTALTNAME) and ESC8 (web enrollment) require reading
        # the CA's on-box configuration, which is not exposed in AD. Presence + published
        # templates are what the directory offers; the detector notes the CA for manual
        # ESC6/ESC8 follow-up.
        [PSCustomObject]@{
            Check                = 'CertificateAuthority'
            Category             = 'ADCS'
            Item                 = Get-TJETLdapProperty $flat 'cn'
            Detail               = Get-TJETLdapProperty $flat 'dnshostname'
            DistinguishedName    = $dn
            CA_GUID              = Get-TJETLdapProperty $flat 'objectguid'
            Published_Templates  = ($publishedList -join '; ')
            Published_Count      = $publishedList.Count
            Scanned_By           = "$env:USERDOMAIN\$env:USERNAME"
            Schema_Version       = $script:TJETConfig.SchemaVersion
            Collector_Version    = $script:TJETConfig.CollectorVersion
        }
    }

    $cas.Dispose()
    $caSearcher.Dispose()

    Write-TJETLog INFO 'ADCS collection complete.'
}


# ==========================================================================
# SOURCE: Collectors\Collect-Computers.ps1
# ==========================================================================
function Collect-Computers {
<#
.SYNOPSIS
    Collects computer objects and derives delegation / hardening flags -- via ADSI, no RSAT.
.DESCRIPTION
    [ADSI REWRITE] Queries computer objects over LDAP with System.DirectoryServices.
    Output contract unchanged: same field names as the AD-module version, so detectors
    INF-001..INF-005 and the privilege model are unaffected.

    LAPS handling is actually SIMPLER under ADSI: requesting an attribute the schema
    lacks is not an error (it just is not returned), so there is no schema-probe abort
    risk. LAPS presence is detected two ways: (1) does any host carry a LAPS expiration
    attribute value, and (2) does the schema define the attribute at all -- checked once
    against the schema naming context so the report can distinguish "not deployed here"
    from "schema cannot express LAPS".
#>
    [CmdletBinding()]
    param(
        [string]$Server,
        [System.Management.Automation.PSCredential]$Credential
    )

    $ctx = Get-TJETDirectoryContext -Server:$Server -Credential:$Credential

    # Is LAPS in the schema at all? One cheap lookup against the schema NC.
    $lapsSchemaPresent = $false
    foreach ($lapsAttr in 'ms-Mcs-AdmPwdExpirationTime','msLAPS-PasswordExpirationTime') {
        try {
            $probe = $ctx.NewSearcher("(lDAPDisplayName=$lapsAttr)", @('lDAPDisplayName'), $ctx.SchemaNC, 'Subtree')
            if ($probe.FindOne()) { $lapsSchemaPresent = $true }
            $probe.Dispose()
        }
        catch { }
    }

    if (-not $lapsSchemaPresent) {
        Write-TJETLog INFO 'No LAPS attributes in this schema. INF-003 will report all member servers as lacking LAPS evidence.'
    }

    $properties = @(
        'distinguishedName','objectGUID','objectSid','sAMAccountName','dNSHostName',
        'operatingSystem','operatingSystemVersion','userAccountControl','primaryGroupID',
        'pwdLastSet','whenCreated','lastLogonTimestamp','description',
        'msDS-AllowedToActOnBehalfOfOtherIdentity','msDS-KeyCredentialLink',
        'ms-Mcs-AdmPwdExpirationTime','msLAPS-PasswordExpirationTime'
    )

    $searcher = $ctx.NewSearcher('(objectClass=computer)', $properties)
    $results = $searcher.FindAll()

    foreach ($result in $results) {

        $flat = Convert-TJETSearchResult $result
        $record = [ordered]@{}

        $uac = [int](Get-TJETLdapProperty $flat 'useraccountcontrol' 0)

        $record['DistinguishedName'] = Get-TJETLdapProperty $flat 'distinguishedname'
        $record['SamAccountName']    = Get-TJETLdapProperty $flat 'samaccountname'
        $record['DNSHostName']       = Get-TJETLdapProperty $flat 'dnshostname'
        $record['ObjectGUID']        = Get-TJETLdapProperty $flat 'objectguid'
        $record['ObjectSID']         = Get-TJETLdapProperty $flat 'objectsid'
        $record['Enabled']           = (-not (Test-TJETUacFlag $uac 'Disabled'))
        $record['OperatingSystem']         = Get-TJETLdapProperty $flat 'operatingsystem'
        $record['OperatingSystemVersion']  = Get-TJETLdapProperty $flat 'operatingsystemversion'

        # 516 = writable DC, 521 = read-only DC.
        $primaryGroup = [int](Get-TJETLdapProperty $flat 'primarygroupid' 0)
        $record['Is_Domain_Controller'] = [bool]($primaryGroup -in @(516, 521))

        $record['Has_Unconstrained_Delegation'] = (Test-TJETUacFlag $uac 'TrustedForDelegation')
        $record['Has_RBCD_Configured']    = [bool](Get-TJETLdapProperty $flat 'msds-allowedtoactonbehalfofotheridentity')
        $record['Has_Shadow_Credentials'] = [bool](Get-TJETLdapProperty $flat 'msds-keycredentiallink')

        $lapsEvidence = $false
        if (Get-TJETLdapProperty $flat 'ms-mcs-admpwdexpirationtime')   { $lapsEvidence = $true }
        if (Get-TJETLdapProperty $flat 'mslaps-passwordexpirationtime') { $lapsEvidence = $true }
        $record['Has_LAPS'] = $lapsEvidence

        $record['LAPS_Schema_Present'] = [bool]$lapsSchemaPresent

        [PSCustomObject]$record
    }

    $results.Dispose()
    $searcher.Dispose()
}


# ==========================================================================
# SOURCE: Collectors\Collect-DomainSummary.ps1
# ==========================================================================
function Collect-DomainSummary {
<#
.SYNOPSIS
    Collects the domain control-plane summary / run manifest -- via ADSI, no RSAT.
.DESCRIPTION
    [ADSI REWRITE] Every value here maps to an LDAP read:
      - domain object attributes (name, MAQ, default password policy, msDS-Behavior-Version)
      - forest root from RootDSE (rootDomainNamingContext)
      - krbtgt pwdLastSet
      - ADCS presence: any pKIEnrollmentService under the Configuration NC
      - Protected Users member count and trust count
    Output contract unchanged, so DOM-001 (krbtgt age), DOM-005 (MAQ) and ID-011
    (MinPwdLength baseline) are unaffected.

    Domain/forest "mode" is the msDS-Behavior-Version integer; it is emitted raw with a
    friendly label, since the AD module's enum names are not reproducible without it.
#>
    [CmdletBinding()]
    param(
        [string]$Server,
        [System.Management.Automation.PSCredential]$Credential
    )

    $ctx = Get-TJETDirectoryContext -Server:$Server -Credential:$Credential

    function Get-FunctionalLevelName {
        param([int]$Level)
        switch ($Level) {
            0 { 'Windows2000' } 1 { 'Windows2003Interim' } 2 { 'Windows2003' }
            3 { 'Windows2008' } 4 { 'Windows2008R2' } 5 { 'Windows2012' }
            6 { 'Windows2012R2' } 7 { 'Windows2016' } default { "Level$Level" }
        }
    }

    # --- domain object -------------------------------------------------------
    $domSearcher = $ctx.NewSearcher('(objectClass=domainDNS)',
        @('objectGUID','minPwdLength','maxPwdAge','ms-DS-MachineAccountQuota','msDS-Behavior-Version'),
        $ctx.DefaultNC, 'Base')
    $domResult = $domSearcher.FindOne()
    $domSearcher.Dispose()
    $domFlat = if ($domResult) { Convert-TJETSearchResult $domResult } else { [ordered]@{} }

    $domainDNS = ($ctx.DefaultNC -replace 'DC=', '' -replace ',', '.')
    $forestDNS = ($ctx.RootDomainNC -replace 'DC=', '' -replace ',', '.')

    $maq = Get-TJETLdapProperty $domFlat 'ms-ds-machineaccountquota' $null
    $domLevel = [int](Get-TJETLdapProperty $domFlat 'msds-behavior-version' 0)

    $minPwdLength = [int](Get-TJETLdapProperty $domFlat 'minpwdlength' 0)

    $maxPwdAgeRaw = Get-TJETLdapProperty $domFlat 'maxpwdage' 0
    $maxPwdAgeDays = $null
    $ticks = 0L
    if ([long]::TryParse("$maxPwdAgeRaw", [ref]$ticks) -and $ticks -ne 0 -and $ticks -ne [long]::MinValue) {
        $maxPwdAgeDays = [math]::Round([math]::Abs($ticks) / 864000000000.0)
    }

    # --- forest functional level (root domain object) ------------------------
    $forestLevel = $domLevel
    if ($ctx.RootDomainNC -and $ctx.RootDomainNC -ne $ctx.DefaultNC) {
        try {
            $fSearcher = $ctx.NewSearcher('(objectClass=domainDNS)', @('msDS-Behavior-Version'), $ctx.RootDomainNC, 'Base')
            $fResult = $fSearcher.FindOne()
            $fSearcher.Dispose()
            if ($fResult -and $fResult.Properties['msds-behavior-version'].Count) {
                $forestLevel = [int]$fResult.Properties['msds-behavior-version'][0]
            }
        }
        catch { }
    }

    # --- krbtgt password age -------------------------------------------------
    $krbtgtAge = 'Unknown'
    try {
        $kSearcher = $ctx.NewSearcher('(sAMAccountName=krbtgt)', @('pwdLastSet'), $ctx.DefaultNC, 'Subtree')
        $kResult = $kSearcher.FindOne()
        $kSearcher.Dispose()
        if ($kResult -and $kResult.Properties['pwdlastset'].Count) {
            $pls = ConvertFrom-TJETFileTime $kResult.Properties['pwdlastset'][0]
            if ($pls) { $krbtgtAge = [math]::Round(((Get-Date).ToUniversalTime() - $pls).TotalDays) }
        }
    }
    catch { }

    # --- ADCS presence (Configuration NC) ------------------------------------
    $adcs = $false
    try {
        $pkiBase = "CN=Public Key Services,CN=Services,$($ctx.ConfigurationNC)"
        $pkiSearcher = $ctx.NewSearcher('(objectClass=pKIEnrollmentService)', @('cn'), $pkiBase, 'Subtree')
        if ($pkiSearcher.FindOne()) { $adcs = $true }
        $pkiSearcher.Dispose()
    }
    catch { }

    # --- Protected Users count -----------------------------------------------
    $protectedUsers = 0
    try {
        $puSearcher = $ctx.NewSearcher('(sAMAccountName=Protected Users)', @('member'), $ctx.DefaultNC, 'Subtree')
        $puResult = $puSearcher.FindOne()
        $puSearcher.Dispose()
        if ($puResult -and $puResult.Properties['member'].Count) { $protectedUsers = $puResult.Properties['member'].Count }
    }
    catch { }

    # --- trust count ---------------------------------------------------------
    $trustCount = 0
    try {
        $tSearcher = $ctx.NewSearcher('(objectClass=trustedDomain)', @('name'))
        $tResults = $tSearcher.FindAll()
        $trustCount = $tResults.Count
        $tResults.Dispose(); $tSearcher.Dispose()
    }
    catch { }

    [PSCustomObject]@{
        Collector_Version    = $script:TJETConfig.CollectorVersion
        Correlation_Version  = $script:TJETConfig.CorrelationVersion
        Schema_Version       = $script:TJETConfig.SchemaVersion
        Executed_By          = "$env:USERDOMAIN\$env:USERNAME"
        Scan_Start           = (Get-Date -Format 'o')
        Domain               = $domainDNS
        Domain_GUID          = Get-TJETLdapProperty $domFlat 'objectguid'
        DomainMode           = Get-FunctionalLevelName $domLevel
        Forest               = $forestDNS
        ForestMode           = Get-FunctionalLevelName $forestLevel
        PDCEmulator          = $ctx.DomainController
        KRBTGT_PwdAgeDays    = $krbtgtAge
        MachineAccountQuota  = $maq
        MinPwdLength         = $minPwdLength
        MaxPwdAge_Days       = $maxPwdAgeDays
        ProtectedUsers_Count = $protectedUsers
        Has_ADCS             = $adcs
        TrustCount           = $trustCount
    }
}


# ==========================================================================
# SOURCE: Collectors\Collect-FGPP.ps1
# ==========================================================================
function Collect-FGPP {
<#
.SYNOPSIS
    Collects Fine-Grained Password Policies (PSOs) with the domain default -- via ADSI.
.DESCRIPTION
    [ADSI REWRITE] The domain default policy lives on the domain object itself
    (minPwdLength, pwdProperties, maxPwdAge...). PSOs are msDS-PasswordSettings objects
    under CN=Password Settings Container,CN=System. This reads both over LDAP and emits
    the identical field contract, so DOM-006 is unaffected.

    AD stores durations as negative Integer8 100-nanosecond intervals; ConvertTo-Days
    turns maxPwdAge into whole days. pwdProperties bit 0x1 = DOMAIN_PASSWORD_COMPLEX.
#>
    [CmdletBinding()]
    param(
        [string]$Server,
        [System.Management.Automation.PSCredential]$Credential
    )

    $ctx = Get-TJETDirectoryContext -Server:$Server -Credential:$Credential

    function ConvertTo-Days {
        param($Interval)
        $ticks = 0L
        if (-not [long]::TryParse("$Interval", [ref]$ticks)) { return 0 }
        if ($ticks -eq 0 -or $ticks -eq [long]::MinValue) { return 0 }
        # Negative 100-ns intervals -> days.
        return [math]::Round([math]::Abs($ticks) / 864000000000.0)
    }

    # --- domain default policy (attributes on the domain object) -------------
    $domSearcher = $ctx.NewSearcher('(objectClass=domainDNS)',
        @('minPwdLength','pwdProperties','pwdHistoryLength','maxPwdAge'), $ctx.DefaultNC, 'Base')
    $domResult = $domSearcher.FindOne()
    $domSearcher.Dispose()

    $domFlat = if ($domResult) { Convert-TJETSearchResult $domResult } else { [ordered]@{} }

    $defaultMinLen  = [int](Get-TJETLdapProperty $domFlat 'minpwdlength' 0)
    $defaultHistory = [int](Get-TJETLdapProperty $domFlat 'pwdhistorylength' 0)
    $defaultPwdProps = [int](Get-TJETLdapProperty $domFlat 'pwdproperties' 0)
    $defaultComplexity = (($defaultPwdProps -band 0x1) -ne 0)

    # --- PSOs ----------------------------------------------------------------
    $psoContainer = "CN=Password Settings Container,CN=System,$($ctx.DefaultNC)"
    $psoProps = @('name','msDS-PasswordSettingsPrecedence','msDS-MinimumPasswordLength',
        'msDS-PasswordHistoryLength','msDS-PasswordComplexityEnabled','msDS-LockoutThreshold',
        'msDS-PasswordReversibleEncryptionEnabled','msDS-MaximumPasswordAge','msDS-PSOAppliesTo')

    $psoSearcher = $ctx.NewSearcher('(objectClass=msDS-PasswordSettings)', $psoProps, $psoContainer, 'Subtree')

    $psoResults = $null
    try { $psoResults = $psoSearcher.FindAll() } catch { }

    if (-not $psoResults -or $psoResults.Count -eq 0) {
        Write-TJETLog INFO 'No Fine-Grained Password Policies found.'
        $psoSearcher.Dispose()
        return
    }

    foreach ($result in $psoResults) {

        $flat = Convert-TJETSearchResult $result

        $appliesRaw = Get-TJETLdapProperty $flat 'msds-psoappliesto'
        $applies = if ($appliesRaw) { @($appliesRaw -split '; ') } else { @() }
        $appliesNames = ($applies | ForEach-Object { ($_ -split ',')[0] -replace '^CN=', '' }) -join ';'

        [PSCustomObject]@{
            Name                             = Get-TJETLdapProperty $flat 'name'
            Precedence                       = [int](Get-TJETLdapProperty $flat 'msds-passwordsettingsprecedence' 0)
            MinPasswordLength                = [int](Get-TJETLdapProperty $flat 'msds-minimumpasswordlength' 0)
            PasswordHistoryCount             = [int](Get-TJETLdapProperty $flat 'msds-passwordhistorylength' 0)
            ComplexityEnabled                = [bool]((Get-TJETLdapProperty $flat 'msds-passwordcomplexityenabled') -eq 'True')
            LockoutThreshold                 = [int](Get-TJETLdapProperty $flat 'msds-lockoutthreshold' 0)
            ReversibleEncryptionEnabled      = [bool]((Get-TJETLdapProperty $flat 'msds-passwordreversibleencryptionenabled') -eq 'True')
            MaxPasswordAge_Days              = ConvertTo-Days (Get-TJETLdapProperty $flat 'msds-maximumpasswordage' 0)
            AppliesTo                        = ($applies -join ';')
            AppliesTo_Names                  = $appliesNames
            AppliesTo_Count                  = $applies.Count
            Applies_To_Privileged_Name_Match = [bool]($appliesNames -match '(?i)Domain Admins|Enterprise Admins|Schema Admins|Administrators|DnsAdmins')
            Domain_Default_MinLength         = $defaultMinLen
            Domain_Default_Complexity        = [bool]$defaultComplexity
            Domain_Default_HistoryCount      = $defaultHistory
            Schema_Version                   = $script:TJETConfig.SchemaVersion
            Collector_Version                = $script:TJETConfig.CollectorVersion
        }
    }

    $psoResults.Dispose()
    $psoSearcher.Dispose()
}


# ==========================================================================
# SOURCE: Collectors\Collect-GPOs.ps1
# ==========================================================================
function Collect-GPOs {
<#
.SYNOPSIS
    Collects GPO metadata, delegation and SYSVOL permissions -- via ADSI + SYSVOL, no RSAT.
.DESCRIPTION
    [ADSI REWRITE] Replaces the GroupPolicy module entirely, per design decision.

    Sources:
      - GPO objects: groupPolicyContainer objects in CN=Policies,CN=System over LDAP
        (displayName, gPCFileSysPath, flags, versionNumber, whenCreated/Changed).
      - Delegation/permissions: the object's nTSecurityDescriptor DACL (same mechanism
        as Collect-ACLs), mapped to GPO permission semantics -- an ACE granting
        write-class rights to a broad principal is the GpoEdit risk.
      - Links: gPLink back-references found by an LDAP filter.
      - SYSVOL folder ACL: Get-Acl on the UNC path (a filesystem call, no RSAT needed).
      - Policy SETTINGS: parsed directly from the SYSVOL files that the GPO report would
        otherwise summarise -- GptTmpl.inf (user-rights assignments, LSA settings) and
        the presence of Registry.pol. This recovers Has_Privileged_UserRights and
        Has_Auth_Hardening without the module.

    Output contract preserved so GPO-001/002/003 are unaffected.
#>
    [CmdletBinding()]
    param(
        [string]$Server,
        [System.Management.Automation.PSCredential]$Credential
    )

    $ctx = Get-TJETDirectoryContext -Server:$Server -Credential:$Credential

    $broadPrincipalSids = @(
        'S-1-1-0'       # Everyone
        'S-1-5-11'      # Authenticated Users
        'S-1-5-32-545'  # BUILTIN\Users
    )
    # Domain Users is domain-relative RID 513; matched separately.

    $expectedSysvol = '(?i)SYSTEM|Domain Admins|Enterprise Admins|Group Policy Creator Owners|Administrators|CREATOR OWNER'
    $domainDNS = ($ctx.DefaultNC -replace 'DC=', '' -replace ',', '.')

    # Write-class AD rights that constitute "can edit this GPO".
    $editRights = 'GenericAll|GenericWrite|WriteDacl|WriteOwner|WriteProperty'

    $policyBase = "CN=Policies,CN=System,$($ctx.DefaultNC)"
    $props = @('displayName','name','gPCFileSysPath','flags','versionNumber','whenCreated','whenChanged')

    $searcher = $ctx.NewSearcher('(objectClass=groupPolicyContainer)', $props, $policyBase, 'Subtree')
    $searcher.SecurityMasks = [System.DirectoryServices.SecurityMasks]::Dacl -bor [System.DirectoryServices.SecurityMasks]::Owner
    $results = $searcher.FindAll()

    foreach ($result in $results) {

        $flat = Convert-TJETSearchResult $result

        $displayName = Get-TJETLdapProperty $flat 'displayname'
        $guidName    = Get-TJETLdapProperty $flat 'name'          # e.g. {31B2F340-...}
        $sysvolPath  = Get-TJETLdapProperty $flat 'gpcfilesyspath'
        $dn          = "CN=$guidName,$policyBase"

        # --- permissions from the SD DACL -----------------------------------
        $permissionPairs = New-Object System.Collections.Generic.List[string]
        $owner = ''
        $hasBroadModify = $false

        try {
            $entryPath = "$($ctx.Prefix)/$dn"
            $entry = if ($ctx.Credential) {
                New-Object System.DirectoryServices.DirectoryEntry($entryPath, $ctx.Credential.UserName, $ctx.Credential.GetNetworkCredential().Password)
            } else {
                New-Object System.DirectoryServices.DirectoryEntry($entryPath)
            }

            $security = $entry.ObjectSecurity
            try { $owner = $security.GetOwner([System.Security.Principal.SecurityIdentifier]).Value } catch { }

            foreach ($ace in $security.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {

                if ("$($ace.AccessControlType)" -ne 'Allow') { continue }

                $sid = "$($ace.IdentityReference.Value)"
                $rights = "$($ace.ActiveDirectoryRights)"

                $name = $sid
                try { $name = (New-Object System.Security.Principal.SecurityIdentifier($sid)).Translate([System.Security.Principal.NTAccount]).Value } catch { }

                $permissionPairs.Add("$name`:$rights")

                if ($rights -match $editRights) {
                    if (($broadPrincipalSids -contains $sid) -or ($sid -match '-513$')) {
                        $hasBroadModify = $true
                    }
                }
            }
        }
        catch {
            Write-Verbose "GPO SD read failed for $displayName : $($_.Exception.Message)"
        }

        # --- links -----------------------------------------------------------
        $linkDNs = @()
        try {
            $linkSearcher = $ctx.NewSearcher("(gPLink=*$guidName*)", @('distinguishedName'))
            $linkResults = $linkSearcher.FindAll()
            $linkDNs = foreach ($lr in $linkResults) { "$($lr.Properties['distinguishedname'][0])" }
            $linkResults.Dispose(); $linkSearcher.Dispose()
        }
        catch { }

        # --- SYSVOL folder ACL (filesystem, no RSAT) -------------------------
        $sysvolModify = @()
        if ($sysvolPath) {
            try {
                $sysvolModify = @(
                    (Get-Acl -Path $sysvolPath -ErrorAction Stop).Access |
                        Where-Object { $_.FileSystemRights -match 'Modify|FullControl|Write' } |
                        ForEach-Object { $_.IdentityReference.Value }
                )
            }
            catch {
                Write-Verbose "SYSVOL ACL read failed for $displayName"
            }
        }
        $unexpectedSysvol = @($sysvolModify | Where-Object { $_ -and $_ -notmatch $expectedSysvol } | Select-Object -Unique)

        # --- policy settings parsed from SYSVOL files ------------------------
        # GptTmpl.inf holds user-rights assignments (SeDebugPrivilege etc.) and LSA
        # settings; registry.pol holds registry-based policy. Reading these directly
        # replaces the GPO report for the two flags the detector needs.
        $userRightsText = ''
        $hasRegistryPol = $false
        if ($sysvolPath) {
            $gptTmpl = Join-Path $sysvolPath 'Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf'
            try {
                if (Test-Path $gptTmpl) { $userRightsText = (Get-Content $gptTmpl -Raw -ErrorAction Stop) }
            }
            catch { }

            foreach ($polRel in 'Machine\Registry.pol','User\Registry.pol') {
                if (Test-Path (Join-Path $sysvolPath $polRel)) { $hasRegistryPol = $true }
            }
        }

        # --- flags -----------------------------------------------------------
        # flags bit 0 = user config disabled, bit 1 = computer config disabled; 3 = all.
        $flags = [int](Get-TJETLdapProperty $flat 'flags' 0)
        $statusText = switch ($flags) {
            0 { 'AllSettingsEnabled' }
            1 { 'UserSettingsDisabled' }
            2 { 'ComputerSettingsDisabled' }
            3 { 'AllSettingsDisabled' }
            default { "Flags$flags" }
        }

        [PSCustomObject]@{
            GPO_Name                     = $displayName
            GPO_GUID                     = ($guidName -replace '[{}]', '')
            Domain                       = $domainDNS
            Owner                        = $owner
            Created                      = Get-TJETLdapProperty $flat 'whencreated'
            Modified                     = Get-TJETLdapProperty $flat 'whenchanged'
            Status                       = $statusText
            Linked_To                    = ($linkDNs -join '; ')
            Link_Count                   = @($linkDNs).Count
            Is_Unlinked                  = (@($linkDNs).Count -eq 0)
            Permissions                  = ($permissionPairs -join '; ')
            Has_Broad_Modify_Right       = [bool]$hasBroadModify
            Has_Privileged_UserRights    = [bool]($userRightsText -match 'SeDebugPrivilege|SeTcbPrivilege|SeBackupPrivilege|SeRestorePrivilege|SeTakeOwnershipPrivilege')
            Has_Auth_Hardening           = [bool]($userRightsText -match 'LmCompatibilityLevel|LDAPServerIntegrity|LDAPClientIntegrity')
            Has_Registry_Policy          = [bool]$hasRegistryPol
            SYSVOL_Modify                = ($sysvolModify -join '; ')
            SYSVOL_Unexpected_Modify     = ($unexpectedSysvol -join '; ')
            Has_Unexpected_SYSVOL_Rights = [bool]($unexpectedSysvol.Count -gt 0)
            Schema_Version               = $script:TJETConfig.SchemaVersion
            Collector_Version            = $script:TJETConfig.CollectorVersion
        }
    }

    $results.Dispose()
    $searcher.Dispose()
}


# ==========================================================================
# SOURCE: Collectors\Collect-Groups.ps1
# ==========================================================================
function Collect-Groups {
<#
.SYNOPSIS
    Collects group objects and derives Tier 0 / hygiene flags -- via ADSI, no RSAT.
.DESCRIPTION
    [ADSI REWRITE] Queries groups over LDAP. Output contract unchanged (GRP-001..003,
    the attack-path graph, and the privilege model all read the same field names).

    Two ADSI-specific details:
      - groupType is a bitmask; the SECURITY_ENABLED bit is 0x80000000. Distribution
        groups lack it. This replaces GroupCategory -eq 'Security'.
      - member enumeration is capped at 1500 values per LDAP response, so a very large
        group returns 'member;range=0-1499'. Get-TJETGroupMemberNames handles the range
        paging so Member_Count is accurate for big groups (the AD module hid this).
#>
    [CmdletBinding()]
    param(
        [string]$Server,
        [System.Management.Automation.PSCredential]$Credential
    )

    $ctx = Get-TJETDirectoryContext -Server:$Server -Credential:$Credential

    # Range-paged member enumeration for a single group DN.
    function Get-GroupMemberDNs {
        param([string]$GroupDN)

        $members = New-Object System.Collections.Generic.List[string]
        $low = 0
        $step = 1500

        while ($true) {
            $rangeAttr = "member;range=$low-$($low + $step - 1)"
            $s = $ctx.NewSearcher("(distinguishedName=$GroupDN)", @($rangeAttr), $ctx.DefaultNC, 'Base')
            $r = $s.FindOne()
            $s.Dispose()

            if (-not $r) { break }

            # The returned attribute name carries the actual upper bound, which is '*'
            # on the final page. Find whichever member;range=* property came back.
            $rangeProp = $r.Properties.PropertyNames | Where-Object { $_ -like 'member;range=*' } | Select-Object -First 1

            if (-not $rangeProp) {
                # No ranged property: either a small group already returned in full, or none.
                if ($r.Properties.Contains('member')) {
                    foreach ($m in $r.Properties['member']) { $members.Add("$m") }
                }
                break
            }

            foreach ($m in $r.Properties[$rangeProp]) { $members.Add("$m") }

            if ($rangeProp -like '*-`*') { break }   # final page (upper bound '*')
            $low += $step
        }

        return $members
    }

    $properties = @(
        'distinguishedName','objectGUID','objectSid','sAMAccountName','name',
        'member','memberOf','managedBy','adminCount','groupType'
    )

    $searcher = $ctx.NewSearcher('(objectClass=group)', $properties)
    $results = $searcher.FindAll()

    foreach ($result in $results) {

        $flat = Convert-TJETSearchResult $result
        $record = [ordered]@{}

        $sidValue = Get-TJETLdapProperty $flat 'objectsid'
        $dn       = Get-TJETLdapProperty $flat 'distinguishedname'
        $name     = Get-TJETLdapProperty $flat 'name'

        $record['DistinguishedName'] = $dn
        $record['Name']              = $name
        $record['SamAccountName']    = Get-TJETLdapProperty $flat 'samaccountname'
        $record['ObjectGUID']        = Get-TJETLdapProperty $flat 'objectguid'
        $record['ObjectSID']         = $sidValue

        # Member enumeration. The base result already carries members for small groups;
        # only page explicitly when the count looks capped.
        $memberRaw = Get-TJETLdapProperty $flat 'member'
        $memberDNs = if ($memberRaw) { @($memberRaw -split '; ') } else { @() }

        # If we hit the response cap, re-enumerate with range paging for an accurate count.
        if ($memberDNs.Count -ge 1500) {
            $memberDNs = @(Get-GroupMemberDNs $dn)
        }

        $record['Member_Count'] = $memberDNs.Count

        # Flattened member CNs for the graph.
        $memberNames = $memberDNs | ForEach-Object {
            if ($_ -match '^CN=([^,]+),') { $Matches[1] } else { "$_" }
        }
        $record['Member_Values'] = ($memberNames -join ';')

        # Domain Users (513) etc. are primaryGroupID-backed: `member` is always empty.
        $primaryGroupBacked = [bool]($sidValue -match '-(513|514|515|516|521)$')
        $record['Membership_Via_PrimaryGroupID'] = $primaryGroupBacked

        $record['Is_Empty'] = [bool](($memberDNs.Count -eq 0) -and (-not $primaryGroupBacked))

        $isDefaultGroup = $false
        if ($sidValue -match '^S-1-5-32-\d+$') { $isDefaultGroup = $true }
        elseif ($sidValue -match '-(\d+)$' -and [int]$Matches[1] -lt 1000) { $isDefaultGroup = $true }
        $record['Is_Default_Group'] = $isDefaultGroup

        # Tier 0 by SID, name fallback for DnsAdmins.
        $record['Is_Tier0'] = [bool](
            (Test-Tier0Sid $sidValue) -or
            ($name -match '(?i)^(DnsAdmins)$')
        )

        $record['Has_AdminCount'] = [bool]([int](Get-TJETLdapProperty $flat 'admincount' 0) -eq 1)

        $record['Is_Empty_Privileged'] = [bool](
            $record['Is_Empty'] -and ($record['Is_Tier0'] -or $record['Has_AdminCount'])
        )

        $record['Has_Owner'] = [bool](Get-TJETLdapProperty $flat 'managedby')

        $memberOfRaw = Get-TJETLdapProperty $flat 'memberof'
        $memberOfDNs = if ($memberOfRaw) { @($memberOfRaw -split '; ') } else { @() }
        $record['Outbound_Nesting_Count'] = $memberOfDNs.Count

        $memberOfNames = $memberOfDNs | ForEach-Object {
            if ($_ -match '^CN=([^,]+),') { $Matches[1] } else { "$_" }
        }
        $record['MemberOf_Values'] = ($memberOfNames -join ';')

        # groupType bitmask: 0x80000000 = SECURITY_ENABLED (stored as signed -2147483648).
        $groupType = [int64](Get-TJETLdapProperty $flat 'grouptype' 0)
        $record['Is_Security_Group'] = [bool](($groupType -band 0x80000000) -ne 0)

        [PSCustomObject]$record
    }

    $results.Dispose()
    $searcher.Dispose()
}


# ==========================================================================
# SOURCE: Collectors\Collect-LocalHost.ps1
# ==========================================================================
function Collect-LocalHost {
<#
.SYNOPSIS
    Collects local Windows privilege-escalation surface from the current host.
.DESCRIPTION
    The local-host half of the assessment. Covers the highest-signal privilege
    escalation categories a tool like WinPEAS checks, structured as one record per
    check result so correlation can classify severity consistently with the AD findings.

    This does NOT require Active Directory -- it inspects the local machine (services,
    registry, filesystem, scheduled tasks, the current token). It DOES benefit from
    running elevated: some checks (service ACLs, certain registry hives) return partial
    results without administrative rights, which is recorded rather than hidden.

    Categories collected:
        UnquotedServicePath      service path with a space and no quotes
        ModifiableService        service whose binary or config a non-admin can change
        AlwaysInstallElevated    MSI packages install as SYSTEM
        WritablePathDir          a %PATH% directory writable by the current user
        Autorun                  autorun pointing at a writable target
        StoredCredential         plaintext credential in a well-known location
        TokenPrivilege           dangerous privilege held by the current token
        UACConfig                UAC weakened or disabled
        CredentialProtection     WDigest / LSA protection / Credential Guard state
        SMBSigning               SMB signing not required
        LegacyProtocol           PowerShell v2, SMBv1

    Output field contract consumed by Invoke-LocalFindings:
        Check, Category, Item, Detail, Risk_Hint, Is_Elevated_Scan
.PARAMETER SkipTokenChecks
    Skip inspection of the current process token (the one check that reflects the
    running context rather than the machine).
#>
    [CmdletBinding()]
    param(
        [switch]$SkipTokenChecks
    )

    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]$identity

    # Two DIFFERENT facts, previously conflated:
    #
    #   $isElevated       - does THIS PROCESS hold an elevated (high-integrity) token?
    #                       False for an unelevated shell even when the user is an admin,
    #                       because UAC hands the process a filtered token.
    #
    #   $isAdminMember    - is the user a MEMBER of a local-admin-equivalent group?
    #                       True even in an unelevated shell if they could elevate.
    #
    # The distinction matters for what we report. If the user is an admin member, every
    # local privesc route is one the user could already reach by simply elevating -- so
    # reporting those routes against "current user" is noise. What is actually useful is:
    # what could a genuinely NON-privileged user do on this host? That is the report the
    # user asked for, and it is driven by $isAdminMember, not $isElevated.
    $isElevated = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    # Membership check that survives UAC token filtering: enumerate the token groups and
    # look for the well-known admin-equivalent SIDs directly, rather than trusting the
    # role check (which reflects the FILTERED token in an unelevated shell).
    $adminEquivalentSids = @(
        'S-1-5-32-544'   # BUILTIN\Administrators
        'S-1-5-32-551'   # Backup Operators (SeBackup -> effectively admin)
        'S-1-5-32-549'   # Server Operators
        'S-1-5-32-550'   # Print Operators
    )

    $isAdminMember = $false

    try {
        foreach ($group in $identity.Groups) {
            $sidValue = $group.Translate([Security.Principal.SecurityIdentifier]).Value
            if ($adminEquivalentSids -contains $sidValue) { $isAdminMember = $true; break }
        }
    }
    catch {
        # Translate can fail for orphaned SIDs; fall back to the role check.
        $isAdminMember = $isElevated
    }

    # If the process holds an elevated token, the user is definitionally an admin member.
    if ($isElevated) { $isAdminMember = $true }

    if (-not $isElevated) {
        Write-TJETLog WARNING 'Local host scan is not elevated. Service-ACL and some registry checks will be partial.'
    }

    if ($isAdminMember -and -not $isElevated) {
        Write-TJETLog INFO 'Scanning account is an administrator running unelevated. Privesc findings will be scoped to what a NON-privileged user could exploit.'
    }

    $currentUser = $identity.Name

    function New-LocalRecord {
        param($Check, $Category, $Item, $Detail, $RiskHint)

        [PSCustomObject]@{
            Check             = $Check
            Category          = $Category
            Item             = $Item
            Detail           = $Detail
            Risk_Hint        = $RiskHint
            Is_Elevated_Scan = $isElevated
            Is_Admin_Member  = $isAdminMember
            Scanned_Host     = $env:COMPUTERNAME
            Schema_Version   = $script:TJETConfig.SchemaVersion
            Collector_Version = $script:TJETConfig.CollectorVersion
        }
    }

    # Helper: is a path writable BY A NON-PRIVILEGED PRINCIPAL?
    #
    # [FIX] The previous version probed with the CURRENT token (write a temp file, see
    # if it works). When the operator is a local admin running unelevated, that probe
    # can succeed BECAUSE THEY ARE AN ADMIN -- producing a 'writable directory' privesc
    # finding that a genuinely unprivileged user could not reproduce. The user asked
    # for exactly the opposite: report only what a non-privileged user could exploit.
    #
    # This now inspects the ACL and returns true only if a NON-PRIVILEGED group holds a
    # write-class right: Users, Authenticated Users, Everyone, INTERACTIVE, or an
    # explicit non-admin identity. Admin-equivalent grants (Administrators, SYSTEM,
    # TrustedInstaller, the local admin group) are ignored, because a right that only
    # an admin holds is not an escalation route for a standard user.
    $nonPrivilegedSids = @(
        'S-1-1-0'      # Everyone
        'S-1-5-11'     # Authenticated Users
        'S-1-5-32-545' # BUILTIN\Users
        'S-1-5-4'      # INTERACTIVE
        'S-1-5-32-546' # Guests
        'S-1-5-7'      # Anonymous
    )

    $plantRights = [System.Security.AccessControl.FileSystemRights]::CreateFiles `
        -bor [System.Security.AccessControl.FileSystemRights]::CreateDirectories

    function Test-Writable {
        param([string]$DirectoryPath)

        if ([string]::IsNullOrWhiteSpace($DirectoryPath)) { return $false }
        if (-not (Test-Path $DirectoryPath)) { return $false }

        try {
            $acl = Get-Acl -Path $DirectoryPath -ErrorAction Stop
        }
        catch {
            return $false
        }

        foreach ($ace in $acl.Access) {

            if ($ace.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { continue }

            # Resolve the ACE identity to a SID.
            $sid = $null
            try {
                if ($ace.IdentityReference -is [System.Security.Principal.SecurityIdentifier]) {
                    $sid = $ace.IdentityReference.Value
                }
                else {
                    $sid = $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
                }
            }
            catch {
                $sid = "$($ace.IdentityReference)"
            }

            # Only non-privileged principals count.
            $isNonPriv = $false

            if ($nonPrivilegedSids -contains $sid) {
                $isNonPriv = $true
            }
            elseif ($sid -match '^S-1-5-21-.+-(\d+)$') {
                # A domain/local user or non-admin group. Exclude admin-equivalent RIDs.
                $rid = [int]$Matches[1]
                if ($rid -notin 500, 512, 516, 518, 519, 544) { $isNonPriv = $true }
            }

            if (-not $isNonPriv) { continue }

            if (([int]$ace.FileSystemRights -band [int]$plantRights) -ne 0) {
                return $true
            }
        }

        return $false
    }

    # ------------------------------------------------ Services (unquoted + ACL) ---
    try {
        $services = Get-CimInstance -ClassName Win32_Service -ErrorAction Stop

        foreach ($service in $services) {

            $path = $service.PathName

            if ([string]::IsNullOrWhiteSpace($path)) { continue }

            # Unquoted path containing a space, with an executable argument boundary.
            if ($path -notmatch '^\s*"' -and $path -match '\s' -and $path -match '\.exe') {

                $exePath = ($path -split '\.exe')[0] + '.exe'

                if ($exePath -match '\s') {
                    New-LocalRecord -Check 'UnquotedServicePath' -Category 'Local Privilege Escalation' `
                        -Item $service.Name `
                        -Detail "Path: $path ; StartMode: $($service.StartMode) ; Account: $($service.StartName)" `
                        -RiskHint 'An executable planted at an earlier space-delimited path segment runs in the service context.'
                }
            }

            # Modifiable service binary: is the directory holding the exe writable?
            $binDir = $null

            if ($path -match '^\s*"?([A-Za-z]:\\[^"]+\.exe)') {
                $binDir = Split-Path $Matches[1] -Parent
            }

            if ($binDir -and (Test-Writable $binDir)) {
                New-LocalRecord -Check 'ModifiableService' -Category 'Local Privilege Escalation' `
                    -Item $service.Name `
                    -Detail "Binary directory writable by current user: $binDir ; Account: $($service.StartName)" `
                    -RiskHint 'Replacing or planting the service binary yields code execution in the service account context.'
            }
        }
    }
    catch {
        Write-TJETLog WARNING "Service enumeration failed: $($_.Exception.Message)"
    }

    # ------------------------------------------------- AlwaysInstallElevated ---
    try {
        $hklm = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name AlwaysInstallElevated -ErrorAction SilentlyContinue
        $hkcu = Get-ItemProperty 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name AlwaysInstallElevated -ErrorAction SilentlyContinue

        if ($hklm.AlwaysInstallElevated -eq 1 -and $hkcu.AlwaysInstallElevated -eq 1) {
            New-LocalRecord -Check 'AlwaysInstallElevated' -Category 'Local Privilege Escalation' `
                -Item 'AlwaysInstallElevated' `
                -Detail 'Both HKLM and HKCU AlwaysInstallElevated are set to 1.' `
                -RiskHint 'Any user can install an MSI that executes as SYSTEM. Direct local privilege escalation.'
        }
    }
    catch {
        Write-Verbose "AlwaysInstallElevated check skipped: $($_.Exception.Message)"
    }

    # ------------------------------------------------------ Writable PATH dirs ---
    # [FIX] Use the MACHINE PATH, not $env:PATH. The process PATH includes the user's own
    # per-user PATH entries (e.g. ...\AppData\Local\Microsoft\WindowsApps), and a user
    # being able to write inside their OWN profile is not privilege escalation -- it was
    # producing a false LOCAL-004 on every run. Only a writable directory on the
    # machine-wide PATH is a route a non-privileged user could use against a privileged
    # process, and self-owned profile paths are excluded explicitly.
    try {
        $machinePathForDirs = [Environment]::GetEnvironmentVariable('Path', 'Machine')
        $userProfile = $env:USERPROFILE

        foreach ($dir in ($machinePathForDirs -split ';' | Where-Object { $_ -and $_.Trim() })) {

            $dir = $dir.Trim()

            # Skip anything under the current user's profile -- writing to your own
            # profile is not escalation.
            if ($userProfile -and $dir -like "$userProfile*") { continue }

            if (Test-Writable $dir) {
                New-LocalRecord -Check 'WritablePathDir' -Category 'Local Privilege Escalation' `
                    -Item $dir `
                    -Detail "Directory on the machine %PATH% is writable by a non-privileged user" `
                    -RiskHint 'Planting a DLL or a shadowing executable here can hijack processes that resolve names via PATH.'
            }
        }
    }
    catch {
        Write-Verbose "PATH check skipped: $($_.Exception.Message)"
    }

    # ---------------------------------------------------------------- Autoruns ---
    $autorunKeys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
        'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run'
    )

    foreach ($key in $autorunKeys) {

        try {
            $entries = Get-ItemProperty $key -ErrorAction SilentlyContinue

            if (-not $entries) { continue }

            foreach ($property in $entries.PSObject.Properties) {

                if ($property.Name -match '^PS') { continue }

                $command = "$($property.Value)"

                if ($command -match '([A-Za-z]:\\[^"]+?\.exe)') {

                    $dir = Split-Path $Matches[1] -Parent

                    if (Test-Writable $dir) {
                        New-LocalRecord -Check 'Autorun' -Category 'Local Privilege Escalation' `
                            -Item $property.Name `
                            -Detail "Autorun target in a writable directory: $command" `
                            -RiskHint 'Replacing the autorun target executes code the next time the triggering user logs on.'
                    }
                }
            }
        }
        catch {
            Write-Verbose "Autorun key $key skipped."
        }
    }

    # ------------------------------------------------------ Stored credentials ---
    # [FIX] Unattend/sysprep answer files are covered by the dedicated LOCAL-015
    # (UnattendFile) check in the extended collector, which also inspects them for an
    # actual <Password> element. Listing them here too produced TWO findings for one
    # file (LOCAL-006 High + LOCAL-015 Critical). LOCAL-006 now covers only the GPP /
    # Group Policy credential locations that LOCAL-015 does not touch.
    $credentialLocations = @(
        "$env:WINDIR\System32\GroupPolicy\Groups.xml"
        "$env:ProgramData\Microsoft\Group Policy\History"
    )

    foreach ($location in $credentialLocations) {
        if (Test-Path $location) {
            New-LocalRecord -Check 'StoredCredential' -Category 'Credential Exposure' `
                -Item $location `
                -Detail 'File that historically contains plaintext or reversibly-encrypted credentials is present.' `
                -RiskHint 'Group Policy Preferences files can contain the AES-encrypted "cpassword" whose key Microsoft published, making it trivially recoverable offline.'
        }
    }

    # Registry autologon
    try {
        $winlogon = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -ErrorAction SilentlyContinue

        if ($winlogon.DefaultPassword) {
            New-LocalRecord -Check 'StoredCredential' -Category 'Credential Exposure' `
                -Item 'Winlogon DefaultPassword' `
                -Detail "Autologon password stored in the registry for user $($winlogon.DefaultUserName)." `
                -RiskHint 'The password is readable in cleartext by any local user.'
        }
    }
    catch {
        Write-Verbose 'Winlogon check skipped.'
    }

    # ----------------------------------------------------- Token privileges ---
    if (-not $SkipTokenChecks) {
        try {
            $whoami = whoami /priv 2>$null

            $dangerousPrivileges = @{
                'SeImpersonatePrivilege'      = 'Potato-family attacks escalate to SYSTEM.'
                'SeAssignPrimaryTokenPrivilege' = 'Token assignment enables SYSTEM impersonation.'
                'SeBackupPrivilege'           = 'Read any file, including SAM/SYSTEM hives and NTDS.dit.'
                'SeRestorePrivilege'          = 'Write any file; can overwrite protected binaries.'
                'SeTakeOwnershipPrivilege'    = 'Take ownership of any object, then rewrite its ACL.'
                'SeDebugPrivilege'            = 'Access any process, including LSASS, for credential theft.'
                'SeLoadDriverPrivilege'       = 'Load a driver to execute code in kernel context.'
                'SeTcbPrivilege'              = 'Act as part of the operating system.'
            }

            foreach ($privilege in $dangerousPrivileges.Keys) {

                $line = $whoami | Where-Object { $_ -match [regex]::Escape($privilege) }

                if ($line -and $line -match '(?i)Enabled') {
                    New-LocalRecord -Check 'TokenPrivilege' -Category 'Local Privilege Escalation' `
                        -Item $privilege `
                        -Detail "Current token holds $privilege (Enabled) as $currentUser." `
                        -RiskHint $dangerousPrivileges[$privilege]
                }
            }
        }
        catch {
            Write-Verbose "Token privilege check skipped: $($_.Exception.Message)"
        }
    }

    # ------------------------------------------------------------- UAC config ---
    try {
        $uac = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -ErrorAction Stop

        if ($uac.EnableLUA -ne 1) {
            New-LocalRecord -Check 'UACConfig' -Category 'Host Hardening' `
                -Item 'EnableLUA' `
                -Detail 'User Account Control is disabled (EnableLUA=0).' `
                -RiskHint 'Elevation prompts are bypassed; any process runs with the full admin token.'
        }

        if ($uac.FilterAdministratorToken -ne 1) {
            New-LocalRecord -Check 'UACConfig' -Category 'Host Hardening' `
                -Item 'FilterAdministratorToken' `
                -Detail 'The built-in Administrator is not token-filtered by UAC.' `
                -RiskHint 'Remote logons as the built-in Administrator receive a full token, aiding lateral movement.'
        }
    }
    catch {
        Write-Verbose 'UAC check skipped.'
    }

    # ------------------------------------------------- Credential protection ---
    try {
        $wdigest = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name UseLogonCredential -ErrorAction SilentlyContinue

        if ($wdigest.UseLogonCredential -eq 1) {
            New-LocalRecord -Check 'CredentialProtection' -Category 'Host Hardening' `
                -Item 'WDigest UseLogonCredential' `
                -Detail 'WDigest is configured to keep cleartext credentials in memory (UseLogonCredential=1).' `
                -RiskHint 'Credentials are recoverable in cleartext from LSASS memory.'
        }

        $lsa = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -ErrorAction SilentlyContinue

        if ($lsa.RunAsPPL -ne 1) {
            New-LocalRecord -Check 'CredentialProtection' -Category 'Host Hardening' `
                -Item 'LSA Protection (RunAsPPL)' `
                -Detail 'LSASS is not running as a protected process (RunAsPPL is not 1).' `
                -RiskHint 'LSASS memory can be read by administrative tooling for credential theft.'
        }
    }
    catch {
        Write-Verbose 'Credential-protection check skipped.'
    }

    # ------------------------------------------------------------ SMB signing ---
    try {
        $smb = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name RequireSecuritySignature -ErrorAction SilentlyContinue

        if ($smb.RequireSecuritySignature -ne 1) {
            New-LocalRecord -Check 'SMBSigning' -Category 'Host Hardening' `
                -Item 'SMB Signing' `
                -Detail 'SMB signing is not required on this host.' `
                -RiskHint 'Enables SMB relay attacks for lateral movement and privilege escalation.'
        }
    }
    catch {
        Write-Verbose 'SMB signing check skipped.'
    }

    # --------------------------------------------------------- Legacy protocols ---
    try {
        $smb1 = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10' -Name Start -ErrorAction SilentlyContinue

        if ($smb1 -and $smb1.Start -ne 4) {
            New-LocalRecord -Check 'LegacyProtocol' -Category 'Host Hardening' `
                -Item 'SMBv1' `
                -Detail 'The SMBv1 client/server driver is not disabled.' `
                -RiskHint 'SMBv1 is unauthenticated-relay and wormable-exploit prone (for example EternalBlue).'
        }
    }
    catch {
        Write-Verbose 'SMBv1 check skipped.'
    }

    if (Test-Path "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe") {
        try {
            $v2 = Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2 -ErrorAction SilentlyContinue

            if ($v2 -and $v2.State -eq 'Enabled') {
                New-LocalRecord -Check 'LegacyProtocol' -Category 'Host Hardening' `
                    -Item 'PowerShell v2' `
                    -Detail 'The PowerShell v2 engine is enabled.' `
                    -RiskHint 'PowerShell v2 bypasses AMSI, script block logging and constrained language mode.'
            }
        }
        catch {
            Write-Verbose 'PowerShell v2 check skipped (needs elevation).'
        }
    }

    Write-TJETLog INFO 'Local host collection complete.'
}


# ==========================================================================
# SOURCE: Collectors\Collect-LocalHostAll.ps1
# ==========================================================================
function Collect-LocalHostAll {
<#
.SYNOPSIS
    Runs the full local host enumeration (core + extended WinPEAS-style checks).
.DESCRIPTION
    Both collectors emit the same record shape, so they merge into one
    AD_LocalHost_Audit.csv and are consumed by one detector.

    Each is isolated: if the extended set fails on an unusual Windows build, the core
    checks still produce output rather than the whole local surface disappearing.
#>
    [CmdletBinding()]
    param()

    try {
        Collect-LocalHost
    }
    catch {
        Write-TJETLog ERROR "Core local host checks failed: $($_.Exception.Message)"
    }

    try {
        Collect-LocalHostExtended
    }
    catch {
        Write-TJETLog ERROR "Extended local host checks failed: $($_.Exception.Message)"
    }

    try {
        Collect-SoftwareInventory
    }
    catch {
        Write-TJETLog ERROR "Software inventory failed: $($_.Exception.Message)"
    }

    try {
        Collect-OpenPorts
    }
    catch {
        Write-TJETLog ERROR "Open port enumeration failed: $($_.Exception.Message)"
    }

    try {
        # Modules are captured only when the filesystem cred scan is also on, as a proxy
        # for "deep local review"; otherwise the process list stays fast.
        Collect-RunningProcesses -IncludeModules:([bool]$script:TJETConfig.EnableFilesystemCredentialScan)
    }
    catch {
        Write-TJETLog ERROR "Process inventory failed: $($_.Exception.Message)"
    }

    if ($script:TJETConfig.EnableFilesystemCredentialScan) {
        try {
            Collect-FilesystemCredentials
        }
        catch {
            Write-TJETLog ERROR "Filesystem credential scan failed: $($_.Exception.Message)"
        }
    }
}


# ==========================================================================
# SOURCE: Collectors\Collect-LocalHostExtended.ps1
# ==========================================================================
function Collect-LocalHostExtended {
<#
.SYNOPSIS
    Extended WinPEAS-style local enumeration: credential stores, hijack paths, and
    host exposure.
.DESCRIPTION
    Companion to Collect-LocalHost. Emits the SAME record shape (Check, Category, Item,
    Detail, Risk_Hint, Is_Elevated_Scan, Scanned_Host) so both feed one detector and one
    remediation table.

    Detection only. Nothing here exploits anything, decrypts anything, or reads a
    secret's value -- it reports that a credential store EXISTS and is reachable, which
    is what a defender needs in order to remove it. Reporting the location is
    actionable; printing the contents into a report that gets emailed around is not.

    Checks added here (Check name -> what it looks for):

        ScheduledTask        tasks whose action binary sits in a user-writable path
        DLLHijack            writable directories referenced by service binaries
        PowerShellHistory    PSReadline history containing credential-like lines
        UnattendFile         unattend/sysprep/answer files left on disk
        CloudCredential      .aws, .azure, gcloud credential files
        SSHKey               private keys in .ssh
        SessionManager       saved PuTTY/WinSCP/RDP sessions and stored passwords
        RegistryCredential   VNC, SNMP, autologon and similar credential registry keys
        AccessibilityBackdoor sethc/utilman debugger hijacks and binary replacement
        WSUSConfig           WSUS served over cleartext HTTP
        RDPConfig            RDP enabled with NLA disabled
        DefenderStatus       real-time protection / tamper protection disabled
        FirewallProfile      a firewall profile that is off
        SpoolerService       Print Spooler running (PrintNightmare / relay surface)
        LocalAdminMember     non-default members of the local Administrators group
        ShareExposure        non-administrative shares and their permissions
#>
    [CmdletBinding()]
    param()

    $isElevated = ([Security.Principal.WindowsPrincipal] `
        [Security.Principal.WindowsIdentity]::GetCurrent()
        ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    function New-LocalRecord {
        param($Check, $Category, $Item, $Detail, $RiskHint)

        [PSCustomObject]@{
            Check             = $Check
            Category          = $Category
            Item              = $Item
            Detail            = $Detail
            Risk_Hint         = $RiskHint
            Is_Elevated_Scan  = $isElevated
            Is_Admin_Member  = $isElevated
            Scanned_Host      = $env:COMPUTERNAME
            Schema_Version    = $script:TJETConfig.SchemaVersion
            Collector_Version = $script:TJETConfig.CollectorVersion
        }
    }

    # [FIX] ACL/principal-based writability, matching Collect-LocalHost. Probing with
    # the current token reports what the OPERATOR can do -- misleading when the operator
    # is an unelevated admin. This returns true only when a NON-PRIVILEGED principal has
    # a write-class right, so findings reflect what a standard user could exploit.
    $nonPrivilegedSids = @('S-1-1-0','S-1-5-11','S-1-5-32-545','S-1-5-4','S-1-5-32-546','S-1-5-7')

    function Test-UserWritable {
        param([string]$TargetPath)

        if ([string]::IsNullOrWhiteSpace($TargetPath)) { return $false }
        if (-not (Test-Path $TargetPath)) { return $false }

        try {
            $acl = Get-Acl -Path $TargetPath -ErrorAction Stop
        }
        catch {
            return $false
        }

        foreach ($ace in $acl.Access) {

            if ($ace.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { continue }

            $sid = $null
            try {
                if ($ace.IdentityReference -is [System.Security.Principal.SecurityIdentifier]) {
                    $sid = $ace.IdentityReference.Value
                }
                else {
                    $sid = $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
                }
            }
            catch { $sid = "$($ace.IdentityReference)" }

            $isNonPriv = $false
            if ($nonPrivilegedSids -contains $sid) {
                $isNonPriv = $true
            }
            elseif ($sid -match '^S-1-5-21-.+-(\d+)$') {
                $rid = [int]$Matches[1]
                if ($rid -notin 500, 512, 516, 518, 519, 544) { $isNonPriv = $true }
            }

            if (-not $isNonPriv) { continue }

            $w = [System.Security.AccessControl.FileSystemRights]::CreateFiles `
                -bor [System.Security.AccessControl.FileSystemRights]::CreateDirectories

            if (([int]$ace.FileSystemRights -band [int]$w) -ne 0) { return $true }
        }

        return $false
    }

    # Directories any standard user can write to -- the classic planting grounds.
    # (Removed $userWritableRoots -- the hardcoded-directory DLLHijack probe it fed was
    # retired; see the DLL hijack note below.)

    # -------------------------------------------------------- Scheduled tasks ---
    try {
        $tasks = Get-ScheduledTask -ErrorAction Stop |
            Where-Object { $_.State -ne 'Disabled' }

        foreach ($task in $tasks) {

            $principal = "$($task.Principal.UserId)"

            # Only tasks that run as something privileged are interesting.
            if ($principal -notmatch '(?i)SYSTEM|Administrator|NETWORK SERVICE|LOCAL SERVICE') { continue }

            foreach ($action in @($task.Actions)) {

                $execute = "$($action.Execute)"

                if ([string]::IsNullOrWhiteSpace($execute)) { continue }

                $binary = $execute.Trim('"')
                $folder = Split-Path $binary -Parent -ErrorAction SilentlyContinue

                if (-not $folder) { continue }

                if (Test-UserWritable $folder) {

                    New-LocalRecord -Check 'ScheduledTask' -Category 'Local PrivEsc' `
                        -Item "$($task.TaskPath)$($task.TaskName)" `
                        -Detail "Scheduled task runs as '$principal' from a user-writable directory: $folder" `
                        -RiskHint 'Replacing the task binary yields code execution as the task principal.'
                }
            }
        }
    }
    catch {
        Write-Verbose "Scheduled task enumeration failed: $($_.Exception.Message)"
    }

    # ------------------------------------------------- DLL hijack opportunities ---
    # [FIX] This check previously probed a hardcoded list of temp/profile directories and
    # fired on every host (several are writable by Authenticated Users BY DESIGN on a
    # default install). It is also redundant: writable *service binary* directories are
    # already reported by LOCAL-002 (ModifiableService), and writable *machine PATH*
    # directories by LOCAL-004 (WritablePathDir). Rather than re-flag the same conditions
    # under a third ID -- which is what produced the C:\, C:\ProgramData, C:\Windows\Temp
    # noise -- LOCAL-013 is retired in favour of those two targeted checks.
    #
    # (Intentionally no emission here. LOCAL-002 and LOCAL-004 cover the real routes.)

    # ---------------------------------------------------- PowerShell history ---
    try {
        $historyPaths = @(
            (Join-Path $env:APPDATA 'Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt')
        )

        foreach ($userDir in (Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue)) {
            $historyPaths += Join-Path $userDir.FullName 'AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt'
        }

        foreach ($historyPath in ($historyPaths | Select-Object -Unique)) {

            if (-not (Test-Path $historyPath)) { continue }

            # NOTE: not $matches -- that is an automatic variable populated by -match,
            # and overwriting it corrupts regex captures elsewhere in the same scope.
            $historyHits = Select-String -Path $historyPath `
                -Pattern '(?i)(-Password|ConvertTo-SecureString|-AsPlainText|net user .+ /add|psexec .*-p |cmdkey .*/pass)' `
                -ErrorAction SilentlyContinue

            if ($historyHits) {

                New-LocalRecord -Check 'PowerShellHistory' -Category 'Credential Exposure' `
                    -Item $historyPath `
                    -Detail "PowerShell history contains $(@($historyHits).Count) credential-like command(s)" `
                    -RiskHint 'Console history persists plaintext arguments. Anyone who can read the file inherits the credentials.'
            }
        }
    }
    catch {
        Write-Verbose "PowerShell history check failed: $($_.Exception.Message)"
    }

    # ------------------------------------------------------- Unattend answers ---
    try {
        $unattendPaths = @(
            'C:\Windows\Panther\Unattend.xml'
            'C:\Windows\Panther\Unattended.xml'
            'C:\Windows\Panther\Unattend\Unattend.xml'
            'C:\Windows\System32\Sysprep\Unattend.xml'
            'C:\Windows\System32\Sysprep\Panther\Unattend.xml'
            'C:\unattend.xml'
            'C:\sysprep.inf'
            'C:\sysprep\sysprep.xml'
        )

        foreach ($unattendPath in $unattendPaths) {

            if (-not (Test-Path $unattendPath)) { continue }

            $hasPassword = $false

            try {
                $hasPassword = [bool](Select-String -Path $unattendPath -Pattern '<Password>|<AdministratorPassword>' -ErrorAction SilentlyContinue)
            }
            catch { }

            $detail = if ($hasPassword) {
                "Answer file present and contains a password element: $unattendPath"
            }
            else {
                "Deployment answer file left on disk: $unattendPath"
            }

            New-LocalRecord -Check 'UnattendFile' -Category 'Credential Exposure' `
                -Item $unattendPath `
                -Detail $detail `
                -RiskHint 'Answer files commonly retain the local administrator password in plaintext or base64.'
        }
    }
    catch {
        Write-Verbose "Unattend file check failed: $($_.Exception.Message)"
    }

    # --------------------------------------------------- Cloud credentials ---
    try {
        foreach ($userDir in (Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue)) {

            $cloudPaths = @(
                @{ Path = Join-Path $userDir.FullName '.aws\credentials';               Kind = 'AWS access keys' }
                @{ Path = Join-Path $userDir.FullName '.azure\accessTokens.json';        Kind = 'Azure access tokens' }
                @{ Path = Join-Path $userDir.FullName '.azure\azureProfile.json';        Kind = 'Azure profile' }
                @{ Path = Join-Path $userDir.FullName 'AppData\Roaming\gcloud\credentials.db'; Kind = 'GCP credentials' }
                @{ Path = Join-Path $userDir.FullName '.docker\config.json';             Kind = 'Docker registry auth' }
                @{ Path = Join-Path $userDir.FullName '.kube\config';                    Kind = 'Kubernetes config' }
            )

            foreach ($cloud in $cloudPaths) {

                if (-not (Test-Path $cloud.Path)) { continue }

                New-LocalRecord -Check 'CloudCredential' -Category 'Credential Exposure' `
                    -Item $cloud.Path `
                    -Detail "$($cloud.Kind) file present for user $($userDir.Name)" `
                    -RiskHint 'Cloud credential files grant access beyond this host and often outlive the account that created them.'
            }

            # ------------------------------------------------------- SSH keys ---
            $sshDir = Join-Path $userDir.FullName '.ssh'

            if (Test-Path $sshDir) {

                $keys = Get-ChildItem $sshDir -File -ErrorAction SilentlyContinue |
                    Where-Object { $_.Name -match '^id_(rsa|dsa|ecdsa|ed25519)$' }

                foreach ($key in $keys) {

                    New-LocalRecord -Check 'SSHKey' -Category 'Credential Exposure' `
                        -Item $key.FullName `
                        -Detail "SSH private key present for user $($userDir.Name)" `
                        -RiskHint 'An unencrypted private key grants access to every host trusting it.'
                }
            }
        }
    }
    catch {
        Write-Verbose "Cloud/SSH credential check failed: $($_.Exception.Message)"
    }

    # -------------------------------------------- Saved sessions and managers ---
    try {
        $puttySessions = 'HKCU:\Software\SimonTatham\PuTTY\Sessions'

        if (Test-Path $puttySessions) {

            foreach ($session in (Get-ChildItem $puttySessions -ErrorAction SilentlyContinue)) {

                $props = Get-ItemProperty $session.PSPath -ErrorAction SilentlyContinue

                New-LocalRecord -Check 'SessionManager' -Category 'Credential Exposure' `
                    -Item "PuTTY: $($session.PSChildName)" `
                    -Detail "Saved PuTTY session to $($props.HostName) as $($props.UserName)" `
                    -RiskHint 'Saved sessions disclose internal hosts and usernames; some store proxy passwords in cleartext.'
            }
        }

        $winScp = 'HKCU:\Software\Martin Prikryl\WinSCP 2\Sessions'

        if (Test-Path $winScp) {

            foreach ($session in (Get-ChildItem $winScp -ErrorAction SilentlyContinue)) {

                $props = Get-ItemProperty $session.PSPath -ErrorAction SilentlyContinue
                $stored = if ($props.Password) { ' with a stored password' } else { '' }

                New-LocalRecord -Check 'SessionManager' -Category 'Credential Exposure' `
                    -Item "WinSCP: $($session.PSChildName)" `
                    -Detail "Saved WinSCP session to $($props.HostName)$stored" `
                    -RiskHint 'WinSCP stores session passwords with reversible obfuscation, not encryption.'
            }
        }

        $rdpServers = 'HKCU:\Software\Microsoft\Terminal Server Client\Servers'

        if (Test-Path $rdpServers) {

            $servers = @(Get-ChildItem $rdpServers -ErrorAction SilentlyContinue)

            if ($servers.Count -gt 0) {

                New-LocalRecord -Check 'SessionManager' -Category 'Credential Exposure' `
                    -Item 'RDP connection history' `
                    -Detail "$($servers.Count) saved RDP destination(s): $(($servers.PSChildName | Select-Object -First 8) -join ', ')" `
                    -RiskHint 'RDP history maps lateral-movement targets and the usernames used against them.'
            }
        }
    }
    catch {
        Write-Verbose "Session manager check failed: $($_.Exception.Message)"
    }

    # --------------------------------------------------- Registry credentials ---
    try {
        $registryCredentials = @(
            @{ Path = 'HKLM:\SOFTWARE\RealVNC\WinVNC4';                          Name = 'Password';        Kind = 'VNC password' }
            @{ Path = 'HKLM:\SOFTWARE\TightVNC\Server';                          Name = 'Password';        Kind = 'TightVNC password' }
            @{ Path = 'HKCU:\Software\ORL\WinVNC3';                              Name = 'Password';        Kind = 'VNC password' }
            @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities'; Name = $null; Kind = 'SNMP community string' }
            @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'; Name = 'DefaultPassword'; Kind = 'Autologon password' }
        )

        foreach ($entry in $registryCredentials) {

            if (-not (Test-Path $entry.Path)) { continue }

            if ($entry.Name) {

                $value = Get-ItemProperty -Path $entry.Path -Name $entry.Name -ErrorAction SilentlyContinue

                if ($null -eq $value -or -not $value.($entry.Name)) { continue }
            }

            New-LocalRecord -Check 'RegistryCredential' -Category 'Credential Exposure' `
                -Item "$($entry.Path)\$($entry.Name)" `
                -Detail "$($entry.Kind) present in the registry" `
                -RiskHint 'Registry-stored credentials are readable by any principal with read access to the key, and are often only obfuscated.'
        }
    }
    catch {
        Write-Verbose "Registry credential check failed: $($_.Exception.Message)"
    }

    # ------------------------------------------------ Accessibility backdoors ---
    try {
        $accessibilityBinaries = 'sethc.exe','utilman.exe','osk.exe','magnify.exe','narrator.exe','displayswitch.exe'

        foreach ($binary in $accessibilityBinaries) {

            $debuggerKey = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$binary"

            if (Test-Path $debuggerKey) {

                $debugger = (Get-ItemProperty $debuggerKey -Name Debugger -ErrorAction SilentlyContinue).Debugger

                if ($debugger) {

                    New-LocalRecord -Check 'AccessibilityBackdoor' -Category 'Persistence' `
                        -Item $binary `
                        -Detail "Image File Execution Options debugger set on $binary -> $debugger" `
                        -RiskHint 'A debugger on an accessibility binary yields SYSTEM from the logon screen without authenticating.'
                }
            }
        }
    }
    catch {
        Write-Verbose "Accessibility backdoor check failed: $($_.Exception.Message)"
    }

    # ------------------------------------------------------------- WSUS / RDP ---
    try {
        $wsus = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -Name WUServer -ErrorAction SilentlyContinue

        if ($wsus -and $wsus.WUServer -match '^http://') {

            New-LocalRecord -Check 'WSUSConfig' -Category 'Host Hardening' `
                -Item $wsus.WUServer `
                -Detail "WSUS is configured over cleartext HTTP: $($wsus.WUServer)" `
                -RiskHint 'An attacker positioned on the network can inject a malicious update package that installs as SYSTEM.'
        }
    }
    catch { }

    try {
        $rdp = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -ErrorAction SilentlyContinue

        if ($rdp -and $rdp.fDenyTSConnections -eq 0) {

            $nla = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' `
                -Name UserAuthentication -ErrorAction SilentlyContinue

            if ($nla -and $nla.UserAuthentication -eq 0) {

                New-LocalRecord -Check 'RDPConfig' -Category 'Host Hardening' `
                    -Item 'RDP-Tcp' `
                    -Detail 'RDP is enabled with Network Level Authentication disabled' `
                    -RiskHint 'Without NLA the host performs pre-authentication work for unauthenticated clients, widening the attack surface.'
            }
        }
    }
    catch { }

    # ------------------------------------------------------ Defender/firewall ---
    try {
        $defender = Get-MpComputerStatus -ErrorAction Stop

        if (-not $defender.RealTimeProtectionEnabled) {

            New-LocalRecord -Check 'DefenderStatus' -Category 'Host Hardening' `
                -Item 'Microsoft Defender' `
                -Detail 'Real-time protection is disabled' `
                -RiskHint 'Disabled real-time protection removes the primary barrier to tooling execution and is a common post-compromise action.'
        }

        if ($defender.PSObject.Properties.Name -contains 'IsTamperProtected' -and -not $defender.IsTamperProtected) {

            New-LocalRecord -Check 'DefenderStatus' -Category 'Host Hardening' `
                -Item 'Microsoft Defender' `
                -Detail 'Tamper protection is disabled' `
                -RiskHint 'Without tamper protection an administrator-level process can silently disable Defender.'
        }
    }
    catch {
        Write-Verbose "Defender status unavailable: $($_.Exception.Message)"
    }

    try {
        foreach ($profile in (Get-NetFirewallProfile -ErrorAction Stop)) {

            if (-not $profile.Enabled) {

                New-LocalRecord -Check 'FirewallProfile' -Category 'Host Hardening' `
                    -Item "$($profile.Name) profile" `
                    -Detail "Windows Firewall is disabled for the $($profile.Name) profile" `
                    -RiskHint 'A disabled profile exposes local services to the network segment the host is attached to.'
            }
        }
    }
    catch {
        Write-Verbose "Firewall profile check failed: $($_.Exception.Message)"
    }

    # --------------------------------------------------------- Spooler / shares ---
    try {
        $spooler = Get-Service -Name Spooler -ErrorAction SilentlyContinue

        if ($spooler -and $spooler.Status -eq 'Running') {

            New-LocalRecord -Check 'SpoolerService' -Category 'Host Hardening' `
                -Item 'Print Spooler' `
                -Detail 'Print Spooler service is running' `
                -RiskHint 'The spooler is the surface for PrintNightmare-class bugs and for coercing machine authentication (relay).'
        }
    }
    catch { }

    try {
        $shares = Get-CimInstance -ClassName Win32_Share -ErrorAction Stop |
            Where-Object { $_.Name -notmatch '\$$' }

        foreach ($share in $shares) {

            New-LocalRecord -Check 'ShareExposure' -Category 'Host Hardening' `
                -Item "$($share.Name) -> $($share.Path)" `
                -Detail "Non-administrative share '$($share.Name)' published at $($share.Path)" `
                -RiskHint 'Review share and NTFS permissions; user-writable shares are a common planting and staging point.'
        }
    }
    catch {
        Write-Verbose "Share enumeration failed: $($_.Exception.Message)"
    }

    # ------------------------------------------------ Local Administrators ---
    try {
        $members = Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop

        foreach ($member in $members) {

            # Domain Admins and the built-in Administrator are expected here.
            if ("$($member.Name)" -match '(?i)\\(Administrator|Domain Admins|Enterprise Admins)$') { continue }

            New-LocalRecord -Check 'LocalAdminMember' -Category 'Local PrivEsc' `
                -Item "$($member.Name)" `
                -Detail "Non-default member of the local Administrators group: $($member.Name) ($($member.ObjectClass))" `
                -RiskHint 'Every extra local administrator is another account whose compromise yields SYSTEM on this host.'
        }
    }
    catch {
        Write-Verbose "Local Administrators enumeration failed: $($_.Exception.Message)"
    }

    Write-TJETLog INFO 'Extended local host collection complete.'
}


# ==========================================================================
# SOURCE: Collectors\Collect-RunningProcesses.ps1
# ==========================================================================
function Collect-RunningProcesses {
<#
.SYNOPSIS
    Inventories running processes with full detail, so network listeners can be tied to
    the process behind them.
.DESCRIPTION
    Collect-OpenPorts records an owning PID per listener; this collector makes that PID
    meaningful by capturing, for every process:

        PID, parent PID, name, and the full executable path
        the complete command line (arguments included)
        the owning user
        the company/description/version of the on-disk image
        a signed/unsigned indication where obtainable
        the loaded module (DLL) list

    Command lines are where a lot of the value is: scheduled-task wrappers,
    service invocations, and pasted credentials all surface here. Modules matter for
    hijack analysis -- an unsigned DLL loaded from a user-writable path into a service
    process is a finding on its own.

    The port and process CSVs share the PID column, so a reviewer (or the report) can
    join "TCP 445 -> PID 4" to "PID 4 = System, C:\\Windows\\System32\\..., signed".

    Everything is best-effort: command line and owner require a WMI/CIM query that can
    be denied for protected processes, and module enumeration fails for processes the
    scanner cannot open. Each is wrapped so one inaccessible process does not abort the
    collector; the field is recorded as '(access denied)' instead.
.PARAMETER IncludeModules
    Capture the loaded-module list per process. Off by default because it is slow on a
    busy host (hundreds of processes x dozens of modules); enable when doing hijack
    analysis.
#>
    [CmdletBinding()]
    param(
        [switch]$IncludeModules
    )

    # One CIM query for command line + parent + owner, keyed by PID, rather than a
    # per-process query (which would be far slower).
    $cimByPid = @{}

    try {
        $cimProcesses = Get-CimInstance -ClassName Win32_Process -ErrorAction Stop

        foreach ($cim in $cimProcesses) {
            $cimByPid[[int]$cim.ProcessId] = $cim
        }
    }
    catch {
        Write-TJETLog WARNING "Win32_Process query failed; command lines will be unavailable: $($_.Exception.Message)"
    }

    # Owner lookup is a separate CIM method call; cache it per PID.
    $ownerByPid = @{}

    function Get-ProcessOwner {
        param($CimProcess)

        if ($null -eq $CimProcess) { return '' }

        $processId = [int]$CimProcess.ProcessId

        if ($ownerByPid.ContainsKey($processId)) { return $ownerByPid[$processId] }

        $owner = ''

        try {
            $result = Invoke-CimMethod -InputObject $CimProcess -MethodName GetOwner -ErrorAction Stop

            if ($result.User) {
                $owner = "$($result.Domain)\$($result.User)".TrimStart('\')
            }
        }
        catch {
            $owner = '(access denied)'
        }

        $ownerByPid[$processId] = $owner
        return $owner
    }

    $processes = Get-Process -ErrorAction SilentlyContinue

    foreach ($process in $processes) {

        $cim = $cimByPid[[int]$process.Id]

        # --- path and file metadata -----------------------------------------
        $path        = ''
        $company     = ''
        $description = ''
        $fileVersion = ''

        try {
            if ($process.Path) {
                $path = $process.Path
            }
            elseif ($cim -and $cim.ExecutablePath) {
                $path = $cim.ExecutablePath
            }
        }
        catch { }

        if ($process.MainModule -and $process.MainModule.FileVersionInfo) {
            try {
                $info        = $process.MainModule.FileVersionInfo
                $company     = "$($info.CompanyName)".Trim()
                $description = "$($info.FileDescription)".Trim()
                $fileVersion = "$($info.FileVersion)".Trim()
            }
            catch { }
        }

        # --- signing state (best effort) ------------------------------------
        $signed = 'unknown'

        if ($path -and (Test-Path $path)) {
            try {
                $signature = Get-AuthenticodeSignature -FilePath $path -ErrorAction Stop
                $signed = "$($signature.Status)"
            }
            catch {
                $signed = 'unknown'
            }
        }

        # --- command line and owner -----------------------------------------
        $commandLine = ''
        $parentPid   = ''

        if ($cim) {
            $commandLine = "$($cim.CommandLine)".Trim()
            $parentPid   = "$($cim.ParentProcessId)"
        }

        $owner = Get-ProcessOwner $cim

        # --- suspicious-path heuristic --------------------------------------
        # A process running from a user-writable location is worth surfacing.
        $fromUserWritable = $false

        if ($path -match '(?i)\\(Users|Temp|AppData|ProgramData|Public|Downloads)\\') {
            $fromUserWritable = $true
        }

        $processRiskHint = ''
        if ($fromUserWritable) { $processRiskHint = 'Process image is in a user-writable location.' }

        $record = [PSCustomObject]@{
            Check              = 'RunningProcess'
            Category           = 'Process Inventory'
            Item               = "$($process.ProcessName) (PID $($process.Id))"
            Detail             = "$($process.ProcessName) PID $($process.Id) -> $path"
            Risk_Hint          = $processRiskHint
            Process_PID        = $process.Id
            Process_Parent_PID = $parentPid
            Process_Name       = $process.ProcessName
            Process_Path       = $path
            Process_CommandLine = $commandLine
            Process_Owner      = $owner
            Process_Company    = $company
            Process_Description = $description
            Process_FileVersion = $fileVersion
            Process_Signed     = $signed
            Process_FromUserWritable = $fromUserWritable
            Process_Modules    = ''
            Process_Module_Count = 0
            Is_Elevated_Scan   = $false
            Is_Admin_Member    = $false
            Scanned_Host       = $env:COMPUTERNAME
            Schema_Version     = $script:TJETConfig.SchemaVersion
            Collector_Version  = $script:TJETConfig.CollectorVersion
        }

        # --- modules (optional, slow) ---------------------------------------
        if ($IncludeModules) {
            try {
                $modules = @($process.Modules | ForEach-Object { $_.ModuleName })
                $record.Process_Modules     = ($modules -join ' | ')
                $record.Process_Module_Count = $modules.Count
            }
            catch {
                $record.Process_Modules = '(access denied)'
            }
        }

        $record
    }

    Write-TJETLog INFO 'Running process inventory complete.'
}


# ==========================================================================
# SOURCE: Collectors\Collect-ServiceAccounts.ps1
# ==========================================================================
function Collect-ServiceAccounts {
<#
.SYNOPSIS
    Collects managed service accounts (gMSA and sMSA) -- via ADSI, no RSAT.
.DESCRIPTION
    [ADSI REWRITE] gMSA/sMSA are msDS-GroupManagedServiceAccount / msDS-ManagedServiceAccount
    objects. Output contract unchanged, so GMSA-001 is unaffected.

    The important ADSI detail: the AD module's PrincipalsAllowedToRetrieveManagedPassword
    is a friendly projection of msDS-GroupMSAMembership, which on the wire is a SECURITY
    DESCRIPTOR blob, not a DN list. This parses that SD's DACL and extracts the SIDs of
    principals granted access, then resolves each SID to a name. All three forms (SID,
    resolved name, raw) are emitted, exactly as before, so GMSA-001's name/DN/SID
    matching all keep working.
#>
    [CmdletBinding()]
    param(
        [string]$Server,
        [System.Management.Automation.PSCredential]$Credential
    )

    $ctx = Get-TJETDirectoryContext -Server:$Server -Credential:$Credential

    # Resolve a SID string to a friendly name via a directory lookup (best-effort).
    function Resolve-SidName {
        param([string]$Sid)
        if ([string]::IsNullOrWhiteSpace($Sid)) { return '' }
        try {
            $s = $ctx.NewSearcher("(objectSid=$Sid)", @('sAMAccountName','name'), $ctx.DefaultNC, 'Subtree')
            $r = $s.FindOne()
            $s.Dispose()
            if ($r) {
                if ($r.Properties['samaccountname'].Count) { return "$($r.Properties['samaccountname'][0])" }
                if ($r.Properties['name'].Count) { return "$($r.Properties['name'][0])" }
            }
        }
        catch { }
        return $Sid
    }

    $properties = @(
        'distinguishedName','objectGUID','objectSid','sAMAccountName','dNSHostName',
        'objectClass','userAccountControl','servicePrincipalName','memberOf',
        'msDS-GroupMSAMembership','msDS-AllowedToDelegateTo','msDS-KeyCredentialLink'
    )

    # Both managed-account classes.
    $filter = '(|(objectClass=msDS-GroupManagedServiceAccount)(objectClass=msDS-ManagedServiceAccount))'
    $searcher = $ctx.NewSearcher($filter, $properties)
    $results = $searcher.FindAll()

    if ($results.Count -eq 0) {
        Write-TJETLog INFO 'No managed service accounts found.'
        $results.Dispose(); $searcher.Dispose()
        return
    }

    foreach ($result in $results) {

        $flat = Convert-TJETSearchResult $result
        $record = [ordered]@{}

        $uac = [int](Get-TJETLdapProperty $flat 'useraccountcontrol' 0)
        $objectClass = Get-TJETLdapProperty $flat 'objectclass'

        $record['DistinguishedName'] = Get-TJETLdapProperty $flat 'distinguishedname'
        $record['SamAccountName']    = Get-TJETLdapProperty $flat 'samaccountname'
        $record['DNSHostName']       = Get-TJETLdapProperty $flat 'dnshostname'
        $record['ObjectGUID']        = Get-TJETLdapProperty $flat 'objectguid'
        $record['ObjectSID']         = Get-TJETLdapProperty $flat 'objectsid'
        $record['Enabled']           = (-not (Test-TJETUacFlag $uac 'Disabled'))

        # --- retrieval principals: parse the msDS-GroupMSAMembership SD --------
        $principalSids = New-Object System.Collections.Generic.List[string]

        # The raw attribute is only available on the SearchResult as a byte[]; re-fetch
        # the DirectoryEntry to read the security descriptor cleanly.
        try {
            $entryPath = "$($ctx.Prefix)/$($record['DistinguishedName'])"
            $entry = if ($ctx.Credential) {
                New-Object System.DirectoryServices.DirectoryEntry($entryPath, $ctx.Credential.UserName, $ctx.Credential.GetNetworkCredential().Password)
            } else {
                New-Object System.DirectoryServices.DirectoryEntry($entryPath)
            }

            $sdBytes = $entry.Properties['msDS-GroupMSAMembership'].Value

            if ($sdBytes) {
                $sd = New-Object System.DirectoryServices.ActiveDirectorySecurity
                $sd.SetSecurityDescriptorBinaryForm([byte[]]$sdBytes)

                foreach ($ace in $sd.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
                    if ($ace.AccessControlType -eq 'Allow') {
                        $principalSids.Add("$($ace.IdentityReference.Value)")
                    }
                }
            }
        }
        catch { }

        $principalSids = @($principalSids | Select-Object -Unique)

        $record['Is_gMSA'] = [bool](
            ($objectClass -match '(?i)msDS-GroupManagedServiceAccount') -or
            ($principalSids.Count -gt 0)
        )

        $record['Retrieval_Principals']       = ($principalSids -join ';')
        $record['Retrieval_Principal_Count']  = $principalSids.Count

        $names = New-Object System.Collections.Generic.List[string]
        foreach ($sid in $principalSids) { $names.Add((Resolve-SidName $sid)) }
        $record['Retrieval_Principal_Names'] = ($names -join ';')

        $record['Has_SPNs'] = [bool](Get-TJETLdapProperty $flat 'serviceprincipalname')
        $record['Has_Unconstrained_Delegation'] = (Test-TJETUacFlag $uac 'TrustedForDelegation')
        $record['Has_Shadow_Credentials'] = [bool](Get-TJETLdapProperty $flat 'msds-keycredentiallink')

        [PSCustomObject]$record
    }

    $results.Dispose()
    $searcher.Dispose()
}


# ==========================================================================
# SOURCE: Collectors\Collect-SoftwareAndExposure.ps1
# ==========================================================================
function Collect-SoftwareInventory {
<#
.SYNOPSIS
    Inventories installed software with versions, plus applied patches, for offline CVE
    matching.
.DESCRIPTION
    Reads installed products from BOTH 64-bit and 32-bit Uninstall registry hives (the
    WOW6432Node view is where a lot of software actually registers) rather than
    Win32_Product, which is slow, triggers MSI reconfiguration, and misses non-MSI
    installs. Also captures applied hotfixes (Get-HotFix) and the OS build.

    Emits one record per product with DisplayName, DisplayVersion and Publisher. The CVE
    detector consumes these against an offline database; nothing here needs network
    access.

    Records use the same envelope as the other local collectors (Check, Category, Item,
    Detail, plus a Product/Version/Publisher triple the CVE matcher reads) so software
    inventory can travel in the same AD_LocalHost CSV, but the CVE detector reads the
    dedicated Software_* fields, not the free-text Detail.
#>
    [CmdletBinding()]
    param()

    function New-SoftwareRecord {
        param($Product, $Version, $Publisher, $Kind)

        [PSCustomObject]@{
            Check              = 'SoftwareInventory'
            Category           = 'Inventory'
            Item               = $Product
            Detail             = "$Product $Version ($Publisher)"
            Risk_Hint          = ''
            Software_Product   = $Product
            Software_Version   = $Version
            Software_Publisher = $Publisher
            Software_Kind      = $Kind
            Is_Elevated_Scan   = $false
            Is_Admin_Member  = $false
            Scanned_Host       = $env:COMPUTERNAME
            Schema_Version     = $script:TJETConfig.SchemaVersion
            Collector_Version  = $script:TJETConfig.CollectorVersion
        }
    }

    $uninstallKeys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )

    $seen = @{}

    foreach ($keyPath in $uninstallKeys) {

        try {
            $entries = Get-ItemProperty -Path $keyPath -ErrorAction SilentlyContinue
        }
        catch {
            continue
        }

        foreach ($entry in $entries) {

            $name = "$($entry.DisplayName)".Trim()

            if ([string]::IsNullOrWhiteSpace($name)) { continue }

            # Skip pure updates/hotfix rows here -- hotfixes are captured separately and
            # KB rows would otherwise flood the product list.
            if ($entry.PSObject.Properties.Name -contains 'SystemComponent' -and $entry.SystemComponent -eq 1) { continue }

            $version   = "$($entry.DisplayVersion)".Trim()
            $publisher = "$($entry.Publisher)".Trim()

            $dedupeKey = "$($name.ToLower())|$version"

            if ($seen.ContainsKey($dedupeKey)) { continue }
            $seen[$dedupeKey] = $true

            New-SoftwareRecord -Product $name -Version $version -Publisher $publisher -Kind 'Application'
        }
    }

    # ------------------------------------------------------------- OS build ---
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop

        New-SoftwareRecord -Product $os.Caption -Version $os.Version `
            -Publisher 'Microsoft Corporation' -Kind 'OperatingSystem'
    }
    catch {
        Write-Verbose "OS build capture failed: $($_.Exception.Message)"
    }

    # ------------------------------------------------------- Applied hotfixes ---
    # These let the CVE detector reason about "is patch X present" and let a reviewer
    # see how current the host is.
    try {
        $hotfixes = Get-HotFix -ErrorAction Stop

        $mostRecent = $hotfixes |
            Where-Object { $_.InstalledOn } |
            Sort-Object InstalledOn -Descending |
            Select-Object -First 1

        foreach ($hotfix in $hotfixes) {

            New-SoftwareRecord -Product "Hotfix $($hotfix.HotFixID)" `
                -Version "$($hotfix.HotFixID)" `
                -Publisher 'Microsoft Corporation' -Kind 'Hotfix'
        }

        if ($mostRecent) {

            $age = (New-TimeSpan -Start $mostRecent.InstalledOn -End (Get-Date)).Days

            $patchRiskHint = ''
            if ($age -gt 60) { $patchRiskHint = "Host is $age days behind on patching." }

            [PSCustomObject]@{
                Check              = 'PatchLevel'
                Category           = 'Host Hardening'
                Item               = 'Most recent hotfix'
                Detail             = "Latest patch $($mostRecent.HotFixID) installed $($mostRecent.InstalledOn.ToString('yyyy-MM-dd')) ($age days ago)"
                Risk_Hint          = $patchRiskHint
                Software_Product   = ''
                Software_Version   = ''
                Software_Publisher = ''
                Software_Kind      = 'PatchAge'
                Patch_Age_Days     = $age
                Is_Elevated_Scan   = $false
            Is_Admin_Member  = $false
                Scanned_Host       = $env:COMPUTERNAME
                Schema_Version     = $script:TJETConfig.SchemaVersion
                Collector_Version  = $script:TJETConfig.CollectorVersion
            }
        }
    }
    catch {
        Write-Verbose "Hotfix enumeration failed: $($_.Exception.Message)"
    }

    Write-TJETLog INFO 'Software inventory complete.'
}


function Collect-OpenPorts {
<#
.SYNOPSIS
    Enumerates listening TCP/UDP ports and maps them to owning processes and services.
.DESCRIPTION
    A listening port is attack surface. This records every listener, the process behind
    it, and whether it is bound to all interfaces (0.0.0.0 / ::) versus loopback only --
    the distinction between "reachable from the network" and "local only" is what makes a
    port interesting.

    The detector flags ports associated with commonly-abused or legacy-cleartext
    services (SMB, RDP, WinRM, RPC, LDAP, Telnet, FTP, and so on). This is inventory plus
    classification, not a vulnerability scanner in itself -- but a listening Telnet or an
    externally-bound SMB is a finding on its own, and the port list also scopes what the
    CVE results actually expose.
#>
    [CmdletBinding()]
    param()

    function New-PortRecord {
        param($Protocol, $LocalAddress, $LocalPort, $ProcessName, $ProcessId, $State, $Service)

        $boundToAll = ($LocalAddress -eq '0.0.0.0' -or $LocalAddress -eq '::')

        [PSCustomObject]@{
            Check             = 'OpenPort'
            Category          = 'Network Exposure'
            Item              = "$Protocol/$LocalPort"
            Detail            = "$Protocol $LocalAddress`:$LocalPort ($ProcessName, PID $ProcessId)"
            Risk_Hint         = ''
            Port_Protocol     = $Protocol
            Port_Number       = $LocalPort
            Port_LocalAddress = $LocalAddress
            Port_BoundToAll   = $boundToAll
            Port_Process      = $ProcessName
            Port_PID          = $ProcessId
            Port_Service      = $Service
            Is_Elevated_Scan  = $false
            Is_Admin_Member  = $false
            Scanned_Host      = $env:COMPUTERNAME
            Schema_Version    = $script:TJETConfig.SchemaVersion
            Collector_Version = $script:TJETConfig.CollectorVersion
        }
    }

    $processCache = @{}

    function Get-ProcessName {
        param($ProcessId)

        if ($null -eq $ProcessId) { return 'unknown' }
        if ($processCache.ContainsKey($ProcessId)) { return $processCache[$ProcessId] }

        $name = 'unknown'

        try {
            $process = Get-Process -Id $ProcessId -ErrorAction Stop
            $name = $process.ProcessName
        }
        catch { }

        $processCache[$ProcessId] = $name
        return $name
    }

    # --------------------------------------------------------------- TCP ---
    try {
        $tcp = Get-NetTCPConnection -State Listen -ErrorAction Stop

        foreach ($connection in $tcp) {

            New-PortRecord -Protocol 'TCP' `
                -LocalAddress $connection.LocalAddress `
                -LocalPort $connection.LocalPort `
                -ProcessName (Get-ProcessName $connection.OwningProcess) `
                -ProcessId $connection.OwningProcess `
                -State 'Listen' `
                -Service ''
        }
    }
    catch {
        # Get-NetTCPConnection is absent on very old hosts; fall back to netstat.
        Write-Verbose "Get-NetTCPConnection unavailable, falling back to netstat: $($_.Exception.Message)"

        try {
            $netstat = netstat -ano | Select-String 'LISTENING'

            foreach ($line in $netstat) {

                $fields = ($line -replace '\s+', ' ').Trim().Split(' ')

                if ($fields.Count -lt 5) { continue }

                $localEndpoint = $fields[1]
                $processId     = $fields[4]

                $port = ($localEndpoint -split ':')[-1]
                $addr = $localEndpoint -replace ":$port$", ''

                New-PortRecord -Protocol 'TCP' -LocalAddress $addr -LocalPort $port `
                    -ProcessName (Get-ProcessName ([int]$processId)) -ProcessId $processId `
                    -State 'Listen' -Service ''
            }
        }
        catch {
            Write-TJETLog WARNING "Port enumeration failed entirely: $($_.Exception.Message)"
        }
    }

    # --------------------------------------------------------------- UDP ---
    try {
        $udp = Get-NetUDPEndpoint -ErrorAction Stop

        foreach ($endpoint in $udp) {

            New-PortRecord -Protocol 'UDP' `
                -LocalAddress $endpoint.LocalAddress `
                -LocalPort $endpoint.LocalPort `
                -ProcessName (Get-ProcessName $endpoint.OwningProcess) `
                -ProcessId $endpoint.OwningProcess `
                -State 'Listen' `
                -Service ''
        }
    }
    catch {
        Write-Verbose "UDP endpoint enumeration failed: $($_.Exception.Message)"
    }

    Write-TJETLog INFO 'Open port enumeration complete.'
}


function Collect-FilesystemCredentials {
<#
.SYNOPSIS
    Datamines the filesystem for credential-bearing files and password patterns.
.DESCRIPTION
    Extends the credential hunt from AD attributes onto disk. Two passes:

    1. HIGH-SIGNAL FILENAMES -- files whose name alone implies secrets (web.config,
       *.kdbx, id_rsa, .env, credentials.xml, unattend.xml, *.ppk, and so on) in the
       usual locations.

    2. CONTENT GREP -- assignment-style patterns (password=, connectionString,
       api_key, BEGIN PRIVATE KEY) inside common config and script extensions, scanned
       only in the directories worth scanning so this does not read the entire disk.

    Detection only, and deliberately careful:

    - It records the FILE and the line NUMBER, never the secret value. A short redacted
      preview is included so a reviewer can triage without the report itself becoming a
      credential store.
    - Scanning is bounded: a capped set of roots, a file-size ceiling, and an extension
      allowlist, so it does not run for hours or read gigabyte log files.
    - Everything is best-effort and wrapped: an unreadable file or a denied directory is
      skipped, not fatal.
#>
    [CmdletBinding()]
    param(
        [string[]]$SearchRoots,

        [int]$MaxFileSizeKB = 2048,

        [int]$MaxFindings = 500
    )

    if (-not $SearchRoots -or $SearchRoots.Count -eq 0) {

        $SearchRoots = @(   # lint:allow-param-assign
            'C:\inetpub'
            'C:\xampp'
            'C:\Apache24'
            'C:\ProgramData'
            'C:\Scripts'
            'C:\Automation'
            (Join-Path $env:USERPROFILE 'Documents')
            (Join-Path $env:USERPROFILE 'Desktop')
            (Join-Path $env:USERPROFILE 'Downloads')
            'C:\Users\Public'
        )
    }

    function New-CredFileRecord {
        param($File, $Detail, $RiskHint, $Line)

        [PSCustomObject]@{
            Check             = 'FilesystemCredential'
            Category          = 'Credential Exposure'
            Item             = $File
            Detail           = $Detail
            Risk_Hint        = $RiskHint
            Cred_Line        = $Line
            Is_Elevated_Scan = $false
            Is_Admin_Member  = $false
            Scanned_Host     = $env:COMPUTERNAME
            Schema_Version   = $script:TJETConfig.SchemaVersion
            Collector_Version = $script:TJETConfig.CollectorVersion
        }
    }

    function Get-RedactedPreview {
        param([string]$Value)

        if ([string]::IsNullOrEmpty($Value)) { return '' }
        $clean = ($Value -replace '\s+', ' ').Trim()
        if ($clean.Length -le 14) { return ('*' * $clean.Length) }
        return ($clean.Substring(0, 10) + ('*' * 10) + " [len=$($clean.Length)]")
    }

    # Filenames that are interesting on their own.
    $secretFilePatterns = @(
        '*.kdbx','*.ppk','id_rsa','id_dsa','id_ecdsa','id_ed25519','*.pfx','*.pem'
        'web.config','app.config','*.rdp','unattend.xml','sysprep.xml','autounattend.xml'
        '.env','credentials','credentials.xml','*.kdb','*.psafe3','*.agilekeychain'
        'wp-config.php','settings.py','application.properties','.npmrc','.git-credentials'
    )

    # Content patterns for the grep pass.
    $contentPatterns = @(
        @{ Name = 'password assignment';  Pattern = '(?i)(password|passwd|pwd)\s*[:=]\s*\S{4,}' }
        @{ Name = 'connection string';    Pattern = '(?i)(password|pwd)\s*=\s*[^;\s]{4,}\s*;' }
        @{ Name = 'API key or secret';    Pattern = '(?i)(api[_-]?key|secret|access[_-]?key|token)\s*[:=]\s*\S{8,}' }
        @{ Name = 'private key material'; Pattern = '-----BEGIN (RSA |OPENSSH |EC |DSA |PGP )?PRIVATE KEY-----' }
        @{ Name = 'AWS access key';       Pattern = 'AKIA[0-9A-Z]{16}' }
    )

    $scanExtensions = @('.config','.xml','.ini','.txt','.ps1','.psm1','.bat','.cmd','.py',
                        '.php','.js','.json','.yml','.yaml','.properties','.env','.sh','.pl','.rb')

    $findingCount = 0

    foreach ($root in $SearchRoots) {

        if ($findingCount -ge $MaxFindings) { break }
        if ([string]::IsNullOrWhiteSpace($root) -or -not (Test-Path $root)) { continue }

        # ---- pass 1: interesting filenames ---------------------------------
        foreach ($pattern in $secretFilePatterns) {

            if ($findingCount -ge $MaxFindings) { break }

            try {
                # not $matches -- automatic variable populated by -match
                $namedFiles = Get-ChildItem -Path $root -Filter $pattern -Recurse -File `
                    -ErrorAction SilentlyContinue -Force |
                    Select-Object -First 50

                foreach ($file in $namedFiles) {

                    New-CredFileRecord -File $file.FullName `
                        -Detail "Credential-bearing file present: $($file.Name)" `
                        -RiskHint 'The filename indicates stored secrets; review and secure or remove it.' `
                        -Line 0

                    $findingCount++

                    if ($findingCount -ge $MaxFindings) { break }
                }
            }
            catch { }
        }

        # ---- pass 2: content grep ------------------------------------------
        try {
            $candidateFiles = Get-ChildItem -Path $root -Recurse -File -ErrorAction SilentlyContinue -Force |
                Where-Object {
                    ($scanExtensions -contains $_.Extension.ToLower()) -and
                    ($_.Length -le ($MaxFileSizeKB * 1024))
                } |
                Select-Object -First 2000

            foreach ($file in $candidateFiles) {

                if ($findingCount -ge $MaxFindings) { break }

                try {
                    $content = Get-Content -Path $file.FullName -ErrorAction Stop
                }
                catch {
                    continue
                }

                $lineNumber = 0

                foreach ($line in $content) {

                    $lineNumber++

                    foreach ($pattern in $contentPatterns) {

                        if ($line -match $pattern.Pattern) {

                            New-CredFileRecord -File $file.FullName `
                                -Detail "$($pattern.Name) in $($file.Name) at line $lineNumber. Preview (redacted): $(Get-RedactedPreview $line)" `
                                -RiskHint 'A credential appears to be stored in this file. Rotate it and remove it from source.' `
                                -Line $lineNumber

                            $findingCount++
                            break
                        }
                    }

                    if ($findingCount -ge $MaxFindings) { break }
                }
            }
        }
        catch { }
    }

    if ($findingCount -ge $MaxFindings) {
        Write-TJETLog WARNING "Filesystem credential scan hit the $MaxFindings finding cap; narrow -SearchRoots for full coverage."
    }

    Write-TJETLog INFO "Filesystem credential scan complete ($findingCount hit(s))."
}


# ==========================================================================
# SOURCE: Collectors\Collect-Trusts.ps1
# ==========================================================================
function Collect-Trusts {
<#
.SYNOPSIS
    Collects domain and forest trust relationships -- via ADSI, no RSAT.
.DESCRIPTION
    [ADSI REWRITE] Trusts are trustedDomain objects in the System container. This reads
    them over LDAP and decodes the raw trustDirection / trustType / trustAttributes
    integers into the same fields the AD-module version exposed, so DOM-004 (SID
    filtering / intra-forest suppression) is unaffected.

    trustDirection: 1=Inbound, 2=Outbound, 3=Bidirectional.
    trustAttributes bits: 0x1 NON_TRANSITIVE, 0x4 QUARANTINED_DOMAIN (SID filtering on),
    0x8 FOREST_TRANSITIVE, 0x20 WITHIN_FOREST, 0x40 TREAT_AS_EXTERNAL.
    DOM-004 keys on TrustAttributes and SIDFilteringQuarantined, both preserved.
#>
    [CmdletBinding()]
    param(
        [string]$Server,
        [System.Management.Automation.PSCredential]$Credential
    )

    $ctx = Get-TJETDirectoryContext -Server:$Server -Credential:$Credential

    $properties = @('name','trustDirection','trustType','trustAttributes','trustPartner','flatName')
    $searcher = $ctx.NewSearcher('(objectClass=trustedDomain)', $properties)
    $results = $searcher.FindAll()

    foreach ($result in $results) {

        $flat = Convert-TJETSearchResult $result

        $direction = [int](Get-TJETLdapProperty $flat 'trustdirection' 0)
        $attributes = [int](Get-TJETLdapProperty $flat 'trustattributes' 0)
        $trustType  = [int](Get-TJETLdapProperty $flat 'trusttype' 0)

        $directionText = switch ($direction) {
            1 { 'Inbound' }
            2 { 'Outbound' }
            3 { 'Bidirectional' }
            default { "Unknown($direction)" }
        }

        # SID filtering is ON when the trust is quarantined (0x4) OR is within the same
        # forest (0x20, where filtering is inherent). External trusts without 0x4 are the
        # DOM-004 risk case.
        $withinForest = (($attributes -band 0x20) -ne 0)
        $quarantined  = (($attributes -band 0x4) -ne 0)

        [PSCustomObject]@{
            Name                    = Get-TJETLdapProperty $flat 'name'
            Direction               = $directionText
            TrustType               = $trustType
            TrustAttributes         = $attributes
            SelectiveAuthentication = (($attributes -band 0x10) -ne 0)
            SIDFilteringQuarantined = $quarantined
            Within_Forest           = $withinForest
            Trust_Partner           = Get-TJETLdapProperty $flat 'trustpartner'
            Schema_Version          = $script:TJETConfig.SchemaVersion
            Collector_Version       = $script:TJETConfig.CollectorVersion
        }
    }

    $results.Dispose()
    $searcher.Dispose()
}


# ==========================================================================
# SOURCE: Collectors\Collect-Users.ps1
# ==========================================================================
function Collect-Users {
<#
.SYNOPSIS
    Collects user objects and derives risk-relevant flags -- via ADSI/LDAP, no RSAT.
.DESCRIPTION
    [ADSI REWRITE] This no longer depends on the ActiveDirectory module. It queries the
    domain over LDAP with System.DirectoryServices (built into .NET), so it runs on any
    domain-joined host without RSAT.

    The OUTPUT CONTRACT is unchanged: every field name this used to emit is still emitted,
    so the correlation layer, the CSV schema, and every detector keep working untouched.
    Only the data SOURCE changed (AD-module cmdlets -> DirectorySearcher).

    userAccountControl is decoded via Test-TJETUacFlag to recover the friendly booleans
    the AD module used to synthesise (Enabled, PasswordNeverExpires, PasswordNotRequired,
    TrustedForDelegation, DoesNotRequirePreAuth). Dates come from FILETIME integers via
    ConvertFrom-TJETFileTime.
#>
    [CmdletBinding()]
    param(
        # Optional explicit DC / credentials, passed through to the ADSI context.
        [string]$Server,
        [System.Management.Automation.PSCredential]$Credential
    )

    $privilegedGroupNames =
        'Domain Admins|Enterprise Admins|Schema Admins|Administrators|' +
        'Account Operators|Backup Operators|Server Operators|Print Operators|' +
        'Cert Publishers|DnsAdmins'

    $ctx = Get-TJETDirectoryContext -Server:$Server -Credential:$Credential

    # Attributes to pull. Requesting an attribute the schema lacks is harmless in ADSI
    # (it simply is not returned), so no schema probing is needed here -- a further
    # simplification over the AD-module version.
    $properties = @(
        'distinguishedName','objectGUID','objectSid','sAMAccountName','sidHistory',
        'memberOf','servicePrincipalName','adminCount','userAccountControl',
        'pwdLastSet','lastLogonTimestamp','whenCreated',
        'msDS-AllowedToDelegateTo','msDS-KeyCredentialLink'
    )

    $searcher = $ctx.NewSearcher('(&(objectCategory=person)(objectClass=user))', $properties)

    $results = $searcher.FindAll()

    foreach ($result in $results) {

        $flat = Convert-TJETSearchResult $result

        # Convert-TJETSearchResult returns an [ordered] with lowercase LDAP names. Build
        # the audit record with the SAME field names the AD-module collector produced.
        $record = [ordered]@{}

        $dn  = Get-TJETLdapProperty $flat 'distinguishedname'
        $sid = Get-TJETLdapProperty $flat 'objectsid'
        $uac = [int](Get-TJETLdapProperty $flat 'useraccountcontrol' 0)

        $record['DistinguishedName'] = $dn
        $record['SamAccountName']    = Get-TJETLdapProperty $flat 'samaccountname'
        $record['ObjectGUID']        = Get-TJETLdapProperty $flat 'objectguid'
        $record['ObjectSID']         = $sid
        $record['Enabled']           = (-not (Test-TJETUacFlag $uac 'Disabled'))

        # --- SID history -----------------------------------------------------
        $record['SIDHistory_Values'] = Get-TJETLdapProperty $flat 'sidhistory'

        # --- Privilege -------------------------------------------------------
        $memberOfRaw = Get-TJETLdapProperty $flat 'memberof'
        $record['Potentially_Privileged_Direct'] = [bool](
            ($memberOfRaw -match "(?i)CN=($privilegedGroupNames),") -or
            ($sid -match '-500$')
        )

        $record['Has_AdminCount'] = [bool]([int](Get-TJETLdapProperty $flat 'admincount' 0) -eq 1)

        # Flattened group membership for the attack-path graph (leaf CN of each DN).
        $memberOfNames = @($memberOfRaw -split '; ') | ForEach-Object {
            if ($_ -match '^CN=([^,]+),') { $Matches[1] } else { "$_" }
        }
        $record['MemberOf_Values'] = ($memberOfNames -join ';')

        # --- Kerberos / delegation ------------------------------------------
        $record['Has_SPNs']                     = [bool](Get-TJETLdapProperty $flat 'serviceprincipalname')
        $record['Has_Delegation_Targets']       = [bool](Get-TJETLdapProperty $flat 'msds-allowedtodelegateto')
        $record['Has_Unconstrained_Delegation'] = (Test-TJETUacFlag $uac 'TrustedForDelegation')
        $record['Has_ASREP_Risk']               = (Test-TJETUacFlag $uac 'NoPreAuth')

        # --- Credential material --------------------------------------------
        $record['Has_Shadow_Credentials'] = [bool](Get-TJETLdapProperty $flat 'msds-keycredentiallink')
        $record['PasswordNeverExpires']   = (Test-TJETUacFlag $uac 'PasswordNeverExpires')
        $record['PasswordNotRequired']    = (Test-TJETUacFlag $uac 'PasswordNotRequired')

        $pwdLastSet = ConvertFrom-TJETFileTime (Get-TJETLdapProperty $flat 'pwdlastset' $null)
        $record['Password_Age_Days'] =
            if ($pwdLastSet) { [math]::Round(((Get-Date).ToUniversalTime() - $pwdLastSet).TotalDays) }
            else { $null }

        # --- Lifecycle -------------------------------------------------------
        $whenCreatedRaw = Get-TJETLdapProperty $flat 'whencreated' $null
        $whenCreated = $null
        if ($whenCreatedRaw) {
            try { $whenCreated = [datetime]::ParseExact("$whenCreatedRaw", 'yyyyMMddHHmmss.0Z', $null, 'AssumeUniversal') }
            catch { try { $whenCreated = [datetime]"$whenCreatedRaw" } catch { } }
        }

        $lastLogon = ConvertFrom-TJETFileTime (Get-TJETLdapProperty $flat 'lastlogontimestamp' $null)

        $ageDays = if ($whenCreated) { ((Get-Date).ToUniversalTime() - $whenCreated).TotalDays } else { 999 }

        $record['Is_Stale_180Days'] = [bool](
            $ageDays -gt 180 -and
            ($null -eq $lastLogon -or $lastLogon -lt (Get-Date).ToUniversalTime().AddDays(-180))
        )

        [PSCustomObject]$record
    }

    $results.Dispose()
    $searcher.Dispose()
}


# ==========================================================================
# SOURCE: Correlation\Invoke-ACLFindings.ps1
# ==========================================================================
function Invoke-ACLFindings {
<#
.SYNOPSIS
    PATH-001 (delegated rights over a Tier 0 object) and PATH-002 (AdminSDHolder backdoor).
.DESCRIPTION
    Rewritten after a live run produced 75 PATH-001 findings of which 60 were false.

    [FIX] Deny ACEs were reported as attack paths. The collector gathers them
    deliberately as evidence; correlation must gate on AccessType -eq 'Allow'.

    [FIX] SYSTEM and SELF were reported. They hold broad rights on nearly every object
    by design and accounted for 45 of the 75 findings.

    [FIX] ObjectType was ignored, so the default "Change Password" right granted to
    Everyone was reported identically to DS-Replication-Get-Changes-All (DCSync).
    Rights are now classified. Broad principals such as Everyone and Authenticated
    Users are deliberately NOT excluded by identity -- a GenericAll held by Everyone is
    a real critical finding -- they are filtered by right instead.

    [FIX] AdminSDHolder was never evaluated. It is a container with no Tier 0 SID, so
    the privilege-model check skipped it. AdminSDHolder stamps (copies, not inherits)
    its ACL onto every adminCount=1 object roughly hourly, so a single backdoor ACE
    there reappears on every protected object. That produced 15 identical PATH-001
    findings with the actual cause never reported. PATH-002 now names it.
#>
    param($Context)

    $protectedObjectAces = @{}

    foreach ($acl in $Context.Data.ACLs) {

        # --- Gate 1: Allow only -------------------------------------------------
        if ($acl.AccessType -and $acl.AccessType -ne 'Allow') { continue }

        # --- Gate 2: infrastructure principals ----------------------------------
        if (Test-TJETInfrastructureTrustee -TrusteeSid $acl.TrusteeSID -TrusteeName $acl.Trustee) {
            continue
        }

        # --- Gate 3: already-privileged trustees --------------------------------
        if ($Context.IsPrivilegedSid($acl.TrusteeSID)) { continue }

        # --- Gate 4: is the right actually dangerous? ---------------------------
        $classification = Test-TJETDangerousRight -Rights $acl.Rights -ObjectType $acl.ObjectType

        if (-not $classification.IsDangerous) { continue }

        $isAdminSDHolder = ($acl.DistinguishedName -match '(?i)CN=AdminSDHolder,CN=System,')

        # ---------------------------------------------- PATH-002 AdminSDHolder ---
        if ($isAdminSDHolder) {

            New-Finding `
                -Finding_ID 'PATH-002' `
                -Severity 'Critical' `
                -Confidence 'High' `
                -Category 'Attack Path' `
                -Target 'AdminSDHolder' `
                -Target_GUID $acl.ObjectGUID `
                -Finding 'Non-privileged principal has modification rights over AdminSDHolder (persistence backdoor).' `
                -Evidence "$($acl.Trustee) has $($classification.RightName). $($classification.Reason) AdminSDHolder stamps its ACL onto every adminCount=1 object approximately hourly, so this right is replicated to all protected accounts and groups." `
                -Recommendation 'Remove the ACE from AdminSDHolder FIRST, then clean the copies it stamped onto protected objects. Removing only the copies is ineffective -- SDProp restores them within the hour.'

            continue
        }

        # ---------------------------------------------------- PATH-001 Tier 0 ---
        if (-not $Context.IsPrivilegedGuid($acl.ObjectGUID)) { continue }

        # Track trustee -> objects so widespread stamping can be called out.
        $key = "$($acl.Trustee)|$($classification.RightName)"

        if (-not $protectedObjectAces.ContainsKey($key)) {
            $protectedObjectAces[$key] = New-Object System.Collections.Generic.List[string]
        }

        $protectedObjectAces[$key].Add($acl.ObjectName)

        New-Finding `
            -Finding_ID 'PATH-001' `
            -Severity 'Critical' `
            -Confidence 'High' `
            -Category 'Attack Path' `
            -Target $acl.ObjectName `
            -Target_GUID $acl.ObjectGUID `
            -Finding 'Non-privileged principal has modification rights over a Tier 0 object.' `
            -Evidence "$($acl.Trustee) has $($classification.RightName). $($classification.Reason) Inherited=$($acl.IsInherited)." `
            -Recommendation 'Remove the delegated permission after confirming no automation depends on it, then audit how it was granted -- the same delegation pattern is usually present elsewhere.'
    }

    # ------------------------------------------------- widespread stamping note ---
    # The same trustee holding the same right across many protected objects is the
    # signature of an AdminSDHolder backdoor rather than many separate mistakes.
    foreach ($key in $protectedObjectAces.Keys) {

        $objects = $protectedObjectAces[$key]

        if ($objects.Count -lt 5) { continue }

        $parts   = $key -split '\|'
        $trustee = $parts[0]
        $right   = $parts[1]

        New-Finding `
            -Finding_ID 'PATH-003' `
            -Severity 'Critical' `
            -Confidence 'High' `
            -Category 'Attack Path' `
            -Target $trustee `
            -Finding 'A single principal holds the same dangerous right across many Tier 0 objects.' `
            -Evidence "$trustee has $right on $($objects.Count) protected objects: $(($objects | Select-Object -First 10) -join ', ')$(if ($objects.Count -gt 10) { ', ...' }). Uniform rights across all adminCount=1 objects indicate AdminSDHolder propagation rather than individual delegations." `
            -Recommendation 'Inspect the AdminSDHolder ACL (CN=AdminSDHolder,CN=System). Remediate there first; per-object cleanup alone will be reverted by SDProp.'
    }
}


# ==========================================================================
# SOURCE: Correlation\Invoke-ADCSFindings.ps1
# ==========================================================================
function Invoke-ADCSFindings {
<#
.SYNOPSIS
    Detects abusable AD Certificate Services configurations (ESC1-ESC8).
.DESCRIPTION
    Consumes the CertTemplate / CertificateAuthority records from Collect-ADCS and emits
    findings for the certificate-based escalation paths. Certificate abuse is among the
    most impactful modern AD escalation classes -- several ESCs give domain admin in a
    single hop -- so these are Critical/High by default.

    Findings:
      ADCS-001  ESC1  Enrollee-supplies-subject + client-auth EKU + low-priv enrollment +
                      no manager approval and no RA signature. A standard user enrols a
                      cert as any principal (including a DA) and authenticates as them.
      ADCS-002  ESC2  Any-Purpose or no-EKU template enrollable by low-priv users. The
                      cert can be used for anything, including client auth.
      ADCS-003  ESC3  Enrollment-Agent template enrollable by low-priv users -- lets the
                      holder enrol on behalf of others.
      ADCS-004  ESC4  Low-priv principals have write/control over a template; they can
                      reconfigure it into an ESC1 and then abuse it.
      ADCS-005  ESC6/ESC8 (advisory) A CA is present. EDITF_ATTRIBUTESUBJECTALTNAME
                      (ESC6) and web-enrollment NTLM relay (ESC8) live in on-box CA
                      config not exposed via LDAP, so this flags the CA for manual check.
      ADCS-006        A template grants enrollment to an overly broad principal even if
                      not otherwise ESC1 -- surfaced as hygiene / attack surface.

    ESC1 is the highest-confidence, highest-severity finding here because every
    precondition is verifiable from the directory alone.
#>
    param($Context)

    $records = @($Context.Data.ADCS)
    if ($records.Count -eq 0) { return }

    $templates = @($records | Where-Object { $_.Check -eq 'CertTemplate' })
    $cas       = @($records | Where-Object { $_.Check -eq 'CertificateAuthority' })

    # Only templates actually published by a CA are exploitable; an unpublished template
    # cannot be enrolled. Build the set of published template names.
    $publishedNames = @{}
    foreach ($ca in $cas) {
        foreach ($t in ("$($ca.Published_Templates)" -split '; ')) {
            if ($t) { $publishedNames[$t.Trim()] = $true }
        }
    }

    foreach ($t in $templates) {

        $name        = "$($t.Item)"
        $isPublished = $publishedNames.ContainsKey($name)

        # An unpublished template is latent, not live. Note it at lower confidence only
        # when it would otherwise be ESC1, and skip the rest.
        $publishNote = if ($isPublished) { 'Template is published by a CA (live).' }
                       else { 'Template is NOT currently published by a CA, so it is not directly enrollable until published.' }

        $enrolleeSubject = ConvertTo-Bool $t.Enrollee_Supplies_Subject
        $managerApproval = ConvertTo-Bool $t.Manager_Approval_Required
        $hasAuthEku      = ConvertTo-Bool $t.Has_Auth_EKU
        $lowPrivEnroll   = ConvertTo-Bool $t.Low_Priv_Can_Enroll
        $lowPrivWrite    = ConvertTo-Bool $t.Low_Priv_Can_Write
        $noEku           = ConvertTo-Bool $t.No_EKU_Any_Purpose
        $raSigs          = [int]("$($t.RA_Signatures_Required)")

        # -------------------------------------------------- ESC1 (ADCS-001) ---
        # Enrollee supplies subject + auth EKU + low-priv can enrol + no approval + no
        # co-sign. This is the canonical one-hop escalation.
        if ($enrolleeSubject -and $hasAuthEku -and $lowPrivEnroll -and -not $managerApproval -and $raSigs -eq 0) {

            $severity   = if ($isPublished) { 'Critical' } else { 'High' }
            $confidence = if ($isPublished) { 'High' } else { 'Medium' }

            New-Finding `
                -Finding_ID 'ADCS-001' `
                -Severity $severity `
                -Confidence $confidence `
                -Category 'ADCS' `
                -Target "Certificate template: $name" `
                -Target_GUID "$($t.Template_GUID)" `
                -Finding 'Certificate template is vulnerable to ESC1 (enrollee supplies subject).' `
                -Evidence ("Template '$name' lets the enrollee supply the subject, issues a certificate valid for client authentication ($($t.Auth_EKU_Names)$(if($noEku){'no EKU = any purpose'})), requires no manager approval and no enrollment-agent signature, and is enrollable by low-privileged principals ($($t.Enroll_Principals)). A standard user can request a certificate as any account, including a Domain Admin, and authenticate as them. $publishNote") `
                -Recommendation 'Remediate ESC1: remove ENROLLEE_SUPPLIES_SUBJECT from the template (msPKI-Certificate-Name-Flag), or require manager approval, or require an authorized signature, or restrict enrollment to a trusted group. If the template is unused, unpublish it from all CAs.'
        }

        # -------------------------------------------------- ESC2 (ADCS-002) ---
        # Any-Purpose / no-EKU template enrollable by low-priv users.
        if ($noEku -and $lowPrivEnroll -and -not $managerApproval) {

            New-Finding `
                -Finding_ID 'ADCS-002' `
                -Severity ($(if ($isPublished) { 'High' } else { 'Medium' })) `
                -Confidence 'Medium' `
                -Category 'ADCS' `
                -Target "Certificate template: $name" `
                -Target_GUID "$($t.Template_GUID)" `
                -Finding 'Certificate template is vulnerable to ESC2 (Any-Purpose / no EKU).' `
                -Evidence ("Template '$name' defines no EKU (usable for any purpose, including client authentication) and is enrollable by low-privileged principals ($($t.Enroll_Principals)) without manager approval. $publishNote") `
                -Recommendation 'Constrain the template EKUs to the minimum required, require manager approval, or restrict enrollment. Unpublish if unused.'
        }

        # -------------------------------------------------- ESC4 (ADCS-004) ---
        # Low-priv principals can WRITE the template -> reconfigure into ESC1.
        if ($lowPrivWrite) {

            New-Finding `
                -Finding_ID 'ADCS-004' `
                -Severity 'High' `
                -Confidence 'High' `
                -Category 'ADCS' `
                -Target "Certificate template: $name" `
                -Target_GUID "$($t.Template_GUID)" `
                -Finding 'Certificate template has weak access control (ESC4).' `
                -Evidence ("Low-privileged principals ($($t.Write_Principals)) hold write/control over template '$name'. An attacker can reconfigure it (enable enrollee-supplies-subject, add a client-auth EKU, remove approval) to create an ESC1 condition on demand. Template owner: $($t.Owner).") `
                -Recommendation 'Restrict write/full-control on the template to administrators only. Review the template owner. Audit for recent unexpected template modifications.'
        }

        # -------------------------------------------------- broad enroll (ADCS-006) ---
        # Overly broad enrollment that is not otherwise ESC1/2 -- surface area.
        if ($lowPrivEnroll -and $hasAuthEku -and -not ($enrolleeSubject -and -not $managerApproval -and $raSigs -eq 0)) {

            New-Finding `
                -Finding_ID 'ADCS-006' `
                -Severity 'Low' `
                -Confidence 'Medium' `
                -Category 'ADCS' `
                -Target "Certificate template: $name" `
                -Target_GUID "$($t.Template_GUID)" `
                -Finding 'Certificate template grants broad enrollment for an authentication certificate.' `
                -Evidence ("Template '$name' issues an authentication-capable certificate and is enrollable by low-privileged principals ($($t.Enroll_Principals)). It is not directly ESC1 (approval or subject constraints apply), but broad enrollment for auth certs is attack surface worth restricting. $publishNote") `
                -Recommendation 'Restrict enrollment to the groups that genuinely need this template.'
        }
    }

    # -------------------------------------------------- ESC6/ESC8 (ADCS-005) ---
    # One advisory per CA: the on-box conditions cannot be read via LDAP.
    foreach ($ca in $cas) {

        New-Finding `
            -Finding_ID 'ADCS-005' `
            -Severity 'Medium' `
            -Confidence 'Low' `
            -Category 'ADCS' `
            -Target "Certificate Authority: $($ca.Item)" `
            -Target_GUID "$($ca.CA_GUID)" `
            -Finding 'Certificate Authority present -- verify ESC6/ESC8 conditions on the CA host.' `
            -Evidence ("CA '$($ca.Item)' on $($ca.Detail) publishes $($ca.Published_Count) template(s). ESC6 (EDITF_ATTRIBUTESUBJECTALTNAME lets any request specify an arbitrary SAN) and ESC8 (HTTP web enrollment enables NTLM relay to the CA) depend on on-box configuration not exposed through the directory, so they cannot be confirmed remotely.") `
            -Recommendation 'On the CA host, run: certutil -getreg policy\EditFlags and confirm EDITF_ATTRIBUTESUBJECTALTNAME is NOT set (ESC6). Disable HTTP web enrollment or enforce Extended Protection for Authentication / require HTTPS (ESC8). Consider certutil or Certify/Certipy for a full on-box template audit.'
    }
}


# ==========================================================================
# SOURCE: Correlation\Invoke-AttackPathFindings.ps1
# ==========================================================================
function Invoke-AttackPathFindings {
<#
.SYNOPSIS
    PATH-GRAPH: multi-hop control paths from non-privileged principals to Tier 0.
.DESCRIPTION
    Builds the control graph and reports the shortest path from each principal that can
    reach Tier 0. Where PATH-001 reports a single dangerous ACE, this reports the whole
    chain -- membership plus ACL plus delegation hops -- which is what makes a finding
    actionable: the fix is usually a single edge in the middle of the chain, not the
    endpoint.

    Also writes two artefacts into a Graph subfolder:
        Attack_Paths.csv  one row per traced path: source, Tier 0 target, hop count,
                          the full chain written out, and the specific link to cut

    The edge list is deliberately in a generic source/target/type shape so it can be
    loaded into BloodHound, Neo4j, Gephi or a spreadsheet pivot without transformation.
#>
    param($Context)

    $graph = Build-TJETGraph -Context $Context

    Write-TJETLog INFO "Attack-path graph: $($graph.Nodes.Count) node(s), $($graph.Edges.Count) edge(s)"

    if ($graph.Edges.Count -eq 0) { return }

    $paths = Find-TJETAttackPathInternal -Graph $graph

    # De-duplicate to the shortest path per (source -> target) pair.
    $shortest = @{}

    foreach ($path in $paths) {
        $key = "$($path.Source)|$($path.Target)"
        if (-not $shortest.ContainsKey($key) -or $path.Hops -lt $shortest[$key].Hops) {
            $shortest[$key] = $path
        }
    }

    foreach ($key in $shortest.Keys) {

        $path  = $shortest[$key]
        $chain = Format-TJETPath -PathResult $path -Graph $graph

        # A one-hop path is already reported by PATH-001; the value here is the
        # multi-hop chains a single-ACE detector cannot see.
        $severity = if ($path.Hops -ge 2) { 'Critical' } else { 'High' }

        New-Finding `
            -Finding_ID 'PATH-GRAPH' `
            -Severity $severity `
            -Confidence 'High' `
            -Category 'Attack Path' `
            -Target $path.Source `
            -Finding "Control path from $($path.Source) to Tier 0 ($($path.Target)) in $($path.Hops) hop(s)." `
            -Evidence "Path: $chain" `
            -Recommendation 'Break the chain at its weakest link -- usually a single delegated right or group nesting mid-path. See remediation steps.'
    }

    # ---------------------------------------------------- edge / node export ---
    # [CHANGE] The BloodHound-style node/edge CSV export has been removed. What is
    # wanted is the traced path itself, written out in readable form -- not a graph to
    # visualise. Attack_Paths.csv gives one row per path with the full chain spelled
    # out, the hop count, and the specific link to cut to break it.
    if ($Context.OutputPath) {

        $pathRows = New-Object System.Collections.Generic.List[object]

        foreach ($key in $shortest.Keys) {

            $path  = $shortest[$key]
            $chain = Format-TJETPath -PathResult $path -Graph $graph

            $hops      = @($path.Path)
            $firstHop  = $hops | Select-Object -First 1

            $firstFrom = $graph.Nodes[$firstHop.From].Name
            $firstTo   = $graph.Nodes[$firstHop.To].Name

            $pathRows.Add([PSCustomObject]@{
                Source       = $path.Source
                Target_Tier0 = $path.Target
                Hop_Count    = $path.Hops
                Path         = $chain
                First_Link   = "$firstFrom -[$($firstHop.Type)]-> $firstTo"
                Break_At     = "Remove the '$($firstHop.Type)' right held by $firstFrom over $firstTo"
            })
        }

        if ($pathRows.Count -gt 0) {

            $pathRows |
                Sort-Object Hop_Count, Source |
                Export-Csv -Path (Join-Path $Context.OutputPath 'Attack_Paths.csv') `
                    -NoTypeInformation -Encoding UTF8

            Write-TJETLog INFO "Attack paths traced: $($pathRows.Count) path(s) -> Attack_Paths.csv"
        }
    }
}


# ==========================================================================
# SOURCE: Correlation\Invoke-ComputerFindings.ps1
# ==========================================================================
function Invoke-ComputerFindings {
<#
.SYNOPSIS
    Infrastructure-layer detections.
.DESCRIPTION
    [FIX] Restored INF-002 (RBCD), INF-003 (no LAPS evidence) and INF-004
    (unsupported OS). Has_RBCD_Configured, Has_LAPS and OperatingSystem were all
    being collected with no detector consuming them.

    [FIX] Disabled computer objects are now skipped -- they carry stale flags.
#>
    param($Context)

    foreach ($computer in $Context.Data.Computers) {

        if ($computer.PSObject.Properties.Name -contains 'Enabled' -and
            -not (ConvertTo-Bool $computer.Enabled)) {
            continue
        }

        $isDC = ConvertTo-Bool $computer.Is_Domain_Controller

        # ------------------------------------ INF-001 unconstrained delegation
        if ((ConvertTo-Bool $computer.Has_Unconstrained_Delegation) -and -not $isDC) {

            New-Finding `
                -Finding_ID 'INF-001' `
                -Severity 'Critical' `
                -Confidence 'High' `
                -Category 'Infrastructure' `
                -Target $computer.Name `
                -Target_GUID $computer.ObjectGUID `
                -Finding 'Non-domain controller has unconstrained delegation.' `
                -Evidence 'TrustedForDelegation=True on a member system.' `
                -Recommendation 'Remove unconstrained delegation and use resource-based constrained delegation.'
        }

        # ---------------------------------------------------------- INF-002 RBCD
        if (ConvertTo-Bool $computer.Has_RBCD_Configured) {

            New-Finding `
                -Finding_ID 'INF-002' `
                -Severity 'High' `
                -Confidence 'High' `
                -Category 'Infrastructure' `
                -Target $computer.Name `
                -Target_GUID $computer.ObjectGUID `
                -Finding 'Resource-based constrained delegation is configured.' `
                -Evidence 'msDS-AllowedToActOnBehalfOfOtherIdentity is populated.' `
                -Recommendation 'Verify the RBCD authorization is intended and scoped correctly.'
        }

        # ---------------------------------------------------------- INF-003 LAPS
        if (-not (ConvertTo-Bool $computer.Has_LAPS) -and
            $computer.OperatingSystem -match 'Server' -and
            -not $isDC) {

            New-Finding `
                -Finding_ID 'INF-003' `
                -Severity 'Medium' `
                -Confidence 'Medium' `
                -Category 'Infrastructure' `
                -Target $computer.Name `
                -Target_GUID $computer.ObjectGUID `
                -Finding 'No local administrator password solution (LAPS) evidence on a member server.' `
                -Evidence "No LAPS attributes present. OS: $($computer.OperatingSystem)." `
                -Recommendation 'Deploy Windows LAPS or confirm equivalent coverage.'
        }

        # ------------------------------------------------ INF-004 unsupported OS
        if ($computer.OperatingSystem -match 'Windows (XP|7|8|Vista)\b|Server (2000|2003|2008|2012)') {

            New-Finding `
                -Finding_ID 'INF-004' `
                -Severity 'High' `
                -Confidence 'High' `
                -Category 'Infrastructure' `
                -Target $computer.Name `
                -Target_GUID $computer.ObjectGUID `
                -Finding 'Unsupported operating system detected.' `
                -Evidence "OperatingSystem: $($computer.OperatingSystem)." `
                -Recommendation 'Decommission or isolate legacy operating systems.'
        }

        # ------------------------------------------- INF-005 shadow credentials
        if (ConvertTo-Bool $computer.Has_Shadow_Credentials) {

            New-Finding `
                -Finding_ID 'INF-005' `
                -Severity $(if ($isDC) { 'High' } else { 'Medium' }) `
                -Confidence 'Medium' `
                -Category 'Infrastructure' `
                -Target $computer.Name `
                -Target_GUID $computer.ObjectGUID `
                -Finding 'Computer object has msDS-KeyCredentialLink populated (possible shadow credentials).' `
                -Evidence "Key credential material present. IsDC=$isDC. Device registration populates this legitimately." `
                -Recommendation 'Validate the key credential is an expected registration and remove unrecognized entries.'
        }
    }
}


# ==========================================================================
# SOURCE: Correlation\Invoke-CredentialHuntFindings.ps1
# ==========================================================================
function Invoke-CredentialHuntFindings {
<#
.SYNOPSIS
    CRED-001: secrets found in Active Directory attribute values.
.DESCRIPTION
    Collectors now capture EVERY attribute, because plaintext credentials routinely turn
    up in fields nobody audits: description, info, comment, notes, custom schema
    extensions, and the legacy userPassword / unixUserPassword attributes. This detector
    is the reason capturing everything is worth the volume.

    It scans every attribute value of every collected object against two signal classes:

    1. HIGH-SIGNAL ATTRIBUTES -- fields that should never hold a secret at all
       (userPassword, unixUserPassword, ms-Mcs-AdmPwd). Any value is reportable.

    2. CONTENT PATTERNS -- "password = x", "pwd:", connection strings, API keys, and
       private key headers appearing in free-text fields.

    Deliberate design choices:

    - The matched VALUE IS NOT WRITTEN to the findings CSV. The finding names the object
      and the attribute, and shows a short redacted preview. Copying discovered
      credentials into a report that then gets emailed around is its own incident.
    - Free-text fields are matched on assignment-like patterns rather than the bare word
      "password", so "user must change password at next logon" does not fire.
    - Every object type is scanned, not just users -- service and computer objects are
      common hiding places.
#>
    param($Context)

    # Attributes whose mere population is a finding.
    $secretAttributes = @(
        'userPassword'
        'unixUserPassword'
        'ms-Mcs-AdmPwd'
        'msLAPS-Password'
        'msDS-ManagedPassword'
        'orclCommonAttribute'
        'defenderAdminPassword'
    )

    # Free-text fields where credentials are habitually parked.
    $freeTextAttributes = @(
        'description'
        'info'
        'comment'
        'notes'
        'displayName'
        'adminDescription'
        'extensionAttribute1','extensionAttribute2','extensionAttribute3'
        'extensionAttribute4','extensionAttribute5','extensionAttribute6'
        'extensionAttribute7','extensionAttribute8','extensionAttribute9'
        'extensionAttribute10','extensionAttribute11','extensionAttribute12'
        'extensionAttribute13','extensionAttribute14','extensionAttribute15'
        'wWWHomePage'
        'url'
        'scriptPath'
        'userWorkstations'
        'physicalDeliveryOfficeName'
        'title'
        'department'
    )

    # Assignment-like patterns. Anchored on a separator so prose does not match.
    $contentPatterns = @(
        @{ Name = 'password assignment';  Pattern = '(?i)\b(pass|pwd|passwd|password|senha|contrase)\w*\s*[:=]\s*\S{4,}' }
        @{ Name = 'credential phrase';    Pattern = '(?i)\b(cred|credential|login|logon)\w*\s*[:=]\s*\S{4,}' }
        @{ Name = 'connection string';    Pattern = '(?i)(password|pwd)\s*=\s*[^;\s]{4,}\s*;' }
        @{ Name = 'API key or token';     Pattern = '(?i)\b(api[_-]?key|secret|token|bearer)\s*[:=]\s*\S{8,}' }
        @{ Name = 'private key material'; Pattern = '-----BEGIN (RSA |OPENSSH |EC |DSA |PGP )?PRIVATE KEY-----' }
        @{ Name = 'default credential';   Pattern = '(?i)\b(pass|pwd|password)\w*\s*[:=]\s*(P@ssw0rd|Password1|Welcome1|Changeme|Summer|Winter|Spring|Autumn)\w*' }
    )

    function Get-RedactedPreview {
        param([string]$Value)

        if ([string]::IsNullOrEmpty($Value)) { return '' }

        $clean = ($Value -replace '\s+', ' ').Trim()

        # Show enough to locate it, never enough to use it.
        if ($clean.Length -le 12) {
            return ('*' * $clean.Length)
        }

        return ($clean.Substring(0, 8) + ('*' * 12) + " [len=$($clean.Length)]")
    }

    $sources = @(
        @{ Name = 'User';           Items = $Context.Data.Users;           Label = 'SamAccountName' }
        @{ Name = 'Computer';       Items = $Context.Data.Computers;       Label = 'Name' }
        @{ Name = 'Group';          Items = $Context.Data.Groups;          Label = 'Name' }
        @{ Name = 'ServiceAccount'; Items = $Context.Data.ServiceAccounts; Label = 'Name' }
    )

    foreach ($source in $sources) {

        foreach ($item in $source.Items) {

            if ($null -eq $item) { continue }

            $target = "$($item.($source.Label))"

            if ([string]::IsNullOrWhiteSpace($target)) { $target = 'unknown object' }

            foreach ($property in $item.PSObject.Properties) {

                $name  = $property.Name
                $value = "$($property.Value)"

                if ([string]::IsNullOrWhiteSpace($value)) { continue }
                if ($name -like '*_Count') { continue }

                # ---- class 1: attributes that should never hold a secret ----------
                if ($secretAttributes -contains $name) {

                    New-Finding `
                        -Finding_ID 'CRED-001' `
                        -Severity 'Critical' `
                        -Confidence 'High' `
                        -Category 'Credential Exposure' `
                        -Target $target `
                        -Target_GUID $item.ObjectGUID `
                        -Finding "Secret-bearing attribute is populated on a $($source.Name) object." `
                        -Evidence "Attribute '$name' contains a value. Preview (redacted): $(Get-RedactedPreview $value). Any principal able to read this attribute can read the secret." `
                        -Recommendation "Clear '$name' on this object, rotate the exposed credential, and restrict read access to the attribute."

                    continue
                }

                # ---- class 2: credential patterns in free-text fields -------------
                # Restricted to known free-text attributes to keep the false-positive
                # rate sane; binary and structural attributes are not prose.
                if ($freeTextAttributes -notcontains $name) { continue }

                foreach ($pattern in $contentPatterns) {

                    if ($value -notmatch $pattern.Pattern) { continue }

                    New-Finding `
                        -Finding_ID 'CRED-001' `
                        -Severity 'Critical' `
                        -Confidence 'Medium' `
                        -Category 'Credential Exposure' `
                        -Target $target `
                        -Target_GUID $item.ObjectGUID `
                        -Finding "Possible credential stored in a $($source.Name) object attribute." `
                        -Evidence "Attribute '$name' matched '$($pattern.Name)'. Preview (redacted): $(Get-RedactedPreview $value). Every authenticated user can read this attribute by default." `
                        -Recommendation "Review and clear the value in '$name', then rotate any credential it exposed. Attribute values are world-readable to authenticated users by default."

                    break
                }
            }
        }
    }
}


# ==========================================================================
# SOURCE: Correlation\Invoke-DomainFindings.ps1
# ==========================================================================
function Invoke-DomainFindings {


param(
    $Context
)



$domain =
    $Context.Data.Domain



if(-not $domain){

    return

}



$age =
    ConvertTo-Int `
        $domain.KRBTGT_PwdAgeDays



if($age -gt 730){


New-Finding `
    -Finding_ID 'DOM-001' `
    -Severity Critical `
    -Confidence High `
    -Category Domain `
    -Target KRBTGT `
    -Finding "KRBTGT password age exceeds 730 days." `
    -Evidence "Password age: $age days." `
    -Recommendation "Rotate KRBTGT twice following Microsoft guidance."



}


elseif($age -gt 365){


New-Finding `
    -Finding_ID 'DOM-001' `
    -Severity High `
    -Confidence High `
    -Category Domain `
    -Target KRBTGT `
    -Finding "KRBTGT password age exceeds one year." `
    -Evidence "Password age: $age days."

}



if(
    (ConvertTo-Int $domain.MachineAccountQuota) -gt 0
){


New-Finding `
    -Finding_ID 'DOM-005' `
    -Severity Low `
    -Confidence High `
    -Category Domain `
    -Target $domain.Domain `
    -Finding "Domain permits standard users to create computer objects." `
    -Evidence "MachineAccountQuota=$($domain.MachineAccountQuota)"

}



}

# ==========================================================================
# SOURCE: Correlation\Invoke-ExposureFindings.ps1
# ==========================================================================
function Invoke-ExposureFindings {
<#
.SYNOPSIS
    Findings from open ports (PORT-*), patch level (PATCH-*) and filesystem credential
    hunting (CRED-002).
.DESCRIPTION
    Consumes the records added by Collect-OpenPorts, Collect-SoftwareInventory (patch
    age) and Collect-FilesystemCredentials, all of which travel in the LocalHost data.

    Port findings are risk-classified: a listening service that is legacy-cleartext
    (Telnet, FTP, rlogin) or a high-value lateral-movement surface (SMB, RDP, WinRM,
    RPC, LDAP, WSMan) is reported, and binding to all interfaces raises the severity
    over a loopback-only bind. An ordinary ephemeral or loopback listener is inventory,
    not a finding, so the port list does not drown the report.
#>
    param($Context)

    $records = @($Context.Data.LocalHost)

    if ($records.Count -eq 0) { return }

    # Index running processes by PID so a listening port can name the process behind it
    # with full detail (path, command line, signer), not just a bare PID.
    $processByPid = @{}

    foreach ($record in $records) {
        if ($record.Check -eq 'RunningProcess' -and $record.Process_PID) {
            $processByPid["$($record.Process_PID)"] = $record
        }
    }

    $scannedHost = $env:COMPUTERNAME
    foreach ($record in $records) {
        if ($record.Scanned_Host) { $scannedHost = $record.Scanned_Host; break }
    }

    # Notable ports: cleartext legacy, and high-value services.
    $portClasses = @{
        21    = @{ Name = 'FTP';        Severity = 'High';   Cleartext = $true;  Note = 'FTP transmits credentials in cleartext.' }
        23    = @{ Name = 'Telnet';     Severity = 'High';   Cleartext = $true;  Note = 'Telnet transmits everything, including credentials, in cleartext.' }
        69    = @{ Name = 'TFTP';       Severity = 'Medium'; Cleartext = $true;  Note = 'TFTP has no authentication.' }
        111   = @{ Name = 'RPCbind';    Severity = 'Medium'; Cleartext = $false; Note = 'RPC portmapper exposes RPC services for enumeration.' }
        135   = @{ Name = 'MSRPC';      Severity = 'Medium'; Cleartext = $false; Note = 'RPC endpoint mapper is used for lateral movement and coercion.' }
        139   = @{ Name = 'NetBIOS';    Severity = 'Medium'; Cleartext = $false; Note = 'Legacy NetBIOS session service; a downgrade and enumeration surface.' }
        445   = @{ Name = 'SMB';        Severity = 'High';   Cleartext = $false; Note = 'SMB is the primary lateral-movement and relay surface.' }
        512   = @{ Name = 'rexec';      Severity = 'High';   Cleartext = $true;  Note = 'Berkeley r-service with cleartext auth.' }
        513   = @{ Name = 'rlogin';     Severity = 'High';   Cleartext = $true;  Note = 'Berkeley r-service with cleartext auth.' }
        1433  = @{ Name = 'MSSQL';      Severity = 'Medium'; Cleartext = $false; Note = 'Database service exposed; verify authentication and network scope.' }
        3306  = @{ Name = 'MySQL';      Severity = 'Medium'; Cleartext = $false; Note = 'Database service exposed; verify authentication and network scope.' }
        3389  = @{ Name = 'RDP';        Severity = 'High';   Cleartext = $false; Note = 'RDP is a primary remote-access and brute-force target.' }
        5432  = @{ Name = 'PostgreSQL'; Severity = 'Medium'; Cleartext = $false; Note = 'Database service exposed; verify authentication and network scope.' }
        5985  = @{ Name = 'WinRM-HTTP'; Severity = 'Medium'; Cleartext = $false; Note = 'WinRM over HTTP is a remote-execution surface.' }
        5986  = @{ Name = 'WinRM-HTTPS';Severity = 'Low';    Cleartext = $false; Note = 'WinRM over HTTPS; confirm it is intended to be reachable.' }
        389   = @{ Name = 'LDAP';       Severity = 'Low';    Cleartext = $true;  Note = 'LDAP without TLS exposes directory queries and simple-bind credentials.' }
    }

    foreach ($record in $records) {

        # ------------------------------------------------------- ports (PORT-001) ---
        if ($record.Check -eq 'OpenPort') {

            $portNumber = 0
            [int]::TryParse("$($record.Port_Number)", [ref]$portNumber) | Out-Null

            $class = $portClasses[$portNumber]

            if (-not $class) { continue }        # not a notable port

            $boundAll = ConvertTo-Bool $record.Port_BoundToAll

            # Loopback-only bind of an otherwise notable service is much lower risk.
            $severity = $class.Severity

            if (-not $boundAll) {
                $severity = switch ($severity) { 'High' { 'Low' } 'Medium' { 'Low' } default { 'Info' } }
            }

            $scope = if ($boundAll) { 'all interfaces (network-reachable)' } else { 'loopback only' }

            # Resolve the owning process to full detail if the process collector ran.
            $proc = $processByPid["$($record.Port_PID)"]

            $procDetail = ''
            if ($proc) {
                $procDetail = " Process: $($proc.Process_Path)"
                if ($proc.Process_CommandLine) { $procDetail += " [cmdline: $($proc.Process_CommandLine)]" }
                if ($proc.Process_Owner)       { $procDetail += " (owner: $($proc.Process_Owner))" }
                if ($proc.Process_Signed -and $proc.Process_Signed -ne 'Valid' -and $proc.Process_Signed -ne 'unknown') {
                    $procDetail += " SIGNATURE: $($proc.Process_Signed)"
                }
            }

            New-Finding `
                -Finding_ID 'PORT-001' `
                -Severity $severity `
                -Confidence 'High' `
                -Category 'Network Exposure' `
                -Target "$scannedHost`:$($record.Port_Number)/$($record.Port_Protocol)" `
                -Finding "Listening service on port $($record.Port_Number) ($($class.Name))." `
                -Evidence "$($class.Name) listening on $scope via process '$($record.Port_Process)' (PID $($record.Port_PID)). $($class.Note)$procDetail" `
                -Recommendation "Confirm this service is required and correctly scoped. If not needed, disable it; if needed, restrict it to the required networks by firewall and require encrypted/authenticated access."

            continue
        }

        # ------------------------------------------------- patch level (PATCH-001) ---
        if ($record.Check -eq 'PatchLevel') {

            $age = 0
            [int]::TryParse("$($record.Patch_Age_Days)", [ref]$age) | Out-Null

            if ($age -le 60) { continue }        # current enough

            $severity = if ($age -gt 180) { 'High' } elseif ($age -gt 90) { 'Medium' } else { 'Low' }

            New-Finding `
                -Finding_ID 'PATCH-001' `
                -Severity $severity `
                -Confidence 'High' `
                -Category 'Host Hardening' `
                -Target $scannedHost `
                -Finding 'Host is behind on operating-system patching.' `
                -Evidence "$($record.Detail) A patch gap widens exposure to every vulnerability fixed since the last update." `
                -Recommendation 'Apply outstanding operating-system and security updates, and confirm the host is receiving updates from WSUS or Windows Update.'

            continue
        }

        # -------------------------------------- suspicious process (PROC-001) ---
        if ($record.Check -eq 'RunningProcess') {

            $fromWritable = ConvertTo-Bool $record.Process_FromUserWritable
            $badSignature = ($record.Process_Signed -and
                             $record.Process_Signed -notin 'Valid','unknown','')

            # Only surface processes that are actually notable: running from a
            # user-writable location, or carrying an invalid signature. The full
            # process list is inventory (in the CSV), not findings.
            if (-not $fromWritable -and -not $badSignature) { continue }

            $why = @()
            if ($fromWritable) { $why += 'runs from a user-writable path' }
            if ($badSignature) { $why += "signature status is '$($record.Process_Signed)'" }

            New-Finding `
                -Finding_ID 'PROC-001' `
                -Severity 'Medium' `
                -Confidence 'Medium' `
                -Category 'Process Inventory' `
                -Target "$scannedHost\$($record.Process_Name) (PID $($record.Process_PID))" `
                -Finding 'Running process is suspicious.' `
                -Evidence "$($record.Process_Name) ($(($why) -join '; ')). Path: $($record.Process_Path). Command line: $($record.Process_CommandLine). Owner: $($record.Process_Owner)." `
                -Recommendation 'Verify this process is legitimate. A signed binary from a standard location is expected; an unsigned binary running from a user-writable path warrants investigation.'

            continue
        }

        # ------------------------------------ filesystem credentials (CRED-002) ---
        if ($record.Check -eq 'FilesystemCredential') {

            New-Finding `
                -Finding_ID 'CRED-002' `
                -Severity 'High' `
                -Confidence 'Medium' `
                -Category 'Credential Exposure' `
                -Target $record.Item `
                -Finding 'Possible credential found on the filesystem.' `
                -Evidence "$($record.Detail) $($record.Risk_Hint)" `
                -Recommendation 'Review the file, rotate any exposed credential, and remove the secret from disk. Store secrets in a vault or use managed identities instead of files.'

            continue
        }
    }
}


# ==========================================================================
# SOURCE: Correlation\Invoke-FGPPFindings.ps1
# ==========================================================================
function Invoke-FGPPFindings {
<#
.SYNOPSIS
    DOM-006 (weak PSO) and ID-011 (privileged identity without a directly assigned PSO).
.DESCRIPTION
    [FIX] PARSE ERROR: the minimum-length comparison was written as
        [int]$pso.MinPasswordLength -
        lt
        [int]$pso.Domain_Default_MinLength
    The '-lt' operator was split across lines, which does not parse. This file failed
    to load, so BOTH DOM-006 and ID-011 were silently absent from every assessment.

    [FIX] Tier 0 escalation now resolves AppliesTo names to group SIDs via
    Resolve-PrincipalRiskContext (previously defined but never called anywhere) and
    only falls back to the collector's name heuristic when nothing resolves.
    Confidence tracks that certainty: High when SID-resolved, Medium on fallback.

    [FIX] ID-011 previously keyed the domain baseline off $fgpp[0], so a domain with a
    weak default and NO PSOs produced no finding. Now reads the domain summary and
    runs independently of whether any PSO exists.
#>
    param($Context)

    $fgpp   = $Context.Data.FGPP
    $groups = $Context.Data.Groups
    $domain = $Context.Data.Domain

    # ---------------------------------------------------------------- DOM-006
    if ($fgpp) {

        foreach ($pso in $fgpp) {

            $weaknesses = @()

            $psoMin      = ConvertTo-Int $pso.MinPasswordLength
            $baselineMin = ConvertTo-Int $pso.Domain_Default_MinLength

            if ($psoMin -gt 0 -and $psoMin -lt $baselineMin) {
                $weaknesses += "MinPasswordLength $psoMin is below the domain default of $baselineMin"
            }

            if (-not (ConvertTo-Bool $pso.ComplexityEnabled) -and (ConvertTo-Bool $pso.Domain_Default_Complexity)) {
                $weaknesses += 'Complexity disabled while the domain default enables it'
            }

            if (ConvertTo-Bool $pso.ReversibleEncryptionEnabled) {
                $weaknesses += 'Reversible encryption enabled'
            }

            if ($weaknesses.Count -eq 0) { continue }

            # Resolve each AppliesTo name to a SID and test Tier 0 properly.
            $isTier0    = $false
            $sidResolved = $false

            foreach ($name in (@($pso.AppliesTo_Names -split ';') | Where-Object { $_ })) {

                $ctx = Resolve-PrincipalRiskContext -PrincipalName $name.Trim() -Groups $groups

                if ($ctx.Resolution -eq 'SID') { $sidResolved = $true }
                if ($ctx.IsTier0)              { $isTier0 = $true }
            }

            if (-not $sidResolved -and (ConvertTo-Bool $pso.Applies_To_Privileged_Name_Match)) {
                $isTier0 = $true
            }

            $basis = if ($sidResolved) { 'SID-resolved' } else { 'name heuristic (unresolved)' }

            # Severity = impact. Confidence = certainty of the Tier 0 call.
            $severity   = if ($isTier0) { 'High' } else { 'Medium' }
            $confidence = if (-not $isTier0 -or $sidResolved) { 'High' } else { 'Medium' }

            New-Finding `
                -Finding_ID 'DOM-006' `
                -Severity $severity `
                -Confidence $confidence `
                -Category 'Password Policy' `
                -Target $pso.Name `
                -Finding 'Fine-grained password policy is weaker than the domain baseline.' `
                -Evidence "$($weaknesses -join '; '). AppliesTo: $($pso.AppliesTo_Names). Tier0=$isTier0 ($basis)." `
                -Recommendation 'Align the PSO with the organizational baseline and scope weak PSOs away from privileged principals.'
        }
    }

    # ---------------------------------------------------------------- ID-011
    # Domain baseline is read from the domain summary so this runs even with no PSOs.
    $domainMin = ConvertTo-Int $domain.MinPwdLength

    if ($domainMin -le 0 -or $domainMin -ge $script:TJETConfig.PrivilegedPasswordBaselineLength) {
        return
    }

    foreach ($user in $Context.Data.Users) {

        if (-not $Context.IsPrivilegedSid($user.ObjectSID)) { continue }

        # [FIX] This loop had no Enabled check, unlike Invoke-IdentityFindings, so
        # disabled accounts produced password-policy findings.
        if ($user.PSObject.Properties.Name -contains 'Enabled' -and
            -not (ConvertTo-Bool $user.Enabled)) {
            continue
        }

        # [FIX] krbtgt (RID 502) and Guest (RID 501) have machine-generated or
        # disabled credentials that no password policy governs. krbtgt's password is
        # 128 characters and never user-set, so flagging it for a weak domain minimum
        # is meaningless.
        if ($user.ObjectSID -match '-(501|502)$') { continue }

        # Direct assignment only. Group-based PSO inheritance is NOT resolved here;
        # the finding text and Confidence=Medium both say so explicitly.
        $covered = $false

        foreach ($pso in $fgpp) {
            if ($user.DistinguishedName -and $pso.AppliesTo -match [regex]::Escape($user.DistinguishedName)) {
                $covered = $true
                break
            }
        }

        if ($covered) { continue }

        New-Finding `
            -Finding_ID 'ID-011' `
            -Severity 'High' `
            -Confidence 'Medium' `
            -Category 'Identity' `
            -Target $user.SamAccountName `
            -Target_GUID $user.ObjectGUID `
            -Finding 'Privileged identity has no directly assigned fine-grained password policy.' `
            -Evidence "Domain default MinPasswordLength=$domainMin is below the privileged baseline of $($script:TJETConfig.PrivilegedPasswordBaselineLength). Group-based PSO inheritance was not evaluated." `
            -Recommendation 'Assign a strong PSO to privileged accounts or their groups.'
    }
}


# ==========================================================================
# SOURCE: Correlation\Invoke-GMSAFindings.ps1
# ==========================================================================
function Invoke-GMSAFindings {
<#
.SYNOPSIS
    GMSA-001: managed service account password retrievable by a broad principal.
.DESCRIPTION
    Anyone who can retrieve the managed password can authenticate as the service. When
    that is Domain Users or Authenticated Users, every account in the domain can become
    the service -- which defeats the entire point of using a gMSA.

    [FIX] Matching now considers both the raw attribute value and the extracted leaf
    names. PrincipalsAllowedToRetrieveManagedPassword serialises differently across
    environments (DN, NT account name, or SID); matching only the raw string would
    silently miss "CN=Domain Users,CN=Users,DC=..." in some domains and match it in
    others. This was the last field in the framework with no live validation.

    Retrieval by a Tier 0 group is deliberately NOT reported: those principals are
    already privileged, so it is not an escalation.
#>
    param($Context)

    $broadPrincipals = 'Domain Users|Authenticated Users|Everyone|Domain Computers|Users'

    foreach ($gmsa in $Context.Data.ServiceAccounts) {

        $raw   = "$($gmsa.Retrieval_Principals)"
        $names = "$($gmsa.Retrieval_Principal_Names)"

        $combined = ($raw, $names | Where-Object { $_ }) -join ';'

        if ([string]::IsNullOrWhiteSpace($combined)) { continue }

        if ($combined -notmatch $broadPrincipals) { continue }

        New-Finding `
            -Finding_ID 'GMSA-001' `
            -Severity 'Critical' `
            -Confidence 'High' `
            -Category 'Service Account' `
            -Target $gmsa.Name `
            -Target_GUID $gmsa.ObjectGUID `
            -Finding 'Broad principal can retrieve managed service account password material.' `
            -Evidence "Retrieval principals: $combined. Any member of these groups can authenticate as this service account." `
            -Recommendation 'Restrict PrincipalsAllowedToRetrieveManagedPassword to the specific host group that runs the service.'
    }
}


# ==========================================================================
# SOURCE: Correlation\Invoke-GPOFindings.ps1
# ==========================================================================
function Invoke-GPOFindings {
<#
.SYNOPSIS
    GPO delegation and SYSVOL permission detections.
.DESCRIPTION
    [NEW] There was no GPO correlation at all in this revision (and no GPO collector
    either). GPO edit rights and SYSVOL modify rights are direct code-execution paths
    onto every machine the policy applies to.
#>
    param($Context)

    foreach ($gpo in $Context.Data.GPOs) {

        # ------------------------------------------- GPO-001 broad edit rights
        if (ConvertTo-Bool $gpo.Has_Broad_Modify_Right) {

            # A GPO linked to the Domain Controllers OU is a Tier 0 code path.
            $severity = if ($gpo.Linked_To -match '(?i)Domain Controllers') { 'Critical' } else { 'High' }

            New-Finding `
                -Finding_ID 'GPO-001' `
                -Severity $severity `
                -Confidence 'High' `
                -Category 'Policy' `
                -Target $gpo.GPO_Name `
                -Target_GUID $gpo.GPO_GUID `
                -Finding 'Group Policy Object can be modified by a broad, low-privilege principal.' `
                -Evidence "Permissions: $($gpo.Permissions)" `
                -Recommendation 'Restrict GPO edit rights to Domain Admins or a dedicated delegated group.'
        }

        # -------------------------------------- GPO-002 SYSVOL modify rights
        if (ConvertTo-Bool $gpo.Has_Unexpected_SYSVOL_Rights) {

            New-Finding `
                -Finding_ID 'GPO-002' `
                -Severity 'High' `
                -Confidence 'Medium' `
                -Category 'Policy' `
                -Target $gpo.GPO_Name `
                -Target_GUID $gpo.GPO_GUID `
                -Finding 'Principals outside the administrative baseline have Modify rights on the GPO SYSVOL folder.' `
                -Evidence "Unexpected principals: $($gpo.SYSVOL_Unexpected_Modify)" `
                -Recommendation 'Restore default SYSVOL folder permissions for this policy.'
        }

        # ------------------------------------- GPO-003 privileged user rights
        # [FIX] This previously fired on the Default Domain Controllers Policy, whose
        # entire purpose is to assign SeDebugPrivilege and similar to Administrators.
        # Reporting the shipped default as a Medium finding is unactionable noise that
        # appears in every domain. Built-in default policies are now excluded; a
        # CUSTOM policy granting privileged rights is what warrants review.
        $isDefaultPolicy = $gpo.GPO_Name -match '(?i)^Default Domain (Controllers )?Policy$'

        if ((ConvertTo-Bool $gpo.Has_Privileged_UserRights) -and -not $isDefaultPolicy) {

            New-Finding `
                -Finding_ID 'GPO-003' `
                -Severity 'Medium' `
                -Confidence 'Medium' `
                -Category 'Policy' `
                -Target $gpo.GPO_Name `
                -Target_GUID $gpo.GPO_GUID `
                -Finding 'Non-default Group Policy Object assigns privileged user rights.' `
                -Evidence "Privileged user-right assignments (for example SeDebugPrivilege, SeBackupPrivilege, SeTakeOwnershipPrivilege) detected in a custom policy. SeBackupPrivilege alone permits reading NTDS.dit. Linked to: $($gpo.Linked_To)" `
                -Recommendation 'Confirm these rights are granted only to the intended administrative tier, and only on the systems that require them.'
        }
    }
}


# ==========================================================================
# SOURCE: Correlation\Invoke-GroupFindings.ps1
# ==========================================================================
function Invoke-GroupFindings {
<#
.SYNOPSIS
    GRP-001 (empty privileged group) and GRP-002 (Tier 0 group without an owner).
.DESCRIPTION
    Rewritten after a live run produced 23 findings of which 22 were default AD state.

    [FIX] GRP-001 reported "Domain Controllers" and "Read-only Domain Controllers" as
    empty. They are not -- membership is conferred by primaryGroupID, not the `member`
    attribute. The collector now accounts for that.

    [FIX] GRP-001 fired at High for built-in operator groups that ship empty. An empty
    Account Operators group is the HARDENED state, recommended by CIS and Microsoft.
    Flagging it told administrators to break a correct configuration. Now limited to
    custom groups and reduced to Low.

    [FIX] GRP-002 fired for all 12 built-in groups because Microsoft never populates
    ManagedBy on them. That is unactionable by definition. Now limited to custom Tier 0
    groups and reduced to Info.
#>
    param($Context)

    foreach ($group in $Context.Data.Groups) {

        $isDefault = ConvertTo-Bool $group.Is_Default_Group
        $isTier0   = ConvertTo-Bool $group.Is_Tier0

        # ------------------------------------------------------------- GRP-001 ---
        # A custom group that carries privilege but has no members is unmonitored
        # privilege: adding one member is a quiet escalation. Built-in groups are
        # excluded because empty is their correct, shipped state.
        if ((ConvertTo-Bool $group.Is_Empty_Privileged) -and -not $isDefault) {

            New-Finding `
                -Finding_ID 'GRP-001' `
                -Severity 'Low' `
                -Confidence 'High' `
                -Category 'Privilege' `
                -Target $group.Name `
                -Target_GUID $group.ObjectGUID `
                -Finding 'Custom privileged group has no members.' `
                -Evidence 'Group carries Tier 0 or adminCount privilege but contains zero members. Membership changes to an unused privileged group are easily missed.' `
                -Recommendation 'Delete the group if it is genuinely unused, or monitor it for membership changes.'
        }

        # ------------------------------------------------------------- GRP-002 ---
        if ($isTier0 -and -not $isDefault -and -not (ConvertTo-Bool $group.Has_Owner)) {

            New-Finding `
                -Finding_ID 'GRP-002' `
                -Severity 'Info' `
                -Confidence 'High' `
                -Category 'Privilege' `
                -Target $group.Name `
                -Target_GUID $group.ObjectGUID `
                -Finding 'Custom Tier 0 group has no accountable owner recorded.' `
                -Evidence 'ManagedBy is empty on a custom privileged group.' `
                -Recommendation 'Set ManagedBy and include the group in periodic access reviews.'
        }

        # ------------------------------------------------------------- GRP-003 ---
        # A Tier 0 group nested into another group extends privilege to that group's
        # members, which membership reviews of the Tier 0 group will not reveal.
        if ($isTier0 -and (ConvertTo-Int $group.Outbound_Nesting_Count) -gt 0) {

            New-Finding `
                -Finding_ID 'GRP-003' `
                -Severity 'Medium' `
                -Confidence 'Medium' `
                -Category 'Privilege' `
                -Target $group.Name `
                -Target_GUID $group.ObjectGUID `
                -Finding 'Tier 0 group is nested inside another group.' `
                -Evidence "Group is a member of $($group.Outbound_Nesting_Count) other group(s), extending its privilege beyond its direct membership." `
                -Recommendation 'Flatten privileged group nesting so that Tier 0 membership is explicit.'
        }
    }
}


# ==========================================================================
# SOURCE: Correlation\Invoke-IdentityFindings.ps1
# ==========================================================================
function Invoke-IdentityFindings {
<#
.SYNOPSIS
    Identity-layer detections.
.DESCRIPTION
    [FIX] Privileged lookups used $user.SID; detectors now key consistently on
    ObjectSID (with the context builder accepting either).

    [FIX] Restored detections whose data was already being collected but had no
    consumer at all: ID-001 (Kerberoasting), ID-002 (constrained delegation),
    ID-004 (unconstrained delegation on a user), ID-005 (SIDHistory), ID-006
    (dormant privileged account) and ID-010 (PasswordNotRequired). Collecting an
    attribute and never evaluating it is indistinguishable from not collecting it.

    [FIX] ID-007 severity/confidence now scale with privilege rather than being flat.
#>
    param($Context)

    foreach ($user in $Context.Data.Users) {

        # Disabled accounts carry stale flags; evaluating them creates noise.
        if ($user.PSObject.Properties.Name -contains 'Enabled' -and
            -not (ConvertTo-Bool $user.Enabled)) {
            continue
        }

        $isPrivileged = [bool](
            $Context.IsPrivilegedSid($user.ObjectSID) -or
            (ConvertTo-Bool $user.Potentially_Privileged_Direct) -or
            (ConvertTo-Bool $user.Has_AdminCount)
        )

        # ---------------------------------------------------- ID-001 Kerberoasting
        # [FIX] Previously required the account to be privileged, so an ordinary
        # service account with an SPN produced no finding at all -- despite being the
        # standard Kerberoasting target. Any SPN-bearing user account is roastable by
        # any authenticated user; privilege now scales the severity rather than
        # gating the detection.
        if (ConvertTo-Bool $user.Has_SPNs) {

            $pwdAge = ConvertTo-Int $user.Password_Age_Days

            $severity = 'Medium'

            if ($isPrivileged) {
                $severity = 'High'
                if ($pwdAge -gt 365) { $severity = 'Critical' }
            }
            elseif ($pwdAge -gt 365) {
                $severity = 'High'
            }

            # NOTE: must NOT be named $context. PowerShell variable names are
            # case-insensitive, so $context and the $Context parameter are the SAME
            # variable -- assigning here replaced the correlation context with a
            # string and every later $Context.IsPrivilegedSid() call threw, aborting
            # this entire detector and silently losing seven detections.
            $privilegeLabel = 'standard account'

            if ($isPrivileged) { $privilegeLabel = 'PRIVILEGED account' }

            New-Finding `
                -Finding_ID 'ID-001' `
                -Severity $severity `
                -Confidence 'High' `
                -Category 'Identity' `
                -Target $user.SamAccountName `
                -Target_GUID $user.ObjectGUID `
                -Finding 'User account has a Service Principal Name (Kerberoasting exposure).' `
                -Evidence "SPN present on a $privilegeLabel. Password age: $pwdAge days. Any authenticated user can request a service ticket for this account and crack it offline." `
                -Recommendation 'Migrate to a group managed service account (gMSA), which rotates a 120-character password automatically. Otherwise set a 25+ character random password.'
        }

        # ------------------------------------------- ID-002 constrained delegation
        if (ConvertTo-Bool $user.Has_Delegation_Targets) {

            New-Finding `
                -Finding_ID 'ID-002' `
                -Severity 'High' `
                -Confidence 'High' `
                -Category 'Identity' `
                -Target $user.SamAccountName `
                -Target_GUID $user.ObjectGUID `
                -Finding 'Constrained delegation is configured on a user account.' `
                -Evidence 'msDS-AllowedToDelegateTo is populated.' `
                -Recommendation 'Review the delegation requirement and prefer resource-based constrained delegation.'
        }

        # ----------------------------------------- ID-004 unconstrained delegation
        if (ConvertTo-Bool $user.Has_Unconstrained_Delegation) {

            New-Finding `
                -Finding_ID 'ID-004' `
                -Severity 'Critical' `
                -Confidence 'High' `
                -Category 'Identity' `
                -Target $user.SamAccountName `
                -Target_GUID $user.ObjectGUID `
                -Finding 'Unconstrained delegation is enabled on a user account.' `
                -Evidence 'TrustedForDelegation=True.' `
                -Recommendation 'Remove unconstrained delegation; use resource-based constrained delegation instead.'
        }

        # ------------------------------------------------------- ID-005 SIDHistory
        if ($user.SIDHistory_Values) {

            $privilegedSid = Get-PrivilegedSidFromHistory $user.SIDHistory_Values

            if ($privilegedSid) {
                New-Finding `
                    -Finding_ID 'ID-005' `
                    -Severity 'Critical' `
                    -Confidence 'High' `
                    -Category 'Identity' `
                    -Target $user.SamAccountName `
                    -Target_GUID $user.ObjectGUID `
                    -Finding 'Account SIDHistory contains a Tier 0 privileged SID.' `
                    -Evidence "Privileged SID in history: $privilegedSid" `
                    -Recommendation 'Investigate immediately for intra-domain escalation and clear SIDHistory once migration is complete.'
            }
            else {
                New-Finding `
                    -Finding_ID 'ID-005' `
                    -Severity 'High' `
                    -Confidence 'Medium' `
                    -Category 'Identity' `
                    -Target $user.SamAccountName `
                    -Target_GUID $user.ObjectGUID `
                    -Finding 'Account has a populated SIDHistory attribute.' `
                    -Evidence "SIDHistory: $($user.SIDHistory_Values)" `
                    -Recommendation 'Clear SIDHistory once migration is complete to prevent token bloat and abuse.'
            }
        }

        # ------------------------------------------- ID-006 dormant privileged acct
        if ($isPrivileged -and (ConvertTo-Bool $user.Is_Stale_180Days)) {

            New-Finding `
                -Finding_ID 'ID-006' `
                -Severity 'High' `
                -Confidence 'Medium' `
                -Category 'Identity' `
                -Target $user.SamAccountName `
                -Target_GUID $user.ObjectGUID `
                -Finding 'Dormant privileged account detected.' `
                -Evidence 'Account is older than 180 days with no logon in the last 180 days (lastLogonTimestamp is approximate).' `
                -Recommendation 'Disable dormant administrative accounts.'
        }

        # ------------------------------------------------- ID-007 AS-REP roasting
        if (ConvertTo-Bool $user.Has_ASREP_Risk) {

            New-Finding `
                -Finding_ID 'ID-007' `
                -Severity $(if ($isPrivileged) { 'Critical' } else { 'High' }) `
                -Confidence $(if ($isPrivileged) { 'High' } else { 'Medium' }) `
                -Category 'Identity' `
                -Target $user.SamAccountName `
                -Target_GUID $user.ObjectGUID `
                -Finding 'Account does not require Kerberos pre-authentication (AS-REP roastable).' `
                -Evidence "DoesNotRequirePreAuth=True. Privileged=$isPrivileged." `
                -Recommendation 'Remove the DONT_REQ_PREAUTH flag; if unavoidable, enforce a long complex password.'
        }

        # -------------------------------------------- ID-008 shadow credentials
        if (ConvertTo-Bool $user.Has_Shadow_Credentials) {

            New-Finding `
                -Finding_ID 'ID-008' `
                -Severity $(if ($isPrivileged) { 'High' } else { 'Medium' }) `
                -Confidence 'Medium' `
                -Category 'Identity' `
                -Target $user.SamAccountName `
                -Target_GUID $user.ObjectGUID `
                -Finding 'Account has msDS-KeyCredentialLink populated (possible shadow credentials).' `
                -Evidence "Key credential material present. Privileged=$isPrivileged. Windows Hello and device registration populate this legitimately." `
                -Recommendation 'Validate each key credential is an expected registration and remove unrecognized entries.'
        }

        # --------------------------------------- ID-009 / ID-010 password hygiene
        if ($isPrivileged -and (ConvertTo-Bool $user.PasswordNeverExpires)) {

            New-Finding `
                -Finding_ID 'ID-009' `
                -Severity 'High' `
                -Confidence 'High' `
                -Category 'Identity' `
                -Target $user.SamAccountName `
                -Target_GUID $user.ObjectGUID `
                -Finding 'Privileged account is set to never expire its password.' `
                -Evidence 'PasswordNeverExpires=True on a privileged identity.' `
                -Recommendation 'Remove PasswordNeverExpires or migrate to a managed (gMSA) identity.'
        }

        if ($isPrivileged -and (ConvertTo-Bool $user.PasswordNotRequired)) {

            New-Finding `
                -Finding_ID 'ID-010' `
                -Severity 'Critical' `
                -Confidence 'High' `
                -Category 'Identity' `
                -Target $user.SamAccountName `
                -Target_GUID $user.ObjectGUID `
                -Finding 'Privileged account has the PASSWD_NOTREQD flag set.' `
                -Evidence 'PasswordNotRequired=True on a privileged identity.' `
                -Recommendation 'Clear the PASSWD_NOTREQD flag and set a compliant password immediately.'
        }
    }
}


# ==========================================================================
# SOURCE: Correlation\Invoke-LocalFindings.ps1
# ==========================================================================
function Invoke-LocalFindings {
<#
.SYNOPSIS
    LOCAL-*: host privilege-escalation and hardening findings, scoped by run context.
.DESCRIPTION
    [FIX] When the assessment already runs as a local administrator, listing every
    privilege-escalation route is noise: the operator cannot escalate to something they
    already hold. Worse, several checks fire *because* the context is privileged --
    an administrator inherently holds SeDebugPrivilege, SeBackupPrivilege,
    SeRestorePrivilege and SeTakeOwnershipPrivilege, so LOCAL-007 would flag the
    assessment's own token every time.

    Behaviour now depends on the scan context:

    PRIVILEGED RUN
        Emits LOCAL-000 once, recording that the scan ran with administrative rights.
        Then reports only the checks that represent a route an UNPRIVILEGED user could
        take to elevate on this host -- the genuinely useful output, because the
        operator is assessing the host's exposure, not their own.
        Findings are worded from the unprivileged attacker's perspective.

    UNPRIVILEGED RUN
        Reports everything, including privileges held by the current context, because
        each one is a live escalation route for the operator right now.

    Host-hardening checks (UAC, credential protection, SMB signing, legacy protocols)
    are reported in both contexts -- they describe the host, not the operator.
#>
    param($Context)

    $checkMap = @{
        'UnquotedServicePath'   = @{ Id = 'LOCAL-001'; Severity = 'High';     Category = 'Local PrivEsc';        UnprivPath = $true  }
        'ModifiableService'     = @{ Id = 'LOCAL-002'; Severity = 'Critical'; Category = 'Local PrivEsc';        UnprivPath = $true  }
        'AlwaysInstallElevated' = @{ Id = 'LOCAL-003'; Severity = 'Critical'; Category = 'Local PrivEsc';        UnprivPath = $true  }
        'WritablePathDir'       = @{ Id = 'LOCAL-004'; Severity = 'High';     Category = 'Local PrivEsc';        UnprivPath = $true  }
        'Autorun'               = @{ Id = 'LOCAL-005'; Severity = 'High';     Category = 'Local PrivEsc';        UnprivPath = $true  }
        'StoredCredential'      = @{ Id = 'LOCAL-006'; Severity = 'High';     Category = 'Credential Exposure';  UnprivPath = $true  }
        'TokenPrivilege'        = @{ Id = 'LOCAL-007'; Severity = 'Critical'; Category = 'Local PrivEsc';        UnprivPath = $false }
        'UACConfig'             = @{ Id = 'LOCAL-008'; Severity = 'Medium';   Category = 'Host Hardening';       UnprivPath = $true  }
        'CredentialProtection'  = @{ Id = 'LOCAL-009'; Severity = 'High';     Category = 'Host Hardening';       UnprivPath = $true  }
        'SMBSigning'            = @{ Id = 'LOCAL-010'; Severity = 'Medium';   Category = 'Host Hardening';       UnprivPath = $true  }
        'LegacyProtocol'        = @{ Id = 'LOCAL-011'; Severity = 'Medium';   Category = 'Host Hardening';       UnprivPath = $true  }

        # Extended WinPEAS-style checks.
        'ScheduledTask'         = @{ Id = 'LOCAL-012'; Severity = 'Critical'; Category = 'Local PrivEsc';       UnprivPath = $true  }
        'DLLHijack'             = @{ Id = 'LOCAL-013'; Severity = 'High';     Category = 'Local PrivEsc';       UnprivPath = $true  }
        'PowerShellHistory'     = @{ Id = 'LOCAL-014'; Severity = 'High';     Category = 'Credential Exposure'; UnprivPath = $true  }
        'UnattendFile'          = @{ Id = 'LOCAL-015'; Severity = 'Critical'; Category = 'Credential Exposure'; UnprivPath = $true  }
        'CloudCredential'       = @{ Id = 'LOCAL-016'; Severity = 'High';     Category = 'Credential Exposure'; UnprivPath = $true  }
        'SSHKey'                = @{ Id = 'LOCAL-017'; Severity = 'High';     Category = 'Credential Exposure'; UnprivPath = $true  }
        'SessionManager'        = @{ Id = 'LOCAL-018'; Severity = 'Medium';   Category = 'Credential Exposure'; UnprivPath = $true  }
        'RegistryCredential'    = @{ Id = 'LOCAL-019'; Severity = 'Critical'; Category = 'Credential Exposure'; UnprivPath = $true  }
        'AccessibilityBackdoor' = @{ Id = 'LOCAL-020'; Severity = 'Critical'; Category = 'Persistence';         UnprivPath = $true  }
        'WSUSConfig'            = @{ Id = 'LOCAL-021'; Severity = 'High';     Category = 'Host Hardening';      UnprivPath = $true  }
        'RDPConfig'             = @{ Id = 'LOCAL-022'; Severity = 'Medium';   Category = 'Host Hardening';      UnprivPath = $true  }
        'DefenderStatus'        = @{ Id = 'LOCAL-023'; Severity = 'High';     Category = 'Host Hardening';      UnprivPath = $true  }
        'FirewallProfile'       = @{ Id = 'LOCAL-024'; Severity = 'Medium';   Category = 'Host Hardening';      UnprivPath = $true  }
        'SpoolerService'        = @{ Id = 'LOCAL-025'; Severity = 'Medium';   Category = 'Host Hardening';      UnprivPath = $true  }
        'ShareExposure'         = @{ Id = 'LOCAL-026'; Severity = 'Low';      Category = 'Host Hardening';      UnprivPath = $true  }
        'LocalAdminMember'      = @{ Id = 'LOCAL-027'; Severity = 'Medium';   Category = 'Local PrivEsc';       UnprivPath = $false }
    }

    $records = @($Context.Data.LocalHost)

    if ($records.Count -eq 0) { return }

    # The collector stamps every row with two facts: whether the PROCESS was elevated,
    # and whether the USER is an admin member. Scoping is driven by MEMBERSHIP: an admin
    # who happens to be running unelevated can escalate at will, so privesc routes that
    # only help an admin are noise for them too. What is useful is what a genuinely
    # non-privileged user could exploit.
    $elevated    = $false
    $adminMember = $false

    foreach ($record in $records) {
        if (ConvertTo-Bool $record.Is_Elevated_Scan) { $elevated = $true }
        if (ConvertTo-Bool $record.Is_Admin_Member)  { $adminMember = $true }
    }

    # Treat "admin member" as the scoping trigger. (Elevated implies admin member.)
    $scopeToUnprivileged = $adminMember

    $scannedHost = $env:COMPUTERNAME

    foreach ($record in $records) {
        if ($record.Scanned_Host) { $scannedHost = $record.Scanned_Host; break }
    }

    # ------------------------------------------------------------- LOCAL-000 ---
    if ($adminMember) {

        $contextDetail = if ($elevated) {
            'The scanning account holds local administrator rights and the process was elevated.'
        }
        else {
            'The scanning account is a member of a local administrator group but the process was NOT elevated. Because the user could elevate at will, escalation routes that only benefit an administrator are still treated as noise.'
        }

        New-Finding `
            -Finding_ID 'LOCAL-000' `
            -Severity 'Info' `
            -Confidence 'High' `
            -Category 'Assessment Context' `
            -Target $scannedHost `
            -Finding 'Assessment was run by a local administrator; privesc findings are scoped to non-privileged escalation routes.' `
            -Evidence "$contextDetail Privilege-escalation routes available only to an administrator are not reported. Findings below describe routes a genuinely UNPRIVILEGED user on this host could take." `
            -Recommendation 'To enumerate every route from a true standard-user perspective, re-run this assessment as a non-administrative account that is not a member of any administrator-equivalent group.'
    }

    foreach ($record in $records) {

        $mapping = $checkMap[$record.Check]

        if (-not $mapping) { continue }

        # In a privileged run, drop the checks that only matter because the operator
        # is already an administrator. TokenPrivilege is the main one: an admin token
        # legitimately carries SeDebug/SeBackup/SeRestore/SeTakeOwnership.
        if ($scopeToUnprivileged -and -not $mapping.UnprivPath) {

            # SeImpersonatePrivilege is the exception worth keeping: it is held by
            # service accounts, so its presence still indicates a service-context
            # escalation route independent of the operator's own rights.
            if ("$($record.Detail)$($record.Item)" -notmatch '(?i)SeImpersonate|SeAssignPrimaryToken') {
                continue
            }
        }

        $target = $record.Item

        if ([string]::IsNullOrWhiteSpace($target)) { $target = $record.Check }

        # Host-hardening findings (UAC, LSA protection, Defender, SMB signing, legacy
        # protocols) describe the host's posture -- they are NOT routes a non-privileged
        # user can walk to elevate, so they must not claim to be. Only genuine PrivEsc /
        # Credential-Exposure checks get the escalation wording.
        $isEscalationRoute = $mapping.Category -in 'Local PrivEsc', 'Credential Exposure'

        $perspective = if (-not $isEscalationRoute) {
            'This is a host-hardening gap that weakens the host''s defenses; it is not by itself an unprivileged escalation route.'
        }
        elseif ($scopeToUnprivileged) {
            'An unprivileged user on this host could use this to elevate.'
        }
        else {
            'This is a live escalation route from the current unprivileged context.'
        }

        New-Finding `
            -Finding_ID $mapping.Id `
            -Severity $mapping.Severity `
            -Confidence 'High' `
            -Category $mapping.Category `
            -Target "$scannedHost\$target" `
            -Finding $record.Detail `
            -Evidence "$($record.Risk_Hint) $perspective (Scan elevated: $elevated; admin member: $adminMember)" `
            -Recommendation 'See remediation steps.'
    }
}


# ==========================================================================
# SOURCE: Correlation\Invoke-OfflineCVEScan.ps1
# ==========================================================================
function Invoke-OfflineCVEScan {
<#
.SYNOPSIS
    Matches the collected software inventory against a local MITRE CVE database.
.DESCRIPTION
    An offline vulnerability scan. Reads the software inventory produced by
    Collect-SoftwareInventory and looks each product up in a local SQLite database built
    from MITRE's cvelistV5, emitting a CVE-* finding per credible match.

    Database contract (as built by the user's ingestion script):

        table  vulnerabilities(id, cve_id, product_name, vendor_name, vulnerable_spec)
        index  idx_product on product_name
        vulnerable_spec is one of:
            "Ver: X to <Y"   -> affected range  [X, Y)
            "Ver: X"         -> exact affected version X

    Matching is deliberately conservative, because a CVE feed keyed on free-text product
    names is noisy and a scan that cries wolf gets ignored:

    1. PRODUCT MATCH. The installed DisplayName is normalised (lowercased, version
       numbers and edition words stripped) and matched against product_name. An exact
       normalised match is High confidence; a contained-substring match is Medium.
    2. VERSION MATCH. The installed version is parsed and tested against vulnerable_spec.
       A range hit ([X,Y)) is reported. An exact-version spec must equal the installed
       version. If either version cannot be parsed, the match is reported at LOW
       confidence and flagged for manual triage rather than dropped or over-claimed.

    Requires the PSSQLite module and the database. Both are checked at call time; if
    either is absent the scan is skipped with a clear message rather than failing the
    assessment. This detector is OFF by default in the orchestrator and enabled with
    -IncludeCVEScan, because it depends on infrastructure the user has to build.

    Findings never claim exploitability -- a CVE being present is not proof the code path
    is reachable. The recommendation says "validate and patch", not "you are owned".
#>
    [CmdletBinding()]
    param(
        $Context,

        [string]$DatabasePath = 'C:\Security\cves.db',

        # Products whose CVE noise is not worth the triage cost by default.
        [string[]]$ExcludeProducts = @()
    )

    # ------------------------------------------------------- preconditions ---
    if (-not (Test-Path $DatabasePath)) {
        Write-TJETLog WARNING "CVE database not found at $DatabasePath. Skipping offline CVE scan."
        return
    }

    if (-not (Get-Module -ListAvailable -Name PSSQLite)) {
        Write-TJETLog WARNING 'PSSQLite module not available. Install it (Install-Module PSSQLite) to enable the offline CVE scan. Skipping.'
        return
    }

    try {
        Import-Module PSSQLite -ErrorAction Stop
    }
    catch {
        Write-TJETLog ERROR "Failed to import PSSQLite: $($_.Exception.Message). Skipping CVE scan."
        return
    }

    $software = @($Context.Data.LocalHost | Where-Object {
        $_.Check -eq 'SoftwareInventory' -and $_.Software_Product
    })

    if ($software.Count -eq 0) {
        Write-TJETLog INFO 'No software inventory present; run with software collection to enable the CVE scan.'
        return
    }

    Write-TJETLog INFO "Offline CVE scan: $($software.Count) product(s) against $DatabasePath"

    # ------------------------------------------------------------ helpers ---

    # Normalise a product name to improve the odds of matching a CVE product string:
    # lowercase, drop bracketed/edition noise, drop trailing version numbers.
    function Get-NormalizedProduct {
        param([string]$Name)

        $normalized = $Name.ToLower()
        $normalized = $normalized -replace '\(.*?\)', ' '
        $normalized = $normalized -replace '(?i)\b(x64|x86|64-bit|32-bit|edition|version|professional|enterprise|standard|community|update|kb\d+)\b', ' '
        $normalized = $normalized -replace '\d+(\.\d+)+', ' '        # version-like tokens
        $normalized = $normalized -replace '[^a-z0-9]+', ' '
        return ($normalized -replace '\s+', ' ').Trim()
    }

    # Parse a dotted version into a comparable [version], tolerantly.
    function ConvertTo-ComparableVersion {
        param([string]$Raw)

        if ([string]::IsNullOrWhiteSpace($Raw)) { return $null }

        $match = [regex]::Match($Raw, '\d+(\.\d+){0,3}')
        if (-not $match.Success) { return $null }

        $parts = $match.Value.Split('.')
        while ($parts.Count -lt 2) { $parts += '0' }

        try { return [version]($parts -join '.') }
        catch { return $null }
    }

    # Parse a vulnerable_spec into a testable shape.
    function ConvertFrom-VulnerableSpec {
        param([string]$Spec)

        $result = [PSCustomObject]@{ Kind = 'unknown'; Low = $null; High = $null; Exact = $null; Raw = $Spec }

        if ([string]::IsNullOrWhiteSpace($Spec)) { return $result }

        # "Ver: X to <Y"
        $range = [regex]::Match($Spec, '(?i)Ver:\s*(?<low>\S+)\s*to\s*<\s*(?<high>\S+)')
        if ($range.Success) {
            $result.Kind = 'range'
            $result.Low  = ConvertTo-ComparableVersion $range.Groups['low'].Value
            $result.High = ConvertTo-ComparableVersion $range.Groups['high'].Value
            return $result
        }

        # "Ver: X"
        $exact = [regex]::Match($Spec, '(?i)Ver:\s*(?<v>\S+)')
        if ($exact.Success) {
            $result.Kind  = 'exact'
            $result.Exact = ConvertTo-ComparableVersion $exact.Groups['v'].Value
            return $result
        }

        return $result
    }

    # Test an installed version against a parsed spec.
    function Test-VersionAffected {
        param($Installed, $ParsedSpec)

        # Result: Affected (bool), Certain (bool). Certain is false when a version could
        # not be parsed, which downgrades confidence rather than guessing.
        if ($null -eq $Installed) {
            return [PSCustomObject]@{ Affected = $true; Certain = $false }
        }

        switch ($ParsedSpec.Kind) {

            'range' {
                if ($null -eq $ParsedSpec.Low -or $null -eq $ParsedSpec.High) {
                    return [PSCustomObject]@{ Affected = $true; Certain = $false }
                }
                $affected = ($Installed -ge $ParsedSpec.Low -and $Installed -lt $ParsedSpec.High)
                return [PSCustomObject]@{ Affected = $affected; Certain = $true }
            }

            'exact' {
                if ($null -eq $ParsedSpec.Exact) {
                    return [PSCustomObject]@{ Affected = $true; Certain = $false }
                }
                return [PSCustomObject]@{ Affected = ($Installed -eq $ParsedSpec.Exact); Certain = $true }
            }

            default {
                return [PSCustomObject]@{ Affected = $true; Certain = $false }
            }
        }
    }

    # ------------------------------------------------------------- scan ---
    $matchedCount = 0

    foreach ($product in $software) {

        $displayName = "$($product.Software_Product)".Trim()
        $normalized  = Get-NormalizedProduct $displayName

        if ([string]::IsNullOrWhiteSpace($normalized)) { continue }
        if ($ExcludeProducts -contains $displayName) { continue }

        $installedVersion = ConvertTo-ComparableVersion $product.Software_Version

        # Query on the leading token, which is the indexed column's most selective
        # prefix, then refine in PowerShell. Parameterised to avoid injection and quote
        # breakage from product names with apostrophes.
        $leadToken = ($normalized -split ' ')[0]

        if ($leadToken.Length -lt 3) { continue }   # too generic to query usefully

        try {
            $rows = Invoke-SqliteQuery -DataSource $DatabasePath `
                -Query 'SELECT cve_id, product_name, vendor_name, vulnerable_spec FROM vulnerabilities WHERE product_name LIKE @p' `
                -SqlParameters @{ p = "%$leadToken%" } `
                -ErrorAction Stop
        }
        catch {
            Write-TJETLog WARNING "CVE query failed for '$displayName': $($_.Exception.Message)"
            continue
        }

        if (-not $rows) { continue }

        # De-duplicate: one finding per CVE per product, keeping the best confidence.
        $bestByCve = @{}

        foreach ($row in $rows) {

            $cveProduct    = Get-NormalizedProduct "$($row.product_name)"

            if ([string]::IsNullOrWhiteSpace($cveProduct)) { continue }

            # Product name gate: exact normalised equality, or full-word containment.
            $exactProduct = ($cveProduct -eq $normalized)
            $contains     = ($normalized -like "*$cveProduct*" -or $cveProduct -like "*$normalized*")

            if (-not $exactProduct -and -not $contains) { continue }

            $parsedSpec = ConvertFrom-VulnerableSpec "$($row.vulnerable_spec)"
            $versionTest = Test-VersionAffected -Installed $installedVersion -ParsedSpec $parsedSpec

            if (-not $versionTest.Affected) { continue }

            # Confidence: product exactness AND version certainty both contribute.
            $confidence = if ($exactProduct -and $versionTest.Certain) { 'High' }
                          elseif ($versionTest.Certain) { 'Medium' }
                          else { 'Low' }

            $cveId = "$($row.cve_id)"

            $existing = $bestByCve[$cveId]
            $rank = @{ High = 3; Medium = 2; Low = 1 }

            if ($null -eq $existing -or $rank[$confidence] -gt $rank[$existing.Confidence]) {
                $bestByCve[$cveId] = [PSCustomObject]@{
                    Confidence = $confidence
                    Vendor     = "$($row.vendor_name)"
                    Spec       = "$($row.vulnerable_spec)"
                    Certain    = $versionTest.Certain
                }
            }
        }

        foreach ($cveId in $bestByCve.Keys) {

            $detail = $bestByCve[$cveId]

            $severity = switch ($detail.Confidence) {
                'High'   { 'High' }
                'Medium' { 'Medium' }
                default  { 'Low' }
            }

            $triage = if (-not $detail.Certain) {
                ' Version could not be compared precisely -- verify the installed version against the CVE manually.'
            }
            else { '' }

            New-Finding `
                -Finding_ID 'CVE-001' `
                -Severity $severity `
                -Confidence $detail.Confidence `
                -Category 'Vulnerable Software' `
                -Target "$displayName $($product.Software_Version)" `
                -Finding "Installed software matches a known CVE ($cveId)." `
                -Evidence "$cveId affects $($detail.Vendor) $displayName. Installed version: $($product.Software_Version). Affected spec: $($detail.Spec).$triage Match confidence: $($detail.Confidence)." `
                -Recommendation "Validate whether this host is genuinely affected (the vulnerable component and code path may not be in use), then patch or upgrade $displayName above the affected range. Reference $cveId."

            $matchedCount++
        }
    }

    Write-TJETLog INFO "Offline CVE scan complete: $matchedCount CVE match(es) across $($software.Count) product(s)."
}


# ==========================================================================
# SOURCE: Correlation\Invoke-TrustFindings.ps1
# ==========================================================================
function Invoke-TrustFindings {
<#
.SYNOPSIS
    DOM-004: trusts where SID filtering is genuinely applicable but disabled.
.DESCRIPTION
    [FIX] The previous version flagged every trust with SIDFilteringQuarantined=False,
    which incorrectly reported intra-forest (parent/child) trusts. Within a forest the
    FOREST is the security boundary, not the domain: SID filtering is disabled there by
    design, and enabling quarantine on a parent-child trust breaks normal operation.
    Reporting it is a well-known scanner error that costs credibility with AD teams.

    TrustAttributes was already collected and carries the answer:

        0x00000001 NON_TRANSITIVE
        0x00000004 QUARANTINED_DOMAIN   (SID filtering enabled)
        0x00000008 FOREST_TRANSITIVE    (forest trust -- filtering applicable)
        0x00000020 WITHIN_FOREST        (intra-forest -- filtering NOT applicable)
        0x00000040 TREAT_AS_EXTERNAL
#>
    param($Context)

    foreach ($trust in $Context.Data.Trusts) {

        $attributes = ConvertTo-Int $trust.TrustAttributes

        $withinForest    = [bool]($attributes -band 0x20)
        $forestTransitive = [bool]($attributes -band 0x08)
        $treatAsExternal  = [bool]($attributes -band 0x40)

        # Intra-forest trust: SID filtering is not the applicable control.
        if ($withinForest -and -not $treatAsExternal) {
            Write-Verbose "Skipping intra-forest trust $($trust.Name): SID filtering is not applicable within a forest."
            continue
        }

        if (ConvertTo-Bool $trust.SIDFilteringQuarantined) { continue }

        # A forest trust without SID filtering is serious but bounded by the forest
        # trust's own protections; an external trust is the classic escalation path.
        $isExternal = $treatAsExternal -or ($trust.TrustType -match '(?i)External') -or (-not $forestTransitive)

        $severity = 'High'
        $scope    = 'Forest trust'

        if ($isExternal) {
            $severity = 'Critical'
            $scope    = 'External trust'
        }

        New-Finding `
            -Finding_ID 'DOM-004' `
            -Severity $severity `
            -Confidence 'High' `
            -Category 'Domain' `
            -Target $trust.Name `
            -Finding 'Trust crosses a forest boundary without SID filtering.' `
            -Evidence "$scope. Type: $($trust.TrustType); Direction: $($trust.Direction); TrustAttributes: 0x$('{0:X}' -f $attributes); SIDFilteringQuarantined: False. A compromised principal on the trusted side can inject a privileged SID via SIDHistory." `
            -Recommendation 'Enable SID filtering (quarantine) on this trust. Test first: quarantine breaks access that legitimately depends on SIDHistory.'
    }
}


# ==========================================================================
# SOURCE: Reporting\Compare-ThreatJetBaseline.ps1
# ==========================================================================
function Compare-ThreatJetBaseline {
<#
.SYNOPSIS
    Compares two assessment findings files and reports drift.
.DESCRIPTION
    [FIX] Info-severity findings are now excluded, matching the reporting layer.

    [FIX] Persistent findings and a summary object are now produced. Previously only
    NEW and REMOVED rows were emitted, so "nothing changed" and "comparison failed"
    looked identical.

    The composite key falls back to Target when Target_GUID is 'N/A'. This matters:
    domain and trust findings all carry Target_GUID='N/A', so keying on the GUID alone
    collapses every distinct trust into a single entry and hides remediation.
.PARAMETER CurrentPath
    Path to the current AD_Assessment_Findings.csv.
.PARAMETER BaselinePath
    Path to the earlier AD_Assessment_Findings.csv to compare against.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$CurrentPath,

        [Parameter(Mandatory)]
        [string]$BaselinePath,

        [switch]$IncludeInfo
    )

    foreach ($path in @($CurrentPath, $BaselinePath)) {
        if (-not (Test-Path $path)) {
            Write-TJETLog ERROR "Findings file not found: $path"
            return
        }
    }

    $current  = @(Import-Csv $CurrentPath)
    $baseline = @(Import-Csv $BaselinePath)

    if (-not $IncludeInfo) {
        $current  = @($current  | Where-Object { $_.Severity -ne 'Info' })
        $baseline = @($baseline | Where-Object { $_.Severity -ne 'Info' })
    }

    function Get-FindingKey {
        param($Finding)

        if ($Finding.Target_GUID -and $Finding.Target_GUID -ne 'N/A') {
            return "$($Finding.Finding_ID):$($Finding.Target_GUID)"
        }

        return "$($Finding.Finding_ID):$($Finding.Target)"
    }

    $currentMap  = @{}
    $baselineMap = @{}

    foreach ($finding in $current)  { $currentMap[(Get-FindingKey $finding)]  = $finding }
    foreach ($finding in $baseline) { $baselineMap[(Get-FindingKey $finding)] = $finding }

    $results = New-Object System.Collections.Generic.List[object]

    foreach ($key in $currentMap.Keys) {

        $status = if ($baselineMap.ContainsKey($key)) { 'PERSISTENT' } else { 'NEW' }

        $results.Add([PSCustomObject]@{
            Status     = $status
            Finding_ID = $currentMap[$key].Finding_ID
            Target     = $currentMap[$key].Target
            Severity   = $currentMap[$key].Severity
        })
    }

    foreach ($key in $baselineMap.Keys) {

        if ($currentMap.ContainsKey($key)) { continue }

        $results.Add([PSCustomObject]@{
            Status     = 'RESOLVED'
            Finding_ID = $baselineMap[$key].Finding_ID
            Target     = $baselineMap[$key].Target
            Severity   = $baselineMap[$key].Severity
        })
    }

    Write-TJETLog INFO (
        "Baseline comparison: " +
        "$(@($results | Where-Object Status -eq 'NEW').Count) new, " +
        "$(@($results | Where-Object Status -eq 'RESOLVED').Count) resolved, " +
        "$(@($results | Where-Object Status -eq 'PERSISTENT').Count) persistent"
    )

    return $results
}


# ==========================================================================
# SOURCE: Reporting\Export-Findings.ps1
# ==========================================================================
function Export-Findings {
<#
.SYNOPSIS
    Enriches findings with security-assessment metadata and writes them to CSV.
.DESCRIPTION
    Enrichment happens here rather than in each detector so that the ATT&CK mapping and
    detection guidance live in exactly one place (Get-TJETFindingMetadata) and cannot
    drift between detectors that emit the same Finding_ID.

    Output column order puts the red-team view (what the finding is, what an attacker
    does with it) next to the blue-team view (what to hunt for), which is the point of
    a security-assessment deliverable.
#>
    [CmdletBinding()]
    param(
        [object[]]$Findings,

        [Alias('OutDir')]
        [string]$Path
    )

    $severityOrder = @{
        Critical = 1
        High     = 2
        Medium   = 3
        Low      = 4
        Info     = 5
    }

    $enriched = New-Object System.Collections.Generic.List[object]

    foreach ($finding in $Findings) {

        $meta        = Get-TJETFindingMetadata -FindingId $finding.Finding_ID
        $remediation = Get-TJETRemediation   -FindingId $finding.Finding_ID

        $enriched.Add([PSCustomObject]@{
            Finding_ID          = $finding.Finding_ID
            Assessment_Date     = $finding.Assessment_Date
            Severity            = $finding.Severity
            Confidence          = $finding.Confidence
            Category            = $finding.Category
            Target              = $finding.Target
            Target_GUID         = $finding.Target_GUID
            Finding             = $finding.Finding
            Evidence            = $finding.Evidence
            Attack_Technique    = $meta.Attack_Technique
            MITRE_Technique     = $meta.MITRE_Technique
            Detection_Guidance  = $meta.Detection_Guidance
            Recommendation      = $finding.Recommendation
            Remediation_Steps   = $remediation
            Collector_Version   = $finding.Collector_Version
            Correlation_Version = $finding.Correlation_Version
            Schema_Version      = $finding.Schema_Version
        })
    }

    $sorted = $enriched | Sort-Object `
        @{ Expression = { $severityOrder[$_.Severity] } },
        @{ Expression = { $_.Finding_ID } },
        @{ Expression = { $_.Target } }

    $sorted | Export-Csv -Path (Join-Path $Path 'AD_Assessment_Findings.csv') `
        -NoTypeInformation -Encoding UTF8

    # ATT&CK coverage summary: which techniques this domain is currently exposed to.
    $sorted |
        Group-Object MITRE_Technique |
        Where-Object { $_.Name -ne 'Not mapped' } |
        ForEach-Object {
            [PSCustomObject]@{
                MITRE_Technique = $_.Name
                Finding_Count   = $_.Count
                Max_Severity    = ($_.Group | Sort-Object { $severityOrder[$_.Severity] } | Select-Object -First 1).Severity
                Finding_IDs     = (($_.Group.Finding_ID | Sort-Object -Unique) -join ', ')
            }
        } |
        Sort-Object { $severityOrder[$_.Max_Severity] }, MITRE_Technique |
        Export-Csv -Path (Join-Path $Path 'ATTACK_Coverage.csv') -NoTypeInformation -Encoding UTF8

    return $sorted
}


# ==========================================================================
# SOURCE: Reporting\Export-ThreatJetJSON.ps1
# ==========================================================================
function Export-ThreatJetJSON {


param(

    [string]
    $Path

)



$findings =
    Import-Csv `
        "$Path\AD_Assessment_Findings.csv"



$findings |
    ConvertTo-Json `
        -Depth 5 |
    Out-File `
        "$Path\AD_Assessment_Findings.json" `
        -Encoding UTF8


}

# ==========================================================================
# SOURCE: Reporting\New-AssessmentSummary.ps1
# ==========================================================================
function New-AssessmentSummary {


param(

    [string]
    $Path

)



$findings =
    Import-Csv `
        "$Path\AD_Assessment_Findings.csv"



[PSCustomObject]@{


Assessment_Date =
    Get-Date -Format yyyy-MM-dd


Total_Findings =
    $findings.Count


Critical =
    @(
        $findings |
        Where-Object Severity -eq Critical
    ).Count


High =
    @(
        $findings |
        Where-Object Severity -eq High
    ).Count


Medium =
    @(
        $findings |
        Where-Object Severity -eq Medium
    ).Count


Low =
    @(
        $findings |
        Where-Object Severity -eq Low
    ).Count


CollectorVersion =
    $script:TJETConfig.CollectorVersion


CorrelationVersion =
    $script:TJETConfig.CorrelationVersion


SchemaVersion =
    $script:TJETConfig.SchemaVersion


}

}

# ==========================================================================
# SOURCE: Public\Export-ADObjectInventory.ps1
# ==========================================================================
function Export-ADObjectInventory {
<#
.SYNOPSIS
    Exports a complete inventory of Active Directory objects with all properties.
.DESCRIPTION
    Companion to the findings output. Where the findings answer "what is wrong", the
    inventory answers "what exists" -- the raw material for hunting, scoping, and
    answering questions the detectors were never written to ask.

    Two forms of output are produced, because they serve different jobs:

    1. AD_Inventory_<Type>.csv -- one row per object, EVERY property, multi-valued
       attributes joined with " | " plus a _Count column. Good for reading, filtering
       and pivoting in a spreadsheet.

    2. REL_<Relationship>.csv -- normalised edge lists, one row per value, for the
       multi-valued attributes that matter for analysis (group membership, SPNs,
       SIDHistory, delegation targets, GPO links, gMSA retrievers). Good for joins and
       for loading into a graph tool.

    Object types covered: users, computers, groups, GPOs, organizational units,
    contacts, managed service accounts, foreign security principals, containers,
    trusts, domain, forest, sites, subnets and domain controllers.

    Note on volume: -Properties * on every object is genuinely expensive. On a large
    estate this is the slowest part of an assessment and produces the largest files.
    Use -ObjectType to scope it when that matters.
.PARAMETER Path
    Output directory. Created if missing.
.PARAMETER ObjectType
    Limit the export to specific types. Defaults to all.
.PARAMETER SkipRelationships
    Write only the main inventory CSVs, not the normalised edge lists.
.EXAMPLE
    Export-ADObjectInventory -Path C:\Audit
.EXAMPLE
    Export-ADObjectInventory -Path C:\Audit -ObjectType Users,Groups
#>
    [CmdletBinding()]
    param(
        [Alias('OutDir')]
        [string]$Path = (Join-Path $PWD 'ThreatJet_Output'),

        [ValidateSet('Users','Computers','Groups','GPOs','OrganizationalUnits','Contacts',
                     'ManagedServiceAccounts','ForeignSecurityPrincipals','Containers',
                     'Trusts','Domain','Forest','Sites','Subnets','DomainControllers','All')]
        [string[]]$ObjectType = @('All'),

        [switch]$SkipRelationships
    )

    if (-not (Test-Path $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }

    $inventoryPath = Join-Path $Path 'Inventory'

    if (-not (Test-Path $inventoryPath)) {
        New-Item -ItemType Directory -Path $inventoryPath -Force | Out-Null
    }

    $wantAll = $ObjectType -contains 'All'

    function Test-Wanted {
        param([string]$Type)
        return ($wantAll -or ($ObjectType -contains $Type))
    }

    function Write-Inventory {
        param([string]$Name, $Data)

        # Filter nulls at the source as well as in the flattener -- belt and braces,
        # because a null here silently costs an entire object type's CSV.
        $items = @($Data | Where-Object { $null -ne $_ })

        if ($items.Count -eq 0) {
            Write-TJETLog INFO "Inventory $Name : 0 object(s)"
            return @()
        }

        $flat = $items | ConvertTo-InventoryRecord

        $flat | Export-Csv -Path (Join-Path $inventoryPath "AD_Inventory_$Name.csv") `
            -NoTypeInformation -Encoding UTF8

        Write-TJETLog INFO "Inventory $Name : $($items.Count) object(s)"

        return $items
    }

    # --- data source selection: RSAT if present, ADSI otherwise ---------------
    # Per the design decision, the inventory USES the ActiveDirectory module when it is
    # available (richer, native property projection) and FALLS BACK to ADSI/LDAP when it
    # is not, so -IncludeInventory works on a host without RSAT. The choice is made once.
    $useADModule = [bool](Get-Module -ListAvailable -Name ActiveDirectory)

    if ($useADModule) {
        try { Import-Module ActiveDirectory -ErrorAction Stop }
        catch { $useADModule = $false }
    }

    $adsiCtx = $null
    if (-not $useADModule) {
        Write-TJETLog INFO 'ActiveDirectory module not available - using ADSI/LDAP for inventory.'
        $adsiCtx = Get-TJETDirectoryContext
    }
    else {
        Write-TJETLog INFO 'ActiveDirectory module present - using it for inventory.'
    }

    # Dispatcher: return all objects of a type. $AdScript runs when RSAT is present;
    # otherwise the LDAP filter/root drive the ADSI fallback via Get-TJETInventoryObject.
    function Get-InventorySource {
        param(
            [scriptblock]$AdScript,
            [string]$LdapFilter,
            [string]$SearchRoot,
            [string]$Scope = 'Subtree'
        )

        if ($useADModule) {
            return & $AdScript
        }

        $root = if ($SearchRoot) { $SearchRoot } else { $adsiCtx.DefaultNC }
        return Get-TJETInventoryObject -Context $adsiCtx -Filter $LdapFilter -SearchRoot $root -Scope $Scope
    }

    Write-TJETLog INFO "Starting full object inventory to $inventoryPath"

    $summary = New-Object System.Collections.Generic.List[object]
    $users = @(); $computers = @(); $groups = @(); $gmsa = @(); $gpos = @()

    # ------------------------------------------------------------------ Users ---
    if (Test-Wanted 'Users') {
        try {
            $users = Write-Inventory 'Users' (Get-InventorySource -AdScript { Get-ADUser -Filter * -Properties * -ErrorAction Stop } -LdapFilter '(&(objectCategory=person)(objectClass=user))')
            $summary.Add([PSCustomObject]@{ Type='Users'; Count=@($users).Count; Status='OK' })
        }
        catch {
            Write-TJETLog ERROR "Inventory Users failed: $($_.Exception.Message)"
            $summary.Add([PSCustomObject]@{ Type='Users'; Count=0; Status="FAILED: $($_.Exception.Message)" })
        }
    }

    # -------------------------------------------------------------- Computers ---
    if (Test-Wanted 'Computers') {
        try {
            $computers = Write-Inventory 'Computers' (Get-InventorySource -AdScript { Get-ADComputer -Filter * -Properties * -ErrorAction Stop } -LdapFilter '(objectClass=computer)')
            $summary.Add([PSCustomObject]@{ Type='Computers'; Count=@($computers).Count; Status='OK' })
        }
        catch {
            Write-TJETLog ERROR "Inventory Computers failed: $($_.Exception.Message)"
            $summary.Add([PSCustomObject]@{ Type='Computers'; Count=0; Status="FAILED: $($_.Exception.Message)" })
        }
    }

    # ----------------------------------------------------------------- Groups ---
    if (Test-Wanted 'Groups') {
        try {
            $groups = Write-Inventory 'Groups' (Get-InventorySource -AdScript { Get-ADGroup -Filter * -Properties * -ErrorAction Stop } -LdapFilter '(objectClass=group)')
            $summary.Add([PSCustomObject]@{ Type='Groups'; Count=@($groups).Count; Status='OK' })
        }
        catch {
            Write-TJETLog ERROR "Inventory Groups failed: $($_.Exception.Message)"
            $summary.Add([PSCustomObject]@{ Type='Groups'; Count=0; Status="FAILED: $($_.Exception.Message)" })
        }
    }

    # ------------------------------------------------ Managed service accounts ---
    if (Test-Wanted 'ManagedServiceAccounts') {
        try {
            $gmsa = Write-Inventory 'ManagedServiceAccounts' (Get-InventorySource -AdScript { Get-ADServiceAccount -Filter * -Properties * -ErrorAction Stop } -LdapFilter '(|(objectClass=msDS-GroupManagedServiceAccount)(objectClass=msDS-ManagedServiceAccount))')
            $summary.Add([PSCustomObject]@{ Type='ManagedServiceAccounts'; Count=@($gmsa).Count; Status='OK' })
        }
        catch {
            Write-TJETLog WARNING "Inventory ManagedServiceAccounts skipped: $($_.Exception.Message)"
            $summary.Add([PSCustomObject]@{ Type='ManagedServiceAccounts'; Count=0; Status='Skipped' })
        }
    }

    # ------------------------------------------------------------------- OUs ---
    if (Test-Wanted 'OrganizationalUnits') {
        try {
            $ous = Write-Inventory 'OrganizationalUnits' (Get-InventorySource -AdScript { Get-ADOrganizationalUnit -Filter * -Properties * -ErrorAction Stop } -LdapFilter '(objectClass=organizationalUnit)')
            $summary.Add([PSCustomObject]@{ Type='OrganizationalUnits'; Count=@($ous).Count; Status='OK' })
        }
        catch { Write-TJETLog ERROR "Inventory OUs failed: $($_.Exception.Message)" }
    }

    # -------------------------------------------------------------- Contacts ---
    if (Test-Wanted 'Contacts') {
        try {
            $contacts = Write-Inventory 'Contacts' (Get-InventorySource -AdScript { Get-ADObject -LDAPFilter '(objectClass=contact)' -Properties * -ErrorAction Stop } -LdapFilter '(objectClass=contact)')
            $summary.Add([PSCustomObject]@{ Type='Contacts'; Count=@($contacts).Count; Status='OK' })
        }
        catch { Write-TJETLog WARNING "Inventory Contacts skipped: $($_.Exception.Message)" }
    }

    # ------------------------------------------- Foreign security principals ---
    if (Test-Wanted 'ForeignSecurityPrincipals') {
        try {
            $fsp = Write-Inventory 'ForeignSecurityPrincipals' (Get-InventorySource -AdScript { Get-ADObject -LDAPFilter '(objectClass=foreignSecurityPrincipal)' -Properties * -ErrorAction Stop } -LdapFilter '(objectClass=foreignSecurityPrincipal)')
            $summary.Add([PSCustomObject]@{ Type='ForeignSecurityPrincipals'; Count=@($fsp).Count; Status='OK' })
        }
        catch { Write-TJETLog WARNING "Inventory ForeignSecurityPrincipals skipped: $($_.Exception.Message)" }
    }

    # ------------------------------------------------------------ Containers ---
    if (Test-Wanted 'Containers') {
        try {
            $containers = Write-Inventory 'Containers' (Get-InventorySource -AdScript { Get-ADObject -LDAPFilter '(objectClass=container)' -Properties * -ErrorAction Stop } -LdapFilter '(objectClass=container)')
            $summary.Add([PSCustomObject]@{ Type='Containers'; Count=@($containers).Count; Status='OK' })
        }
        catch { Write-TJETLog WARNING "Inventory Containers skipped: $($_.Exception.Message)" }
    }

    # ------------------------------------------------------------------ GPOs ---
    if (Test-Wanted 'GPOs') {
        # RSAT path uses the GroupPolicy module for the friendly projection; the ADSI
        # fallback reads the raw groupPolicyContainer objects directly (works with no
        # RSAT at all).
        if ($useADModule -and (Get-Module -ListAvailable -Name GroupPolicy)) {
            try {
                Import-Module GroupPolicy -ErrorAction Stop
                $gpos = Write-Inventory 'GPOs' (Get-GPO -All -ErrorAction Stop)
                $summary.Add([PSCustomObject]@{ Type='GPOs'; Count=@($gpos).Count; Status='OK' })
            }
            catch { Write-TJETLog ERROR "Inventory GPOs failed: $($_.Exception.Message)" }
        }
        else {
            try {
                $policyBase = "CN=Policies,CN=System,$($adsiCtx.DefaultNC)"
                $gpos = Write-Inventory 'GPOs' (Get-TJETInventoryObject -Context $adsiCtx -Filter '(objectClass=groupPolicyContainer)' -SearchRoot $policyBase)
                $summary.Add([PSCustomObject]@{ Type='GPOs'; Count=@($gpos).Count; Status='OK' })
            }
            catch { Write-TJETLog ERROR "Inventory GPOs (ADSI) failed: $($_.Exception.Message)" }
        }
    }

    # ---------------------------------------------------------------- Trusts ---
    if (Test-Wanted 'Trusts') {
        try {
            $trusts = Write-Inventory 'Trusts' (Get-InventorySource -AdScript { Get-ADTrust -Filter * -Properties * -ErrorAction Stop } -LdapFilter '(objectClass=trustedDomain)')
            $summary.Add([PSCustomObject]@{ Type='Trusts'; Count=@($trusts).Count; Status='OK' })
        }
        catch { Write-TJETLog WARNING "Inventory Trusts skipped: $($_.Exception.Message)" }
    }

    # ------------------------------------------------------- Domain / forest ---
    if (Test-Wanted 'Domain') {
        try {
            $rows = Write-Inventory 'Domain' (Get-InventorySource -AdScript { Get-ADDomain -ErrorAction Stop } -LdapFilter '(objectClass=domainDNS)' -Scope 'Base')
            $summary.Add([PSCustomObject]@{ Type='Domain'; Count=@($rows).Count; Status='OK' })
        }
        catch { Write-TJETLog ERROR "Inventory Domain failed: $($_.Exception.Message)" }
    }

    if (Test-Wanted 'Forest') {
        try {
            $rows = Write-Inventory 'Forest' (Get-InventorySource -AdScript { Get-ADForest -ErrorAction Stop } -LdapFilter '(objectClass=domainDNS)' -SearchRoot $adsiCtx.RootDomainNC -Scope 'Base')
            $summary.Add([PSCustomObject]@{ Type='Forest'; Count=@($rows).Count; Status='OK' })
        }
        catch { Write-TJETLog ERROR "Inventory Forest failed: $($_.Exception.Message)" }
    }

    if (Test-Wanted 'DomainControllers') {
        try {
            $rows = Write-Inventory 'DomainControllers' (Get-InventorySource -AdScript { Get-ADDomainController -Filter * -ErrorAction Stop } -LdapFilter '(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))')
            $summary.Add([PSCustomObject]@{ Type='DomainControllers'; Count=@($rows).Count; Status='OK' })
        }
        catch { Write-TJETLog WARNING "Inventory DomainControllers skipped: $($_.Exception.Message)" }
    }

    if (Test-Wanted 'Sites') {
        try {
            $config = if ($useADModule) { (Get-ADRootDSE -ErrorAction Stop).configurationNamingContext } else { $adsiCtx.ConfigurationNC }
            $rows = Write-Inventory 'Sites' (Get-InventorySource -AdScript { Get-ADObject -SearchBase "CN=Sites,$config" -LDAPFilter '(objectClass=site)' -Properties * -ErrorAction Stop } -LdapFilter '(objectClass=site)' -SearchRoot "CN=Sites,$config")
            $summary.Add([PSCustomObject]@{ Type='Sites'; Count=@($rows).Count; Status='OK' })
        }
        catch { Write-TJETLog WARNING "Inventory Sites skipped: $($_.Exception.Message)" }
    }

    if (Test-Wanted 'Subnets') {
        try {
            $config = if ($useADModule) { (Get-ADRootDSE -ErrorAction Stop).configurationNamingContext } else { $adsiCtx.ConfigurationNC }
            $rows = Write-Inventory 'Subnets' (Get-InventorySource -AdScript { Get-ADObject -SearchBase "CN=Subnets,CN=Sites,$config" -LDAPFilter '(objectClass=subnet)' -Properties * -ErrorAction Stop } -LdapFilter '(objectClass=subnet)' -SearchRoot "CN=Subnets,CN=Sites,$config")
            $summary.Add([PSCustomObject]@{ Type='Subnets'; Count=@($rows).Count; Status='OK' })
        }
        catch { Write-TJETLog WARNING "Inventory Subnets skipped: $($_.Exception.Message)" }
    }

    # ------------------------------------------------------- Relationships ---
    if (-not $SkipRelationships) {

        Write-TJETLog INFO 'Writing normalised relationship files'

        $relationships = @(
            @{ Objects=$groups;    Property='Member';                    Column='Member_DN';        File='REL_Group_Members.csv' }
            @{ Objects=$groups;    Property='MemberOf';                  Column='ParentGroup_DN';   File='REL_Group_MemberOf.csv' }
            @{ Objects=$users;     Property='MemberOf';                  Column='Group_DN';         File='REL_User_MemberOf.csv' }
            @{ Objects=$users;     Property='ServicePrincipalNames';     Column='SPN';              File='REL_User_SPNs.csv' }
            @{ Objects=$users;     Property='SIDHistory';                Column='SIDHistory';       File='REL_User_SIDHistory.csv' }
            @{ Objects=$users;     Property='msDS-AllowedToDelegateTo';  Column='Delegation_Target'; File='REL_User_DelegationTargets.csv' }
            @{ Objects=$computers; Property='MemberOf';                  Column='Group_DN';         File='REL_Computer_MemberOf.csv' }
            @{ Objects=$computers; Property='ServicePrincipalNames';     Column='SPN';              File='REL_Computer_SPNs.csv' }
            @{ Objects=$computers; Property='msDS-AllowedToDelegateTo';  Column='Delegation_Target'; File='REL_Computer_DelegationTargets.csv' }
            @{ Objects=$gmsa;      Property='PrincipalsAllowedToRetrieveManagedPassword'; Column='Retriever_DN'; File='REL_gMSA_Retrievers.csv' }
            @{ Objects=$gmsa;      Property='ServicePrincipalNames';     Column='SPN';              File='REL_gMSA_SPNs.csv' }
        )

        foreach ($relationship in $relationships) {

            if (@($relationship.Objects).Count -eq 0) { continue }

            try {
                $count = Export-TJETRelationship `
                    -Objects $relationship.Objects `
                    -Property $relationship.Property `
                    -ValueColumnName $relationship.Column `
                    -Path (Join-Path $inventoryPath $relationship.File)

                if ($count -gt 0) {
                    Write-TJETLog INFO "$($relationship.File): $count row(s)"
                    $summary.Add([PSCustomObject]@{ Type=$relationship.File; Count=$count; Status='OK' })
                }
            }
            catch {
                Write-TJETLog WARNING "$($relationship.File) failed: $($_.Exception.Message)"
            }
        }

        # GPO links are held on the OU/domain side as gPLink, not on the GPO.
        try {
            $linked = Get-InventorySource -AdScript { Get-ADObject -LDAPFilter '(gPLink=*)' -Properties gPLink, distinguishedName -ErrorAction Stop } -LdapFilter '(gPLink=*)'

            $linkRows = New-Object System.Collections.Generic.List[object]

            foreach ($container in $linked) {

                # gPLink / distinguishedName casing differs between the AD module
                # (PascalCase) and ADSI (lowercase); resolve both.
                $gpLinkValue = if ($container.PSObject.Properties['gPLink']) { $container.gPLink }
                               elseif ($container.PSObject.Properties['gplink']) { $container.gplink }
                               else { '' }
                $containerDN = if ($container.PSObject.Properties['DistinguishedName']) { $container.DistinguishedName }
                               elseif ($container.PSObject.Properties['distinguishedname']) { $container.distinguishedname }
                               else { '' }

                foreach ($match in [regex]::Matches("$gpLinkValue", '\{([0-9A-Fa-f-]{36})\};(\d)')) {

                    $options = [int]$match.Groups[2].Value

                    $linkRows.Add([PSCustomObject]@{
                        Container_DN = $containerDN
                        GPO_GUID     = $match.Groups[1].Value
                        Link_Enabled = ($options -band 1) -eq 0
                        Link_Enforced = ($options -band 2) -eq 2
                    })
                }
            }

            if ($linkRows.Count -gt 0) {
                $linkRows | Export-Csv -Path (Join-Path $inventoryPath 'REL_GPO_Links.csv') -NoTypeInformation -Encoding UTF8
                Write-TJETLog INFO "REL_GPO_Links.csv: $($linkRows.Count) row(s)"
                $summary.Add([PSCustomObject]@{ Type='REL_GPO_Links.csv'; Count=$linkRows.Count; Status='OK' })
            }
        }
        catch {
            Write-TJETLog WARNING "REL_GPO_Links failed: $($_.Exception.Message)"
        }
    }

    if ($summary.Count -gt 0) {
        $summary | Export-Csv -Path (Join-Path $inventoryPath 'Inventory_Summary.csv') -NoTypeInformation -Encoding UTF8
    }

    Write-TJETLog INFO 'Inventory complete.'

    $summary | Format-Table -AutoSize | Out-String | Write-Host

    return $summary
}


# ==========================================================================
# SOURCE: Public\Export-ThreatJetData.ps1
# ==========================================================================
function Export-ThreatJetData {
<#
.SYNOPSIS
    Collects Active Directory data to CSV for offline assessment.
.DESCRIPTION
    Read-only collection. Writes one CSV per data domain into -Path, which is then the
    input to Invoke-ThreatJetCorrelation.

    Each collector is isolated: a failure in one is logged and the run continues. The
    summary table at the end reports the record count per collector, so a partial or
    empty collection can never be mistaken for a clean one.
.PARAMETER Path
    Output directory. Created if missing. Alias: -OutDir.
.PARAMETER AclMode
    Targeted (default) collects ACLs on OUs, the domain head, adminCount=1 objects and
    AdminSDHolder. Full collects ACLs on every object -- comprehensive but slow.
.PARAMETER SkipPrerequisiteCheck
    Bypass the RSAT/domain reachability check.
.EXAMPLE
    Export-ThreatJetData -Path C:\Audit
.EXAMPLE
    Export-ThreatJetData -Path C:\Audit -AclMode Full
#>
    [CmdletBinding()]
    param(
        [Alias('OutDir','OutputPath')]
        [string]$Path = (Join-Path $PWD 'ThreatJet_Output'),

        [ValidateSet('Targeted','Full')]
        [string]$AclMode = 'Targeted',

        # Run only specific collectors. 'All' (default) runs everything.
        # LocalHost needs no AD, so it can be selected on its own on a non-domain host.
        [ValidateSet('All','Users','Computers','Groups','ServiceAccounts','GPOs',
                     'ACLs','Trusts','FGPP','Domain','ADCS','LocalHost')]
        [string[]]$Include = @('All'),

        # Exclude specific collectors from an otherwise full run.
        [ValidateSet('Users','Computers','Groups','ServiceAccounts','GPOs',
                     'ACLs','Trusts','FGPP','Domain','ADCS','LocalHost')]
        [string[]]$Exclude = @(),

        [switch]$SkipPrerequisiteCheck
    )

    $runAll = $Include -contains 'All'

    # LocalHost is the only collector that works without AD, so a LocalHost-only run
    # must not be blocked by the domain prerequisite check. Defined BEFORE the check
    # that uses it -- PowerShell would silently treat an undefined variable as $null.
    $adCollectorsRequested = $runAll -or (@($Include | Where-Object { $_ -ne 'LocalHost' }).Count -gt 0)

    if (-not $SkipPrerequisiteCheck -and $adCollectorsRequested) {
        if (-not (Test-TJETPrerequisite -Stage Collection)) {
            Write-TJETLog ERROR 'Prerequisite check failed. Collection aborted.'
            return
        }
    }

    if (-not (Test-Path $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }

    Write-TJETLog INFO "Starting collection to $Path (ACL mode: $AclMode)"

    $collectors = @(
        @{ Key = 'Users';           Name = 'Users';            Function = 'Collect-Users';           Output = 'AD_Users_Audit.csv' }
        @{ Key = 'Computers';       Name = 'Computers';        Function = 'Collect-Computers';       Output = 'AD_Computers_Audit.csv' }
        @{ Key = 'Groups';          Name = 'Groups';           Function = 'Collect-Groups';          Output = 'AD_Groups_Audit.csv' }
        @{ Key = 'ServiceAccounts'; Name = 'Service Accounts'; Function = 'Collect-ServiceAccounts'; Output = 'AD_ServiceAccounts_Audit.csv' }
        @{ Key = 'GPOs';            Name = 'GPOs';             Function = 'Collect-GPOs';            Output = 'AD_GPO_Audit.csv' }
        @{ Key = 'ACLs';            Name = 'ACLs';             Function = 'Collect-ACLs';            Output = 'AD_ACL_Audit.csv'; AclMode = $true }
        @{ Key = 'Trusts';          Name = 'Trusts';           Function = 'Collect-Trusts';          Output = 'AD_Trusts_Audit.csv' }
        @{ Key = 'FGPP';            Name = 'FGPP';             Function = 'Collect-FGPP';            Output = 'AD_FGPP_Audit.csv' }
        @{ Key = 'Domain';          Name = 'Domain Summary';   Function = 'Collect-DomainSummary';   Output = 'AD_Domain_Summary.csv' }
        @{ Key = 'ADCS';            Name = 'ADCS Templates';   Function = 'Collect-ADCS';            Output = 'AD_ADCS_Audit.csv' }
        @{ Key = 'LocalHost';       Name = 'Local Host';       Function = 'Collect-LocalHostAll';       Output = 'AD_LocalHost_Audit.csv' }
    )

    $results = New-Object System.Collections.Generic.List[object]
    $index   = 0

    # Apply -Include / -Exclude before running anything.
    $collectors = @($collectors | Where-Object {
        ($runAll -or ($Include -contains $_.Key)) -and ($Exclude -notcontains $_.Key)
    })

    if ($collectors.Count -eq 0) {
        Write-TJETLog WARNING 'No collectors selected. Check -Include / -Exclude.'
        return
    }

    Write-TJETLog INFO "Collectors selected: $(($collectors.Key) -join ', ')"

    foreach ($collector in $collectors) {

        $index++

        Write-Progress -Activity 'ThreatJet collection' `
            -Status "$($collector.Name) ($index of $($collectors.Count))" `
            -PercentComplete (($index / $collectors.Count) * 100)

        Write-TJETLog INFO "Collecting $($collector.Name)"

        $status = 'OK'
        $count  = 0

        try {
            # Capture collector output into its own variable on its own statement.
            # A previous revision chained this with the argument setup, which meant
            # $data held the ARGUMENTS and every collector's real output was
            # discarded -- producing CSVs containing hashtable metadata with exactly
            # one row each. Keep these steps separate and explicit.
            $data = @()

            if ($collector.ContainsKey('AclMode')) {
                $data = @(& $collector.Function -Mode $AclMode)
            }
            else {
                $data = @(& $collector.Function)
            }

            $count = $data.Count

            if ($count -gt 0) {

                # [FIX] Export-Csv derives its header from the FIRST object only. The
                # LocalHost collector concatenates several record shapes (privesc,
                # software inventory, ports, processes), so if the first record lacks a
                # column that later ones have -- e.g. Software_Product -- that column is
                # silently dropped from the CSV. On re-import the CVE scan then sees no
                # software and skips. Project every record through the UNION of all
                # property names so no column is lost regardless of record order.
                $allColumns = [System.Collections.Specialized.OrderedDictionary]::new()
                foreach ($row in $data) {
                    foreach ($prop in $row.PSObject.Properties.Name) {
                        if (-not $allColumns.Contains($prop)) { $allColumns[$prop] = $true }
                    }
                }
                $columnOrder = @($allColumns.Keys)

                $data |
                    Select-Object -Property $columnOrder |
                    Export-Csv -Path (Join-Path $Path $collector.Output) `
                        -NoTypeInformation -Encoding UTF8
            }
            else {
                $status = 'No data'
            }

            Write-TJETLog INFO "$($collector.Name): $count record(s)"
        }
        catch {
            $status = "FAILED: $($_.Exception.Message)"
            Write-TJETLog ERROR "$($collector.Name) failed: $($_.Exception.Message)"
        }

        $results.Add([PSCustomObject]@{
            Collector = $collector.Name
            Records   = $count
            Status    = $status
            File      = $collector.Output
        })
    }

    Write-Progress -Activity 'ThreatJet collection' -Completed

    $failed = @($results | Where-Object { $_.Status -like 'FAILED*' })

    if ($failed.Count -gt 0) {
        Write-TJETLog WARNING "Collection finished with $($failed.Count) failed collector(s). Findings will be incomplete."
    }
    else {
        Write-TJETLog INFO 'Collection complete.'
    }

    $results | Format-Table -AutoSize | Out-String | Write-Host

    return $results
}


# ==========================================================================
# SOURCE: Public\Find-TJETAttackPathReport.ps1
# ==========================================================================
function Find-TJETAttackPath {
<#
.SYNOPSIS
    Analyses collected data for attack paths to Tier 0 and writes a graph export.
.DESCRIPTION
    Standalone entry point for the attack-path analysis, so it can be run offline
    against an existing collection without re-running the whole assessment.

    Loads the assessment CSVs from -Path, builds the control graph, finds shortest
    paths to Tier 0, prints a summary, and writes Attack_Paths.csv with each
    path traced out in readable form.
.PARAMETER Path
    Directory containing the assessment CSVs.
.PARAMETER Top
    How many shortest paths to print. Default 20.
.EXAMPLE
    Find-TJETAttackPath -Path C:\Audit
#>
    [CmdletBinding()]
    param(
        [Alias('InDir','InputPath')]
        [string]$Path = (Join-Path $PWD 'ThreatJet_Output'),

        [int]$Top = 20
    )

    if (-not (Test-Path $Path)) {
        Write-TJETLog ERROR "Input directory not found: $Path"
        return
    }

    $data    = Import-AssessmentData -Path $Path
    $context = New-TJETContext -Data $data -OutputPath $Path

    $graph = Build-TJETGraph -Context $context

    Write-Host ''
    Write-Host "  Attack-path graph: $($graph.Nodes.Count) nodes, $($graph.Edges.Count) edges" -ForegroundColor Cyan

    if ($graph.Edges.Count -eq 0) {
        Write-Host '  No control edges found. Ensure ACLs and group membership were collected.' -ForegroundColor Yellow
        return
    }

    $paths = Find-TJETAttackPathInternal -Graph $graph

    $shortest = @{}
    foreach ($path in $paths) {
        $key = "$($path.Source)|$($path.Target)"
        if (-not $shortest.ContainsKey($key) -or $path.Hops -lt $shortest[$key].Hops) {
            $shortest[$key] = $path
        }
    }

    $ranked = $shortest.Values | Sort-Object Hops

    Write-Host "  $($ranked.Count) principal(s) can reach Tier 0`n" -ForegroundColor $(if ($ranked.Count) { 'Red' } else { 'Green' })

    foreach ($path in ($ranked | Select-Object -First $Top)) {
        Write-Host "  [$($path.Hops) hop] " -NoNewline -ForegroundColor DarkGray
        Write-Host (Format-TJETPath -PathResult $path -Graph $graph)
    }

    # Reuse the detector's export.
    $graphDir = Join-Path $Path 'Graph'
    if (-not (Test-Path $graphDir)) { New-Item -ItemType Directory -Path $graphDir -Force | Out-Null }

    Write-Host "`n  Graph exported to $graphDir" -ForegroundColor DarkGray

    return $ranked
}


# ==========================================================================
# SOURCE: Public\Invoke-ThreatJetAssessment.ps1
# ==========================================================================
function Invoke-ThreatJetAssessment {
<#
.SYNOPSIS
    Runs a complete AD security assessment assessment: collect, correlate, report.
.DESCRIPTION
    One command for the common case. Equivalent to Export-ThreatJetData,
    Invoke-ThreatJetCorrelation and New-ThreatJetReport in sequence.

    Output is timestamped by default so consecutive assessments do not overwrite each
    other, which also means the previous run is preserved and can be used directly as
    a baseline.

    Use -SkipCollection to re-analyse already-collected data (for example on an
    analyst workstation with no RSAT, or after tuning thresholds).
.PARAMETER Path
    Assessment directory. Defaults to .\ThreatJet_<yyyyMMdd-HHmm>.
.PARAMETER AclMode
    Targeted (default) or Full ACL collection. Full is slow on large estates.
.PARAMETER SkipCollection
    Skip collection; correlate and report from CSVs already in -Path. No RSAT needed.
.PARAMETER Scope
    Which phases to run: All (default), AD, LocalHost, AttackPath, Inventory.
    Combine freely, e.g. -Scope LocalHost,AttackPath.
.PARAMETER ADObjectType
    Restrict AD collection to specific object types. Implies -Scope AD.
.PARAMETER DataminePasswords
    Also scan the filesystem for stored credentials and password patterns. Off by
    default because it reads file contents and is slower. Redacts discovered values.
.PARAMETER IncludeCVEScan
    Run an offline CVE scan of installed software against a local MITRE database
    (default C:\Security\cves.db). Requires the PSSQLite module; skips gracefully if
    the module or database is absent.
.PARAMETER CVEDatabasePath
    Path to the SQLite CVE database. Defaults to the configured path.
.PARAMETER IncludeInventory
    Also export a full inventory of every AD object with all properties, plus
    normalised relationship files, into an Inventory subfolder. Slower and much larger
    than the assessment CSVs -- it queries every object with -Properties *.
.PARAMETER BaselinePath
    Optional path to a previous AD_Assessment_Findings.csv. Produces Baseline_Comparison.csv.
.PARAMETER OpenReport
    Open the HTML report when finished.
.EXAMPLE
    Invoke-ThreatJetAssessment
.EXAMPLE
    Invoke-ThreatJetAssessment -Path C:\Audit\Q3 -AclMode Full -OpenReport
.EXAMPLE
    Invoke-ThreatJetAssessment -Path C:\Audit\Q3 -IncludeInventory
    Full assessment plus a complete object inventory for hunting and scoping.
.EXAMPLE
    Invoke-ThreatJetAssessment -Path C:\Audit\Q3 -BaselinePath C:\Audit\Q2\AD_Assessment_Findings.csv
.EXAMPLE
    Invoke-ThreatJetAssessment -Path C:\Audit\Q3 -SkipCollection
.EXAMPLE
    Invoke-ThreatJetAssessment -Scope LocalHost
    Local privilege-escalation checks only. No AD, no RSAT, no domain required.
.EXAMPLE
    Invoke-ThreatJetAssessment -ADObjectType Users,Groups -Scope AD,AttackPath
    Collect only users and groups, then trace attack paths across them.
.EXAMPLE
    Invoke-ThreatJetAssessment -Scope LocalHost -IncludeCVEScan -DataminePasswords
    Full local host review: WinPEAS-style checks, open ports, credential datamine, and
    an offline CVE scan of installed software.
#>
    [CmdletBinding()]
    param(
        [Alias('OutDir')]
        [string]$Path = (Join-Path $PWD "ThreatJet_$(Get-Date -Format 'yyyyMMdd-HHmm')"),

        [ValidateSet('Targeted','Full')]
        [string]$AclMode = 'Targeted',

        # Which assessment phases to run. 'All' (default) runs everything except the
        # full object inventory, which is opt-in because of its size and runtime.
        #   AD          collect + correlate Active Directory
        #   LocalHost   local privilege-escalation and hardening checks (no AD needed)
        #   AttackPath  trace control paths to Tier 0
        #   Inventory   every object, every attribute, plus relationship files
        [ValidateSet('All','AD','LocalHost','AttackPath','Inventory')]
        [string[]]$Scope = @('All'),

        # Restrict AD collection to specific object types.
        [ValidateSet('Users','Computers','Groups','ServiceAccounts','GPOs',
                     'ACLs','Trusts','FGPP','Domain','ADCS')]
        [string[]]$ADObjectType = @(),

        [switch]$SkipCollection,

        [switch]$IncludeInventory,

        # Datamine the filesystem for stored credentials (reads file contents; slower).
        [switch]$DataminePasswords,

        # Offline CVE scan of installed software against the local MITRE database.
        [switch]$IncludeCVEScan,

        [string]$CVEDatabasePath,

        [string]$BaselinePath,

        [switch]$OpenReport
    )

    $started = Get-Date

    $runAll       = $Scope -contains 'All'

    # The filesystem credential datamine is gated by config so the collector wrapper
    # can see the choice without threading a parameter through every layer.
    $script:TJETConfig.EnableFilesystemCredentialScan = [bool]$DataminePasswords
    $runAD        = $runAll -or ($Scope -contains 'AD') -or ($ADObjectType.Count -gt 0)
    $runLocal     = $runAll -or ($Scope -contains 'LocalHost')
    $runAttack    = $runAll -or ($Scope -contains 'AttackPath')
    $runInventory = $IncludeInventory -or ($Scope -contains 'Inventory')

    Write-Host ''
    Write-Host '  ThreatJet Assessment' -ForegroundColor Cyan
    Write-Host "  Version $($script:TJETConfig.CollectorVersion)  |  Schema $($script:TJETConfig.SchemaVersion)" -ForegroundColor DarkGray
    Write-Host "  Output: $Path" -ForegroundColor DarkGray
    Write-Host ''

    if ($SkipCollection) {

        Write-TJETLog INFO 'Skipping collection (-SkipCollection).'

        if (-not (Test-Path $Path)) {
            Write-TJETLog ERROR "Cannot skip collection: $Path does not exist."
            return
        }
    }
    else {

        $include = New-Object System.Collections.Generic.List[string]

        if ($runAD) {
            if ($ADObjectType.Count -gt 0) {
                foreach ($type in $ADObjectType) { $include.Add($type) }
            }
            else {
                foreach ($type in 'Users','Computers','Groups','ServiceAccounts','GPOs','ACLs','Trusts','FGPP','Domain','ADCS') {
                    $include.Add($type)
                }
            }
        }

        if ($runLocal) { $include.Add('LocalHost') }

        if ($include.Count -gt 0) {
            Export-ThreatJetData -Path $Path -AclMode $AclMode -Include $include.ToArray() | Out-Null
        }
        else {
            Write-TJETLog WARNING 'No collection scope selected.'
        }

        if ($runInventory) {
            Export-ADObjectInventory -Path $Path | Out-Null
        }
    }

    $cveArgs = @{}
    if ($IncludeCVEScan)   { $cveArgs['IncludeCVEScan'] = $true }
    if ($CVEDatabasePath)  { $cveArgs['CVEDatabasePath'] = $CVEDatabasePath }

    $findings = Invoke-ThreatJetCorrelation -Path $Path -PassThru `
        -SkipAttackPath:(-not $runAttack) @cveArgs

    $reportPath = Join-Path $Path 'ThreatJet_Report.html'
    New-ThreatJetReport -Path $Path -ReportPath $reportPath | Out-Null

    $summary = New-AssessmentSummary -Path $Path

    if ($summary) {
        $summary | Export-Csv (Join-Path $Path 'Assessment_Summary.csv') -NoTypeInformation -Encoding UTF8
    }

    if ($BaselinePath) {

        if (Test-Path $BaselinePath) {

            $diff = Compare-ThreatJetBaseline `
                -CurrentPath (Join-Path $Path 'AD_Assessment_Findings.csv') `
                -BaselinePath $BaselinePath

            if ($diff) {
                $diff | Export-Csv (Join-Path $Path 'Baseline_Comparison.csv') -NoTypeInformation -Encoding UTF8
            }
        }
        else {
            Write-TJETLog WARNING "Baseline not found: $BaselinePath. Comparison skipped."
        }
    }

    $elapsed = (Get-Date) - $started

    Write-Host ''
    Write-Host '  Assessment complete' -ForegroundColor Green
    Write-Host "  Duration:  $([math]::Round($elapsed.TotalMinutes,1)) minute(s)"
    Write-Host "  Findings:  $(@($findings).Count)"
    Write-Host "  Report:    $reportPath"
    Write-Host "  Data:      $Path"
    Write-Host ''
    Write-Host '  Keep this folder: it is the baseline for your next assessment.' -ForegroundColor DarkGray
    Write-Host ''

    if ($OpenReport -and (Test-Path $reportPath)) {
        Invoke-Item $reportPath
    }

    return [PSCustomObject]@{
        Path       = $Path
        ReportPath = $reportPath
        Summary    = $summary
        Findings   = $findings
    }
}


# ==========================================================================
# SOURCE: Public\Invoke-ThreatJetCorrelation.ps1
# ==========================================================================
function Invoke-ThreatJetCorrelation {

    [CmdletBinding()]

    param(

        [Alias('InDir','InputPath')]
        [string]
        $Path = (Join-Path $PWD "ThreatJet_Output"),

        [switch]
        $PassThru,

        # Skip the attack-path graph. It is the most expensive detector on a large
        # estate, so a targeted re-run can opt out.
        [switch]
        $SkipAttackPath,

        # Run only these detectors (by name fragment), e.g. -OnlyDetector Local,Cred
        [string[]]
        $OnlyDetector = @(),

        # Offline CVE scan against the local MITRE database. Off unless requested,
        # because it depends on the PSSQLite module and a database the user builds.
        [switch]
        $IncludeCVEScan,

        [string]
        $CVEDatabasePath

    )


    Write-TJETLog `
        INFO `
        "Starting correlation engine"


    $data =
        Import-AssessmentData `
            -Path $Path



    $context =
        New-TJETContext `
            -Data $data `
            -OutputPath $Path


    Write-TJETLog `
        INFO `
        "Privilege model: $($context.PrivilegedSIDs.Count) SID(s), $($context.PrivilegedGUIDs.Count) object(s)"


    # A null domain manifest silently disables every domain-scoped detector while
    # the rest of the run reports success. Surface it.
    if(-not $data.Domain){

        Write-TJETLog `
            WARNING `
            "Domain summary not loaded. DOM-001, DOM-005 and ID-011 will not fire. Check that AD_Domain_Summary.csv exists and is not empty."

    }


    # An empty privilege model silently disables every privileged-only detector,
    # producing a falsely clean report. This is the signature of a broken collector
    # field contract, so surface it loudly rather than letting it pass.
    if($context.PrivilegedSIDs.Count -eq 0){

        Write-TJETLog `
            WARNING `
            "No privileged principals identified. ID-001, ID-006, ID-009, ID-010, ID-011 and PATH-001 will not fire. Check that AD_Users_Audit.csv has Potentially_Privileged_Direct and AD_Groups_Audit.csv has Is_Tier0."

    }



    $findings =
        New-Object `
            System.Collections.Generic.List[object]



    $detectors = @(

        "Invoke-DomainFindings"

        "Invoke-IdentityFindings"

        "Invoke-ComputerFindings"

        "Invoke-GroupFindings"

        "Invoke-ACLFindings"

        "Invoke-FGPPFindings"

        "Invoke-GMSAFindings"

        "Invoke-TrustFindings"

        "Invoke-ADCSFindings"

        "Invoke-GPOFindings"

        "Invoke-CredentialHuntFindings"

        "Invoke-LocalFindings"

        "Invoke-ExposureFindings"

        "Invoke-AttackPathFindings"

        # CVE scan appended conditionally below

    )

    # Append the offline CVE detector only when asked. It is last so its cross-
    # referencing runs after the inventory-producing detectors.
    if ($IncludeCVEScan) {
        $detectors += 'Invoke-OfflineCVEScan'
    }



    foreach($detector in $detectors){


        Write-TJETLog `
            INFO `
            "Running $detector"



        try {

            # Most detectors take only the context. The CVE scan additionally needs the
            # database path, so build its argument set explicitly.
            $detectorArgs = @($context)

            if ($detector -eq 'Invoke-OfflineCVEScan') {
                $dbPath = if ($CVEDatabasePath) { $CVEDatabasePath }
                          elseif ($script:TJETConfig.CVEDatabasePath) { $script:TJETConfig.CVEDatabasePath }
                          else { 'C:\Security\cves.db' }
                $detectorArgs += $dbPath
            }

            foreach($finding in
                (& $detector @detectorArgs)
            ){

                $findings.Add($finding)

            }

        }


        catch {

            Write-TJETLog `
                ERROR `
                "$detector failed: $($_.Exception.Message)"

        }

    }



    # [FIX] Export-Findings returns the enriched, sorted findings. Without Out-Null
    # that return value leaks into THIS function's output stream and is concatenated
    # with the -PassThru result, so callers saw exactly double the real count
    # (35 findings reported as 70).
    Export-Findings `
        -Findings $findings `
        -OutDir $Path |
        Out-Null


    # [FIX] Also emit JSON. Export-ThreatJetJSON existed but was never called by
    # anything, so the JSON artifact the baseline workflow expects was never created.
    Export-ThreatJetJSON `
        -Path $Path



    Write-TJETLog `
        INFO `
        "Correlation complete: $($findings.Count) findings"



    if($PassThru){ return $findings }

}


# ==========================================================================
# SOURCE: Public\New-ThreatJetReport.ps1
# ==========================================================================
function New-ThreatJetReport {
<#
.SYNOPSIS
    Generates an interactive HTML assessment report.
.DESCRIPTION
    The findings table is sortable and filterable in the browser:

      - click any column header to sort (click again to reverse). Severity sorts by
        RANK, not alphabetically, so Critical comes before High.
      - a filter box under each header narrows on that column as you type
      - a global search box matches across every column at once
      - severity cards toggle whole bands on and off
      - a live counter shows how many rows are visible
      - "Export visible to CSV" saves exactly what is on screen

    Self-contained vanilla JavaScript. No CDN and no external requests, because the
    file has to open from a share or an email attachment on a locked-down workstation.

    Every value is HTML-encoded on the way in. AD object names, descriptions and
    attribute values are attacker-influenceable, and an administrator opens this file.
#>
    [CmdletBinding()]
    param(
        [Alias('InDir','InputPath')]
        [string]$Path = (Join-Path $PWD 'ThreatJet_Output'),

        [Alias('OutputPath')]
        [string]$ReportPath
    )

    if (-not $ReportPath) {
        $ReportPath = Join-Path $Path 'ThreatJet_Report.html'   # lint:allow-param-assign
    }

    Write-TJETLog INFO 'Generating HTML assessment report'

    $findingsFile = Join-Path $Path 'AD_Assessment_Findings.csv'

    if (-not (Test-Path $findingsFile)) {
        Write-TJETLog ERROR "Findings file not found: $findingsFile. Run Invoke-ThreatJetCorrelation first."
        return
    }

    $findings = @(Import-Csv $findingsFile)

    $severityRank = @{ Critical = 1; High = 2; Medium = 3; Low = 4; Info = 5 }

    $counts = @{}

    foreach ($level in 'Critical','High','Medium','Low','Info') {
        $counts[$level] = @($findings | Where-Object { $_.Severity -eq $level }).Count
    }

    $domain = ''
    $domainFile = Join-Path $Path 'AD_Domain_Summary.csv'

    if (Test-Path $domainFile) {
        $domainRow = @(Import-Csv $domainFile)
        if ($domainRow.Count -gt 0) { $domain = $domainRow[0].Domain }
    }

    $columns = @(
        @{ Key = 'Finding_ID';         Label = 'ID' }
        @{ Key = 'Severity';           Label = 'Severity' }
        @{ Key = 'Confidence';         Label = 'Confidence' }
        @{ Key = 'Category';           Label = 'Category' }
        @{ Key = 'Target';             Label = 'Target' }
        @{ Key = 'Finding';            Label = 'Finding' }
        @{ Key = 'Evidence';           Label = 'Evidence' }
        @{ Key = 'MITRE_Technique';    Label = 'ATT&CK' }
        @{ Key = 'Detection_Guidance'; Label = 'Detection Guidance' }
        @{ Key = 'Remediation_Steps';  Label = 'Remediation' }
    )

    $longColumns = @('Evidence','Detection_Guidance','Remediation_Steps')

    $headerCells = New-Object System.Collections.Generic.List[string]
    $filterCells = New-Object System.Collections.Generic.List[string]

    $index = 0

    foreach ($column in $columns) {

        $label = [System.Net.WebUtility]::HtmlEncode("$($column.Label)")

        $headerCells.Add("<th onclick=""sortTable($index)"">$label<span class=""arrow""></span></th>")
        $filterCells.Add("<th><input type=""text"" placeholder=""filter"" oninput=""applyFilters()""></th>")

        $index++
    }

    $rowMarkup = New-Object System.Collections.Generic.List[string]

    $ordered = $findings | Sort-Object `
        @{ Expression = { $severityRank["$($_.Severity)"] } },
        @{ Expression = { $_.Finding_ID } },
        @{ Expression = { $_.Target } }

    foreach ($finding in $ordered) {

        $severity = "$($finding.Severity)"

        if (-not $severityRank.ContainsKey($severity)) { $severity = 'Info' }

        $rank = $severityRank[$severity]

        $cells = New-Object System.Collections.Generic.List[string]

        foreach ($column in $columns) {

            $value = [System.Net.WebUtility]::HtmlEncode("$($finding.($column.Key))")

            if ($column.Key -eq 'Severity') {
                $cells.Add("<td data-sort=""$rank""><span class=""pill sev-$severity"">$value</span></td>")
            }
            elseif ($longColumns -contains $column.Key) {
                $cells.Add("<td class=""longtext"" onclick=""this.classList.toggle('open')"">$value</td>")
            }
            else {
                $cells.Add("<td>$value</td>")
            }
        }

        $rowMarkup.Add("<tr data-sev=""$severity"">$($cells -join '')</tr>")
    }

    $headerHtml = $headerCells -join "`n"
    $filterHtml = $filterCells -join "`n"
    $rowsHtml   = $rowMarkup -join "`n"
    $generated  = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $domainHtml = [System.Net.WebUtility]::HtmlEncode("$domain")
    $total      = $findings.Count

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>ThreatJET - Jumbo Evaluation Tool</title>
<style>
:root {
  --bg:#f4f5f8; --panel:#ffffff; --line:#d8dce4; --text:#1a1d24; --muted:#5b6472;
  --crit:#b3123a; --high:#a35200; --med:#7a5b00; --low:#0f6e63; --info:#254fb5;
  --crit-bg:#fdeaee; --high-bg:#fdf0e3; --med-bg:#fcf6e0; --low-bg:#e5f5f3; --info-bg:#e9eefb;
  --accent:#1b3a6b; --header-text:#ffffff;
}
* { box-sizing:border-box; }
body { margin:0; background:var(--bg); color:var(--text);
       font:14px/1.55 "Segoe UI",system-ui,sans-serif; }

/* Header: white text on a deep purple bar. Contrast checked both ways -- the old
   theme put dark text over purple, which was the readability complaint. */
header { padding:22px 30px; color:var(--header-text);
         background:linear-gradient(120deg,#0e2547 0%,#1b3a6b 55%,#2b5aa0 100%);
         border-bottom:1px solid #0a1c38;
         box-shadow:0 2px 10px rgba(14,37,71,.25); }
.brand { display:flex; align-items:center; gap:16px; }
.logo { flex:0 0 auto; display:inline-flex; align-items:center; justify-content:center;
        width:60px; height:60px; border-radius:14px;
        background:rgba(255,255,255,.08); border:1px solid rgba(255,255,255,.18);
        box-shadow:inset 0 1px 0 rgba(255,255,255,.15); }
.logo svg { display:block; filter:drop-shadow(0 2px 3px rgba(0,0,0,.4)); }
h1 { margin:0 0 5px; font-size:24px; font-weight:700; letter-spacing:2px;
     color:#fff; text-shadow:0 1px 2px rgba(0,0,0,.3); }
.sub { color:#c9d9f2; font-size:12.5px; letter-spacing:.2px; }

.wrap { padding:22px 30px 60px; max-width:1400px; }
.cards { display:flex; gap:12px; flex-wrap:wrap; margin-bottom:20px; }
.card { position:relative; background:var(--panel); border:1px solid var(--line);
        border-radius:10px; padding:14px 20px 12px; min-width:116px; cursor:pointer;
        user-select:none; overflow:hidden;
        box-shadow:0 1px 3px rgba(20,25,40,.08); transition:transform .08s, box-shadow .12s; }
.card::before { content:""; position:absolute; top:0; left:0; right:0; height:3px; background:var(--line); }
.card.Critical::before{background:var(--crit)} .card.High::before{background:var(--high)}
.card.Medium::before{background:var(--med)} .card.Low::before{background:var(--low)} .card.Info::before{background:var(--info)}
.card:hover { border-color:var(--accent); transform:translateY(-1px); box-shadow:0 4px 12px rgba(20,25,40,.12); }
.card.off { opacity:.35; }
.card .n { font-size:26px; font-weight:800; letter-spacing:-.5px; }
.card .l { font-size:11px; text-transform:uppercase; letter-spacing:.8px; color:var(--muted); }
.card.Critical .n{color:var(--crit)} .card.High .n{color:var(--high)}
.card.Medium .n{color:var(--med)} .card.Low .n{color:var(--low)} .card.Info .n{color:var(--info)}

.controls { display:flex; gap:10px; align-items:center; margin-bottom:12px; flex-wrap:wrap; }
input[type=text] { background:#fff; color:var(--text); border:1px solid var(--line);
                   border-radius:5px; padding:6px 9px; font-size:12.5px; width:100%; }
input[type=text]:focus { outline:2px solid var(--accent); outline-offset:-1px; }
#globalSearch { max-width:340px; }
button { background:var(--panel); color:var(--text); border:1px solid var(--line);
         border-radius:5px; padding:7px 13px; cursor:pointer; font-size:12.5px; }
button:hover { border-color:var(--accent); color:var(--accent); }
.count { color:var(--muted); font-size:12.5px; margin-left:auto; }

.tablebox { overflow:auto; max-height:72vh; border:1px solid var(--line);
            border-radius:8px; background:var(--panel); }
table { border-collapse:separate; border-spacing:0; width:100%; }
th, td { padding:8px 10px; text-align:left; border-bottom:1px solid var(--line);
         vertical-align:top; font-size:12.5px; }

/* Sticky header: white on purple, matching the page header. */
thead th { position:sticky; top:0; background:var(--accent); color:var(--header-text);
           cursor:pointer; white-space:nowrap; z-index:2; font-weight:600; }
thead th:hover { background:#4a2475; }
thead tr.filters th { top:36px; background:#efeaf6; cursor:default; z-index:1; }
thead tr.filters input { font-size:11.5px; padding:4px 6px; }
th .arrow { margin-left:5px; font-size:10px; color:#e4dcf2; }

tbody tr:nth-child(even) { background:#fafbfc; }
tbody tr:hover { background:#eef1f7; }

.pill { padding:2px 9px; border-radius:11px; font-size:11px; font-weight:700;
        white-space:nowrap; border:1px solid currentColor; }
.sev-Critical{background:var(--crit-bg);color:var(--crit)}
.sev-High{background:var(--high-bg);color:var(--high)}
.sev-Medium{background:var(--med-bg);color:var(--med)}
.sev-Low{background:var(--low-bg);color:var(--low)}
.sev-Info{background:var(--info-bg);color:var(--info)}

td.longtext { max-width:330px; overflow:hidden; text-overflow:ellipsis;
              white-space:nowrap; cursor:pointer; color:var(--muted); }
td.longtext.open { white-space:pre-wrap; max-width:600px; color:var(--text); }
td.longtext:hover { color:var(--accent); }
.hint { color:var(--muted); font-size:11.5px; margin:10px 0 0; }
tr.grouphdr td { background:var(--accent); color:var(--header-text); font-weight:700;
                 text-transform:uppercase; letter-spacing:.6px; font-size:11.5px;
                 position:sticky; top:71px; }

@media print {
  header { background:#fff !important; color:#000 !important; border-bottom:2px solid #000; }
  h1, .sub { color:#000 !important; }
  thead th { background:#e8e8e8 !important; color:#000 !important; }
  .tablebox { max-height:none; overflow:visible; }
  td.longtext { white-space:pre-wrap; max-width:none; color:#000; }
  .controls, .cards { display:none; }
}
</style>
</head>
<body>
<header>
  <div class="brand">
    <span class="logo" aria-hidden="true">
      <svg width="46" height="46" viewBox="0 0 64 64" xmlns="http://www.w3.org/2000/svg">
        <defs>
          <linearGradient id="jetg" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0" stop-color="#eaf2ff"/>
            <stop offset="1" stop-color="#9fc0ee"/>
          </linearGradient>
        </defs>
        <!-- F-22 fighter jet silhouette, top-down, nose up -->
        <g fill="url(#jetg)" stroke="#0e2547" stroke-width="1.1" stroke-linejoin="round">
          <path d="M32 3 L28 15 L28 24 L6 40 L9 44 L28 44 L27 48 L20 55 L26 56 L29 61 L32 62 L35 61 L38 56 L44 55 L37 48 L36 44 L55 44 L58 40 L36 24 L36 15 L32 3 L32 3 Z"/>
        </g>
        <circle cx="32" cy="17" r="2" fill="#0e2547" stroke="none"/>
      </svg>
    </span>
    <div>
      <h1>ThreatJET</h1>
      <div class="sub">Jumbo Evaluation Tool &nbsp;&middot;&nbsp; $domainHtml &nbsp;&middot;&nbsp; $generated &nbsp;&middot;&nbsp; $total findings</div>
    </div>
  </div>
</header>
<div class="wrap">

  <div class="cards">
    <div class="card Critical" data-sev="Critical" onclick="toggleSev(this)"><div class="n">$($counts['Critical'])</div><div class="l">Critical</div></div>
    <div class="card High" data-sev="High" onclick="toggleSev(this)"><div class="n">$($counts['High'])</div><div class="l">High</div></div>
    <div class="card Medium" data-sev="Medium" onclick="toggleSev(this)"><div class="n">$($counts['Medium'])</div><div class="l">Medium</div></div>
    <div class="card Low" data-sev="Low" onclick="toggleSev(this)"><div class="n">$($counts['Low'])</div><div class="l">Low</div></div>
    <div class="card Info" data-sev="Info" onclick="toggleSev(this)"><div class="n">$($counts['Info'])</div><div class="l">Info</div></div>
  </div>

  <div class="controls">
    <input type="text" id="globalSearch" placeholder="Search all columns..." oninput="applyFilters()">
    <button onclick="toggleGroup()" id="groupBtn">Group by category</button>
    <button onclick="selectAllSev()">Show all</button>
    <button onclick="selectNoneSev()">Hide all</button>
    <button onclick="invertSev()">All except filtered</button>
    <button onclick="clearAll()">Clear filters</button>
    <button onclick="exportVisible()">Export visible to CSV</button>
    <span class="count" id="count"></span>
  </div>

  <div class="tablebox">
    <table id="t">
      <thead>
        <tr>
$headerHtml
        </tr>
        <tr class="filters">
$filterHtml
        </tr>
      </thead>
      <tbody>
$rowsHtml
      </tbody>
    </table>
  </div>

  <p class="hint">Click a column header to sort. Click a severity card to show or hide that band.
     Evidence, Detection Guidance and Remediation cells are truncated - click one to expand it.</p>
</div>

<script>
var sortState = { col: -1, asc: true };
var hidden = {};

function rowsOf() {
  return Array.prototype.slice.call(document.querySelectorAll('#t tbody tr'))
    .filter(function (r) { return !r.classList.contains('grouphdr'); });
}

function applyFilters() {
  var global = document.getElementById('globalSearch').value.toLowerCase();
  var boxes = Array.prototype.slice.call(document.querySelectorAll('thead tr.filters input'));
  var shown = 0;
  var all = rowsOf();

  all.forEach(function (row) {
    var cells = row.children;
    var ok = true;

    if (hidden[row.getAttribute('data-sev')]) { ok = false; }

    if (ok) {
      for (var i = 0; i < boxes.length; i++) {
        var term = boxes[i].value.toLowerCase();
        if (term && cells[i] && cells[i].textContent.toLowerCase().indexOf(term) === -1) {
          ok = false;
          break;
        }
      }
    }

    if (ok && global && row.textContent.toLowerCase().indexOf(global) === -1) { ok = false; }

    row.style.display = ok ? '' : 'none';
    if (ok) { shown++; }
  });

  document.getElementById('count').textContent = shown + ' of ' + all.length + ' shown';

  // When grouped, hide a category header if none of its rows are visible.
  if (grouped) {
    var headers = Array.prototype.slice.call(document.querySelectorAll('#t tbody tr.grouphdr'));
    headers.forEach(function (hdr) {
      var anyVisible = false;
      var row = hdr.nextElementSibling;
      while (row && !row.classList.contains('grouphdr')) {
        if (row.style.display !== 'none') { anyVisible = true; break; }
        row = row.nextElementSibling;
      }
      hdr.style.display = anyVisible ? '' : 'none';
    });
  }
}

function sortTable(col) {
  var tbody = document.querySelector('#t tbody');
  var rows = rowsOf();

  sortState.asc = (sortState.col === col) ? !sortState.asc : true;
  sortState.col = col;

  rows.sort(function (a, b) {
    var x = a.children[col], y = b.children[col];
    if (!x || !y) { return 0; }

    var xs = x.getAttribute('data-sort'), ys = y.getAttribute('data-sort');
    var av, bv;

    if (xs !== null && ys !== null) {
      av = parseFloat(xs); bv = parseFloat(ys);
    } else {
      av = x.textContent.trim().toLowerCase();
      bv = y.textContent.trim().toLowerCase();
      var an = parseFloat(av), bn = parseFloat(bv);
      if (!isNaN(an) && !isNaN(bn) && av !== '' && bv !== '') { av = an; bv = bn; }
    }

    if (av < bv) { return sortState.asc ? -1 : 1; }
    if (av > bv) { return sortState.asc ? 1 : -1; }
    return 0;
  });

  rows.forEach(function (r) { tbody.appendChild(r); });

  document.querySelectorAll('thead th .arrow').forEach(function (a) { a.textContent = ''; });

  var head = document.querySelectorAll('thead tr:first-child th')[col];
  if (head) {
    var arrow = head.querySelector('.arrow');
    if (arrow) { arrow.textContent = sortState.asc ? '\u25B2' : '\u25BC'; }
  }
}

function toggleSev(card) {
  var sev = card.getAttribute('data-sev');
  hidden[sev] = !hidden[sev];
  card.classList.toggle('off');
  applyFilters();
}

function clearAll() {
  document.getElementById('globalSearch').value = '';
  document.querySelectorAll('thead tr.filters input').forEach(function (i) { i.value = ''; });
  hidden = {};
  document.querySelectorAll('.card').forEach(function (c) { c.classList.remove('off'); });
  applyFilters();
}

function exportVisible() {
  var out = [];
  var heads = [];

  document.querySelectorAll('thead tr:first-child th').forEach(function (th) {
    heads.push('"' + th.textContent.replace(/[\u25B2\u25BC]/g, '').trim().replace(/"/g, '""') + '"');
  });
  out.push(heads.join(','));

  rowsOf().forEach(function (row) {
    if (row.style.display === 'none') { return; }
    var cells = [];
    Array.prototype.slice.call(row.children).forEach(function (td) {
      cells.push('"' + td.textContent.trim().replace(/"/g, '""') + '"');
    });
    out.push(cells.join(','));
  });

  var blob = new Blob([out.join('\r\n')], { type: 'text/csv;charset=utf-8;' });
  var a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'ThreatJet_Filtered.csv';
  a.click();
}

// ---- severity select helpers -------------------------------------------------
function selectAllSev() {
  hidden = {};
  document.querySelectorAll('.card').forEach(function (c) { c.classList.remove('off'); });
  applyFilters();
}

function selectNoneSev() {
  ['Critical','High','Medium','Low','Info'].forEach(function (s) { hidden[s] = true; });
  document.querySelectorAll('.card').forEach(function (c) { c.classList.add('off'); });
  applyFilters();
}

function invertSev() {
  // "All except filtered": show everything that is NOT currently hidden-by-card,
  // i.e. flip each severity's state.
  ['Critical','High','Medium','Low','Info'].forEach(function (s) { hidden[s] = !hidden[s]; });
  document.querySelectorAll('.card').forEach(function (c) {
    if (hidden[c.getAttribute('data-sev')]) { c.classList.add('off'); }
    else { c.classList.remove('off'); }
  });
  applyFilters();
}

// ---- category grouping -------------------------------------------------------
var grouped = false;
var CATEGORY_COL = 3;   // the Category column index

function toggleGroup() {
  grouped = !grouped;
  document.getElementById('groupBtn').textContent = grouped ? 'Ungroup' : 'Group by category';
  renderGroups();
  applyFilters();
}

function renderGroups() {
  var tbody = document.querySelector('#t tbody');
  // Remove any existing group header rows first.
  Array.prototype.slice.call(tbody.querySelectorAll('tr.grouphdr')).forEach(function (r) { r.remove(); });

  if (!grouped) { return; }

  var rows = rowsOf().filter(function (r) { return !r.classList.contains('grouphdr'); });

  // Stable sort rows by category so members are contiguous.
  rows.sort(function (a, b) {
    var av = a.children[CATEGORY_COL].textContent.trim().toLowerCase();
    var bv = b.children[CATEGORY_COL].textContent.trim().toLowerCase();
    return av < bv ? -1 : av > bv ? 1 : 0;
  });
  rows.forEach(function (r) { tbody.appendChild(r); });

  // Insert a header row before each new category.
  var colCount = document.querySelectorAll('thead tr:first-child th').length;
  var current = null;

  // Distinct colour per category so grouped sections are visually separable.
  var catPalette = ['#1b3a6b','#7a1f5c','#0f6e63','#8a4b00','#3d2b8e',
                    '#0d5a8a','#8a2b2b','#4a6b0f','#5b2d8e','#6b4a00',
                    '#2b6b5a','#8a1f4b'];
  function catColor(name) {
    var h = 0;
    for (var i = 0; i < name.length; i++) { h = (h * 31 + name.charCodeAt(i)) & 0x7fffffff; }
    return catPalette[h % catPalette.length];
  }

  rows.forEach(function (r) {
    var cat = r.children[CATEGORY_COL].textContent.trim() || '(uncategorised)';
    if (cat !== current) {
      current = cat;
      var hdr = document.createElement('tr');
      hdr.className = 'grouphdr';
      hdr.setAttribute('data-cat', cat);
      var td = document.createElement('td');
      td.colSpan = colCount;
      td.textContent = cat;
      var c = catColor(cat);
      td.style.background = c;
      td.style.borderLeft = '6px solid rgba(255,255,255,.55)';
      hdr.appendChild(td);
      tbody.insertBefore(hdr, r);
    }
  });
}

applyFilters();
sortTable(1);
</script>
</body>
</html>
"@

    $html | Out-File -FilePath $ReportPath -Encoding UTF8

    Write-TJETLog INFO "Report created: $ReportPath"

    return $ReportPath
}


# ==========================================================================
# SOURCE: Menu\Show-TJETMenu.ps1
# ==========================================================================
function Show-TJETMenu {
<#
.SYNOPSIS
    Interactive menu for ThreatJet. Answer prompts instead of remembering flags.
.DESCRIPTION
    A front end over the exported commands. After loading the toolkit (dot-source the
    standalone file, or import the module), run Show-TJETMenu and choose what to do. It
    builds the correct parameter set from your answers and calls the real commands, so
    the menu can never do anything the commands cannot.

        . .\ThreatJet_Standalone.ps1
        Show-TJETMenu
#>
    [CmdletBinding()]
    param()

    # ------------------------------------------------------------- helpers ---
    function Write-MenuHeader {
        Clear-Host

        # Enable ANSI/VT so the colour banner renders on PS 5.1 (Win10+ consoles support
        # it but 5.1 does not enable it by default). PS 7 renders ANSI regardless.
        $ansiOk = $false
        try {
            if (-not ('TJETVt' -as [type])) {
                Add-Type -ErrorAction Stop -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class TJETVt {
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr GetStdHandle(int nStdHandle);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool GetConsoleMode(IntPtr h, out uint m);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool SetConsoleMode(IntPtr h, uint m);
    public static bool Enable() {
        IntPtr h = GetStdHandle(-11);
        uint m;
        if (!GetConsoleMode(h, out m)) return false;
        return SetConsoleMode(h, m | 0x0004);
    }
}
'@
            }
            $ansiOk = [TJETVt]::Enable()
        }
        catch { $ansiOk = $false }
        if ($PSVersionTable.PSVersion.Major -ge 6) { $ansiOk = $true }

        # How wide is the console? Drives whether the jet sits BESIDE the wordmark
        # (needs ~133 cols) or STACKED above it (always fits).
        $consoleWidth = 120
        try { $consoleWidth = $Host.UI.RawUI.WindowSize.Width } catch { }
        if (-not $consoleWidth -or $consoleWidth -lt 1) { $consoleWidth = 120 }

        Write-Host ''

        if ($ansiOk) {
            $e = [char]27

        $wordmark = @(
            '@E@[0;97;47m█@E@[0;97;45m▀▀▀▀@E@[0;37;45m▀▀▀▀▀@E@[0;37;40m█ @E@[0;97;47m█@E@[0;97;45m▀▀@E@[0;97;40m█@E@[0;37;40m   @E@[0;97;40m█@E@[0;37;45m▀▀@E@[0;37;40m█ @E@[0;97;45m█▀▀▀▀@E@[0;37;45m▀▀▀▀@E@[0;37;40m▄   @E@[0;97;40m▄@E@[0;97;45m▀▀▀@E@[0;37;45m▀▀▀▀▀@E@[0;37;40m█  @E@[0;97;40m▄@E@[0;97;45m▀▀▀@E@[0;37;45m▀▀▀▀@E@[0;37;40m▄  @E@[0;97;47m█@E@[0;97;45m▀▀▀▀@E@[0;37;45m▀▀▀▀▀@E@[0;37;40m█        @E@[0;97;40m█@E@[0;97;45m▀▀@E@[0;37;40m█  @E@[0;97;40m▄@E@[0;97;45m▀▀▀@E@[0;37;45m▀▀▀▀▀@E@[0;37;40m█ @E@[0;97;47m█@E@[0;97;45m▀▀▀▀@E@[0;37;45m▀▀▀▀▀@E@[0;37;40m█@E@[0m'
            '@E@[0;97;47m█@E@[0;97;45m▄▄▄@E@[0;35;45m██@E@[0;37;45m▄▄▄▄@E@[0;37;40m█ @E@[0;97;47m█@E@[0;97;45m  @E@[0;97;40m█@E@[0;37;40m   @E@[0;97;40m█@E@[0;35;40m██@E@[0;37;40m█ @E@[0;97;45m█  ▄▄@E@[0;37;45m▄▄   @E@[0;37;40m█ @E@[0;97;47m█@E@[0;97;45m  @E@[0;35;40m█@E@[0;97;45m▄@E@[0;37;45m▄▄▄▄▄@E@[0;37;40m█ @E@[0;97;45m█   @E@[0;90;45m▄@E@[0;37;45m▄▄   @E@[0;37;40m█ @E@[0;97;47m█@E@[0;97;45m▄▄▄@E@[0;35;45m██@E@[0;37;45m▄▄▄▄@E@[0;37;40m█        @E@[0;97;40m█@E@[0;97;45m  @E@[0;37;40m█ @E@[0;97;47m█@E@[0;97;45m  @E@[0;35;40m█@E@[0;97;45m▄@E@[0;37;45m▄▄▄▄▄@E@[0;37;40m█ @E@[0;97;47m█@E@[0;97;45m▄▄▄@E@[0;35;45m██@E@[0;37;45m▄▄▄▄@E@[0;37;40m█@E@[0m'
            '@E@[0;37;40m   @E@[0;97;47m█@E@[0;97;45m  @E@[0;37;45m█@E@[0;37;40m     @E@[0;97;47m█@E@[0;97;45m  █@E@[0;37;40m▄▄▄█@E@[0;35;40m██@E@[0;37;40m█ @E@[0;97;45m█  █@E@[0;37;40m▄▄▄@E@[0;37;45m▀  @E@[0;37;40m█ @E@[0;97;47m█@E@[0;97;45m  █@E@[0;37;40m▄▄▄▄▄   @E@[0;97;40m█@E@[0;97;45m  @E@[0;90;47m█@E@[0;37;40m   █@E@[0;37;45m  @E@[0;37;40m█    @E@[0;97;47m█@E@[0;97;45m  @E@[0;37;45m█@E@[0;37;40m            @E@[0;97;45m█  @E@[0;37;40m█ @E@[0;97;47m█@E@[0;97;45m  █@E@[0;37;40m▄▄▄▄▄      @E@[0;97;47m█@E@[0;97;45m  @E@[0;37;45m█@E@[0;37;40m    @E@[0m'
            '@E@[0;37;40m   @E@[0;97;47m▀@E@[0;97;45m  @E@[0;37;40m█     @E@[0;97;47m▀@E@[0;97;45m       @E@[0;35;40m██@E@[0;90;47m▄@E@[0;37;40m @E@[0;97;47m▀@E@[0;97;45m        @E@[0;90;47m▄@E@[0;37;40m  @E@[0;97;47m▀@E@[0;97;45m       @E@[0;90;45m█@E@[0;37;40m   @E@[0;97;47m▀@E@[0;97;45m  @E@[0;90;47m▀@E@[0;37;40m▄@E@[0;97;40m▄▄@E@[0;97;45m█  @E@[0;90;47m▄@E@[0;37;40m    @E@[0;97;47m▀@E@[0;97;45m  @E@[0;37;40m█            @E@[0;97;47m▀@E@[0;97;45m  @E@[0;37;40m█ @E@[0;97;47m▀@E@[0;97;45m       @E@[0;90;45m█@E@[0;37;40m      @E@[0;97;47m▀@E@[0;97;45m  @E@[0;37;40m█    @E@[0m'
            '@E@[0;37;40m   █@E@[0;37;45m  @E@[0;90;45m█@E@[0;37;40m     █@E@[0;37;45m  █@E@[0;37;40m▀▀▀█@E@[0;35;40m██@E@[0;90;40m█@E@[0;37;40m █@E@[0;37;45m  @E@[0;37;40m█▀@E@[0;90;40m▀▀@E@[0;90;45m▄  @E@[0;90;40m█@E@[0;37;40m █@E@[0;37;45m  █@E@[0;37;40m▀▀@E@[0;90;40m▀▀▀@E@[0;37;40m   █@E@[0;37;45m         @E@[0;90;45m█@E@[0;37;40m    █@E@[0;37;45m  @E@[0;90;45m█@E@[0;37;40m           ▄@E@[0;37;45m▀  @E@[0;90;40m█@E@[0;37;40m █@E@[0;37;45m  █@E@[0;37;40m▀▀@E@[0;90;40m▀▀▀@E@[0;37;40m      █@E@[0;37;45m  @E@[0;90;45m█@E@[0;37;40m    @E@[0m'
            '@E@[0;37;40m   █@E@[0;37;45m  @E@[0;90;45m█@E@[0;37;40m     █@E@[0;37;45m  @E@[0;37;40m█   █@E@[0;35;40m██@E@[0;90;45m█@E@[0;37;40m █@E@[0;37;45m  @E@[0;37;40m█   @E@[0;90;40m█@E@[0;90;45m  @E@[0;90;40m█@E@[0;37;40m █@E@[0;37;45m  @E@[0;35;40m█@E@[0;37;45m▀▀@E@[0;90;45m▀▀▀▀█@E@[0;37;40m █@E@[0;37;45m  @E@[0;37;40m█▀@E@[0;90;40m▀▀█@E@[0;90;45m  @E@[0;90;40m█@E@[0;37;40m    █@E@[0;37;45m  @E@[0;90;45m█@E@[0;37;40m     @E@[0;97;40m█@E@[0;97;45m▀▀▀@E@[0;37;45m▀▀@E@[0;35;40m██@E@[0;37;45m @E@[0;90;45m▄@E@[0;90;40m▀@E@[0;37;40m █@E@[0;37;45m  @E@[0;35;40m█@E@[0;37;45m▀▀@E@[0;90;45m▀▀▀▀█@E@[0;37;40m    █@E@[0;37;45m  @E@[0;90;45m█@E@[0;37;40m    @E@[0m'
            '@E@[0;37;40m   █@E@[0;90;45m▄▄█@E@[0;37;40m     █@E@[0;37;45m▄▄@E@[0;37;40m█   @E@[0;90;47m▄@E@[0;90;45m▄▄█@E@[0;37;40m █@E@[0;37;45m▄▄@E@[0;37;40m█   @E@[0;90;40m█@E@[0;90;45m▄▄@E@[0;90;40m█@E@[0;37;40m  ▀@E@[0;37;45m▄▄▄▄@E@[0;90;45m▄▄▄▄█@E@[0;37;40m █@E@[0;37;45m▄▄@E@[0;37;40m█   @E@[0;90;40m█@E@[0;90;45m▄▄@E@[0;90;40m█@E@[0;37;40m    █@E@[0;90;45m▄▄█@E@[0;37;40m     @E@[0;97;40m█@E@[0;37;45m▄▄▄▄@E@[0;90;45m▄▄▄@E@[0;90;40m▀@E@[0;37;40m    ▀@E@[0;37;45m▄▄▄▄@E@[0;90;45m▄▄▄▄█@E@[0;37;40m    █@E@[0;90;45m▄▄█@E@[0;37;40m    '
        )

        $jetF22 = @(
            '                          /\'
            '                         |  |'
            '                        .''  ''.'
            '                        |    |'
            '                        | /\ |'
            '                      .'' |TJ|''.'
            '                      |  |  |  |'
            '                     .''  |  |  ''.'
            '                /\   |   \__/   |   /\'
            '               |  |  |   |  |   |  |  |'
            '           /|  |  |,-\   |  |   /-,|  |  |\'
            '           ||  |,-''   |  |  |  |   ''-,|  ||'
            '           ||-''       |  |  |  |       ''-||'
            '|\     _,-''           |  |  |  |           ''-,_     /|'
            '||-''    =(*)=         |  |  |  |                  ''-||'
            '||                    |  \  /  |                    ||'
            '|\________....--------\   ||   /--------....________/|'
            '                      /|  ||  |\'
            '                   /   |      |   \   '
            '                 //   .|      |.   \'
            '               .'' |_./ |      | \._| ''.'
            '              /     _.-|||  |||-._     \'
            '              \__.-''   \||/\||/   ''-.__/ '
        )

        $wmWidth = 107

            # Jet stacked ABOVE the wordmark (always, regardless of width).
            foreach ($jl in $jetF22) { Write-Host ("$e[1;96m$jl$e[0m") }
            Write-Host ''
            foreach ($wl in $wordmark) { Write-Host ($wl -replace '@E@', $e) }
        }
        else {
            # No ANSI: plain figlet wordmark, no escape codes leak.
            Write-Host '     ______  __                        __      __       __ ' -ForegroundColor Cyan
            Write-Host '    /_  __/ / /_   ____ ___   ____ _  / /_    / /  ___ / /_' -ForegroundColor Cyan
            Write-Host '     / /   / __ \ / __ `__ \ / __ `/ / __/   / /  / _ \ __/' -ForegroundColor Cyan
            Write-Host '    / /   / / / // / / / / // /_/ / / /_  __ / /  /  __/ /_ ' -ForegroundColor Blue
            Write-Host '   /_/   /_/ /_//_/ /_/ /_/ \__,_/  \__/ /_//_/   \___/\__/ ' -ForegroundColor Blue
        }

        Write-Host ''
        Write-Host '         ThreatJET - Jumbo Evaluation Tool' -ForegroundColor DarkGray
        Write-Host ''
    }



    function Read-MenuChoice {
        param([string]$Title, [string[]]$Options, [string]$BackLabel = 'Back')

        while ($true) {
            Write-Host ''
            Write-Host "  $Title" -ForegroundColor Cyan
            Write-Host ''
            for ($i = 0; $i -lt $Options.Count; $i++) {
                Write-Host ("    {0}. {1}" -f ($i + 1), $Options[$i])
            }
            Write-Host ''
            Write-Host "    0. $BackLabel" -ForegroundColor DarkGray
            Write-Host ''

            $choice = Read-Host '  Choice'
            if ($choice -match '^\d+$') {
                $n = [int]$choice
                if ($n -ge 0 -and $n -le $Options.Count) { return $n }
            }
            Write-Host '  Enter a number from the list.' -ForegroundColor Yellow
        }
    }

    function Read-YesNo {
        param([string]$Question, [bool]$Default = $false)
        $suffix = if ($Default) { '[Y/n]' } else { '[y/N]' }
        while ($true) {
            $answer = Read-Host "  $Question $suffix"
            if ([string]::IsNullOrWhiteSpace($answer)) { return $Default }
            if ($answer -match '^(y|yes)$') { return $true }
            if ($answer -match '^(n|no)$')  { return $false }
            Write-Host '  Please answer y or n.' -ForegroundColor Yellow
        }
    }

    function Read-PathOrDefault {
        param([string]$Question, [string]$Default)
        $answer = Read-Host "  $Question (Enter for: $Default)"
        if ([string]::IsNullOrWhiteSpace($answer)) { return $Default }
        return $answer
    }

    function Read-CVEDatabasePath {
        # The CVE scan needs a real database. A mistyped path (or a stray 'y' from the
        # previous prompt) silently wastes the scan, so confirm the file exists and let
        # the user re-enter or proceed anyway.
        param([string]$Default)
        while ($true) {
            $path = Read-PathOrDefault 'CVE database path' $Default
            if (Test-Path $path -PathType Leaf) { return $path }
            Write-Host "  Warning: no file found at '$path'." -ForegroundColor Yellow
            if (-not (Read-YesNo 'Use it anyway (the CVE scan will skip if it is missing)?' $false)) {
                continue
            }
            return $path
        }
    }

    function Invoke-MenuAction {
        param([scriptblock]$Action)
        Write-Host ''
        Write-Host '  Running...' -ForegroundColor Green
        Write-Host ''
        try { & $Action }
        catch { Write-Host ''; Write-Host "  Error: $($_.Exception.Message)" -ForegroundColor Red }
        Write-Host ''
        Read-Host '  Press Enter to return to the menu' | Out-Null
    }

    $defaultOut = Join-Path $PWD "ThreatJet_$(Get-Date -Format 'yyyyMMdd-HHmm')"

    # ------------------------------------------------------- menu actions ---
    function Do-FullAssessment {
        $outPath   = Read-PathOrDefault 'Output folder' $defaultOut
        $inventory = Read-YesNo 'Include full object inventory (slower, larger)?' $false
        $datamine  = Read-YesNo 'Datamine the filesystem for passwords?' $false
        $cve       = Read-YesNo 'Run the offline CVE scan?' $false
        $cveDb     = 'C:\Security\cves.db'
        if ($cve) { $cveDb = Read-CVEDatabasePath $cveDb }
        $open      = Read-YesNo 'Open the HTML report when done?' $true

        Invoke-MenuAction {
            $splat = @{ Path = $outPath; OpenReport = $open }
            if ($inventory) { $splat['IncludeInventory']  = $true }
            if ($datamine)  { $splat['DataminePasswords'] = $true }
            if ($cve)       { $splat['IncludeCVEScan'] = $true; $splat['CVEDatabasePath'] = $cveDb }
            Invoke-ThreatJetAssessment @splat
        }
    }

    function Do-ADOnly {
        $outPath = Read-PathOrDefault 'Output folder' $defaultOut

        $typeChoice = Read-MenuChoice -Title 'Which AD objects?' -Options @('All object types', 'Choose specific types')
        if ($typeChoice -eq 0) { return }

        $adTypes = @()
        if ($typeChoice -eq 2) {
            $all = 'Users','Computers','Groups','ServiceAccounts','GPOs','ACLs','Trusts','FGPP','Domain','ADCS'
            Write-Host ''
            Write-Host '  Enter the numbers you want, comma-separated (e.g. 1,3,5):' -ForegroundColor Cyan
            for ($i = 0; $i -lt $all.Count; $i++) { Write-Host ("    {0}. {1}" -f ($i + 1), $all[$i]) }
            $picks = Read-Host '  Types'
            foreach ($p in ($picks -split '[,\s]+')) {
                if ($p -match '^\d+$' -and [int]$p -ge 1 -and [int]$p -le $all.Count) { $adTypes += $all[[int]$p - 1] }
            }
            if ($adTypes.Count -eq 0) { Write-Host '  No valid types; using all.' -ForegroundColor Yellow }
        }

        $attackPath = Read-YesNo 'Also trace attack paths?' $true
        $open       = Read-YesNo 'Open the HTML report when done?' $true

        Invoke-MenuAction {
            $scope = if ($attackPath) { @('AD','AttackPath') } else { @('AD') }
            $splat = @{ Path = $outPath; Scope = $scope; OpenReport = $open }
            if ($adTypes.Count -gt 0) { $splat['ADObjectType'] = $adTypes }
            Invoke-ThreatJetAssessment @splat
        }
    }

    function Do-LocalOnly {
        $outPath  = Read-PathOrDefault 'Output folder' $defaultOut
        $datamine = Read-YesNo 'Datamine the filesystem for passwords?' $false
        $cve      = Read-YesNo 'Run the offline CVE scan?' $false
        $cveDb    = 'C:\Security\cves.db'
        if ($cve) { $cveDb = Read-CVEDatabasePath $cveDb }
        $open     = Read-YesNo 'Open the HTML report when done?' $true

        Invoke-MenuAction {
            $splat = @{ Path = $outPath; Scope = @('LocalHost'); OpenReport = $open }
            if ($datamine) { $splat['DataminePasswords'] = $true }
            if ($cve)      { $splat['IncludeCVEScan'] = $true; $splat['CVEDatabasePath'] = $cveDb }
            Invoke-ThreatJetAssessment @splat
        }
    }

    function Do-InventoryOnly {
        $outPath = Read-PathOrDefault 'Output folder' $defaultOut
        Invoke-MenuAction {
            Export-ADObjectInventory -Path $outPath
            Write-Host ''
            Write-Host "  Inventory written under $outPath\Inventory" -ForegroundColor Green
        }
    }

    function Do-AttackPathOnly {
        $inPath = Read-PathOrDefault 'Folder with already-collected data' $defaultOut
        if (-not (Test-Path $inPath)) {
            Write-Host '  That folder does not exist; run a collection first.' -ForegroundColor Yellow
            Read-Host '  Press Enter' | Out-Null; return
        }
        Invoke-MenuAction {
            Find-TJETAttackPath -Path $inPath
            Write-Host ''
            Write-Host "  Attack paths written to $inPath\Attack_Paths.csv" -ForegroundColor Green
        }
    }

    function Do-ReanalyzeExisting {
        $inPath = Read-PathOrDefault 'Folder with already-collected CSVs' $defaultOut
        if (-not (Test-Path $inPath)) {
            Write-Host '  That folder does not exist.' -ForegroundColor Yellow
            Read-Host '  Press Enter' | Out-Null; return
        }
        $open = Read-YesNo 'Open the HTML report when done?' $true
        Invoke-MenuAction {
            Invoke-ThreatJetAssessment -Path $inPath -SkipCollection -OpenReport:$open
        }
    }

    function Do-BaselineCompare {
        $current  = Read-Host '  Current findings CSV path'
        $baseline = Read-Host '  Baseline findings CSV path'
        if (-not (Test-Path $current) -or -not (Test-Path $baseline)) {
            Write-Host '  One or both files do not exist.' -ForegroundColor Yellow
            Read-Host '  Press Enter' | Out-Null; return
        }
        Invoke-MenuAction {
            Compare-ThreatJetBaseline -CurrentPath $current -BaselinePath $baseline
        }
    }

    # ------------------------------------------------------------- main loop ---
    $topOptions = @(
        'Full assessment (AD + local host + attack paths)'
        'Active Directory only'
        'Local host only (no domain needed)'
        'Object inventory only'
        'Attack-path trace (from existing data)'
        'Re-analyze already-collected data'
        'Compare against a baseline'
    )

    while ($true) {
        Write-MenuHeader

        # Guard: the toolkit functions must be loaded first.
        if (-not (Get-Command Invoke-ThreatJetAssessment -ErrorAction SilentlyContinue)) {
            Write-Host '  Toolkit not loaded. Dot-source the file first:' -ForegroundColor Red
            Write-Host '      . .\ThreatJet_Standalone.ps1' -ForegroundColor White
            return
        }

        $choice = Read-MenuChoice -Title 'What would you like to do?' -Options $topOptions -BackLabel 'Quit'

        switch ($choice) {
            0 { Write-Host ''; Write-Host '  Goodbye.' -ForegroundColor Magenta; Write-Host ''; return }
            1 { Do-FullAssessment }
            2 { Do-ADOnly }
            3 { Do-LocalOnly }
            4 { Do-InventoryOnly }
            5 { Do-AttackPathOnly }
            6 { Do-ReanalyzeExisting }
            7 { Do-BaselineCompare }
        }
    }
}


# ==========================================================================
# Single-file entry banner (shown only when EXECUTED, not when dot-sourced).
# ==========================================================================
if ($MyInvocation.InvocationName -ne '.') {
    Write-Host ""
    Write-Host "  ThreatJET - Jumbo Evaluation Tool (single-file build, v2.1.2)" -ForegroundColor Cyan
    Write-Host "  Dot-source this file, then run: Show-TJETMenu" -ForegroundColor Gray
    Write-Host ""
}

#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.3.0' }
<#
    Pester 5 test suite for WindowsAssessment.ps1

    Run all (any OS - the host is simulated):   Invoke-Pester ./tests -Output Detailed
    Run the live Windows smoke test too:        Invoke-Pester ./tests -Output Detailed -TagFilter Integration  (on Windows)

    Test groups
      Script integrity        parse, ASCII, dot-source safety, static analysis, catalog <-> code consistency
      MITRE ATT&CK mapping    every technique/mitigation validated against the official ATT&CK STIX data snapshot
      Infrastructure          finding model, parsers, masking, JSON safety
      Checks (regression)     one or more tests per defect fixed from v1.37 + behaviour of new checks
      Scoring and narrative   score formula, attack paths, executive summary
      HTML report             self-contained, escaped, complete
      End-to-end              full assessment against the simulated host (CSV/JSON/HTML/ZIP)
      Integration (Windows)   real run on the local Windows host (tagged Integration)
#>

BeforeDiscovery {
    # Data-driven test cases need the catalog at discovery time.
    . (Join-Path (Split-Path -Path $PSScriptRoot -Parent) 'WindowsAssessment.ps1')
    $TechniqueIds = @($script:WATechniques.Keys | Sort-Object)
    $MitigationIds = @($script:WAMitigations.Keys | Sort-Object)
    $CheckIds = @($script:WACheckCatalog.Keys)
}

BeforeAll {
    $script:Root = Split-Path -Path $PSScriptRoot -Parent
    $script:ScriptPath = Join-Path $script:Root 'WindowsAssessment.ps1'
    . $script:ScriptPath
    . (Join-Path $PSScriptRoot 'SimulatedHost.ps1')
    $script:Snapshot = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'attack-enterprise-snapshot.json') -Raw | ConvertFrom-Json
    $script:Mitigates = @{}
    foreach ($pair in $script:Snapshot.mitigates) { $script:Mitigates[$pair] = $true }

    function New-TestContext {
        param ([int]$ProductType = 1, [string]$WinVersion = '10.0.22631', [bool]$IsAdmin = $true, [bool]$PartOfDomain = $true, [switch]$SkipNetworkTests, [switch]$EnableSensitiveInfoSearch, [string[]]$SensitiveSearchPath)
        $script:WAQuiet = $true
        $p = @{ OutputPath = $TestDrive; NoDiscovery = $true; Hostname = 'TEST01'; ProductType = $ProductType; WinVersion = $WinVersion; IsAdmin = $IsAdmin
            PartOfDomain = $PartOfDomain; DomainName = 'corp.contoso.com'; OSCaption = 'Microsoft Windows 11 Enterprise'; SkipNetworkTests = $SkipNetworkTests
            EnableSensitiveInfoSearch = $EnableSensitiveInfoSearch }
        if ($SensitiveSearchPath) { $p.SensitiveSearchPath = $SensitiveSearchPath }
        return New-WAContext @p
    }
    function Get-TestFinding {
        param ([string]$Id, [string]$Scope = '')
        return @($script:WACtx.Findings | Where-Object { $_.CheckID -eq $Id -and $_.Scope -eq $Scope })[0]
    }
    function Set-SimReg {
        param ([string]$Key, [hashtable]$Values)
        if (-not $script:WASim.Registry.ContainsKey($Key)) { $script:WASim.Registry[$Key] = @{} }
        foreach ($n in $Values.Keys) {
            if ($null -eq $Values[$n]) { $script:WASim.Registry[$Key].Remove($n) } else { $script:WASim.Registry[$Key][$n] = $Values[$n] }
        }
    }
    function Remove-SimKey { param ([string]$Key) $script:WASim.Registry.Remove($Key) }
}

Describe 'Script integrity' {
    It 'parses without syntax errors' {
        $errors = $null; $tokens = $null
        [void][System.Management.Automation.Language.Parser]::ParseFile($script:ScriptPath, [ref]$tokens, [ref]$errors)
        $errors | Should -BeNullOrEmpty
    }

    It 'is pure ASCII (Windows PowerShell 5.1 reads BOM-less files as ANSI)' {
        $bytes = [System.IO.File]::ReadAllBytes($script:ScriptPath)
        @($bytes | Where-Object { $_ -gt 127 }).Count | Should -Be 0
    }

    It 'does not start an assessment when dot-sourced' {
        $dir = Join-Path $TestDrive 'dotsource'
        New-Item -ItemType Directory -Path $dir | Out-Null
        Push-Location $dir
        try { & { . $script:ScriptPath } } finally { Pop-Location }
        Get-ChildItem -LiteralPath $dir | Should -BeNullOrEmpty
    }

    It 'passes PSScriptAnalyzer with the repository settings' -Skip:(-not (Get-Module -ListAvailable -Name PSScriptAnalyzer)) {
        $settings = Join-Path $script:Root 'PSScriptAnalyzerSettings.psd1'
        $r = Invoke-ScriptAnalyzer -Path $script:ScriptPath -Settings $settings
        ($r | ForEach-Object { '{0} L{1}: {2}' -f $_.RuleName, $_.Line, $_.Message }) | Should -BeNullOrEmpty
    }

    Context 'Check catalog and code consistency' {
        BeforeAll {
            $src = Get-Content -LiteralPath $script:ScriptPath -Raw
            $catalogEnd = $src.IndexOf('#endregion', $src.IndexOf('$script:WACheckCatalog'))
            $script:CodeBody = $src.Substring($catalogEnd)
            $ast = [System.Management.Automation.Language.Parser]::ParseInput($src, [ref]$null, [ref]$null)
            $script:LiteralIds = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq 'Add-WAFinding' }, $true) | ForEach-Object {
                    $els = $_.CommandElements
                    for ($i = 0; $i -lt $els.Count - 1; $i++) {
                        if ($els[$i] -is [System.Management.Automation.Language.CommandParameterAst] -and $els[$i].ParameterName -eq 'CheckID' -and $els[$i + 1] -is [System.Management.Automation.Language.StringConstantExpressionAst]) { $els[$i + 1].Value }
                    }
                } | Select-Object -Unique)
        }
        It 'every literal CheckID passed to Add-WAFinding exists in the catalog' {
            $script:LiteralIds.Count | Should -BeGreaterThan 50
            @($script:LiteralIds | Where-Object { -not $script:WACheckCatalog.Contains($_) }) | Should -BeNullOrEmpty
        }
        It 'every catalog entry is referenced by the code' {
            @($script:WACheckCatalog.Keys | Where-Object { -not $_.StartsWith('control_') -and $script:CodeBody -notmatch [regex]::Escape("'$_'") }) | Should -BeNullOrEmpty
        }
        It 'every catalog entry has a valid severity and remediation (non-informational)' {
            foreach ($id in $script:WACheckCatalog.Keys) {
                $m = $script:WACheckCatalog[$id]
                $script:WASeverityWeight.ContainsKey($m.Severity) | Should -BeTrue -Because $id
                if ($m.Severity -ne 'Informational') { $m.Remediation | Should -Not -BeNullOrEmpty -Because $id }
            }
        }
        It 'every plan step refers to an existing function' {
            foreach ($step in (Get-WAPlan)) { Get-Command -Name $step[0] -CommandType Function -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty -Because $step[0] }
        }
    }
}

Describe 'MITRE ATT&CK mapping (validated against the official ATT&CK STIX snapshot)' {
    It 'embedded ATT&CK version matches the snapshot' {
        $script:WAAttackVersion | Should -Be ('{0} v{1}' -f $script:Snapshot.collection, $script:Snapshot.version)
    }

    It 'tactic IDs, names and matrix order match the snapshot' {
        $keys = @($script:WATactics.Keys)
        $keys.Count | Should -Be @($script:Snapshot.tactics).Count
        for ($i = 0; $i -lt $keys.Count; $i++) {
            $s = $script:Snapshot.tactics[$i]
            $keys[$i] | Should -Be $s.shortname
            $script:WATactics[$keys[$i]].Id | Should -Be $s.id
            $script:WATactics[$keys[$i]].Name | Should -Be $s.name
        }
    }

    Context 'Technique <_>' -ForEach $TechniqueIds {
        BeforeAll { $script:t = $script:Snapshot.techniques.$_; $script:id = $_ }
        It 'exists in ATT&CK' { $script:t | Should -Not -BeNullOrEmpty }
        It 'is neither revoked nor deprecated' { $script:t.revoked | Should -BeFalse -Because "revoked by $($script:t.revokedBy)"; $script:t.deprecated | Should -BeFalse }
        It 'has the official name' { $script:WATechniques[$script:id].Name | Should -BeExactly $script:t.name }
        It 'has the official tactics' { (@($script:WATechniques[$script:id].Tactics) -join ',') | Should -Be (@($script:t.tactics) -join ',') }
        It 'applies to the Windows platform' { @($script:t.platforms) | Should -Contain 'Windows' }
    }

    Context 'Mitigation <_>' -ForEach $MitigationIds {
        It 'exists, is current and has the official name' {
            $m = $script:Snapshot.mitigations.$_
            $m | Should -Not -BeNullOrEmpty
            $m.revoked | Should -BeFalse
            $m.deprecated | Should -BeFalse
            $script:WAMitigations[$_] | Should -BeExactly $m.name
        }
    }

    Context 'Check <_>' -ForEach $CheckIds {
        BeforeAll { $script:meta = $script:WACheckCatalog[$_] }
        It 'references only known techniques and mitigations' {
            foreach ($t in $script:meta.Techniques) { $script:WATechniques.ContainsKey($t) | Should -BeTrue -Because $t }
            foreach ($m in $script:meta.Mitigations) { $script:WAMitigations.ContainsKey($m) | Should -BeTrue -Because $m }
        }
        It 'uses only mitigations that ATT&CK links to at least one of its techniques' {
            foreach ($m in $script:meta.Mitigations) {
                $linked = @($script:meta.Techniques | Where-Object { $script:Mitigates.ContainsKey("$m|$_") })
                $linked.Count | Should -BeGreaterThan 0 -Because "$m must mitigate one of $($script:meta.Techniques -join ', ') in ATT&CK"
            }
        }
        It 'maps a security control to at least one technique' {
            if ($script:meta.Severity -ne 'Informational') { @($script:meta.Techniques).Count | Should -BeGreaterThan 0 }
        }
    }
}

Describe 'Infrastructure' {
    BeforeEach { Use-WASimulatedHost -Simulation (New-WASimulatedHost); $null = New-TestContext }

    It 'Write-WAScreen works without an explicit colour (v1: "Yellow" was executed as a command)' {
        $script:WAQuiet = $false
        { Write-WAScreen -Text 'hello' 6>$null } | Should -Not -Throw
        $script:WAQuiet = $true
    }

    It 'Write-WAFile creates the file, appends, and writes arrays as lines (null -> empty line)' {
        Write-WAFile -File 'a.txt' -Text 'one'
        Write-WAFile -File 'a.txt' -Text @('two', $null, 'three')
        $lines = Get-Content -LiteralPath (Join-Path $script:WACtx.DetailPath 'a.txt')
        $lines | Should -Be @('one', 'two', '', 'three')
    }

    It 'Get-WAFileName follows the NAME_HOST.ext convention' {
        Get-WAFileName -Name 'SMB' | Should -Be 'SMB_TEST01.txt'
        Get-WAFileName -Name 'X' -Extension '.csv' | Should -Be 'X_TEST01.csv'
    }

    It 'Add-WAFinding enriches results with catalog and ATT&CK metadata' {
        Add-WAFinding -CheckID 'domain_LLMNR' -Status Fail -Finding 'x'
        $f = Get-TestFinding 'domain_LLMNR'
        $f.Severity | Should -Be 'High'
        $f.LegacyStatus | Should -Be 'Opportunity'
        $f.Techniques | Should -Contain 'T1557.001'
        $f.TechniqueNames | Should -Contain 'Name Resolution Poisoning and SMB Relay'
        $f.Tactics | Should -Be @('Credential Access', 'Collection')
        $f.Mitigations | Should -Contain 'M1042'
        $f.Remediation | Should -Match 'EnableMulticast'
    }

    It 'Add-WAFinding rejects unknown CheckIDs' {
        { Add-WAFinding -CheckID 'no_such_check' -Status Pass } | Should -Throw '*Unknown CheckID*'
    }

    It 'Add-WAFinding replaces a duplicate CheckID+Scope but keeps different scopes' {
        Add-WAFinding -CheckID 'machine_wordDDE' -Scope 'Office 16.0' -Status Fail
        Add-WAFinding -CheckID 'machine_wordDDE' -Scope 'Office 16.0' -Status Pass
        Add-WAFinding -CheckID 'machine_wordDDE' -Scope 'Office 15.0' -Status Fail
        @($script:WACtx.Findings | Where-Object CheckID -eq 'machine_wordDDE').Count | Should -Be 2
        (Get-TestFinding 'machine_wordDDE' 'Office 16.0').Status | Should -Be 'Pass'
    }

    It 'Add-WAFinding keeps the result object intact (v2 regression: $Finding/$finding variable collision)' {
        Add-WAFinding -CheckID 'info_cName' -Status Info -Finding 'TEST01'
        $script:WACtx.Findings[0] | Should -BeOfType [System.Management.Automation.PSCustomObject]
    }

    It 'Invoke-WACheck isolates a failing check and records the error' {
        function Test-WABroken { param ($Name) throw 'boom' }
        { Invoke-WACheck -Function 'Test-WABroken' -Name 'x' } | Should -Not -Throw
        $script:WACtx.Errors.Count | Should -Be 1
        $script:WACtx.Errors[0].Message | Should -Be 'boom'
    }

    It 'Get-WARegValueList returns the DATA of policy list values (v1 returned the value names 1,2,...)' {
        Set-SimReg 'HKLM\SOFTWARE\Test\List' @{ '1' = 'TERMSRV/*'; '2' = 'WSMAN/server01' }
        @(Get-WARegValueList -Path 'SOFTWARE\Test\List') | Sort-Object | Should -Be @('TERMSRV/*', 'WSMAN/server01')
    }

    It 'Test-WAWildcardTarget detects "*" and "SERVICE/*"' {
        Test-WAWildcardTarget -Entries @('TERMSRV/*') | Should -BeTrue
        Test-WAWildcardTarget -Entries @('*') | Should -BeTrue
        Test-WAWildcardTarget -Entries @('TERMSRV/rdsh01.corp.contoso.com') | Should -BeFalse
    }

    It 'decodes AV productState <State> as enabled=<Enabled>, upToDate=<UpToDate>' -ForEach @(
        @{ State = 397568; Enabled = $true; UpToDate = $true }      # 0x061100 Defender on, current
        @{ State = 393472; Enabled = $false; UpToDate = $true }     # 0x060100 off
        @{ State = 397584; Enabled = $true; UpToDate = $false }     # 0x061110 out of date
        @{ State = 1052672; Enabled = $true; UpToDate = $true }     # 0x101000 provider >= 0x10 (broke v1 string offsets)
        @{ State = 266240; Enabled = $true; UpToDate = $true }      # 0x041000
    ) {
        $r = ConvertFrom-WAAvProductState -ProductState $State
        $r.Enabled | Should -Be $Enabled
        $r.UpToDate | Should -Be $UpToDate
    }

    It 'parses a binary security descriptor portably' {
        $bytes = New-WATestSecurityDescriptor -AllowSids 'S-1-5-32-544', 'S-1-5-11', 'S-1-5-21-1-2-3-513'
        $r = ConvertFrom-WASecurityDescriptorBytes -Bytes $bytes
        $r.Valid | Should -BeTrue
        @($r.Aces.SID) | Should -Be @('S-1-5-32-544', 'S-1-5-11', 'S-1-5-21-1-2-3-513')
        @($r.Aces.Type | Select-Object -Unique) | Should -Be @('Allow')
    }

    It 'rejects malformed security descriptor bytes' {
        (ConvertFrom-WASecurityDescriptorBytes -Bytes ([byte[]](1, 2, 3))).Valid | Should -BeFalse
        (ConvertFrom-WASecurityDescriptorBytes -Bytes ([byte[]](@(1, 0, 0, 0) + @(0) * 20))).Valid | Should -BeFalse
    }

    It 'parses SDDL DACL entries (aliases resolved to SIDs)' {
        $a = @(ConvertFrom-WASddlAces -Sddl 'O:BAG:BAD:(A;;RC;;;BA)(A;;RC;;;AU)(D;;RC;;;S-1-5-21-9-9-9-500)')
        @($a.SID) | Should -Be @('S-1-5-32-544', 'S-1-5-11', 'S-1-5-21-9-9-9-500')
        @($a.Type) | Should -Be @('Allow', 'Allow', 'Deny')
    }

    It 'masks secret values: <In>' -ForEach @(
        @{ In = 'password=Summer2024!'; Out = 'password=Su********' }
        @{ In = '<add key="ApiKey" value="x"/> apikey: abcdef123'; Out = '<add key="ApiKey" value="x"/> apikey: ab********' }
        @{ In = 'Server=db;User Id=sa;Password=P@ssw0rd;'; Out = 'Server=db;User Id=sa;Password=P@********;' }
    ) {
        Get-WAMaskedSecret -Line $In | Should -BeExactly $Out
    }

    It 'identifies unquoted service path hijack folders: <Path>' -ForEach @(
        @{ Path = 'C:\Program Files\Acme Backup\agent service.exe -k x'; Expect = @('C:\', 'C:\Program Files', 'C:\Program Files\Acme Backup') }
        @{ Path = 'C:\Tools\svc.exe -arg "a b"'; Expect = $null }                       # no space in the executable path (v1 flagged it)
        @{ Path = '"C:\Program Files\App\svc.exe"'; Expect = $null }                     # quoted
        @{ Path = 'C:\Windows\My App\svc.exe'; Expect = @('C:\Windows') }                # inside C:\Windows (v1 ignored it)
        @{ Path = 'C:\WINDOWS\system32\svchost.exe -k netsvcs -p'; Expect = $null }
    ) {
        $r = Get-WAUnquotedCandidate -PathName $Path
        if ($null -eq $Expect) { $r | Should -BeNullOrEmpty } else { @($r.HijackFolders) | Should -Be $Expect }
    }

    It 'produces script-safe JSON (no script-tag break-out)' {
        $j = ConvertTo-WASafeJson -InputObject @{ a = '</script><script>alert(1)</script>&' }
        $j | Should -Not -Match '<'
        ($j | ConvertFrom-Json).a | Should -Be '</script><script>alert(1)</script>&'
    }

    It 'formats sizes (<Kb> KB -> <Text>)' -ForEach @(@{ Kb = 20480; Text = '20 MB' }, @{ Kb = 196608; Text = '192 MB' }, @{ Kb = 512; Text = '512 KB' }) {
        Format-WASize -Kilobytes $Kb | Should -Be $Text
    }
}

Describe 'Checks - regression tests for v1.37 defects and new controls' {
    BeforeEach { Use-WASimulatedHost -Simulation (New-WASimulatedHost); $null = New-TestContext }

    Context 'SMB' {
        It 'SMBv1 is not reported as enabled when the legacy registry value is absent (v1 false positive)' {
            Test-WASmbHardening -Name 'SMB'
            (Get-TestFinding 'domain_SMBv1').Status | Should -Be 'Pass'
        }
        It 'SMBv1 enabled is a failure' {
            $script:WASim.Cmdlets['Get-SmbServerConfiguration'].EnableSMB1Protocol = $true
            Test-WASmbHardening -Name 'SMB'
            (Get-TestFinding 'domain_SMBv1').Status | Should -Be 'Fail'
        }
        It 'SMB1 client check reads mrxsmb10 and survives a missing driver (v1 queried lanmanworkstation and crashed)' {
            { Test-WASmbHardening -Name 'SMB' } | Should -Not -Throw
            (Get-TestFinding 'domain_SMBv1-client').Status | Should -Be 'Pass'
            Set-SimReg 'HKLM\SYSTEM\CurrentControlSet\Services\mrxsmb10' @{ Start = 2 }
            Test-WASmbHardening -Name 'SMB'
            (Get-TestFinding 'domain_SMBv1-client').Status | Should -Be 'Fail'
        }
        It 'server signing uses the effective SMB configuration' {
            $script:WASim.Cmdlets['Get-SmbServerConfiguration'].RequireSecuritySignature = $true
            Test-WASmbHardening -Name 'SMB'
            (Get-TestFinding 'domain_SMBv2-srvSign').Status | Should -Be 'Pass'
        }
        It 'falls back to the registry when the SMB cmdlets are unavailable' {
            $script:WASim.Cmdlets.Remove('Get-SmbServerConfiguration'); $script:WASim.Cmdlets.Remove('Get-SmbClientConfiguration')
            Set-SimReg 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' @{ SMB1 = 0; RequireSecuritySignature = 1 }
            Test-WASmbHardening -Name 'SMB'
            (Get-TestFinding 'domain_SMBv1').Status | Should -Be 'Pass'
            (Get-TestFinding 'domain_SMBv2-srvSign').Status | Should -Be 'Pass'
            (Get-TestFinding 'domain_SMBv2-clientSign').Status | Should -Be 'Fail'
        }
    }

    Context 'RDP' {
        It 'the GPO value of fDenyTSConnections overrides the local value (v1 false "enabled")' {
            Set-SimReg 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' @{ fDenyTSConnections = 1 }
            Test-WARdpSecurity -Name 'RDP'
            (Get-TestFinding 'machine_RDP-reg').Status | Should -Be 'Pass'
        }
        It 'always reports a status for RDP enabled (v1 left Status empty)' {
            Test-WARdpSecurity -Name 'RDP'
            (Get-TestFinding 'machine_RDP-reg').Status | Should -Be 'Warning'
        }
        It 'flags Domain Users in Remote Desktop Users' {
            Test-WARdpSecurity -Name 'RDP'
            $f = Get-TestFinding 'machine_RDP-Users'
            $f.Status | Should -Be 'Fail'
            $f.Evidence | Should -Match 'CORP\\Domain Users, CORP\\Helpdesk'   # v1 concatenated names without a separator
        }
        It 'reports Pass for an empty group (v1 "only admins" branch was unreachable)' {
            $script:WASim.RdpGroup = [pscustomobject]@{ Resolved = $true; Members = @() }
            Test-WARdpSecurity -Name 'RDP'
            (Get-TestFinding 'machine_RDP-Users').Status | Should -Be 'Pass'
        }
        It 'reports Manual when membership cannot be enumerated' {
            $script:WASim.RdpGroup = [pscustomobject]@{ Resolved = $false; Members = @() }
            Test-WARdpSecurity -Name 'RDP'
            (Get-TestFinding 'machine_RDP-Users').Status | Should -Be 'Manual'
        }
        It 'evaluates NLA and TLS from the registry when WMI is not readable (v1 silently skipped them)' {
            Test-WARdpSecurity -Name 'RDP'
            (Get-TestFinding 'machine_RDP-NLA').Status | Should -Be 'Pass'
            (Get-TestFinding 'machine_RDP-TLS').Status | Should -Be 'Warning'
        }
        It 'reports missing session limits as a failure (v1 passed when the policy key was absent)' {
            Test-WARdpSecurity -Name 'RDP'
            (Get-TestFinding 'machine_RDP-Timeout').Status | Should -Be 'Fail'
        }
        It 'passes when disconnected and idle limits are set' {
            Set-SimReg 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' @{ MaxDisconnectionTime = 900000; MaxIdleTime = 900000 }
            Test-WARdpSecurity -Name 'RDP'
            (Get-TestFinding 'machine_RDP-Timeout').Status | Should -Be 'Pass'
        }
    }

    Context 'Credential protection' {
        It 'RunAsPPL=<Value> is LSA protection enabled (v1 treated 2 as off)' -ForEach @(@{ Value = 1 }, @{ Value = 2 }) {
            Set-SimReg 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa' @{ RunAsPPL = $Value }
            Test-WALsaProtection -Name 'LSA'
            (Get-TestFinding 'machine_LSA-ppl').Status | Should -Be 'Pass'
        }
        It 'LSA protection absent is a failure' {
            Test-WALsaProtection -Name 'LSA'
            (Get-TestFinding 'machine_LSA-ppl').Status | Should -Be 'Fail'
        }
        It 'Credential Guard is N/A on domain controllers' {
            $null = New-TestContext -ProductType 2
            Test-WACredentialGuard -Name 'CG'
            (Get-TestFinding 'machine_LSA-CG-wmi').Status | Should -Be 'NotApplicable'
        }
        It 'Credential Guard running is a pass' {
            $script:WASim.Cim['Win32_DeviceGuard'] = [pscustomobject]@{ SecurityServicesConfigured = @(1, 2); SecurityServicesRunning = @(1, 2); VirtualizationBasedSecurityStatus = 2 }
            Test-WACredentialGuard -Name 'CG'
            (Get-TestFinding 'machine_LSA-CG-wmi').Status | Should -Be 'Pass'
        }
        It 'WDigest default on modern Windows reports a Finding text (v1 wrote it to Comments only)' {
            Test-WAWDigest -Name 'WDigest'
            $f = Get-TestFinding 'domain_WDigest'
            $f.Status | Should -Be 'Pass'
            $f.Finding | Should -Not -BeNullOrEmpty
        }
        It 'WDigest UseLogonCredential=1 is a failure' {
            Set-SimReg 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' @{ UseLogonCredential = 1 }
            Test-WAWDigest -Name 'WDigest'
            (Get-TestFinding 'domain_WDigest').Status | Should -Be 'Fail'
        }
        It 'WDigest absent on Windows 7 is a failure' {
            $null = New-TestContext -WinVersion '6.1.7601'
            Test-WAWDigest -Name 'WDigest'
            (Get-TestFinding 'domain_WDigest').Status | Should -Be 'Fail'
        }
    }

    Context 'Enumeration' {
        It 'NetSessionEnum: Authenticated Users on the ACL is a failure' {
            Set-SimReg 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\DefaultSecurity' @{ SrvsvcSessionInfo = (New-WATestSecurityDescriptor -AllowSids 'S-1-5-32-544', 'S-1-5-11') }
            Test-WANetSessionEnum -Name 'NetSession'
            (Get-TestFinding 'domain_NetSessionEnum').Status | Should -Be 'Fail'
        }
        It 'NetSessionEnum: hardened ACL is a pass' {
            Test-WANetSessionEnum -Name 'NetSession'
            (Get-TestFinding 'domain_NetSessionEnum').Status | Should -Be 'Pass'
        }
        It 'NetSessionEnum: unreadable/garbage data is Manual, not a crash (v1 threw)' {
            Set-SimReg 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\DefaultSecurity' @{ SrvsvcSessionInfo = [byte[]](9, 9, 9) }
            { Test-WANetSessionEnum -Name 'NetSession' } | Should -Not -Throw
            (Get-TestFinding 'domain_NetSessionEnum').Status | Should -Be 'Manual'
        }
        It 'SAM: OS default on Windows 10 1607+ passes with a Finding text (v1 wrote Comments only)' {
            Test-WASamEnum -Name 'SAM'
            $f = Get-TestFinding 'domain_SAMEnum'
            $f.Status | Should -Be 'Pass'
            $f.Finding | Should -Not -BeNullOrEmpty
        }
        It 'SAM: <Sddl> -> <Status>' -ForEach @(
            @{ Sddl = 'O:BAG:BAD:(A;;RC;;;BA)'; Status = 'Pass' }
            @{ Sddl = 'O:BAG:BAD:(A;;RC;;;BA)(A;;RC;;;AU)'; Status = 'Warning' }
        ) {
            Set-SimReg 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa' @{ RestrictRemoteSAM = $Sddl }
            Test-WASamEnum -Name 'SAM'
            (Get-TestFinding 'domain_SAMEnum').Status | Should -Be $Status
        }
        It 'SAM: not applicable on domain controllers' {
            $null = New-TestContext -ProductType 2
            Test-WASamEnum -Name 'SAM'
            (Get-TestFinding 'domain_SAMEnum').Status | Should -Be 'NotApplicable'
        }
    }

    Context 'Authentication' {
        It 'LmCompatibilityLevel <Level> on a <Role> -> <Status>' -ForEach @(
            @{ Level = 1; Role = 'workstation'; Type = 1; Status = 'Fail' }
            @{ Level = 3; Role = 'workstation'; Type = 1; Status = 'Pass' }
            @{ Level = 3; Role = 'domain controller'; Type = 2; Status = 'Warning' }
            @{ Level = 5; Role = 'domain controller'; Type = 2; Status = 'Pass' }
            @{ Level = 7; Role = 'workstation'; Type = 1; Status = 'Manual' }    # v1: parameter binding error
        ) {
            $null = New-TestContext -ProductType $Type
            Set-SimReg 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa' @{ LmCompatibilityLevel = $Level }
            { Test-WANtlmLevel -Name 'NTLM' } | Should -Not -Throw
            (Get-TestFinding 'domain_NTLMComLevel').Status | Should -Be $Status
        }
        It 'Kerberos SupportedEncryptionTypes <Value> -> <Status>' -ForEach @(
            @{ Value = 0x18; Status = 'Pass' }
            @{ Value = 0x7FFFFFF8; Status = 'Pass' }
            @{ Value = 0x1C; Status = 'Fail' }
            @{ Value = 0x7FFFFFFF; Status = 'Fail' }
            @{ Value = 0x4; Status = 'Fail' }
            @{ Value = 0; Status = 'Warning' }
        ) {
            Set-SimReg 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters' @{ SupportedEncryptionTypes = $Value }
            Test-WAKerberosEncryption -Name 'Kerberos'
            (Get-TestFinding 'domain_kerbSupEnc').Status | Should -Be $Status
        }
        It 'Kerberos check is N/A on workgroup hosts' {
            $null = New-TestContext -PartOfDomain $false
            Test-WAKerberosEncryption -Name 'Kerberos'
            (Get-TestFinding 'domain_kerbSupEnc').Status | Should -Be 'NotApplicable'
        }
        It 'UAC: LocalAccountTokenFilterPolicy=1 is a failure' {
            Set-SimReg 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' @{ LocalAccountTokenFilterPolicy = 1 }
            Test-WAUac -Name 'UAC'
            (Get-TestFinding 'machine_UAC-RemoteRestrictions').Status | Should -Be 'Fail'
        }
        It 'UAC: EnableLUA=0 is a failure; ConsentPromptBehaviorAdmin=2 is a pass' {
            Set-SimReg 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' @{ EnableLUA = 0; ConsentPromptBehaviorAdmin = 2 }
            Test-WAUac -Name 'UAC'
            (Get-TestFinding 'machine_UAC-EnableLUA').Status | Should -Be 'Fail'
            (Get-TestFinding 'machine_UAC-AdminPrompt').Status | Should -Be 'Pass'
        }
        It 'LAPS: <Case> -> <Status>' -ForEach @(
            @{ Case = 'Windows LAPS to AD'; Status = 'Pass'; Setup = { } }
            @{ Case = 'legacy LAPS only'; Status = 'Warning'; Setup = { Remove-SimKey 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS'; Set-SimReg 'HKLM\SOFTWARE\Policies\Microsoft Services\AdmPwd' @{ AdmPwdEnabled = 1 } } }
            @{ Case = 'nothing configured'; Status = 'Fail'; Setup = { Remove-SimKey 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS' } }
            @{ Case = 'BackupDirectory=0'; Status = 'Fail'; Setup = { Set-SimReg 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS' @{ BackupDirectory = 0 } } }
        ) {
            & $Setup
            Test-WALaps -Name 'LAPS'
            (Get-TestFinding 'machine_LAPS').Status | Should -Be $Status
        }
    }

    Context 'CredSSP' {
        It 'completes without error (v1 crashed on the "-sty" parameter typo)' {
            { Test-WACredSSP -Name 'CredSSP' } | Should -Not -Throw
            @($script:WACtx.Findings | Where-Object { $_.CheckID -like 'domain_CredSSP*' }).Count | Should -Be 8
        }
        It 'reads the server list DATA from the correct subkey (v1 read AllowSavedCredentials value names)' {
            Test-WACredSSP -Name 'CredSSP'
            $f = Get-TestFinding 'domain_CredSSPDefaultCred'
            $f.Status | Should -Be 'Fail'
            $f.Finding | Should -Match 'TERMSRV/\*'
        }
        It 'AllowSavedCredentialsWhenNTLMOnly uses its own value (v1 tested AllowDefCredentialsWhenNTLMOnly)' {
            Set-SimReg 'HKLM\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation' @{ AllowSavedCredentialsWhenNTLMOnly = 0; AllowDefCredentialsWhenNTLMOnly = 1 }
            Test-WACredSSP -Name 'CredSSP'
            (Get-TestFinding 'domain_CredSSPSavedCredNTLM').Status | Should -Be 'Pass'
            (Get-TestFinding 'domain_CredSSPDefaultCredNTLM').Status | Should -Be 'Fail'
        }
        It 'uses distinct CheckIDs for every CredSSP setting (v1 reused domain_CredSSPSavedCred)' {
            Test-WACredSSP -Name 'CredSSP'
            $ids = @($script:WACtx.Findings | Where-Object { $_.CheckID -like 'domain_CredSSP*' } | ForEach-Object CheckID)
            $ids.Count | Should -Be (@($ids | Select-Object -Unique).Count)
        }
        It 'RestrictedRemoteAdministration=1 is a pass (v1 reported the hardened state as a finding)' {
            Set-SimReg 'HKLM\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation' @{ RestrictedRemoteAdministration = 1; RestrictedRemoteAdministrationType = 2 }
            Test-WACredSSP -Name 'CredSSP'
            (Get-TestFinding 'domain_CredSSPResDelOfCredToRemoteSrv').Status | Should -Be 'Pass'
        }
    }

    Context 'Name resolution' {
        It 'LLMNR disabled by policy is a pass, otherwise a failure' {
            Test-WANameResolution -Name 'N'
            (Get-TestFinding 'domain_LLMNR').Status | Should -Be 'Fail'
            Set-SimReg 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' @{ EnableMulticast = 0 }
            Test-WANameResolution -Name 'N'
            (Get-TestFinding 'domain_LLMNR').Status | Should -Be 'Pass'
        }
        It 'NetBIOS disabled on all adapters passes both NetBIOS checks even without P-node' {
            foreach ($a in $script:WASim.Cim['Win32_NetworkAdapterConfiguration']) { $a.TcpipNetbiosOptions = 2 }
            Test-WANameResolution -Name 'N'
            (Get-TestFinding 'domain_NetBIOSoTCP').Status | Should -Be 'Pass'
            (Get-TestFinding 'domain_NetBIOSNT').Status | Should -Be 'Pass'
        }
        It 'mDNS disabled is a pass' {
            Set-SimReg 'HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters' @{ EnableMDNS = 0 }
            Test-WANameResolution -Name 'N'
            (Get-TestFinding 'domain_mDNS').Status | Should -Be 'Pass'
        }
        It 'mitm6: IPv6 bound with DHCPv6 allowed is a warning; disabled DHCPv6 rule is a pass' {
            Test-WAMitm6 -Name 'M'
            (Get-TestFinding 'domain_mitm6').Status | Should -Be 'Warning'
            $script:WASim.Cmdlets['Get-NetFirewallRule'].Enabled = 'False'
            Test-WAMitm6 -Name 'M'
            (Get-TestFinding 'domain_mitm6').Status | Should -Be 'Pass'
        }
    }

    Context 'Endpoint protection' {
        It 'Defender healthy on a workstation passes; tamper protection off fails' {
            Test-WAAntiVirus -Name 'AV'
            (Get-TestFinding 'machine_AVName').Status | Should -Be 'Pass'
            (Get-TestFinding 'machine_DefenderTamper').Status | Should -Be 'Fail'
            (Get-TestFinding 'machine_ASR-LSASS').Status | Should -Be 'Warning'
            (Get-TestFinding 'machine_ASR-Office').Status | Should -Be 'Warning'
        }
        It 'servers are evaluated through Defender (v1 always returned Unknown on servers)' {
            $null = New-TestContext -ProductType 3
            Test-WAAntiVirus -Name 'AV'
            (Get-TestFinding 'machine_AVName').Status | Should -Be 'Pass'
            $script:WASim.Cmdlets['Get-MpComputerStatus'].AntivirusSignatureAge = 9
            Test-WAAntiVirus -Name 'AV'
            (Get-TestFinding 'machine_AVName').Status | Should -Be 'Fail'
        }
        It 'no registered antivirus on a workstation is a failure' {
            $script:WASim.Cim.Remove('AntiVirusProduct')
            Test-WAAntiVirus -Name 'AV'
            (Get-TestFinding 'machine_AVName').Status | Should -Be 'Fail'
        }
        It 'firewall: a disabled profile fails; all enabled passes' {
            Test-WAFirewall -Name 'FW'
            (Get-TestFinding 'machine_FirewallProfiles').Status | Should -Be 'Fail'
            ($script:WASim.Cmdlets['Get-NetFirewallProfile'] | Where-Object Name -eq 'Public').Enabled = 'True'
            Test-WAFirewall -Name 'FW'
            (Get-TestFinding 'machine_FirewallProfiles').Status | Should -Be 'Pass'
        }
    }

    Context 'Scripting, logging and GPO' {
        It 'PSv2: no false positive from Start-Job on PowerShell 7 - feature state is used' {
            $script:WASim.Cmdlets['Get-WindowsOptionalFeature'][0].State = 'Disabled'
            Remove-SimKey 'HKLM\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine'
            Test-WAPowerShellVersion -Name 'PS'
            (Get-TestFinding 'machine_PSv2').Status | Should -Be 'Pass'
        }
        It 'PSv2 engine present without .NET 3.5 is a warning' {
            Remove-SimKey 'HKLM\SOFTWARE\Microsoft\NET Framework Setup\NDP\v3.5'
            Test-WAPowerShellVersion -Name 'PS'
            (Get-TestFinding 'machine_PSv2').Status | Should -Be 'Warning'
        }
        It 'module logging for the current user only is NOT reported as "all modules" (v1 inverted logic)' {
            Set-SimReg 'HKCU\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' @{ EnableModuleLogging = 1 }
            Set-SimReg 'HKCU\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames' @{ 'Microsoft.PowerShell.Utility' = 'Microsoft.PowerShell.Utility' }
            Test-WAPowerShellLogging -Name 'PSLog'
            (Get-TestFinding 'machine_PSModuleLog').Status | Should -Be 'Warning'
        }
        It 'machine-wide module logging for * passes' {
            Set-SimReg 'HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' @{ EnableModuleLogging = 1 }
            Set-SimReg 'HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames' @{ '*' = '*' }
            Test-WAPowerShellLogging -Name 'PSLog'
            (Get-TestFinding 'machine_PSModuleLog').Status | Should -Be 'Pass'
        }
        It 'transcription enabled without output directory is a warning' {
            Set-SimReg 'HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' @{ EnableTranscripting = 1; EnableInvocationHeader = 1 }
            Test-WAPowerShellLogging -Name 'PSLog'
            (Get-TestFinding 'machine_PSTranscript').Status | Should -Be 'Warning'
        }
        It 'command-line auditing verified through the locale-independent subcategory GUID' {
            Test-WACommandLineAudit -Name 'Audit'
            (Get-TestFinding 'machine_ComLineLog').Status | Should -Be 'Pass'
            $script:WASim.Native['auditpol.exe'][1] = $script:WASim.Native['auditpol.exe'][1].Replace(',Success,', ',No Auditing,')
            Test-WACommandLineAudit -Name 'Audit'
            (Get-TestFinding 'machine_ComLineLog').Status | Should -Be 'Fail'
        }
        It 'event log sizes: no crash on the Setup log (v1 [String]::Parse) and correct units' {
            { Test-WAEventLogSize -Name 'Logs' } | Should -Not -Throw
            $f = Get-TestFinding 'machine_SecMaxLog'
            $f.Status | Should -Be 'Fail'
            $f.Evidence | Should -Match '20 MB'
            (Get-TestFinding 'machine_SetupMaxLog').Status | Should -Be 'Fail'
        }
        It 'GPO reprocessing not configured is consistently a failure (v1 passed the registry policy)' {
            Remove-SimKey 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}'
            Test-WAGpoReprocess -Name 'GPO'
            foreach ($id in 'domain_GPOReRegistry', 'domain_GPOReScript', 'domain_GPOReSecurity') { (Get-TestFinding $id).Status | Should -Be 'Fail' -Because $id }
        }
        It 'GPO reprocessing is N/A on workgroup hosts' {
            $null = New-TestContext -PartOfDomain $false
            Test-WAGpoReprocess -Name 'GPO'
            (Get-TestFinding 'domain_GPOReRegistry').Status | Should -Be 'NotApplicable'
        }
        It 'AlwaysInstallElevated: HKLM only -> Warning, HKLM+HKCU -> Fail (v1 ignored HKCU)' {
            Test-WAInstallElevated -Name 'MH'
            (Get-TestFinding 'machine_installWithElevation').Status | Should -Be 'Warning'
            Set-SimReg 'HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer' @{ AlwaysInstallElevated = 1 }
            Test-WAInstallElevated -Name 'MH'
            (Get-TestFinding 'machine_installWithElevation').Status | Should -Be 'Fail'
        }
    }

    Context 'Patching and proxy' {
        It 'NoAutoUpdate=<Value> -> <Status> (v1 inverted the meaning)' -ForEach @(@{ Value = 0; Status = 'Pass' }, @{ Value = 1; Status = 'Fail' }) {
            Set-SimReg 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' @{ NoAutoUpdate = $Value }
            Test-WAWindowsUpdate -Name 'WU'
            (Get-TestFinding 'machine_autoUpdate').Status | Should -Be $Status
        }
        It 'scheduled install produces a valid status (v1 wrote the string "false")' {
            Test-WAWindowsUpdate -Name 'WU'
            (Get-TestFinding 'machine_autoUpdateSchedule').Status | Should -Be 'Pass'
        }
        It 'WSUS <Url> -> transport <T>, address <A>' -ForEach @(
            @{ Url = 'http://10.0.0.5:8530'; T = 'Fail'; A = 'Fail' }
            @{ Url = 'https://wsus.corp.contoso.com:8531'; T = 'Pass'; A = 'Pass' }
            @{ Url = 'http://wsus01:8530'; T = 'Fail'; A = 'Pass' }
            @{ Url = 'wsus01.corp.contoso.com'; T = 'Fail'; A = 'Pass' }
        ) {
            Set-SimReg 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' @{ WUServer = $Url }
            Test-WAWindowsUpdate -Name 'WU'
            (Get-TestFinding 'machine_wsusUpdate').Status | Should -Be $T
            (Get-TestFinding 'machine_wsusUpdateAddress').Status | Should -Be $A
        }
        It 'patch recency: 44 days -> Warning; no dates -> Manual' {
            Test-WAWindowsUpdate -Name 'WU'
            (Get-TestFinding 'machine_lastPatch').Status | Should -Be 'Warning'
            foreach ($h in $script:WASim.Cmdlets['Get-HotFix']) { $h.InstalledOn = $null }
            $script:WACtx.Cache.Remove('HotFix')
            Test-WAWindowsUpdate -Name 'WU'
            (Get-TestFinding 'machine_lastPatch').Status | Should -Be 'Manual'
        }
        It 'WPAD service disabled is recognised (v1 compared StartType to "Disable")' {
            ($script:WASim.Cim['Win32_Service'] | Where-Object Name -eq 'WinHttpAutoProxySvc').StartMode = 'Disabled'
            Test-WAProxyConfiguration -Name 'Proxy'
            (Get-TestFinding 'machine_WPADSvc').Status | Should -Be 'Pass'
        }
        It 'DisableWpad=1 passes' {
            Set-SimReg 'HKLM\SYSTEM\CurrentControlSet\Services\WinHttp' @{ DisableWpad = 1 }
            Test-WAProxyConfiguration -Name 'Proxy'
            (Get-TestFinding 'machine_WPADSvc').Status | Should -Be 'Pass'
        }
        It 'internet tests honour -SkipNetworkTests' {
            $null = New-TestContext -SkipNetworkTests
            Test-WAInternetAccess -Name 'Net'
            (Get-TestFinding 'machine_na-dns').Status | Should -Be 'Manual'
        }
        It 'non-standard egress port open is a failure' {
            $script:WASim.OpenPorts = @(666)
            Test-WAInternetAccess -Name 'Net'
            (Get-TestFinding 'machine_na-browsing').Status | Should -Be 'Fail'
        }
    }

    Context 'Services and Office' {
        It 'unquoted path with a writable hijack folder is Critical' {
            Test-WAUnquotedServicePath -Name 'Services'
            $f = Get-TestFinding 'vul_quotedPath'
            $f.Status | Should -Be 'Fail'
            $f.Severity | Should -Be 'Critical'
        }
        It 'no unquoted paths -> Pass' {
            $script:WASim.Cim['Win32_Service'] = @($script:WASim.Cim['Win32_Service'] | Where-Object Name -ne 'AcmeBackupAgent')
            Test-WAUnquotedServicePath -Name 'Services'
            (Get-TestFinding 'vul_quotedPath').Status | Should -Be 'Pass'
        }
        It 'detects Click-to-Run Office without Win32_Product (v1 found no Microsoft 365 Apps)' {
            @(Get-WAOfficeVersions).Count | Should -Be 1
            Test-WAOfficeHardening -Name 'Office'
            (Get-TestFinding 'machine_officeVBAWarnings' 'Office 16.0') | Should -Not -BeNullOrEmpty
        }
        It 'Excel WorkbookLinkWarnings=2 is a pass (v1 reported it as a finding)' {
            Set-SimReg 'HKCU\SOFTWARE\Policies\Microsoft\Office\16.0\Excel\Security' @{ WorkbookLinkWarnings = 2 }
            Test-WAOfficeHardening -Name 'Office'
            (Get-TestFinding 'machine_excelDDE' 'Office 16.0').Status | Should -Be 'Pass'
        }
        It 'Word DontUpdateLinks=1 is a pass (v1 inverted); AllowDDE=2 is a failure' {
            Set-SimReg 'HKCU\SOFTWARE\Microsoft\Office\16.0\Word\Options' @{ DontUpdateLinks = 1 }
            Test-WAOfficeHardening -Name 'Office'
            (Get-TestFinding 'machine_wordDDE' 'Office 16.0').Status | Should -Be 'Pass'
            Set-SimReg 'HKCU\SOFTWARE\Microsoft\Office\16.0\Word\Security' @{ AllowDDE = 2 }
            Test-WAOfficeHardening -Name 'Office'
            (Get-TestFinding 'machine_wordDDE' 'Office 16.0').Status | Should -Be 'Fail'
        }
        It 'VBAWarnings=1 (enable all macros) is a Critical failure' {
            Set-SimReg 'HKCU\SOFTWARE\Policies\Microsoft\Office\16.0\Excel\Security' @{ VBAWarnings = 1 }
            Test-WAOfficeHardening -Name 'Office'
            $f = Get-TestFinding 'machine_officeVBAWarnings' 'Office 16.0'
            $f.Status | Should -Be 'Fail'
            $f.Severity | Should -Be 'Critical'
        }
        It 'internet macros explicitly allowed (0) fails even on Microsoft 365 Apps' {
            Set-SimReg 'HKCU\SOFTWARE\Policies\Microsoft\Office\16.0\Word\Security' @{ blockcontentexecutionfrominternet = 0 }
            Test-WAOfficeHardening -Name 'Office'
            (Get-TestFinding 'machine_officeInternetMacros' 'Office 16.0').Status | Should -Be 'Fail'
        }
        It 'no Office installed -> all Office checks N/A' {
            Remove-SimKey 'HKLM\SOFTWARE\Microsoft\Office\ClickToRun\Configuration'
            Test-WAOfficeHardening -Name 'Office'
            (Get-TestFinding 'machine_excelDDE').Status | Should -Be 'NotApplicable'
        }
    }

    Context 'Sensitive data search' {
        BeforeEach {
            $script:SearchDir = Join-Path $TestDrive ('search' + [guid]::NewGuid().ToString('N'))
            New-Item -ItemType Directory -Path $script:SearchDir | Out-Null
            Set-Content -LiteralPath (Join-Path $script:SearchDir 'app.config') -Value '<add name="db" connectionString="Server=sql01;User Id=svc;Password=Winter2025!;" />'
            Set-Content -LiteralPath (Join-Path $script:SearchDir 'backup.pfx') -Value 'binary'
        }
        It 'finds secrets, masks them by default and never copies key files' {
            $null = New-TestContext -EnableSensitiveInfoSearch -SensitiveSearchPath $script:SearchDir
            Test-WASensitiveInfo -Name 'Sensitive-Info'
            (Get-TestFinding 'machine_SensitiveFiles').Status | Should -Be 'Fail'
            $txt = Get-Content -LiteralPath (Join-Path $script:WACtx.DetailPath 'Sensitive-Info_TEST01.txt') -Raw
            $txt | Should -Not -Match 'Winter2025!'
            $txt | Should -Match 'Password=Wi\*{8}'
            $txt | Should -Match 'backup\.pfx'
            $txt | Should -Not -Match 'binary'
        }
        It 'writes unmasked values only with -IncludeSecretValues' {
            $ctx = New-TestContext -EnableSensitiveInfoSearch -SensitiveSearchPath $script:SearchDir
            $ctx.IncludeSecretValues = $true
            Test-WASensitiveInfo -Name 'Sensitive-Info'
            Get-Content -LiteralPath (Join-Path $script:WACtx.DetailPath 'Sensitive-Info_TEST01.txt') -Raw | Should -Match 'Winter2025!'
        }
        It 'does nothing unless -EnableSensitiveInfoSearch is set' {
            Test-WASensitiveInfo -Name 'Sensitive-Info'
            Get-TestFinding 'machine_SensitiveFiles' | Should -BeNullOrEmpty
        }
    }
}

Describe 'Scoring and narrative' {
    BeforeEach { Use-WASimulatedHost -Simulation (New-WASimulatedHost); $null = New-TestContext }

    It 'weights results by severity (Pass=1, Warning=0.5, Fail=0)' {
        $f = @(
            [pscustomobject]@{ Status = 'Pass'; Severity = 'High' }
            [pscustomobject]@{ Status = 'Fail'; Severity = 'High' }
            [pscustomobject]@{ Status = 'Warning'; Severity = 'Medium' }
            [pscustomobject]@{ Status = 'Manual'; Severity = 'Critical' }
            [pscustomobject]@{ Status = 'Info'; Severity = 'Informational' }
        )
        $s = Get-WAScore -Findings $f
        $s.Score | Should -Be 50     # (7 + 2) / (7 + 7 + 4)
        $s.Grade | Should -Be 'F'
        $s.Counts['Manual'] | Should -Be 1
        $s.FailBySeverity['High'] | Should -Be 1
    }

    It 'returns 0 when nothing could be evaluated' {
        (Get-WAScore -Findings @([pscustomobject]@{ Status = 'Manual'; Severity = 'High' })).Score | Should -Be 0
    }

    It 'chains poisoning + missing SMB signing into an attack path' {
        Add-WAFinding -CheckID 'domain_LLMNR' -Status Fail
        Add-WAFinding -CheckID 'domain_SMBv2-srvSign' -Status Fail
        $p = @(Get-WAAttackPaths -Findings @($script:WACtx.Findings))
        $p.Count | Should -Be 1
        $p[0].Title | Should -Match 'relay'
        $p[0].Narrative | Should -Match 'relayed'
        $p[0].Severity | Should -Be 'High'
    }

    It 'produces no attack path when everything passes' {
        Add-WAFinding -CheckID 'domain_LLMNR' -Status Pass
        @(Get-WAAttackPaths -Findings @($script:WACtx.Findings)).Count | Should -Be 0
    }

    It 'generates an executive summary naming the score and the most exposed tactic' {
        Add-WAFinding -CheckID 'domain_WDigest' -Status Fail
        Add-WAFinding -CheckID 'machine_LSA-ppl' -Status Fail
        Add-WAFinding -CheckID 'domain_LLMNR' -Status Pass
        $f = @($script:WACtx.Findings)
        $s = Get-WAScore -Findings $f
        $sum = New-WAExecutiveSummary -Findings $f -Score $s -AttackPaths @(Get-WAAttackPaths -Findings $f)
        $sum[0] | Should -Match ('scored {0}/100' -f $s.Score)
        ($sum -join ' ') | Should -Match 'Credential Access'
        ($sum -join ' ') | Should -Match 'Credential theft from LSASS'
    }
}

Describe 'HTML report' {
    BeforeAll {
        Use-WASimulatedHost -Simulation (New-WASimulatedHost)
        $null = New-TestContext
        foreach ($step in (Get-WAPlan)) { Invoke-WACheck -Function $step[0] -Name $step[1] }
        Add-WAManualControls
        Add-WAFinding -CheckID 'machine_proxySet' -Status Info -Evidence '</script><script>alert("xss")</script><img src=x onerror=alert(1)>'
        $script:ReportPath = Export-WAResults
        $script:Html = Get-Content -LiteralPath $script:ReportPath -Raw
        $m = [regex]::Match($script:Html, '<script id="wa-data" type="application/json">(.*?)</script>', 'Singleline')
        $script:Data = $m.Groups[1].Value | ConvertFrom-Json
    }

    It 'is written' { Test-Path -LiteralPath $script:ReportPath | Should -BeTrue }
    It 'is self-contained (no external scripts, styles, fonts or images)' {
        $script:Html | Should -Not -Match '<script[^>]+src='
        $script:Html | Should -Not -Match '<link[^>]+href='
        $script:Html | Should -Not -Match '@import'
        $script:Html | Should -Not -Match 'url\(\s*["'']?https?:'
    }
    It 'ships a restrictive Content-Security-Policy' { $script:Html | Should -Match "default-src 'none'" }
    It 'escapes host data so it cannot break out of the data block' {
        ([regex]::Matches($script:Html, '</script>')).Count | Should -Be 2
        ($script:Data.findings | Where-Object id -eq 'machine_proxySet').evidence | Should -Match '<img src=x'
    }
    It 'embeds every finding' { @($script:Data.findings).Count | Should -Be $script:WACtx.Findings.Count }
    It 'embeds the score computed by Get-WAScore' { $script:Data.meta.score | Should -Be (Get-WAScore -Findings @($script:WACtx.Findings)).Score }
    It 'embeds ATT&CK metadata for every referenced technique' {
        $ids = @($script:Data.findings | ForEach-Object { $_.techniques } | Select-Object -Unique)
        foreach ($t in $ids) { $script:Data.techniques.$t.name | Should -Not -BeNullOrEmpty -Because $t }
        $script:Data.meta.attackVersion | Should -Be $script:WAAttackVersion
    }
    It 'includes the generated narrative and attack paths' {
        @($script:Data.summary).Count | Should -BeGreaterThan 2
        @($script:Data.attackPaths).Count | Should -BeGreaterThan 3
    }
    It 'carries the MITRE ATT&CK attribution' { $script:Html | Should -Match 'The MITRE Corporation' }
}

Describe 'End-to-end (simulated host)' {
    BeforeAll {
        Use-WASimulatedHost -Simulation (New-WASimulatedHost)
        $script:SearchDir = Join-Path $TestDrive 'e2e-search'
        New-Item -ItemType Directory -Path $script:SearchDir | Out-Null
        Invoke-WindowsAssessment -OutputPath $TestDrive -NoZip -KeepFolder -Quiet -EnableSensitiveInfoSearch -SensitiveSearchPath $script:SearchDir
        $script:Run = $script:WACtx
    }

    It 'completes without execution errors' { @($script:Run.Errors) | Should -BeNullOrEmpty }
    It 'emits every catalog check at least once' {
        $emitted = @($script:Run.Findings | ForEach-Object CheckID | Select-Object -Unique)
        $expectedMissing = @('control_ClearPass')     # automated by -EnableSensitiveInfoSearch (machine_SensitiveFiles)
        @($script:WACheckCatalog.Keys | Where-Object { $emitted -notcontains $_ -and $expectedMissing -notcontains $_ }) | Should -BeNullOrEmpty
    }
    It 'writes the CSV with the v1 columns plus ATT&CK columns' {
        $csv = Import-Csv -LiteralPath (Join-Path $script:Run.RootPath (Get-WAFileName -Name 'Hardening_Checks' -Extension '.csv'))
        $cols = $csv[0].PSObject.Properties.Name
        foreach ($c in 'Category', 'CheckName', 'Status', 'Risk', 'Finding', 'Comments', 'Related file', 'CheckID', 'ATTACK_Techniques', 'ATTACK_Tactics', 'ATTACK_Mitigations') { $cols | Should -Contain $c }
        ($csv | Where-Object CheckID -eq 'domain_LLMNR').ATTACK_Techniques | Should -Be 'T1557.001'
    }
    It 'writes valid JSON' {
        $j = Get-Content -LiteralPath (Join-Path $script:Run.RootPath (Get-WAFileName -Name 'Hardening_Checks' -Extension '.json')) -Raw | ConvertFrom-Json
        @($j.findings).Count | Should -Be $script:Run.Findings.Count
    }
    It 'places a copy of the HTML report next to the output folder' {
        Test-Path -LiteralPath ($script:Run.RootPath + '_Report.html') | Should -BeTrue
    }
    It 'creates a ZIP and removes the folder unless -KeepFolder' {
        $zipOut = Join-Path $TestDrive 'zip'
        New-Item -ItemType Directory -Path $zipOut | Out-Null
        Invoke-WindowsAssessment -OutputPath $zipOut -Quiet -SkipNetworkTests
        Test-Path -LiteralPath ($script:WACtx.RootPath + '.zip') | Should -BeTrue
        Test-Path -LiteralPath $script:WACtx.RootPath | Should -BeFalse
    }
}

Describe 'Integration (live Windows host)' -Tag 'Integration' {
    It 'runs the real assessment end-to-end on this Windows host' -Skip:(-not ($PSVersionTable.PSEdition -eq 'Desktop' -or $IsWindows)) {
        $exe = (Get-Process -Id $PID).Path
        $out = Join-Path $TestDrive 'live'
        New-Item -ItemType Directory -Path $out | Out-Null
        & $exe -NoProfile -ExecutionPolicy Bypass -File $script:ScriptPath -OutputPath $out -NoZip -KeepFolder -Quiet -SkipNetworkTests -SkipGpoCollection
        $folder = Get-ChildItem -LiteralPath $out -Directory | Select-Object -First 1
        $folder | Should -Not -BeNullOrEmpty
        $json = Get-ChildItem -LiteralPath $folder.FullName -Filter 'Hardening_Checks_*.json' | Get-Content -Raw | ConvertFrom-Json
        @($json.findings).Count | Should -BeGreaterThan 60
        @($json.errors) | Should -BeNullOrEmpty
        Get-ChildItem -LiteralPath $out -Filter '*_Report.html' | Should -Not -BeNullOrEmpty
    }
}

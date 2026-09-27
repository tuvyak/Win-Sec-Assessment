<#
    Simulated Windows host for tests and demos. Dot-source AFTER WindowsAssessment.ps1 in the same scope:
        . .\WindowsAssessment.ps1 ; . .\tests\SimulatedHost.ps1 ; Use-WASimulatedHost (New-WASimulatedHost)
    It replaces the data-provider functions (registry, CIM, cmdlets, native tools) with in-memory fakes so the
    complete assessment can run on any OS - including Linux CI - without touching a real system.
    The default profile models a typical, partially hardened Windows 11 23H2 domain workstation.
#>

function ConvertTo-WATestSidBytes {
    # 'S-1-5-32-544' -> binary SID (portable; used to fabricate security descriptors for tests)
    param ([string]$Sid)
    $parts = $Sid.Split('-')
    $subs = @($parts[3..($parts.Count - 1)])
    $b = New-Object System.Collections.ArrayList
    [void]$b.Add([byte][int]$parts[1]); [void]$b.Add([byte]$subs.Count)
    $auth = [uint64]$parts[2]
    for ($i = 5; $i -ge 0; $i--) { [void]$b.Add([byte](($auth -shr (8 * $i)) -band 0xFF)) }
    foreach ($s in $subs) { $b.AddRange([BitConverter]::GetBytes([uint32]$s)) }
    return [byte[]]$b.ToArray()
}

function New-WATestSecurityDescriptor {
    # Self-relative security descriptor with a DACL of ACCESS_ALLOWED ACEs for the given SIDs.
    param ([string[]]$AllowSids, [uint32]$Mask = 1)
    $aces = New-Object System.Collections.ArrayList
    foreach ($s in $AllowSids) {
        $sid = ConvertTo-WATestSidBytes -Sid $s
        $size = 8 + $sid.Length
        [void]$aces.Add([byte]0); [void]$aces.Add([byte]0); $aces.AddRange([BitConverter]::GetBytes([uint16]$size)); $aces.AddRange([BitConverter]::GetBytes($Mask)); $aces.AddRange($sid)
    }
    $acl = New-Object System.Collections.ArrayList
    [void]$acl.Add([byte]2); [void]$acl.Add([byte]0); $acl.AddRange([BitConverter]::GetBytes([uint16](8 + $aces.Count))); $acl.AddRange([BitConverter]::GetBytes([uint16]$AllowSids.Count)); $acl.AddRange([BitConverter]::GetBytes([uint16]0)); $acl.AddRange($aces.ToArray())
    $sd = New-Object System.Collections.ArrayList
    [void]$sd.Add([byte]1); [void]$sd.Add([byte]0); $sd.AddRange([BitConverter]::GetBytes([uint16]0x8004))
    $sd.AddRange([BitConverter]::GetBytes([uint32]0)); $sd.AddRange([BitConverter]::GetBytes([uint32]0)); $sd.AddRange([BitConverter]::GetBytes([uint32]0)); $sd.AddRange([BitConverter]::GetBytes([uint32]20))
    $sd.AddRange($acl.ToArray())
    return [byte[]]$sd.ToArray()
}

function New-WASimulatedHost {
    [CmdletBinding()]
    param ()
    $reg = @{}   # 'HKLM\Path' -> hashtable(valueName -> data); PowerShell hashtables are case-insensitive
    $set = { param($k, $v) if (-not $reg.ContainsKey($k)) { $reg[$k] = @{} }; foreach ($n in $v.Keys) { $reg[$k][$n] = $v[$n] } }

    & $set 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa' @{ LmCompatibilityLevel = 3 }
    & $set 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion' @{ ProductName = 'Windows 10 Enterprise'; DisplayVersion = '23H2'; CurrentBuild = '22631'; UBR = 4037 }
    & $set 'HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server' @{ fDenyTSConnections = 0 }
    & $set 'HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' @{ UserAuthentication = 1; SecurityLayer = 1; PortNumber = 3389 }
    & $set 'HKLM\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine' @{ PowerShellVersion = '2.0' }
    & $set 'HKLM\SOFTWARE\Microsoft\NET Framework Setup\NDP\v3.5' @{ Install = 1 }
    & $set 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}' @{ NoGPOListChanges = 0 }
    & $set 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer' @{ AlwaysInstallElevated = 1 }
    & $set 'HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' @{ EnableScriptBlockLogging = 1 }
    & $set 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' @{ ProcessCreationIncludeCmdLine_Enabled = 1 }
    & $set 'HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security' @{ MaxSize = 20480 }
    & $set 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings' @{ ProxyEnable = 0; AutoConfigURL = 'http://pac.corp.contoso.com/proxy.pac' }
    & $set 'HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Control Panel' @{ Proxy = 1 }
    & $set 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' @{ NoAutoUpdate = 0; AUOptions = 4; ScheduledInstallDay = 0; ScheduledInstallTime = 3; UseWUServer = 1 }
    & $set 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' @{ WUServer = 'http://wsus01.corp.contoso.com:8530' }
    & $set 'HKLM\SOFTWARE\Microsoft\Office\ClickToRun\Configuration' @{ VersionToReport = '16.0.17928.20156' }
    & $set 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters' @{ SupportedEncryptionTypes = 28 }
    & $set 'HKLM\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation' @{ AllowDefaultCredentials = 1; ConcatenateDefaults_AllowDefault = 1 }
    & $set 'HKLM\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\AllowDefaultCredentials' @{ '1' = 'TERMSRV/*' }
    & $set 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' @{ EnableLUA = 1; ConsentPromptBehaviorAdmin = 5; PromptOnSecureDesktop = 1 }
    & $set 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS' @{ BackupDirectory = 2; ADPasswordEncryptionEnabled = 1; PasswordLength = 20 }
    & $set 'HKLM\SYSTEM\CurrentControlSet\Services\WinHttp' @{ }
    & $set 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation' @{ DependOnService = @('Bowser', 'MRxSmb20', 'NSI') }

    # SrvsvcSessionInfo - hardened default ACL (no Authenticated Users)
    & $set 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\DefaultSecurity' @{ SrvsvcSessionInfo = (New-WATestSecurityDescriptor -AllowSids 'S-1-5-32-544', 'S-1-5-32-549', 'S-1-5-4', 'S-1-5-18') }

    $now = Get-Date
    return @{
        Registry = $reg
        Cim      = @{
            'Win32_OperatingSystem'              = [pscustomobject]@{ ProductType = 1; Caption = 'Microsoft Windows 11 Enterprise'; Version = '10.0.22631'; LastBootUpTime = $now.AddDays(-3) }
            'Win32_ComputerSystem'               = [pscustomobject]@{ PartOfDomain = $true; Domain = 'corp.contoso.com' }
            'Win32_DeviceGuard'                  = [pscustomobject]@{ SecurityServicesConfigured = @(0); SecurityServicesRunning = @(0); VirtualizationBasedSecurityStatus = 0 }
            'AntiVirusProduct'                   = @([pscustomobject]@{ displayName = 'Microsoft Defender Antivirus'; productState = 397568; pathToSignedProductExe = 'windowsdefender://'; timestamp = $now.ToString('r') })
            'Win32_NetworkAdapterConfiguration'  = @([pscustomobject]@{ Description = 'Intel(R) Ethernet Connection I219-LM'; TcpipNetbiosOptions = 0 }, [pscustomobject]@{ Description = 'Intel(R) Wi-Fi 6E AX211'; TcpipNetbiosOptions = 0 })
            'Win32_Service'                      = @(
                [pscustomobject]@{ Name = 'AcmeBackupAgent'; DisplayName = 'Acme Backup Agent'; State = 'Running'; StartMode = 'Auto'; StartName = 'LocalSystem'; PathName = 'C:\Program Files\Acme Backup\agent service.exe -k backup' },
                [pscustomobject]@{ Name = 'WinDefend'; DisplayName = 'Microsoft Defender Antivirus Service'; State = 'Running'; StartMode = 'Auto'; StartName = 'LocalSystem'; PathName = '"C:\ProgramData\Microsoft\Windows Defender\platform\4.18.24090.11-0\MsMpEng.exe"' },
                [pscustomobject]@{ Name = 'WinHttpAutoProxySvc'; DisplayName = 'WinHTTP Web Proxy Auto-Discovery Service'; State = 'Running'; StartMode = 'Manual'; StartName = 'LocalService'; PathName = 'C:\WINDOWS\system32\svchost.exe -k LocalServiceNetworkRestricted -p' }
            )
            'Win32_Share'                        = @([pscustomobject]@{ Name = 'ADMIN$'; Path = 'C:\WINDOWS'; Description = 'Remote Admin'; Type = 2147483648 }, [pscustomobject]@{ Name = 'C$'; Path = 'C:\'; Description = 'Default share'; Type = 2147483648 })
        }
        Cmdlets  = @{
            'Get-SmbServerConfiguration' = [pscustomobject]@{ EnableSMB1Protocol = $false; EnableSMB2Protocol = $true; RequireSecuritySignature = $false; EnableSecuritySignature = $true; AuditSmb1Access = $false }
            'Get-SmbClientConfiguration' = [pscustomobject]@{ RequireSecuritySignature = $false; EnableSecuritySignature = $true }
            'Get-MpComputerStatus'       = [pscustomobject]@{ AMServiceEnabled = $true; AntivirusEnabled = $true; AMRunningMode = 'Normal'; AntivirusSignatureAge = 0; RealTimeProtectionEnabled = $true; BehaviorMonitorEnabled = $true; IoavProtectionEnabled = $true; IsTamperProtected = $false }
            'Get-MpPreference'           = [pscustomobject]@{ AttackSurfaceReductionRules_Ids = @('9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2', 'd4f940ab-401b-4efc-aadc-ad5f3c50688a', '3b576869-a4ec-4529-8536-b80a7769e899'); AttackSurfaceReductionRules_Actions = @(2, 1, 1) }
            'Get-NetFirewallProfile'     = @(
                [pscustomobject]@{ Name = 'Domain'; Enabled = 'True'; DefaultInboundAction = 'Block'; DefaultOutboundAction = 'Allow'; AllowLocalFirewallRules = 'True'; LogBlocked = 'False' },
                [pscustomobject]@{ Name = 'Private'; Enabled = 'True'; DefaultInboundAction = 'Block'; DefaultOutboundAction = 'Allow'; AllowLocalFirewallRules = 'True'; LogBlocked = 'False' },
                [pscustomobject]@{ Name = 'Public'; Enabled = 'False'; DefaultInboundAction = 'Block'; DefaultOutboundAction = 'Allow'; AllowLocalFirewallRules = 'True'; LogBlocked = 'False' })
            'Get-NetAdapterBinding'      = @([pscustomobject]@{ Name = 'Ethernet'; ComponentID = 'ms_tcpip6'; Enabled = $true })
            'Get-NetFirewallRule'        = [pscustomobject]@{ Name = 'CoreNet-DHCPV6-In'; Enabled = 'True'; Action = 'Allow' }
            'Get-HotFix'                 = @(
                [pscustomobject]@{ HotFixID = 'KB5041585'; Description = 'Security Update'; InstalledOn = $now.AddDays(-44); InstalledBy = 'NT AUTHORITY\SYSTEM'; Caption = '' },
                [pscustomobject]@{ HotFixID = 'KB5040442'; Description = 'Security Update'; InstalledOn = $now.AddDays(-75); InstalledBy = 'NT AUTHORITY\SYSTEM'; Caption = '' })
            'Resolve-DnsName'            = [pscustomobject]@{ Name = 'www.microsoft.com'; Type = 'CNAME'; NameHost = 'www.microsoft.com-c-3.edgekey.net' }
            'Get-WinEvent:ListLog'       = @{ Application = 20971520; System = 20971520; Setup = 1052672 }
            'Get-WindowsOptionalFeature' = @([pscustomobject]@{ FeatureName = 'MicrosoftWindowsPowerShellV2Root'; State = 'Enabled' }, [pscustomobject]@{ FeatureName = 'SMB1Protocol'; State = 'Disabled' })
        }
        Native   = @{
            'auditpol.exe' = @('Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting', 'FIN-WS-0142,System,Process Creation,{0CCE922B-69AE-11D9-BED3-505054503030},Success,')
            'whoami.exe'   = @('USER INFORMATION', '----------------', 'User Name           SID', 'corp\adm-assessor   S-1-5-21-1004336348-1177238915-682003330-5120')
            'ipconfig.exe' = @('Windows IP Configuration', '', '   Host Name . . . . . . . . . . . . : FIN-WS-0142', '   Primary Dns Suffix  . . . . . . . : corp.contoso.com')
        }
        Services = @{ 'mpssvc' = [pscustomobject]@{ Name = 'mpssvc'; Status = 'Running' } }
        RdpGroup = [pscustomobject]@{ Resolved = $true; Members = @([pscustomobject]@{ Name = 'CORP\Domain Users'; SID = 'S-1-5-21-1004336348-1177238915-682003330-513' }, [pscustomobject]@{ Name = 'CORP\Helpdesk'; SID = 'S-1-5-21-1004336348-1177238915-682003330-4411' }) }
        OpenPorts = @(80, 443)
        WritableFolders = @('C:\Program Files\Acme Backup')
    }
}

function Use-WASimulatedHost {
    # Installs the fakes. Must run in the same scope into which WindowsAssessment.ps1 was dot-sourced.
    [CmdletBinding()]
    param ([Parameter(Mandatory = $true)][hashtable]$Simulation)
    $script:WASim = $Simulation
}

function Get-WARegValue {
    [CmdletBinding()]
    param ([string]$Hive = 'HKLM', [string]$Path, [string]$Name)
    $k = '{0}\{1}' -f $Hive, $Path.Trim().Trim('\')
    $key = $script:WASim.Registry[$k]
    if ($null -eq $key -or -not $key.ContainsKey($Name)) { return $null }
    return $key[$Name]
}
function Get-WARegKeyValues {
    [CmdletBinding()]
    param ([string]$Hive = 'HKLM', [string]$Path)
    $k = '{0}\{1}' -f $Hive, $Path.Trim().Trim('\')
    $key = $script:WASim.Registry[$k]
    if ($null -eq $key) { return $null }
    $o = [ordered]@{}; foreach ($n in $key.Keys) { $o[$n] = $key[$n] }
    return $o
}
function Get-WARegSubKeyNames {
    [CmdletBinding()]
    param ([string]$Hive = 'HKLM', [string]$Path)
    $prefix = ('{0}\{1}\' -f $Hive, $Path.Trim().Trim('\'))
    return @($script:WASim.Registry.Keys | Where-Object { $_.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase) } | ForEach-Object { ($_.Substring($prefix.Length) -split '\\')[0] } | Select-Object -Unique)
}
function Get-WACimInstance {
    [CmdletBinding()]
    param ([string]$ClassName, [string]$Namespace = 'root\cimv2', [string]$Filter)
    $v = $script:WASim.Cim[$ClassName]
    if ($Filter -and $ClassName -eq 'Win32_Service' -and $Filter -match "Name='([^']+)'") { $n = $Matches[1]; return @($v | Where-Object { $_.Name -eq $n }) | Select-Object -First 1 }
    return $v
}
function Invoke-WACmdlet {
    [CmdletBinding()]
    param ([string]$Name, [hashtable]$Parameters = @{})
    if ($Name -eq 'Get-WinEvent' -and $Parameters.ContainsKey('ListLog')) {
        $bytes = $script:WASim.Cmdlets['Get-WinEvent:ListLog'][$Parameters['ListLog']]
        if ($null -eq $bytes) { return $null }
        return [pscustomobject]@{ LogName = $Parameters['ListLog']; MaximumSizeInBytes = $bytes }
    }
    if ($Name -eq 'Get-WindowsOptionalFeature' -and $Parameters.ContainsKey('FeatureName')) {
        return @($script:WASim.Cmdlets['Get-WindowsOptionalFeature'] | Where-Object { $_.FeatureName -eq $Parameters['FeatureName'] })
    }
    return $script:WASim.Cmdlets[$Name]
}
function Invoke-WANative {
    [CmdletBinding()]
    param ([string]$FilePath, [string[]]$ArgumentList = @())
    $v = $script:WASim.Native[$FilePath]
    if ($null -eq $v) { return @() }
    return @($v)
}
function Get-WAService {
    [CmdletBinding()]
    param ([string]$Name)
    return $script:WASim.Services[$Name]
}
function Get-WALocalGroupMembers {
    [CmdletBinding()]
    param ([string]$Sid)
    return $script:WASim.RdpGroup
}
function Test-WATcpPort {
    [CmdletBinding()]
    param ([string]$ComputerName, [int]$Port, [int]$TimeoutMs = 2500)
    return ($script:WASim.OpenPorts -contains $Port)
}
function Test-WABroadWriteAccess {
    [CmdletBinding()]
    param ([string]$Path)
    return ($script:WASim.WritableFolders -contains $Path)
}
function Get-WAFirewallBlockedPorts {
    [CmdletBinding()]
    param ([string]$Direction = 'Inbound', [string]$Protocol = 'UDP')
    return @()
}
function Get-WAFirewallRuleExport { [CmdletBinding()] param () return $null }

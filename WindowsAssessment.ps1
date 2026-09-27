<#
.SYNOPSIS
    Windows host security assessment with MITRE ATT&CK mapping and an interactive HTML report.

.DESCRIPTION
    Collects configuration evidence from a Windows host, evaluates ~75 hardening controls,
    maps every control to MITRE ATT&CK (Enterprise) techniques and mitigations, and produces:
      - Hardening_Checks_<host>.csv / .json   (machine-readable results)
      - WindowsAssessment_Report_<host>.html  (self-contained interactive report, works offline)
      - "Detailed information" evidence files (text/CSV/GPResult/secedit exports)
    All output is written to a timestamped folder and zipped at the end.

    The script is read-only: it does not change system configuration.
    Run from an elevated PowerShell prompt for complete results.

    Supported: Windows PowerShell 5.1 (recommended) and PowerShell 7.x on Windows.
    Degraded but functional: Windows PowerShell 3.0/4.0.

.PARAMETER EnableSensitiveInfoSearch
    Search common locations (C:\Temp, Desktop, IIS root) for clear-text credentials and key material.
    Secret values are masked in the output unless -IncludeSecretValues is also specified.

.PARAMETER IncludeSecretValues
    Write matched secret values to the evidence file unmasked. Not recommended: the output
    package then contains live credentials.

.PARAMETER SensitiveSearchPath
    Folders searched by -EnableSensitiveInfoSearch. Default: C:\Temp, the current user's Desktop, C:\inetpub\wwwroot.

.PARAMETER SkipNetworkTests
    Skip the outbound connectivity tests (DNS to 8.8.8.8, TCP to portquiz.net). Use in
    environments where egress probes would raise alerts.

.PARAMETER SkipGpoCollection
    Skip GPResult export and the copy of applied GPOs from SYSVOL.

.PARAMETER OutputPath
    Parent folder for the output. Defaults to the current directory.

.PARAMETER NoZip
    Do not compress the output folder.

.PARAMETER KeepFolder
    Keep the output folder after it was zipped (default: folder is removed after a successful zip).

.PARAMETER Quiet
    Suppress progress messages on screen.

.EXAMPLE
    .\WindowsAssessment.ps1
.EXAMPLE
    .\WindowsAssessment.ps1 -EnableSensitiveInfoSearch -SkipNetworkTests -OutputPath D:\Assessments

.NOTES
    Version 2.0.0 - refactor of v1.37 (Haim Nachmias / Nital Ruzin).
    See CHANGELOG.md for the list of defects fixed and the ATT&CK mapping methodology.
    Tests: Invoke-Pester .\tests -Output Detailed
#>
[CmdletBinding()]
param (
    [switch]$EnableSensitiveInfoSearch,
    [switch]$IncludeSecretValues,
    [string[]]$SensitiveSearchPath,
    [switch]$SkipNetworkTests,
    [switch]$SkipGpoCollection,
    [string]$OutputPath = (Get-Location).Path,
    [switch]$NoZip,
    [switch]$KeepFolder,
    [switch]$Quiet
)

$script:WAVersion = '2.0.0'
$script:WAQuiet = [bool]$Quiet
$script:WAUtf8Bom = New-Object System.Text.UTF8Encoding $true
$script:WAUtf8NoBom = New-Object System.Text.UTF8Encoding $false
$script:WASeverityWeight = @{ 'Critical' = 10; 'High' = 7; 'Medium' = 4; 'Low' = 2; 'Informational' = 0 }
$script:WASeverityOrder = @{ 'Critical' = 0; 'High' = 1; 'Medium' = 2; 'Low' = 3; 'Informational' = 4 }
$script:WALegacyStatus = @{ 'Pass' = 'Strength'; 'Fail' = 'Opportunity'; 'Warning' = 'Opportunity'; 'Manual' = 'Unknown'; 'Error' = 'Unknown'; 'Info' = ''; 'NotApplicable' = '' }

#region ATT&CK reference data + check catalog
# GENERATED from the official MITRE ATT&CK STIX bundle - do not edit by hand.
# Regenerate/validate with tools/Update-AttackSnapshot.ps1 and tests/WindowsAssessment.Tests.ps1.
$script:WAAttackVersion = 'Enterprise ATT&CK v19.2'
$script:WAAttackModified = '2026-08-05'
$script:WATactics = [ordered]@{
    'reconnaissance' = @{ Id = 'TA0043'; Name = 'Reconnaissance'; Order = 0 }
    'resource-development' = @{ Id = 'TA0042'; Name = 'Resource Development'; Order = 1 }
    'initial-access' = @{ Id = 'TA0001'; Name = 'Initial Access'; Order = 2 }
    'execution' = @{ Id = 'TA0002'; Name = 'Execution'; Order = 3 }
    'persistence' = @{ Id = 'TA0003'; Name = 'Persistence'; Order = 4 }
    'privilege-escalation' = @{ Id = 'TA0004'; Name = 'Privilege Escalation'; Order = 5 }
    'stealth' = @{ Id = 'TA0005'; Name = 'Stealth'; Order = 6 }
    'defense-impairment' = @{ Id = 'TA0112'; Name = 'Defense Impairment'; Order = 7 }
    'credential-access' = @{ Id = 'TA0006'; Name = 'Credential Access'; Order = 8 }
    'discovery' = @{ Id = 'TA0007'; Name = 'Discovery'; Order = 9 }
    'lateral-movement' = @{ Id = 'TA0008'; Name = 'Lateral Movement'; Order = 10 }
    'collection' = @{ Id = 'TA0009'; Name = 'Collection'; Order = 11 }
    'command-and-control' = @{ Id = 'TA0011'; Name = 'Command and Control'; Order = 12 }
    'exfiltration' = @{ Id = 'TA0010'; Name = 'Exfiltration'; Order = 13 }
    'impact' = @{ Id = 'TA0040'; Name = 'Impact'; Order = 14 }
}
$script:WATechniques = @{
    'T1003.001' = @{ Name = 'LSASS Memory'; Tactics = @('credential-access') }
    'T1011' = @{ Name = 'Exfiltration Over Other Network Medium'; Tactics = @('exfiltration') }
    'T1021' = @{ Name = 'Remote Services'; Tactics = @('lateral-movement') }
    'T1021.001' = @{ Name = 'Remote Desktop Protocol'; Tactics = @('lateral-movement') }
    'T1021.002' = @{ Name = 'SMB/Windows Admin Shares'; Tactics = @('lateral-movement') }
    'T1027' = @{ Name = 'Obfuscated Files or Information'; Tactics = @('stealth') }
    'T1033' = @{ Name = 'System Owner/User Discovery'; Tactics = @('discovery') }
    'T1039' = @{ Name = 'Data from Network Shared Drive'; Tactics = @('collection') }
    'T1041' = @{ Name = 'Exfiltration Over C2 Channel'; Tactics = @('exfiltration') }
    'T1048' = @{ Name = 'Exfiltration Over Alternative Protocol'; Tactics = @('exfiltration') }
    'T1049' = @{ Name = 'System Network Connections Discovery'; Tactics = @('discovery') }
    'T1059.001' = @{ Name = 'PowerShell'; Tactics = @('execution') }
    'T1059.003' = @{ Name = 'Windows Command Shell'; Tactics = @('execution') }
    'T1059.005' = @{ Name = 'Visual Basic'; Tactics = @('execution') }
    'T1068' = @{ Name = 'Exploitation for Privilege Escalation'; Tactics = @('privilege-escalation') }
    'T1069.001' = @{ Name = 'Local Groups'; Tactics = @('discovery') }
    'T1071.001' = @{ Name = 'Web Protocols'; Tactics = @('command-and-control') }
    'T1071.004' = @{ Name = 'DNS'; Tactics = @('command-and-control') }
    'T1078' = @{ Name = 'Valid Accounts'; Tactics = @('stealth','persistence','privilege-escalation','initial-access') }
    'T1078.002' = @{ Name = 'Domain Accounts'; Tactics = @('stealth','persistence','privilege-escalation','initial-access') }
    'T1078.003' = @{ Name = 'Local Accounts'; Tactics = @('stealth','persistence','privilege-escalation','initial-access') }
    'T1087.001' = @{ Name = 'Local Account'; Tactics = @('discovery') }
    'T1090' = @{ Name = 'Proxy'; Tactics = @('command-and-control') }
    'T1098' = @{ Name = 'Account Manipulation'; Tactics = @('persistence','privilege-escalation') }
    'T1110' = @{ Name = 'Brute Force'; Tactics = @('credential-access') }
    'T1110.002' = @{ Name = 'Password Cracking'; Tactics = @('credential-access') }
    'T1112' = @{ Name = 'Modify Registry'; Tactics = @('defense-impairment','persistence') }
    'T1134.001' = @{ Name = 'Token Impersonation/Theft'; Tactics = @('stealth','privilege-escalation') }
    'T1135' = @{ Name = 'Network Share Discovery'; Tactics = @('discovery') }
    'T1137' = @{ Name = 'Office Application Startup'; Tactics = @('persistence') }
    'T1187' = @{ Name = 'Forced Authentication'; Tactics = @('credential-access') }
    'T1203' = @{ Name = 'Exploitation for Client Execution'; Tactics = @('execution') }
    'T1204.002' = @{ Name = 'Malicious File'; Tactics = @('execution') }
    'T1210' = @{ Name = 'Exploitation of Remote Services'; Tactics = @('lateral-movement') }
    'T1218.007' = @{ Name = 'Msiexec'; Tactics = @('stealth') }
    'T1219' = @{ Name = 'Remote Access Tools'; Tactics = @('command-and-control') }
    'T1543.003' = @{ Name = 'Windows Service'; Tactics = @('persistence','privilege-escalation') }
    'T1547.008' = @{ Name = 'LSASS Driver'; Tactics = @('persistence','privilege-escalation') }
    'T1548' = @{ Name = 'Abuse Elevation Control Mechanism'; Tactics = @('privilege-escalation') }
    'T1548.002' = @{ Name = 'Bypass User Account Control'; Tactics = @('privilege-escalation') }
    'T1550.002' = @{ Name = 'Pass the Hash'; Tactics = @('lateral-movement') }
    'T1552.001' = @{ Name = 'Credentials In Files'; Tactics = @('credential-access') }
    'T1552.004' = @{ Name = 'Private Keys'; Tactics = @('credential-access') }
    'T1555.004' = @{ Name = 'Windows Credential Manager'; Tactics = @('credential-access') }
    'T1557' = @{ Name = 'Adversary-in-the-Middle'; Tactics = @('credential-access','collection') }
    'T1557.001' = @{ Name = 'Name Resolution Poisoning and SMB Relay'; Tactics = @('credential-access','collection') }
    'T1557.003' = @{ Name = 'DHCP Spoofing'; Tactics = @('credential-access','collection') }
    'T1558' = @{ Name = 'Steal or Forge Kerberos Tickets'; Tactics = @('credential-access') }
    'T1558.003' = @{ Name = 'Kerberoasting'; Tactics = @('credential-access') }
    'T1558.004' = @{ Name = 'AS-REP Roasting'; Tactics = @('credential-access') }
    'T1559.002' = @{ Name = 'Dynamic Data Exchange'; Tactics = @('execution') }
    'T1563.002' = @{ Name = 'RDP Hijacking'; Tactics = @('lateral-movement') }
    'T1566.001' = @{ Name = 'Spearphishing Attachment'; Tactics = @('initial-access') }
    'T1571' = @{ Name = 'Non-Standard Port'; Tactics = @('command-and-control') }
    'T1574.009' = @{ Name = 'Path Interception by Unquoted Path'; Tactics = @('stealth','execution') }
    'T1685' = @{ Name = 'Disable or Modify Tools'; Tactics = @('defense-impairment') }
    'T1685.001' = @{ Name = 'Disable or Modify Windows Event Log'; Tactics = @('defense-impairment') }
    'T1685.005' = @{ Name = 'Clear Windows Event Logs'; Tactics = @('defense-impairment') }
    'T1686.003' = @{ Name = 'Windows Host Firewall'; Tactics = @('defense-impairment') }
    'T1688' = @{ Name = 'Safe Mode Boot'; Tactics = @('defense-impairment') }
    'T1689' = @{ Name = 'Downgrade Attack'; Tactics = @('defense-impairment') }
}
$script:WAMitigations = @{
    'M1018' = 'User Account Management'
    'M1022' = 'Restrict File and Directory Permissions'
    'M1025' = 'Privileged Process Integrity'
    'M1026' = 'Privileged Account Management'
    'M1027' = 'Password Policies'
    'M1028' = 'Operating System Configuration'
    'M1029' = 'Remote Data Storage'
    'M1031' = 'Network Intrusion Prevention'
    'M1035' = 'Limit Access to Resource Over Network'
    'M1037' = 'Filter Network Traffic'
    'M1038' = 'Execution Prevention'
    'M1040' = 'Behavior Prevention on Endpoint'
    'M1041' = 'Encrypt Sensitive Information'
    'M1042' = 'Disable or Remove Feature or Program'
    'M1043' = 'Credential Access Protection'
    'M1047' = 'Audit'
    'M1049' = 'Antivirus/Antimalware'
    'M1051' = 'Update Software'
    'M1052' = 'User Account Control'
    'M1054' = 'Software Configuration'
}
$script:WACheckCatalog = [ordered]@{
    'info_cName' = @{ Name = 'Computer name'; Category = 'Information'; Severity = 'Informational'; Manual = $false; Coverage = ''; Techniques = @(); Mitigations = @(); Remediation = ''; Reference = '' }
    'info_sVer' = @{ Name = 'Script version'; Category = 'Information'; Severity = 'Informational'; Manual = $false; Coverage = ''; Techniques = @(); Mitigations = @(); Remediation = ''; Reference = '' }
    'info_wVer' = @{ Name = 'Windows version'; Category = 'Information'; Severity = 'Informational'; Manual = $false; Coverage = ''; Techniques = @(); Mitigations = @(); Remediation = ''; Reference = '' }
    'info_computerType' = @{ Name = 'Computer type'; Category = 'Information'; Severity = 'Informational'; Manual = $false; Coverage = ''; Techniques = @(); Mitigations = @(); Remediation = ''; Reference = '' }
    'info_dName' = @{ Name = 'Domain name'; Category = 'Information'; Severity = 'Informational'; Manual = $false; Coverage = ''; Techniques = @(); Mitigations = @(); Remediation = ''; Reference = '' }
    'info_psVer' = @{ Name = 'PowerShell version'; Category = 'Information'; Severity = 'Informational'; Manual = $false; Coverage = ''; Techniques = @(); Mitigations = @(); Remediation = ''; Reference = '' }
    'info_isAdmin' = @{ Name = 'Elevated execution'; Category = 'Information'; Severity = 'Informational'; Manual = $false; Coverage = ''; Techniques = @(); Mitigations = @(); Remediation = ''; Reference = '' }
    'info_uptime' = @{ Name = 'Last boot time'; Category = 'Information'; Severity = 'Informational'; Manual = $false; Coverage = ''; Techniques = @(); Mitigations = @(); Remediation = ''; Reference = '' }
    'machine_LSA-CG-wmi' = @{ Name = 'Credential Guard'; Category = 'Machine Hardening - Authentication'; Severity = 'Medium'; Manual = $false; Coverage = 'Prevent'; Techniques = @('T1003.001','T1550.002','T1558'); Mitigations = @('M1043'); Remediation = 'Enable VBS with Credential Guard (GPO: System > Device Guard > Turn On Virtualization Based Security > Credential Guard Configuration = Enabled with UEFI lock). Validate UEFI, Secure Boot, TPM 2.0 and virtualization extensions first.'; Reference = 'https://learn.microsoft.com/windows/security/identity-protection/credential-guard/configure' }
    'machine_LSA-ppl' = @{ Name = 'LSA Protection (RunAsPPL)'; Category = 'Machine Hardening - Authentication'; Severity = 'High'; Manual = $false; Coverage = 'Prevent'; Techniques = @('T1003.001','T1547.008'); Mitigations = @('M1025'); Remediation = 'Set HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL = 1 (UEFI lock) or 2 (no UEFI lock, Windows 11 22H2+) via GPO ''Configure LSASS to run as a protected process''. Audit third-party LSA plug-ins first (CodeIntegrity events 3065/3066).'; Reference = 'https://learn.microsoft.com/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection' }
    'domain_WDigest' = @{ Name = 'WDigest clear-text credentials in LSASS'; Category = 'Machine Hardening - Authentication'; Severity = 'Critical'; Manual = $false; Coverage = 'Prevent'; Techniques = @('T1003.001'); Mitigations = @('M1028'); Remediation = 'Set HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential = 0 via GPO (MS Security Guide ADMX: ''WDigest Authentication'' = Disabled) and alert on any change to this value (a common attacker tactic).'; Reference = '' }
    'machine_ASR-LSASS' = @{ Name = 'ASR - Block credential stealing from LSASS'; Category = 'Machine Hardening - Security'; Severity = 'Medium'; Manual = $false; Coverage = 'Prevent'; Techniques = @('T1003.001'); Mitigations = @('M1040'); Remediation = 'Configure Defender ASR rule 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2 in Block mode (1) via Intune/GPO. Pilot in Audit mode (2) first.'; Reference = 'https://learn.microsoft.com/defender-endpoint/attack-surface-reduction-rules-reference' }
    'domain_PrevStorOfPassAndCred' = @{ Name = 'Storage of network passwords and credentials'; Category = 'Machine Hardening - Authentication'; Severity = 'Medium'; Manual = $false; Coverage = 'Prevent'; Techniques = @('T1555.004'); Mitigations = @('M1042'); Remediation = 'GPO: ''Network access: Do not allow storage of passwords and credentials for network authentication'' = Enabled (DisableDomainCreds = 1).'; Reference = '' }
    'domain_CredSSPDefaultCred' = @{ Name = 'CredSSP - Allow delegation of default credentials'; Category = 'Machine Hardening - Authentication'; Severity = 'Medium'; Manual = $false; Coverage = 'Prevent'; Techniques = @('T1003.001','T1557'); Mitigations = @('M1028'); Remediation = 'Leave ''Allow delegating default credentials'' Not Configured/Disabled. If required, scope to explicit SPNs (never ''*'' or TERMSRV/*).'; Reference = '' }
    'domain_CredSSPDefaultCredNTLM' = @{ Name = 'CredSSP - Allow delegation of default credentials with NTLM-only'; Category = 'Machine Hardening - Authentication'; Severity = 'High'; Manual = $false; Coverage = 'Prevent'; Techniques = @('T1003.001','T1557'); Mitigations = @('M1028'); Remediation = 'Disable ''Allow delegating default credentials with NTLM-only server authentication''. NTLM-only delegation sends reusable credentials to servers that were never mutually authenticated.'; Reference = '' }
    'domain_CredSSPSavedCred' = @{ Name = 'CredSSP - Allow delegation of saved credentials'; Category = 'Machine Hardening - Authentication'; Severity = 'Low'; Manual = $false; Coverage = 'Prevent'; Techniques = @('T1003.001','T1557'); Mitigations = @('M1028'); Remediation = 'Configure ''Allow delegating saved credentials'' with an explicit server list, or disable it. When not configured Windows permits delegation to TERMSRV/*.'; Reference = '' }
    'domain_CredSSPSavedCredNTLM' = @{ Name = 'CredSSP - Allow delegation of saved credentials with NTLM-only'; Category = 'Machine Hardening - Authentication'; Severity = 'Medium'; Manual = $false; Coverage = 'Prevent'; Techniques = @('T1003.001','T1557'); Mitigations = @('M1028'); Remediation = 'Disable ''Allow delegating saved credentials with NTLM-only server authentication'' (not configured = allowed to TERMSRV/*).'; Reference = '' }
    'domain_CredSSPDefaultCredDeny' = @{ Name = 'CredSSP - Deny delegation of default credentials'; Category = 'Machine Hardening - Authentication'; Severity = 'Low'; Manual = $false; Coverage = 'Prevent'; Techniques = @('T1003.001'); Mitigations = @('M1028'); Remediation = 'Enable ''Deny delegating default credentials'' with ''*'' and add only the required exceptions to the allow lists.'; Reference = '' }
    'domain_CredSSPSavedCredDeny' = @{ Name = 'CredSSP - Deny delegation of saved credentials'; Category = 'Machine Hardening - Authentication'; Severity = 'Low'; Manual = $false; Coverage = 'Prevent'; Techniques = @('T1003.001'); Mitigations = @('M1028'); Remediation = 'Enable ''Deny delegating saved credentials'' with ''*'' unless saved-credential RDP is an explicit business requirement.'; Reference = '' }
    'domain_CredSSPNonExportableCred' = @{ Name = 'Remote host allows delegation of non-exportable credentials'; Category = 'Machine Hardening - Authentication'; Severity = 'Low'; Manual = $false; Coverage = 'Prevent'; Techniques = @('T1003.001','T1550.002'); Mitigations = @('M1043'); Remediation = 'Enable ''Remote host allows delegation of non-exportable credentials'' (AllowProtectedCreds = 1) on RDP targets so Remote Credential Guard can be used.'; Reference = 'https://learn.microsoft.com/windows/security/identity-protection/remote-credential-guard' }
    'domain_CredSSPResDelOfCredToRemoteSrv' = @{ Name = 'Restrict delegation of credentials to remote servers'; Category = 'Machine Hardening - Authentication'; Severity = 'Low'; Manual = $false; Coverage = 'Prevent'; Techniques = @('T1003.001','T1021.001'); Mitigations = @('M1043','M1028'); Remediation = 'Enable ''Restrict delegation of credentials to remote servers'' on admin workstations. Prefer ''Require Remote Credential Guard'' - Restricted Admin mode enables pass-the-hash over RDP.'; Reference = 'https://learn.microsoft.com/windows/security/identity-protection/remote-credential-guard' }
    'domain_NTLMComLevel' = @{ Name = 'LAN Manager authentication level'; Category = 'Machine Hardening - Authentication'; Severity = 'High'; Manual = $false; Coverage = 'Prevent'; Techniques = @('T1557.001','T1110.002','T1550.002'); Mitigations = @('M1042'); Remediation = 'GPO: ''Network security: LAN Manager authentication level'' = ''Send NTLMv2 response only. Refuse LM & NTLM'' (LmCompatibilityLevel = 5). Audit NTLMv1 usage first (event 4624, Package Name NTLM V1).'; Reference = 'https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/network-security-lan-manager-authentication-level' }
    'domain_kerbSupEnc' = @{ Name = 'Kerberos supported encryption types'; Category = 'Machine Hardening - Authentication'; Severity = 'Medium'; Manual = $false; Coverage = 'Prevent'; Techniques = @('T1558.003','T1558.004'); Mitigations = @('M1041'); Remediation = 'GPO: ''Network security: Configure encryption types allowed for Kerberos'' = AES128 + AES256 (+ Future). Remove DES and RC4 after confirming no service accounts depend on them (msDS-SupportedEncryptionTypes).'; Reference = 'https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/network-security-configure-encryption-types-allowed-for-kerberos' }
    'machine_LAPS' = @{ Name = 'Local administrator password management (LAPS)'; Category = 'Machine Hardening - Users'; Severity = 'High'; Manual = $false; Coverage = 'Prevent'; Techniques = @('T1078.003','T1550.002'); Mitigations = @('M1026','M1027'); Remediation = 'Deploy Windows LAPS (BackupDirectory = 1 Entra ID or 2 Active Directory) with password encryption, and retire legacy Microsoft LAPS.'; Reference = 'https://learn.microsoft.com/windows-server/identity/laps/laps-overview' }
    'machine_UAC-EnableLUA' = @{ Name = 'UAC - Admin Approval Mode'; Category = 'Machine Hardening - Security'; Severity = 'High'; Manual = $false; Coverage = 'Prevent'; Techniques = @('T1548.002'); Mitigations = @('M1052'); Remediation = 'GPO: ''User Account Control: Run all administrators in Admin Approval Mode'' = Enabled (EnableLUA = 1).'; Reference = 'https://learn.microsoft.com/windows/security/application-security/application-control/user-account-control/settings-and-configuration' }
    'machine_UAC-AdminPrompt' = @{ Name = 'UAC - Elevation prompt for administrators'; Category = 'Machine Hardening - Security'; Severity = 'Medium'; Manual = $false; Coverage = 'Prevent'; Techniques = @('T1548.002'); Mitigations = @('M1052'); Remediation = 'GPO: ''Behavior of the elevation prompt for administrators in Admin Approval Mode'' = ''Prompt for consent on the secure desktop'' (2) or ''Prompt for credentials on the secure desktop'' (1).'; Reference = 'https://learn.microsoft.com/windows/security/application-security/application-control/user-account-control/settings-and-configuration' }
    'machine_UAC-RemoteRestrictions' = @{ Name = 'UAC remote restrictions for local accounts'; Category = 'Machine Hardening - Security'; Severity = 'High'; Manual = $false; Coverage = 'Prevent'; Techniques = @('T1550.002','T1021.002'); Mitigations = @('M1052','M1026'); Remediation = 'Remove LocalAccountTokenFilterPolicy (or set 0) and apply the MS Security Guide setting ''Apply UAC restrictions to local accounts on network logons''.'; Reference = 'https://learn.microsoft.com/troubleshoot/windows-server/windows-security/user-account-control-and-remote-restriction' }
    'domain_LLMNR' = @{ Name = 'LLMNR'; Category = 'Domain Hardening - Network'; Severity = 'High'; Manual = $false; Coverage = 'Prevent'; Techniques = @('T1557.001'); Mitigations = @('M1042','M1037'); Remediation = 'GPO: Network > DNS Client > ''Turn off multicast name resolution'' = Enabled (EnableMulticast = 0).'; Reference = '' }
    'domain_NetBIOSNT' = @{ Name = 'NetBIOS node type'; Category = 'Domain Hardening - Network'; Severity = 'Medium'; Manual = $false; Coverage = 'Prevent'; Techniques = @('T1557.001'); Mitigations = @('M1042'); Remediation = 'Set NetBT NodeType = 2 (P-node) via GPO (MS Security Guide ''NetBT NodeType configuration'') or disable NetBIOS over TCP/IP on every interface.'; Reference = '' }
    'domain_NetBIOSoTCP' = @{ Name = 'NetBIOS over TCP/IP (per interface)'; Category = 'Domain Hardening - Network'; Severity = 'Medium'; Manual = $false; Coverage = 'Prevent'; Techniques = @('T1557.001'); Mitigations = @('M1042'); Remediation = 'Disable NetBIOS over TCP/IP on all interfaces (NetbiosOptions = 2) via DHCP option 001 (Microsoft vendor class) or configuration management.'; Reference = '' }
    'domain_mDNS' = @{ Name = 'mDNS responder'; Category = 'Domain Hardening - Network'; Severity = 'Medium'; Manual = $false; Coverage = 'Prevent'; Techniques = @('T1557.001'); Mitigations = @('M1042','M1037'); Remediation = 'Disable mDNS where not required: HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\EnableMDNS = 0, or block UDP 5353 inbound in Windows Firewall.'; Reference = '' }
    'domain_mitm6' = @{ Name = 'IPv6 DHCPv6 spoofing exposure (mitm6)'; Category = 'Domain Hardening - Network'; Severity = 'Medium'; Manual = $false; Coverage = 'Prevent'; Techniques = @('T1557.003'); Mitigations = @('M1037'); Remediation = 'If IPv6 is not used, block inbound DHCPv6 (UDP 546) and inbound ICMPv6 Router Advertisements and outbound DHCPv6 (UDP 547) via Windows Firewall GPO. Do not unbind IPv6 (unsupported by Microsoft).'; Reference = '' }
    'domain_SMBv2-srvSign' = @{ Name = 'SMB server signing required'; Category = 'Domain Hardening - SMB'; Severity = 'High'; Manual = $false; Coverage = 'Prevent'; Techniques = @('T1557.001'); Mitigations = @('M1037'); Remediation = 'GPO: ''Microsoft network server: Digitally sign communications (always)'' = Enabled (RequireSecuritySignature = 1). Mandatory on DCs and file servers.'; Reference = 'https://learn.microsoft.com/windows-server/storage/file-server/smb-signing' }
    'domain_SMBv2-clientSign' = @{ Name = 'SMB client signing required'; Category = 'Domain Hardening - SMB'; Severity = 'Medium'; Manual = $false; Coverage = 'Prevent'; Techniques = @('T1557.001'); Mitigations = @('M1037'); Remediation = 'GPO: ''Microsoft network client: Digitally sign communications (always)'' = Enabled.'; Reference = 'https://learn.microsoft.com/windows-server/storage/file-server/smb-signing' }
    'machine_autoIsoProxyDiscovery' = @{ Name = 'Network Isolation automatic proxy discovery'; Category = 'Machine Hardening - Networking'; Severity = 'Low'; Manual = $false; Coverage = 'Prevent'; Techniques = @('T1557'); Mitigations = @('M1042'); Remediation = 'GPO: Network > Network Isolation > ''Proxy definitions are authoritative'' = Enabled (DProxiesAuthoritive = 1).'; Reference = '' }
    'machine_AutoProxyResultCache' = @{ Name = 'Auto-proxy script result caching'; Category = 'Machine Hardening - Networking'; Severity = 'Low'; Manual = $false; Coverage = 'Prevent'; Techniques = @('T1557'); Mitigations = @('M1042'); Remediation = 'GPO: ''Disable caching of Auto-Proxy scripts'' = Enabled (EnableAutoProxyResultCache = 0) so a poisoned PAC result is not reused.'; Reference = '' }
    'machine_WPADSvc' = @{ Name = 'WPAD (WinHTTP auto-proxy discovery)'; Category = 'Machine Hardening - Networking'; Severity = 'Medium'; Manual = $false; Coverage = 'Prevent'; Techniques = @('T1557','T1187'); Mitigations = @('M1042'); Remediation = 'Disable WPAD via HKLM\SYSTEM\CurrentControlSet\Services\WinHttp\DisableWpad = 1 (supported), publish a ''wpad'' DNS record you control and keep ''wpad'' in the DNS global query block list.'; Reference = '' }
    'domain_SMBv1' = @{ Name = 'SMBv1 server'; Category = 'Domain Hardening - SMB'; Severity = 'High'; Manual = $false; Coverage = 'Prevent'; Techniques = @('T1210','T1021.002'); Mitigations = @('M1042','M1051'); Remediation = 'Remove SMB1: Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol (or Set-SmbServerConfiguration -EnableSMB1Protocol $false). Audit first with Set-SmbServerConfiguration -AuditSmb1Access $true.'; Reference = 'https://learn.microsoft.com/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3' }
    'domain_SMBv1-client' = @{ Name = 'SMBv1 client driver (mrxsmb10)'; Category = 'Domain Hardening - SMB'; Severity = 'Medium'; Manual = $false; Coverage = 'Prevent'; Techniques = @('T1210','T1557'); Mitigations = @('M1042'); Remediation = 'Remove the SMB1Protocol-Client feature, or: sc.exe config lanmanworkstation depend= bowser/mrxsmb20/nsi and sc.exe config mrxsmb10 start= disabled.'; Reference = 'https://learn.microsoft.com/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3' }
    'domain_SMBv2-3' = @{ Name = 'SMB2/3 server support'; Category = 'Domain Hardening - SMB'; Severity = 'Informational'; Manual = $false; Coverage = ''; Techniques = @(); Mitigations = @(); Remediation = ''; Reference = '' }
    'machine_RDP-reg' = @{ Name = 'RDP service status'; Category = 'Machine Hardening - RDP'; Severity = 'Low'; Manual = $false; Coverage = 'Prevent'; Techniques = @('T1021.001'); Mitigations = @('M1042','M1035'); Remediation = 'Disable RDP where not required (fDenyTSConnections = 1). Where required, restrict TCP 3389 to a PAW/jump-host subnet with Windows Firewall and require NLA.'; Reference = '' }
    'machine_RDP-Users' = @{ Name = 'RDP allowed users'; Category = 'Machine Hardening - RDP'; Severity = 'Medium'; Manual = $false; Coverage = 'Prevent'; Techniques = @('T1021.001','T1078'); Mitigations = @('M1018','M1026'); Remediation = 'Remove broad principals (Everyone, Authenticated Users, Domain Users) from ''Remote Desktop Users''; grant ''Allow log on through Remote Desktop Services'' to named admin groups only.'; Reference = '' }
    'machine_RDP-NLA' = @{ Name = 'RDP Network Level Authentication'; Category = 'Machine Hardening - RDP'; Severity = 'Medium'; Manual = $false; Coverage = 'Prevent'; Techniques = @('T1021.001','T1210'); Mitigations = @('M1028'); Remediation = 'GPO: ''Require user authentication for remote connections by using Network Level Authentication'' = Enabled (UserAuthentication = 1).'; Reference = '' }
    'machine_RDP-TLS' = @{ Name = 'RDP security layer (TLS)'; Category = 'Machine Hardening - RDP'; Severity = 'Low'; Manual = $false; Coverage = 'Prevent'; Techniques = @('T1557','T1021.001'); Mitigations = @('M1041'); Remediation = 'GPO: ''Require use of specific security layer for remote (RDP) connections'' = SSL (SecurityLayer = 2) and bind a certificate from an internal CA.'; Reference = '' }
    'machine_RDP-Timeout' = @{ Name = 'RDP session time limits'; Category = 'Machine Hardening - RDP'; Severity = 'Low'; Manual = $false; Coverage = 'Prevent'; Techniques = @('T1563.002'); Mitigations = @('M1028'); Remediation = 'GPO: Remote Desktop Session Host > Session Time Limits - set disconnected (MaxDisconnectionTime) and idle (MaxIdleTime) limits and enable ''End session when time limits are reached'' (fResetBroken = 1).'; Reference = '' }
    'machine_AVName' = @{ Name = 'Antivirus registration and health'; Category = 'Machine Hardening - Security'; Severity = 'Critical'; Manual = $false; Coverage = 'Prevent'; Techniques = @('T1566.001','T1027'); Mitigations = @('M1049'); Remediation = 'Ensure an AV/EDR product is registered, running, and has signatures updated within 24 hours.'; Reference = '' }
    'machine_DefenderRTP' = @{ Name = 'Microsoft Defender real-time protection'; Category = 'Machine Hardening - Security'; Severity = 'High'; Manual = $false; Coverage = 'Prevent'; Techniques = @('T1685'); Mitigations = @('M1054'); Remediation = 'Enable real-time protection and behavior monitoring; review exclusions (Get-MpPreference ExclusionPath/Process/Extension) for over-broad entries.'; Reference = '' }
    'machine_DefenderTamper' = @{ Name = 'Microsoft Defender tamper protection'; Category = 'Machine Hardening - Security'; Severity = 'Medium'; Manual = $false; Coverage = 'Prevent'; Techniques = @('T1685'); Mitigations = @('M1054'); Remediation = 'Enable tamper protection tenant-wide from the Defender portal (Settings > Endpoints > Advanced features) or Intune.'; Reference = 'https://learn.microsoft.com/defender-endpoint/prevent-changes-to-security-settings-with-tamper-protection' }
    'machine_ASR-Office' = @{ Name = 'ASR - Office child process / injection rules'; Category = 'Machine Hardening - Security'; Severity = 'Medium'; Manual = $false; Coverage = 'Prevent'; Techniques = @('T1204.002','T1566.001'); Mitigations = @('M1040'); Remediation = 'Set ASR rules d4f940ab-401b-4efc-aadc-ad5f3c50688a, 3b576869-a4ec-4529-8536-b80a7769e899, 75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84 and 92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b to Block (1).'; Reference = 'https://learn.microsoft.com/defender-endpoint/attack-surface-reduction-rules-reference' }
    'machine_FirewallProfiles' = @{ Name = 'Windows Firewall profiles'; Category = 'Machine Hardening - Network Access'; Severity = 'High'; Manual = $false; Coverage = 'Prevent'; Techniques = @('T1021','T1686.003'); Mitigations = @('M1035'); Remediation = 'Enable Windows Firewall on Domain, Private and Public profiles with default inbound action Block, managed by GPO so local admins cannot override (disable local rule merge).'; Reference = '' }
    'domain_NetSessionEnum' = @{ Name = 'NetSessionEnum (SMB session enumeration) permissions'; Category = 'Domain Hardening - Enumeration'; Severity = 'Medium'; Manual = $false; Coverage = 'Prevent'; Techniques = @('T1049','T1033'); Mitigations = @(); Remediation = 'Remove Authenticated Users from the SrvsvcSessionInfo ACL (NetCease or equivalent), most importantly on DCs and file servers. Windows Server 2019+/Windows 10 1607+ are hardened by default.'; Reference = '' }
    'domain_SAMEnum' = @{ Name = 'Remote SAM (SAMR) enumeration'; Category = 'Domain Hardening - Enumeration'; Severity = 'High'; Manual = $false; Coverage = 'Prevent'; Techniques = @('T1087.001','T1069.001'); Mitigations = @('M1028'); Remediation = 'GPO: ''Network access: Restrict clients allowed to make remote calls to SAM'' = O:BAG:BAD:(A;;RC;;;BA) (Administrators only).'; Reference = 'https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/network-access-restrict-clients-allowed-to-make-remote-sam-calls' }
    'machine_PSv2' = @{ Name = 'PowerShell 2.0 engine'; Category = 'Machine Hardening - Operation system'; Severity = 'High'; Manual = $false; Coverage = 'Prevent'; Techniques = @('T1689','T1059.001'); Mitigations = @('M1042'); Remediation = 'Remove the engine: Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root (clients) or Uninstall-WindowsFeature PowerShell-V2 (servers).'; Reference = '' }
    'machine_PSModuleLog' = @{ Name = 'PowerShell module logging'; Category = 'Machine Hardening - Audit'; Severity = 'Medium'; Manual = $false; Coverage = 'Detect'; Techniques = @('T1059.001'); Mitigations = @(); Remediation = 'GPO: Windows PowerShell > ''Turn on Module Logging'' = Enabled with module name ''*'' (HKLM policy).'; Reference = 'https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_logging_windows' }
    'machine_PSScriptBlock' = @{ Name = 'PowerShell script block logging'; Category = 'Machine Hardening - Audit'; Severity = 'High'; Manual = $false; Coverage = 'Detect'; Techniques = @('T1059.001','T1027'); Mitigations = @(); Remediation = 'GPO: Windows PowerShell > ''Turn on PowerShell Script Block Logging'' = Enabled (HKLM policy). Forward event 4104 to the SIEM.'; Reference = 'https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_logging_windows' }
    'machine_PSTranscript' = @{ Name = 'PowerShell transcription'; Category = 'Machine Hardening - Audit'; Severity = 'Medium'; Manual = $false; Coverage = 'Detect'; Techniques = @('T1059.001'); Mitigations = @(); Remediation = 'GPO: ''Turn on PowerShell Transcription'' = Enabled with invocation headers and a write-only central OutputDirectory (UNC share with create-only ACL).'; Reference = '' }
    'machine_ComLineLog' = @{ Name = 'Process creation command-line auditing'; Category = 'Machine Hardening - Audit'; Severity = 'Medium'; Manual = $false; Coverage = 'Detect'; Techniques = @('T1059.003','T1059.001'); Mitigations = @(); Remediation = 'Enable ''Audit Process Creation'' (Success) and ''Include command line in process creation events'' (ProcessCreationIncludeCmdLine_Enabled = 1). Forward event 4688.'; Reference = 'https://learn.microsoft.com/windows-server/identity/ad-ds/manage/component-updates/command-line-process-auditing' }
    'machine_AppMaxLog' = @{ Name = 'Application event log maximum size'; Category = 'Machine Hardening - Audit'; Severity = 'Low'; Manual = $false; Coverage = 'Detect'; Techniques = @('T1685.005'); Mitigations = @('M1029'); Remediation = 'Set the Application log maximum size to at least 32,768 KB via GPO and forward events to the SIEM.'; Reference = '' }
    'machine_SysMaxLog' = @{ Name = 'System event log maximum size'; Category = 'Machine Hardening - Audit'; Severity = 'Low'; Manual = $false; Coverage = 'Detect'; Techniques = @('T1685.005'); Mitigations = @('M1029'); Remediation = 'Set the System log maximum size to at least 32,768 KB via GPO and forward events to the SIEM.'; Reference = '' }
    'machine_SecMaxLog' = @{ Name = 'Security event log maximum size'; Category = 'Machine Hardening - Audit'; Severity = 'Medium'; Manual = $false; Coverage = 'Detect'; Techniques = @('T1685.005'); Mitigations = @('M1029'); Remediation = 'Set the Security log maximum size to at least 196,608 KB via GPO and forward events to the SIEM in near real time.'; Reference = '' }
    'machine_SetupMaxLog' = @{ Name = 'Setup event log'; Category = 'Machine Hardening - Audit'; Severity = 'Informational'; Manual = $false; Coverage = ''; Techniques = @(); Mitigations = @(); Remediation = ''; Reference = '' }
    'machine_installWithElevation' = @{ Name = 'AlwaysInstallElevated'; Category = 'Machine Hardening - Operation system'; Severity = 'High'; Manual = $false; Coverage = 'Prevent'; Techniques = @('T1218.007','T1548'); Mitigations = @('M1042','M1026'); Remediation = 'Set ''Always install with elevated privileges'' = Disabled in both Computer and User configuration (AlwaysInstallElevated = 0 under HKLM and HKCU).'; Reference = 'https://learn.microsoft.com/windows/win32/msi/alwaysinstallelevated' }
    'vul_quotedPath' = @{ Name = 'Unquoted service paths'; Category = 'Machine Vulnerabilities'; Severity = 'High'; Manual = $false; Coverage = 'Prevent'; Techniques = @('T1574.009'); Mitigations = @('M1047','M1022'); Remediation = 'Quote the ImagePath of every listed service (HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath) and verify non-admins cannot write to any parent folder in the path.'; Reference = '' }
    'machine_SafeModeAcc4NonAdmin' = @{ Name = 'Safe Mode access by non-admins'; Category = 'Machine Hardening - Operation system'; Severity = 'Low'; Manual = $false; Coverage = 'Prevent'; Techniques = @('T1688'); Mitigations = @('M1054','M1026'); Remediation = 'Set HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\SafeModeBlockNonAdmins = 1.'; Reference = '' }
    'domain_GPOReRegistry' = @{ Name = 'GPO reprocessing - registry policy'; Category = 'Domain Hardening - General'; Severity = 'Medium'; Manual = $false; Coverage = 'Prevent'; Techniques = @('T1112','T1685'); Mitigations = @('M1054'); Remediation = 'GPO: System > Group Policy > ''Configure registry policy processing'' = Enabled with ''Process even if the Group Policy objects have not changed'' checked.'; Reference = '' }
    'domain_GPOReScript' = @{ Name = 'GPO reprocessing - scripts policy'; Category = 'Domain Hardening - General'; Severity = 'Low'; Manual = $false; Coverage = 'Prevent'; Techniques = @('T1112','T1685'); Mitigations = @('M1054'); Remediation = 'GPO: ''Configure scripts policy processing'' = Enabled with ''Process even if the Group Policy objects have not changed''.'; Reference = '' }
    'domain_GPOReSecurity' = @{ Name = 'GPO reprocessing - security policy'; Category = 'Domain Hardening - General'; Severity = 'Medium'; Manual = $false; Coverage = 'Prevent'; Techniques = @('T1112','T1685'); Mitigations = @('M1054'); Remediation = 'GPO: ''Configure security policy processing'' = Enabled with ''Process even if the Group Policy objects have not changed''.'; Reference = '' }
    'machine_autoUpdate' = @{ Name = 'Windows automatic updates'; Category = 'Machine Hardening - Patching'; Severity = 'Medium'; Manual = $false; Coverage = 'Prevent'; Techniques = @('T1068','T1210','T1203'); Mitigations = @('M1051'); Remediation = 'Do not set NoAutoUpdate = 1. Manage updates via WSUS/Intune/ConfigMgr with enforced deadlines.'; Reference = '' }
    'machine_autoUpdateSchedule' = @{ Name = 'Windows automatic update behaviour'; Category = 'Machine Hardening - Patching'; Severity = 'Low'; Manual = $false; Coverage = 'Prevent'; Techniques = @('T1068','T1210','T1203'); Mitigations = @('M1051'); Remediation = 'AUOptions = 4 (auto download and schedule install) or an equivalent managed deadline; avoid 2 (notify) and 5 (local admin chooses).'; Reference = '' }
    'machine_lastPatch' = @{ Name = 'Patch recency'; Category = 'Machine Hardening - Patching'; Severity = 'High'; Manual = $false; Coverage = 'Prevent'; Techniques = @('T1068','T1210','T1203'); Mitigations = @('M1051'); Remediation = 'Install the latest cumulative update. Target: security updates within 14 days (critical/exploited within 72 hours) of Patch Tuesday.'; Reference = '' }
    'machine_wsusUpdate' = @{ Name = 'WSUS transport security'; Category = 'Machine Hardening - Patching'; Severity = 'Medium'; Manual = $false; Coverage = 'Prevent'; Techniques = @('T1557','T1068'); Mitigations = @('M1041'); Remediation = 'Publish WSUS over HTTPS (port 8531) and update WUServer/WUStatusServer to https:// URLs.'; Reference = 'https://learn.microsoft.com/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus' }
    'machine_wsusUpdateAddress' = @{ Name = 'WSUS server address type'; Category = 'Machine Hardening - Patching'; Severity = 'Low'; Manual = $false; Coverage = 'Prevent'; Techniques = @('T1557.001'); Mitigations = @(); Remediation = 'Reference WSUS by FQDN so Kerberos (not NTLM) is used.'; Reference = '' }
    'machine_na-dns' = @{ Name = 'Internet access - DNS'; Category = 'Machine Hardening - Networking'; Severity = 'Medium'; Manual = $false; Coverage = 'Prevent'; Techniques = @('T1071.004','T1048'); Mitigations = @('M1037','M1031'); Remediation = 'Block outbound TCP/UDP 53 to the internet except from designated DNS forwarders; force resolution through internal DNS with query logging.'; Reference = '' }
    'machine_na-browsing' = @{ Name = 'Internet access - Direct egress ports'; Category = 'Machine Hardening - Networking'; Severity = 'Medium'; Manual = $false; Coverage = 'Prevent'; Techniques = @('T1071.001','T1571','T1041'); Mitigations = @('M1037','M1031'); Remediation = 'Default-deny outbound at the perimeter; allow web only through an authenticated proxy. Servers should have no direct internet egress.'; Reference = '' }
    'machine_proxyConf' = @{ Name = 'Proxy configuration scope'; Category = 'Machine Hardening - Networking'; Severity = 'Low'; Manual = $false; Coverage = 'Prevent'; Techniques = @('T1090','T1071.001'); Mitigations = @('M1037'); Remediation = 'Set ''Make proxy settings per-machine (rather than per-user)'' = Enabled (ProxySettingsPerUser = 0).'; Reference = '' }
    'machine_proxySet' = @{ Name = 'User proxy settings'; Category = 'Machine Hardening - Networking'; Severity = 'Informational'; Manual = $false; Coverage = ''; Techniques = @(); Mitigations = @(); Remediation = ''; Reference = '' }
    'machine_accConfProxy' = @{ Name = 'Users can change proxy settings'; Category = 'Machine Hardening - Networking'; Severity = 'Low'; Manual = $false; Coverage = 'Prevent'; Techniques = @('T1090'); Mitigations = @('M1037'); Remediation = 'GPO: Internet Explorer > ''Prevent changing proxy settings'' = Enabled (computer scope) and enforce egress at the perimeter.'; Reference = '' }
    'machine_ethSim' = @{ Name = 'Simultaneous network connections'; Category = 'Machine Hardening - Networking'; Severity = 'Low'; Manual = $false; Coverage = 'Prevent'; Techniques = @('T1011'); Mitigations = @('M1028'); Remediation = 'GPO: Network > Windows Connection Manager > ''Minimize the number of simultaneous connections to the Internet or a Windows Domain'' = 3 (Prevent Wi-Fi when on Ethernet).'; Reference = '' }
    'machine_PCTNDNetwork' = @{ Name = 'Non-domain networks while domain-connected'; Category = 'Machine Hardening - Networking'; Severity = 'Low'; Manual = $false; Coverage = 'Prevent'; Techniques = @('T1011'); Mitigations = @('M1028'); Remediation = 'GPO: ''Prohibit connection to non-domain networks when connected to domain authenticated network'' = Enabled.'; Reference = '' }
    'machine_excelDDE' = @{ Name = 'Excel automatic update of links (DDE)'; Category = 'Machine Hardening - Software'; Severity = 'Medium'; Manual = $false; Coverage = 'Prevent'; Techniques = @('T1559.002'); Mitigations = @('M1054','M1042'); Remediation = 'Set Excel ''WorkbookLinkWarnings'' = 2 (disable automatic update of workbook links) and disable DDE server launch via Office policy.'; Reference = '' }
    'machine_outlookDDE' = @{ Name = 'Outlook automatic update of links (DDE)'; Category = 'Machine Hardening - Software'; Severity = 'Medium'; Manual = $false; Coverage = 'Prevent'; Techniques = @('T1559.002'); Mitigations = @('M1054','M1042'); Remediation = 'Set Word\Options\WordMail ''DontUpdateLinks'' = 1.'; Reference = '' }
    'machine_wordDDE' = @{ Name = 'Word automatic update of links (DDE)'; Category = 'Machine Hardening - Software'; Severity = 'Medium'; Manual = $false; Coverage = 'Prevent'; Techniques = @('T1559.002'); Mitigations = @('M1054','M1042'); Remediation = 'Set Word\Options ''DontUpdateLinks'' = 1.'; Reference = '' }
    'machine_officeVBAWarnings' = @{ Name = 'Office VBA macro notification settings'; Category = 'Machine Hardening - Software'; Severity = 'High'; Manual = $false; Coverage = 'Prevent'; Techniques = @('T1204.002','T1137','T1059.005'); Mitigations = @('M1042','M1038'); Remediation = 'Office policy ''VBA Macro Notification Settings'' = ''Disable all except digitally signed macros'' (VBAWarnings = 3) or ''Disable all without notification'' (4) for Word, Excel, PowerPoint, Outlook, Access, Visio, Publisher.'; Reference = '' }
    'machine_officeInternetMacros' = @{ Name = 'Block macros in files from the internet'; Category = 'Machine Hardening - Software'; Severity = 'High'; Manual = $false; Coverage = 'Prevent'; Techniques = @('T1566.001','T1059.005'); Mitigations = @('M1038','M1054'); Remediation = 'Office policy ''Block macros from running in Office files from the Internet'' = Enabled (blockcontentexecutionfrominternet = 1) for Word, Excel, PowerPoint, Visio and Access.'; Reference = 'https://learn.microsoft.com/microsoft-365-apps/security/internet-macros-blocked' }
    'machine_SensitiveFiles' = @{ Name = 'Clear-text credentials in files'; Category = 'Machine Hardening - Authentication'; Severity = 'High'; Manual = $false; Coverage = 'Prevent'; Techniques = @('T1552.001','T1552.004'); Mitigations = @('M1022','M1047'); Remediation = 'Remove secrets from files, rotate every exposed credential/private key, and move secrets to a vault (e.g., Azure Key Vault, CyberArk).'; Reference = '' }
    'control_AuditPol' = @{ Name = 'Audit policy'; Category = 'Machine Hardening - Audit'; Severity = 'Medium'; Manual = $true; Coverage = 'Detect'; Techniques = @('T1685.001'); Mitigations = @('M1047'); Remediation = 'Review Audit-Policy output against the Microsoft/CIS advanced audit policy baseline (requires admin).'; Reference = '' }
    'control_LocalUsers' = @{ Name = 'Local users'; Category = 'Machine Hardening - Users'; Severity = 'High'; Manual = $true; Coverage = 'Prevent'; Techniques = @('T1078.003'); Mitigations = @('M1026','M1027'); Remediation = 'All local users should be disabled or LAPS-managed; deny local accounts network logon (''Deny access to this computer from the network'': Local account).'; Reference = '' }
    'control_LocalAdminRes' = @{ Name = 'Local administrators in Restricted Groups'; Category = 'Machine Hardening - Users'; Severity = 'Low'; Manual = $true; Coverage = 'Prevent'; Techniques = @('T1098'); Mitigations = @('M1026'); Remediation = 'Manage local Administrators membership centrally (Restricted Groups / Group Policy Preferences / Intune LocalUsersAndGroups).'; Reference = '' }
    'control_DomainAdminsAcc' = @{ Name = 'Domain admin access tiering'; Category = 'Machine Hardening - Users'; Severity = 'High'; Manual = $true; Coverage = 'Prevent'; Techniques = @('T1078.002'); Mitigations = @('M1026'); Remediation = 'Deny Tier-0 accounts logon to lower-tier hosts (Deny log on locally / through RDS / as a batch job / as a service), or use Authentication Policy Silos.'; Reference = '' }
    'control_SvcAcc' = @{ Name = 'Service accounts interactive logon'; Category = 'Machine Hardening - Operation system'; Severity = 'High'; Manual = $true; Coverage = 'Prevent'; Techniques = @('T1078.002'); Mitigations = @('M1026','M1018'); Remediation = 'Deny service accounts interactive and RDP logon; prefer gMSA/dMSA.'; Reference = '' }
    'control_LocalAndDomainPassPol' = @{ Name = 'Local and domain password policies'; Category = 'Machine Hardening - Authentication'; Severity = 'Medium'; Manual = $true; Coverage = 'Prevent'; Techniques = @('T1110'); Mitigations = @('M1027'); Remediation = 'Minimum 14 characters, lockout threshold, banned-password list (Entra Password Protection) per organizational policy.'; Reference = '' }
    'control_SharePerm' = @{ Name = 'Overly permissive shares'; Category = 'Machine Hardening - Operation system'; Severity = 'Medium'; Manual = $true; Coverage = 'Prevent'; Techniques = @('T1039','T1135'); Mitigations = @('M1028'); Remediation = 'Remove Everyone/Authenticated Users write access from share and NTFS ACLs; review the Shares output.'; Reference = '' }
    'control_ClearPass' = @{ Name = 'No clear-text passwords in files'; Category = 'Machine Hardening - Authentication'; Severity = 'High'; Manual = $true; Coverage = 'Prevent'; Techniques = @('T1552.001'); Mitigations = @('M1022','M1047'); Remediation = 'Run with -EnableSensitiveInfoSearch to automate this control.'; Reference = '' }
    'control_NumOfUsersAndGroups' = @{ Name = 'Local administrator group membership'; Category = 'Machine Hardening - Users'; Severity = 'Medium'; Manual = $true; Coverage = 'Prevent'; Techniques = @('T1078.003'); Mitigations = @('M1026'); Remediation = 'Keep local Administrators to the built-in account (LAPS managed) plus one scoped admin group.'; Reference = '' }
    'control_UserRights' = @{ Name = 'User Rights Assignment'; Category = 'Machine Hardening - Users'; Severity = 'High'; Manual = $true; Coverage = 'Prevent'; Techniques = @('T1134.001'); Mitigations = @('M1026'); Remediation = 'Ensure SeImpersonate/SeAssignPrimaryToken/SeDebug/SeBackup/SeRestore/SeTakeOwnership/SeLoadDriver/SeTcb/SeCreateToken are not granted to non-admins (Security-Policy.inf).'; Reference = '' }
    'control_SvcPer' = @{ Name = 'Service privileges'; Category = 'Machine Hardening - Operation system'; Severity = 'Medium'; Manual = $true; Coverage = 'Prevent'; Techniques = @('T1543.003'); Mitigations = @('M1018'); Remediation = 'Run services as virtual accounts / LocalService / gMSA; avoid LocalSystem and domain admin service accounts.'; Reference = '' }
    'control_MalProcSrvSoft' = @{ Name = 'Unwanted processes, services and software'; Category = 'Machine Hardening - Operation system'; Severity = 'High'; Manual = $true; Coverage = 'Prevent'; Techniques = @('T1219'); Mitigations = @('M1038','M1042'); Remediation = 'Review Services, Process-list, Software and Netstat outputs for unapproved RMM/remote-access and unknown software.'; Reference = '' }
    'control_EventLog' = @{ Name = 'Event log forwarding to SIEM'; Category = 'Machine Hardening - Audit'; Severity = 'Low'; Manual = $true; Coverage = 'Detect'; Techniques = @('T1685.005'); Mitigations = @('M1029'); Remediation = 'Forward Security, System, PowerShell and Sysmon logs to the SIEM (e.g., Microsoft Sentinel via AMA/DCR).'; Reference = '' }
    'control_HostFW' = @{ Name = 'Host firewall inbound rules'; Category = 'Machine Hardening - Network Access'; Severity = 'High'; Manual = $true; Coverage = 'Prevent'; Techniques = @('T1021'); Mitigations = @('M1035'); Remediation = 'Review Windows-Firewall-Rules CSV: inbound allow rules should be scoped to management subnets (host isolation).'; Reference = '' }
}
#endregion

#region Infrastructure (output, logging, data providers, finding model)
# Every access to the registry, CIM, cmdlets or native tools goes through the Get-WA*/Invoke-WA* wrappers
# below. This keeps the checks deterministic and lets the Pester tests mock the host completely.

function Write-WAScreen {
    [CmdletBinding()]
    param ([string]$Text, [ConsoleColor]$Color = [ConsoleColor]::Yellow)
    if (-not $script:WAQuiet) { Write-Host $Text -ForegroundColor $Color }
}

function Get-WAFileName {
    [CmdletBinding()]
    param ([Parameter(Mandatory = $true)][string]$Name, [string]$Extension = '.txt')
    $hostPart = 'host'
    if ($script:WACtx -and $script:WACtx.Hostname) { $hostPart = $script:WACtx.Hostname }
    return ('{0}_{1}{2}' -f $Name, $hostPart, $Extension)
}

function Write-WAFile {
    # Appends text (string or array of lines) to an evidence file. Creates the file on first write.
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)][string]$File,
        [AllowNull()][AllowEmptyCollection()][object[]]$Text,
        [string]$Path
    )
    if (-not $Path) { $Path = $script:WACtx.DetailPath }
    $full = Join-Path -Path $Path -ChildPath $File
    $lines = [System.Collections.Generic.List[string]]@()
    foreach ($t in @($Text)) {
        if ($null -eq $t) { $lines.Add('') } else { $lines.Add([string]$t) }
    }
    try {
        [System.IO.File]::AppendAllText($full, (($lines -join [Environment]::NewLine) + [Environment]::NewLine), $script:WAUtf8Bom)
    }
    catch {
        Write-Verbose ("Write-WAFile failed for {0}: {1}" -f $full, $_.Exception.Message)
    }
}

function Write-WALog {
    [CmdletBinding()]
    param ([string]$Message)
    if (-not $script:WACtx -or -not $script:WACtx.RootPath) { Write-Verbose $Message; return }
    $stamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    Write-WAFile -Path $script:WACtx.RootPath -File (Get-WAFileName -Name 'Log') -Text ("{0} {1}" -f $stamp, $Message)
}

function Write-WACsv {
    # CSV writer that produces UTF-8 with BOM on every PowerShell version (Excel-friendly).
    [CmdletBinding()]
    param ([Parameter(Mandatory = $true)][string]$FullPath, [AllowNull()][object[]]$InputObject)
    if (-not $InputObject -or @($InputObject).Count -eq 0) { return }
    try {
        $csv = @($InputObject) | ConvertTo-Csv -NoTypeInformation
        [System.IO.File]::WriteAllText($FullPath, (($csv -join [Environment]::NewLine) + [Environment]::NewLine), $script:WAUtf8Bom)
    }
    catch { Write-WALog ("Write-WACsv failed for {0}: {1}" -f $FullPath, $_.Exception.Message) }
}

function ConvertTo-WARegPath {
    [CmdletBinding()]
    param ([ValidateSet('HKLM', 'HKCU')][string]$Hive = 'HKLM', [Parameter(Mandatory = $true)][string]$Path)
    return ('{0}:\{1}' -f $Hive, $Path.Trim().TrimStart('\').TrimEnd('\'))
}

function Get-WARegValue {
    # Returns the data of a single registry value, or $null when the key/value does not exist.
    [CmdletBinding()]
    param (
        [ValidateSet('HKLM', 'HKCU')][string]$Hive = 'HKLM',
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Name
    )
    try {
        $item = Get-ItemProperty -LiteralPath (ConvertTo-WARegPath -Hive $Hive -Path $Path) -Name $Name -ErrorAction Stop
        return $item.$Name
    }
    catch { return $null }
}

function Get-WARegKeyValues {
    # Returns an ordered hashtable (value name -> data) for a key, or $null when the key does not exist.
    [CmdletBinding()]
    param ([ValidateSet('HKLM', 'HKCU')][string]$Hive = 'HKLM', [Parameter(Mandatory = $true)][string]$Path)
    try {
        $key = Get-Item -LiteralPath (ConvertTo-WARegPath -Hive $Hive -Path $Path) -ErrorAction Stop
        $result = [ordered]@{}
        foreach ($n in $key.GetValueNames()) { $result[$n] = $key.GetValue($n) }
        return $result
    }
    catch { return $null }
}

function Get-WARegSubKeyNames {
    [CmdletBinding()]
    param ([ValidateSet('HKLM', 'HKCU')][string]$Hive = 'HKLM', [Parameter(Mandatory = $true)][string]$Path)
    try {
        return @(Get-ChildItem -LiteralPath (ConvertTo-WARegPath -Hive $Hive -Path $Path) -ErrorAction Stop | ForEach-Object { $_.PSChildName })
    }
    catch { return @() }
}

function Get-WARegValueList {
    # Policy "list" keys (e.g. CredentialsDelegation\AllowDefaultCredentials, ModuleLogging\ModuleNames)
    # store entries as numbered values whose DATA is the entry. Returns the data values.
    [CmdletBinding()]
    param ([ValidateSet('HKLM', 'HKCU')][string]$Hive = 'HKLM', [Parameter(Mandatory = $true)][string]$Path)
    $values = Get-WARegKeyValues -Hive $Hive -Path $Path
    if ($null -eq $values) { return @() }
    $list = @()
    foreach ($k in $values.Keys) {
        $data = [string]$values[$k]
        if ($data) { $list += $data } elseif ($k) { $list += [string]$k }
    }
    return $list
}

function Get-WACimInstance {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWMICmdlet', '', Justification = 'Fallback for PowerShell 2.0 hosts without CIM cmdlets')]
    [CmdletBinding()]
    param ([Parameter(Mandatory = $true)][string]$ClassName, [string]$Namespace = 'root\cimv2', [string]$Filter)
    try {
        if (Get-Command -Name Get-CimInstance -ErrorAction SilentlyContinue) {
            $p = @{ ClassName = $ClassName; Namespace = $Namespace; ErrorAction = 'Stop' }
            if ($Filter) { $p.Filter = $Filter }
            return Get-CimInstance @p
        }
        $w = @{ Class = $ClassName; Namespace = $Namespace; ErrorAction = 'Stop' }
        if ($Filter) { $w.Filter = $Filter }
        return Get-WmiObject @w
    }
    catch {
        Write-WALog ("CIM query failed: {0} ({1}): {2}" -f $ClassName, $Namespace, $_.Exception.Message)
        return $null
    }
}

function Invoke-WANative {
    # Runs a native tool and returns its output as string lines (stderr merged). Never throws.
    [CmdletBinding()]
    param ([Parameter(Mandatory = $true)][string]$FilePath, [string[]]$ArgumentList = @())
    $prev = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $out = & $FilePath @ArgumentList 2>&1
        return @($out | ForEach-Object { [string]$_ })
    }
    catch {
        Write-WALog ("Native command failed: {0} {1}: {2}" -f $FilePath, ($ArgumentList -join ' '), $_.Exception.Message)
        return @()
    }
    finally { $ErrorActionPreference = $prev }
}

function Invoke-WACmdlet {
    # Calls a cmdlet only if it exists on this host; returns $null on absence or failure.
    [CmdletBinding()]
    param ([Parameter(Mandatory = $true)][string]$Name, [hashtable]$Parameters = @{})
    if (-not (Get-Command -Name $Name -ErrorAction SilentlyContinue)) { return $null }
    $p = @{}
    foreach ($k in $Parameters.Keys) { $p[$k] = $Parameters[$k] }
    $p['ErrorAction'] = 'Stop'
    try { return & $Name @p }
    catch {
        Write-WALog ("{0} failed: {1}" -f $Name, $_.Exception.Message)
        return $null
    }
}

function Get-WAService {
    [CmdletBinding()]
    param ([Parameter(Mandatory = $true)][string]$Name)
    try { return Get-Service -Name $Name -ErrorAction Stop } catch { return $null }
}

function Test-WAIsAdmin {
    [CmdletBinding()]
    param ()
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($id)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch { return $false }
}

function Test-WAOSVersion {
    # True when the host OS version is >= the given version (e.g. '6.3', '10.0.14393').
    [CmdletBinding()]
    param ([Parameter(Mandatory = $true)][version]$Minimum)
    return ($script:WACtx.WinVersion -ge $Minimum)
}

function Test-WADomainConnectivity {
    # Replaces Test-ComputerSecureChannel (not available in PowerShell 7) with a cached, multi-method test.
    [CmdletBinding()]
    param ()
    $ctx = $script:WACtx
    if ($ctx.Cache.ContainsKey('DomainConnectivity')) { return $ctx.Cache['DomainConnectivity'] }
    $result = $false
    if (-not $ctx.PartOfDomain) { $result = $false }
    elseif ($ctx.IsDC) { $result = $true }
    else {
        $done = $false
        if (Get-Command -Name Test-ComputerSecureChannel -ErrorAction SilentlyContinue) {
            try { $result = [bool](Test-ComputerSecureChannel -ErrorAction Stop); $done = $true } catch { $done = $false }
        }
        if (-not $done) {
            $out = Invoke-WANative -FilePath 'nltest.exe' -ArgumentList @("/sc_query:$($ctx.DomainName)")
            $result = [bool](@($out) -match 'NERR_Success')
        }
    }
    $ctx.Cache['DomainConnectivity'] = $result
    return $result
}

function New-WAContext {
    # Builds the run context. Every discovered value can be overridden (used by the Pester tests).
    [CmdletBinding()]
    param (
        [string]$OutputPath = (Get-Location).Path,
        [string]$Hostname,
        [ValidateSet(0, 1, 2, 3)][int]$ProductType = 0,
        [version]$WinVersion,
        [Nullable[bool]]$IsAdmin,
        [Nullable[bool]]$PartOfDomain,
        [string]$DomainName,
        [string]$OSCaption,
        [int]$PSVersionMajor = $PSVersionTable.PSVersion.Major,
        [switch]$NoDiscovery,
        [switch]$NoCreateFolders,
        [switch]$EnableSensitiveInfoSearch,
        [switch]$IncludeSecretValues,
        [string[]]$SensitiveSearchPath,
        [switch]$SkipNetworkTests,
        [switch]$SkipGpoCollection
    )
    $os = $null; $cs = $null
    if (-not $NoDiscovery) {
        $os = Get-WACimInstance -ClassName Win32_OperatingSystem
        $cs = Get-WACimInstance -ClassName Win32_ComputerSystem
    }
    if (-not $Hostname) { $Hostname = [Environment]::MachineName }
    if ($ProductType -eq 0) { if ($os) { $ProductType = [int]$os.ProductType } else { $ProductType = 1 } }
    if (-not $WinVersion) { if ($os -and $os.Version) { $WinVersion = [version]$os.Version } else { $WinVersion = [Environment]::OSVersion.Version } }
    if ($null -eq $IsAdmin) { $IsAdmin = if ($NoDiscovery) { $false } else { Test-WAIsAdmin } }
    if ($null -eq $PartOfDomain) { $PartOfDomain = if ($cs) { [bool]$cs.PartOfDomain } else { $false } }
    if (-not $DomainName -and $PartOfDomain -and $cs) { $DomainName = [string]$cs.Domain }
    if (-not $OSCaption) { if ($os) { $OSCaption = [string]$os.Caption } else { $OSCaption = [Environment]::OSVersion.VersionString } }

    $role = switch ($ProductType) { 1 { 'Workstation' } 2 { 'Domain Controller' } 3 { 'Member Server' } default { 'Unknown' } }
    $suffix = if ($PartOfDomain -and $DomainName) { $DomainName } else {
        ($OSCaption -replace 'Microsoft', '' -replace 'Windows', 'Win' -replace '\s', '')
    }
    $invalid = [System.IO.Path]::GetInvalidFileNameChars()
    $folderName = ('{0}_{1}_{2}' -f $Hostname, $suffix, (Get-Date).ToString('yyyyMMdd-HHmmss'))
    foreach ($c in $invalid) { $folderName = $folderName.Replace([string]$c, '') }
    $root = Join-Path -Path $OutputPath -ChildPath $folderName

    $ctx = [pscustomobject]@{
        Hostname                  = $Hostname
        OSCaption                 = $OSCaption
        WinVersion                = $WinVersion
        ProductType               = $ProductType
        Role                      = $role
        IsServer                  = ($ProductType -eq 2 -or $ProductType -eq 3)
        IsDC                      = ($ProductType -eq 2)
        PartOfDomain              = [bool]$PartOfDomain
        DomainName                = $DomainName
        IsAdmin                   = [bool]$IsAdmin
        PSVersionMajor            = $PSVersionMajor
        RootPath                  = $root
        DetailPath                = (Join-Path -Path $root -ChildPath 'Detailed information')
        EnableSensitiveInfoSearch = [bool]$EnableSensitiveInfoSearch
        IncludeSecretValues       = [bool]$IncludeSecretValues
        SensitiveSearchPath       = $(if ($SensitiveSearchPath) { @($SensitiveSearchPath) } else { @('C:\Temp', [Environment]::GetFolderPath('Desktop'), 'C:\inetpub\wwwroot') })
        SkipNetworkTests          = [bool]$SkipNetworkTests
        SkipGpoCollection         = [bool]$SkipGpoCollection
        StartTime                 = Get-Date
        LastBoot                  = $(if ($os) { $os.LastBootUpTime } else { $null })
        User                      = [Environment]::UserDomainName + '\' + [Environment]::UserName
        Findings                  = [System.Collections.Generic.List[object]]@()
        Errors                    = [System.Collections.Generic.List[object]]@()
        Timings                   = [System.Collections.Generic.List[object]]@()
        Cache                     = @{}
    }
    $script:WACtx = $ctx
    if (-not $NoCreateFolders) {
        New-Item -Path $ctx.DetailPath -ItemType Directory -Force | Out-Null
    }
    return $ctx
}

function Add-WAFinding {
    # Adds (or replaces, for the same CheckID + Scope) a result enriched with catalog + ATT&CK metadata.
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)][string]$CheckID,
        [Parameter(Mandatory = $true)][ValidateSet('Pass', 'Fail', 'Warning', 'Manual', 'Info', 'NotApplicable', 'Error')][string]$Status,
        [string]$Finding,
        [string]$Evidence,
        [string]$Comment,
        [string]$RelatedFile,
        [string]$Scope = '',
        [ValidateSet('', 'Critical', 'High', 'Medium', 'Low', 'Informational')][string]$Severity = ''
    )
    $meta = $script:WACheckCatalog[$CheckID]
    if ($null -eq $meta) { throw "Unknown CheckID '$CheckID'. Add it to the check catalog." }
    if (-not $Severity) { $Severity = $meta.Severity }

    $tactics = @()
    foreach ($t in $meta.Techniques) {
        foreach ($tac in $script:WATechniques[$t].Tactics) { if ($tactics -notcontains $tac) { $tactics += $tac } }
    }
    $tactics = @($tactics | Sort-Object { $script:WATactics[$_].Order })

    $result = [pscustomobject][ordered]@{
        CheckID         = $CheckID
        Category        = $meta.Category
        CheckName       = $meta.Name
        Scope           = $Scope
        Status          = $Status
        LegacyStatus    = $script:WALegacyStatus[$Status]
        Severity        = $Severity
        Finding         = $Finding
        Evidence        = $Evidence
        Comments        = $Comment
        RelatedFile     = $RelatedFile
        Remediation     = $meta.Remediation
        Reference       = $meta.Reference
        Coverage        = $meta.Coverage
        Techniques      = @($meta.Techniques)
        TechniqueNames  = @($meta.Techniques | ForEach-Object { $script:WATechniques[$_].Name })
        Tactics         = @($tactics | ForEach-Object { $script:WATactics[$_].Name })
        Mitigations     = @($meta.Mitigations)
        MitigationNames = @($meta.Mitigations | ForEach-Object { $script:WAMitigations[$_] })
        Timestamp       = (Get-Date).ToString('s')
    }
    $list = $script:WACtx.Findings
    for ($i = $list.Count - 1; $i -ge 0; $i--) {
        if ($list[$i].CheckID -eq $CheckID -and $list[$i].Scope -eq $Scope) {
            Write-WALog ("Add-WAFinding: {0} [{1}] reported twice - keeping the latest result" -f $CheckID, $Scope)
            $list.RemoveAt($i)
        }
    }
    $list.Add($result)
    return
}

function Invoke-WACheck {
    # Runs one collection/check function with error isolation and timing.
    [CmdletBinding()]
    param ([Parameter(Mandatory = $true)][string]$Function, [Parameter(Mandatory = $true)][string]$Name)
    $sw = [Diagnostics.Stopwatch]::StartNew()
    try {
        & $Function -Name $Name
    }
    catch {
        $msg = $_.Exception.Message
        $line = $_.InvocationInfo.ScriptLineNumber
        Write-WALog ("ERROR in {0} (line {1}): {2}" -f $Function, $line, $msg)
        Write-WAScreen -Text ("  ! {0} failed: {1}" -f $Function, $msg) -Color Red
        $script:WACtx.Errors.Add([pscustomobject]@{ Function = $Function; Line = $line; Message = $msg })
    }
    finally {
        $sw.Stop()
        $script:WACtx.Timings.Add([pscustomobject]@{ Function = $Function; Seconds = [math]::Round($sw.Elapsed.TotalSeconds, 2) })
    }
}

function Format-WASize {
    [CmdletBinding()]
    param ([double]$Kilobytes)
    if ($Kilobytes -ge 1048576) { return ('{0:N1} GB' -f ($Kilobytes / 1048576)) }
    if ($Kilobytes -ge 1024) { return ('{0:N0} MB' -f ($Kilobytes / 1024)) }
    return ('{0:N0} KB' -f $Kilobytes)
}

$script:WASddlAlias = @{
    'BA' = 'S-1-5-32-544'; 'BU' = 'S-1-5-32-545'; 'BG' = 'S-1-5-32-546'; 'PU' = 'S-1-5-32-547'; 'AO' = 'S-1-5-32-548'; 'SO' = 'S-1-5-32-549'
    'BO' = 'S-1-5-32-551'; 'RD' = 'S-1-5-32-555'; 'AU' = 'S-1-5-11'; 'WD' = 'S-1-1-0'; 'SY' = 'S-1-5-18'; 'LS' = 'S-1-5-19'; 'NS' = 'S-1-5-20'
    'IU' = 'S-1-5-4'; 'NU' = 'S-1-5-2'; 'SU' = 'S-1-5-6'; 'AN' = 'S-1-5-7'
}
$script:WAWellKnownSid = @{
    'S-1-1-0' = 'Everyone'; 'S-1-5-11' = 'Authenticated Users'; 'S-1-5-4' = 'INTERACTIVE'; 'S-1-5-18' = 'SYSTEM'; 'S-1-5-32-544' = 'Administrators'
    'S-1-5-32-545' = 'Users'; 'S-1-5-32-546' = 'Guests'; 'S-1-5-32-547' = 'Power Users'; 'S-1-5-32-549' = 'Server Operators'; 'S-1-5-32-555' = 'Remote Desktop Users'
    'S-1-5-2' = 'NETWORK'; 'S-1-5-6' = 'SERVICE'; 'S-1-5-3' = 'BATCH'; 'S-1-5-7' = 'ANONYMOUS LOGON'
}

function ConvertFrom-WASidBytes {
    [CmdletBinding()]
    param ([Parameter(Mandatory = $true)][byte[]]$Bytes, [int]$Offset = 0)
    $count = $Bytes[$Offset + 1]
    [uint64]$auth = 0
    for ($j = 0; $j -lt 6; $j++) { $auth = ($auth * 256) + $Bytes[$Offset + 2 + $j] }
    $sb = 'S-{0}-{1}' -f $Bytes[$Offset], $auth
    for ($j = 0; $j -lt $count; $j++) { $sb += '-' + [BitConverter]::ToUInt32($Bytes, $Offset + 8 + 4 * $j) }
    return $sb
}

function ConvertFrom-WASecurityDescriptorBytes {
    # Minimal, platform-independent parser for a self-relative security descriptor (e.g. SrvsvcSessionInfo).
    # Returns @{ Valid; Aces } - Aces holds the DACL entries (Type, SID, Mask). Valid is $false for malformed data.
    [CmdletBinding()]
    param ([byte[]]$Bytes)
    try {
        $invalid = [pscustomobject]@{ Valid = $false; Aces = @() }
        if ($null -eq $Bytes -or $Bytes.Length -lt 20 -or $Bytes[0] -ne 1) { return $invalid }
        $control = [BitConverter]::ToUInt16($Bytes, 2)
        if (($control -band 0x8000) -eq 0) { return $invalid }          # SE_SELF_RELATIVE
        $daclOff = [int][BitConverter]::ToUInt32($Bytes, 16)
        if (($control -band 0x0004) -eq 0 -or $daclOff -eq 0) { return [pscustomobject]@{ Valid = $true; Aces = @() } }   # no DACL = full access
        $aceCount = [BitConverter]::ToUInt16($Bytes, $daclOff + 4)
        $pos = $daclOff + 8
        $aces = @()
        for ($i = 0; $i -lt $aceCount; $i++) {
            $type = $Bytes[$pos]
            $size = [BitConverter]::ToUInt16($Bytes, $pos + 2)
            $mask = [BitConverter]::ToUInt32($Bytes, $pos + 4)
            $typeName = switch ($type) { 0 { 'Allow' } 1 { 'Deny' } default { 'Type' + $type } }
            $aces += [pscustomobject]@{ Type = $typeName; SID = (ConvertFrom-WASidBytes -Bytes $Bytes -Offset ($pos + 8)); Mask = ('0x{0:X}' -f $mask) }
            if ($size -lt 8) { return $invalid }
            $pos += $size
        }
        return [pscustomobject]@{ Valid = $true; Aces = $aces }
    }
    catch { return [pscustomobject]@{ Valid = $false; Aces = @() } }
}

function ConvertFrom-WASddlAces {
    # Extracts DACL ACEs from an SDDL string (platform independent). Returns Type/SID pairs.
    [CmdletBinding()]
    param ([string]$Sddl)
    if (-not $Sddl) { return }
    $dacl = $Sddl
    $i = $Sddl.IndexOf('D:')
    if ($i -ge 0) { $dacl = $Sddl.Substring($i + 2); $s = $dacl.IndexOf('S:'); if ($s -ge 0) { $dacl = $dacl.Substring(0, $s) } }
    foreach ($m in [regex]::Matches($dacl, '\(([^;()]*);[^;()]*;[^;()]*;[^;()]*;[^;()]*;([^;()]+)[^()]*\)')) {
        $t = switch ($m.Groups[1].Value) { 'A' { 'Allow' } 'D' { 'Deny' } default { $m.Groups[1].Value } }
        $who = $m.Groups[2].Value
        if ($script:WASddlAlias.ContainsKey($who)) { $who = $script:WASddlAlias[$who] }
        [pscustomobject]@{ Type = $t; SID = $who }
    }
}

function Resolve-WASidName {
    [CmdletBinding()]
    param ([string]$Sid)
    if ($script:WAWellKnownSid.ContainsKey($Sid)) { return $script:WAWellKnownSid[$Sid] }
    try { return (New-Object Security.Principal.SecurityIdentifier($Sid)).Translate([Security.Principal.NTAccount]).Value } catch { return $Sid }
}

function Test-WAWildcardTarget {
    # True for delegation targets that match any host (e.g. '*', 'TERMSRV/*', 'WSMAN/*').
    [CmdletBinding()]
    param ([string[]]$Entries)
    foreach ($e in $Entries) { if ($e -eq '*' -or $e -match '/\*$') { return $true } }
    return $false
}
#endregion

#region Evidence collection (no pass/fail logic - raw data for the analyst)

function Get-WAWhoAmI {
    # v1: dataWhoAmI
    [CmdletBinding()]
    param ([string]$Name)
    $file = Get-WAFileName -Name $Name
    Write-WAScreen 'Running whoami...'
    Write-WALog 'running Get-WAWhoAmI'
    Write-WAFile -File $file -Text 'Output of "whoami /all":', ''
    # whoami /all fails to resolve claims when the domain is unreachable - fall back to the partial output.
    if ($script:WACtx.PartOfDomain -and -not (Test-WADomainConnectivity)) {
        Write-WAFile -File $file -Text (Invoke-WANative -FilePath 'whoami.exe' -ArgumentList @('/user', '/groups', '/priv'))
    }
    else {
        Write-WAFile -File $file -Text (Invoke-WANative -FilePath 'whoami.exe' -ArgumentList @('/all'))
    }
    Write-WAFile -File $file -Text '', ('=' * 100),
    'These privileges allow local privilege escalation to SYSTEM and must not be granted to non-admin users:',
    'SeImpersonatePrivilege, SeAssignPrimaryTokenPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege,',
    'SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege',
    'Reference: MITRE ATT&CK T1134 Access Token Manipulation - https://attack.mitre.org/techniques/T1134/'
}

function Get-WAIpSettings {
    # v1: dataIpSettings
    [CmdletBinding()]
    param ([string]$Name)
    Write-WAScreen 'Running ipconfig...'
    Write-WALog 'running Get-WAIpSettings'
    $cfg = Invoke-WACmdlet -Name 'Get-NetIPConfiguration' -Parameters @{ Detailed = $true }
    if ($cfg) {
        $rows = foreach ($c in @($cfg)) {
            foreach ($ip in @($c.AllIPAddresses)) {
                [pscustomobject]@{
                    InterfaceAlias = $c.InterfaceAlias; InterfaceDescription = $c.InterfaceDescription
                    IPAddress = $ip.IPAddress; PrefixLength = $ip.PrefixLength; AddressFamily = [string]$ip.AddressFamily
                    DnsServers = (@($c.DNSServer | ForEach-Object { $_.ServerAddresses }) -join ';')
                    Gateway = (@($c.IPv4DefaultGateway | ForEach-Object { $_.NextHop }) -join ';')
                }
            }
        }
        Write-WACsv -FullPath (Join-Path $script:WACtx.DetailPath (Get-WAFileName -Name $Name -Extension '.csv')) -InputObject $rows
    }
    $file = Get-WAFileName -Name $Name
    Write-WAFile -File $file -Text 'Output of "ipconfig /all":', '', (Invoke-WANative -FilePath 'ipconfig.exe' -ArgumentList @('/all'))
}

function Get-WANetConnections {
    # v1: getNetCon
    [CmdletBinding()]
    param ([string]$Name)
    Write-WAScreen 'Running netstat...'
    Write-WALog 'running Get-WANetConnections'
    $tcp = Invoke-WACmdlet -Name 'Get-NetTCPConnection'
    if ($tcp) {
        $procs = @{}
        foreach ($p in @(Get-Process -ErrorAction SilentlyContinue)) { $procs[[int]$p.Id] = $p.ProcessName }
        $rows = foreach ($c in @($tcp)) {
            [pscustomobject]@{
                LocalAddress = $c.LocalAddress; LocalPort = $c.LocalPort; RemoteAddress = $c.RemoteAddress; RemotePort = $c.RemotePort
                State = [string]$c.State; OwningProcess = $c.OwningProcess; Process = $procs[[int]$c.OwningProcess]
            }
        }
        Write-WACsv -FullPath (Join-Path $script:WACtx.DetailPath (Get-WAFileName -Name $Name -Extension '.csv')) -InputObject $rows
    }
    else {
        $file = Get-WAFileName -Name $Name
        Write-WAFile -File $file -Text '============= netstat -nao =============', (Invoke-WANative -FilePath 'netstat.exe' -ArgumentList @('-nao'))
        if ($script:WACtx.IsAdmin) {
            Write-WAFile -File $file -Text '============= netstat -naob =============', (Invoke-WANative -FilePath 'netstat.exe' -ArgumentList @('-naob'))
        }
    }
}

function Get-WAGpo {
    # v1: dataGPO. Fixed: invalid "gpresult <path>" fallback, duplicate folder creation error,
    # Test-ComputerSecureChannel dependency (absent in PowerShell 7).
    [CmdletBinding()]
    param ([string]$Name)
    Write-WALog 'running Get-WAGpo'
    $ctx = $script:WACtx
    if ($ctx.SkipGpoCollection) { Write-WALog 'Get-WAGpo: skipped by -SkipGpoCollection'; return }
    if (-not $ctx.PartOfDomain) { Write-WALog 'Get-WAGpo: not domain joined - skipped'; return }
    if (-not (Test-WADomainConnectivity)) {
        Write-WAScreen 'Unable to get GPO configuration - no connectivity to the domain' Red
        Write-WALog 'Get-WAGpo: no connectivity to the domain'
        return
    }
    Write-WAScreen 'Running GPResult to get GPOs...'
    $htmlPath = Join-Path $ctx.DetailPath (Get-WAFileName -Name $Name -Extension '.html')
    Invoke-WANative -FilePath 'gpresult.exe' -ArgumentList @('/f', '/h', $htmlPath) | Out-Null
    if (-not (Test-Path -LiteralPath $htmlPath)) {
        Write-WALog 'Get-WAGpo: HTML export failed - exporting verbose text'
        Write-WAFile -File (Get-WAFileName -Name $Name) -Text (Invoke-WANative -FilePath 'gpresult.exe' -ArgumentList @('/z'))
    }
    $xmlPath = Join-Path $ctx.DetailPath (Get-WAFileName -Name $Name -Extension '.xml')
    Invoke-WANative -FilePath 'gpresult.exe' -ArgumentList @('/f', '/x', $xmlPath) | Out-Null
    if (-not (Test-Path -LiteralPath $xmlPath)) { Write-WALog 'Get-WAGpo: XML export failed'; return }
    try { [xml]$rsop = Get-Content -LiteralPath $xmlPath -Raw -ErrorAction Stop } catch { Write-WALog 'Get-WAGpo: cannot parse RSoP XML'; return }

    $gpoFolder = Join-Path $ctx.DetailPath 'Applied GPOs'
    New-Item -Path $gpoFolder -ItemType Directory -Force | Out-Null
    $maxBytes = 5MB
    $seen = @{}
    $gpos = @($rsop.Rsop.ComputerResults.GPO) + @($rsop.Rsop.UserResults.GPO)
    foreach ($gpo in $gpos) {
        if ($null -eq $gpo -or $gpo.Name -eq 'Local Group Policy') { continue }
        if ($gpo.Enabled -ne 'true' -or $gpo.IsValid -ne 'true') { continue }
        $guid = [string]$gpo.Path.Identifier.'#text'
        if (-not $guid) { $guid = [string]$gpo.Name }
        if ($seen.ContainsKey($guid)) { continue }
        $seen[$guid] = $true
        $src = "\\$($ctx.DomainName)\SYSVOL\$($ctx.DomainName)\Policies\$guid\"
        try {
            $size = (Get-ChildItem -LiteralPath $src -Recurse -File -ErrorAction Stop | Measure-Object -Property Length -Sum).Sum
            if ($size -le $maxBytes) {
                $safe = [string]$gpo.Name
                foreach ($c in [System.IO.Path]::GetInvalidFileNameChars()) { $safe = $safe.Replace([string]$c, '_') }
                Copy-Item -LiteralPath $src -Destination (Join-Path $gpoFolder $safe) -Recurse -Force -ErrorAction Stop
            }
            else { Write-WALog ("Get-WAGpo: {0} skipped ({1:N1} MB > 5 MB)" -f $gpo.Name, ($size / 1MB)) }
        }
        catch { Write-WALog ("Get-WAGpo: cannot copy {0}: {1}" -f $src, $_.Exception.Message) }
    }
}

function Get-WASecurityPolicy {
    # v1: dataSecurityPolicy
    [CmdletBinding()]
    param ([string]$Name)
    Write-WALog 'running Get-WASecurityPolicy'
    if (-not $script:WACtx.IsAdmin) {
        Write-WAScreen 'Unable to export security policy - elevation required' Red
        Write-WALog 'Get-WASecurityPolicy: elevation required'
        return
    }
    Write-WAScreen 'Exporting security policy (secedit)...'
    $infPath = Join-Path $script:WACtx.DetailPath (Get-WAFileName -Name $Name -Extension '.inf')
    Invoke-WANative -FilePath 'secedit.exe' -ArgumentList @('/export', '/cfg', $infPath, '/quiet') | Out-Null
    if (-not (Test-Path -LiteralPath $infPath)) { Write-WALog 'Get-WASecurityPolicy: secedit export failed' }
}

function Get-WAWindowsFeatures {
    # v1: dataWinFeatures. Fixed version logic (5.1 was treated as 6.1+).
    [CmdletBinding()]
    param ([string]$Name)
    Write-WALog 'running Get-WAWindowsFeatures'
    $ctx = $script:WACtx
    $file = Get-WAFileName -Name $Name
    Write-WAScreen 'Getting Windows features...'
    if ($ctx.IsServer) {
        $f = Invoke-WACmdlet -Name 'Get-WindowsFeature'
        if ($f) {
            Write-WACsv -FullPath (Join-Path $ctx.DetailPath (Get-WAFileName -Name $Name -Extension '.csv')) -InputObject @($f | Select-Object Name, DisplayName, Installed, InstallState, FeatureType)
        }
    }
    if ($ctx.IsAdmin) {
        $o = Invoke-WACmdlet -Name 'Get-WindowsOptionalFeature' -Parameters @{ Online = $true }
        if ($o) {
            $ctx.Cache['OptionalFeatures'] = @($o)
            Write-WACsv -FullPath (Join-Path $ctx.DetailPath (Get-WAFileName -Name $Name -Extension '-optional.csv')) -InputObject @($o | Sort-Object FeatureName | Select-Object FeatureName, State)
        }
        else {
            Write-WAFile -File $file -Text '============= dism /online /get-features /format:table =============', (Invoke-WANative -FilePath 'dism.exe' -ArgumentList @('/online', '/get-features', '/format:table'))
        }
    }
    else {
        Write-WAFile -File $file -Text 'Optional features require elevation (Get-WindowsOptionalFeature / dism).'
    }
}

function Get-WAHotfixes {
    # v1: dataInstalledHotfixes. Results cached for the patch-recency check.
    [CmdletBinding()]
    param ([string]$Name)
    Write-WALog 'running Get-WAHotfixes'
    Write-WAScreen 'Getting installed hotfixes...'
    $hf = @(Invoke-WACmdlet -Name 'Get-HotFix')
    $script:WACtx.Cache['HotFix'] = $hf
    $cv = Get-WARegKeyValues -Path 'SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $file = Get-WAFileName -Name $Name
    $build = ''
    if ($cv) { $build = ('{0} {1} build {2}.{3}' -f $cv['ProductName'], $cv['DisplayVersion'], $cv['CurrentBuild'], $cv['UBR']) }
    Write-WAFile -File $file -Text ("OS: {0} | {1}" -f $script:WACtx.OSCaption, $build),
    'Lifecycle: https://learn.microsoft.com/lifecycle/products/ | Release health: https://learn.microsoft.com/windows/release-health/', '',
    'Output of Get-HotFix (newest first):', ($hf | Sort-Object { $_.InstalledOn } -Descending | Format-Table -AutoSize HotFixID, Description, InstalledOn, InstalledBy | Out-String -Width 200)
    Write-WACsv -FullPath (Join-Path $script:WACtx.DetailPath (Get-WAFileName -Name $Name -Extension '.csv')) -InputObject @($hf | Select-Object HotFixID, Description, InstalledOn, InstalledBy, Caption)
}

function Get-WAProcesses {
    # v1: dataRunningProcess
    [CmdletBinding()]
    param ([string]$Name)
    Write-WALog 'running Get-WAProcesses'
    Write-WAScreen 'Getting processes...'
    $procs = $null
    if ($script:WACtx.IsAdmin) { $procs = Invoke-WACmdlet -Name 'Get-Process' -Parameters @{ IncludeUserName = $true } }
    if (-not $procs) { $procs = Get-Process -ErrorAction SilentlyContinue }
    $rows = @($procs | Select-Object ProcessName, Id, UserName, Company, ProductVersion, Path, CPU, WorkingSet64)
    Write-WACsv -FullPath (Join-Path $script:WACtx.DetailPath (Get-WAFileName -Name $Name -Extension '.csv')) -InputObject $rows
}

function Get-WAServices {
    # v1: dataServices. Now CSV incl. PathName; cached for the unquoted path check.
    [CmdletBinding()]
    param ([string]$Name)
    Write-WALog 'running Get-WAServices'
    Write-WAScreen 'Getting services...'
    $svc = @(Get-WACimInstance -ClassName Win32_Service)
    $script:WACtx.Cache['Services'] = $svc
    Write-WACsv -FullPath (Join-Path $script:WACtx.DetailPath (Get-WAFileName -Name $Name -Extension '.csv')) -InputObject @($svc | Sort-Object DisplayName | Select-Object DisplayName, Name, State, StartMode, StartName, PathName)
}

function Get-WAInstalledSoftware {
    # v1: dataInstalledSoftware. Fixed: only the 32-bit (WOW6432Node) hive was read - 64-bit and per-user software were missed.
    [CmdletBinding()]
    param ([string]$Name)
    Write-WALog 'running Get-WAInstalledSoftware'
    Write-WAScreen 'Getting installed software...'
    $roots = @(
        @{ Hive = 'HKLM'; Path = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'; Arch = 'x64' },
        @{ Hive = 'HKLM'; Path = 'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'; Arch = 'x86' },
        @{ Hive = 'HKCU'; Path = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'; Arch = 'User' }
    )
    $rows = [System.Collections.Generic.List[object]]@()
    foreach ($r in $roots) {
        foreach ($sub in (Get-WARegSubKeyNames -Hive $r.Hive -Path $r.Path)) {
            $v = Get-WARegKeyValues -Hive $r.Hive -Path ("{0}\{1}" -f $r.Path, $sub)
            if ($v -and $v['DisplayName']) {
                $rows.Add([pscustomobject]@{ DisplayName = $v['DisplayName']; DisplayVersion = $v['DisplayVersion']; Publisher = $v['Publisher']; InstallDate = $v['InstallDate']; Scope = $r.Arch })
            }
        }
    }
    $script:WACtx.Cache['Software'] = $rows.ToArray()
    Write-WACsv -FullPath (Join-Path $script:WACtx.DetailPath (Get-WAFileName -Name $Name -Extension '.csv')) -InputObject @($rows | Sort-Object DisplayName)
}

function Get-WASharedFolders {
    # v1: dataSharedFolders. Fixed: try/catch never fired (non-terminating errors) so the WMI fallback was dead code.
    [CmdletBinding()]
    param ([string]$Name)
    Write-WALog 'running Get-WASharedFolders'
    Write-WAScreen 'Getting shared folders...'
    $file = Get-WAFileName -Name $Name
    $shares = @(Get-WACimInstance -ClassName Win32_Share)
    Write-WAFile -File $file -Text '============= Shared Folders =============', ($shares | Format-Table -AutoSize Name, Path, Description, Type | Out-String -Width 200)
    foreach ($share in $shares) {
        Write-WAFile -File $file -Text ("============= Share: {0} | Path: {1} =============" -f $share.Name, $share.Path), 'Share permissions:'
        $acc = Invoke-WACmdlet -Name 'Get-SmbShareAccess' -Parameters @{ Name = [string]$share.Name }
        if ($acc) {
            Write-WAFile -File $file -Text ($acc | Format-Table -AutoSize AccountName, AccessControlType, AccessRight | Out-String -Width 200)
        }
        else {
            $sec = Get-WACimInstance -ClassName Win32_LogicalShareSecuritySetting -Filter ("Name='{0}'" -f ([string]$share.Name).Replace("'", "''"))
            if ($null -eq $sec) { Write-WAFile -File $file -Text 'Share permissions not available (not in WMI Win32_LogicalShareSecuritySetting).' }
            else {
                try {
                    $sd = if (Get-Command -Name Invoke-CimMethod -ErrorAction SilentlyContinue) { (Invoke-CimMethod -InputObject $sec -MethodName GetSecurityDescriptor -ErrorAction Stop).Descriptor } else { $sec.GetSecurityDescriptor().Descriptor }
                    foreach ($ace in @($sd.DACL)) {
                        $trustee = if ($ace.Trustee.Domain) { $ace.Trustee.Domain + '\' + $ace.Trustee.Name } else { $ace.Trustee.Name }
                        Write-WAFile -File $file -Text ("Trustee: {0} | Type: {1} | Permission: {2}" -f $trustee, [Security.AccessControl.AceType]$ace.AceType, ($ace.AccessMask -as [Security.AccessControl.FileSystemRights]))
                    }
                }
                catch { Write-WAFile -File $file -Text ('Share permissions could not be read: ' + $_.Exception.Message) }
            }
        }
        Write-WAFile -File $file -Text 'NTFS permissions:'
        if ($share.Path) {
            try { Write-WAFile -File $file -Text ((Get-Acl -LiteralPath $share.Path -ErrorAction Stop).Access | Format-Table -AutoSize IdentityReference, FileSystemRights, AccessControlType, IsInherited | Out-String -Width 200) }
            catch { Write-WAFile -File $file -Text 'NTFS permissions could not be read.' }
        }
    }
}

function Get-WAAccountPolicy {
    # v1: dataAccountPolicy
    [CmdletBinding()]
    param ([string]$Name)
    Write-WALog 'running Get-WAAccountPolicy'
    Write-WAScreen 'Getting local and domain account policy...'
    $file = Get-WAFileName -Name $Name
    Write-WAFile -File $file -Text '============= Local Account Policy (net accounts) =============', (Invoke-WANative -FilePath 'net.exe' -ArgumentList @('accounts'))
    Write-WAFile -File $file -Text '============= Domain Account Policy (net accounts /domain) ============='
    if (-not $script:WACtx.PartOfDomain) { Write-WAFile -File $file -Text 'The computer is not part of a domain.' }
    elseif (Test-WADomainConnectivity) { Write-WAFile -File $file -Text (Invoke-WANative -FilePath 'net.exe' -ArgumentList @('accounts', '/domain')) }
    else { Write-WAFile -File $file -Text 'No connectivity to the domain.' }
}

function Get-WALocalUsers {
    # v1: dataLocalUsers (skipped on DCs - no local SAM accounts)
    [CmdletBinding()]
    param ([string]$Name)
    Write-WALog 'running Get-WALocalUsers'
    if ($script:WACtx.IsDC) { return }
    Write-WAScreen 'Getting local users and administrators...'
    $file = Get-WAFileName -Name $Name
    $admins = Invoke-WACmdlet -Name 'Get-LocalGroupMember' -Parameters @{ SID = 'S-1-5-32-544' }
    Write-WAFile -File $file -Text '============= Local Administrators ============='
    if ($admins) { Write-WAFile -File $file -Text ($admins | Format-Table -AutoSize Name, ObjectClass, PrincipalSource, SID | Out-String -Width 200) }
    else { Write-WAFile -File $file -Text (Invoke-WANative -FilePath 'net.exe' -ArgumentList @('localgroup', (Get-WALocalGroupName -Sid 'S-1-5-32-544'))) }
    Write-WAFile -File $file -Text '============= Local Users ============='
    $users = Invoke-WACmdlet -Name 'Get-LocalUser'
    if ($users) {
        Write-WAFile -File $file -Text ($users | Format-Table -AutoSize Name, Enabled, PasswordRequired, PasswordLastSet, PasswordExpires, LastLogon, Description, SID | Out-String -Width 250)
    }
    else {
        $u = Get-WACimInstance -ClassName Win32_UserAccount -Filter 'LocalAccount=True'
        Write-WAFile -File $file -Text ($u | Format-Table -AutoSize Caption, Disabled, Lockout, PasswordExpires, PasswordRequired, Description, SID | Out-String -Width 250)
    }
}

function Get-WALocalGroupName {
    # Resolves a well-known group SID to its localized name (e.g. S-1-5-32-555 -> 'Remote Desktop Users').
    [CmdletBinding()]
    param ([Parameter(Mandatory = $true)][string]$Sid)
    try {
        $n = (New-Object Security.Principal.SecurityIdentifier($Sid)).Translate([Security.Principal.NTAccount]).Value
        return ($n -split '\\')[-1]
    }
    catch {
        switch ($Sid) { 'S-1-5-32-544' { 'Administrators' } 'S-1-5-32-555' { 'Remote Desktop Users' } default { $Sid } }
    }
}

function Get-WASystemInfo {
    # v1: dataSystemInfo. Fixed: PS version compared as a string.
    [CmdletBinding()]
    param ([string]$Name)
    Write-WALog 'running Get-WASystemInfo'
    Write-WAScreen 'Running systeminfo...'
    $file = Get-WAFileName -Name $Name
    $ci = Invoke-WACmdlet -Name 'Get-ComputerInfo'
    if ($ci) { Write-WAFile -File $file -Text '============= Get-ComputerInfo =============', ($ci | Out-String -Width 200) }
    Write-WAFile -File $file -Text '============= systeminfo =============', (Invoke-WANative -FilePath 'systeminfo.exe')
}

function Get-WAAuditPolicy {
    # v1: dataAuditPolicy. Output cached for the command-line auditing check.
    [CmdletBinding()]
    param ([string]$Name)
    Write-WALog 'running Get-WAAuditPolicy'
    $file = Get-WAFileName -Name $Name
    Write-WAFile -File $file -Text '', '============= Audit policy (auditpol /get /category:*) ============='
    if (-not $script:WACtx.IsAdmin) {
        Write-WAFile -File $file -Text 'auditpol requires elevation.'
        return
    }
    Write-WAScreen 'Getting audit policy configuration...'
    $out = Invoke-WANative -FilePath 'auditpol.exe' -ArgumentList @('/get', '/category:*')
    $script:WACtx.Cache['AuditPol'] = $out
    Write-WAFile -File $file -Text $out
}
#endregion

#region Checks - credential protection, network exposure, SMB, RDP

function Test-WACredentialGuard {
    # v1: checkCredentialGuard. Changes: single WMI source (Get-ComputerInfo was slow and redundant),
    # "configured but not running" distinguished, DCs marked N/A (Microsoft does not support CG benefits on DCs).
    [CmdletBinding()]
    param ([string]$Name)
    Write-WALog 'running Test-WACredentialGuard'
    $ctx = $script:WACtx
    $file = Get-WAFileName -Name $Name
    if ($ctx.IsDC) {
        Add-WAFinding -CheckID 'machine_LSA-CG-wmi' -Status NotApplicable -RelatedFile $file -Finding 'Credential Guard provides no added protection on domain controllers and is not recommended there.'
        return
    }
    if ($ctx.WinVersion.Major -lt 10) {
        Add-WAFinding -CheckID 'machine_LSA-CG-wmi' -Status Fail -RelatedFile $file -Finding 'The operating system does not support Credential Guard (requires Windows 10 / Server 2016 or later).'
        return
    }
    Write-WAScreen 'Getting Credential Guard settings...'
    $dg = Get-WACimInstance -ClassName Win32_DeviceGuard -Namespace 'root\Microsoft\Windows\DeviceGuard'
    Write-WAFile -File $file -Text '============= Device Guard (Win32_DeviceGuard) =============', ($dg | Format-List * | Out-String -Width 200)
    if ($null -eq $dg) {
        Add-WAFinding -CheckID 'machine_LSA-CG-wmi' -Status Manual -RelatedFile $file -Finding 'The Win32_DeviceGuard WMI query failed - Credential Guard state unknown.'
        return
    }
    $configured = @($dg.SecurityServicesConfigured) -contains 1
    $running = @($dg.SecurityServicesRunning) -contains 1
    $evidence = 'SecurityServicesConfigured={0}; SecurityServicesRunning={1}; VBS status={2}' -f (@($dg.SecurityServicesConfigured) -join ','), (@($dg.SecurityServicesRunning) -join ','), $dg.VirtualizationBasedSecurityStatus
    if ($running) {
        Add-WAFinding -CheckID 'machine_LSA-CG-wmi' -Status Pass -RelatedFile $file -Evidence $evidence -Finding 'Credential Guard is configured and running.'
    }
    elseif ($configured) {
        Add-WAFinding -CheckID 'machine_LSA-CG-wmi' -Status Fail -RelatedFile $file -Evidence $evidence -Finding 'Credential Guard is configured but NOT running (pending reboot or unsupported hardware/firmware).'
    }
    else {
        Add-WAFinding -CheckID 'machine_LSA-CG-wmi' -Status Fail -RelatedFile $file -Evidence $evidence -Finding 'Credential Guard is not enabled.'
    }
}

function Test-WALsaProtection {
    # v1: checkLSAProtectionConf. Fixed: RunAsPPL=2 (Windows 11 22H2+, no UEFI lock) was reported as "off";
    # added effective-state evidence from Wininit event 12 (covers default-enabled LSA protection).
    [CmdletBinding()]
    param ([string]$Name)
    Write-WALog 'running Test-WALsaProtection'
    $file = Get-WAFileName -Name $Name
    if (-not (Test-WAOSVersion -Minimum '6.3')) {
        Add-WAFinding -CheckID 'machine_LSA-ppl' -Status Fail -RelatedFile $file -Finding 'The operating system does not support LSA protection (requires Windows 8.1 / Server 2012 R2 or later).'
        return
    }
    Write-WAScreen 'Getting LSA protection settings...'
    $ppl = Get-WARegValue -Path 'SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RunAsPPL'
    $pplBoot = Get-WARegValue -Path 'SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RunAsPPLBoot'
    Write-WAFile -File $file -Text ('RunAsPPL = {0}; RunAsPPLBoot = {1}' -f $ppl, $pplBoot)
    if ($ppl -eq 1 -or $ppl -eq 2) {
        $mode = if ($ppl -eq 1) { 'with UEFI lock' } else { 'without UEFI lock' }
        Add-WAFinding -CheckID 'machine_LSA-ppl' -Status Pass -RelatedFile $file -Evidence "RunAsPPL=$ppl" -Finding "LSA protection is enabled ($mode)."
        return
    }
    $evt = Invoke-WACmdlet -Name 'Get-WinEvent' -Parameters @{ FilterHashtable = @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-Wininit'; Id = 12 }; MaxEvents = 1 }
    if ($evt -and ([string]$evt.Message -match 'protected process')) {
        Write-WAFile -File $file -Text ('Wininit event 12: ' + $evt.Message)
        Add-WAFinding -CheckID 'machine_LSA-ppl' -Status Pass -RelatedFile $file -Evidence ("RunAsPPL={0}; Wininit event 12 at {1}" -f $ppl, $evt.TimeCreated) -Finding 'LSASS runs as a protected process (effective state from Wininit event 12; registry value not set - consider enforcing by policy).'
        return
    }
    $txt = if ($null -eq $ppl) { 'RunAsPPL is not set - LSA protection is off.' } else { "RunAsPPL=$ppl - LSA protection is off." }
    Add-WAFinding -CheckID 'machine_LSA-ppl' -Status Fail -RelatedFile $file -Evidence "RunAsPPL=$ppl" -Finding $txt
}

function Test-WAWDigest {
    # v1: checkWDigest. Fixed: the "secure by default" branch wrote its text to Comments, leaving Finding empty.
    [CmdletBinding()]
    param ([string]$Name)
    Write-WALog 'running Test-WAWDigest'
    Write-WAScreen 'Getting WDigest configuration...'
    $file = Get-WAFileName -Name $Name
    $v = Get-WARegValue -Path 'SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name 'UseLogonCredential'
    Write-WAFile -File $file -Text '============= WDigest =============', "UseLogonCredential = $v"
    if ($v -eq 1) {
        Add-WAFinding -CheckID 'domain_WDigest' -Status Fail -RelatedFile $file -Evidence 'UseLogonCredential=1' -Finding 'WDigest stores clear-text credentials in LSASS memory (UseLogonCredential=1). Set by an administrator or by an attacker preparing credential theft - investigate.'
    }
    elseif ($v -eq 0) {
        Add-WAFinding -CheckID 'domain_WDigest' -Status Pass -RelatedFile $file -Evidence 'UseLogonCredential=0' -Finding 'WDigest credential caching is explicitly disabled.'
    }
    elseif (Test-WAOSVersion -Minimum '6.3') {
        Add-WAFinding -CheckID 'domain_WDigest' -Status Pass -RelatedFile $file -Evidence 'UseLogonCredential not set' -Finding 'WDigest caching is off by default on Windows 8.1/2012 R2+.' -Comment 'Set UseLogonCredential=0 explicitly and monitor it, so a malicious change is detectable.'
    }
    elseif (Test-WAOSVersion -Minimum '6.1') {
        Add-WAFinding -CheckID 'domain_WDigest' -Status Fail -RelatedFile $file -Evidence 'UseLogonCredential not set' -Finding 'Windows 7/2008 R2/8/2012 cache WDigest clear-text credentials by default (install KB2871997 and set UseLogonCredential=0).'
    }
    else {
        Add-WAFinding -CheckID 'domain_WDigest' -Status Fail -RelatedFile $file -Finding 'Legacy OS - WDigest caching cannot be disabled.'
    }
}

function Test-WANetworkCredStorage {
    # v1: checkPrevStorOfPassAndCred
    [CmdletBinding()]
    param ([string]$Name)
    Write-WALog 'running Test-WANetworkCredStorage'
    $file = Get-WAFileName -Name $Name
    $v = Get-WARegValue -Path 'SYSTEM\CurrentControlSet\Control\Lsa' -Name 'DisableDomainCreds'
    Write-WAFile -File $file -Text '============= Storage of network passwords and credentials =============', "DisableDomainCreds = $v"
    if ($v -eq 1) { Add-WAFinding -CheckID 'domain_PrevStorOfPassAndCred' -Status Pass -RelatedFile $file -Evidence 'DisableDomainCreds=1' -Finding 'Storage of network passwords and credentials is blocked.' }
    else { Add-WAFinding -CheckID 'domain_PrevStorOfPassAndCred' -Status Fail -RelatedFile $file -Evidence "DisableDomainCreds=$v" -Finding 'Windows may store network passwords and credentials (Credential Manager).' }
}

function Test-WATcpPort {
    # Direct TCP connect (bypasses any proxy) - measures real egress filtering.
    [CmdletBinding()]
    param ([Parameter(Mandatory = $true)][string]$ComputerName, [Parameter(Mandatory = $true)][int]$Port, [int]$TimeoutMs = 2500)
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $ar = $client.BeginConnect($ComputerName, $Port, $null, $null)
        if ($ar.AsyncWaitHandle.WaitOne($TimeoutMs, $false) -and $client.Connected) { $client.EndConnect($ar); return $true }
        return $false
    }
    catch { return $false }
    finally { $client.Close() }
}

function Test-WAInternetAccess {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingComputerNameHardcoded', '', Justification = 'portquiz.net is the intentional egress probe target')]
    # v1: checkInternetAccess. Changes: direct TCP connects instead of proxy-aware HTTP (the v1 test could not tell
    # proxy egress from direct egress), port 663/666 label typo fixed, -SkipNetworkTests honoured, loop instead of 4 copies.
    [CmdletBinding()]
    param ([string]$Name)
    Write-WALog 'running Test-WAInternetAccess'
    $ctx = $script:WACtx
    $file = Get-WAFileName -Name $Name
    $sev = if ($ctx.IsServer) { 'High' } else { 'Medium' }
    if ($ctx.SkipNetworkTests) {
        Add-WAFinding -CheckID 'machine_na-dns' -Status Manual -Severity $sev -RelatedFile $file -Finding 'Skipped by operator (-SkipNetworkTests).'
        Add-WAFinding -CheckID 'machine_na-browsing' -Status Manual -Severity $sev -RelatedFile $file -Finding 'Skipped by operator (-SkipNetworkTests).'
        return
    }
    Write-WAScreen 'Checking direct internet access...'
    Write-WAFile -File $file -Text '============= ping -n 2 8.8.8.8 =============', (Invoke-WANative -FilePath 'ping.exe' -ArgumentList @('-n', '2', '8.8.8.8'))

    # DNS directly to a public resolver
    $dnsOpen = $false
    $dns = Invoke-WACmdlet -Name 'Resolve-DnsName' -Parameters @{ Name = 'www.microsoft.com'; Server = '8.8.8.8'; DnsOnly = $true; QuickTimeout = $true }
    if ($null -ne $dns) { $dnsOpen = $true; $dnsOut = ($dns | Out-String) }
    elseif (-not (Get-Command -Name Resolve-DnsName -ErrorAction SilentlyContinue)) {
        $ns = Invoke-WANative -FilePath 'nslookup.exe' -ArgumentList @('www.microsoft.com', '8.8.8.8')
        $dnsOut = ($ns -join [Environment]::NewLine)
        $dnsOpen = ($dnsOut -notmatch 'timed out|time-out') -and ($dnsOut -match 'Address(es)?:\s+\S+[\s\S]*Address')
    }
    Write-WAFile -File $file -Text '============= DNS query to 8.8.8.8 =============', $dnsOut
    if ($dnsOpen) {
        $st = if ($ctx.IsServer) { 'Fail' } else { 'Warning' }
        Add-WAFinding -CheckID 'machine_na-dns' -Status $st -Severity $sev -RelatedFile $file -Evidence 'Resolved www.microsoft.com via 8.8.8.8' -Finding 'Public DNS (8.8.8.8) is directly reachable - DNS tunnelling/exfiltration channel available.'
    }
    else {
        Add-WAFinding -CheckID 'machine_na-dns' -Status Pass -Severity $sev -RelatedFile $file -Evidence 'No answer from 8.8.8.8' -Finding 'Direct queries to public DNS are blocked.'
    }

    # Direct TCP egress (portquiz.net listens on all TCP ports)
    $results = [ordered]@{}
    foreach ($port in 80, 443, 666, 8080) {
        $results[[string]$port] = Test-WATcpPort -ComputerName 'portquiz.net' -Port $port
    }
    $summary = ($results.Keys | ForEach-Object { '{0}:{1}' -f $_, $(if ($results[$_]) { 'Open' } else { 'Blocked' }) }) -join '; '
    Write-WAFile -File $file -Text '============= Direct TCP egress to portquiz.net =============', $summary
    $std = $results['80'] -or $results['443']
    $nonStd = $results['666'] -or $results['8080']
    if ($nonStd) {
        Add-WAFinding -CheckID 'machine_na-browsing' -Status Fail -Severity $sev -RelatedFile $file -Evidence $summary -Finding 'Direct outbound connections on non-standard ports are allowed (no default-deny egress).'
    }
    elseif ($std) {
        $st = if ($ctx.IsServer) { 'Fail' } else { 'Warning' }
        Add-WAFinding -CheckID 'machine_na-browsing' -Status $st -Severity $sev -RelatedFile $file -Evidence $summary -Finding 'Direct outbound HTTP/HTTPS is allowed without the proxy.'
    }
    else {
        Add-WAFinding -CheckID 'machine_na-browsing' -Status Pass -Severity $sev -RelatedFile $file -Evidence $summary -Finding 'Direct outbound connections are blocked on all tested ports (80, 443, 666, 8080).'
    }
}

function Test-WASmbHardening {
    # v1: checkSMBHardening. Fixed: SMB1 reported "supported" whenever the legacy registry value was absent (false positive
    # on every modern OS); SMB1 client check queried lanmanworkstation (SMB2/3 client) instead of mrxsmb10 and crashed when
    # the driver was absent; signing now read from the SMB configuration cmdlets (effective incl. OS defaults).
    [CmdletBinding()]
    param ([string]$Name)
    Write-WALog 'running Test-WASmbHardening'
    Write-WAScreen 'Getting SMB hardening configuration...'
    $file = Get-WAFileName -Name $Name
    $srv = Invoke-WACmdlet -Name 'Get-SmbServerConfiguration'
    $cli = Invoke-WACmdlet -Name 'Get-SmbClientConfiguration'
    $lmPath = 'SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
    $wkPath = 'SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'

    # --- SMB1 server
    if ($srv) {
        if ($srv.EnableSMB1Protocol) { Add-WAFinding -CheckID 'domain_SMBv1' -Status Fail -RelatedFile $file -Evidence 'Get-SmbServerConfiguration: EnableSMB1Protocol=True' -Finding 'The SMBv1 server protocol is enabled.' }
        else { Add-WAFinding -CheckID 'domain_SMBv1' -Status Pass -RelatedFile $file -Evidence 'Get-SmbServerConfiguration: EnableSMB1Protocol=False' -Finding 'The SMBv1 server protocol is disabled.' }
        Add-WAFinding -CheckID 'domain_SMBv2-3' -Status Info -RelatedFile $file -Evidence ('EnableSMB2Protocol=' + $srv.EnableSMB2Protocol) -Finding $(if ($srv.EnableSMB2Protocol) { 'SMB2/3 server is enabled.' } else { 'SMB2/3 server is disabled (unusual).' })
    }
    else {
        $smb1 = Get-WARegValue -Path $lmPath -Name 'SMB1'
        $smb2 = Get-WARegValue -Path $lmPath -Name 'SMB2'
        if ($smb1 -eq 0) { Add-WAFinding -CheckID 'domain_SMBv1' -Status Pass -RelatedFile $file -Evidence 'SMB1=0' -Finding 'The SMBv1 server protocol is disabled (registry).' }
        elseif ($smb1 -eq 1 -or -not (Test-WAOSVersion -Minimum '6.2')) { Add-WAFinding -CheckID 'domain_SMBv1' -Status Fail -RelatedFile $file -Evidence "SMB1=$smb1" -Finding 'The SMBv1 server protocol is enabled (registry / OS default).' }
        else { Add-WAFinding -CheckID 'domain_SMBv1' -Status Manual -RelatedFile $file -Evidence 'SMB1 registry value not set; SMB cmdlets unavailable' -Finding 'SMBv1 server state could not be determined - verify the SMB1Protocol optional feature.' }
        Add-WAFinding -CheckID 'domain_SMBv2-3' -Status Info -RelatedFile $file -Evidence "SMB2=$smb2" -Finding $(if ($smb2 -eq 0) { 'SMB2/3 server is disabled (unusual).' } else { 'SMB2/3 server is enabled.' })
    }

    # --- SMB1 client driver
    $mrx = Get-WARegValue -Path 'SYSTEM\CurrentControlSet\Services\mrxsmb10' -Name 'Start'
    $deps = Get-WARegValue -Path 'SYSTEM\CurrentControlSet\Services\LanmanWorkstation' -Name 'DependOnService'
    $ev = 'mrxsmb10 Start={0}; LanmanWorkstation DependOnService={1}' -f $(if ($null -eq $mrx) { '(driver not installed)' } else { $mrx }), (@($deps) -join ',')
    Write-WAFile -File $file -Text '============= SMB1 client =============', $ev
    if ($null -eq $mrx -or $mrx -eq 4) { Add-WAFinding -CheckID 'domain_SMBv1-client' -Status Pass -RelatedFile $file -Evidence $ev -Finding 'The SMBv1 client driver is disabled or not installed.' }
    elseif ($mrx -eq 3) { Add-WAFinding -CheckID 'domain_SMBv1-client' -Status Warning -RelatedFile $file -Evidence $ev -Finding 'The SMBv1 client driver is set to manual start (loaded on demand).' }
    else { Add-WAFinding -CheckID 'domain_SMBv1-client' -Status Fail -RelatedFile $file -Evidence $ev -Finding 'The SMBv1 client driver is enabled.' }

    # --- signing (server)
    if ($srv) { $sReq = [bool]$srv.RequireSecuritySignature; $sEn = [bool]$srv.EnableSecuritySignature; $src = 'Get-SmbServerConfiguration' }
    else { $sReq = (Get-WARegValue -Path $lmPath -Name 'RequireSecuritySignature') -eq 1; $sEn = (Get-WARegValue -Path $lmPath -Name 'EnableSecuritySignature') -eq 1; $src = 'registry' }
    $ev = "{0}: RequireSecuritySignature={1}; EnableSecuritySignature={2}" -f $src, $sReq, $sEn
    if ($sReq) { Add-WAFinding -CheckID 'domain_SMBv2-srvSign' -Status Pass -RelatedFile $file -Evidence $ev -Finding 'SMB signing is required by the server.' }
    elseif ($sEn) { Add-WAFinding -CheckID 'domain_SMBv2-srvSign' -Status Fail -RelatedFile $file -Evidence $ev -Finding 'SMB signing is enabled but not required by the server - NTLM relay to this host is possible.' }
    else { Add-WAFinding -CheckID 'domain_SMBv2-srvSign' -Status Fail -RelatedFile $file -Evidence $ev -Finding 'SMB signing is disabled on the server - NTLM relay to this host is possible.' }

    # --- signing (client)
    if ($cli) { $cReq = [bool]$cli.RequireSecuritySignature; $cEn = [bool]$cli.EnableSecuritySignature; $src = 'Get-SmbClientConfiguration' }
    else { $cReq = (Get-WARegValue -Path $wkPath -Name 'RequireSecuritySignature') -eq 1; $cEn = (Get-WARegValue -Path $wkPath -Name 'EnableSecuritySignature') -ne 0; $src = 'registry' }
    $ev = "{0}: RequireSecuritySignature={1}; EnableSecuritySignature={2}" -f $src, $cReq, $cEn
    if ($cReq) { Add-WAFinding -CheckID 'domain_SMBv2-clientSign' -Status Pass -RelatedFile $file -Evidence $ev -Finding 'SMB signing is required by the client.' }
    else { Add-WAFinding -CheckID 'domain_SMBv2-clientSign' -Status Fail -RelatedFile $file -Evidence $ev -Finding 'SMB signing is not required by the client.' }

    if ($srv) { Write-WAFile -File $file -Text '============= Get-SmbServerConfiguration =============', ($srv | Format-List * | Out-String -Width 200) }
    if ($cli) { Write-WAFile -File $file -Text '============= Get-SmbClientConfiguration =============', ($cli | Format-List * | Out-String -Width 200) }
}

function Get-WALocalGroupMembers {
    # Members of a local group by SID. Returns @{ Resolved = <bool>; Members = @(Name, SID) } so that "empty group" and
    # "could not enumerate" are distinguishable. Falls back to "net localgroup" (Get-LocalGroupMember fails on orphaned SIDs).
    [CmdletBinding()]
    param ([Parameter(Mandatory = $true)][string]$Sid)
    if (Get-Command -Name Get-LocalGroupMember -ErrorAction SilentlyContinue) {
        try {
            $m = @(Get-LocalGroupMember -SID $Sid -ErrorAction Stop)
            return [pscustomobject]@{ Resolved = $true; Members = @($m | Where-Object { $_ } | ForEach-Object { [pscustomobject]@{ Name = [string]$_.Name; SID = [string]$_.SID } }) }
        }
        catch { Write-WALog ('Get-LocalGroupMember failed, falling back to net.exe: ' + $_.Exception.Message) }
    }
    $lines = @(Invoke-WANative -FilePath 'net.exe' -ArgumentList @('localgroup', (Get-WALocalGroupName -Sid $Sid)))
    $start = -1
    for ($i = 0; $i -lt $lines.Count; $i++) { if ($lines[$i] -match '^-{5,}') { $start = $i + 1; break } }
    if ($start -lt 0) { return [pscustomobject]@{ Resolved = $false; Members = @() } }
    $body = @()
    if ($start -lt $lines.Count) { $body = @($lines[$start..($lines.Count - 1)] | Where-Object { $_.Trim() }) }
    if ($body.Count -gt 0) { $body = @($body | Select-Object -First ($body.Count - 1)) }   # last line is the localized "command completed" message
    return [pscustomobject]@{ Resolved = $true; Members = @($body | ForEach-Object { [pscustomobject]@{ Name = $_.Trim(); SID = '' } }) }
}

function Test-WARdpSecurity {
    # v1: checkRDPSecurity. Fixed: GPO override of fDenyTSConnections ignored ("RDP disabled" false results), missing status,
    # RDP users concatenated without separator and "only admins" branch unreachable, NLA/TLS silently skipped when the
    # WMI class is not readable (non-admin), timeout check reported PASS when the policy key does not exist.
    [CmdletBinding()]
    param ([string]$Name)
    Write-WALog 'running Test-WARdpSecurity'
    Write-WAScreen 'Getting RDP security settings...'
    $ctx = $script:WACtx
    $file = Get-WAFileName -Name $Name
    $polPath = 'SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
    $tsPath = 'SYSTEM\CurrentControlSet\Control\Terminal Server'
    $wsPath = 'SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'

    # --- service exposure (policy wins over local setting)
    $pDeny = Get-WARegValue -Path $polPath -Name 'fDenyTSConnections'
    $lDeny = Get-WARegValue -Path $tsPath -Name 'fDenyTSConnections'
    $deny = if ($null -ne $pDeny) { $pDeny } elseif ($null -ne $lDeny) { $lDeny } else { 1 }
    $port = Get-WARegValue -Path $wsPath -Name 'PortNumber'
    $ev = 'fDenyTSConnections policy={0}; local={1}; effective={2}; PortNumber={3}' -f $pDeny, $lDeny, $deny, $port
    Write-WAFile -File $file -Text '============= RDP service status =============', $ev
    $rdpEnabled = ($deny -eq 0)
    if (-not $rdpEnabled) { Add-WAFinding -CheckID 'machine_RDP-reg' -Status Pass -RelatedFile $file -Evidence $ev -Finding 'RDP is disabled.' }
    elseif ($ctx.IsServer) { Add-WAFinding -CheckID 'machine_RDP-reg' -Status Info -RelatedFile $file -Evidence $ev -Finding 'RDP is enabled (expected on servers - ensure firewall scoping to admin subnets).' }
    else { Add-WAFinding -CheckID 'machine_RDP-reg' -Status Warning -RelatedFile $file -Evidence $ev -Finding 'RDP is enabled on a workstation.' }

    # --- Remote Desktop Users
    $grp = Get-WALocalGroupMembers -Sid 'S-1-5-32-555'
    $members = @($grp.Members)
    $broadSids = @('S-1-1-0', 'S-1-5-11', 'S-1-5-32-545', 'S-1-5-4', 'S-1-5-32-546')
    $broadNames = '^(.*\\)?(Everyone|Authenticated Users|Domain Users|Users|INTERACTIVE|Guests|Guest|Domain Guests)$'
    $broad = @($members | Where-Object { ($_.SID -and ($broadSids -contains $_.SID -or $_.SID -match '-513$|-514$')) -or $_.Name -match $broadNames })
    $builtinAdmin = @($members | Where-Object { $_.SID -match '-500$' -or $_.Name -match '(^|\\)Administrator$' })
    $names = ($members | ForEach-Object { $_.Name }) -join ', '
    Write-WAFile -File $file -Text '============= Remote Desktop Users =============', $(if ($names) { $names } else { '(no members - only Administrators can connect)' })
    if (-not $grp.Resolved) {
        Add-WAFinding -CheckID 'machine_RDP-Users' -Status Manual -RelatedFile $file -Finding 'Members of Remote Desktop Users could not be enumerated.'
    }
    elseif ($broad.Count -gt 0) {
        Add-WAFinding -CheckID 'machine_RDP-Users' -Status Fail -RelatedFile $file -Evidence "Members: $names" -Finding ('Broad principals can log on over RDP: ' + (($broad | ForEach-Object { $_.Name }) -join ', '))
    }
    elseif ($builtinAdmin.Count -gt 0) {
        Add-WAFinding -CheckID 'machine_RDP-Users' -Status Warning -RelatedFile $file -Evidence "Members: $names" -Finding 'The built-in Administrator account is explicitly allowed to log on over RDP.'
    }
    elseif ($members.Count -gt 0) {
        Add-WAFinding -CheckID 'machine_RDP-Users' -Status Manual -RelatedFile $file -Evidence "Members: $names" -Finding "Review the Remote Desktop Users members: $names"
    }
    else {
        Add-WAFinding -CheckID 'machine_RDP-Users' -Status Pass -RelatedFile $file -Evidence 'Remote Desktop Users is empty' -Finding 'Only Administrators are allowed to connect over RDP.'
    }

    # --- NLA / security layer (policy > WinStation registry > WMI)
    $wmi = Get-WACimInstance -ClassName Win32_TSGeneralSetting -Namespace 'root\cimv2\terminalservices' -Filter "TerminalName='RDP-Tcp'"
    $nla = Get-WARegValue -Path $polPath -Name 'UserAuthentication'
    $nlaSrc = 'policy'
    if ($null -eq $nla) { $nla = Get-WARegValue -Path $wsPath -Name 'UserAuthentication'; $nlaSrc = 'RDP-Tcp registry' }
    if ($null -eq $nla -and $wmi) { $nla = $wmi.UserAuthenticationRequired; $nlaSrc = 'WMI' }
    $sl = Get-WARegValue -Path $polPath -Name 'SecurityLayer'
    $slSrc = 'policy'
    if ($null -eq $sl) { $sl = Get-WARegValue -Path $wsPath -Name 'SecurityLayer'; $slSrc = 'RDP-Tcp registry' }
    if ($null -eq $sl -and $wmi) { $sl = $wmi.SecurityLayer; $slSrc = 'WMI' }
    $note = if ($rdpEnabled) { '' } else { ' (RDP currently disabled)' }
    Write-WAFile -File $file -Text '============= NLA / Security layer =============', "UserAuthentication=$nla ($nlaSrc); SecurityLayer=$sl ($slSrc)"
    switch ($nla) {
        1 { Add-WAFinding -CheckID 'machine_RDP-NLA' -Status Pass -RelatedFile $file -Evidence "UserAuthentication=1 ($nlaSrc)" -Finding "NLA is required$note." }
        0 { Add-WAFinding -CheckID 'machine_RDP-NLA' -Status $(if ($rdpEnabled) { 'Fail' } else { 'Warning' }) -RelatedFile $file -Evidence "UserAuthentication=0 ($nlaSrc)" -Finding "NLA is not required$note." }
        default { Add-WAFinding -CheckID 'machine_RDP-NLA' -Status Manual -RelatedFile $file -Finding 'NLA setting could not be read.' }
    }
    switch ($sl) {
        2 { Add-WAFinding -CheckID 'machine_RDP-TLS' -Status Pass -RelatedFile $file -Evidence "SecurityLayer=2 ($slSrc)" -Finding "TLS is required for RDP$note." }
        1 { Add-WAFinding -CheckID 'machine_RDP-TLS' -Status Warning -RelatedFile $file -Evidence "SecurityLayer=1 ($slSrc)" -Finding "RDP security layer is 'Negotiate' - TLS not enforced$note." }
        0 { Add-WAFinding -CheckID 'machine_RDP-TLS' -Status Fail -RelatedFile $file -Evidence "SecurityLayer=0 ($slSrc)" -Finding "Native RDP encryption is used instead of TLS$note." }
        default { Add-WAFinding -CheckID 'machine_RDP-TLS' -Status Manual -RelatedFile $file -Finding 'RDP security layer could not be read.' }
    }

    # --- session time limits (policy)
    $pol = Get-WARegKeyValues -Path $polPath
    $maxDisc = $null; $maxIdle = $null; $reset = $null
    if ($pol) { $maxDisc = $pol['MaxDisconnectionTime']; $maxIdle = $pol['MaxIdleTime']; $reset = $pol['fResetBroken'] }
    $ev = 'MaxDisconnectionTime={0}; MaxIdleTime={1}; fResetBroken={2} (ms; 60000 = 1 minute)' -f $maxDisc, $maxIdle, $reset
    Write-WAFile -File $file -Text '============= RDP session time limits (policy) =============', $ev
    if ($maxDisc -gt 0 -and $maxIdle -gt 0) { Add-WAFinding -CheckID 'machine_RDP-Timeout' -Status Pass -RelatedFile $file -Evidence $ev -Finding 'Disconnected and idle RDP session limits are configured.' }
    elseif ($maxDisc -gt 0 -or $maxIdle -gt 0) { Add-WAFinding -CheckID 'machine_RDP-Timeout' -Status Warning -RelatedFile $file -Evidence $ev -Finding 'Only one of the disconnected/idle RDP session limits is configured.' }
    else { Add-WAFinding -CheckID 'machine_RDP-Timeout' -Status Fail -RelatedFile $file -Evidence $ev -Finding 'RDP session time limits are not configured - disconnected sessions persist and can be hijacked.' }
    if ($wmi) { Write-WAFile -File $file -Text '============= Win32_TSGeneralSetting =============', ($wmi | Format-List TerminalName, *Encrypt*, Policy*, Security*, SSL*, *Auth* | Out-String) }
}

function Test-WANetSessionEnum {
    # v1: checkNetSessionEnum (evidence only, crashed when the value was missing). Now evaluated.
    [CmdletBinding()]
    param ([string]$Name)
    Write-WALog 'running Test-WANetSessionEnum'
    Write-WAScreen 'Getting NetSession enumeration permissions...'
    $file = Get-WAFileName -Name $Name
    $raw = Get-WARegValue -Path 'SYSTEM\CurrentControlSet\Services\LanmanServer\DefaultSecurity' -Name 'SrvsvcSessionInfo'
    Write-WAFile -File $file -Text '============= NetSessionEnum permissions (SrvsvcSessionInfo) =============',
    'Authenticated Users/Everyone on this ACL enables SMB session enumeration (BloodHound session collection).'
    if ($null -eq $raw) {
        Add-WAFinding -CheckID 'domain_NetSessionEnum' -Status Manual -RelatedFile $file -Finding 'SrvsvcSessionInfo could not be read.'
        return
    }
    $parsed = ConvertFrom-WASecurityDescriptorBytes -Bytes ([byte[]]$raw)
    if (-not $parsed.Valid) {
        Add-WAFinding -CheckID 'domain_NetSessionEnum' -Status Manual -RelatedFile $file -Finding 'SrvsvcSessionInfo could not be parsed.'
        return
    }
    $aces = @($parsed.Aces | ForEach-Object { [pscustomobject]@{ SID = $_.SID; Name = (Resolve-WASidName -Sid $_.SID); Type = $_.Type; Mask = $_.Mask } })
    Write-WAFile -File $file -Text ($aces | Format-Table -AutoSize | Out-String)
    $bad = @($aces | Where-Object { $_.Type -eq 'Allow' -and ($_.SID -eq 'S-1-5-11' -or $_.SID -eq 'S-1-1-0') })
    $ev = ($aces | ForEach-Object { '{0} ({1})' -f $_.Name, $_.Type }) -join '; '
    if ($bad.Count -gt 0) { Add-WAFinding -CheckID 'domain_NetSessionEnum' -Status Fail -RelatedFile $file -Evidence $ev -Finding 'Any authenticated user can enumerate SMB sessions on this host (NetSessionEnum).' }
    else { Add-WAFinding -CheckID 'domain_NetSessionEnum' -Status Pass -RelatedFile $file -Evidence $ev -Finding 'SMB session enumeration is restricted (Authenticated Users/Everyone not granted).' }
}

function Test-WASamEnum {
    # v1: checkSAMEnum. Fixed: hardened-by-default branch wrote Comments instead of Finding; ConvertFrom-SddlString
    # (PS 5.1+ only) replaced by .NET parsing; DCs marked N/A (the restriction must not be applied to DCs by default).
    [CmdletBinding()]
    param ([string]$Name)
    Write-WALog 'running Test-WASamEnum'
    Write-WAScreen 'Getting remote SAM enumeration configuration...'
    $ctx = $script:WACtx
    $file = Get-WAFileName -Name $Name
    $sddl = Get-WARegValue -Path 'SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RestrictRemoteSAM'
    Write-WAFile -File $file -Text '============= Remote SAM (SAMR) restrictions =============', "RestrictRemoteSAM = $sddl"
    if ($ctx.IsDC) {
        Add-WAFinding -CheckID 'domain_SAMEnum' -Status NotApplicable -RelatedFile $file -Evidence "RestrictRemoteSAM=$sddl" -Finding 'Domain controller - SAMR access is governed by AD permissions, not RestrictRemoteSAM.'
        return
    }
    if (-not $sddl) {
        if (Test-WAOSVersion -Minimum '10.0.14393') { Add-WAFinding -CheckID 'domain_SAMEnum' -Status Pass -RelatedFile $file -Evidence 'RestrictRemoteSAM not set (OS default: Administrators only)' -Finding 'Remote SAM enumeration is restricted to Administrators by OS default (Windows 10 1607 / Server 2016+).' }
        else { Add-WAFinding -CheckID 'domain_SAMEnum' -Status Fail -RelatedFile $file -Evidence 'RestrictRemoteSAM not set' -Finding 'Any domain user can enumerate local accounts and groups over SAMR (pre-1607 OS default).' }
        return
    }
    $allowed = @(ConvertFrom-WASddlAces -Sddl $sddl | Where-Object { $_.Type -eq 'Allow' } | ForEach-Object { $_.SID })
    if ($allowed.Count -eq 0) {
        Add-WAFinding -CheckID 'domain_SAMEnum' -Status Manual -RelatedFile $file -Evidence "RestrictRemoteSAM=$sddl" -Finding 'RestrictRemoteSAM contains no allow entries or could not be parsed - review manually.'
        return
    }
    $others = @($allowed | Where-Object { $_ -ne 'S-1-5-32-544' })
    if ($others.Count -eq 0) { Add-WAFinding -CheckID 'domain_SAMEnum' -Status Pass -RelatedFile $file -Evidence "RestrictRemoteSAM=$sddl" -Finding 'Remote SAM enumeration is restricted to Administrators.' }
    else { Add-WAFinding -CheckID 'domain_SAMEnum' -Status Warning -RelatedFile $file -Evidence "RestrictRemoteSAM=$sddl" -Finding ('Remote SAM enumeration is also granted to: ' + (($others | ForEach-Object { Resolve-WASidName -Sid $_ }) -join ', ')) }
}
#endregion

#region Checks - endpoint protection, name resolution, scripting & logging

function ConvertFrom-WAAvProductState {
    # Decodes SecurityCenter2 productState: byte 2 = scanner state (0x10 on, 0x11 snoozed, 0x00/0x01 off),
    # byte 1 = signature state (0x00 up to date, 0x10 out of date).
    # v1 used string offsets on a variable-length hex string, which broke for providers >= 0x10.
    [CmdletBinding()]
    param ([Parameter(Mandatory = $true)][long]$ProductState)
    $scanner = ($ProductState -shr 8) -band 0xFF
    $sig = $ProductState -band 0xFF
    return [pscustomobject]@{
        Enabled   = ($scanner -eq 0x10 -or $scanner -eq 0x11)
        UpToDate  = ($sig -eq 0x00)
        Hex       = ('0x{0:X6}' -f $ProductState)
    }
}

function Get-WAAsrRules {
    # Returns hashtable ruleGuid(lower) -> action (0 off, 1 block, 2 audit, 6 warn) from Defender and/or GPO registry.
    [CmdletBinding()]
    param ($MpPreference)
    $rules = @{}
    if ($MpPreference -and $MpPreference.AttackSurfaceReductionRules_Ids) {
        $ids = @($MpPreference.AttackSurfaceReductionRules_Ids); $acts = @($MpPreference.AttackSurfaceReductionRules_Actions)
        for ($i = 0; $i -lt $ids.Count; $i++) { $rules[([string]$ids[$i]).ToLower()] = [int]$acts[$i] }
    }
    $gpo = Get-WARegKeyValues -Path 'SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
    if ($gpo) { foreach ($k in $gpo.Keys) { if (-not $rules.ContainsKey($k.ToLower())) { $rules[$k.ToLower()] = [int]$gpo[$k] } } }
    return $rules
}

function Test-WAAntiVirus {
    # v1: checkAntiVirusStatus. Fixed: productState parsing, servers were never evaluated, Get-MpPreference errors
    # ("registry access is not allowed") uncaught. Added Defender RTP, tamper protection and ASR evaluation.
    [CmdletBinding()]
    param ([string]$Name)
    Write-WALog 'running Test-WAAntiVirus'
    Write-WAScreen 'Getting antivirus / Defender status...'
    $ctx = $script:WACtx
    $file = Get-WAFileName -Name $Name
    $mp = Invoke-WACmdlet -Name 'Get-MpComputerStatus'
    $pref = Invoke-WACmdlet -Name 'Get-MpPreference'
    $thirdPartyActive = $false

    if (-not $ctx.IsServer) {
        $avs = @(Get-WACimInstance -ClassName AntiVirusProduct -Namespace 'root\SecurityCenter2')
        Write-WAFile -File $file -Text '============= Security Center antivirus products =============', ($avs | Format-List displayName, pathToSignedProductExe, productState, timestamp | Out-String)
        if ($avs.Count -eq 0 -or $null -eq $avs[0]) {
            Add-WAFinding -CheckID 'machine_AVName' -Status Fail -RelatedFile $file -Finding 'No antivirus product is registered with Windows Security Center.'
        }
        else {
            $bad = @(); $lines = @()
            foreach ($av in $avs) {
                $s = ConvertFrom-WAAvProductState -ProductState ([long]$av.productState)
                $lines += ('{0}: state {1}, enabled={2}, signatures up to date={3}' -f $av.displayName, $s.Hex, $s.Enabled, $s.UpToDate)
                if (-not $s.Enabled -or -not $s.UpToDate) { $bad += $av.displayName }
                if ($s.Enabled -and $av.displayName -notmatch 'Windows Defender|Microsoft Defender') { $thirdPartyActive = $true }
            }
            $enabledAny = @($avs | Where-Object { (ConvertFrom-WAAvProductState -ProductState ([long]$_.productState)).Enabled -and (ConvertFrom-WAAvProductState -ProductState ([long]$_.productState)).UpToDate }).Count -gt 0
            if ($enabledAny) { Add-WAFinding -CheckID 'machine_AVName' -Status Pass -RelatedFile $file -Evidence ($lines -join ' | ') -Finding 'An enabled antivirus product with current signatures is registered.' }
            else { Add-WAFinding -CheckID 'machine_AVName' -Status Fail -RelatedFile $file -Evidence ($lines -join ' | ') -Finding ('No registered antivirus is both enabled and up to date: ' + ($bad -join ', ')) }
        }
    }
    else {
        # Security Center does not exist on servers - use Defender status.
        if ($mp) {
            $ok = $mp.AMServiceEnabled -and $mp.AntivirusEnabled -and ($mp.AntivirusSignatureAge -le 1)
            $ev = 'AMServiceEnabled={0}; AntivirusEnabled={1}; AMRunningMode={2}; SignatureAge={3} day(s)' -f $mp.AMServiceEnabled, $mp.AntivirusEnabled, $mp.AMRunningMode, $mp.AntivirusSignatureAge
            if ($ok) { Add-WAFinding -CheckID 'machine_AVName' -Status Pass -RelatedFile $file -Evidence $ev -Finding 'Microsoft Defender Antivirus is enabled with current signatures.' }
            elseif ([string]$mp.AMRunningMode -match 'Passive|EDR Block') { $thirdPartyActive = $true; Add-WAFinding -CheckID 'machine_AVName' -Status Manual -RelatedFile $file -Evidence $ev -Finding 'Defender runs in passive/EDR block mode - verify the primary (third-party) antivirus.' }
            else { Add-WAFinding -CheckID 'machine_AVName' -Status Fail -RelatedFile $file -Evidence $ev -Finding 'Microsoft Defender Antivirus is disabled or signatures are older than 1 day.' }
        }
        else {
            $thirdPartyActive = $true
            Add-WAFinding -CheckID 'machine_AVName' -Status Manual -RelatedFile $file -Finding 'Defender is not present/queryable on this server - verify the installed antivirus/EDR manually (see Software and Services outputs).'
        }
    }

    # --- Defender real-time and tamper protection
    if ($mp) {
        Write-WAFile -File $file -Text '============= Get-MpComputerStatus =============', ($mp | Format-List * | Out-String -Width 200)
        if ($thirdPartyActive -and [string]$mp.AMRunningMode -notmatch 'Normal') {
            Add-WAFinding -CheckID 'machine_DefenderRTP' -Status NotApplicable -RelatedFile $file -Finding 'A third-party antivirus is primary; Defender is not in active mode.'
            Add-WAFinding -CheckID 'machine_DefenderTamper' -Status NotApplicable -RelatedFile $file -Finding 'A third-party antivirus is primary; Defender is not in active mode.'
        }
        else {
            $ev = 'RealTimeProtectionEnabled={0}; BehaviorMonitorEnabled={1}; IoavProtectionEnabled={2}' -f $mp.RealTimeProtectionEnabled, $mp.BehaviorMonitorEnabled, $mp.IoavProtectionEnabled
            if ($mp.RealTimeProtectionEnabled) { Add-WAFinding -CheckID 'machine_DefenderRTP' -Status Pass -RelatedFile $file -Evidence $ev -Finding 'Defender real-time protection is on.' }
            else { Add-WAFinding -CheckID 'machine_DefenderRTP' -Status Fail -RelatedFile $file -Evidence $ev -Finding 'Defender real-time protection is OFF.' }
            if ($null -eq $mp.IsTamperProtected) { Add-WAFinding -CheckID 'machine_DefenderTamper' -Status Manual -RelatedFile $file -Finding 'Tamper protection state is not reported by this Defender platform version.' }
            elseif ($mp.IsTamperProtected) { Add-WAFinding -CheckID 'machine_DefenderTamper' -Status Pass -RelatedFile $file -Evidence 'IsTamperProtected=True' -Finding 'Defender tamper protection is on.' }
            else { Add-WAFinding -CheckID 'machine_DefenderTamper' -Status Fail -RelatedFile $file -Evidence 'IsTamperProtected=False' -Finding 'Defender tamper protection is off - local admins/malware can disable Defender.' }
        }
    }
    else {
        Add-WAFinding -CheckID 'machine_DefenderRTP' -Status NotApplicable -RelatedFile $file -Finding 'Microsoft Defender Antivirus is not present or not queryable.'
        Add-WAFinding -CheckID 'machine_DefenderTamper' -Status NotApplicable -RelatedFile $file -Finding 'Microsoft Defender Antivirus is not present or not queryable.'
    }

    # --- ASR rules
    $asr = Get-WAAsrRules -MpPreference $pref
    $actionName = @{ 0 = 'Off'; 1 = 'Block'; 2 = 'Audit'; 6 = 'Warn' }
    if ($pref) {
        Write-WAFile -File $file -Text '============= Get-MpPreference =============', ($pref | Format-List * | Out-String -Width 200)
    }
    Write-WAFile -File $file -Text '============= ASR rules (id = action) =============', (($asr.Keys | ForEach-Object { '{0} = {1}' -f $_, $actionName[$asr[$_]] }) -join [Environment]::NewLine)
    if (-not $mp -and $asr.Count -eq 0) {
        Add-WAFinding -CheckID 'machine_ASR-LSASS' -Status NotApplicable -RelatedFile $file -Finding 'Microsoft Defender is not present - ASR not available.'
        Add-WAFinding -CheckID 'machine_ASR-Office' -Status NotApplicable -RelatedFile $file -Finding 'Microsoft Defender is not present - ASR not available.'
    }
    else {
        $lsass = '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2'
        $a = $asr[$lsass]
        if ($a -eq 1) { Add-WAFinding -CheckID 'machine_ASR-LSASS' -Status Pass -RelatedFile $file -Evidence "$lsass=Block" -Finding 'ASR rule "Block credential stealing from LSASS" is in Block mode.' }
        elseif ($a -eq 2 -or $a -eq 6) { Add-WAFinding -CheckID 'machine_ASR-LSASS' -Status Warning -RelatedFile $file -Evidence ("{0}={1}" -f $lsass, $actionName[$a]) -Finding 'ASR LSASS rule is in audit/warn mode only.' }
        else { Add-WAFinding -CheckID 'machine_ASR-LSASS' -Status Fail -RelatedFile $file -Evidence "$lsass not configured" -Finding 'ASR rule "Block credential stealing from LSASS" is not enabled.' }

        $office = @('d4f940ab-401b-4efc-aadc-ad5f3c50688a', '3b576869-a4ec-4529-8536-b80a7769e899', '75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84', '92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b')
        $blocked = @($office | Where-Object { $asr[$_] -eq 1 }).Count
        $partial = @($office | Where-Object { $asr[$_] -eq 2 -or $asr[$_] -eq 6 }).Count
        $ev = ($office | ForEach-Object { '{0}={1}' -f $_.Substring(0, 8), $(if ($asr.ContainsKey($_)) { $actionName[$asr[$_]] } else { 'NotConfigured' }) }) -join '; '
        if ($blocked -eq $office.Count) { Add-WAFinding -CheckID 'machine_ASR-Office' -Status Pass -RelatedFile $file -Evidence $ev -Finding 'All four Office ASR rules are in Block mode.' }
        elseif ($blocked + $partial -gt 0) { Add-WAFinding -CheckID 'machine_ASR-Office' -Status Warning -RelatedFile $file -Evidence $ev -Finding ("{0} of 4 Office ASR rules block; {1} audit/warn only." -f $blocked, $partial) }
        else { Add-WAFinding -CheckID 'machine_ASR-Office' -Status Fail -RelatedFile $file -Evidence $ev -Finding 'None of the Office ASR rules are enabled.' }
    }
}

function Test-WAFirewall {
    # v1: dataWinFirewall (evidence only). Adds the profile-state check.
    [CmdletBinding()]
    param ([string]$Name)
    Write-WALog 'running Test-WAFirewall'
    Write-WAScreen 'Getting Windows Firewall configuration...'
    $ctx = $script:WACtx
    $file = Get-WAFileName -Name $Name
    $svc = Get-WAService -Name 'mpssvc'
    if ($null -eq $svc -or [string]$svc.Status -ne 'Running') {
        Write-WAFile -File $file -Text 'The Windows Firewall service (mpssvc) is not running.'
        Add-WAFinding -CheckID 'machine_FirewallProfiles' -Status Fail -RelatedFile $file -Evidence ('mpssvc status: ' + $(if ($svc) { $svc.Status } else { 'not found' })) -Finding 'The Windows Firewall service is not running.'
        return
    }
    $profiles = Invoke-WACmdlet -Name 'Get-NetFirewallProfile' -Parameters @{ PolicyStore = 'ActiveStore' }
    if ($profiles) {
        Write-WAFile -File $file -Text '============= Get-NetFirewallProfile (ActiveStore) =============', ($profiles | Format-Table -AutoSize Name, Enabled, DefaultInboundAction, DefaultOutboundAction, AllowLocalFirewallRules, LogBlocked | Out-String -Width 200)
        $off = @($profiles | Where-Object { [string]$_.Enabled -ne 'True' } | ForEach-Object { $_.Name })
        $allowIn = @($profiles | Where-Object { [string]$_.DefaultInboundAction -eq 'Allow' } | ForEach-Object { $_.Name })
        $ev = ($profiles | ForEach-Object { '{0}: Enabled={1}, Inbound={2}' -f $_.Name, $_.Enabled, $_.DefaultInboundAction }) -join '; '
        if ($off.Count -gt 0) { Add-WAFinding -CheckID 'machine_FirewallProfiles' -Status Fail -RelatedFile $file -Evidence $ev -Finding ('Windows Firewall is disabled for profile(s): ' + ($off -join ', ')) }
        elseif ($allowIn.Count -gt 0) { Add-WAFinding -CheckID 'machine_FirewallProfiles' -Status Fail -RelatedFile $file -Evidence $ev -Finding ('Default inbound action is Allow for profile(s): ' + ($allowIn -join ', ')) }
        else { Add-WAFinding -CheckID 'machine_FirewallProfiles' -Status Pass -RelatedFile $file -Evidence $ev -Finding 'Windows Firewall is enabled on all profiles with default inbound Block.' }
    }
    else {
        $st = Invoke-WANative -FilePath 'netsh.exe' -ArgumentList @('advfirewall', 'show', 'allprofiles', 'state')
        Write-WAFile -File $file -Text $st
        Add-WAFinding -CheckID 'machine_FirewallProfiles' -Status Manual -RelatedFile $file -Evidence (($st | Where-Object { $_ -match '\S' }) -join ' | ') -Finding 'Firewall profile state collected via netsh - review manually.'
    }
    if ($ctx.IsAdmin) {
        $rules = Get-WAFirewallRuleExport
        if ($rules) { Write-WACsv -FullPath (Join-Path $ctx.DetailPath (Get-WAFileName -Name ($Name + '-Rules') -Extension '.csv')) -InputObject $rules }
        $wfw = Join-Path $ctx.DetailPath (Get-WAFileName -Name $Name -Extension '.wfw')
        Invoke-WANative -FilePath 'netsh.exe' -ArgumentList @('advfirewall', 'export', $wfw) | Out-Null
        Write-WAFile -File $file -Text "Firewall policy exported to $wfw (import into a test GPO: Windows Defender Firewall > Import Policy)."
    }
}

function Get-WAFirewallRuleExport {
    # Enabled firewall rules with their port/address/application filters (slow on hosts with thousands of rules).
    [CmdletBinding()]
    param ()
    if (-not (Get-Command -Name Get-NetFirewallRule -ErrorAction SilentlyContinue)) { return $null }
    try {
        $rules = @(Get-NetFirewallRule -PolicyStore ActiveStore -Enabled True -ErrorAction Stop)
        $ports = @{}; foreach ($f in @(Get-NetFirewallPortFilter -PolicyStore ActiveStore -ErrorAction SilentlyContinue)) { $ports[$f.InstanceID] = $f }
        $addrs = @{}; foreach ($f in @(Get-NetFirewallAddressFilter -PolicyStore ActiveStore -ErrorAction SilentlyContinue)) { $addrs[$f.InstanceID] = $f }
        $apps = @{}; foreach ($f in @(Get-NetFirewallApplicationFilter -PolicyStore ActiveStore -ErrorAction SilentlyContinue)) { $apps[$f.InstanceID] = $f }
        return @($rules | ForEach-Object {
                $id = $_.InstanceID
                [pscustomobject]@{
                    Name = $_.Name; DisplayName = $_.DisplayName; Group = $_.DisplayGroup; Direction = [string]$_.Direction; Action = [string]$_.Action
                    Profile = [string]$_.Profile; Protocol = $ports[$id].Protocol; LocalPort = (@($ports[$id].LocalPort) -join ',')
                    RemotePort = (@($ports[$id].RemotePort) -join ','); RemoteAddress = (@($addrs[$id].RemoteAddress) -join ',')
                    Program = $apps[$id].Program; Source = [string]$_.PolicyStoreSourceType
                }
            })
    }
    catch { Write-WALog ('Get-WAFirewallRuleExport: ' + $_.Exception.Message); return $null }
}

function Test-WANameResolution {
    # v1: checkLLMNRAndNetBIOS. Adds CSV results for NetBIOS over TCP/IP (v1 only dumped raw data) and mDNS.
    [CmdletBinding()]
    param ([string]$Name)
    Write-WALog 'running Test-WANameResolution'
    Write-WAScreen 'Getting LLMNR / NetBIOS / mDNS configuration...'
    $ctx = $script:WACtx
    $file = Get-WAFileName -Name $Name

    # LLMNR
    $llmnr = Get-WARegValue -Path 'SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name 'EnableMulticast'
    Write-WAFile -File $file -Text '============= LLMNR =============', "Policy EnableMulticast = $llmnr"
    if ($llmnr -eq 0) { Add-WAFinding -CheckID 'domain_LLMNR' -Status Pass -RelatedFile $file -Evidence 'EnableMulticast=0' -Finding 'LLMNR is disabled by policy.' }
    else { Add-WAFinding -CheckID 'domain_LLMNR' -Status Fail -RelatedFile $file -Evidence "EnableMulticast=$llmnr" -Finding 'LLMNR is enabled - hosts answer poisoned name queries (Responder/Inveigh).' }

    # NetBIOS over TCP/IP per active adapter (0 = DHCP decides, 1 = enabled, 2 = disabled)
    $adapters = @(Get-WACimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True')
    $nbRows = @($adapters | Where-Object { $_ } | ForEach-Object { [pscustomobject]@{ Adapter = $_.Description; Setting = [int]$_.TcpipNetbiosOptions } })
    if ($nbRows.Count -eq 0) {
        foreach ($k in (Get-WARegSubKeyNames -Path 'SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces')) {
            $v = Get-WARegValue -Path ("SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\{0}" -f $k) -Name 'NetbiosOptions'
            $nbRows += [pscustomobject]@{ Adapter = $k; Setting = [int]$v }
        }
    }
    $nbEnabled = @($nbRows | Where-Object { $_.Setting -ne 2 })
    $nbEv = ($nbRows | ForEach-Object { '{0}={1}' -f $_.Adapter, $_.Setting }) -join '; '
    Write-WAFile -File $file -Text '============= NetBIOS over TCP/IP (0=DHCP/default, 1=enabled, 2=disabled) =============', ($nbRows | Format-Table -AutoSize | Out-String)
    if ($nbRows.Count -eq 0) { Add-WAFinding -CheckID 'domain_NetBIOSoTCP' -Status Manual -RelatedFile $file -Finding 'No network adapters could be enumerated.' }
    elseif ($nbEnabled.Count -eq 0) { Add-WAFinding -CheckID 'domain_NetBIOSoTCP' -Status Pass -RelatedFile $file -Evidence $nbEv -Finding 'NetBIOS over TCP/IP is disabled on all active adapters.' }
    else { Add-WAFinding -CheckID 'domain_NetBIOSoTCP' -Status Fail -RelatedFile $file -Evidence $nbEv -Finding ('NetBIOS over TCP/IP is enabled (or DHCP-controlled) on: ' + (($nbEnabled | ForEach-Object { $_.Adapter }) -join ', ')) }

    # Node type
    $node = Get-WARegValue -Path 'SYSTEM\CurrentControlSet\Services\NetBT\Parameters' -Name 'NodeType'
    $nodeName = switch ($node) { 1 { 'B-node (broadcast)' } 2 { 'P-node (WINS only)' } 4 { 'M-node (broadcast, then WINS)' } 8 { 'H-node (WINS, then broadcast)' } default { 'not set (B-node, or H-node when WINS is configured)' } }
    Write-WAFile -File $file -Text '============= NetBIOS node type =============', "NodeType = $node ($nodeName)"
    if ($node -eq 2) { Add-WAFinding -CheckID 'domain_NetBIOSNT' -Status Pass -RelatedFile $file -Evidence 'NodeType=2' -Finding 'NetBIOS node type is P-node - no broadcast name resolution.' }
    elseif ($nbRows.Count -gt 0 -and $nbEnabled.Count -eq 0) { Add-WAFinding -CheckID 'domain_NetBIOSNT' -Status Pass -RelatedFile $file -Evidence "NodeType=$node; NetBIOS disabled on all adapters" -Finding 'Node type is not P-node, but NetBIOS over TCP/IP is disabled on all adapters (not exploitable).' }
    else { Add-WAFinding -CheckID 'domain_NetBIOSNT' -Status Fail -RelatedFile $file -Evidence "NodeType=$node" -Finding "NetBIOS name resolution uses broadcasts: $nodeName." }

    # mDNS
    if ($ctx.WinVersion.Major -lt 10) {
        Add-WAFinding -CheckID 'domain_mDNS' -Status NotApplicable -RelatedFile $file -Finding 'The Windows DNS client mDNS responder exists only on Windows 10 / Server 2016+.'
    }
    else {
        $m1 = Get-WARegValue -Path 'SYSTEM\CurrentControlSet\Services\Dnscache\Parameters' -Name 'EnableMDNS'
        $m2 = Get-WARegValue -Path 'SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name 'EnableMDNS'
        $ev = "Dnscache EnableMDNS=$m1; policy EnableMDNS=$m2"
        Write-WAFile -File $file -Text '============= mDNS =============', $ev
        if ($m1 -eq 0 -or $m2 -eq 0) { Add-WAFinding -CheckID 'domain_mDNS' -Status Pass -RelatedFile $file -Evidence $ev -Finding 'The mDNS responder is disabled.' }
        else { Add-WAFinding -CheckID 'domain_mDNS' -Status Warning -RelatedFile $file -Evidence $ev -Finding 'mDNS is enabled (Windows default) - Responder can poison mDNS answers unless UDP 5353 is filtered.' }
    }
}

function Test-WAMitm6 {
    # New (v1 TODO): exposure to DHCPv6/DNS takeover (mitm6) - IPv6 enabled with DHCPv6 not filtered.
    [CmdletBinding()]
    param ([string]$Name)
    Write-WALog 'running Test-WAMitm6'
    $ctx = $script:WACtx
    $file = Get-WAFileName -Name $Name
    if (-not $ctx.PartOfDomain) { Add-WAFinding -CheckID 'domain_mitm6' -Status NotApplicable -RelatedFile $file -Finding 'Not domain joined - mitm6 targets AD DNS/NTLM relay.'; return }
    $dc = Get-WARegValue -Path 'SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters' -Name 'DisabledComponents'
    if ($null -ne $dc -and (([int64]$dc -band 0xFF) -eq 0xFF)) {
        Add-WAFinding -CheckID 'domain_mitm6' -Status Pass -RelatedFile $file -Evidence ('DisabledComponents=0x{0:X}' -f [int64]$dc) -Finding 'IPv6 is disabled on all interfaces (note: Microsoft recommends prefer-IPv4 0x20 instead of disabling).'
        return
    }
    $bind = @(Invoke-WACmdlet -Name 'Get-NetAdapterBinding' -Parameters @{ ComponentID = 'ms_tcpip6' })
    $bound = @($bind | Where-Object { $_ -and $_.Enabled })
    if ($bind.Count -gt 0 -and $null -ne $bind[0] -and $bound.Count -eq 0) {
        Add-WAFinding -CheckID 'domain_mitm6' -Status Pass -RelatedFile $file -Evidence 'ms_tcpip6 unbound on all adapters' -Finding 'IPv6 is not bound to any adapter.'
        return
    }
    $rule = Invoke-WACmdlet -Name 'Get-NetFirewallRule' -Parameters @{ Name = 'CoreNet-DHCPV6-In'; PolicyStore = 'ActiveStore' }
    $blockPorts = @(Get-WAFirewallBlockedPorts -Direction Inbound -Protocol UDP)
    $ev = 'IPv6 bound adapters={0}; CoreNet-DHCPV6-In Enabled={1} Action={2}; inbound UDP block ports={3}' -f $bound.Count, $(if ($rule) { $rule.Enabled } else { 'n/a' }), $(if ($rule) { $rule.Action } else { 'n/a' }), ($blockPorts -join ',')
    Write-WAFile -File $file -Text '============= IPv6 / DHCPv6 (mitm6) =============', $ev
    if ($blockPorts -contains '546' -or ($rule -and [string]$rule.Enabled -ne 'True')) {
        Add-WAFinding -CheckID 'domain_mitm6' -Status Pass -RelatedFile $file -Evidence $ev -Finding 'Inbound DHCPv6 is blocked/disabled - rogue DHCPv6 (mitm6) cannot configure this host.'
    }
    elseif ($null -eq $rule -and $blockPorts.Count -eq 0 -and -not $ctx.IsAdmin) {
        Add-WAFinding -CheckID 'domain_mitm6' -Status Manual -RelatedFile $file -Evidence $ev -Finding 'IPv6 is enabled; firewall rules could not be read without elevation.'
    }
    else {
        Add-WAFinding -CheckID 'domain_mitm6' -Status Warning -RelatedFile $file -Evidence $ev -Finding 'IPv6 is enabled and inbound DHCPv6 is allowed - an attacker on the segment can become the DNS server (mitm6) and relay NTLM.'
    }
}

function Get-WAFirewallBlockedPorts {
    [CmdletBinding()]
    param ([ValidateSet('Inbound', 'Outbound')][string]$Direction = 'Inbound', [string]$Protocol = 'UDP')
    if (-not (Get-Command -Name Get-NetFirewallRule -ErrorAction SilentlyContinue)) { return @() }
    try {
        $rules = @(Get-NetFirewallRule -PolicyStore ActiveStore -Direction $Direction -Action Block -Enabled True -ErrorAction Stop)
        $ports = foreach ($r in $rules) { $f = $r | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue; if ($f.Protocol -eq $Protocol) { @($f.LocalPort) } }
        return @($ports | ForEach-Object { [string]$_ } | Select-Object -Unique)
    }
    catch { return @() }
}

function Test-WAPowerShellVersion {
    # v1: checkPowershellVer. Fixed: Start-Job -PSVersion 2.0 gives a false positive on PowerShell 7 (runs the job in
    # PS7) and "Get-Job | Remove-Job" deleted all of the user's jobs. Now: optional-feature state (authoritative) or
    # engine registration + CLR2 presence.
    [CmdletBinding()]
    param ([string]$Name)
    Write-WALog 'running Test-WAPowerShellVersion'
    Write-WAScreen 'Checking for the PowerShell 2.0 engine...'
    $ctx = $script:WACtx
    $file = Get-WAFileName -Name $Name
    Write-WAFile -File $file -Text ('Running on PowerShell ' + $PSVersionTable.PSVersion), 'PowerShell 2.0 lacks AMSI, script block logging and constrained language mode (downgrade attack).'
    $state = $null; $src = ''
    if ($ctx.IsServer) {
        $f = Invoke-WACmdlet -Name 'Get-WindowsFeature' -Parameters @{ Name = 'PowerShell-V2' }
        if ($f) { $state = if ($f.Installed) { 'Enabled' } else { 'Disabled' }; $src = 'Get-WindowsFeature PowerShell-V2' }
    }
    elseif ($ctx.IsAdmin) {
        $opt = $ctx.Cache['OptionalFeatures']
        $f = if ($opt) { $opt | Where-Object { $_.FeatureName -eq 'MicrosoftWindowsPowerShellV2Root' } } else { Invoke-WACmdlet -Name 'Get-WindowsOptionalFeature' -Parameters @{ Online = $true; FeatureName = 'MicrosoftWindowsPowerShellV2Root' } }
        if ($f) { $state = if ([string]$f.State -eq 'Enabled') { 'Enabled' } else { 'Disabled' }; $src = 'Optional feature MicrosoftWindowsPowerShellV2Root=' + $f.State }
    }
    $engine = Get-WARegValue -Path 'SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine' -Name 'PowerShellVersion'
    $clr2 = (Get-WARegValue -Path 'SOFTWARE\Microsoft\NET Framework Setup\NDP\v2.0.50727' -Name 'Install') -eq 1 -or (Get-WARegValue -Path 'SOFTWARE\Microsoft\NET Framework Setup\NDP\v3.5' -Name 'Install') -eq 1
    $ev = 'Feature: {0}; PowerShellEngine\1 version={1}; .NET 2.0/3.5 CLR present={2}' -f $(if ($src) { $src } else { 'not queried (requires elevation)' }), $engine, $clr2
    Write-WAFile -File $file -Text $ev
    if ($null -eq $state) { $state = if ($engine -eq '2.0' -or $engine -eq '1.0') { 'Enabled' } else { 'Disabled' } }
    if ($state -eq 'Enabled' -and $clr2) { Add-WAFinding -CheckID 'machine_PSv2' -Status Fail -RelatedFile $file -Evidence $ev -Finding 'The PowerShell 2.0 engine is installed and runnable (.NET 3.5 present) - logging/AMSI can be bypassed with "powershell -version 2".' }
    elseif ($state -eq 'Enabled') { Add-WAFinding -CheckID 'machine_PSv2' -Status Warning -RelatedFile $file -Evidence $ev -Finding 'The PowerShell 2.0 engine is installed but .NET 3.5 is missing (not runnable until .NET 3.5 is added).' }
    else { Add-WAFinding -CheckID 'machine_PSv2' -Status Pass -RelatedFile $file -Evidence $ev -Finding 'The PowerShell 2.0 engine is not installed.' }
}

function Test-WANtlmLevel {
    # v1: checkNTLMv2. Fixed: the "unknown level" branch threw a parameter-binding error ("-str 'a' + $x"); now evaluated
    # on non-domain hosts too; DCs below level 5 flagged.
    [CmdletBinding()]
    param ([string]$Name)
    Write-WALog 'running Test-WANtlmLevel'
    Write-WAScreen 'Getting LAN Manager authentication level...'
    $ctx = $script:WACtx
    $file = Get-WAFileName -Name $Name
    $lvl = Get-WARegValue -Path 'SYSTEM\CurrentControlSet\Control\Lsa' -Name 'LmCompatibilityLevel'
    $desc = @{ 0 = 'Send LM & NTLM responses'; 1 = 'Send LM & NTLM - use NTLMv2 session security if negotiated'; 2 = 'Send NTLM response only'; 3 = 'Send NTLMv2 response only'; 4 = 'Send NTLMv2 response only. Refuse LM'; 5 = 'Send NTLMv2 response only. Refuse LM & NTLM' }
    $eff = if ($null -eq $lvl) { 3 } else { [int]$lvl }
    $ev = 'LmCompatibilityLevel={0} (effective {1}: {2})' -f $(if ($null -eq $lvl) { 'not set' } else { $lvl }), $eff, $desc[$eff]
    Write-WAFile -File $file -Text '============= LAN Manager authentication level =============', $ev
    if ($eff -le 2) { Add-WAFinding -CheckID 'domain_NTLMComLevel' -Status Fail -RelatedFile $file -Evidence $ev -Finding "LM/NTLMv1 responses are sent (level $eff) - captured hashes are trivially crackable/relayable." }
    elseif ($eff -eq 5) { Add-WAFinding -CheckID 'domain_NTLMComLevel' -Status Pass -RelatedFile $file -Evidence $ev -Finding 'Only NTLMv2 is sent and LM/NTLMv1 are refused (level 5).' }
    elseif ($eff -in 3, 4) {
        if ($ctx.IsDC) { Add-WAFinding -CheckID 'domain_NTLMComLevel' -Status Warning -RelatedFile $file -Evidence $ev -Finding "Domain controller accepts NTLMv1 authentication (level $eff); set level 5 once NTLMv1 usage is ruled out." }
        else { Add-WAFinding -CheckID 'domain_NTLMComLevel' -Status Pass -RelatedFile $file -Evidence $ev -Finding "Only NTLMv2 responses are sent (level $eff)." }
    }
    else { Add-WAFinding -CheckID 'domain_NTLMComLevel' -Status Manual -RelatedFile $file -Evidence $ev -Finding "Unexpected LmCompatibilityLevel value ($lvl)." }
}

function Test-WAGpoReprocess {
    # v1: checkGPOReprocess. Fixed: "registry policy not configured" was reported as a strength while the identical
    # state for scripts/security was a finding. Non-domain hosts are N/A.
    [CmdletBinding()]
    param ([string]$Name)
    Write-WALog 'running Test-WAGpoReprocess'
    Write-WAScreen 'Getting GPO reprocessing configuration...'
    $file = Get-WAFileName -Name $Name
    $items = @(
        @{ Id = 'domain_GPOReRegistry'; Guid = '{35378EAC-683F-11D2-A89A-00C04FBBCFA2}'; Label = 'registry' },
        @{ Id = 'domain_GPOReScript'; Guid = '{42B5FAAE-6536-11d2-AE5A-0000F87571E3}'; Label = 'scripts' },
        @{ Id = 'domain_GPOReSecurity'; Guid = '{827D319E-6EAC-11D2-A4EA-00C04F79F83A}'; Label = 'security' }
    )
    Write-WAFile -File $file -Text '============= GPO reprocessing =============', 'Without reprocessing, a local administrator can override a GPO setting and it stays overridden until the GPO itself changes.'
    foreach ($i in $items) {
        if (-not $script:WACtx.PartOfDomain) { Add-WAFinding -CheckID $i.Id -Status NotApplicable -RelatedFile $file -Finding 'Not domain joined - no domain GPOs.'; continue }
        $v = Get-WARegValue -Path ("SOFTWARE\Policies\Microsoft\Windows\Group Policy\{0}" -f $i.Guid) -Name 'NoGPOListChanges'
        Write-WAFile -File $file -Text ("{0} policy ({1}): NoGPOListChanges = {2}" -f $i.Label, $i.Guid, $v)
        if ($v -eq 0) { Add-WAFinding -CheckID $i.Id -Status Pass -RelatedFile $file -Evidence 'NoGPOListChanges=0' -Finding ("GPO {0} policy is reprocessed even when unchanged." -f $i.Label) }
        elseif ($v -eq 1) { Add-WAFinding -CheckID $i.Id -Status Fail -RelatedFile $file -Evidence 'NoGPOListChanges=1' -Finding ("GPO {0} policy reprocessing is explicitly disabled." -f $i.Label) }
        else { Add-WAFinding -CheckID $i.Id -Status Fail -RelatedFile $file -Evidence 'NoGPOListChanges not set' -Finding ("GPO {0} policy reprocessing is not configured (only applied when the GPO changes)." -f $i.Label) }
    }
}

function Test-WAInstallElevated {
    # v1: checkInstallElevated. Fixed: only HKLM was read; the escalation requires HKLM *and* HKCU = 1.
    [CmdletBinding()]
    param ([string]$Name)
    Write-WALog 'running Test-WAInstallElevated'
    $file = Get-WAFileName -Name $Name
    $lm = Get-WARegValue -Hive HKLM -Path 'SOFTWARE\Policies\Microsoft\Windows\Installer' -Name 'AlwaysInstallElevated'
    $cu = Get-WARegValue -Hive HKCU -Path 'SOFTWARE\Policies\Microsoft\Windows\Installer' -Name 'AlwaysInstallElevated'
    $ev = "HKLM=$lm; HKCU=$cu (HKCU evaluated for the account running the script)"
    Write-WAFile -File $file -Text '============= AlwaysInstallElevated =============', $ev
    if ($lm -eq 1 -and $cu -eq 1) { Add-WAFinding -CheckID 'machine_installWithElevation' -Status Fail -RelatedFile $file -Evidence $ev -Finding 'AlwaysInstallElevated is enabled in HKLM and HKCU - any user can install an MSI as SYSTEM.' }
    elseif ($lm -eq 1 -or $cu -eq 1) { Add-WAFinding -CheckID 'machine_installWithElevation' -Status Warning -RelatedFile $file -Evidence $ev -Finding 'AlwaysInstallElevated is enabled in one hive only - not exploitable alone, but one user-policy change away (check other users).' }
    else { Add-WAFinding -CheckID 'machine_installWithElevation' -Status Pass -RelatedFile $file -Evidence $ev -Finding 'AlwaysInstallElevated is not enabled.' }
}

function Test-WAPowerShellLogging {
    # v1: checkPowerShellAudit. Fixed: HKCU module-logging logic was inverted AND never matched (read .Property from
    # Get-ItemProperty output), so it always reported "enabled on all modules".
    [CmdletBinding()]
    param ([string]$Name)
    Write-WALog 'running Test-WAPowerShellLogging'
    Write-WAScreen 'Getting PowerShell logging policies...'
    $file = Get-WAFileName -Name $Name
    $base = 'SOFTWARE\Policies\Microsoft\Windows\PowerShell'
    Write-WAFile -File $file -Text '============= PowerShell logging =============', 'Module logging (4103), Script block logging (4104) and Transcription together form the PowerShell audit trail.'

    # Module logging
    $mlLm = Get-WARegValue -Hive HKLM -Path "$base\ModuleLogging" -Name 'EnableModuleLogging'
    $mlCu = Get-WARegValue -Hive HKCU -Path "$base\ModuleLogging" -Name 'EnableModuleLogging'
    $modsLm = @(Get-WARegValueList -Hive HKLM -Path "$base\ModuleLogging\ModuleNames")
    $modsCu = @(Get-WARegValueList -Hive HKCU -Path "$base\ModuleLogging\ModuleNames")
    $ev = 'HKLM Enable={0} Modules=[{1}]; HKCU Enable={2} Modules=[{3}]' -f $mlLm, ($modsLm -join ','), $mlCu, ($modsCu -join ',')
    Write-WAFile -File $file -Text "Module logging: $ev"
    if ($mlLm -eq 1 -and $modsLm -contains '*') { Add-WAFinding -CheckID 'machine_PSModuleLog' -Status Pass -RelatedFile $file -Evidence $ev -Finding 'Module logging is enabled machine-wide for all modules.' }
    elseif ($mlLm -eq 1) { Add-WAFinding -CheckID 'machine_PSModuleLog' -Status Warning -RelatedFile $file -Evidence $ev -Finding 'Module logging is enabled machine-wide but not for all modules (*).' }
    elseif ($mlCu -eq 1) { Add-WAFinding -CheckID 'machine_PSModuleLog' -Status Warning -RelatedFile $file -Evidence $ev -Finding 'Module logging is configured for the current user only.' }
    else { Add-WAFinding -CheckID 'machine_PSModuleLog' -Status Fail -RelatedFile $file -Evidence $ev -Finding 'PowerShell module logging is not enabled.' }

    # Script block logging
    $sbLm = Get-WARegValue -Hive HKLM -Path "$base\ScriptBlockLogging" -Name 'EnableScriptBlockLogging'
    $sbCu = Get-WARegValue -Hive HKCU -Path "$base\ScriptBlockLogging" -Name 'EnableScriptBlockLogging'
    $sbInv = Get-WARegValue -Hive HKLM -Path "$base\ScriptBlockLogging" -Name 'EnableScriptBlockInvocationLogging'
    $ev = "HKLM Enable=$sbLm Invocation=$sbInv; HKCU Enable=$sbCu"
    Write-WAFile -File $file -Text "Script block logging: $ev"
    if ($sbLm -eq 1) { Add-WAFinding -CheckID 'machine_PSScriptBlock' -Status Pass -RelatedFile $file -Evidence $ev -Finding 'Script block logging is enabled machine-wide.' -Comment $(if ($sbInv -ne 1) { 'Invocation logging (start/stop events) is off - optional, high volume.' } else { '' }) }
    elseif ($sbCu -eq 1) { Add-WAFinding -CheckID 'machine_PSScriptBlock' -Status Warning -RelatedFile $file -Evidence $ev -Finding 'Script block logging is configured for the current user only.' }
    else { Add-WAFinding -CheckID 'machine_PSScriptBlock' -Status Fail -RelatedFile $file -Evidence $ev -Finding 'Script block logging is not enabled (only automatic "suspicious" block logging applies).' }

    # Transcription
    $trLm = Get-WARegKeyValues -Hive HKLM -Path "$base\Transcription"
    $trCu = Get-WARegKeyValues -Hive HKCU -Path "$base\Transcription"
    $scope = $null; $tr = $null
    if ($trLm -and $trLm['EnableTranscripting'] -eq 1) { $scope = 'machine'; $tr = $trLm }
    elseif ($trCu -and $trCu['EnableTranscripting'] -eq 1) { $scope = 'user'; $tr = $trCu }
    if ($null -eq $tr) {
        Add-WAFinding -CheckID 'machine_PSTranscript' -Status Fail -RelatedFile $file -Evidence 'EnableTranscripting not set' -Finding 'PowerShell transcription is not enabled.'
    }
    else {
        $ev = 'Scope={0}; OutputDirectory={1}; EnableInvocationHeader={2}' -f $scope, $tr['OutputDirectory'], $tr['EnableInvocationHeader']
        Write-WAFile -File $file -Text "Transcription: $ev"
        $gaps = @()
        if (-not $tr['OutputDirectory']) { $gaps += 'no central OutputDirectory (transcripts stay in user profiles)' }
        if ($tr['EnableInvocationHeader'] -ne 1) { $gaps += 'invocation headers off' }
        if ($scope -eq 'user') { $gaps += 'current user only' }
        if ($gaps.Count -eq 0) { Add-WAFinding -CheckID 'machine_PSTranscript' -Status Pass -RelatedFile $file -Evidence $ev -Finding 'Transcription is enabled machine-wide with invocation headers and a central output directory.' }
        else { Add-WAFinding -CheckID 'machine_PSTranscript' -Status Warning -RelatedFile $file -Evidence $ev -Finding ('Transcription is enabled but: ' + ($gaps -join '; ')) }
    }
}

function Test-WACommandLineAudit {
    # v1: checkCommandLineAudit. Fixed: version gate, one CSV row per auditpol line, English-only substring match.
    [CmdletBinding()]
    param ([string]$Name)
    Write-WALog 'running Test-WACommandLineAudit'
    $ctx = $script:WACtx
    $file = Get-WAFileName -Name $Name
    $reg = Get-WARegValue -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -Name 'ProcessCreationIncludeCmdLine_Enabled'
    $sysmon = (Get-WAService -Name 'Sysmon64') -or (Get-WAService -Name 'Sysmon')
    $audit = $null
    if ($ctx.IsAdmin) {
        # Subcategory GUID is locale independent; /r gives CSV output.
        $out = @(Invoke-WANative -FilePath 'auditpol.exe' -ArgumentList @('/get', '/subcategory:{0CCE922B-69AE-11D9-BED3-505054503030}', '/r'))
        $row = $out | Where-Object { $_ -match '0CCE922B' } | Select-Object -First 1
        if ($row) { $cols = $row -split ','; if ($cols.Count -ge 5) { $audit = $cols[4].Trim() } }
    }
    $ev = 'ProcessCreationIncludeCmdLine_Enabled={0}; Process Creation audit={1}; Sysmon installed={2}' -f $reg, $(if ($audit) { $audit } else { 'unknown (requires elevation)' }), [bool]$sysmon
    Write-WAFile -File $file -Text '============= Command-line process auditing (4688) =============', $ev
    if ($reg -ne 1) { Add-WAFinding -CheckID 'machine_ComLineLog' -Status Fail -RelatedFile $file -Evidence $ev -Finding 'Command lines are not included in process creation events.' -Comment $(if ($sysmon) { 'Sysmon (event 1) may compensate.' } else { '' }) }
    elseif ($null -eq $audit) { Add-WAFinding -CheckID 'machine_ComLineLog' -Status Manual -RelatedFile $file -Evidence $ev -Finding 'Command-line inclusion is enabled; the Process Creation audit subcategory could not be verified without elevation.' }
    elseif ($audit -match 'Success') { Add-WAFinding -CheckID 'machine_ComLineLog' -Status Pass -RelatedFile $file -Evidence $ev -Finding 'Process creation auditing with command lines is enabled.' }
    elseif ($audit -match 'No Auditing|Failure') { Add-WAFinding -CheckID 'machine_ComLineLog' -Status Fail -RelatedFile $file -Evidence $ev -Finding 'Command-line inclusion is enabled but the Process Creation audit subcategory does not log Success (no 4688 events).' }
    else { Add-WAFinding -CheckID 'machine_ComLineLog' -Status Manual -RelatedFile $file -Evidence $ev -Finding "Unrecognised auditpol value '$audit' (localized OS?) - verify manually." }
}

function Test-WAEventLogSize {
    # v1: checkLogSize. Fixed: Setup log read property 'Enable' (actual: 'Enabled') and crashed on [String]::Parse;
    # "default is 1MB" was wrong (20 MB since Vista); effective size now read when no policy is set.
    [CmdletBinding()]
    param ([string]$Name)
    Write-WALog 'running Test-WAEventLogSize'
    Write-WAScreen 'Getting event log size configuration...'
    $file = Get-WAFileName -Name $Name
    $logs = @(
        @{ Log = 'Application'; Id = 'machine_AppMaxLog'; MinKB = 32768 },
        @{ Log = 'System'; Id = 'machine_SysMaxLog'; MinKB = 32768 },
        @{ Log = 'Security'; Id = 'machine_SecMaxLog'; MinKB = 196608 },
        @{ Log = 'Setup'; Id = 'machine_SetupMaxLog'; MinKB = 32768 }
    )
    Write-WAFile -File $file -Text '============= Event log maximum sizes ============='
    foreach ($l in $logs) {
        $kb = Get-WARegValue -Path ("SOFTWARE\Policies\Microsoft\Windows\EventLog\{0}" -f $l.Log) -Name 'MaxSize'
        $src = 'policy'
        if ($null -eq $kb) {
            $info = Invoke-WACmdlet -Name 'Get-WinEvent' -Parameters @{ ListLog = $l.Log }
            if ($info) { $kb = [math]::Round($info.MaximumSizeInBytes / 1KB); $src = 'effective (no policy)' }
            else {
                $b = Get-WARegValue -Path ("SYSTEM\CurrentControlSet\Services\EventLog\{0}" -f $l.Log) -Name 'MaxSize'
                if ($null -ne $b) { $kb = [math]::Round($b / 1KB); $src = 'effective (service registry)' }
            }
        }
        if ($null -eq $kb) {
            Add-WAFinding -CheckID $l.Id -Status Manual -RelatedFile $file -Finding ("{0} log size could not be read." -f $l.Log)
            continue
        }
        $ev = '{0}: {1} ({2}); recommended >= {3}' -f $l.Log, (Format-WASize $kb), $src, (Format-WASize $l.MinKB)
        Write-WAFile -File $file -Text $ev
        if ([double]$kb -ge $l.MinKB) { Add-WAFinding -CheckID $l.Id -Status Pass -RelatedFile $file -Evidence $ev -Finding ("{0} log maximum size is {1}." -f $l.Log, (Format-WASize $kb)) }
        else { Add-WAFinding -CheckID $l.Id -Status Fail -RelatedFile $file -Evidence $ev -Finding ("{0} log maximum size is {1} (below {2}) - evidence rolls over quickly unless forwarded to a SIEM." -f $l.Log, (Format-WASize $kb), (Format-WASize $l.MinKB)) }
    }
}

function Test-WASafeModeNonAdmin {
    # v1: checkSafeModeAcc4NonAdmin
    [CmdletBinding()]
    param ([string]$Name)
    Write-WALog 'running Test-WASafeModeNonAdmin'
    $file = Get-WAFileName -Name $Name
    $v = Get-WARegValue -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'SafeModeBlockNonAdmins'
    Write-WAFile -File $file -Text '============= Safe Mode access by non-admins =============', "SafeModeBlockNonAdmins = $v"
    if ($v -eq 1) { Add-WAFinding -CheckID 'machine_SafeModeAcc4NonAdmin' -Status Pass -RelatedFile $file -Evidence 'SafeModeBlockNonAdmins=1' -Finding 'Non-admins are blocked from logging on in Safe Mode.' }
    else { Add-WAFinding -CheckID 'machine_SafeModeAcc4NonAdmin' -Status Fail -RelatedFile $file -Evidence "SafeModeBlockNonAdmins=$v" -Finding 'Non-admins can log on in Safe Mode, where EDR/AV services may not run.' }
}
#endregion

#region Checks - proxy, patching, services, Office, Kerberos, CredSSP, UAC, LAPS, sensitive data

function Test-WAProxyConfiguration {
    # v1: checkProxyConfiguration. Fixed: WPAD service StartType compared to 'Disable' (never matched -> always a finding);
    # DisableWpad (the supported WPAD switch) added.
    [CmdletBinding()]
    param ([string]$Name)
    Write-WALog 'running Test-WAProxyConfiguration'
    Write-WAScreen 'Getting proxy / WPAD configuration...'
    $ctx = $script:WACtx
    $file = Get-WAFileName -Name $Name
    Write-WAFile -File $file -Text '============= Proxy configuration ============='

    $perUser = Get-WARegValue -Path 'SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings' -Name 'ProxySettingsPerUser'
    if ($perUser -eq 0) { Add-WAFinding -CheckID 'machine_proxyConf' -Status Pass -RelatedFile $file -Evidence 'ProxySettingsPerUser=0' -Finding 'Proxy settings are per-machine (enforced for all users).' }
    else { Add-WAFinding -CheckID 'machine_proxyConf' -Status Fail -RelatedFile $file -Evidence "ProxySettingsPerUser=$perUser" -Finding 'Proxy settings are per-user - each user (or malware in user context) controls its own proxy.' }

    $user = Get-WARegKeyValues -Hive HKCU -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings'
    $ev = if ($user) { 'ProxyEnable={0}; ProxyServer={1}; AutoConfigURL={2}; ProxyOverride={3}' -f $user['ProxyEnable'], $user['ProxyServer'], $user['AutoConfigURL'], $user['ProxyOverride'] } else { 'not readable' }
    Write-WAFile -File $file -Text "Current user: $ev"
    Add-WAFinding -CheckID 'machine_proxySet' -Status Info -RelatedFile $file -Evidence $ev -Finding $(if ($user -and $user['ProxyEnable'] -eq 1) { 'A user-level proxy is configured.' } elseif ($user -and $user['AutoConfigURL']) { 'A PAC (AutoConfigURL) is configured for the user.' } else { 'No user-level proxy is configured.' })

    if (Test-WAOSVersion -Minimum '6.2') {
        $v = Get-WARegValue -Path 'SOFTWARE\Policies\Microsoft\Windows\NetworkIsolation' -Name 'DProxiesAuthoritive'
        if ($v -eq 1) { Add-WAFinding -CheckID 'machine_autoIsoProxyDiscovery' -Status Pass -RelatedFile $file -Evidence 'DProxiesAuthoritive=1' -Finding 'Network Isolation proxy definitions are authoritative (no auto-discovery).' }
        else { Add-WAFinding -CheckID 'machine_autoIsoProxyDiscovery' -Status Fail -RelatedFile $file -Evidence "DProxiesAuthoritive=$v" -Finding 'Network Isolation automatic proxy discovery is enabled.' }
    }

    $lock = Get-WARegValue -Hive HKLM -Path 'SOFTWARE\Policies\Microsoft\Internet Explorer\Control Panel' -Name 'Proxy'
    $lockU = Get-WARegValue -Hive HKCU -Path 'SOFTWARE\Policies\Microsoft\Internet Explorer\Control Panel' -Name 'Proxy'
    if ($lock -eq 1) { Add-WAFinding -CheckID 'machine_accConfProxy' -Status Pass -RelatedFile $file -Evidence 'HKLM Proxy=1' -Finding 'Users cannot change proxy settings (computer policy).' }
    elseif ($lockU -eq 1) { Add-WAFinding -CheckID 'machine_accConfProxy' -Status Warning -RelatedFile $file -Evidence 'HKCU Proxy=1' -Finding 'Proxy settings are locked for the current user only.' }
    else { Add-WAFinding -CheckID 'machine_accConfProxy' -Status Fail -RelatedFile $file -Evidence "HKLM Proxy=$lock; HKCU Proxy=$lockU" -Finding 'Standard users can change the system proxy settings.' }

    $cache = Get-WARegValue -Path 'SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings' -Name 'EnableAutoProxyResultCache'
    if ($cache -eq 0) { Add-WAFinding -CheckID 'machine_AutoProxyResultCache' -Status Pass -RelatedFile $file -Evidence 'EnableAutoProxyResultCache=0' -Finding 'Caching of auto-proxy script results is disabled.' }
    else { Add-WAFinding -CheckID 'machine_AutoProxyResultCache' -Status Fail -RelatedFile $file -Evidence "EnableAutoProxyResultCache=$cache" -Finding 'Auto-proxy script results are cached (a poisoned WPAD answer persists).' }

    $disableWpad = Get-WARegValue -Path 'SYSTEM\CurrentControlSet\Services\WinHttp' -Name 'DisableWpad'
    $svc = Get-WACimInstance -ClassName Win32_Service -Filter "Name='WinHttpAutoProxySvc'"
    $ev = 'DisableWpad={0}; WinHttpAutoProxySvc StartMode={1} State={2}' -f $disableWpad, $(if ($svc) { $svc.StartMode } else { 'n/a' }), $(if ($svc) { $svc.State } else { 'n/a' })
    Write-WAFile -File $file -Text "WPAD: $ev"
    if ($disableWpad -eq 1) { Add-WAFinding -CheckID 'machine_WPADSvc' -Status Pass -RelatedFile $file -Evidence $ev -Finding 'WPAD is disabled (DisableWpad=1).' }
    elseif ($svc -and [string]$svc.StartMode -eq 'Disabled') { Add-WAFinding -CheckID 'machine_WPADSvc' -Status Pass -RelatedFile $file -Evidence $ev -Finding 'The WinHTTP auto-proxy (WPAD) service is disabled.' -Comment 'Microsoft recommends DisableWpad=1 instead of disabling the service.' }
    else { Add-WAFinding -CheckID 'machine_WPADSvc' -Status Fail -RelatedFile $file -Evidence $ev -Finding 'WPAD auto-discovery is active - a rogue "wpad" host can proxy traffic and harvest credentials.' }
    Write-WAFile -File $file -Text '============= netsh winhttp show proxy =============', (Invoke-WANative -FilePath 'netsh.exe' -ArgumentList @('winhttp', 'show', 'proxy'))
    [void]$ctx
}

function Test-WAWindowsUpdate {
    # v1: checkWinUpdateConfig. Fixed: NoAutoUpdate logic inverted (0 reported as "disabled"); install-day rows had status
    # "false"; https:// parsing via Substring; IP detection accepted "10" as an IP and missed host:port. Added patch recency.
    [CmdletBinding()]
    param ([string]$Name)
    Write-WALog 'running Test-WAWindowsUpdate'
    Write-WAScreen 'Getting Windows Update configuration...'
    $ctx = $script:WACtx
    $file = Get-WAFileName -Name $Name
    $au = 'SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
    $wu = 'SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
    $cfg = Get-WARegKeyValues -Path $au
    $noAuto = $null; $opt = $null
    if ($cfg) { $noAuto = $cfg['NoAutoUpdate']; $opt = $cfg['AUOptions'] }
    $ccm = Get-WAService -Name 'CcmExec'
    Write-WAFile -File $file -Text '============= Windows Update policy =============', ($(if ($cfg) { ($cfg.Keys | ForEach-Object { '{0} = {1}' -f $_, $cfg[$_] }) } else { 'No Windows Update policy configured.' }))

    if ($noAuto -eq 1) {
        if ($ccm) { Add-WAFinding -CheckID 'machine_autoUpdate' -Status Info -RelatedFile $file -Evidence 'NoAutoUpdate=1; ConfigMgr client present' -Finding 'Automatic updates are disabled; updates appear to be managed by Configuration Manager - verify deployment deadlines.' }
        else { Add-WAFinding -CheckID 'machine_autoUpdate' -Status Fail -RelatedFile $file -Evidence 'NoAutoUpdate=1' -Finding 'Automatic updates are disabled by policy.' }
    }
    else { Add-WAFinding -CheckID 'machine_autoUpdate' -Status Pass -RelatedFile $file -Evidence "NoAutoUpdate=$noAuto" -Finding 'Automatic updates are not disabled.' }

    switch ($opt) {
        2 { Add-WAFinding -CheckID 'machine_autoUpdateSchedule' -Status Fail -RelatedFile $file -Evidence 'AUOptions=2' -Finding 'Updates only notify for download and install - users can defer indefinitely.' }
        3 { Add-WAFinding -CheckID 'machine_autoUpdateSchedule' -Status Warning -RelatedFile $file -Evidence 'AUOptions=3' -Finding 'Updates download automatically but install needs manual action (acceptable only with an enforced monthly patch process).' }
        4 {
            $day = if ($cfg) { $cfg['ScheduledInstallDay'] } else { $null }
            $hour = if ($cfg) { $cfg['ScheduledInstallTime'] } else { $null }
            $dayName = @{ 0 = 'every day'; 1 = 'Sunday'; 2 = 'Monday'; 3 = 'Tuesday'; 4 = 'Wednesday'; 5 = 'Thursday'; 6 = 'Friday'; 7 = 'Saturday' }[[int]$day]
            Add-WAFinding -CheckID 'machine_autoUpdateSchedule' -Status Pass -RelatedFile $file -Evidence ("AUOptions=4; ScheduledInstallDay={0}; ScheduledInstallTime={1}" -f $day, $hour) -Finding ("Updates download and install on a schedule ({0} at {1}:00)." -f $dayName, $hour)
        }
        5 { Add-WAFinding -CheckID 'machine_autoUpdateSchedule' -Status Fail -RelatedFile $file -Evidence 'AUOptions=5' -Finding 'Local administrators choose the update behaviour.' }
        7 { Add-WAFinding -CheckID 'machine_autoUpdateSchedule' -Status Warning -RelatedFile $file -Evidence 'AUOptions=7' -Finding 'Updates download automatically; install and restart need manual action.' }
        default {
            if ($null -eq $opt) {
                if ($ctx.IsServer) { Add-WAFinding -CheckID 'machine_autoUpdateSchedule' -Status Manual -RelatedFile $file -Evidence 'AUOptions not set' -Finding 'No update behaviour policy - verify the server patching process.' }
                else { Add-WAFinding -CheckID 'machine_autoUpdateSchedule' -Status Pass -RelatedFile $file -Evidence 'AUOptions not set' -Finding 'No update behaviour policy - Windows default (automatic) applies.' }
            }
            else { Add-WAFinding -CheckID 'machine_autoUpdateSchedule' -Status Manual -RelatedFile $file -Evidence "AUOptions=$opt" -Finding "Unrecognised AUOptions value ($opt)." }
        }
    }

    # WSUS
    $useWu = if ($cfg) { $cfg['UseWUServer'] } else { $null }
    $server = Get-WARegValue -Path $wu -Name 'WUServer'
    Write-WAFile -File $file -Text '============= WSUS =============', "UseWUServer=$useWu; WUServer=$server"
    if ($useWu -eq 1 -and $server) {
        $uri = $null
        if (-not [uri]::TryCreate([string]$server, [UriKind]::Absolute, [ref]$uri)) { [void][uri]::TryCreate('http://' + $server, [UriKind]::Absolute, [ref]$uri) }
        if ($uri -and $uri.Scheme -eq 'https') { Add-WAFinding -CheckID 'machine_wsusUpdate' -Status Pass -RelatedFile $file -Evidence "WUServer=$server" -Finding 'WSUS is reached over HTTPS.' }
        else { Add-WAFinding -CheckID 'machine_wsusUpdate' -Status Fail -RelatedFile $file -Evidence "WUServer=$server" -Finding 'WSUS is reached over HTTP - update metadata can be tampered with (WSUSpect / local privilege escalation).' }
        if ($uri -and ($uri.HostNameType -eq 'IPv4' -or $uri.HostNameType -eq 'IPv6')) { Add-WAFinding -CheckID 'machine_wsusUpdateAddress' -Status Fail -RelatedFile $file -Evidence "WUServer=$server" -Finding 'WSUS is referenced by IP address - authentication falls back to NTLM.' }
        else { Add-WAFinding -CheckID 'machine_wsusUpdateAddress' -Status Pass -RelatedFile $file -Evidence "WUServer=$server" -Finding 'WSUS is referenced by host name.' }
    }
    elseif ($useWu -eq 1) {
        Add-WAFinding -CheckID 'machine_wsusUpdate' -Status Fail -RelatedFile $file -Evidence 'UseWUServer=1; WUServer empty' -Finding 'WSUS is enabled but no server is configured - the host may not receive updates.'
        Add-WAFinding -CheckID 'machine_wsusUpdateAddress' -Status NotApplicable -RelatedFile $file -Finding 'No WSUS server configured.'
    }
    else {
        Add-WAFinding -CheckID 'machine_wsusUpdate' -Status NotApplicable -RelatedFile $file -Evidence "UseWUServer=$useWu" -Finding 'WSUS is not used (Windows Update / Intune / ConfigMgr).'
        Add-WAFinding -CheckID 'machine_wsusUpdateAddress' -Status NotApplicable -RelatedFile $file -Finding 'WSUS is not used.'
    }

    # Patch recency (hotfix list collected by Get-WAHotfixes)
    $hf = $ctx.Cache['HotFix']
    if ($null -eq $hf) { $hf = @(Invoke-WACmdlet -Name 'Get-HotFix') }
    $dates = @($hf | Where-Object { $_ -and $_.InstalledOn } | ForEach-Object { [datetime]$_.InstalledOn })
    if ($dates.Count -eq 0) {
        Add-WAFinding -CheckID 'machine_lastPatch' -Status Manual -RelatedFile (Get-WAFileName -Name 'Hotfixes') -Finding 'Installation dates of updates are not available - verify the patch level against the latest cumulative update.'
    }
    else {
        $last = ($dates | Sort-Object -Descending)[0]
        $days = [int]((Get-Date) - $last).TotalDays
        $ev = 'Most recent update installed {0:yyyy-MM-dd} ({1} days ago)' -f $last, $days
        if ($days -le 35) { Add-WAFinding -CheckID 'machine_lastPatch' -Status Pass -RelatedFile (Get-WAFileName -Name 'Hotfixes') -Evidence $ev -Finding "An update was installed within the last month ($days days)." }
        elseif ($days -le 60) { Add-WAFinding -CheckID 'machine_lastPatch' -Status Warning -RelatedFile (Get-WAFileName -Name 'Hotfixes') -Evidence $ev -Finding "No update for $days days - at least one Patch Tuesday was missed." }
        else { Add-WAFinding -CheckID 'machine_lastPatch' -Status Fail -RelatedFile (Get-WAFileName -Name 'Hotfixes') -Evidence $ev -Finding "No update for $days days - the host is missing multiple monthly security updates." }
    }
}

function Test-WABroadWriteAccess {
    # True when Everyone/Authenticated Users/Users/INTERACTIVE can create files in the folder.
    [CmdletBinding()]
    param ([Parameter(Mandatory = $true)][string]$Path)
    try {
        $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
        $broad = @('S-1-1-0', 'S-1-5-11', 'S-1-5-32-545', 'S-1-5-4')
        $write = [System.Security.AccessControl.FileSystemRights]'CreateFiles, WriteData, AppendData'
        foreach ($ace in $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
            if ($ace.AccessControlType -eq 'Allow' -and $broad -contains $ace.IdentityReference.Value -and ([int]($ace.FileSystemRights -band $write) -ne 0)) { return $true }
        }
        return $false
    }
    catch { return $false }
}

function Get-WAUnquotedCandidate {
    # Returns the exploitable hijack folders for an unquoted service path, or $null when the path is safe.
    [CmdletBinding()]
    param ([string]$PathName)
    if (-not $PathName) { return $null }
    $p = $PathName.Trim()
    if ($p.StartsWith('"') -or $p.StartsWith("'")) { return $null }
    $m = [regex]::Match($p, '^(.+?\.(exe|com|bat|cmd|sys))(\s|$)', 'IgnoreCase')
    $exe = if ($m.Success) { $m.Groups[1].Value } else { $p }
    if ($exe -notmatch '\s') { return $null }
    if ($exe -match '^(\\SystemRoot|%SystemRoot%|\\\?\?\\)') { return $null }
    $folders = @()
    $idx = $exe.IndexOf(' ')
    while ($idx -gt 0) {
        $prefix = $exe.Substring(0, $idx)
        $cut = $prefix.LastIndexOf('\')
        if ($cut -ge 0) { $folders += $(if ($cut -le 2) { $prefix.Substring(0, $cut + 1) } else { $prefix.Substring(0, $cut) }) }
        $idx = $exe.IndexOf(' ', $idx + 1)
    }
    return [pscustomobject]@{ Executable = $exe; HijackFolders = @($folders | Select-Object -Unique) }
}

function Test-WAUnquotedServicePath {
    # v1: checkUnquotedSePath. Fixed: flagged every unquoted path outside C:\Windows (even without spaces) and ignored
    # paths with spaces inside C:\Windows; now also checks whether a hijack folder is writable by non-admins.
    [CmdletBinding()]
    param ([string]$Name)
    Write-WALog 'running Test-WAUnquotedServicePath'
    Write-WAScreen 'Checking for unquoted service paths...'
    $ctx = $script:WACtx
    $file = Get-WAFileName -Name $Name
    $svc = $ctx.Cache['Services']
    if ($null -eq $svc) { $svc = @(Get-WACimInstance -ClassName Win32_Service) }
    $vuln = @()
    foreach ($s in @($svc)) {
        if (-not $s) { continue }
        $c = Get-WAUnquotedCandidate -PathName ([string]$s.PathName)
        if ($c) {
            $writable = @($c.HijackFolders | Where-Object { Test-WABroadWriteAccess -Path $_ })
            $vuln += [pscustomobject]@{ Service = $s.Name; StartName = $s.StartName; PathName = $s.PathName; WritableFolders = ($writable -join ', ') }
        }
    }
    Write-WAFile -File $file -Text '', '============= Unquoted service paths (T1574.009) ============='
    if ($vuln.Count -eq 0) {
        Write-WAFile -File $file -Text 'No unquoted service paths containing spaces were found.'
        Add-WAFinding -CheckID 'vul_quotedPath' -Status Pass -RelatedFile $file -Finding 'No services with unquoted paths containing spaces.'
        return
    }
    Write-WAFile -File $file -Text ($vuln | Format-Table -AutoSize -Wrap | Out-String -Width 250)
    $ev = ($vuln | ForEach-Object { '{0} [{1}]{2}' -f $_.Service, $_.PathName, $(if ($_.WritableFolders) { ' WRITABLE: ' + $_.WritableFolders } else { '' }) }) -join ' | '
    $exploitable = @($vuln | Where-Object { $_.WritableFolders })
    if ($exploitable.Count -gt 0) { Add-WAFinding -CheckID 'vul_quotedPath' -Status Fail -Severity Critical -RelatedFile $file -Evidence $ev -Finding ("{0} unquoted service path(s); {1} with a hijack folder writable by non-admins (direct privilege escalation)." -f $vuln.Count, $exploitable.Count) }
    else { Add-WAFinding -CheckID 'vul_quotedPath' -Status Fail -RelatedFile $file -Evidence $ev -Finding ("{0} unquoted service path(s) containing spaces (not currently writable by non-admins)." -f $vuln.Count) }
}

function Test-WASimultaneousConnections {
    # v1: checkSimulEhtrAndWifi. Servers N/A.
    [CmdletBinding()]
    param ([string]$Name)
    Write-WALog 'running Test-WASimultaneousConnections'
    $ctx = $script:WACtx
    $file = Get-WAFileName -Name $Name
    if ($ctx.IsServer) {
        Add-WAFinding -CheckID 'machine_ethSim' -Status NotApplicable -RelatedFile $file -Finding 'Server - setting targets mobile workstations.'
        Add-WAFinding -CheckID 'machine_PCTNDNetwork' -Status NotApplicable -RelatedFile $file -Finding 'Server - setting targets mobile workstations.'
        return
    }
    $path = 'SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy'
    $min = Get-WARegValue -Path $path -Name 'fMinimizeConnections'
    $block = Get-WARegValue -Path $path -Name 'fBlockNonDomain'
    Write-WAFile -File $file -Text '============= Simultaneous connections =============', "fMinimizeConnections=$min; fBlockNonDomain=$block"
    switch ($min) {
        0 { Add-WAFinding -CheckID 'machine_ethSim' -Status Fail -RelatedFile $file -Evidence 'fMinimizeConnections=0' -Finding 'Simultaneous connections are allowed (host can bridge corporate and other networks).' }
        { $_ -in 1, 2, 3 } { Add-WAFinding -CheckID 'machine_ethSim' -Status Pass -RelatedFile $file -Evidence "fMinimizeConnections=$min" -Finding 'Simultaneous connections are minimised by policy.' }
        default { Add-WAFinding -CheckID 'machine_ethSim' -Status Manual -RelatedFile $file -Evidence "fMinimizeConnections=$min" -Finding 'Not configured by policy (Windows default minimises connections) - confirm for mobile devices.' }
    }
    if ($block -eq 1) { Add-WAFinding -CheckID 'machine_PCTNDNetwork' -Status Pass -RelatedFile $file -Evidence 'fBlockNonDomain=1' -Finding 'Connections to non-domain networks are blocked while on the domain network.' }
    elseif ($block -eq 0) { Add-WAFinding -CheckID 'machine_PCTNDNetwork' -Status Fail -RelatedFile $file -Evidence 'fBlockNonDomain=0' -Finding 'Connections to non-domain networks are allowed while on the domain network.' }
    else { Add-WAFinding -CheckID 'machine_PCTNDNetwork' -Status Manual -RelatedFile $file -Evidence 'fBlockNonDomain not set' -Finding 'Not configured - review for mobile workstations.' }
}

function Get-WAOfficeVersions {
    # Office detection without Win32_Product (v1 used Win32_Product, which triggers MSI self-repair on every product
    # and does not list Click-to-Run / Microsoft 365 Apps at all).
    [CmdletBinding()]
    param ()
    $found = @{}
    $c2r = Get-WARegValue -Path 'SOFTWARE\Microsoft\Office\ClickToRun\Configuration' -Name 'VersionToReport'
    if ($c2r) { $found['16.0'] = [pscustomobject]@{ Version = '16.0'; Build = [string]$c2r; ClickToRun = $true } }
    foreach ($v in '12.0', '14.0', '15.0', '16.0') {
        if ($found.ContainsKey($v)) { continue }
        foreach ($root in 'SOFTWARE\Microsoft\Office', 'SOFTWARE\WOW6432Node\Microsoft\Office') {
            $p = Get-WARegValue -Path ("{0}\{1}\Common\InstallRoot" -f $root, $v) -Name 'Path'
            if ($p) { $found[$v] = [pscustomobject]@{ Version = $v; Build = $v; ClickToRun = $false }; break }
        }
    }
    return @($found.Values | Sort-Object Version)
}

function Get-WAOfficePolicyValue {
    # Office user policy (Software\Policies) wins over the user preference (Software\Microsoft).
    [CmdletBinding()]
    param ([string]$Version, [string]$SubPath, [string]$Name)
    $v = Get-WARegValue -Hive HKCU -Path ("SOFTWARE\Policies\Microsoft\Office\{0}\{1}" -f $Version, $SubPath) -Name $Name
    if ($null -ne $v) { return [pscustomobject]@{ Value = $v; Source = 'policy' } }
    $v = Get-WARegValue -Hive HKCU -Path ("SOFTWARE\Microsoft\Office\{0}\{1}" -f $Version, $SubPath) -Name $Name
    if ($null -ne $v) { return [pscustomobject]@{ Value = $v; Source = 'user' } }
    return [pscustomobject]@{ Value = $null; Source = 'default' }
}

function Test-WAOfficeHardening {
    # v1: checkMacroAndDDE. Fixed: DDE results were inverted (hardened value reported as a finding); Office Click-to-Run
    # was never detected; string version comparison. Added macro policy checks (were TODO in v1).
    [CmdletBinding()]
    param ([string]$Name)
    Write-WALog 'running Test-WAOfficeHardening'
    Write-WAScreen 'Checking Office macro and DDE configuration...'
    $file = Get-WAFileName -Name $Name
    $ids = 'machine_excelDDE', 'machine_wordDDE', 'machine_outlookDDE', 'machine_officeVBAWarnings', 'machine_officeInternetMacros'
    $versions = @(Get-WAOfficeVersions)
    Write-WAFile -File $file -Text '============= Office macro / DDE configuration (HKCU of the account running the script) =============', ('Detected: ' + (($versions | ForEach-Object { '{0} (build {1}, C2R={2})' -f $_.Version, $_.Build, $_.ClickToRun }) -join '; '))
    if ($versions.Count -eq 0) {
        foreach ($i in $ids) { Add-WAFinding -CheckID $i -Status NotApplicable -RelatedFile $file -Finding 'Microsoft Office was not detected.' }
        return
    }
    $note = 'Office settings are per-user: evaluated for the account running this script.'
    foreach ($o in $versions) {
        $v = $o.Version; $scope = "Office $v"
        # Excel - WorkbookLinkWarnings: 1 prompt (default), 2 disable automatic update, 3 allow
        $x = Get-WAOfficePolicyValue -Version $v -SubPath 'Excel\Security' -Name 'WorkbookLinkWarnings'
        $ev = 'WorkbookLinkWarnings={0} ({1})' -f $x.Value, $x.Source
        if ($x.Value -eq 2) { Add-WAFinding -CheckID 'machine_excelDDE' -Scope $scope -Status Pass -RelatedFile $file -Evidence $ev -Finding 'Excel does not update workbook links automatically.' -Comment $note }
        elseif ($x.Value -eq 3) { Add-WAFinding -CheckID 'machine_excelDDE' -Scope $scope -Status Fail -RelatedFile $file -Evidence $ev -Finding 'Excel updates workbook/DDE links without prompting.' -Comment $note }
        else { Add-WAFinding -CheckID 'machine_excelDDE' -Scope $scope -Status Warning -RelatedFile $file -Evidence $ev -Finding 'Excel prompts before updating links (default) - users can still accept.' -Comment $note }

        # Word - AllowDDE: 0 disabled (default since ADV170021), 1 existing apps, 2 all
        $w = Get-WAOfficePolicyValue -Version $v -SubPath 'Word\Security' -Name 'AllowDDE'
        $wl = Get-WAOfficePolicyValue -Version $v -SubPath 'Word\Options' -Name 'DontUpdateLinks'
        $ev = 'AllowDDE={0} ({1}); DontUpdateLinks={2} ({3})' -f $w.Value, $w.Source, $wl.Value, $wl.Source
        if ($w.Value -eq 1 -or $w.Value -eq 2) { Add-WAFinding -CheckID 'machine_wordDDE' -Scope $scope -Status Fail -RelatedFile $file -Evidence $ev -Finding 'Word allows DDE requests.' -Comment $note }
        elseif ($wl.Value -eq 1 -or $w.Value -eq 0) { Add-WAFinding -CheckID 'machine_wordDDE' -Scope $scope -Status Pass -RelatedFile $file -Evidence $ev -Finding 'Word DDE is disabled and/or automatic link update is off.' -Comment $note }
        else { Add-WAFinding -CheckID 'machine_wordDDE' -Scope $scope -Status Pass -RelatedFile $file -Evidence $ev -Finding 'Word DDE is disabled by default (ADV170021); set DontUpdateLinks=1 for defence in depth.' -Comment $note }

        # Outlook (Word as email editor)
        $ol = Get-WAOfficePolicyValue -Version $v -SubPath 'Word\Options\WordMail' -Name 'DontUpdateLinks'
        $ev = 'WordMail DontUpdateLinks={0} ({1})' -f $ol.Value, $ol.Source
        if ($ol.Value -eq 1) { Add-WAFinding -CheckID 'machine_outlookDDE' -Scope $scope -Status Pass -RelatedFile $file -Evidence $ev -Finding 'Outlook does not update links automatically.' -Comment $note }
        else { Add-WAFinding -CheckID 'machine_outlookDDE' -Scope $scope -Status Warning -RelatedFile $file -Evidence $ev -Finding 'Outlook automatic link update is not disabled.' -Comment $note }

        # VBA macro notification: 1 enable all, 2 disable with notification (default), 3 disable except signed, 4 disable all
        $apps = 'Word', 'Excel', 'PowerPoint'
        $vals = @{}
        foreach ($a in $apps) { $vals[$a] = (Get-WAOfficePolicyValue -Version $v -SubPath "$a\Security" -Name 'VBAWarnings').Value }
        $ev = ($apps | ForEach-Object { '{0}={1}' -f $_, $(if ($null -eq $vals[$_]) { 'default(2)' } else { $vals[$_] }) }) -join '; '
        $eff = @($apps | ForEach-Object { if ($null -eq $vals[$_]) { 2 } else { [int]$vals[$_] } })
        if ($eff -contains 1) { Add-WAFinding -CheckID 'machine_officeVBAWarnings' -Scope $scope -Status Fail -Severity Critical -RelatedFile $file -Evidence $ev -Finding 'All macros are enabled without notification in at least one Office application.' -Comment $note }
        elseif (@($eff | Where-Object { $_ -lt 3 }).Count -gt 0) { Add-WAFinding -CheckID 'machine_officeVBAWarnings' -Scope $scope -Status Warning -RelatedFile $file -Evidence $ev -Finding 'Macros are disabled with notification - users can still enable them.' -Comment $note }
        else { Add-WAFinding -CheckID 'machine_officeVBAWarnings' -Scope $scope -Status Pass -RelatedFile $file -Evidence $ev -Finding 'Only signed macros (or none) can run.' -Comment $note }

        # Internet macros (Mark of the Web)
        $blk = @{}
        foreach ($a in $apps) { $blk[$a] = (Get-WAOfficePolicyValue -Version $v -SubPath "$a\Security" -Name 'blockcontentexecutionfrominternet').Value }
        $ev = ($apps | ForEach-Object { '{0}={1}' -f $_, $blk[$_] }) -join '; '
        $defaultBlock = $false
        if ($o.ClickToRun) { try { $defaultBlock = ([version]$o.Build).Build -ge 15000 } catch { $defaultBlock = $false } }
        $notBlocked = @($apps | Where-Object { $blk[$_] -ne 1 })
        if ($notBlocked.Count -eq 0) { Add-WAFinding -CheckID 'machine_officeInternetMacros' -Scope $scope -Status Pass -RelatedFile $file -Evidence $ev -Finding 'Macros in files from the internet are blocked by policy.' -Comment $note }
        elseif ($defaultBlock -and @($notBlocked | Where-Object { $blk[$_] -eq 0 }).Count -eq 0) { Add-WAFinding -CheckID 'machine_officeInternetMacros' -Scope $scope -Status Pass -RelatedFile $file -Evidence ($ev + "; build $($o.Build) blocks by default") -Finding 'Microsoft 365 Apps blocks internet macros by default (not enforced by policy).' -Comment $note }
        else { Add-WAFinding -CheckID 'machine_officeInternetMacros' -Scope $scope -Status Fail -RelatedFile $file -Evidence $ev -Finding ('Macros in files from the internet are not blocked for: ' + ($notBlocked -join ', ')) -Comment $note }
    }
}

function Test-WAKerberosEncryption {
    # v1: checkKerberos. Replaced the value lookup table with bitmask evaluation (v1 missed most combinations and its
    # default branch threw a binding error and reported an undefined variable).
    [CmdletBinding()]
    param ([string]$Name)
    Write-WALog 'running Test-WAKerberosEncryption'
    $ctx = $script:WACtx
    $file = Get-WAFileName -Name $Name
    if (-not $ctx.PartOfDomain) { Add-WAFinding -CheckID 'domain_kerbSupEnc' -Status NotApplicable -RelatedFile $file -Finding 'Not domain joined.'; return }
    Write-WAScreen 'Getting Kerberos encryption settings...'
    $v = Get-WARegValue -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters' -Name 'SupportedEncryptionTypes'
    if ($null -eq $v -or [int64]$v -eq 0) {
        Write-WAFile -File $file -Text '============= Kerberos SupportedEncryptionTypes =============', "Not configured by policy (value: $v)."
        Add-WAFinding -CheckID 'domain_kerbSupEnc' -Status Warning -RelatedFile $file -Evidence 'SupportedEncryptionTypes not set' -Finding 'Kerberos encryption types are not restricted by policy - RC4 may still be negotiated depending on OS build and account settings.'
        return
    }
    $n = [int64]$v -band 0xFFFFFFFF
    $names = @()
    if ($n -band 0x1) { $names += 'DES-CBC-CRC' }
    if ($n -band 0x2) { $names += 'DES-CBC-MD5' }
    if ($n -band 0x4) { $names += 'RC4-HMAC' }
    if ($n -band 0x8) { $names += 'AES128' }
    if ($n -band 0x10) { $names += 'AES256' }
    if ($n -band 0x20) { $names += 'AES256-SK' }
    if ($n -band 0x7FFFFFC0) { $names += 'Future' }
    $ev = 'SupportedEncryptionTypes=0x{0:X} ({1})' -f $n, ($names -join ', ')
    Write-WAFile -File $file -Text '============= Kerberos SupportedEncryptionTypes =============', $ev
    if ($n -band 0x7) { Add-WAFinding -CheckID 'domain_kerbSupEnc' -Status Fail -RelatedFile $file -Evidence $ev -Finding ('Weak Kerberos encryption types are allowed: ' + (($names | Where-Object { $_ -match 'DES|RC4' }) -join ', ')) }
    elseif (-not ($n -band 0x18)) { Add-WAFinding -CheckID 'domain_kerbSupEnc' -Status Fail -RelatedFile $file -Evidence $ev -Finding 'No AES encryption type is allowed - Kerberos authentication will fail.' }
    else { Add-WAFinding -CheckID 'domain_kerbSupEnc' -Status Pass -RelatedFile $file -Evidence $ev -Finding 'Only AES Kerberos encryption types are allowed.' }
}

function Test-WACredSSP {
    # v1: checkCredSSP. Fixed: server lists read value NAMES (1,2,...) instead of data and from the wrong subkey,
    # AllowSavedCredentialsWhenNTLMOnly tested the wrong value, duplicate CheckIDs, '-sty' typo crashed the function,
    # RestrictedRemoteAdministration=1 (hardened) reported as a finding.
    [CmdletBinding()]
    param ([string]$Name)
    Write-WALog 'running Test-WACredSSP'
    Write-WAScreen 'Checking CredSSP / credential delegation...'
    $file = Get-WAFileName -Name $Name
    $base = 'SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation'
    $cfg = Get-WARegKeyValues -Path $base
    Write-WAFile -File $file -Text '============= Credential delegation (CredSSP) policy =============', ($(if ($cfg) { $cfg.Keys | ForEach-Object { '{0} = {1}' -f $_, $cfg[$_] } } else { 'No credential delegation policy configured.' }))
    $get = { param($n) if ($cfg) { $cfg[$n] } else { $null } }

    $allowItems = @(
        @{ Id = 'domain_CredSSPDefaultCred'; Value = 'AllowDefaultCredentials'; DefaultOpen = $false; Label = 'default credentials' },
        @{ Id = 'domain_CredSSPDefaultCredNTLM'; Value = 'AllowDefCredentialsWhenNTLMOnly'; DefaultOpen = $false; Label = 'default credentials to NTLM-only servers' },
        @{ Id = 'domain_CredSSPSavedCred'; Value = 'AllowSavedCredentials'; DefaultOpen = $true; Label = 'saved credentials' },
        @{ Id = 'domain_CredSSPSavedCredNTLM'; Value = 'AllowSavedCredentialsWhenNTLMOnly'; DefaultOpen = $true; Label = 'saved credentials to NTLM-only servers' }
    )
    foreach ($i in $allowItems) {
        $on = & $get $i.Value
        $list = @(Get-WARegValueList -Path ("{0}\{1}" -f $base, $i.Value))
        $ev = '{0}={1}; targets=[{2}]' -f $i.Value, $on, ($list -join ', ')
        if ($null -eq $on) {
            if ($i.DefaultOpen) { Add-WAFinding -CheckID $i.Id -Status Warning -RelatedFile $file -Evidence "$($i.Value) not configured" -Finding ("Not configured - Windows allows delegation of {0} (default target TERMSRV/*)." -f $i.Label) }
            else { Add-WAFinding -CheckID $i.Id -Status Pass -RelatedFile $file -Evidence "$($i.Value) not configured" -Finding ("Delegation of {0} is not allowed (default)." -f $i.Label) }
        }
        elseif ($on -ne 1) { Add-WAFinding -CheckID $i.Id -Status Pass -RelatedFile $file -Evidence $ev -Finding ("Delegation of {0} is disabled." -f $i.Label) }
        elseif ((Test-WAWildcardTarget -Entries $list) -or $i.Value -like '*NTLMOnly') { Add-WAFinding -CheckID $i.Id -Status Fail -RelatedFile $file -Evidence $ev -Finding ("Delegation of {0} is allowed to: {1}" -f $i.Label, ($list -join ', ')) }
        else { Add-WAFinding -CheckID $i.Id -Status Warning -RelatedFile $file -Evidence $ev -Finding ("Delegation of {0} is allowed to specific targets: {1} - confirm each is required." -f $i.Label, ($list -join ', ')) }
    }

    foreach ($d in @(@{ Id = 'domain_CredSSPDefaultCredDeny'; Value = 'DenyDefaultCredentials'; Label = 'default' }, @{ Id = 'domain_CredSSPSavedCredDeny'; Value = 'DenySavedCredentials'; Label = 'saved' })) {
        $on = & $get $d.Value
        $list = @(Get-WARegValueList -Path ("{0}\{1}" -f $base, $d.Value))
        $ev = '{0}={1}; targets=[{2}]' -f $d.Value, $on, ($list -join ', ')
        if ($on -eq 1 -and ($list -contains '*')) { Add-WAFinding -CheckID $d.Id -Status Pass -RelatedFile $file -Evidence $ev -Finding ("Delegation of {0} credentials is denied to all targets (except explicit allow-list)." -f $d.Label) }
        elseif ($on -eq 1) { Add-WAFinding -CheckID $d.Id -Status Warning -RelatedFile $file -Evidence $ev -Finding ("Delegation of {0} credentials is denied only to: {1}" -f $d.Label, ($list -join ', ')) }
        else { Add-WAFinding -CheckID $d.Id -Status Warning -RelatedFile $file -Evidence $ev -Finding ("No explicit deny list for delegation of {0} credentials." -f $d.Label) }
    }

    $pc = & $get 'AllowProtectedCreds'
    if ($pc -eq 1) { Add-WAFinding -CheckID 'domain_CredSSPNonExportableCred' -Status Pass -RelatedFile $file -Evidence 'AllowProtectedCreds=1' -Finding 'This host accepts non-exportable credentials (Restricted Admin / Remote Credential Guard).' }
    else { Add-WAFinding -CheckID 'domain_CredSSPNonExportableCred' -Status Fail -RelatedFile $file -Evidence "AllowProtectedCreds=$pc" -Finding 'This host does not accept non-exportable credentials - RDP users always expose reusable credentials to it.' }

    $rra = & $get 'RestrictedRemoteAdministration'
    $rrt = & $get 'RestrictedRemoteAdministrationType'
    $mode = @{ 1 = 'Require Restricted Admin'; 2 = 'Require Remote Credential Guard'; 3 = 'Restrict credential delegation' }[[int]$rrt]
    $ev = "RestrictedRemoteAdministration=$rra; Type=$rrt ($mode)"
    if ($rra -eq 1) { Add-WAFinding -CheckID 'domain_CredSSPResDelOfCredToRemoteSrv' -Status Pass -RelatedFile $file -Evidence $ev -Finding "Credential delegation to remote servers is restricted ($mode)." -Comment $(if ($rrt -eq 1) { 'Restricted Admin allows pass-the-hash to RDP targets - prefer Remote Credential Guard.' } else { '' }) }
    else { Add-WAFinding -CheckID 'domain_CredSSPResDelOfCredToRemoteSrv' -Status Fail -RelatedFile $file -Evidence $ev -Finding 'Outgoing RDP sessions delegate reusable credentials to the remote host.' }
}

function Test-WAUac {
    # New: UAC posture (was a manual control in v1).
    [CmdletBinding()]
    param ([string]$Name)
    Write-WALog 'running Test-WAUac'
    $file = Get-WAFileName -Name $Name
    $p = Get-WARegKeyValues -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    $g = { param($n) if ($p) { $p[$n] } else { $null } }
    $lua = & $g 'EnableLUA'; $cpba = & $g 'ConsentPromptBehaviorAdmin'; $sd = & $g 'PromptOnSecureDesktop'; $latfp = & $g 'LocalAccountTokenFilterPolicy'; $fat = & $g 'FilterAdministratorToken'
    $ev = "EnableLUA=$lua; ConsentPromptBehaviorAdmin=$cpba; PromptOnSecureDesktop=$sd; LocalAccountTokenFilterPolicy=$latfp; FilterAdministratorToken=$fat"
    Write-WAFile -File $file -Text '============= User Account Control =============', $ev
    if ($lua -eq 0) { Add-WAFinding -CheckID 'machine_UAC-EnableLUA' -Status Fail -RelatedFile $file -Evidence $ev -Finding 'UAC is disabled - every administrator process runs with a full token.' }
    else { Add-WAFinding -CheckID 'machine_UAC-EnableLUA' -Status Pass -RelatedFile $file -Evidence $ev -Finding 'UAC Admin Approval Mode is enabled.' }

    $effCpba = if ($null -eq $cpba) { 5 } else { [int]$cpba }
    if ($effCpba -eq 0) { Add-WAFinding -CheckID 'machine_UAC-AdminPrompt' -Status Fail -RelatedFile $file -Evidence $ev -Finding 'Administrators are elevated without any prompt (silent UAC bypass).' }
    elseif ($effCpba -in 1, 2 -and $sd -ne 0) { Add-WAFinding -CheckID 'machine_UAC-AdminPrompt' -Status Pass -RelatedFile $file -Evidence $ev -Finding 'Administrators must consent/authenticate on the secure desktop.' }
    else { Add-WAFinding -CheckID 'machine_UAC-AdminPrompt' -Status Warning -RelatedFile $file -Evidence $ev -Finding 'UAC uses the default auto-elevation for Windows binaries (value 5) or no secure desktop - many public UAC bypasses apply.' }

    if ($latfp -eq 1) { Add-WAFinding -CheckID 'machine_UAC-RemoteRestrictions' -Status Fail -RelatedFile $file -Evidence $ev -Finding 'LocalAccountTokenFilterPolicy=1 - any local administrator hash grants full remote admin (pass-the-hash).' }
    else { Add-WAFinding -CheckID 'machine_UAC-RemoteRestrictions' -Status Pass -RelatedFile $file -Evidence $ev -Finding 'UAC remote restrictions apply to local accounts.' }
}

function Test-WALaps {
    # New: Windows LAPS / legacy LAPS (was not assessed in v1).
    [CmdletBinding()]
    param ([string]$Name)
    Write-WALog 'running Test-WALaps'
    $ctx = $script:WACtx
    $file = Get-WAFileName -Name $Name
    $sources = @(
        @{ Path = 'SOFTWARE\Microsoft\Policies\LAPS'; Label = 'Windows LAPS (CSP/Intune)' },
        @{ Path = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS'; Label = 'Windows LAPS (GPO)' },
        @{ Path = 'SOFTWARE\Microsoft\Windows\CurrentVersion\LAPS\Config'; Label = 'Windows LAPS (local)' }
    )
    $win = $null
    foreach ($s in $sources) {
        $bd = Get-WARegValue -Path $s.Path -Name 'BackupDirectory'
        if ($null -ne $bd) { $win = [pscustomobject]@{ Source = $s.Label; BackupDirectory = [int]$bd; Values = Get-WARegKeyValues -Path $s.Path }; break }
    }
    $legacy = Get-WARegValue -Path 'SOFTWARE\Policies\Microsoft Services\AdmPwd' -Name 'AdmPwdEnabled'
    $legacyCse = [bool]($env:ProgramFiles -and (Test-Path -LiteralPath (Join-Path $env:ProgramFiles 'LAPS\CSE\AdmPwd.dll')))
    $ev = 'WindowsLAPS={0}; Legacy AdmPwdEnabled={1}; Legacy CSE installed={2}' -f $(if ($win) { '{0} BackupDirectory={1}' -f $win.Source, $win.BackupDirectory } else { 'not configured' }), $legacy, $legacyCse
    Write-WAFile -File $file -Text '============= LAPS =============', $ev
    if ($win -and $win.BackupDirectory -in 1, 2) {
        $target = if ($win.BackupDirectory -eq 1) { 'Microsoft Entra ID' } else { 'Active Directory' }
        $enc = $win.Values['ADPasswordEncryptionEnabled']
        Add-WAFinding -CheckID 'machine_LAPS' -Status Pass -RelatedFile $file -Evidence $ev -Finding "Windows LAPS backs up the local admin password to $target." -Comment $(if ($win.BackupDirectory -eq 2 -and $enc -eq 0) { 'AD password encryption is disabled - enable ADPasswordEncryptionEnabled.' } else { '' })
    }
    elseif ($legacy -eq 1) {
        Add-WAFinding -CheckID 'machine_LAPS' -Status Warning -RelatedFile $file -Evidence $ev -Finding 'Legacy Microsoft LAPS is used (clear-text ms-Mcs-AdmPwd attribute) - migrate to Windows LAPS with encryption.'
    }
    elseif ($win -and $win.BackupDirectory -eq 0) {
        Add-WAFinding -CheckID 'machine_LAPS' -Status Fail -RelatedFile $file -Evidence $ev -Finding 'Windows LAPS policy exists but BackupDirectory=0 (disabled).'
    }
    else {
        $st = if ($ctx.IsDC) { 'Warning' } else { 'Fail' }
        Add-WAFinding -CheckID 'machine_LAPS' -Status $st -RelatedFile $file -Evidence $ev -Finding $(if ($ctx.IsDC) { 'No LAPS policy - consider Windows LAPS DSRM password management on DCs.' } else { 'No LAPS policy - the local administrator password is likely static/shared (lateral movement via pass-the-hash).' })
    }
}

function Get-WAMaskedSecret {
    # Masks the value part of "key = value" / "key: value" matches.
    [CmdletBinding()]
    param ([string]$Line)
    return [regex]::Replace($Line, '(?i)((?:password|passwd|pwd|secret|token|apikey|api_key|connectionstring)[^=:"]{0,20}["'']?\s*[=:]\s*["'']?)([^"''\s;<]{1,})', {
            param($m)
            $v = $m.Groups[2].Value
            $keep = if ($v.Length -gt 4) { $v.Substring(0, 2) } else { '' }
            return $m.Groups[1].Value + $keep + '********'
        })
}

function Test-WASensitiveInfo {
    # v1: checkSensitiveInfo. Changes: secrets masked by default, private keys/PFX never copied, output folder excluded,
    # result reported as a check (control_ClearPass automated).
    [CmdletBinding()]
    param ([string]$Name)
    $ctx = $script:WACtx
    if (-not $ctx.EnableSensitiveInfoSearch) { return }
    Write-WALog 'running Test-WASensitiveInfo'
    Write-WAScreen 'Searching for sensitive information (this can take a while)...'
    $file = Get-WAFileName -Name $Name
    $paths = @($ctx.SensitiveSearchPath | Where-Object { $_ -and (Test-Path -LiteralPath $_) })
    $contentTypes = @('*.txt', '*.ini', '*.config', '*.xml', '*.ps1', '*.bat', '*.cmd', '*.vbs', '*.json', '*.yml', '*.yaml', '*vnc*')
    $keyTypes = @('*.pfx', '*.p12', '*.pem', '*.key', '*.kdbx', 'id_rsa*', 'unattend.xml', 'sysprep.inf')
    $pattern = '(?i)(password|passwd|pwd|secret|apikey|api_key|connectionstring)\s*["'']?\s*[=:]|-----BEGIN [A-Z ]*PRIVATE KEY-----'
    $hits = [System.Collections.Generic.List[string]]@()
    $keys = [System.Collections.Generic.List[string]]@()
    foreach ($p in $paths) {
        $files = @(Get-ChildItem -LiteralPath $p -Recurse -File -Include $contentTypes -ErrorAction SilentlyContinue | Where-Object { $_.FullName -notlike "$($ctx.RootPath)*" -and $_.Length -lt 5MB })
        foreach ($m in @($files | Select-String -Pattern $pattern -ErrorAction SilentlyContinue)) {
            $line = $m.Line.Trim()
            if ($line.Length -gt 300) { $line = $line.Substring(0, 300) + '...' }
            if (-not $ctx.IncludeSecretValues) { $line = Get-WAMaskedSecret -Line $line }
            $hits.Add(('{0}:{1}: {2}' -f $m.Path, $m.LineNumber, $line))
        }
        foreach ($k in @(Get-ChildItem -LiteralPath $p -Recurse -File -Include $keyTypes -ErrorAction SilentlyContinue | Where-Object { $_.FullName -notlike "$($ctx.RootPath)*" })) {
            $keys.Add(('{0} ({1:N0} bytes, modified {2:yyyy-MM-dd})' -f $k.FullName, $k.Length, $k.LastWriteTime))
        }
    }
    Write-WAFile -File $file -Text ('============= Clear-text credential search in: ' + ($paths -join ', ') + ' ============='), $(if ($ctx.IncludeSecretValues) { 'WARNING: secret values are NOT masked in this file.' } else { 'Secret values are masked.' }), '', '--- Content matches ---', $hits.ToArray(), '', '--- Key / credential files (content not copied) ---', $keys.ToArray()
    $total = $hits.Count + $keys.Count
    if ($total -gt 0) { Add-WAFinding -CheckID 'machine_SensitiveFiles' -Status Fail -RelatedFile $file -Evidence ("{0} content match(es), {1} key/credential file(s)" -f $hits.Count, $keys.Count) -Finding 'Potential clear-text credentials or private keys were found in files - review the evidence file.' }
    else { Add-WAFinding -CheckID 'machine_SensitiveFiles' -Status Pass -RelatedFile $file -Evidence ('Searched: ' + ($paths -join ', ')) -Finding 'No clear-text credentials or key files were found in the searched locations.' }
}

function Add-WAManualControls {
    # v1: addControlsToCSV - controls that need analyst review of the collected evidence.
    [CmdletBinding()]
    param ()
    $related = @{
        control_AuditPol = 'Audit-Policy'; control_LocalUsers = 'Local-Users, Security-Policy.inf'; control_LocalAdminRes = 'Security-Policy.inf'
        control_DomainAdminsAcc = 'Security-Policy.inf'; control_SvcAcc = 'Security-Policy.inf, Services'; control_LocalAndDomainPassPol = 'AccountPolicy'
        control_SharePerm = 'Shares'; control_ClearPass = 'Sensitive-Info'; control_NumOfUsersAndGroups = 'Local-Users'; control_UserRights = 'Security-Policy.inf'
        control_SvcPer = 'Services'; control_MalProcSrvSoft = 'Services, Process-list, Software, Netstat'; control_EventLog = 'Audit-Policy'; control_HostFW = 'Windows-Firewall, Windows-Firewall-Rules'
    }
    foreach ($id in $script:WACheckCatalog.Keys) {
        $meta = $script:WACheckCatalog[$id]
        if (-not $meta.Manual) { continue }
        if ($id -eq 'control_ClearPass' -and $script:WACtx.EnableSensitiveInfoSearch) { continue }
        Add-WAFinding -CheckID $id -Status Manual -RelatedFile $related[$id] -Finding ('Manual review: ' + $meta.Remediation)
    }
}
#endregion

#region Results, scoring, narrative and report generation

function Get-WAScore {
    # Weighted score: Pass = full weight, Warning = half, Fail = 0. Info/Manual/N/A/Error are excluded.
    [CmdletBinding()]
    param ([object[]]$Findings)
    $earned = 0.0; $possible = 0.0
    foreach ($f in @($Findings)) {
        if (-not $f) { continue }
        $w = $script:WASeverityWeight[[string]$f.Severity]
        switch ($f.Status) {
            'Pass' { $earned += $w; $possible += $w }
            'Warning' { $earned += ($w / 2); $possible += $w }
            'Fail' { $possible += $w }
        }
    }
    $score = if ($possible -gt 0) { [int][math]::Round(100 * $earned / $possible) } else { 0 }
    $grade = if ($score -ge 90) { 'A' } elseif ($score -ge 80) { 'B' } elseif ($score -ge 70) { 'C' } elseif ($score -ge 60) { 'D' } else { 'F' }
    $count = @{}
    foreach ($s in 'Pass', 'Fail', 'Warning', 'Manual', 'Info', 'NotApplicable', 'Error') { $count[$s] = @($Findings | Where-Object { $_ -and $_.Status -eq $s }).Count }
    $failSev = @{}
    foreach ($s in 'Critical', 'High', 'Medium', 'Low', 'Informational') { $failSev[$s] = @($Findings | Where-Object { $_ -and $_.Status -eq 'Fail' -and $_.Severity -eq $s }).Count }
    return [pscustomobject]@{ Score = $score; Grade = $grade; Earned = $earned; Possible = $possible; Counts = $count; FailBySeverity = $failSev }
}

function Get-WAPriority {
    [CmdletBinding()]
    param ($Finding)
    $w = $script:WASeverityWeight[[string]$Finding.Severity]
    $factor = switch ($Finding.Status) { 'Fail' { 1.0 } 'Warning' { 0.5 } default { 0 } }
    return [math]::Round($w * $factor * (1 + 0.15 * @($Finding.Techniques).Count), 2)
}

function Get-WAAttackPaths {
    # Rule-based attack-path narratives: combinations of weaknesses that chain into a realistic attack.
    [CmdletBinding()]
    param ([object[]]$Findings)
    $bad = @{}
    foreach ($f in @($Findings)) { if ($f -and ($f.Status -eq 'Fail' -or $f.Status -eq 'Warning')) { $bad[$f.CheckID] = $f } }
    $has = { param([string[]]$ids) @($ids | Where-Object { $bad.ContainsKey($_) }) }
    $paths = @()

    $cred = @(& $has @('domain_WDigest', 'machine_LSA-ppl', 'machine_LSA-CG-wmi', 'machine_ASR-LSASS'))
    if ($cred.Count -gt 0) {
        $paths += [pscustomobject]@{ Title = 'Credential theft from LSASS'; Techniques = @('T1003.001', 'T1550.002'); Checks = $cred
            Narrative = 'An attacker with local admin rights can dump credentials from LSASS memory (e.g., Mimikatz, nanodump) because ' + (($cred | ForEach-Object { $bad[$_].CheckName }) -join ', ') + ' ' + $(if ($cred.Count -gt 1) { 'are' } else { 'is' }) + ' not in place. Harvested NTLM hashes and Kerberos tickets enable pass-the-hash and pass-the-ticket to other hosts.' }
    }
    $poison = @(& $has @('domain_LLMNR', 'domain_NetBIOSNT', 'domain_NetBIOSoTCP', 'domain_mDNS', 'domain_mitm6', 'machine_WPADSvc'))
    $relay = @(& $has @('domain_SMBv2-srvSign', 'domain_SMBv2-clientSign', 'domain_NTLMComLevel'))
    if ($poison.Count -gt 0) {
        $txt = 'An attacker on the same network segment can answer broadcast/multicast name queries (' + (($poison | ForEach-Object { $bad[$_].CheckName }) -join ', ') + ') and capture NTLM authentication.'
        if ($relay.Count -gt 0) { $txt += ' Because ' + (($relay | ForEach-Object { $bad[$_].CheckName }) -join ', ') + ' ' + $(if ($relay.Count -gt 1) { 'are' } else { 'is' }) + ' not enforced, the captured authentication can be relayed or cracked.' }
        $paths += [pscustomobject]@{ Title = 'Name-resolution poisoning and NTLM relay'; Techniques = @('T1557.001', 'T1557.003', 'T1110.002'); Checks = @($poison + $relay); Narrative = $txt }
    }
    $lat = @(& $has @('machine_LAPS', 'machine_UAC-RemoteRestrictions', 'machine_RDP-Users', 'machine_FirewallProfiles', 'domain_SMBv1'))
    if ($lat.Count -gt 0) {
        $paths += [pscustomobject]@{ Title = 'Lateral movement'; Techniques = @('T1550.002', 'T1021.001', 'T1021.002', 'T1210'); Checks = $lat
            Narrative = 'Compromise of this host can spread laterally: ' + (($lat | ForEach-Object { '{0} ({1})' -f $bad[$_].CheckName, $bad[$_].Status }) -join '; ') + '. Shared local administrator passwords and unrestricted remote services are the most common enablers of domain-wide ransomware deployment.' }
    }
    $pe = @(& $has @('machine_installWithElevation', 'vul_quotedPath', 'machine_UAC-EnableLUA', 'machine_UAC-AdminPrompt', 'machine_wsusUpdate', 'machine_lastPatch'))
    if ($pe.Count -gt 0) {
        $paths += [pscustomobject]@{ Title = 'Local privilege escalation'; Techniques = @('T1218.007', 'T1574.009', 'T1548.002', 'T1068'); Checks = $pe
            Narrative = 'A standard user or low-privileged foothold can escalate to administrator/SYSTEM through: ' + (($pe | ForEach-Object { $bad[$_].CheckName }) -join ', ') + '.' }
    }
    $doc = @(& $has @('machine_officeVBAWarnings', 'machine_officeInternetMacros', 'machine_ASR-Office', 'machine_excelDDE', 'machine_wordDDE', 'machine_outlookDDE'))
    if ($doc.Count -gt 0) {
        $paths += [pscustomobject]@{ Title = 'Initial access via malicious documents'; Techniques = @('T1566.001', 'T1204.002', 'T1559.002'); Checks = $doc
            Narrative = 'Phishing attachments can execute code on this host: ' + (($doc | ForEach-Object { $bad[$_].CheckName }) -join ', ') + ' leave macro/DDE execution paths open.' }
    }
    $blind = @(& $has @('machine_PSScriptBlock', 'machine_PSModuleLog', 'machine_ComLineLog', 'machine_SecMaxLog', 'machine_DefenderTamper', 'machine_DefenderRTP', 'machine_AVName', 'machine_PSv2'))
    if ($blind.Count -gt 0) {
        $paths += [pscustomobject]@{ Title = 'Detection blind spots and defense impairment'; Techniques = @('T1059.001', 'T1685', 'T1689'); Checks = $blind
            Narrative = 'Attacker activity is less likely to be detected or can be hidden: ' + (($blind | ForEach-Object { $bad[$_].CheckName }) -join ', ') + '. This lengthens dwell time and weakens incident response.' }
    }
    $egress = @(& $has @('machine_na-dns', 'machine_na-browsing', 'machine_WPADSvc', 'machine_proxyConf'))
    if ($egress.Count -gt 0) {
        $paths += [pscustomobject]@{ Title = 'Command and control / exfiltration egress'; Techniques = @('T1071.001', 'T1071.004', 'T1571', 'T1048'); Checks = $egress
            Narrative = 'Malware on this host can reach the internet outside the controlled proxy path (' + (($egress | ForEach-Object { $bad[$_].CheckName }) -join ', ') + '), enabling command-and-control and data exfiltration.' }
    }
    foreach ($p in $paths) {
        $worst = @($p.Checks | ForEach-Object { $bad[$_] } | Sort-Object { $script:WASeverityOrder[$_.Severity] })[0]
        $p | Add-Member -NotePropertyName Severity -NotePropertyValue $worst.Severity
    }
    return @($paths | Sort-Object { $script:WASeverityOrder[$_.Severity] })
}

function New-WAExecutiveSummary {
    # Generates the narrative summary paragraphs shown in the report and on screen.
    [CmdletBinding()]
    param ([object[]]$Findings, $Score, [object[]]$AttackPaths)
    $ctx = $script:WACtx
    $auto = @($Findings | Where-Object { $_.Status -in 'Pass', 'Fail', 'Warning' }).Count
    $fs = $Score.FailBySeverity
    $out = @()
    $out += ('{0} ({1}, {2}) scored {3}/100 (grade {4}) across {5} evaluated controls. {6} failed ({7} critical, {8} high, {9} medium), {10} returned warnings and {11} need manual review.' -f `
            $ctx.Hostname, $ctx.Role, $ctx.OSCaption, $Score.Score, $Score.Grade, $auto, $Score.Counts['Fail'], $fs['Critical'], $fs['High'], $fs['Medium'], $Score.Counts['Warning'], $Score.Counts['Manual'])

    # Tactic exposure = severity-weighted sum of failing controls mapped to the tactic (ties: matrix order).
    $exp = @{}
    foreach ($f in @($Findings | Where-Object { $_.Status -eq 'Fail' })) {
        $w = $script:WASeverityWeight[[string]$f.Severity]
        foreach ($t in $f.Techniques) {
            foreach ($tac in $script:WATechniques[$t].Tactics) {
                if (-not $exp.ContainsKey($tac)) { $exp[$tac] = @{ Weight = 0; Techniques = @{}; Checks = @{} } }
                $exp[$tac].Techniques[$t] = $true
                if (-not $exp[$tac].Checks.ContainsKey($f.CheckID + '|' + $f.Scope)) { $exp[$tac].Checks[$f.CheckID + '|' + $f.Scope] = $true; $exp[$tac].Weight += $w }
            }
        }
    }
    if ($exp.Count -gt 0) {
        $top = @($exp.Keys | Sort-Object @{ Expression = { $exp[$_].Weight }; Descending = $true }, @{ Expression = { $script:WATactics[$_].Order } } | Select-Object -First 3)
        $parts = $top | ForEach-Object { '{0} ({1} failing control{2}, {3} technique{4})' -f $script:WATactics[$_].Name, $exp[$_].Checks.Count, $(if ($exp[$_].Checks.Count -ne 1) { 's' } else { '' }), $exp[$_].Techniques.Count, $(if ($exp[$_].Techniques.Count -ne 1) { 's' } else { '' }) }
        $out += ('Mapped to MITRE ATT&CK ({0}), the failing controls leave the host most exposed in: {1}.' -f $script:WAAttackVersion, ($parts -join ', '))
    }
    if (@($AttackPaths).Count -gt 0) {
        $out += ('{0} attack path(s) were identified by chaining the weaknesses: {1}.' -f @($AttackPaths).Count, ((@($AttackPaths) | ForEach-Object { $_.Title }) -join '; '))
    }
    $prio = @($Findings | Where-Object { $_.Status -eq 'Fail' } | Sort-Object @{ Expression = { Get-WAPriority $_ }; Descending = $true } | Select-Object -First 3)
    if ($prio.Count -gt 0) {
        $out += ('Highest-impact fixes: ' + (($prio | ForEach-Object { '{0} [{1}]' -f $_.CheckName, $_.Severity }) -join '; ') + '.')
    }
    if (-not $ctx.IsAdmin) { $out += 'The assessment ran without elevation - several controls could not be verified and are marked for manual review. Re-run elevated for full coverage.' }
    return $out
}

function ConvertTo-WAReportData {
    [CmdletBinding()]
    param ()
    $ctx = $script:WACtx
    $findings = @($ctx.Findings)
    $score = Get-WAScore -Findings $findings
    $paths = @(Get-WAAttackPaths -Findings $findings)
    $summary = @(New-WAExecutiveSummary -Findings $findings -Score $score -AttackPaths $paths)
    $usedTech = @{}
    foreach ($f in $findings) { foreach ($t in $f.Techniques) { $usedTech[$t] = $true } }
    $tech = [ordered]@{}
    foreach ($t in ($usedTech.Keys | Sort-Object)) { $tech[$t] = @{ name = $script:WATechniques[$t].Name; tactics = @($script:WATechniques[$t].Tactics) } }
    $tactics = @($script:WATactics.Keys | ForEach-Object { @{ key = $_; id = $script:WATactics[$_].Id; name = $script:WATactics[$_].Name; order = $script:WATactics[$_].Order } })
    $end = Get-Date
    return [ordered]@{
        meta        = [ordered]@{
            host = $ctx.Hostname; domain = $(if ($ctx.PartOfDomain) { $ctx.DomainName } else { 'WORKGROUP' }); os = $ctx.OSCaption; osVersion = [string]$ctx.WinVersion
            role = $ctx.Role; isAdmin = $ctx.IsAdmin; user = $ctx.User; psVersion = [string]$PSVersionTable.PSVersion; scriptVersion = $script:WAVersion
            attackVersion = $script:WAAttackVersion; attackModified = $script:WAAttackModified
            started = $ctx.StartTime.ToString('s'); generated = $end.ToString('s'); durationSec = [int]($end - $ctx.StartTime).TotalSeconds
            lastBoot = $(if ($ctx.LastBoot) { ([datetime]$ctx.LastBoot).ToString('s') } else { '' })
            options = [ordered]@{ sensitiveSearch = $ctx.EnableSensitiveInfoSearch; skipNetworkTests = $ctx.SkipNetworkTests; skipGpo = $ctx.SkipGpoCollection }
            score = $score.Score; grade = $score.Grade; counts = $score.Counts; failBySeverity = $score.FailBySeverity
        }
        summary     = $summary
        attackPaths = @($paths | ForEach-Object { [ordered]@{ title = $_.Title; severity = $_.Severity; narrative = $_.Narrative; techniques = @($_.Techniques); checks = @($_.Checks) } })
        tactics     = $tactics
        techniques  = $tech
        mitigations = $script:WAMitigations
        findings    = @($findings | ForEach-Object {
                [ordered]@{
                    id = $_.CheckID; name = $_.CheckName; category = $_.Category; scope = $_.Scope; status = $_.Status; severity = $_.Severity
                    finding = $_.Finding; evidence = $_.Evidence; comments = $_.Comments; relatedFile = $_.RelatedFile
                    remediation = $_.Remediation; reference = $_.Reference; coverage = $_.Coverage; priority = (Get-WAPriority $_)
                    techniques = @($_.Techniques); mitigations = @($_.Mitigations)
                }
            })
        errors      = @($ctx.Errors)
        timings     = @($ctx.Timings | Sort-Object Seconds -Descending | Select-Object -First 12)
    }
}

function ConvertTo-WASafeJson {
    # JSON safe for embedding inside a <script> element (no "</script>", no U+2028/2029 line breaks).
    [CmdletBinding()]
    param ([Parameter(Mandatory = $true)]$InputObject, [int]$Depth = 8)
    $json = $InputObject | ConvertTo-Json -Depth $Depth -Compress
    return $json.Replace('<', '\u003c').Replace('>', '\u003e').Replace('&', '\u0026').Replace([string][char]0x2028, '\u2028').Replace([string][char]0x2029, '\u2029')
}

function Export-WAResults {
    # Writes CSV (backward-compatible columns + ATT&CK columns), JSON and the HTML report. Returns the report path.
    [CmdletBinding()]
    param ()
    $ctx = $script:WACtx
    $rows = @($ctx.Findings | ForEach-Object {
            [pscustomobject][ordered]@{
                'Category' = $_.Category; 'CheckName' = $_.CheckName; 'CheckID' = $_.CheckID; 'Scope' = $_.Scope; 'Status' = $_.Status
                'LegacyStatus' = $_.LegacyStatus; 'Risk' = $_.Severity; 'Finding' = $_.Finding; 'Evidence' = $_.Evidence; 'Comments' = $_.Comments
                'Related file' = $_.RelatedFile; 'Remediation' = $_.Remediation; 'Reference' = $_.Reference; 'Coverage' = $_.Coverage
                'ATTACK_Techniques' = ($_.Techniques -join ';'); 'ATTACK_TechniqueNames' = ($_.TechniqueNames -join ';')
                'ATTACK_Tactics' = ($_.Tactics -join ';'); 'ATTACK_Mitigations' = ($_.Mitigations -join ';'); 'ATTACK_MitigationNames' = ($_.MitigationNames -join ';')
            }
        })
    Write-WACsv -FullPath (Join-Path $ctx.RootPath (Get-WAFileName -Name 'Hardening_Checks' -Extension '.csv')) -InputObject $rows
    $data = ConvertTo-WAReportData
    [System.IO.File]::WriteAllText((Join-Path $ctx.RootPath (Get-WAFileName -Name 'Hardening_Checks' -Extension '.json')), ($data | ConvertTo-Json -Depth 8), $script:WAUtf8NoBom)
    $reportPath = Join-Path $ctx.RootPath (Get-WAFileName -Name 'WindowsAssessment_Report' -Extension '.html')
    New-WAHtmlReport -Data $data -Path $reportPath
    return $reportPath
}

function New-WAHtmlReport {
    [CmdletBinding()]
    param ([Parameter(Mandatory = $true)]$Data, [Parameter(Mandatory = $true)][string]$Path)
    $json = ConvertTo-WASafeJson -InputObject $Data
    $title = 'Security Assessment - ' + [System.Net.WebUtility]::HtmlEncode([string]$Data.meta.host)
    $html = $script:WAReportTemplate.Replace('__WA_TITLE__', $title).Replace('__WA_DATA__', $json)
    [System.IO.File]::WriteAllText($Path, $html, $script:WAUtf8NoBom)
}
#endregion

#region HTML report template (self-contained; data injected at __WA_DATA__)
$script:WAReportTemplate = @'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:;">
<title>__WA_TITLE__</title>
<style>
:root{
  --bg:#f5f6f8;--surface:#fff;--surface-2:#f0f2f5;--border:#dfe3e8;--text:#1b1f24;--muted:#5b6571;--accent:#0f6cbd;
  --pass:#107c41;--fail:#c42b1c;--warn:#b86e00;--manual:#4f5bd5;--info:#5b6571;--na:#8a939e;--error:#8e24aa;
  --crit:#7d0b12;--high:#c42b1c;--med:#d06b00;--low:#a88400;--inf:#6b7280;
  --pass-bg:#e7f4ec;--fail-bg:#fbe9e7;--warn-bg:#fdf1dc;--manual-bg:#eceefd;--na-bg:#eef0f2;
  --shadow:0 1px 2px rgba(16,24,40,.06),0 1px 3px rgba(16,24,40,.08);
  --mono:Consolas,"Cascadia Mono","SF Mono",Menlo,monospace;
}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){
  --bg:#0f1216;--surface:#171b21;--surface-2:#1e232b;--border:#2b323c;--text:#e6e9ee;--muted:#9aa4b1;--accent:#4aa3ff;
  --pass:#3ccf7e;--fail:#ff6b5e;--warn:#f0a935;--manual:#8f99ff;--info:#9aa4b1;--na:#6b7480;--error:#d17be0;
  --crit:#ff4d5e;--high:#ff6b5e;--med:#f0a935;--low:#d9c24a;--inf:#9aa4b1;
  --pass-bg:#12301f;--fail-bg:#3a1714;--warn-bg:#3a2a0c;--manual-bg:#1f2350;--na-bg:#20252c;--shadow:none;}}
:root[data-theme="dark"]{
  --bg:#0f1216;--surface:#171b21;--surface-2:#1e232b;--border:#2b323c;--text:#e6e9ee;--muted:#9aa4b1;--accent:#4aa3ff;
  --pass:#3ccf7e;--fail:#ff6b5e;--warn:#f0a935;--manual:#8f99ff;--info:#9aa4b1;--na:#6b7480;--error:#d17be0;
  --crit:#ff4d5e;--high:#ff6b5e;--med:#f0a935;--low:#d9c24a;--inf:#9aa4b1;
  --pass-bg:#12301f;--fail-bg:#3a1714;--warn-bg:#3a2a0c;--manual-bg:#1f2350;--na-bg:#20252c;--shadow:none;}
*{box-sizing:border-box}
html{scroll-behavior:smooth;scroll-padding-top:64px}
body{margin:0;background:var(--bg);color:var(--text);font:14px/1.5 "Segoe UI",system-ui,-apple-system,Roboto,"Helvetica Neue",Arial,sans-serif}
a{color:var(--accent)}
header.top{position:sticky;top:0;z-index:20;background:var(--surface);border-bottom:1px solid var(--border);display:flex;align-items:center;gap:16px;padding:10px 24px;flex-wrap:wrap}
.brand{font-weight:600;font-size:15px;white-space:nowrap}
.brand small{color:var(--muted);font-weight:400;margin-left:8px}
nav.sections{display:flex;gap:4px;flex-wrap:wrap;flex:1}
nav.sections a{color:var(--muted);text-decoration:none;padding:6px 10px;border-radius:6px;font-size:13px}
nav.sections a:hover{background:var(--surface-2);color:var(--text)}
.tools{display:flex;gap:6px}
button{font:inherit;color:inherit;background:var(--surface-2);border:1px solid var(--border);border-radius:6px;padding:6px 10px;cursor:pointer}
button:hover{border-color:var(--accent)}
button:focus-visible,a:focus-visible,input:focus-visible,select:focus-visible,tr:focus-visible,.cell:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
main{max-width:1400px;margin:0 auto;padding:20px 24px 60px;overflow-wrap:anywhere}
section{margin-bottom:28px}
h2{font-size:18px;margin:0 0 12px;font-weight:600}
h3{font-size:14px;margin:0 0 8px;font-weight:600}
.card{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:16px;box-shadow:var(--shadow)}
.grid{display:grid;gap:16px}
.grid>*{min-width:0}
.hero{grid-template-columns:260px 1fr}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(150px,100%),1fr));gap:12px}
.kpi{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:12px 14px}
.kpi .v{font-size:26px;font-weight:600;font-variant-numeric:tabular-nums}
.kpi .l{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.04em}
.kpi .s{font-size:12px;color:var(--muted);margin-top:2px}
.meta{display:flex;flex-wrap:wrap;gap:6px;margin:0 0 16px}
.chip{display:inline-flex;align-items:center;gap:4px;border:1px solid var(--border);background:var(--surface);border-radius:999px;padding:2px 10px;font-size:12px;color:var(--muted)}
.chip b{color:var(--text);font-weight:600}
.score-wrap{display:flex;flex-direction:column;align-items:center;justify-content:center;text-align:center}
.score-wrap .grade{font-size:13px;color:var(--muted)}
.summary p{margin:0 0 8px}
.summary p:first-child{font-size:15px}
.charts{grid-template-columns:repeat(auto-fit,minmax(min(300px,100%),1fr));align-items:start}
.bars .row{display:grid;grid-template-columns:minmax(90px,1.1fr) 3fr 44px;gap:8px;align-items:center;margin:6px 0;font-size:13px}
.bars .row>:first-child{overflow-wrap:anywhere}
.bars a{color:var(--text);text-decoration:none}.bars a:hover{color:var(--accent);text-decoration:underline}
.bars .track{height:10px;background:var(--surface-2);border-radius:5px;overflow:hidden;display:flex}
.bars .seg{height:100%}
.bars .n{text-align:right;font-variant-numeric:tabular-nums;color:var(--muted)}
.legend{display:flex;flex-wrap:wrap;gap:10px;font-size:12px;color:var(--muted);margin-top:8px}
.legend i{display:inline-block;width:10px;height:10px;border-radius:2px;margin-right:4px;vertical-align:-1px}
.pill{display:inline-block;border-radius:4px;padding:1px 7px;font-size:12px;font-weight:600;white-space:nowrap}
.st-Pass{color:var(--pass);background:var(--pass-bg)}.st-Fail{color:var(--fail);background:var(--fail-bg)}.st-Warning{color:var(--warn);background:var(--warn-bg)}
.st-Manual{color:var(--manual);background:var(--manual-bg)}.st-Info,.st-NotApplicable{color:var(--muted);background:var(--na-bg)}.st-Error{color:var(--error);background:var(--na-bg)}
.sv{display:inline-flex;align-items:center;gap:5px;font-size:12px;white-space:nowrap}
.sv::before{content:"";width:8px;height:8px;border-radius:50%;background:var(--c)}
.sv-Critical{--c:var(--crit)}.sv-High{--c:var(--high)}.sv-Medium{--c:var(--med)}.sv-Low{--c:var(--low)}.sv-Informational{--c:var(--inf)}
.tchip{font-family:var(--mono);font-size:11px;border:1px solid var(--border);border-radius:4px;padding:0 5px;margin:1px 2px 1px 0;display:inline-block;color:var(--muted);text-decoration:none;background:var(--surface)}
a.tchip:hover{border-color:var(--accent);color:var(--accent)}
.paths{grid-template-columns:repeat(auto-fit,minmax(min(320px,100%),1fr))}
.path{border-left:4px solid var(--c)}
.path p{margin:6px 0 8px;color:var(--text)}
.path .checks{font-size:12px;color:var(--muted)}
.matrix-wrap{overflow-x:auto;padding-bottom:6px}
.matrix{display:flex;gap:8px;min-width:min-content}
.tactic{width:190px;flex:0 0 190px}
.tactic .th{font-size:12px;font-weight:600;padding:6px 8px;border-radius:6px;background:var(--surface-2);border:1px solid var(--border);margin-bottom:6px}
.tactic .th small{display:block;color:var(--muted);font-weight:400}
.cell{display:block;width:100%;text-align:left;border:1px solid var(--border);border-left:5px solid var(--c);background:var(--surface);border-radius:6px;padding:6px 8px;margin-bottom:6px;cursor:pointer;font-size:12px;line-height:1.3}
.cell .tid{font-family:var(--mono);font-size:11px;color:var(--muted);display:flex;justify-content:space-between}
.cell.sel{outline:2px solid var(--accent)}
.c-crit{--c:var(--crit)}.c-high{--c:var(--high)}.c-med{--c:var(--med)}.c-low{--c:var(--low)}.c-warn{--c:var(--warn)}.c-manual{--c:var(--manual)}.c-pass{--c:var(--pass)}.c-na{--c:var(--na)}
.detail-panel{margin-top:12px}
.toolbar{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-bottom:10px}
.toolbar input[type=search]{flex:1;min-width:200px;padding:7px 10px;border:1px solid var(--border);border-radius:6px;background:var(--surface);color:var(--text);font:inherit}
.toolbar select{padding:6px 8px;border:1px solid var(--border);border-radius:6px;background:var(--surface);color:var(--text);font:inherit;max-width:220px}
.toggle{border-radius:999px;padding:3px 10px;font-size:12px}
.toggle[aria-pressed="false"]{opacity:.45}
.count{color:var(--muted);font-size:12px;margin-left:auto}
.active-filter{background:var(--manual-bg);color:var(--manual);border-color:transparent}
.table-wrap{overflow-x:auto;border:1px solid var(--border);border-radius:10px;background:var(--surface)}
table{border-collapse:collapse;width:100%}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--border);vertical-align:top}
th{font-size:12px;color:var(--muted);font-weight:600;background:var(--surface-2);position:sticky;top:0;cursor:pointer;user-select:none;white-space:nowrap}
th[aria-sort="ascending"]::after{content:" \25B2"}th[aria-sort="descending"]::after{content:" \25BC"}
tr.row{cursor:pointer}
tr.row:hover td{background:var(--surface-2)}
td .cid{font-family:var(--mono);font-size:11px;color:var(--muted)}
td{overflow-wrap:anywhere}
tr.det td{background:var(--surface-2);padding:12px 16px}
.kv{display:grid;grid-template-columns:130px 1fr;gap:6px 12px;font-size:13px}
.kv .k{color:var(--muted)}
pre{margin:0;white-space:pre-wrap;word-break:break-word;font-family:var(--mono);font-size:12px;background:var(--surface);border:1px solid var(--border);border-radius:6px;padding:8px}
.plan{grid-template-columns:repeat(auto-fit,minmax(min(300px,100%),1fr));align-items:start}
.plan ol{margin:0;padding-left:20px}
.plan li{margin-bottom:10px}
.plan li .r{color:var(--muted);font-size:12.5px}
.muted{color:var(--muted)}
footer{color:var(--muted);font-size:12px;border-top:1px solid var(--border);padding-top:12px}
.empty{color:var(--muted);font-style:italic;padding:8px 0}
@media (max-width:820px){.hero{grid-template-columns:1fr}header.top{position:static;padding:8px 16px;gap:8px}nav.sections{order:3;flex:1 1 100%;flex-wrap:nowrap;overflow-x:auto}nav.sections a{white-space:nowrap}main{padding:16px}.kv{grid-template-columns:1fr}}
@media print{header.top,.toolbar,.tools,#matrix-detail{display:none!important}body{background:#fff}main{max-width:none;padding:0}.card,.kpi,.table-wrap{box-shadow:none;break-inside:avoid}section{break-inside:avoid-page}}
</style>
</head>
<body>
<header class="top">
  <div class="brand">Windows Security Assessment<small id="h-host"></small></div>
  <nav class="sections" aria-label="Report sections">
    <a href="#overview">Overview</a><a href="#paths">Attack paths</a><a href="#attack">ATT&amp;CK matrix</a>
    <a href="#findings">Findings</a><a href="#plan">Remediation plan</a><a href="#mitigations">Mitigations</a><a href="#run">Run details</a>
  </nav>
  <div class="tools">
    <button type="button" id="btn-theme" aria-label="Toggle dark mode">Theme</button>
    <button type="button" id="btn-print">Print</button>
  </div>
</header>
<main>
  <section id="overview">
    <div class="meta" id="meta-chips"></div>
    <div class="grid hero">
      <div class="card score-wrap" id="score-card"></div>
      <div class="grid" style="gap:12px">
        <div class="kpis" id="kpis"></div>
        <div class="card summary" id="summary"><h3>Executive summary</h3></div>
      </div>
    </div>
    <div class="grid charts" style="margin-top:16px">
      <div class="card"><h3>Result distribution</h3><div id="donut"></div></div>
      <div class="card"><h3>Failed controls by severity</h3><div class="bars" id="sev-bars"></div></div>
      <div class="card"><h3>Results by category</h3><div class="bars" id="cat-bars"></div><div class="legend" id="cat-legend"></div></div>
    </div>
  </section>

  <section id="paths">
    <h2>Attack paths</h2>
    <p class="muted" style="margin-top:-6px">Weaknesses that chain together into a realistic attack, generated from the failing and warning controls.</p>
    <div class="grid paths" id="path-cards"></div>
  </section>

  <section id="attack">
    <h2>MITRE ATT&amp;CK coverage</h2>
    <p class="muted" style="margin-top:-6px" id="attack-caption"></p>
    <div class="card">
      <div class="matrix-wrap"><div class="matrix" id="matrix"></div></div>
      <div class="legend" id="matrix-legend"></div>
    </div>
    <div class="card detail-panel" id="matrix-detail" hidden></div>
  </section>

  <section id="findings">
    <h2>Findings</h2>
    <div class="toolbar" role="search">
      <input type="search" id="q" placeholder="Search controls, findings, evidence, technique IDs..." aria-label="Search findings">
      <span id="status-toggles"></span>
      <select id="f-sev" aria-label="Severity"><option value="">All severities</option></select>
      <select id="f-cat" aria-label="Category"><option value="">All categories</option></select>
      <select id="f-tac" aria-label="Tactic"><option value="">All tactics</option></select>
      <button type="button" id="f-tech" hidden class="active-filter"></button>
      <button type="button" id="btn-reset">Reset</button>
      <button type="button" id="btn-csv">Export CSV</button>
      <span class="count" id="f-count"></span>
    </div>
    <div class="table-wrap">
      <table id="tbl">
        <thead><tr>
          <th data-k="severity" scope="col">Severity</th><th data-k="status" scope="col">Status</th><th data-k="name" scope="col">Control</th>
          <th data-k="category" scope="col">Category</th><th data-k="techniques" scope="col">ATT&amp;CK</th><th data-k="priority" scope="col">Priority</th>
        </tr></thead>
        <tbody id="tbody"></tbody>
      </table>
    </div>
  </section>

  <section id="plan">
    <h2>Remediation plan</h2>
    <div class="grid plan" id="plan-cols"></div>
  </section>

  <section id="mitigations">
    <h2>ATT&amp;CK mitigation coverage</h2>
    <div class="card"><div class="bars" id="mit-bars"></div><div class="legend" id="mit-legend"></div></div>
  </section>

  <section id="run">
    <h2>Run details</h2>
    <div class="grid charts">
      <div class="card"><h3>Execution</h3><div class="kv" id="run-kv"></div></div>
      <div class="card"><h3>Slowest steps</h3><div class="bars" id="timings"></div></div>
      <div class="card"><h3>Execution errors</h3><div id="errors"></div></div>
    </div>
  </section>
  <footer id="footer"></footer>
</main>
<script id="wa-data" type="application/json">__WA_DATA__</script>
<script>
(function () {
  'use strict';
  var D = JSON.parse(document.getElementById('wa-data').textContent);
  var F = D.findings || [];
  var SEV = ['Critical', 'High', 'Medium', 'Low', 'Informational'];
  var STAT = ['Fail', 'Warning', 'Manual', 'Pass', 'Info', 'NotApplicable', 'Error'];
  var STAT_LABEL = { Fail: 'Fail', Warning: 'Warning', Manual: 'Manual', Pass: 'Pass', Info: 'Info', NotApplicable: 'N/A', Error: 'Error' };
  var STAT_VAR = { Fail: '--fail', Warning: '--warn', Manual: '--manual', Pass: '--pass', Info: '--info', NotApplicable: '--na', Error: '--error' };
  var SEV_VAR = { Critical: '--crit', High: '--high', Medium: '--med', Low: '--low', Informational: '--inf' };
  var tacticByKey = {};
  (D.tactics || []).forEach(function (t) { tacticByKey[t.key] = t; });

  function el(tag, attrs, kids) {
    var e = document.createElement(tag);
    if (attrs) Object.keys(attrs).forEach(function (k) {
      if (k === 'text') e.textContent = attrs[k];
      else if (k === 'cls') e.className = attrs[k];
      else if (k === 'style') e.setAttribute('style', attrs[k]);
      else if (k.indexOf('on') === 0) e.addEventListener(k.slice(2), attrs[k]);
      else e.setAttribute(k, attrs[k]);
    });
    (kids || []).forEach(function (c) { if (c != null) e.appendChild(typeof c === 'string' ? document.createTextNode(c) : c); });
    return e;
  }
  function clear(n) { while (n.firstChild) n.removeChild(n.firstChild); return n; }
  function cssVar(v) { return getComputedStyle(document.documentElement).getPropertyValue(v).trim(); }
  function techUrl(id) { return 'https://attack.mitre.org/techniques/' + id.replace('.', '/') + '/'; }
  function mitUrl(id) { return 'https://attack.mitre.org/mitigations/' + id + '/'; }
  function techChip(id) {
    var t = D.techniques[id] || {};
    return el('a', { cls: 'tchip', href: techUrl(id), target: '_blank', rel: 'noopener', title: id + ' ' + (t.name || ''), text: id });
  }
  function pill(s) { return el('span', { cls: 'pill st-' + s, text: STAT_LABEL[s] || s }); }
  function sev(s) { return el('span', { cls: 'sv sv-' + s, text: s }); }
  function count(arr, fn) { return arr.filter(fn).length; }

  /* ---------- header + overview ---------- */
  var M = D.meta;
  document.getElementById('h-host').textContent = M.host;
  var chips = document.getElementById('meta-chips');
  [['Host', M.host], ['Domain', M.domain], ['Role', M.role], ['OS', M.os + ' (' + M.osVersion + ')'], ['Elevated', M.isAdmin ? 'Yes' : 'No'],
   ['Generated', (M.generated || '').replace('T', ' ')], ['ATT&CK', M.attackVersion]].forEach(function (p) {
    chips.appendChild(el('span', { cls: 'chip' }, [p[0] + ': ', el('b', { text: String(p[1]) })]));
  });

  function ring(score, grade) {
    var r = 64, c = 2 * Math.PI * r, col = score >= 80 ? '--pass' : score >= 60 ? '--warn' : '--fail';
    var ns = 'http://www.w3.org/2000/svg';
    var svg = document.createElementNS(ns, 'svg');
    svg.setAttribute('viewBox', '0 0 160 160'); svg.setAttribute('width', '170'); svg.setAttribute('height', '170');
    svg.setAttribute('role', 'img'); svg.setAttribute('aria-label', 'Security score ' + score + ' of 100, grade ' + grade);
    function circ(stroke, dash) {
      var ci = document.createElementNS(ns, 'circle');
      ci.setAttribute('cx', 80); ci.setAttribute('cy', 80); ci.setAttribute('r', r); ci.setAttribute('fill', 'none');
      ci.setAttribute('stroke', stroke); ci.setAttribute('stroke-width', 14);
      if (dash != null) { ci.setAttribute('stroke-dasharray', dash + ' ' + c); ci.setAttribute('transform', 'rotate(-90 80 80)'); ci.setAttribute('stroke-linecap', 'round'); }
      return ci;
    }
    svg.appendChild(circ(cssVar('--surface-2'), null));
    svg.appendChild(circ(cssVar(col), c * score / 100));
    var t = document.createElementNS(ns, 'text');
    t.setAttribute('x', 80); t.setAttribute('y', 88); t.setAttribute('text-anchor', 'middle');
    t.setAttribute('font-size', 38); t.setAttribute('font-weight', 600); t.setAttribute('fill', cssVar('--text'));
    t.textContent = score; svg.appendChild(t);
    return svg;
  }
  function renderScore() {
    var sc = clear(document.getElementById('score-card'));
    sc.appendChild(el('div', { cls: 'kpi-l muted', text: 'Security score', style: 'font-size:12px;text-transform:uppercase;letter-spacing:.04em' }));
    sc.appendChild(ring(M.score, M.grade));
    sc.appendChild(el('div', { cls: 'grade', text: 'Grade ' + M.grade + ' \u00b7 weighted by severity' }));
  }
  renderScore();

  var techFail = {};
  F.forEach(function (f) { if (f.status === 'Fail') f.techniques.forEach(function (t) { techFail[t] = true; }); });
  var kpis = document.getElementById('kpis');
  var fbs = M.failBySeverity || {};
  [['Failed', M.counts.Fail, (fbs.Critical || 0) + ' critical \u00b7 ' + (fbs.High || 0) + ' high', '--fail'],
   ['Warnings', M.counts.Warning, 'partial or weak configuration', '--warn'],
   ['Passed', M.counts.Pass, 'controls in place', '--pass'],
   ['Manual review', M.counts.Manual, 'analyst validation needed', '--manual'],
   ['Techniques exposed', Object.keys(techFail).length, 'of ' + Object.keys(D.techniques).length + ' mapped ATT&CK techniques', '--high']
  ].forEach(function (k) {
    kpis.appendChild(el('div', { cls: 'kpi', style: 'border-top:3px solid var(' + k[3] + ')' }, [
      el('div', { cls: 'l', text: k[0] }), el('div', { cls: 'v', text: String(k[1]) }), el('div', { cls: 's', text: k[2] })]));
  });
  var sum = document.getElementById('summary');
  (D.summary || []).forEach(function (p) { sum.appendChild(el('p', { text: p })); });

  function donut(target) {
    var ns = 'http://www.w3.org/2000/svg', r = 52, c = 2 * Math.PI * r, off = 0;
    var svg = document.createElementNS(ns, 'svg');
    svg.setAttribute('viewBox', '0 0 140 140'); svg.setAttribute('width', '150'); svg.setAttribute('height', '150');
    var tot = F.length || 1, lg = el('div', { cls: 'legend' });
    var parts = STAT.map(function (s) { return [s, count(F, function (f) { return f.status === s; })]; }).filter(function (p) { return p[1] > 0; });
    svg.setAttribute('role', 'img');
    svg.setAttribute('aria-label', parts.map(function (p) { return STAT_LABEL[p[0]] + ' ' + p[1]; }).join(', '));
    parts.forEach(function (p) {
      var len = c * p[1] / tot;
      var ci = document.createElementNS(ns, 'circle');
      ci.setAttribute('cx', 70); ci.setAttribute('cy', 70); ci.setAttribute('r', r); ci.setAttribute('fill', 'none');
      ci.setAttribute('stroke', cssVar(STAT_VAR[p[0]])); ci.setAttribute('stroke-width', 20);
      ci.setAttribute('stroke-dasharray', Math.max(len - 1.5, 0.5) + ' ' + c);
      ci.setAttribute('stroke-dashoffset', -off); ci.setAttribute('transform', 'rotate(-90 70 70)');
      var ti = document.createElementNS(ns, 'title'); ti.textContent = STAT_LABEL[p[0]] + ': ' + p[1]; ci.appendChild(ti);
      svg.appendChild(ci); off += len;
      lg.appendChild(el('span', {}, [el('i', { style: 'background:var(' + STAT_VAR[p[0]] + ')' }), STAT_LABEL[p[0]] + ' ' + p[1]]));
    });
    var t = document.createElementNS(ns, 'text');
    t.setAttribute('x', 70); t.setAttribute('y', 76); t.setAttribute('text-anchor', 'middle'); t.setAttribute('font-size', 22);
    t.setAttribute('font-weight', 600); t.setAttribute('fill', cssVar('--text')); t.textContent = F.length; svg.appendChild(t);
    var t2 = document.createElementNS(ns, 'text'); t2.setAttribute('x', 70); t2.setAttribute('y', 94); t2.setAttribute('text-anchor', 'middle'); t2.setAttribute('font-size', 10);
    t2.setAttribute('fill', cssVar('--muted')); t2.textContent = 'results'; svg.appendChild(t2);
    clear(target).appendChild(el('div', { style: 'display:flex;gap:16px;align-items:center;flex-wrap:wrap' }, [svg, lg]));
  }
  donut(document.getElementById('donut'));

  function barRow(label, segs, total, max, onclick) {
    var track = el('div', { cls: 'track' });
    segs.forEach(function (s) { if (s[0] > 0) track.appendChild(el('div', { cls: 'seg', title: s[2] + ': ' + s[0], style: 'width:' + (100 * s[0] / (max || 1)) + '%;background:var(' + s[1] + ')' })); });
    var lab = onclick ? el('a', { href: '#findings', onclick: onclick, text: label }) : el('span', { text: label });
    return el('div', { cls: 'row' }, [lab, track, el('span', { cls: 'n', text: String(total) })]);
  }
  var sevBars = document.getElementById('sev-bars');
  var maxSev = Math.max.apply(null, SEV.map(function (s) { return fbs[s] || 0; }).concat([1]));
  SEV.forEach(function (s) {
    sevBars.appendChild(barRow(s, [[fbs[s] || 0, SEV_VAR[s], s]], fbs[s] || 0, maxSev, function () { setFilter({ severity: s, statuses: ['Fail'] }); }));
  });
  var cats = {};
  F.forEach(function (f) { (cats[f.category] = cats[f.category] || []).push(f); });
  var catNames = Object.keys(cats).filter(function (c) { return c !== 'Information'; }).sort(function (a, b) {
    return count(cats[b], function (f) { return f.status === 'Fail'; }) - count(cats[a], function (f) { return f.status === 'Fail'; }) || a.localeCompare(b);
  });
  var maxCat = Math.max.apply(null, catNames.map(function (c) { return cats[c].length; }).concat([1]));
  var catBars = document.getElementById('cat-bars');
  catNames.forEach(function (c) {
    var l = cats[c];
    catBars.appendChild(barRow(c.replace('Machine Hardening - ', '').replace('Domain Hardening - ', 'Domain: '), [
      [count(l, function (f) { return f.status === 'Fail'; }), '--fail', 'Fail'], [count(l, function (f) { return f.status === 'Warning'; }), '--warn', 'Warning'],
      [count(l, function (f) { return f.status === 'Manual'; }), '--manual', 'Manual'], [count(l, function (f) { return f.status === 'Pass'; }), '--pass', 'Pass'],
      [count(l, function (f) { return ['Info', 'NotApplicable', 'Error'].indexOf(f.status) >= 0; }), '--na', 'Other']
    ], l.length, maxCat, function () { setFilter({ category: c }); }));
  });
  ['Fail', 'Warning', 'Manual', 'Pass'].forEach(function (s) { document.getElementById('cat-legend').appendChild(el('span', {}, [el('i', { style: 'background:var(' + STAT_VAR[s] + ')' }), STAT_LABEL[s]])); });
  document.getElementById('cat-legend').appendChild(el('span', {}, [el('i', { style: 'background:var(--na)' }), 'Info / N/A']));

  /* ---------- attack paths ---------- */
  var pc = document.getElementById('path-cards');
  if (!(D.attackPaths || []).length) pc.appendChild(el('div', { cls: 'empty', text: 'No attack paths identified - no chained weaknesses among failing controls.' }));
  (D.attackPaths || []).forEach(function (p) {
    var names = p.checks.map(function (id) { var f = F.filter(function (x) { return x.id === id; })[0]; return f ? f.name : id; });
    pc.appendChild(el('div', { cls: 'card path', style: '--c:var(' + SEV_VAR[p.severity] + ')' }, [
      el('div', { style: 'display:flex;justify-content:space-between;gap:8px;align-items:baseline' }, [el('h3', { text: p.title }), sev(p.severity)]),
      el('p', { text: p.narrative }),
      el('div', {}, p.techniques.filter(function (t) { return D.techniques[t]; }).map(techChip)),
      el('div', { cls: 'checks', text: 'Contributing controls: ' + names.join(', ') })
    ]));
  });

  /* ---------- ATT&CK matrix ---------- */
  var RANK = { crit: 0, high: 1, med: 2, low: 3, warn: 4, manual: 5, pass: 6, na: 7 };
  function techState(tid) {
    var fs = F.filter(function (f) { return f.techniques.indexOf(tid) >= 0; });
    var best = 'na', fails = 0;
    fs.forEach(function (f) {
      var k = 'na';
      if (f.status === 'Fail') { fails++; k = { Critical: 'crit', High: 'high', Medium: 'med', Low: 'low', Informational: 'low' }[f.severity]; }
      else if (f.status === 'Warning') k = 'warn';
      else if (f.status === 'Manual' || f.status === 'Error') k = 'manual';
      else if (f.status === 'Pass') k = 'pass';
      if (RANK[k] < RANK[best]) best = k;
    });
    return { cls: best, fails: fails, findings: fs };
  }
  document.getElementById('attack-caption').textContent = 'Each cell is an ATT&CK technique mapped to at least one control, coloured by the worst result of its controls. ' +
    'Source: ' + M.attackVersion + ' (' + M.attackModified + '). Click a technique for details.';
  var matrix = document.getElementById('matrix');
  var tacCols = {};
  Object.keys(D.techniques).forEach(function (tid) { D.techniques[tid].tactics.forEach(function (k) { (tacCols[k] = tacCols[k] || []).push(tid); }); });
  Object.keys(tacCols).sort(function (a, b) { return (tacticByKey[a] || {}).order - (tacticByKey[b] || {}).order; }).forEach(function (k) {
    var t = tacticByKey[k] || { name: k, id: '' };
    var col = el('div', { cls: 'tactic' }, [el('div', { cls: 'th' }, [t.name, el('small', { text: t.id + ' \u00b7 ' + tacCols[k].length + ' techniques' })])]);
    tacCols[k].map(function (tid) { return [tid, techState(tid)]; })
      .sort(function (a, b) { return RANK[a[1].cls] - RANK[b[1].cls] || a[0].localeCompare(b[0]); })
      .forEach(function (x) {
        var tid = x[0], st = x[1];
        col.appendChild(el('button', { type: 'button', cls: 'cell c-' + st.cls, 'data-tid': tid, 'aria-label': tid + ' ' + D.techniques[tid].name + ', ' + st.fails + ' failing controls', onclick: function () { showTech(tid); } }, [
          el('span', { cls: 'tid' }, [tid, st.fails ? el('b', { text: st.fails + ' fail', style: 'color:var(--fail)' }) : null]),
          el('span', { text: D.techniques[tid].name })]));
      });
    matrix.appendChild(col);
  });
  [['crit', 'Fail - critical'], ['high', 'Fail - high'], ['med', 'Fail - medium'], ['low', 'Fail - low'], ['warn', 'Warning'], ['manual', 'Manual'], ['pass', 'Pass'], ['na', 'N/A / info']].forEach(function (l) {
    document.getElementById('matrix-legend').appendChild(el('span', {}, [el('i', { cls: 'c-' + l[0], style: 'background:var(--c)' }), l[1]]));
  });
  function showTech(tid) {
    Array.prototype.forEach.call(document.querySelectorAll('.cell'), function (c) { c.classList.toggle('sel', c.getAttribute('data-tid') === tid); });
    var p = clear(document.getElementById('matrix-detail')); p.hidden = false;
    var t = D.techniques[tid], st = techState(tid);
    p.appendChild(el('div', { style: 'display:flex;justify-content:space-between;gap:8px;flex-wrap:wrap;align-items:baseline' }, [
      el('h3', {}, [el('a', { href: techUrl(tid), target: '_blank', rel: 'noopener', text: tid + ' ' + t.name })]),
      el('span', { cls: 'muted', text: t.tactics.map(function (k) { return (tacticByKey[k] || {}).name || k; }).join(', ') })]));
    var tb = el('tbody');
    st.findings.forEach(function (f) { tb.appendChild(el('tr', {}, [el('td', {}, [pill(f.status)]), el('td', {}, [sev(f.severity)]), el('td', { text: f.name + (f.scope ? ' (' + f.scope + ')' : '') }), el('td', { text: f.finding || '' })])); });
    p.appendChild(el('div', { cls: 'table-wrap' }, [el('table', {}, [tb])]));
    p.appendChild(el('div', { style: 'margin-top:8px' }, [el('button', { type: 'button', text: 'Show these controls in Findings', onclick: function () { setFilter({ technique: tid }); location.hash = '#findings'; } })]));
  }

  /* ---------- findings table ---------- */
  var state = { q: '', statuses: STAT.slice(), severity: '', category: '', tactic: '', technique: '', sort: 'priority', dir: -1 };
  var st = document.getElementById('status-toggles');
  STAT.forEach(function (s) {
    if (!count(F, function (f) { return f.status === s; })) return;
    st.appendChild(el('button', { type: 'button', cls: 'toggle pill st-' + s, 'aria-pressed': 'true', 'data-s': s, text: STAT_LABEL[s] + ' ' + count(F, function (f) { return f.status === s; }),
      onclick: function (e) { var s2 = e.currentTarget.getAttribute('data-s'); var i = state.statuses.indexOf(s2); if (i >= 0) state.statuses.splice(i, 1); else state.statuses.push(s2); renderTable(); } }));
    st.appendChild(document.createTextNode(' '));
  });
  function fillSelect(id, values) { var s = document.getElementById(id); values.forEach(function (v) { s.appendChild(el('option', { value: v[0], text: v[1] })); }); }
  fillSelect('f-sev', SEV.map(function (s) { return [s, s]; }));
  fillSelect('f-cat', Object.keys(cats).sort().map(function (c) { return [c, c]; }));
  fillSelect('f-tac', Object.keys(tacCols).sort(function (a, b) { return tacticByKey[a].order - tacticByKey[b].order; }).map(function (k) { return [k, tacticByKey[k].name]; }));
  function bind(id, key) { document.getElementById(id).addEventListener('change', function (e) { state[key] = e.target.value; renderTable(); }); }
  bind('f-sev', 'severity'); bind('f-cat', 'category'); bind('f-tac', 'tactic');
  document.getElementById('q').addEventListener('input', function (e) { state.q = e.target.value.toLowerCase(); renderTable(); });
  document.getElementById('f-tech').addEventListener('click', function () { state.technique = ''; renderTable(); });
  document.getElementById('btn-reset').addEventListener('click', function () { setFilter({}); });
  function setFilter(o) {
    state.q = ''; state.severity = o.severity || ''; state.category = o.category || ''; state.tactic = o.tactic || ''; state.technique = o.technique || '';
    state.statuses = o.statuses ? o.statuses.slice() : STAT.slice();
    document.getElementById('q').value = ''; document.getElementById('f-sev').value = state.severity;
    document.getElementById('f-cat').value = state.category; document.getElementById('f-tac').value = state.tactic;
    renderTable();
  }
  function matches(f) {
    if (state.statuses.indexOf(f.status) < 0) return false;
    if (state.severity && f.severity !== state.severity) return false;
    if (state.category && f.category !== state.category) return false;
    if (state.technique && f.techniques.indexOf(state.technique) < 0) return false;
    if (state.tactic && !f.techniques.some(function (t) { return D.techniques[t].tactics.indexOf(state.tactic) >= 0; })) return false;
    if (state.q) {
      var hay = [f.id, f.name, f.category, f.scope, f.finding, f.evidence, f.comments, f.remediation, f.techniques.join(' '), f.mitigations.join(' '),
        f.techniques.map(function (t) { return D.techniques[t].name; }).join(' ')].join(' ').toLowerCase();
      if (hay.indexOf(state.q) < 0) return false;
    }
    return true;
  }
  var SEVRANK = { Critical: 0, High: 1, Medium: 2, Low: 3, Informational: 4 };
  var STATRANK = { Fail: 0, Warning: 1, Error: 2, Manual: 3, Pass: 4, Info: 5, NotApplicable: 6 };
  function cmp(a, b) {
    var k = state.sort, d = state.dir, va, vb;
    if (k === 'severity') { va = SEVRANK[a.severity]; vb = SEVRANK[b.severity]; d = -d; }
    else if (k === 'status') { va = STATRANK[a.status]; vb = STATRANK[b.status]; d = -d; }
    else if (k === 'priority') { va = a.priority; vb = b.priority; }
    else if (k === 'techniques') { va = a.techniques.length; vb = b.techniques.length; }
    else { va = String(a[k] || '').toLowerCase(); vb = String(b[k] || '').toLowerCase(); }
    if (va < vb) return -1 * d; if (va > vb) return 1 * d;
    return (STATRANK[a.status] - STATRANK[b.status]) || (SEVRANK[a.severity] - SEVRANK[b.severity]) || a.name.localeCompare(b.name);
  }
  Array.prototype.forEach.call(document.querySelectorAll('#tbl th'), function (th) {
    th.tabIndex = 0;
    function go() { var k = th.getAttribute('data-k'); if (state.sort === k) state.dir = -state.dir; else { state.sort = k; state.dir = (k === 'name' || k === 'category') ? 1 : -1; } renderTable(); }
    th.addEventListener('click', go); th.addEventListener('keydown', function (e) { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); go(); } });
  });
  function detailRow(f) {
    function kv(k, v) { return v ? [el('div', { cls: 'k', text: k }), v] : []; }
    var items = [].concat(
      kv('Finding', f.finding ? el('div', { text: f.finding }) : null),
      kv('Evidence', f.evidence ? el('pre', { text: f.evidence }) : null),
      kv('Comments', f.comments ? el('div', { text: f.comments }) : null),
      kv('Remediation', f.remediation ? el('div', { text: f.remediation }) : null),
      kv('Reference', f.reference ? el('a', { href: f.reference, target: '_blank', rel: 'noopener', text: f.reference }) : null),
      kv('Techniques', f.techniques.length ? el('div', {}, f.techniques.map(function (t) { return el('div', {}, [techChip(t), ' ' + D.techniques[t].name + ' \u2014 ' + D.techniques[t].tactics.map(function (k) { return tacticByKey[k].name; }).join(', ')]); })) : null),
      kv('Mitigations', f.mitigations.length ? el('div', {}, f.mitigations.map(function (m) { return el('div', {}, [el('a', { cls: 'tchip', href: mitUrl(m), target: '_blank', rel: 'noopener', text: m }), ' ' + (D.mitigations[m] || '')]); })) : (f.coverage === 'Detect' ? el('div', { cls: 'muted', text: 'Detective control (visibility) - no preventive ATT&CK mitigation.' }) : null)),
      kv('Coverage', f.coverage ? el('div', { text: f.coverage }) : null),
      kv('Evidence file', f.relatedFile ? el('div', { text: f.relatedFile }) : null),
      kv('Check ID', el('div', { cls: 'cid', text: f.id }))
    );
    return el('tr', { cls: 'det' }, [el('td', { colspan: '6' }, [el('div', { cls: 'kv' }, items)])]);
  }
  var open = {};
  function renderTable() {
    var rows = F.filter(matches).sort(cmp), tb = clear(document.getElementById('tbody'));
    Array.prototype.forEach.call(document.querySelectorAll('#tbl th'), function (th) {
      th.setAttribute('aria-sort', th.getAttribute('data-k') === state.sort ? (state.dir > 0 ? 'ascending' : 'descending') : 'none');
    });
    Array.prototype.forEach.call(document.querySelectorAll('#status-toggles button'), function (b) { b.setAttribute('aria-pressed', state.statuses.indexOf(b.getAttribute('data-s')) >= 0 ? 'true' : 'false'); });
    var ft = document.getElementById('f-tech');
    ft.hidden = !state.technique; ft.textContent = state.technique ? 'Technique ' + state.technique + ' \u00d7' : '';
    rows.forEach(function (f) {
      var key = f.id + '|' + f.scope;
      var tr = el('tr', { cls: 'row', tabindex: '0', 'aria-expanded': open[key] ? 'true' : 'false' }, [
        el('td', {}, [sev(f.severity)]), el('td', {}, [pill(f.status)]),
        el('td', {}, [el('div', { text: f.name + (f.scope ? ' (' + f.scope + ')' : '') }), el('div', { cls: 'muted', style: 'font-size:12.5px', text: f.finding || '' })]),
        el('td', { cls: 'muted', text: f.category }),
        el('td', {}, f.techniques.map(techChip)),
        el('td', { cls: 'muted', style: 'font-variant-numeric:tabular-nums', text: f.priority ? String(f.priority) : '' })
      ]);
      function toggle(e) { if (e.target.closest('a')) return; open[key] = !open[key]; renderTable(); }
      tr.addEventListener('click', toggle);
      tr.addEventListener('keydown', function (e) { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); toggle(e); } });
      tb.appendChild(tr);
      if (open[key]) tb.appendChild(detailRow(f));
    });
    if (!rows.length) tb.appendChild(el('tr', {}, [el('td', { colspan: '6', cls: 'empty', text: 'No findings match the current filters.' })]));
    document.getElementById('f-count').textContent = rows.length + ' of ' + F.length + ' results';
  }
  renderTable();

  function toCsv(rows) {
    var cols = ['id', 'name', 'scope', 'category', 'status', 'severity', 'priority', 'finding', 'evidence', 'remediation', 'techniques', 'mitigations', 'relatedFile'];
    function q(v) { v = Array.isArray(v) ? v.join(';') : (v == null ? '' : String(v)); if (/^[=+\-@]/.test(v)) v = "'" + v; return '"' + v.replace(/"/g, '""') + '"'; }
    return '\ufeff' + cols.join(',') + '\r\n' + rows.map(function (r) { return cols.map(function (c) { return q(r[c]); }).join(','); }).join('\r\n');
  }
  document.getElementById('btn-csv').addEventListener('click', function () {
    var blob = new Blob([toCsv(F.filter(matches).sort(cmp))], { type: 'text/csv;charset=utf-8' });
    var a = el('a', { href: URL.createObjectURL(blob), download: 'findings_' + M.host + '.csv' });
    document.body.appendChild(a); a.click(); setTimeout(function () { URL.revokeObjectURL(a.href); a.remove(); }, 500);
  });

  /* ---------- remediation plan ---------- */
  var actionable = F.filter(function (f) { return (f.status === 'Fail' || f.status === 'Warning') && f.remediation; }).sort(function (a, b) { return b.priority - a.priority; });
  var buckets = [
    ['Now', 'Critical and high severity failures', function (f) { return f.status === 'Fail' && (f.severity === 'Critical' || f.severity === 'High'); }],
    ['Next', 'Medium failures and high-severity warnings', function (f) { return (f.status === 'Fail' && f.severity === 'Medium') || (f.status === 'Warning' && (f.severity === 'Critical' || f.severity === 'High')); }],
    ['Later', 'Low severity and remaining warnings', function () { return true; }]
  ];
  var used = {}, planCols = document.getElementById('plan-cols');
  buckets.forEach(function (b) {
    var items = actionable.filter(function (f) { var k = f.id + '|' + f.scope; if (used[k] || !b[2](f)) return false; used[k] = true; return true; });
    var ol = el('ol');
    items.forEach(function (f) {
      ol.appendChild(el('li', {}, [el('div', {}, [sev(f.severity), ' ', el('b', { text: f.name + (f.scope ? ' (' + f.scope + ')' : '') }), ' ', pill(f.status)]),
        el('div', { cls: 'r', text: f.remediation }), el('div', {}, f.techniques.map(techChip))]));
    });
    planCols.appendChild(el('div', { cls: 'card' }, [el('h3', { text: b[0] + ' (' + items.length + ')' }), el('div', { cls: 'muted', style: 'margin:-4px 0 10px;font-size:12px', text: b[1] }),
      items.length ? ol : el('div', { cls: 'empty', text: 'Nothing in this bucket.' })]));
  });

  /* ---------- mitigation coverage ---------- */
  var mit = {};
  F.forEach(function (f) { f.mitigations.forEach(function (m) { (mit[m] = mit[m] || []).push(f); }); });
  var mids = Object.keys(mit).sort(function (a, b) { return count(mit[b], function (f) { return f.status === 'Fail'; }) - count(mit[a], function (f) { return f.status === 'Fail'; }) || a.localeCompare(b); });
  var maxM = Math.max.apply(null, mids.map(function (m) { return mit[m].length; }).concat([1]));
  mids.forEach(function (m) {
    var l = mit[m];
    document.getElementById('mit-bars').appendChild(barRow(m + ' ' + (D.mitigations[m] || ''), [
      [count(l, function (f) { return f.status === 'Fail'; }), '--fail', 'Fail'], [count(l, function (f) { return f.status === 'Warning'; }), '--warn', 'Warning'],
      [count(l, function (f) { return f.status === 'Manual'; }), '--manual', 'Manual'], [count(l, function (f) { return f.status === 'Pass'; }), '--pass', 'Pass'],
      [count(l, function (f) { return ['Info', 'NotApplicable', 'Error'].indexOf(f.status) >= 0; }), '--na', 'Other']], l.length, maxM));
  });
  ['Fail', 'Warning', 'Manual', 'Pass'].forEach(function (s) { document.getElementById('mit-legend').appendChild(el('span', {}, [el('i', { style: 'background:var(' + STAT_VAR[s] + ')' }), STAT_LABEL[s]])); });

  /* ---------- run details ---------- */
  var kv = document.getElementById('run-kv');
  [['Script version', M.scriptVersion], ['PowerShell', M.psVersion], ['Run as', M.user + (M.isAdmin ? ' (elevated)' : ' (not elevated)')],
   ['Started', (M.started || '').replace('T', ' ')], ['Duration', M.durationSec + ' s'], ['Last boot', (M.lastBoot || '').replace('T', ' ')],
   ['Options', 'Sensitive search: ' + (M.options.sensitiveSearch ? 'on' : 'off') + '; network tests: ' + (M.options.skipNetworkTests ? 'skipped' : 'on') + '; GPO collection: ' + (M.options.skipGpo ? 'skipped' : 'on')],
   ['ATT&CK data', M.attackVersion + ' (' + M.attackModified + ')']].forEach(function (p) {
    kv.appendChild(el('div', { cls: 'k', text: p[0] })); kv.appendChild(el('div', { text: String(p[1]) }));
  });
  var tm = D.timings || [], maxT = Math.max.apply(null, tm.map(function (t) { return t.Seconds; }).concat([1]));
  tm.forEach(function (t) { document.getElementById('timings').appendChild(barRow(t.Function, [[t.Seconds, '--accent', 'Seconds']], t.Seconds + 's', maxT)); });
  var er = document.getElementById('errors');
  if (!(D.errors || []).length) er.appendChild(el('div', { cls: 'empty', text: 'No execution errors.' }));
  (D.errors || []).forEach(function (e) { er.appendChild(el('div', { style: 'margin-bottom:6px' }, [el('b', { text: e.Function }), el('span', { cls: 'muted', text: ' (line ' + e.Line + '): ' }), e.Message])); });
  document.getElementById('footer').appendChild(el('div', { text: 'Generated by WindowsAssessment.ps1 v' + M.scriptVersion + ' on ' + (M.generated || '').replace('T', ' ') +
    '. This report contains sensitive configuration data - handle as CONFIDENTIAL. MITRE ATT&CK\u00ae content \u00a9 The MITRE Corporation, reproduced and distributed with the permission of The MITRE Corporation.' }));

  /* ---------- theme / print ---------- */
  var root = document.documentElement;
  try { var saved = localStorage.getItem('wa-theme'); if (saved) root.setAttribute('data-theme', saved); } catch (e) { /* storage unavailable */ }
  document.getElementById('btn-theme').addEventListener('click', function () {
    var dark = root.getAttribute('data-theme') ? root.getAttribute('data-theme') === 'dark' : window.matchMedia('(prefers-color-scheme: dark)').matches;
    root.setAttribute('data-theme', dark ? 'light' : 'dark');
    try { localStorage.setItem('wa-theme', root.getAttribute('data-theme')); } catch (e) { /* storage unavailable */ }
    renderScore(); donut(document.getElementById('donut'));
  });
  document.getElementById('btn-print').addEventListener('click', function () { window.print(); });
})();
</script>
</body>
</html>
'@
#endregion

#region Main

function Get-WAPlan {
    # Ordered list of (function, evidence file name) pairs executed by Invoke-WindowsAssessment.
    [CmdletBinding()]
    param ()
    # Order matters only where a later check reuses cached data (features -> PSv2, hotfixes -> patching, services -> unquoted paths).
    return @(
        @('Get-WAWhoAmI', 'Whoami'), @('Get-WAIpSettings', 'Ipconfig'),
        @('Test-WAProxyConfiguration', 'Internet-Connectivity'), @('Test-WAInternetAccess', 'Internet-Connectivity'),
        @('Get-WANetConnections', 'Netstat'), @('Get-WAGpo', 'GPResult'), @('Get-WASecurityPolicy', 'Security-Policy'),
        @('Get-WAWindowsFeatures', 'Windows-Features'), @('Get-WAHotfixes', 'Hotfixes'), @('Test-WAWindowsUpdate', 'Windows-Updates'),
        @('Get-WAProcesses', 'Process-list'), @('Get-WAServices', 'Services'), @('Test-WAUnquotedServicePath', 'Services'),
        @('Get-WAInstalledSoftware', 'Software'), @('Get-WASharedFolders', 'Shares'), @('Get-WAAccountPolicy', 'AccountPolicy'),
        @('Get-WALocalUsers', 'Local-Users'), @('Test-WANtlmLevel', 'Domain-Authentication'), @('Test-WASmbHardening', 'SMB'),
        @('Test-WARdpSecurity', 'RDP'), @('Test-WACredentialGuard', 'Credential-Guard'), @('Test-WALsaProtection', 'LSA-Protection'),
        @('Test-WAAntiVirus', 'Antivirus'), @('Test-WAFirewall', 'Windows-Firewall'), @('Test-WANameResolution', 'LLMNR_NetBIOS_mDNS'),
        @('Test-WAMitm6', 'IPv6-DHCPv6'), @('Test-WAWDigest', 'WDigest'), @('Test-WANetSessionEnum', 'NetSession'),
        @('Test-WASamEnum', 'SAM-Enumeration'), @('Test-WAPowerShellVersion', 'PowerShell-Versions'), @('Test-WAGpoReprocess', 'GPO-Reprocess'),
        @('Get-WAAuditPolicy', 'Audit-Policy'), @('Test-WACommandLineAudit', 'Audit-Policy'), @('Test-WAPowerShellLogging', 'Audit-Policy'),
        @('Test-WAEventLogSize', 'Audit-Policy'), @('Test-WAInstallElevated', 'Machine-Hardening'), @('Test-WASafeModeNonAdmin', 'Machine-Hardening'),
        @('Test-WAUac', 'Machine-Hardening'), @('Test-WALaps', 'Machine-Hardening'), @('Test-WASimultaneousConnections', 'Internet-Connectivity'),
        @('Test-WAKerberosEncryption', 'Domain-Authentication'), @('Test-WANetworkCredStorage', 'Domain-Authentication'), @('Test-WACredSSP', 'CredSSP'),
        @('Test-WAOfficeHardening', 'Office'), @('Test-WASensitiveInfo', 'Sensitive-Info'), @('Get-WASystemInfo', 'Systeminfo')
    )
}

function Invoke-WindowsAssessment {
    [CmdletBinding()]
    param (
        [switch]$EnableSensitiveInfoSearch,
        [switch]$IncludeSecretValues,
        [string[]]$SensitiveSearchPath,
        [switch]$SkipNetworkTests,
        [switch]$SkipGpoCollection,
        [string]$OutputPath = (Get-Location).Path,
        [switch]$NoZip,
        [switch]$KeepFolder,
        [switch]$Quiet
    )
    $script:WAQuiet = [bool]$Quiet
    $resolved = (Resolve-Path -LiteralPath $OutputPath -ErrorAction Stop).ProviderPath
    try {
        $ctx = New-WAContext -OutputPath $resolved -EnableSensitiveInfoSearch:$EnableSensitiveInfoSearch -IncludeSecretValues:$IncludeSecretValues -SensitiveSearchPath $SensitiveSearchPath -SkipNetworkTests:$SkipNetworkTests -SkipGpoCollection:$SkipGpoCollection
    }
    catch {
        Write-Host ("Failed to create the output folder under {0}: {1}" -f $resolved, $_.Exception.Message) -ForegroundColor Red
        return
    }
    $transcript = $false
    try { Start-Transcript -Path (Join-Path $ctx.RootPath (Get-WAFileName -Name 'Log-ScriptTranscript')) -ErrorAction Stop | Out-Null; $transcript = $true } catch { Write-WALog 'Transcript not available in this host' }

    Write-WAScreen ("Windows Security Assessment v{0} - ATT&CK {1}" -f $script:WAVersion, $script:WAAttackVersion) Green
    Write-WAScreen ("Output folder: {0}" -f $ctx.RootPath) Green
    if (-not $ctx.IsAdmin) { Write-WAScreen 'Not running elevated - several checks will be incomplete. Re-run as administrator for full coverage.' Red }

    Write-WALog ("Script version {0}; host {1}; role {2}; OS {3} ({4}); domain {5}; admin {6}; PowerShell {7}" -f $script:WAVersion, $ctx.Hostname, $ctx.Role, $ctx.OSCaption, $ctx.WinVersion, $ctx.DomainName, $ctx.IsAdmin, $PSVersionTable.PSVersion)
    Add-WAFinding -CheckID 'info_cName' -Status Info -Finding $ctx.Hostname
    Add-WAFinding -CheckID 'info_sVer' -Status Info -Finding $script:WAVersion
    Add-WAFinding -CheckID 'info_wVer' -Status Info -Finding ('{0} ({1})' -f $ctx.OSCaption, $ctx.WinVersion)
    Add-WAFinding -CheckID 'info_computerType' -Status Info -Finding $ctx.Role
    Add-WAFinding -CheckID 'info_dName' -Status Info -Finding $(if ($ctx.PartOfDomain) { $ctx.DomainName } else { 'WORKGROUP' })
    Add-WAFinding -CheckID 'info_psVer' -Status Info -Finding ([string]$PSVersionTable.PSVersion)
    Add-WAFinding -CheckID 'info_isAdmin' -Status Info -Finding ([string]$ctx.IsAdmin)
    if ($ctx.LastBoot) { Add-WAFinding -CheckID 'info_uptime' -Status Info -Finding ([datetime]$ctx.LastBoot).ToString('yyyy-MM-dd HH:mm') }

    $plan = @(Get-WAPlan)
    $i = 0
    foreach ($step in $plan) {
        $i++
        if (-not $script:WAQuiet) { Write-Progress -Activity 'Windows Security Assessment' -Status $step[0] -PercentComplete ([int](100 * $i / $plan.Count)) }
        Invoke-WACheck -Function $step[0] -Name $step[1]
    }
    if (-not $script:WAQuiet) { Write-Progress -Activity 'Windows Security Assessment' -Completed }
    Add-WAManualControls

    $reportPath = $null
    try { $reportPath = Export-WAResults } catch { Write-WALog ('Export failed: ' + $_.Exception.Message); Write-WAScreen ('Export failed: ' + $_.Exception.Message) Red }
    $score = Get-WAScore -Findings @($ctx.Findings)
    Write-WALog ("Finished in {0:N0} s; score {1} ({2}); errors {3}" -f ((Get-Date) - $ctx.StartTime).TotalSeconds, $score.Score, $score.Grade, $ctx.Errors.Count)
    if ($transcript) { try { Stop-Transcript | Out-Null } catch { Write-Verbose 'Stop-Transcript failed' } }

    # Keep a copy of the report next to the archive so it can be opened without unzipping.
    $outsideReport = $null
    if ($reportPath -and (Test-Path -LiteralPath $reportPath)) {
        $outsideReport = Join-Path (Split-Path -Path $ctx.RootPath -Parent) ((Split-Path -Path $ctx.RootPath -Leaf) + '_Report.html')
        Copy-Item -LiteralPath $reportPath -Destination $outsideReport -Force
    }
    $zip = $null
    if (-not $NoZip) {
        $zip = $ctx.RootPath + '.zip'
        try {
            Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop
            if (Test-Path -LiteralPath $zip) { Remove-Item -LiteralPath $zip -Force }
            [System.IO.Compression.ZipFile]::CreateFromDirectory($ctx.RootPath, $zip)
            if (-not $KeepFolder) { Remove-Item -LiteralPath $ctx.RootPath -Recurse -Force -ErrorAction SilentlyContinue }
        }
        catch { Write-WAScreen ('Could not create the ZIP archive: ' + $_.Exception.Message) Red; $zip = $null }
    }

    $c = $score.Counts
    Write-WAScreen '' Green
    Write-WAScreen ("Score: {0}/100 (grade {1})  |  Fail {2}  Warning {3}  Pass {4}  Manual {5}" -f $score.Score, $score.Grade, $c['Fail'], $c['Warning'], $c['Pass'], $c['Manual']) Cyan
    if ($outsideReport) { Write-WAScreen ("HTML report : {0}" -f $outsideReport) Green }
    if ($zip) { Write-WAScreen ("Output ZIP  : {0}" -f $zip) Green } else { Write-WAScreen ("Output     : {0}" -f $ctx.RootPath) Green }
    if ($ctx.Errors.Count -gt 0) { Write-WAScreen ("{0} step(s) reported errors - see the Log file and the report's Run details." -f $ctx.Errors.Count) Yellow }
    Write-WAScreen 'The output contains sensitive configuration data - handle and transfer it as CONFIDENTIAL.' Yellow
}
#endregion

# Entry point: run when executed, not when dot-sourced (the Pester tests dot-source this file).
if ($MyInvocation.InvocationName -ne '.' -and $MyInvocation.Line -notmatch '^\s*\.\s') {
    Invoke-WindowsAssessment @PSBoundParameters
}

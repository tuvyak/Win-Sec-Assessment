# WindowsAssessment.ps1 - v2.0.0

Refactor of v1.37. The script is still a single, read-only, drop-on-host file, but every check now produces a
structured result mapped to **MITRE ATT&CK Enterprise v19.2**, the run ends with a self-contained interactive
HTML report, and the logic is covered by a Pester 5 suite (774 tests) that runs on any OS against a simulated host.

## Quick start

```powershell
# elevated Windows PowerShell 5.1 or PowerShell 7
.\WindowsAssessment.ps1                                   # full run -> <host>_<domain>_<timestamp>.zip + _Report.html
.\WindowsAssessment.ps1 -SkipNetworkTests -NoZip          # no egress probes, keep the folder
.\WindowsAssessment.ps1 -EnableSensitiveInfoSearch        # secrets are masked unless -IncludeSecretValues

Invoke-Pester .\tests -Output Detailed                    # tests (any OS; Pester 5.3+)
Invoke-Pester .\tests -TagFilter Integration              # + live run on the local Windows host
pwsh .\tools\Update-AttackSnapshot.ps1                    # after each ATT&CK release: refresh + drift report
pwsh .\tools\New-SampleReport.ps1 -OutputPath .\sample    # demo report from the simulated host
```

## Breaking changes

| Area | v1.37 | v2.0.0 |
|---|---|---|
| Result file | `Hardening_Checks_BETA_<host>.csv/.json` | `Hardening_Checks_<host>.csv/.json` + `WindowsAssessment_Report_<host>.html` |
| Status values | Strength / Opportunity / Unknown | Pass / Fail / Warning / Manual / Info / NotApplicable / Error. The old value is kept in the `LegacyStatus` column. |
| CSV columns | 8 columns | Same 8 columns (same names) + Scope, Evidence, Remediation, Reference, Coverage, `ATTACK_*` columns |
| Output folder | `<host>_<domain>`, previous run silently deleted | `<host>_<domain>_<yyyyMMdd-HHmmss>`, never deletes existing data |
| PowerShell | Get-WmiObject throughout (fails on PowerShell 7) | CIM with WMI fallback; tested on 5.1 semantics and 7.4 |
| CheckIDs | `domain_CredSSPSavedCred` used twice | NTLM-only default credentials is now `domain_CredSSPDefaultCredNTLM`; `machine_LSA-CG-PS` removed (duplicate of `-wmi`); SMB2/3 is one row `domain_SMBv2-3` |

## Defects fixed (line numbers refer to v1.37)

### Runtime errors (crash, exception or lost output)

| # | Line | Defect | Effect |
|---|---|---|---|
| 1 | 61 | `$ForegroundColor = Yellow` - `Yellow` is executed as a command | Exception whenever no colour was passed |
| 2 | 3289-3291 | `writeToFile -sty` (typo for `-str`) x3 | Parameter-binding errors every run, CredSSP evidence lost |
| 3 | 1863, 2910 | `-str " > text" + $value + "..."` - `+` bound as positional arguments | Parameter-binding error in the "unknown level" branches of NTLM and Kerberos; line 2911 also used an undefined `$temp` |
| 4 | 2284 | `[String]::Parse($Calc)` - method does not exist | Setup log branch threw |
| 5 | 1100 | `(sc.exe qc lanmanworkstation ...).split(...)` | Queried the SMB2/3 client instead of `mrxsmb10`; crashed when the line was missing |
| 6 | 1661 | `CommonSecurityDescriptor` built from a missing value | Exception when `SrvsvcSessionInfo` is absent/unreadable |
| 7 | 1709 | `ConvertFrom-SddlString` | Not available before PowerShell 5.1 |
| 8 | 1733, 1744 | `Start-Job -PSVersion 2.0`; `Get-Job \| Remove-Job -Force` | False "PSv2 installed" on PowerShell 7 (job runs in PS7); deleted all of the user's background jobs |
| 9 | 198, 279, 603 | `Test-ComputerSecureChannel` | Command does not exist in PowerShell 7; unguarded calls threw on domain members |
| 10 | throughout | `Get-WmiObject` | Removed in PowerShell 7 - script unusable there |
| 11 | 3345 | `-str "text"$pwd.Path` | Extra positional argument in the error handler itself |
| 12 | 3353 | `Get-Host` version used as PowerShell version | Wrong in ISE/VS Code hosts (reports the host/extension version) |
| 13 | 3392 | `default:` in `switch` | Parsed as a literal string - unknown product types unhandled |
| 14 | 288 | `gpresult $gpoPath` | Invalid syntax in the TXT fallback |

### Logic errors (wrong result)

| # | Line | Defect | Effect |
|---|---|---|---|
| 15 | 1043 | SMB1 "supported" when the legacy `SMB1` registry value is absent | False positive on every Windows 10 1709+/Server 2019+ host |
| 16 | 1220 | GPO value of `fDenyTSConnections` ignored | Wrong RDP state (the v1 TODO "RDP check writes disabled when it is open") |
| 17 | 1227 | RDP-enabled row written without `-status` | Empty status |
| 18 | 1260, 1279 | `$rdpUsers += $line` without separator; `$null -eq ""` | Member names concatenated; "only administrators" branch unreachable |
| 19 | 1216 | NLA/TLS read only from a WMI class that requires admin | No NLA/TLS result at all when not elevated |
| 20 | 1316-1317 | `Get-Item` on a missing policy key, then `.ValueCount -eq 0` | **False pass**: "RDP timeout configured" when nothing is configured |
| 21 | 834 | Only `RunAsPPL = 1` accepted | LSA protection reported off on Windows 11 22H2+ (`RunAsPPL = 2`) |
| 22 | 1421 | `productState` decoded with string offsets on a variable-length hex string | Wrong AV state when the provider byte is >= 0x10 |
| 23 | 1386 | AV check skipped on all servers | Always "Unknown" on servers |
| 24 | 1487 | `Get-MpPreference` unguarded | The v1 TODO "registry access is not allowed" exception |
| 25 | 1603, 1697 | Text passed as `-comment` instead of `-finding` | Empty Finding for WDigest and SAM "secure by default" rows |
| 26 | 1890 | Registry-policy reprocessing not configured = Strength | Inconsistent with scripts/security (same state = Opportunity) |
| 27 | 1951 | Only HKLM `AlwaysInstallElevated` read | Exploitation requires HKLM **and** HKCU |
| 28 | 1989-2003 | `Get-ItemProperty(...).Property` is always empty and the branch texts are inverted | **False pass**: HKCU module logging always reported "enabled on all modules" |
| 29 | 2215 ff. | "Default is 1 MB", only the policy value read | Wrong default (20 MB since Vista); effective size ignored |
| 30 | 2275 | `$setupLogging.Enable` (property is `Enabled`) | Setup log always "not enabled" |
| 31 | 2410 | `StartType -eq "Disable"` (enum value is `Disabled`) | WPAD service always a finding |
| 32 | 2496 | `NoAutoUpdate -eq 0` treated as "updates disabled" | **Inverted**: compliant hosts flagged, non-compliant passed |
| 33 | 2522-2551 | Status written as the string `"false"` | Invalid status values in the CSV |
| 34 | 2590-2611 | WSUS URL parsed with `Substring`; `[IPAddress]"10"` succeeds | Host names mis-classified as IPs and `ip:port` missed |
| 35 | 2640 | Every unquoted path outside `C:\Windows` flagged; spaces not considered | False positives (no space) and false negatives (spaces under `C:\Windows`) |
| 36 | 2735 | Office found via `Win32_Product` | Triggers MSI self-repair on every product (event 1035), slow, and never lists Click-to-Run / Microsoft 365 Apps - Office checks silently skipped on modern builds |
| 37 | 2757, 2779, 2796, 2814 | DDE results inverted | Hardened settings reported as findings |
| 38 | 2754 | `"16.0" -ge 12.0` string comparison | Version gating unreliable |
| 39 | 3030 | Server list read from `...\AllowSavedCredentials` in the `AllowDefaultCredentials` branch | Wrong evidence |
| 40 | 3033 ff. | Value **names** (1, 2, ...) read instead of data | `*` / `TERMSRV/*` wildcards never detected |
| 41 | 3066 | Duplicate CheckID `domain_CredSSPSavedCred` | Rows overwrite each other downstream |
| 42 | 3152 | `AllowSavedCredentialsWhenNTLMOnly` branch tests `AllowDefCredentialsWhenNTLMOnly` | Wrong result |
| 43 | 3300 | `RestrictedRemoteAdministration = 1` (hardened) = Opportunity | **Inverted** |
| 44 | 964-975 | Port 666 labelled 663 | Wrong evidence |
| 45 | 905 | `Invoke-WebRequest` without `-UseBasicParsing`, through the proxy | Fails on Server Core; could not tell proxy egress from direct egress |
| 46 | 532 | Only the WOW6432Node uninstall key | 64-bit and per-user software missing from the inventory |
| 47 | 554-579 | `try/catch` around non-terminating errors | WMI share-permission fallback never ran |
| 48 | 424, 437, 2139, 2365, 2666 | `(Major -ge 7) -or (Minor -ge 1)` | Windows XP (5.1) treated as 6.1+ |
| 49 | 723 | PowerShell version compared as a string | Accidental correctness only |
| 50 | 3331 | `.Trim("Microsoft")` trims characters, not the word | Fragile folder names |
| 51 | 3338 | Previous output folder deleted without warning | Data loss on re-run |
| 52 | 1360-1370 | Full content of credential files (incl. PFX) copied into the output | The assessment package itself became a credential store - now masked, key files listed only |

### Found while refactoring
* `$finding` local variable collided with the `[string]$Finding` parameter (PowerShell variables are case-insensitive) - would have stringified every result. Caught by the tests.
* PowerShell 7.4: `@()` over a `New-Object`-created `List[object]` throws "Argument types do not match" - lists are now created by cast.
* .NET ACL types throw `PlatformNotSupportedException` off-Windows - replaced by a small portable security-descriptor/SDDL parser (also more robust against malformed registry data).

## New controls (v1 TODOs and gaps)
UAC (EnableLUA, admin prompt, LocalAccountTokenFilterPolicy) - Windows/legacy LAPS - Defender real-time and tamper protection -
ASR LSASS and Office rules - Windows Firewall profile state - NetBIOS over TCP/IP per adapter - mDNS - IPv6/DHCPv6 (mitm6) -
patch recency - Office VBA macro policy and internet-macro blocking - NetSessionEnum and SAM now evaluated (v1: evidence only) -
DisableWpad - effective event-log sizes.

## MITRE ATT&CK mapping methodology
* Each control lists the **techniques it prevents or gives visibility into** and the **ATT&CK mitigations it implements**.
* Validation (automated in the tests and in `tools/Update-AttackSnapshot.ps1`) against the official STIX bundle, Enterprise ATT&CK **v19.2 (2026-08-05)**:
  every technique exists, is not revoked/deprecated, applies to Windows, and has the official name and tactics; every mitigation exists; and
  **every mitigation is linked by ATT&CK to at least one of the control's techniques** (`mitigates` relationship).
* ATT&CK v19 split Defense Evasion into **Stealth (TA0005)** and **Defense Impairment (TA0112)** and revoked T1562.x / T1070.001
  (e.g. T1562.001 -> T1685, T1562.010 -> T1689, T1070.001 -> T1685.005). Mappings written from older references would fail these tests.
* Detective controls (logging) are marked `Coverage = Detect`; ATT&CK has no preventive mitigation for them, so none is claimed.

## Known limitations
* The Pester suite simulates the host (registry, CIM, cmdlets, native tools). The `Integration` test runs the real script on a Windows host;
  run it on a representative workstation, member server and DC before production use.
* Office, AlwaysInstallElevated (HKCU) and proxy user settings are per-user and are evaluated for the account running the script.
* `auditpol` status text is matched in English (`Success`/`No Auditing`); on localized OS builds the check reports Manual rather than guessing.

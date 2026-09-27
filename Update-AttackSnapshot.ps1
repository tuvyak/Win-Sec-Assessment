#Requires -Version 7.0
<#
.SYNOPSIS
    Refreshes tests/attack-enterprise-snapshot.json from the official MITRE ATT&CK STIX bundle and reports
    catalog drift (revoked/deprecated/renamed techniques, broken mitigation links) in WindowsAssessment.ps1.

.DESCRIPTION
    ATT&CK changes twice a year (e.g. v19 split Defense Evasion into Stealth + Defense Impairment and revoked
    T1562.x / T1070.001). Run this after each ATT&CK release, then run the Pester suite:
        pwsh ./tools/Update-AttackSnapshot.ps1
        Invoke-Pester ./tests
    If drift is reported, update the technique/mitigation IDs in the catalog region of WindowsAssessment.ps1
    (names and tactics come from the report below).

.PARAMETER BundlePath
    Use a local enterprise-attack.json instead of downloading it.
.PARAMETER Url
    Source of the STIX 2.1 bundle (default: mitre-attack/attack-stix-data on GitHub).
#>
[CmdletBinding()]
param (
    [string]$BundlePath,
    [string]$Url = 'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json',
    [string]$SnapshotPath = (Join-Path (Split-Path $PSScriptRoot -Parent) 'tests/attack-enterprise-snapshot.json'),
    [string]$ScriptPath = (Join-Path (Split-Path $PSScriptRoot -Parent) 'WindowsAssessment.ps1')
)
$ErrorActionPreference = 'Stop'

if (-not $BundlePath) {
    $BundlePath = Join-Path ([IO.Path]::GetTempPath()) 'enterprise-attack.json'
    Write-Host "Downloading $Url ..."
    Invoke-WebRequest -Uri $Url -OutFile $BundlePath -UseBasicParsing
}
Write-Host "Parsing $BundlePath ..."
$bundle = Get-Content -LiteralPath $BundlePath -Raw | ConvertFrom-Json -Depth 100
$objs = $bundle.objects
$byId = @{}; foreach ($o in $objs) { $byId[$o.id] = $o }
function Get-ExtId ($o) { ($o.external_references | Where-Object source_name -eq 'mitre-attack' | Select-Object -First 1).external_id }

$collection = $objs | Where-Object type -eq 'x-mitre-collection' | Select-Object -First 1
$matrix = $objs | Where-Object type -eq 'x-mitre-matrix' | Select-Object -First 1
$tactics = @($matrix.tactic_refs | ForEach-Object { $t = $byId[$_]; [ordered]@{ id = (Get-ExtId $t); shortname = $t.x_mitre_shortname; name = $t.name } })

$revokedBy = @{}
foreach ($r in ($objs | Where-Object { $_.type -eq 'relationship' -and $_.relationship_type -eq 'revoked-by' })) {
    $revokedBy[(Get-ExtId $byId[$r.source_ref])] = Get-ExtId $byId[$r.target_ref]
}
$techniques = [ordered]@{}
foreach ($o in ($objs | Where-Object type -eq 'attack-pattern')) {
    $id = Get-ExtId $o; if (-not $id) { continue }
    $t = [ordered]@{
        name = $o.name; tactics = @($o.kill_chain_phases | Where-Object kill_chain_name -eq 'mitre-attack' | ForEach-Object phase_name)
        revoked = [bool]$o.revoked; deprecated = [bool]$o.x_mitre_deprecated; platforms = @($o.x_mitre_platforms)
    }
    if ($revokedBy.ContainsKey($id)) { $t.revokedBy = $revokedBy[$id] }
    $techniques[$id] = $t
}
$mitigations = [ordered]@{}
foreach ($o in ($objs | Where-Object type -eq 'course-of-action')) {
    $id = Get-ExtId $o
    if ($id -and $id.StartsWith('M')) { $mitigations[$id] = [ordered]@{ name = $o.name; revoked = [bool]$o.revoked; deprecated = [bool]$o.x_mitre_deprecated } }
}
$pairs = [System.Collections.Generic.SortedSet[string]]::new()
foreach ($r in ($objs | Where-Object { $_.type -eq 'relationship' -and $_.relationship_type -eq 'mitigates' -and -not $_.revoked -and -not $_.x_mitre_deprecated })) {
    $s = $byId[$r.source_ref]; $t = $byId[$r.target_ref]
    if ($s.type -eq 'course-of-action' -and $t.type -eq 'attack-pattern') { [void]$pairs.Add(('{0}|{1}' -f (Get-ExtId $s), (Get-ExtId $t))) }
}
$snapshot = [ordered]@{
    source = 'https://github.com/mitre-attack/attack-stix-data (enterprise-attack.json)'; collection = $collection.name
    version = $collection.x_mitre_version; modified = $collection.modified; tactics = $tactics
    techniques = $techniques; mitigations = $mitigations; mitigates = @($pairs)
}
$snapshot | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $SnapshotPath -Encoding utf8NoBOM
Write-Host ("Snapshot written: {0} v{1} - {2} techniques, {3} mitigations, {4} mitigation links" -f $collection.name, $collection.x_mitre_version, $techniques.Count, $mitigations.Count, $pairs.Count) -ForegroundColor Green

# ---- drift report against the script catalog
. $ScriptPath
$drift = 0
if ($script:WAAttackVersion -ne ('{0} v{1}' -f $collection.name, $collection.x_mitre_version)) {
    Write-Host ("Script catalog was generated from {0}; latest is v{1}." -f $script:WAAttackVersion, $collection.x_mitre_version) -ForegroundColor Yellow
}
foreach ($tid in $script:WATechniques.Keys) {
    $t = $techniques[$tid]
    if (-not $t) { Write-Host "  $tid : not found in ATT&CK" -ForegroundColor Red; $drift++; continue }
    if ($t.revoked -or $t.deprecated) { Write-Host ("  {0} : revoked/deprecated{1}" -f $tid, $(if ($t.revokedBy) { " -> replace with $($t.revokedBy) ($($techniques[$t.revokedBy].name))" })) -ForegroundColor Red; $drift++ }
    elseif ($t.name -cne $script:WATechniques[$tid].Name) { Write-Host ("  {0} : renamed '{1}' -> '{2}'" -f $tid, $script:WATechniques[$tid].Name, $t.name) -ForegroundColor Yellow; $drift++ }
    elseif ((@($t.tactics) -join ',') -ne (@($script:WATechniques[$tid].Tactics) -join ',')) { Write-Host ("  {0} : tactics changed to {1}" -f $tid, (@($t.tactics) -join ',')) -ForegroundColor Yellow; $drift++ }
}
foreach ($id in $script:WACheckCatalog.Keys) {
    $m = $script:WACheckCatalog[$id]
    foreach ($mid in $m.Mitigations) {
        if (-not (@($m.Techniques) | Where-Object { $pairs.Contains("$mid|$_") })) { Write-Host "  $id : $mid no longer mitigates any of $($m.Techniques -join ', ')" -ForegroundColor Red; $drift++ }
    }
}
if ($drift -eq 0) { Write-Host 'No drift: every technique and mitigation in the catalog is current.' -ForegroundColor Green }
else { Write-Host "$drift drift item(s) - update the catalog region of WindowsAssessment.ps1, then run Invoke-Pester ./tests." -ForegroundColor Red }

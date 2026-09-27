<#
.SYNOPSIS
    Builds a sample HTML report from the simulated workstation in tests/SimulatedHost.ps1 (no real host data).
    Useful for demos, report-template changes and reviewing the ATT&CK visualisation.
.EXAMPLE
    pwsh ./tools/New-SampleReport.ps1 -OutputPath ./sample
#>
[CmdletBinding()]
param ([string]$OutputPath = (Get-Location).Path)
$root = Split-Path -Path $PSScriptRoot -Parent
$null = New-Item -ItemType Directory -Path $OutputPath -Force
$target = (Resolve-Path -LiteralPath $OutputPath).ProviderPath   # capture first: dot-sourcing the script re-binds its own $OutputPath
. (Join-Path $root 'WindowsAssessment.ps1')
. (Join-Path $root 'tests/SimulatedHost.ps1')
Use-WASimulatedHost -Simulation (New-WASimulatedHost)
$script:WAQuiet = $true
$ctx = New-WAContext -OutputPath $target -NoDiscovery -Hostname 'FIN-WS-0142' -ProductType 1 -WinVersion '10.0.22631' `
    -IsAdmin $true -PartOfDomain $true -DomainName 'corp.contoso.com' -OSCaption 'Microsoft Windows 11 Enterprise'
$ctx.User = 'CORP\adm-assessor'
$ctx.LastBoot = (Get-Date).AddDays(-3)
foreach ($step in (Get-WAPlan)) { Invoke-WACheck -Function $step[0] -Name $step[1] }
Add-WAManualControls
$report = Export-WAResults
$dest = Join-Path $target 'WindowsAssessment_SampleReport.html'
Copy-Item -LiteralPath $report -Destination $dest -Force
Remove-Item -LiteralPath $ctx.RootPath -Recurse -Force
Write-Host "Sample report: $dest"

@{
    # Interactive assessment tool: Write-Host is intentional (coloured console progress).
    # Plural nouns (Get-WAServices, Get-WAHotfixes) are kept for readability; New-WA* helpers only write to the run's own output folder.
    Severity     = @('Error', 'Warning')
    ExcludeRules = @('PSAvoidUsingWriteHost', 'PSUseSingularNouns', 'PSUseShouldProcessForStateChangingFunctions')
}

@{
    Severity     = @('Error', 'Warning')
    ExcludeRules = @(
        'PSAvoidUsingWriteHost',          # the scripts are CLI tools; Write-Host is the intended output channel
        'PSUseShouldProcessForStateChangingFunctions',
        'PSAvoidUsingPlainTextForPassword', # rasdial takes the password as an argument; documented trade-off
        'PSAvoidGlobalVars',               # the tray app keeps its state global: WinForms event handlers run outside the function scope
        'PSUseSingularNouns'               # Show-Settings, Get-LastEvents read better than the singular
    )
}

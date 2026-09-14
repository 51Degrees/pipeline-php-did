param (
    [Parameter(Mandatory = $true)]
    [string]$LanguageVersion
)

# Confirms the runner really has the PHP version the build options asked for,
# so a silently wrong runtime shows up here rather than as a confusing test
# failure later.
./php/setup-environment.ps1 -LanguageVersion $LanguageVersion

exit $LASTEXITCODE

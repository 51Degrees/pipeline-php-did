param (
    [Parameter(Mandatory = $true)]
    [string]$RepoName
)
$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $true

# The package's own PHPUnit is used rather than the one the runtime action
# installs globally, because composer.json takes the current major version
# whilst the global tool is pinned to 9.6, and the tests are written for the
# version composer resolves.
#
# The suite names come from phpunit.xml, where Unit holds the tests that need
# nothing outside the process and Live holds the ones that call the cloud.
# Live runs from run-integration-tests.ps1 instead, so a missing resource key
# cannot fail the unit stage.
Push-Location $RepoName
try {
    php vendor/bin/phpunit `
        --testsuite Unit `
        --log-junit test-results/unit/$RepoName/tests.xml
} finally {
    Pop-Location
}

exit $LASTEXITCODE

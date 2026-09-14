param (
    [Parameter(Mandatory = $true)]
    [string]$RepoName,
    [Parameter(Mandatory = $true)]
    [hashtable]$Keys
)
$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $true

# The Live suite calls the running cloud service, so it needs a resource key.
# Without one the test skips itself and reports nothing, which would leave a
# green stage proving nothing at all, so say so plainly instead.
if (!$Keys.TestResourceKey) {
    Write-Output "::warning file=$($MyInvocation.ScriptName),line=$($MyInvocation.ScriptLineNumber),title=No Resource Key::No resource key was provided, so the live cloud tests did not run."
    return
}

$env:_51DEGREES_RESOURCE_KEY = $Keys.TestResourceKey
if ($Keys.TestLicenseKey) {
    $env:_51DEGREES_LICENSE_KEY = $Keys.TestLicenseKey
}

Push-Location $RepoName
try {
    php vendor/bin/phpunit `
        --testsuite Live `
        --log-junit test-results/integration/$RepoName/tests.xml
} finally {
    Pop-Location
}

exit $LASTEXITCODE

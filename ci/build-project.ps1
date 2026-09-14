param (
    [Parameter(Mandatory = $true)]
    [string]$RepoName
)

# composer install. The OWID library is a git submodule consumed through a
# Composer path repository, and common-ci clones with --recurse-submodules,
# so the source is already in place by the time this runs.
./php/build-project.ps1 -RepoName $RepoName

exit $LASTEXITCODE

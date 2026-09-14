param (
    [Parameter(Mandatory = $true)]
    [string]$RepoName
)

# The Live suite is not run here, and this is deliberate.
#
# Live calls the running cloud service for a probabilistic 51Did, which is a
# paid feature, so it needs a licence key as well as a resource key entitled
# to it. The secrets a called workflow may receive are a fixed list, and the
# _51DEGREES_RESOURCE_KEY* secrets the live test reads are not on it, so a key
# passed from here is a free one and every Live test fails with
# "IdProbGlobal is a paid feature" rather than with anything real.
#
# cloud-51did.yml already runs that suite properly, looping over every
# resource key secret the organisation holds, on each pull request and, since
# https://github.com/51Degrees/pipeline-php-did/pull/19, nightly as well. So
# the live cover is there and running it a second time here with the wrong
# key would only produce a failure that means nothing.
Write-Output "The live cloud tests run in cloud-51did.yml, which has the resource key secrets this workflow cannot receive"

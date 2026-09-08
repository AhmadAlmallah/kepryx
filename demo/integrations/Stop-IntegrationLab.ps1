[CmdletBinding()]
param(
    [switch]$RemoveContainers
)

$ErrorActionPreference = "Stop"
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\.." )).Path
$envPath = Join-Path $PSScriptRoot ".env"
if (-not (Test-Path -LiteralPath $envPath -PathType Leaf)) {
    throw "Integration lab environment was not initialized: $envPath"
}

$baseArgs = @(
    "-p", "kepryx",
    "--env-file", (Join-Path $repoRoot ".env"),
    "--env-file", $envPath,
    "-f", (Join-Path $repoRoot "docker-compose.yml"),
    "-f", (Join-Path $repoRoot "docker-compose.demo.yml"),
    "-f", (Join-Path $repoRoot "docker-compose.integrations.yml"),
    "--profile", "demo",
    "--profile", "endpoint",
    "--profile", "network"
)

if ($RemoveContainers) {
    Write-Host "Stopping and removing the kepryx integration containers and network; volumes are preserved..."
    docker compose @baseArgs down --remove-orphans
} else {
    Write-Host "Stopping the kepryx integration lab; provider volumes are preserved..."
    docker compose @baseArgs stop
}
if ($LASTEXITCODE -ne 0) {
    throw "Unable to stop the kepryx integration lab."
}

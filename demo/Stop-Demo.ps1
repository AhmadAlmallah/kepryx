[CmdletBinding()]
param(
    [switch]$RemoveContainers
)

$ErrorActionPreference = "Stop"
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot ".." )).Path
$baseArgs = @(
    "-p", "kepryx-demo",
    "-f", (Join-Path $repoRoot "docker-compose.yml"),
    "-f", (Join-Path $repoRoot "docker-compose.demo.yml"),
    "--profile", "demo"
)

if ($RemoveContainers) {
    Write-Host "Stopping and removing only the kepryx-demo containers and network; volumes are preserved..."
    docker compose @baseArgs down --remove-orphans
} else {
    Write-Host "Stopping the kepryx-demo containers; data volumes are preserved..."
    docker compose @baseArgs stop
}
if ($LASTEXITCODE -ne 0) {
    throw "Unable to stop the kepryx-demo project."
}

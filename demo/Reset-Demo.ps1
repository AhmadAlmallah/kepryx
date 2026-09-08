[CmdletBinding()]
param(
    [switch]$ConfirmReset
)

$ErrorActionPreference = "Stop"
if (-not $ConfirmReset) {
    throw "This removes only the kepryx-demo containers and project volumes. Re-run with -ConfirmReset if that is intended."
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot ".." )).Path
$composeArgs = @(
    "-p", "kepryx-demo",
    "-f", (Join-Path $repoRoot "docker-compose.yml"),
    "-f", (Join-Path $repoRoot "docker-compose.demo.yml"),
    "--profile", "demo",
    "down", "--volumes", "--remove-orphans"
)
docker compose @composeArgs
if ($LASTEXITCODE -ne 0) {
    throw "Demo reset failed."
}
Write-Host "Removed the kepryx-demo containers, networks, and project-scoped volumes."

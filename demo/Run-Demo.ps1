[CmdletBinding()]
param(
    [switch]$NoBuild
)

$ErrorActionPreference = "Stop"
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot ".." )).Path
$integrationEnv = Join-Path $repoRoot "demo\integrations\.env"
$integrationServices = @(
    docker compose -p kepryx --env-file (Join-Path $repoRoot ".env") --env-file $integrationEnv `
        -f (Join-Path $repoRoot "docker-compose.yml") `
        -f (Join-Path $repoRoot "docker-compose.demo.yml") `
        -f (Join-Path $repoRoot "docker-compose.integrations.yml") `
        --profile demo --profile endpoint --profile network ps --status running --services 2>$null
)
if ($LASTEXITCODE -eq 0 -and $integrationServices -contains "api" -and $integrationServices -contains "caddy") {
    throw "The kepryx integration lab is already running on the demo ports. Run demo/integrations/Stop-IntegrationLab.ps1 first."
}
$composeArgs = @(
    "-p", "kepryx-demo",
    "-f", (Join-Path $repoRoot "docker-compose.yml"),
    "-f", (Join-Path $repoRoot "docker-compose.demo.yml"),
    "--profile", "demo",
    "up", "-d"
)
if (-not $NoBuild) {
    $composeArgs += "--build"
}

Write-Host "Starting the bounded Kepryx demo profile..."
docker compose @composeArgs
if ($LASTEXITCODE -ne 0) {
    throw "Demo stack failed to start. Inspect: docker compose -p kepryx-demo -f docker-compose.yml -f docker-compose.demo.yml --profile demo ps"
}

& (Join-Path $PSScriptRoot "Preflight-Demo.ps1")

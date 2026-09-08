[CmdletBinding()]
param(
    [string]$BaseUrl = "https://kepryx.local:8444"
)

$ErrorActionPreference = "Stop"
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot ".." )).Path
$fixturePath = Join-Path $PSScriptRoot "data\assets-full.csv"
$composeArgs = @(
    "-p", "kepryx-demo",
    "-f", (Join-Path $repoRoot "docker-compose.yml"),
    "-f", (Join-Path $repoRoot "docker-compose.demo.yml"),
    "--profile", "demo"
)

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    throw "Docker CLI was not found. Install Docker Desktop or use the prepared Linux host."
}

docker info --format "{{.ServerVersion}}" *> $null
if ($LASTEXITCODE -ne 0) {
    throw "Docker engine is not running. Start Docker Desktop, then run this preflight again."
}

if (-not (Test-Path -LiteralPath $fixturePath -PathType Leaf)) {
    throw "Full demo fixture not found: $fixturePath"
}

$rows = @(Import-Csv -LiteralPath $fixturePath)
$shadowRows = @($rows | Where-Object {
        $_.edr_status -eq "None" -or $_.control_coverage -eq "none"
    })
if ($rows.Count -ne 37 -or $shadowRows.Count -ne 5) {
    throw "Unexpected fixture shape: expected 37 rows and 5 shadow candidates; found $($rows.Count) and $($shadowRows.Count)."
}

docker compose @composeArgs config --quiet *> $null
if ($LASTEXITCODE -ne 0) {
    throw "Docker Compose configuration validation failed."
}

$integrationArgs = @(
    "-p", "kepryx",
    "--env-file", (Join-Path $repoRoot ".env"),
    "--env-file", (Join-Path $repoRoot "demo\integrations\.env"),
    "-f", (Join-Path $repoRoot "docker-compose.yml"),
    "-f", (Join-Path $repoRoot "docker-compose.demo.yml"),
    "-f", (Join-Path $repoRoot "docker-compose.integrations.yml"),
    "--profile", "demo",
    "--profile", "endpoint",
    "--profile", "network"
)
$integrationServices = @(docker compose @integrationArgs ps --status running --services 2>$null)
if ($LASTEXITCODE -eq 0 -and $integrationServices -contains "api" -and $integrationServices -contains "caddy") {
    throw "The kepryx integration lab is already running on the demo ports. Run demo/integrations/Stop-IntegrationLab.ps1 before starting kepryx-demo."
}

$runningServices = @(docker compose @composeArgs ps --status running --services)
if ($LASTEXITCODE -ne 0 -or $runningServices -notcontains "api" -or $runningServices -notcontains "caddy") {
    throw "The kepryx-demo project is not running its API and Caddy services. Run demo/Run-Demo.ps1 first, then rerun this preflight."
}

$base = $BaseUrl.TrimEnd("/")
$health = $null
foreach ($path in @("/health", "/ready")) {
    try {
        $response = Invoke-WebRequest -Uri "$base$path" -Method Get -SkipCertificateCheck -UseBasicParsing
        if ([int]$response.StatusCode -ne 200) {
            throw "HTTP $($response.StatusCode)"
        }
        $health = "ok"
    }
    catch {
        $health = "unavailable"
        Write-Warning "${path} is not ready yet: $($_.Exception.Message)"
    }
}

Write-Host "Kepryx local demo preflight"
Write-Host "Compose project: kepryx-demo"
Write-Host "Fixture: 37 synthetic assets; 5 CSV shadow candidates"
Write-Host "Scan boundary: 198.51.100.240/28 (isolated Docker network)"
Write-Host "Feed mode: local vulnerability snapshot; no live feed required"
Write-Host "API: $health"
Write-Host ""
docker compose @composeArgs --profile demo ps

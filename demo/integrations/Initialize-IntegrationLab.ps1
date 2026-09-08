param(
    [ValidateSet("endpoint", "network")]
    [string]$Provider = "endpoint",
    [switch]$Start,
    [switch]$SeedNetwork
)

$ErrorActionPreference = "Stop"
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..\")).Path
$envPath = Join-Path $PSScriptRoot ".env"

function New-RandomString([int]$Bytes = 32) {
    $buffer = New-Object byte[] $Bytes
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($buffer) } finally { $rng.Dispose() }
    return [Convert]::ToBase64String($buffer).Replace("+", "-").Replace("/", "_").TrimEnd("=")
}

if (-not (Test-Path $envPath)) {
    @(
        "FLEET_MYSQL_ROOT_PASSWORD=$(New-RandomString 24)"
        "FLEET_MYSQL_PASSWORD=$(New-RandomString 24)"
        "FLEET_SERVER_PRIVATE_KEY=$(New-RandomString 32)"
        "FLEET_IMAGE=fleetdm/fleet:v4.90.0"
        "NETBOX_DB_PASSWORD=$(New-RandomString 24)"
        "NETBOX_REDIS_PASSWORD=$(New-RandomString 24)"
        "NETBOX_REDIS_CACHE_PASSWORD=$(New-RandomString 24)"
        "NETBOX_SECRET_KEY=$(New-RandomString 48)"
        "NETBOX_API_TOKEN_PEPPER=$(New-RandomString 48)"
        "NETBOX_SUPERUSER_API_KEY=demo"
        "NETBOX_SUPERUSER_API_TOKEN=$(New-RandomString 30)"
        "NETBOX_SUPERUSER_PASSWORD=$(New-RandomString 24)"
        "NETBOX_IMAGE=docker.io/netboxcommunity/netbox:v4.6.9-5.0.2"
    ) | Set-Content -Path $envPath -Encoding ascii
    Write-Host "Created ignored local integration secrets at $envPath"
}

docker info *> $null
if ($LASTEXITCODE -ne 0) {
    throw "Docker Desktop is not running. Start Docker Desktop, then rerun this script."
}

$compose = @(
    "compose", "-p", "kepryx", "--env-file", (Join-Path $repoRoot ".env"),
    "--env-file", $envPath, "-f", (Join-Path $repoRoot "docker-compose.yml"),
    "-f", (Join-Path $repoRoot "docker-compose.demo.yml"),
    "-f", (Join-Path $repoRoot "docker-compose.integrations.yml"),
    "--profile", "demo", "--profile", $Provider
)

if ($Start) {
    & docker @compose up -d
    if ($LASTEXITCODE -ne 0) { throw "Docker Compose failed to start the $Provider integration profile." }
    Write-Host "Started $Provider integration profile. Provider UI/API is local-only."
}

if ($SeedNetwork) {
    if ($Provider -ne "network") { throw "-SeedNetwork requires -Provider network." }
    & pwsh -NoProfile -File (Join-Path $PSScriptRoot "Seed-NetBox.ps1") -EnvFile $envPath
}

Write-Host "Next: create the provider API token/configuration, register the matching Kepryx integration, then run Test and Run from Integrations."

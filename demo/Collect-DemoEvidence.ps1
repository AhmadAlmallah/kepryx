[CmdletBinding()]
param(
    [string]$BaseUrl = "https://kepryx.local:8444",
    [string]$OutputPath = (Join-Path $PSScriptRoot "evidence-manifest.local.json")
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

function Get-CommitSha {
    $sha = git -C $repoRoot rev-parse HEAD 2>$null
    if ($LASTEXITCODE -ne 0) { return $null }
    return ($sha | Select-Object -First 1).Trim()
}

function Get-EndpointEvidence([string]$Path) {
    $started = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $response = Invoke-WebRequest -Uri "$($BaseUrl.TrimEnd('/'))$Path" -Method Get -SkipCertificateCheck -UseBasicParsing
        $started.Stop()
        return [ordered]@{
            status = [int]$response.StatusCode
            duration_ms = [Math]::Round($started.Elapsed.TotalMilliseconds, 2)
        }
    } catch {
        $started.Stop()
        return [ordered]@{
            status = 0
            duration_ms = [Math]::Round($started.Elapsed.TotalMilliseconds, 2)
            error_code = $_.Exception.GetType().Name
        }
    }
}

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    throw "Docker CLI was not found."
}
docker info --format "{{.ServerVersion}}" *> $null
if ($LASTEXITCODE -ne 0) {
    throw "Docker engine is not running."
}

$rows = @(Import-Csv -LiteralPath $fixturePath)
$shadowRows = @($rows | Where-Object { $_.edr_status -eq "None" -or $_.control_coverage -eq "none" })
$configExit = 0
docker compose @composeArgs config --quiet *> $null
if ($LASTEXITCODE -ne 0) { $configExit = $LASTEXITCODE }

$runningServices = @(docker compose @composeArgs ps --status running --services 2>$null)
$projectRunning = $LASTEXITCODE -eq 0 -and $runningServices -contains "api" -and $runningServices -contains "caddy"
$serviceObjects = @()
$serviceLines = @(docker compose @composeArgs ps --format json 2>$null)
foreach ($line in $serviceLines) {
    try { $serviceObjects += ($line | ConvertFrom-Json) } catch { }
}

$manifest = [ordered]@{
    schema_version = 1
    generated_at_utc = (Get-Date).ToUniversalTime().ToString("o")
    repository = [ordered]@{
        commit = Get-CommitSha
        worktree_dirty = [bool](@(git -C $repoRoot status --porcelain 2>$null).Count)
    }
    demo = [ordered]@{
        profile = "kepryx-demo"
        base_url = $BaseUrl
        compose_config_exit_code = $configExit
        fixture = [ordered]@{
            path = "demo/data/assets-full.csv"
            rows = $rows.Count
            shadow_candidates = $shadowRows.Count
            data_classification = "synthetic/reserved documentation data"
        }
        project_running = $projectRunning
        endpoints = if ($projectRunning) {
            [ordered]@{
                health = Get-EndpointEvidence "/health"
                ready = Get-EndpointEvidence "/ready"
            }
        } else {
            [ordered]@{
                health = [ordered]@{ status = 0; error_code = "demo_project_not_running" }
                ready = [ordered]@{ status = 0; error_code = "demo_project_not_running" }
            }
        }
        services = @($serviceObjects | Select-Object Name, Service, State, Health, Image)
    }
    boundaries = @(
        "Synthetic fixture and local response-shape data only",
        "No provider credentials or secret values are included",
        "Health/readiness timings describe one local machine, not a capacity promise"
    )
}

$parent = Split-Path -Parent $OutputPath
if ($parent -and -not (Test-Path -LiteralPath $parent)) {
    New-Item -ItemType Directory -Path $parent -Force | Out-Null
}
$manifest | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $OutputPath -Encoding utf8
Write-Host "Demo evidence manifest written to $OutputPath"

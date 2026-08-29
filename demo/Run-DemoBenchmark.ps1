[CmdletBinding()]
param(
    [string]$BaseUrl = "https://kepryx.local:8443",
    [ValidateRange(1, 20)]
    [int]$Iterations = 5
)

$ErrorActionPreference = "Stop"
$base = $BaseUrl.TrimEnd("/")
$fixturePath = Join-Path $PSScriptRoot "data\asset_inventory.csv"

if (-not (Test-Path -LiteralPath $fixturePath -PathType Leaf)) {
    throw "Demo fixture not found: $fixturePath"
}

function Measure-Endpoint {
    param([string]$Path)

    $samples = @()
    $status = $null
    for ($attempt = 1; $attempt -le $Iterations; $attempt++) {
        $watch = [System.Diagnostics.Stopwatch]::StartNew()
        try {
            $response = Invoke-WebRequest -Uri "$base$Path" -Method Get -SkipCertificateCheck -UseBasicParsing
            $status = [int]$response.StatusCode
        }
        catch {
            $status = if ($_.Exception.Response) { [int]$_.Exception.Response.StatusCode } else { 0 }
        }
        finally {
            $watch.Stop()
        }
        $samples += [math]::Round($watch.Elapsed.TotalMilliseconds, 2)
    }

    $ordered = @($samples | Sort-Object)
    $median = $ordered[[math]::Floor(($ordered.Count - 1) / 2)]
    [pscustomobject]@{
        Endpoint = $Path
        Status = $status
        Iterations = $Iterations
        MedianMs = $median
        MaxMs = ($ordered | Measure-Object -Maximum).Maximum
    }
}

$fixtureRows = @(Import-Csv -LiteralPath $fixturePath).Count
$results = @(
    (Measure-Endpoint -Path "/health")
    (Measure-Endpoint -Path "/ready")
)

Write-Host "Kepryx demo benchmark (smoke observation; not a capacity test)"
Write-Host "Timestamp: $([DateTime]::UtcNow.ToString('o'))"
Write-Host "Base URL: $base"
Write-Host "Fixture rows: $fixtureRows"
$results | Format-Table -AutoSize

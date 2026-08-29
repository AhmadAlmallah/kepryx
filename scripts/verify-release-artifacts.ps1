[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$SbomDirectory,
    [Parameter(Mandatory = $true)]
    [string]$TrivyDirectory
)

$ErrorActionPreference = "Stop"

# The values below are public SHA-256 artifact identifiers, not credentials. Each digest is
# intentionally allowlisted for detect-secrets so a future change to the manifest still gets
# reviewed as a normal code diff.

$expectedSbom = @{
    "api.cdx.json" = "3B8076DF816AA42FB2A430D3BE5A938699A70C6BF7428B8E9EC67A5DD49A906C" # pragma: allowlist secret
    "asset-source-mock.cdx.json" = "254D89DF225EB3F184877DB0072B2452F502F6AF464838CDDE2B8354C1F86FDF" # pragma: allowlist secret
    "beat.cdx.json" = "BFD3E955833D1BC93015C27B840AE3BDDAFCF9051ABB1158412BEDC08CBD1105" # pragma: allowlist secret
    "caddy.cdx.json" = "0F1B5EE4A70E4E1D6A199ECDBD0FA28560E8E33BC59D7D53B2CBB5811A86357F" # pragma: allowlist secret
    "postgres.cdx.json" = "A58D7DBA3087B65F3DD06DF3DC306D5ED6FDEC5AB13BCAF781CB99865CDA7DDB" # pragma: allowlist secret
    "worker-enrich.cdx.json" = "8CEB113ECA7D08DAA7C1B7B27630746A4446A6FBD243738F7C725A89ACCF3DB3" # pragma: allowlist secret
    "worker-recon.cdx.json" = "5F700932F627EB16441C8D38009F7C79ECBFEFBA1C08E45B4D8F90F630F985C0" # pragma: allowlist secret
    "worker-scanner-final.cdx.json" = "E4AF1130B9C0C39584FA1574B678D402FD79C78A3C8790FCF2945E088F81A92A" # pragma: allowlist secret
    "worker-selfsec.cdx.json" = "C3CBDD4AC3F5E4C7E35C3FB76308E56DA45E8D9AE09D5172F93056E262F7225A" # pragma: allowlist secret
}

$expectedTrivy = @{
    "api.json" = "1B881ED1FD1F94D3CB722D45B1E96903E6E2BC5FBA7E3EABA0A26C25EB1AEB16" # pragma: allowlist secret
    "asset-source-mock.json" = "86A40CB97F172AFFCF67D792F2882B30909C0DB039FC9B6BBD56D8C534258307" # pragma: allowlist secret
    "beat.json" = "4E32963E649281FF47BAB82DAA9452CDC8ACE6465FD0207B3ACE5B6D5944ABE4" # pragma: allowlist secret
    "caddy.json" = "8988DDC6A1AD061A52B513DD3FAF49127C3BC9BDD9E6B395B9EDBDEF27DE2696" # pragma: allowlist secret
    "postgres.json" = "5C9897DBF4D593187CAE738A329B3DD6FECA1BAE09D34FFB0AE43FFD2D7C44AE" # pragma: allowlist secret
    "worker-enrich.json" = "8A91F86AB2E45D1782BE1CDA95E319473D04EA535493D4A8D1BA722E9F71BEF3" # pragma: allowlist secret
    "worker-recon.json" = "7BC8034C9725AE8BC6AC95648F93C71B3D3BA323F9AFF5F916F1E498058A965F" # pragma: allowlist secret
    "worker-scanner.json" = "4A22A9567646042C8E712538A735565A8D91966E8B73B1578AFD921323CD741A" # pragma: allowlist secret
    "worker-selfsec.json" = "1B9D1B22E7FEB837247A440AADBADA76EAA00C7706BB771416BF55CCCCFD3C92" # pragma: allowlist secret
}

function Test-Manifest($directory, $expected, $label) {
    if (-not (Test-Path -LiteralPath $directory -PathType Container)) {
        throw "$label directory does not exist: $directory"
    }
    foreach ($name in $expected.Keys) {
        $path = Join-Path $directory $name
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "Missing $label artifact: $path"
        }
        $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $path).Hash.ToUpperInvariant()
        if ($actual -ne $expected[$name]) {
            throw "Hash mismatch for $label artifact $name"
        }
        Write-Output "$label PASS $name"
    }
}

Test-Manifest $SbomDirectory $expectedSbom "SBOM"
Test-Manifest $TrivyDirectory $expectedTrivy "Trivy"
Write-Output "release-artifacts=PASS"

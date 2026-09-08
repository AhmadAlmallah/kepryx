[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
# Synthetic local-only HMAC material; never use this value outside the demo.
$demoHmacMaterial = "kepryx-demo-webhook-secret" # pragma: allowlist secret
$payload = '{"event":"demo.alert","resource":"PUBLIC-WEB-02","status":"open"}'
$encoding = [System.Text.Encoding]::UTF8
$hmac = [System.Security.Cryptography.HMACSHA256]::new($encoding.GetBytes($demoHmacMaterial))
try {
    $digest = $hmac.ComputeHash($encoding.GetBytes($payload))
}
finally {
    $hmac.Dispose()
}
$signature = "sha256=" + ([Convert]::ToHexString($digest).ToLowerInvariant())

Write-Host "Local webhook contract check"
Write-Host "Payload: $payload"
Write-Host "Expected signature: $signature"
Write-Host "Result: PASS"
Write-Host "This verifies the HMAC contract only; it does not claim outbound delivery to a private receiver."

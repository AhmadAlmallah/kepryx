param(
    [string]$EnvFile = (Join-Path $PSScriptRoot ".env")
)

$ErrorActionPreference = "Stop"

function Read-EnvValue([string]$Name) {
    $line = Get-Content -LiteralPath $EnvFile | Where-Object { $_ -match "^$Name=" } | Select-Object -First 1
    if (-not $line) { throw "Missing $Name in $EnvFile" }
    return $line.Substring($Name.Length + 1)
}

$apiKey = Read-EnvValue "NETBOX_SUPERUSER_API_KEY"
$apiSecret = Read-EnvValue "NETBOX_SUPERUSER_API_TOKEN"
$token = "nbt_$apiKey.$apiSecret"
$headers = @{ Authorization = "Bearer $token"; Accept = "application/json" }
$base = "http://127.0.0.1:8000/api"

function Invoke-NetBox([string]$Method, [string]$Path, [object]$Body = $null) {
    $params = @{ Method = $Method; Uri = "$base$Path"; Headers = $headers; ErrorAction = "Stop" }
    if ($null -ne $Body) {
        $params.ContentType = "application/json"
        $params.Body = ($Body | ConvertTo-Json -Depth 8)
    }
    return Invoke-RestMethod @params
}

function Get-OrCreate([string]$Path, [string]$Filter, [object]$Body) {
    $existing = Invoke-NetBox "GET" "$Path$Filter"
    if ($existing.count -gt 0) { return $existing.results[0] }
    return Invoke-NetBox "POST" $Path $Body
}

for ($attempt = 1; $attempt -le 30; $attempt++) {
    try { Invoke-NetBox "GET" "/" | Out-Null; break } catch {
        if ($attempt -eq 30) { throw }
        Start-Sleep -Seconds 5
    }
}

$site = Get-OrCreate "/dcim/sites/" "?slug=kepryx-lab" @{ name = "Kepryx Lab"; slug = "kepryx-lab"; status = "active" }
$manufacturer = Get-OrCreate "/dcim/manufacturers/" "?slug=kepryx-lab" @{ name = "Kepryx Lab Devices"; slug = "kepryx-lab" }
$role = Get-OrCreate "/dcim/device-roles/" "?slug=network-infrastructure" @{ name = "Network Infrastructure"; slug = "network-infrastructure"; color = "2196f3" }
$deviceType = Get-OrCreate "/dcim/device-types/" "?slug=virtual-switch" @{ manufacturer = $manufacturer.id; model = "Virtual Switch"; slug = "virtual-switch"; u_height = 1 }

$devices = @(
    @{ name = "LAB-SW-01"; serial = "KEPRYX-SW-001"; ip = "198.51.100.61/24"; mac = "02:00:00:10:00:01" }
    @{ name = "LAB-RTR-01"; serial = "KEPRYX-RTR-001"; ip = "198.51.100.62/24"; mac = "02:00:00:10:00:02" }
    @{ name = "LAB-FW-01"; serial = "KEPRYX-FW-001"; ip = "198.51.100.63/24"; mac = "02:00:00:10:00:03" }
)

foreach ($item in $devices) {
    $device = Get-OrCreate "/dcim/devices/" ("?name=" + $item.name) @{
        name = $item.name; device_type = $deviceType.id; role = $role.id; site = $site.id
        status = "active"; serial = $item.serial
    }
    $interface = Get-OrCreate "/dcim/interfaces/" ("?device_id=$($device.id)&name=mgmt0") @{
        device = $device.id; name = "mgmt0"; type = "1000base-t"; enabled = $true; mac_address = $item.mac
    }
    $ipLookup = Invoke-NetBox "GET" ("/ipam/ip-addresses/?address=" + [uri]::EscapeDataString($item.ip))
    if ($ipLookup.count -eq 0) {
        $ip = Invoke-NetBox "POST" "/ipam/ip-addresses/" @{
            address = $item.ip; status = "active"; assigned_object_type = "dcim.interface"; assigned_object_id = $interface.id
        }
    } else { $ip = $ipLookup.results[0] }
    Invoke-NetBox "PATCH" "/dcim/devices/$($device.id)/" @{ primary_ip4 = $ip.id } | Out-Null
}

Write-Host "Seeded three network-device records into NetBox."
Write-Host "NetBox API token is configured for the Kepryx connector as: nbt_$apiKey.<redacted>"

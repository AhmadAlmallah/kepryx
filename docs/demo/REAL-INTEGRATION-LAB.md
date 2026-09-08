# Real local integration lab

This lab adds two small, real open-source systems to the bounded Kepryx demo:

| Source | What it proves | What it does not prove |
|---|---|---|
| FleetDM + one enrolled `fleetd` host | Kepryx can pull endpoint-management inventory from a provider REST API | FleetDM enrollment is not EDR coverage |
| NetBox + three seeded network-device records | Kepryx can pull network source-of-truth records from a provider REST API | NetBox is not live packet monitoring or active network discovery |
| Kepryx Nmap worker | Kepryx can observe the isolated demo network directly | The reserved demo range is not authorization to scan a real network |

The providers are isolated in `kepryx-v09-integration` and are bound to localhost
only. Run one provider profile at a time while recording to keep resource use
predictable. The compose file is a local lab helper, not a production deployment.
The integration and synthetic demo projects use overlapping local demo ports; stop
one before starting the other with `demo/integrations/Stop-IntegrationLab.ps1`
or `demo/Stop-Demo.ps1`.

## Resource fit

The existing Kepryx demo is the main workload. The endpoint profile adds FleetDM,
MySQL, and Redis. The network profile adds NetBox, PostgreSQL, and two Valkey
instances. Do not add Wazuh, Elastic, Snort, or another full SIEM/EDR stack to
this recording profile; that would increase resource use without improving the
integration proof.

## Start the network source

From the repository root:

```powershell
pwsh -NoProfile -File .\demo\integrations\Initialize-IntegrationLab.ps1 -Provider network -Start -SeedNetwork
```

Open NetBox at <http://127.0.0.1:8000>. The script provisions the local admin
and three records: `LAB-SW-01`, `LAB-RTR-01`, and `LAB-FW-01`. It also assigns
reserved documentation addresses so the records can be reconciled with the
Kepryx demo without touching a real network.

The connector follows [NetBox's documented REST API](https://github.com/netbox-community/netbox/blob/main/docs/integrations/rest-api.md)
under `/api/`, including the paginated `/api/dcim/devices/` endpoint.

Register a Kepryx integration in the Integrations page with:

```json
{
  "base_url": "http://netbox:8080",
  "api_token": "nbt_demo.<value-from-demo/integrations/.env>",
  "token_scheme": "bearer",
  "devices_path": "/api/dcim/devices/"
}
```

Use `connector_type: netbox`, test the connection, then run it. The expected
result is a successful provider test and three `netbox` observations in the
asset source list. The Integrations table records the last run duration and a
redacted error class when a run fails; it never displays the provider token.
Never paste the token into a public issue, screenshot, or recording.

## Start the endpoint source

From the repository root:

```powershell
pwsh -NoProfile -File .\demo\integrations\Initialize-IntegrationLab.ps1 -Provider endpoint -Start
```

Open FleetDM at <http://127.0.0.1:1337>, complete the local first-user setup,
and create a Fleet API token from the account page. Enroll one disposable Linux
or Windows lab endpoint using Fleet's official `fleetd` enrollment instructions.
Use [Fleet's REST API documentation](https://fleetdm.com/docs/rest-api/rest-api) and
[fleetd enrollment guide](https://fleetdm.com/guides/enroll-hosts) for the provider-side steps.
Do not install the agent on a production or personal device merely for the
recording. Wait until the host appears as online in Fleet, then register this
Kepryx integration:

```json
{
  "base_url": "http://fleet:1337",
  "api_token": "<Fleet API token>",
  "hosts_path": "/api/v1/fleet/hosts",
  "per_page": 50
}
```

Use `connector_type: fleetdm`, test the connection, then run it. The expected
result is a successful provider test and at least one `fleetdm` observation.
The normalized record intentionally displays `N/A (FleetDM)` for EDR status;
that is a visible boundary against claiming that endpoint management equals EDR.

## Recording proof

1. Show the source provider UI with the device/host record.
2. Show Kepryx Integrations and the successful Test result.
3. Run the integration.
4. Open Inventory and show the `netbox` or `fleetdm` source on the reconciled asset.
5. Show a second source on an asset after Kepryx Nmap discovery where identity matches.
6. Explain that provider API integration is live and the records are local lab data.

Only say “live FleetDM/NetBox integration” after the provider test and run both
complete successfully. Before that, say “adapter prepared; live acceptance
pending.”

The provider adapters enforce bounded timeouts, pagination pages, and imported
asset counts. These limits prevent an unexpectedly large or malformed provider
response from consuming the demo worker indefinitely; adjust them only for an
authorized lab and keep the values visible in the integration configuration.

## Stop and reset

```powershell
docker compose -p kepryx --env-file .env --env-file .\demo\integrations\.env -f docker-compose.yml -f docker-compose.demo.yml -f docker-compose.integrations.yml --profile demo --profile endpoint --profile network stop
```

Do not run `down -v` unless you intentionally want to erase the local provider
databases. The generated `.env` contains local credentials and is ignored by
Git.

# Synthetic Asset Source API fixture

This deterministic, stdlib-only fixture implements the small vendor-neutral
contract used by the Kepryx `asset_api` connector:

- `GET /health`
- `GET /v1/assets`
- `GET /v1/demo-observations`

It returns 24 synthetic assets using reserved documentation IP space. The demo-observations
route returns three records that match the full demo CSV by IP/MAC so the real Kepryx connector
and reconciler can show source enrichment without creating duplicate assets. It does not
contact external services, contain customer data, or represent a vendor product.
Keep it restricted to local demo networks.

Run it directly:

```bash
python -m demo.asset_source_mock.server
```

For the Docker Compose demo profile:

```bash
docker compose --profile demo up -d asset-source-mock
```

Register it only in an isolated local environment with:

```json
{
  "base_url": "http://asset-source-mock:8766",
  "api_token": "simulated-asset-source-token"
}
```

The API connector requires HTTPS by default. For this isolated fixture only, set
`ALLOW_INSECURE_CONNECTORS=true` before registering the HTTP URL. Never carry that
setting or the synthetic token into production.

# Integration Notes

How to connect Kepryx to your existing data sources, and how the reconciliation engine merges them.

## Connector model

Every external data source implements `BaseConnector`:

```python
class BaseConnector(ABC):
    def __init__(self, config: dict): ...
    async def fetch_inventory(self) -> list[dict]: ...
    async def test_connection(self) -> bool: ...
```

Each `fetch_inventory()` call returns a list of asset dictionaries normalized to Kepryx's schema. The reconciler merges them with existing records based on MAC → IP → hostname matching.

## Built-in connectors (v0.9.0 preview)

| Connector | Type | Authority | Reads |
|-----------|------|-----------|-------|
| `asset_api` | Vendor-neutral Asset Source API | 7 | Normalized asset records |
| `ad_ldap` | Active Directory / LDAP | 8 | Domain-joined computer objects |
| `edr_crowdstrike` | CrowdStrike Falcon EDR | 10 | All managed endpoints |
| `vuln_nessus` | Tenable Nessus | 6 | Hosts from completed scans |
| `cloud_aws` | AWS EC2 + RDS | 8 | Running instances, DB instances |
| `dhcp_dns` | Infoblox WAPI / ISC Kea | 5 | Active DHCP leases |

**Source priority** (higher number = more authoritative for field updates):

```
EDR (10) > NAC (9) > AD / Cloud (8) > CMDB (7) > Vuln scanner (6) > DHCP (5) > Nmap (4) > Manual (3)
```

When multiple sources report the same asset (matched by MAC then IP then hostname), the highest-priority source wins for authoritative fields (name, OS, segment, EDR status). Lower-priority sources still contribute to the union of `software_stack`, `cpe`, and `dependencies`.

## Registering a connector

Via API (admin token required):

```bash
curl -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  https://kepryx.local/api/v1/integrations \
  -d '{
    "name": "prod-ad",
    "connector_type": "ad_ldap",
    "config": {
      "server": "ldaps://dc.example.local:636",
      "base_dn": "DC=example,DC=local",
      "bind_dn": "CN=svc-kepryx,OU=Service Accounts,DC=example,DC=local",
      "bind_password": "<provided over TLS; encrypted at rest>",
      "filter": "(objectClass=computer)"
    },
    "schedule_cron": "0 */6 * * *",
    "priority": 8
  }'
```

Then test the credentials before enabling:

```bash
curl -X POST -H "Authorization: Bearer $TOKEN" \
  https://kepryx.local/api/v1/integrations/$ID/test
# → {"connected": true}
```

If the test fails, the response includes the error reason. Fix the config and re-test before scheduling.

## Per-connector config reference

### `asset_api`

```json
{
  "base_url": "https://inventory.example",
  "api_token": "REQUIRED",
  "inventory_path": "/v1/assets",
  "timeout_sec": 10
}
```

The repository includes a local synthetic implementation under
`demo/asset_source_mock/`. It returns reserved-range test assets and is intended
only for connector and reconciliation validation.

### `ad_ldap`

```json
{
  "server": "ldaps://dc.example.local:636",
  "base_dn": "DC=example,DC=local",
  "bind_dn": "CN=svc-kepryx,OU=Service Accounts,DC=example,DC=local",
  "bind_password": "",
  "filter": "(objectClass=computer)"
}
```

Required AD permissions: read on the configured OU. Read-only service account is sufficient — do not use Domain Admin.

### `edr_crowdstrike`

```json
{
  "base_url": "https://api.crowdstrike.com",
  "client_id": "REQUIRED",
  "client_secret": ""
}
```

Region URLs:
- US-1: `https://api.crowdstrike.com`
- US-2: `https://api.us-2.crowdstrike.com`
- EU-1: `https://api.eu-1.crowdstrike.com`
- US-Gov-1: `https://api.laggar.gcw.crowdstrike.com`

Required OAuth2 scopes: `Hosts:read`.

### `vuln_nessus`

```json
{
  "base_url": "https://nessus.example.local:8834",
  "access_key": "REQUIRED",
  "secret_key": "",
  "verify_ssl": true
}
```

For internal Nessus with self-signed cert, set `verify_ssl: false` — but pin the cert via your own CA bundle if possible.

### `cloud_aws`

```json
{
  "access_key_id": "REQUIRED",
  "secret_access_key": "",
  "regions": ["us-east-1", "eu-west-1"]
}
```

IAM policy required (read-only):

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": [
      "ec2:DescribeInstances",
      "rds:DescribeDBInstances",
      "sts:GetCallerIdentity"
    ],
    "Resource": "*"
  }]
}
```

Use a dedicated IAM user or, preferably, an IAM role assumed via STS. Future versions will support IRSA / Workload Identity.

### `dhcp_dns`

For Infoblox:

```json
{
  "provider": "infoblox",
  "base_url": "https://infoblox.example.local/wapi/v2.12",
  "username": "REQUIRED",
  "password": "",
  "verify_ssl": true
}
```

For ISC Kea:

```json
{
  "provider": "kea",
  "base_url": "https://kea.example.local:8000/",
  "verify_ssl": true
}
```

## Reconciliation behavior

```python
# Pseudocode for the merge logic
existing = find_asset_by(mac) or find_asset_by(ip) or find_asset_by(hostname)

if existing:
    if new_source_priority >= existing_max_source_priority:
        # Overwrite authoritative fields (name, OS, segment, EDR, etc.)
    # Always enrich list-type fields (software_stack, cpe, dependencies)
    # Always update last_seen
else:
    create_new_asset()
    if no_authoritative_source_in_sources:
        flag_as_shadow_it()
        raise_alert("shadow_it", "high")
```

## Shadow IT detection

An asset is flagged `is_shadow=true` when no authoritative source claims it. Authoritative sources are:

```
edr_crowdstrike, edr_sentinelone, edr_defender,
nac_cisco_ise, nac_aruba,
ad_ldap, azure_ad,
cmdb_servicenow, cmdb_jira,
cloud_aws, cloud_azure, cloud_gcp
```

If nmap finds a host that none of the above know about, you have shadow IT. An alert fires with type `shadow_it` and severity `high`, routed through your configured notification channels.

## Drift detection

When the same asset is re-reported by the same source and its `services` list has changed (port opened or closed, version bumped), an alert with type `drift`, severity `medium` fires. Drift detection runs on every reconciliation pass — no scheduled job needed.

## EDR gap detection

Runs every 30 minutes (`detect_stale_and_gaps` task). Any Server, Endpoint, Workstation, or Database Server with `edr_status` of `None` or `null` produces an `edr_gap` alert. Adjust the `type` filter in `app/services/reconciler.py:detect_edr_gaps` if you need different scope.

## Adding a new connector

1. Create `app/connectors/your_source.py`
2. Subclass `BaseConnector`
3. Implement `fetch_inventory()` returning normalized asset dicts (see existing connectors for the dict schema)
4. Implement `test_connection()` returning bool
5. Decorate the class with `@register_connector("your_name")`
6. Add to `SOURCE_PRIORITY` in `app/services/reconciler.py`
7. Restart `worker-recon` to pick up the new connector

Normalized asset dict schema (minimum):

```python
{
    "name": "DC-PROD-01",            # required
    "ip": "10.0.1.10",                # at least one of ip/mac required
    "mac": "AA:BB:CC:DD:EE:01",
    "hostname": "DC-PROD-01.corp",   # optional
    "type": "Server",                 # Endpoint, Server, Firewall, ...
    "os": "Windows Server 2022",
    "segment": "Internal",
    "edr_status": "CrowdStrike 7.x",
    "control_coverage": "full",
    "network_exposure": "internal",
    "auth_method": "mfa+pam",
    "criticality": "tier-1",
    "data_classification": "Confidential",
    "software_stack": ["Microsoft Windows Server 2022", "Active Directory"],
    "cpe": ["cpe:2.3:o:microsoft:windows_server_2022:*:*:*:*:*:*:*:*"],
    "dependencies": ["DNS", "DHCP"],
    "attrs": {"<connector-specific metadata>": "..."}
}
```

## Suppressing noise

Some connectors will produce noisy or duplicate alerts in your environment. Strategies:

- **Tune source priority**: if your CMDB has bad data, drop its priority so EDR and AD override it
- **Suppress specific findings**: `POST /api/v1/alerts/{id}/resolve` with a reason — won't re-fire for 24h
- **Disable an integration temporarily**: `enabled=false` via the integrations API
- **Filter at source**: use the LDAP `filter` config or AWS region scoping to cut volume

## Multi-source reconciliation example

You enable AD, the Asset Source API, AWS, and nmap. Scenario:

```
nmap discovers:        host 10.0.1.10, MAC AA:BB:CC:DD:EE:01
AD reports:            DC-PROD-01, OS Windows Server 2022
Asset Source API:      DC-PROD-01, MAC AA:BB:CC:DD:EE:01, OS Windows Server 2022 Build 20348
AWS reports:           (nothing, it's on-prem)
```

Reconciler outcome:
- Single asset created
- Name: `DC-PROD-01` (from highest-priority match — Asset Source API priority 7)
- OS: `Windows Server 2022 Build 20348` (Asset Source API wins over nmap)
- MAC: `AA:BB:CC:DD:EE:01` (any source)
- IP: `10.0.1.10` (nmap)
- Sources: `["nmap_scan", "ad_ldap", "asset_api"]`
- `is_shadow`: `false` (AD and EDR are authoritative)
- `edr_status`: `"None"` unless an EDR connector also reports the asset

## CMDB integration (ServiceNow, Jira)

Not implemented in v0.9.0 and has no committed release date. As a supervised workaround,
export the CMDB to CSV/JSON and use the validated bulk-ingest path.

## Outbound integrations (notifications)

In addition to ingesting data, Kepryx pushes alerts outward:

| Channel | Config | Severity routing |
|---------|--------|------------------|
| Slack | `SLACK_WEBHOOK_URL` | All severities (configurable per alert) |
| Email | `SMTP_*` settings | Default: critical and high |
| PagerDuty | `PAGERDUTY_KEY` | Default: critical only |
| Syslog CEF | Always on (UDP 514) | All severities |

Configure routing per severity in `app/services/notifications.py:_default_channels`.

## Production wiring recommendations

1. **Start with one connector** — usually AD if you're Windows-heavy, or AWS if cloud-heavy
2. **Validate data quality** for 1-2 weeks before adding more sources
3. **Then add EDR** — fastest way to mark assets as "managed"
4. **Then nmap** — to surface shadow IT against the now-established baseline
5. **Then vuln scanner** — to populate CVE evidence
6. **Adjust source priorities** based on what you learn about data quality in your environment

## Failures and auto-disable

If a connector sync fails 5 times in a row, it auto-disables with audit log entry. Re-enable manually after fixing the issue:

```bash
curl -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  https://kepryx.local/api/v1/integrations/$ID \
  -d '{"enabled": true}'
```

Then test before running.

# Kepryx local demo lab plan

This is the recommended recording profile for Kepryx v0.9.0. It is deliberately
vendor-neutral and designed for one Windows host, one optional Linux VM, and a
small amount of synthetic data. The optional real-provider profile adds FleetDM
and NetBox so the recording can show actual API collection without pretending
that a small lab is an enterprise deployment.

## The recommendation

Run the Kepryx Docker stack as the primary system. Add the optional Linux VM only
when a real endpoint view is useful. Do not run Wazuh, an Elastic deployment, a
network IDS, and Kepryx at the same time for the main recording. That would spend
the hardware budget on infrastructure instead of showing the product workflow.

The primary demo profile provides:

- 37 deterministic synthetic assets across Finance, HR, Engineering, DMZ, Perimeter,
  Cloud-Lab, Corporate, Lab, and OT segments.
- Five deliberately unmanaged/shadow candidates to make the inventory gap visible.
- A local Asset Source API mock using the real `asset_api` connector and reconciler.
- A local vulnerability snapshot that implements the response shapes consumed by the
  NVD, EPSS, CISA KEV, and OSV clients. It contains one clearly labelled Log4j demo
  enrichment target; it is not a current vulnerability feed.
- Two harmless HTTP containers on an internal Docker TEST-NET-2 network for an
  authorization-bounded discovery scan.
- A local HMAC signature check for the webhook contract. The main demo does not
  claim delivery to a private receiver because the application intentionally blocks
  private/loopback webhook destinations.
- Optional local Ollama assistance. The product path still works if AI is disabled.

For the real collection path, use [REAL-INTEGRATION-LAB.md](REAL-INTEGRATION-LAB.md). It adds
one FleetDM endpoint and three NetBox network records, one provider profile at a time.

## What is real and what is simulated

| Demo element | Evidence level | How to present it |
|---|---|---|
| CSV import, normalization, risk calculation, compliance, alerts, audit, UI | Kepryx code path | Live local workflow |
| Asset Source API | Real connector protocol against a local fixture | “Vendor-neutral source contract; no provider account required” |
| NVD/EPSS/KEV/OSV responses | Real client code against local response-shape fixtures | “Offline snapshot for repeatability; not fresh authoritative data” |
| Network discovery | Real Nmap worker against two local containers | “Authorized isolated Docker network only” |
| FleetDM endpoint inventory | Native connector plus provider acceptance test | “Live endpoint-management API pull”; do not call it EDR |
| NetBox network inventory | Native connector plus provider acceptance test | “Live network source-of-truth API pull”; not packet monitoring |
| Wazuh/Elastic/Snort | Not included in the primary profile | Not claimed as native integrations |
| Webhook delivery | HMAC contract only | Do not show a private receiver as production delivery |
| AI | Optional local provider | Advisory and read-only; never the source of truth |

## Resource budget

The inspected host has approximately 62 GB RAM, an RTX 5080 with 16 GB VRAM,
an eight-thread Windows view, and about 261 GB free on the system volume. Keep the
demo bounded:

| Component | Target budget | Recording rule |
|---|---:|---|
| Kepryx API, workers, Caddy, PostgreSQL, Redis | 20–24 GB RAM; 6–8 CPU | Primary stack only |
| Two virtual targets and local feed fixtures | under 2 GB RAM | Start with the profile; stop after recording |
| Optional Ubuntu VM | 4–6 GB RAM; 2–4 vCPU | Use only for an endpoint deep-dive |
| FleetDM or NetBox profile | 3–5 GB RAM | Run one provider profile at a time |
| Optional Ollama model | one request at a time | Keep at least 12 GB host RAM free |
| Free disk reserve | at least 100 GB | Do not build unrelated images during recording |

If Docker reports pressure, stop the VM and disable Ollama first. Do not add a full
Wazuh/Elastic deployment to the same run; that is a separate lab profile.

## Run sequence

From the repository root:

```powershell
python demo/generate_full_dataset.py
pwsh -File demo/Run-Demo.ps1
pwsh -File demo/Preflight-Demo.ps1
```

The first run requires Docker to be running and may build the pinned images. Open
`https://kepryx.local:8444`, bootstrap a disposable administrator, then use the UI
to import `demo/data/assets-full.csv` in the disposable demo database.

In **Integrations**, register the local source with this placeholder-only config:

```json
{
  "base_url": "http://asset-source-mock:8766",
  "inventory_path": "/v1/demo-observations",
  "api_token": "simulated-asset-source-token"
}
```

Run the integration once and show that existing records gain a second source rather
than becoming duplicate assets. Then add the scan network through **Scans**:

```text
CIDR: 198.51.100.240/28
Name: isolated-demo-scan
```

Trigger discovery only after the UI shows the network as authorized. The two target
containers are `198.51.100.242` and `198.51.100.243`; no host, home, cloud, or
workplace network is in scope.

## Recording order

1. Establish the problem: security decisions are only as good as the assets and
   evidence the tools can see.
2. Show the dashboard and the 37-asset operating picture.
3. Import the fixture using dry-run first, then process it.
4. Filter the five shadow/unmanaged candidates and open one detail record.
5. Run the local source integration and show source reconciliation.
   For a provider-backed recording, use the real integration lab and show the provider UI,
   successful Test result, Run result, and provider source label in Inventory.
6. Open `PUBLIC-WEB-02`, show the local snapshot provenance, risk factors, and the
   fact that the score is a posture signal—not breach probability.
7. Show the graph as bounded inventory topology, not an attack-path engine.
8. Run compliance and inspect one evidence lineage chain.
9. Show self-security using the local OSV-shaped response and explain the snapshot.
10. Run the authorized discovery scan, then show the scan record and audit trail.
11. Ask the optional Assistant for evidence-backed posture; demonstrate that it
    refuses write actions or secrets.
12. Close with the limitations: one local endpoint, seeded local network records, no enterprise
    scale or third-party production account, and provider-specific acceptance evidence.

## Stop/reset rules

The demo profile is disposable. Stop it with:

```powershell
docker compose -p kepryx-demo -f docker-compose.yml -f docker-compose.demo.yml --profile demo down
```

To remove only this demo database and its project-scoped volumes, use the guarded
reset script:

```powershell
pwsh -File demo/Reset-Demo.ps1 -ConfirmReset
```

Never use the demo reset command against the normal Kepryx project name.

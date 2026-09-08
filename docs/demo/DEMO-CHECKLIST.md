# Kepryx demo checklist

Use this checklist for rehearsal, recording, and post-recording review. A checked item means it
was observed in the current session, not merely expected from documentation.

## 1. Host and presentation readiness

- [ ] Docker Desktop is running and the required project is selected.
- [ ] The Windows host has enough free memory and disk for the selected profile.
- [ ] The primary demo uses `docker-compose.demo.yml`; an integration profile is not running on the
      same ports.
- [ ] Local certificate trust is working, or the browser warning is handled before recording.
- [ ] Browser is at 1280px or wider and 100% zoom.
- [ ] Only the demo browser window is visible; no personal tabs, terminals, credentials, tokens,
      `.env` files, private certificates, or customer data are visible.
- [ ] Notifications, password managers, clipboard history, and unrelated overlays are disabled.
- [ ] The recording has a clean audio path and the operator has the speaker notes open on a second
      screen or printed copy.

## 2. Deterministic demo readiness

Run these commands from the repository root:

```powershell
python .\demo\generate_full_dataset.py
pwsh -NoProfile -File .\demo\Run-Demo.ps1
pwsh -NoProfile -File .\demo\Preflight-Demo.ps1
pwsh -NoProfile -File .\demo\Collect-DemoEvidence.ps1
```

- [ ] The preflight completes without an error.
- [ ] `/health` and `/ready` return HTTP 200.
- [ ] The UI shows **API connected** after login.
- [ ] The disposable demo account works.
- [ ] The CSV dry run shows the actual result for the current fixture.
- [ ] The fixture path is `demo/data/assets-full.csv` and its data is synthetic.
- [ ] The current asset count and shadow-candidate count are noted from the live screen, not
      copied from an old screenshot.
- [ ] The local vulnerability mode is visibly or verbally identified as a snapshot.
- [ ] The two scan targets are reachable only inside the authorized isolated test network.
- [ ] The evidence manifest was generated and stored outside the public recording output.

## 3. Optional real-provider profile

Do this only if the provider was actually installed and tested. One provider profile at a time is
the safe fit for the lab.

### NetBox

- [ ] NetBox is running locally with three disposable device records.
- [ ] The base URL, token, and TLS choice are configured through the API flow; no secret appears
      in the browser or recording.
- [ ] **Test** succeeds.
- [ ] **Sync** succeeds.
- [ ] The run shows bounded pages/assets and a duration.
- [ ] The resulting assets show source/provenance labels that identify NetBox.
- [ ] The operator says “network inventory source of truth,” not “network monitoring.”

### FleetDM

- [ ] FleetDM has completed first-user setup.
- [ ] A disposable lab host is enrolled and visible in FleetDM.
- [ ] A token with only the required scope is used and kept out of the recording.
- [ ] **Test** succeeds.
- [ ] **Sync** succeeds and one observed endpoint is visible in Kepryx.
- [ ] The operator says “endpoint-management inventory,” not “EDR protection.”
- [ ] If first-user setup, enrollment, test, or sync is incomplete, the provider is marked
      **pending validation** and not presented as live.

See [REAL-INTEGRATION-LAB.md](REAL-INTEGRATION-LAB.md) for setup boundaries and stop commands.

## 4. Recording sequence

- [ ] Start with the system-context diagram and state the evidence-first thesis.
- [ ] Show the dashboard briefly; do not read every KPI.
- [ ] Run CSV **Validate only** before any process/import action.
- [ ] Show one asset’s source, risk, vulnerability context, and control state.
- [ ] Explain that the relationship map provides bounded context and is not an attack-path engine.
- [ ] Trace one compliance result to asset evidence and show the rationale.
- [ ] Explain that Assistant output is advisory and does not write Kepryx data.
- [ ] Show authorized discovery only if the isolated scan network is ready.
- [ ] Show provider UI only when the test and sync evidence exists.
- [ ] End with limitations, contribution path, and a focused technical question.

## 5. Claims and security gate

- [ ] No claim says “CVE-free,” “certified,” “production-ready,” “enterprise-ready,” “fully
      automated remediation,” or “attack-path engine.”
- [ ] No current-feed claim is made for local NVD/EPSS/KEV/OSV snapshots.
- [ ] No Wazuh, Elastic, or Snort native integration claim is made unless separately implemented and
      proven.
- [ ] No private webhook delivery is presented as production delivery.
- [ ] No screenshot contains secrets, raw audit details, bearer tokens, or non-public IP data.
- [ ] Any current test, coverage, dependency, container, or secret-scan result is dated and tied to
      a command output. If it was not rerun, it is not described as current.
- [ ] The operator can answer which behavior is code-path proven, fixture-backed, live-provider
      proven, and pending.

## 6. After recording

- [ ] Save the redacted evidence manifest and recording notes.
- [ ] Record commit SHA, Docker image tags/digests, date/time, profile, and deviations.
- [ ] Review the recording frame by frame for secrets, stale screenshots, unsupported claims, and
      accidental external network activity.
- [ ] Stop the demo services with `demo\Stop-Demo.ps1`.
- [ ] If an integration profile was used, stop it with
      `demo\integrations\Stop-IntegrationLab.ps1`.
- [ ] Do not remove provider volumes unless disposable data is intentionally being erased.
- [ ] Keep raw recordings outside the public repository until reviewed.

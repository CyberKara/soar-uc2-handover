# Proofpoint TRAP

## Overview

Ingest and manage incidents from Proofpoint Threat Response Auto-Pull (TRAP) on-premises.

- **Version:** 1.0.13
- **Type:** SIEM (ingest connector)
- **Auth:** API key (`Authorization` header)
- **Min SOAR version:** 6.4.1
- **Polling:** Yes — requires an event label (see below)

## Prerequisites

1. Proofpoint TRAP instance accessible over HTTPS from the SOAR host.
2. API key generated in **TRAP > System Settings > API Keys**.
3. **SOAR event label** created before enabling polling:
   - Go to **Administration > Event Settings > Labels**
   - Create a label (e.g. `proofpoint_trap`)
   - This label will be selected in the asset's Ingest Settings

## Installation

On the SOAR host:

```bash
cd /data/splunk/soar8/soar-connectors/connectors/proofpoint_trap
/opt/phantom/bin/phenv compile_app -i
```

Or build a tarball:

```bash
/opt/phantom/bin/phenv compile_app -t
```

Upload via **Apps > Install App**.

## Asset Configuration

| Field | Type | Required | Default | Description | Example |
|-------|------|----------|---------|-------------|---------|
| `base_url` | string | Yes | — | TRAP server URL | `https://trap.corp.local` |
| `api_key` | password | Yes | — | API key (stored encrypted) | |
| `verify_ssl` | boolean | No | `true` | Verify TRAP TLS certificate | `true` |
| `timeout` | numeric | No | `60` | Request timeout in seconds | `60` |
| `poll_state` | string | No | `new` | Incident state to poll. Valid (confirmed against the real Incident API doc, v1.0.12+): `new`, `open`, `closed` | `new` |
| `abuse_disposition` | string | No | `Unknown` | Comma-separated Abuse Disposition filter (v1.0.10+: full confirmed vocabulary). Valid: `Malicious`, `Suspicious`, `Spam`, `Bulk`, `Low Risk`, `False Negative`, `Known Good`, `Unknown` | `Unknown` |
| `sub_disposition` | string | No | (empty) | Comma-separated Sub Disposition filter (v1.0.10+). Valid: `Needs Manual Review`, `Likely Harmless`. Applied *in addition to* `abuse_disposition` — an incident must pass both. **Only ever populated on `Unknown`-disposition incidents** on real Threat Response (confirmed against the Incident API doc, v1.0.12+) — setting this while `abuse_disposition` excludes `Unknown` guarantees zero results. Leave empty unless `abuse_disposition` includes `Unknown`. | (empty — no filter) |
| `poll_hours` | numeric | No | `1` | Hours to look back on first poll | `1` |
| `fetch_mime_on_poll` | boolean | No | `true` | Auto-fetch + Vault-attach the raw MIME body for every event on each ingested incident (v1.0.8+). Adds one detail call per incident plus one call per event, every poll cycle. Disable if that overhead matters and use the standalone `download mime body` action on-demand instead. | `true` |

## Setting Up Polling (Ingestion)

**Requires event label** — polling will not work without this step.

1. **Create a label** in **Administration > Event Settings > Labels** (e.g. `proofpoint_trap`).
2. Open the TRAP asset, go to the **Ingest Settings** tab.
3. **Select the label** you created.
4. Set a polling interval (in minutes) or use **Poll Now** for a manual one-time run.
5. Save the asset.

**On-prem date-range cap (v1.0.9+):** on-premises Threat Response rejects
`created_after`/`created_before` incident-list queries spanning more than 30
days. If `poll_hours` (or the gap since the last successful poll) exceeds
that, the connector automatically splits the fetch into consecutive
<=30-day calls and merges the results — no config needed, but be aware a
wide first-run window (e.g. `poll_hours` in the thousands) now costs
multiple API calls per poll instead of one.

### What gets created

Each TRAP incident produces:
- **1 container** — named `TRAP-<id>: <summary>`, with severity mapped from TRAP.
- **N artifacts:**
  - **URL Artifact** — one per URL in `hosts.url` (CEF: `requestURL`, contains `url`)
  - **Event Info** — abuse disposition (`cs1`), classification (`cs2`), threat score (`cn1`)

  (An earlier version also created an "IP Artifact" from `hosts.attacker` and a "Forensics URL" from `hosts.forensics` — removed 2026-08-06 once confirmed against real incident data that `hosts` only ever has `url`, not `attacker`/`forensics`.)
  - **MIME Body** (v1.0.7+) — one per event, raw `.eml` content stored in the Vault (CEF: `vaultId`, `fileName`, contains `vault id`). Controlled by the `fetch_mime_on_poll` asset config (default `true`, v1.0.8+).

The connector uses `expand_events=false` for lightweight polling. For full email event details (sender, recipient, attachments), use the `get incident` action. MIME bodies are fetched via a separate per-incident detail call (`expand_events=true`) purely to enumerate event IDs — this adds one extra API call per incident plus one per event during `on_poll`. If that overhead matters for your TRAP instance, set `fetch_mime_on_poll=false` and use the standalone `download mime body` action on-demand instead.

### Severity mapping

TRAP severities collapse into SOAR's 3-level scale:

| TRAP Severity | SOAR Severity |
|---------------|---------------|
| `Critical`    | `high`        |
| `High`        | `medium`      |
| `Informational` | `low`       |
| *(other / unset)* | `low`     |

TRAP's `Critical` maps to SOAR's highest tier (`high`) so on-call sees true-positive phishing first; `High` drops one level because TRAP auto-raises dispositions aggressively and SOAR's `high` should stay reserved for Critical. Anything unclassified falls to `low` rather than a default `medium` to prevent noisy auto-close workflows from firing on ambiguous incidents.

### Checkpoint

After each poll, the connector saves a `last_poll_time` checkpoint. Subsequent polls only fetch incidents created after this time.

## Test Connectivity

Calls the TRAP API to verify the API key and network connectivity.

**Expected result:** "Test Connectivity Passed"

**Common errors:**
- `Auth Error` — invalid API key. Regenerate in TRAP System Settings.
- `Connection error` — check `base_url` and network access.
- `SSL error` — TRAP cert untrusted. Install CA cert on SOAR or set `verify_ssl` to false.

## Actions

| Action | Identifier | Type | Description |
|--------|-----------|------|-------------|
| test connectivity | `test_connectivity` | test | Validate API key and connectivity |
| on poll | `on_poll` | ingest | Ingest incidents as containers/artifacts |
| get incident | `get_incident` | investigate | Fetch full incident details by ID (accepts a single ID or a list of IDs) |
| download mime body | `download_mime_body` | investigate | Fetch raw MIME (.eml) for one event, or every event on an incident, and store in the Vault |
| close incident | `close_incident` | generic | Close an incident (requires summary + detail) |
| add comment | `add_comment` | generic | Add a comment to an incident |

### close incident

Both `summary` and `detail` are **required** by the TRAP API. The action will fail if either is missing.

### add comment

`summary` is required, `detail` is optional.

### download mime body

Params: `incident_id` (required), `event_id` (optional — omit to fetch every event on the incident). Each event downloads to the Vault via `Vault.create_attachment`; output data includes `event_id`, `vault_id`, `file_name` per event. Partial failure (e.g. one bad event_id among several) reports `succeeded`/`failed`/`total` in the summary and only fails the action if *all* events failed.

## Troubleshooting

| Issue | Cause | Fix |
|-------|-------|-----|
| No incidents ingested | Filter mismatch | Check `poll_state`, `abuse_disposition`, and `sub_disposition` (if set) match actual incidents in TRAP — remember `sub_disposition` filters *in addition to* `abuse_disposition`, so an unpopulated Sub Disposition on most incidents will exclude everything if this is set unintentionally |
| No incidents ingested | Label not configured | Verify the event label is created and selected in Ingest Settings |
| Duplicate containers | — | Not possible — dedup uses TRAP incident ID as `source_data_identifier` |
| Close incident fails | Missing field | Both `summary` and `detail` are required |
| `list incidents` fails with `unsupported type for timedelta hours component: str` | `hours_back` arrived as a string — a VPE literal action parameter always does | Fixed in v1.0.34 (the value is validated like every other numeric parameter). On an older build, bind `hours_back` to a numeric datapath instead of a literal |
| Timeout errors | Large response | Increase `timeout` in asset config. Connector retries 500/502/503/504 automatically. |
| No MIME Body artifacts on ingested containers | Vault write failed for every event | Check `spawn.log`/`decided.log` for `"Failed to fetch MIME for incident..."` (only `debug_print`'ed, not surfaced as an action failure — `on_poll` still reports success) |

### `update team and assignee` — diagnosing directly against TRAP, without SOAR

If this action is failing, it's faster to isolate the problem by hitting TRAP's
API directly than round-tripping through SOAR's Test Action dialog every time.
Run this from any host with network access to the TRAP appliance (the SOAR
host itself works fine):

```bash
BASE_URL="https://trap.example.com"            # asset's base_url
API_KEY="<api key from TRAP System Settings>"  # asset's api_key
INCIDENT_ID="134"                              # a real incident id
ASSIGNEE="kiki"                                # must exist as a TRAP user
TEAM="tata"                                    # must exist as a TRAP team

curl -sk -X POST \
  -H "Authorization: ${API_KEY}" \
  -H "Content-Type: application/json" \
  -d "{\"assignee\": \"${ASSIGNEE}\", \"team\": \"${TEAM}\"}" \
  "${BASE_URL}/api/incidents/${INCIDENT_ID}/team_and_assignee.json" \
  -w '\nHTTP %{http_code}\n'
```

Drop `-k` if `verify_ssl` is `true` in the asset and TRAP's cert chain is
trusted by the host you're running this from.

**Known real-appliance responses** (confirmed 2026-08-20; the connector
handles the first two as documented, the last one is still unexplained):

| Response | Meaning |
|----------|---------|
| `200` | Updated successfully. |
| `404` `"the previous team and assignee are same, not updating the incident"` | No-op — requested values already match the incident's current state. Connector v1.0.31+ treats this as a SOAR-side success (`no_op: true` in the action's output data), not a failure. |
| `404` `"no assignee found for <name>"` | `assignee` doesn't exist as a TRAP user — check spelling/case. |
| `400` `"Both team and assignee are required. Team: null, assignee: ..."` | One of the two fields was omitted. TRAP requires **both together** on every call — the API doc's per-field table implies they're independently optional, but its own combined `"team and assignee ... required: yes"` row was the accurate one. Connector v1.0.33+ requires both and won't even send the request without them. |
| `400` `"...org.hibernate.exception.ConstraintViolationException: could not extract resultset"` | A real database-layer rejection on TRAP's own backend, confirmed to happen even with a fully valid, existing `assignee` + `team` pair (not a request-shape problem, not a team-membership problem — both ruled out live). Still unexplained. Try the identical reassignment through TRAP's own web UI: if it also fails there, this is an appliance-side defect worth a Proofpoint support ticket, not something fixable from this connector. Full investigation: `soar-playbooks` repo, `docs/usecases/uc2_implementation_plan.md`'s "Scenario (2) diagnosed further" section. |

**Alternate write path worth testing if `team_and_assignee.json` stays
broken:** `set incident field value` (`/api/incidents/{id}/incident_fields.json`)
is a separate, more generic endpoint — already confirmed working for
`Severity`/`Classification`/`Sub Disposition`/`Abuse Disposition`. Whether
`Team`/`Assignee` are valid field names for it isn't documented, but it's a
different server-side code path and worth 30 seconds to rule in or out:

```bash
# Single field -- matches exactly what the connector's own "set incident
# field value" action sends ({"fields": {field: value}})
curl -sk -X POST \
  -H "Authorization: ${API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{"fields": {"Team": "tata"}}' \
  "${BASE_URL}/api/incidents/${INCIDENT_ID}/incident_fields.json?allow_data_override=true" \
  -w '\nHTTP %{http_code}\n'

# Both fields in one call -- the raw API supports this even though the
# connector's action only exposes one field per call
curl -sk -X POST \
  -H "Authorization: ${API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{"fields": {"Team": "tata", "Assignee": "kiki"}}' \
  "${BASE_URL}/api/incidents/${INCIDENT_ID}/incident_fields.json?allow_data_override=true" \
  -w '\nHTTP %{http_code}\n'
```

If this succeeds where `team_and_assignee.json` doesn't, it's a genuinely
fixable reroute (point the connector's `update team and assignee` action,
or `proofpoint_trap_acknowledge` directly, at this endpoint instead). If it
hits the same `ConstraintViolationException`, that rules out a
request-shape/endpoint issue entirely and points at a shared, broken
write path underneath both endpoints.

# Proofpoint TRAP

Ingest and manage incidents from Proofpoint Threat Response Auto-Pull (TRAP) on-premises.
Classic `BaseConnector` app, Python 3.13, API-key auth (`Authorization` header). The version is the
manifest's `app_version`. The playbooks that use it are UC2 in `soar-playbooks`
(`docs/usecases/uc2_implementation_plan.md`).

## Prerequisites

1. HTTPS access from the SOAR host to TRAP.
2. An API key from **TRAP > System Settings > API Keys**.
3. A SOAR label for the cases (e.g. `proofpoint_trap`): **Administration > Event Settings >
   Labels**, then select it in the asset's **Ingest Settings**. Polling creates nothing without it.

## Installation

Build on a connected host, never on the target (an air-gapped SOAR has no build tooling):

```bash
tools/build.sh proofpoint_trap          # from the soar-connectors root -> dist/proofpoint_trap-v<version>.tgz
```

Install the `.tgz` with **Apps > Install App**. SOAR refuses a package whose `app_version` is not
higher than the installed one.

## Asset configuration

| Field | Default | Notes |
|---|---|---|
| `base_url` | — | e.g. `https://trap.example.com`; the TRAP web UI shares the host |
| `api_key` | — | stored encrypted |
| `verify_ssl` | `true` | |
| `timeout` | `60` | seconds; 500/502/503/504 are retried |
| `poll_state` | `new` | `new`, `open` or `closed` |
| `abuse_disposition` | `Unknown` | comma-separated: Malicious, Suspicious, Spam, Bulk, Low Risk, False Negative, Known Good, Unknown (case-sensitive) |
| `sub_disposition` | empty | Needs Manual Review, Likely Harmless; applied on top of `abuse_disposition` and exists only under Unknown, so with Unknown excluded it matches nothing |
| `poll_hours` | `1` | first-poll lookback; a window over 30 days (TRAP's limit) is split into 30-day calls |
| `severity` / `sensitivity` | `low` / `amber` | initial values of a new case |

## Ingestion (`on_poll`)

Each incident becomes one case, `TRAP-<id>: <summary>` (`No summary` when TRAP has none),
`source_data_identifier` = incident id (no duplicate cases), `data` = the incident. It carries one
artifact, **Event Info** (`run_automation: true`):

| CEF field | Content |
|---|---|
| `incidentId` | data type `proofpoint trap incident id` (1.0.39+) |
| `abuseDisposition`, `subDisposition`, `classification`, `trapSeverity` | incident field values |
| `threatScore`, `eventIds`, `message` | score, alert ids, summary |

Polling uses `expand_events=false`; the playbooks fetch events, emails and URLs with `get incident`
and `download mime body`. A `last_poll_time` checkpoint moves forward after each scheduled poll
(not after Poll Now). Changes to an incident after ingestion are found by the UC2 playbook
`proofpoint_trap_recheck`, not by the connector.

## Actions

Every action taking an incident takes `incident_id` (data type `proofpoint trap incident id`).

| Action | Parameters | Notes |
|---|---|---|
| test connectivity | — | `Auth Error` = bad key; `Connection error` = `base_url`/network; `SSL error` = untrusted cert |
| list incidents | `state`, `hours_back`, `abuse_disposition`, `sub_disposition`, `expand_events`, `max_results` | the On Poll filters on demand; an empty `state` is dropped by SOAR, so send one call per state for "all" |
| get incident | `incident_id` (one or a list), `expand_events` (default true) | each result also has `incident_url`, the incident's TRAP web page |
| download mime body | `incident_id`, `event_id` (omit = every event) | below |
| close incident | `incident_id`, `summary`, `detail` | both texts required by TRAP |
| add comment | `incident_id`, `summary`, `detail` | `detail` is always sent: the appliance answers a comment without it with HTTP 500 `Null detail` |
| add user to incident | `incident_id`, `targets`, `attackers` | |
| update incident description | `incident_id`, `description`, `overwrite` | |
| update team and assignee | `incident_id`, `assignee`, `team` | both required together; a 404 "previous team and assignee are same" is reported as success (`no_op: true`) |
| set incident field value | `incident_id`, `field`, `value` | e.g. `Severity`, `Classification`, `Abuse Disposition` |

**download mime body.** Each event (a TRAP alert) is fetched with
`GET /api/v1/alerts/{event_id}/download_original_msg` (`Accept: message/rfc822`) and stored in the
case's Vault as `trap-<incident>-<event>.eml`. Output per event: `event_id`, `vault_id`,
`file_name`, `size`, `subject`. Run from the asset's action panel there is no case and so no
Vault: each message is still downloaded and checked, nothing is stored. The action fails only when
every event fails; each failure's HTTP status, path and body start go to the progress output.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| No incidents ingested | filters, or no label | check `poll_state` / `abuse_disposition` / `sub_disposition` against TRAP; select the label in Ingest Settings |
| `add comment` → HTTP 500 `Null detail` | 1.0.37 or older sent no `detail` | upgrade to 1.0.38+ |
| `list incidents` → `unsupported type for timedelta` | `hours_back` as text, 1.0.33 or older | upgrade to 1.0.34+ |
| `download mime body` → `Event <id> not found` on every event | 1.0.34 or older used a path the appliance does not have | upgrade to 1.0.35+ |
| `download mime body` → `Container None does not exist` | 1.0.35 run from the action panel | upgrade to 1.0.36+, or run it from a case |
| `download mime body` → `No original message for event <id> (HTTP 404)` | not an alert id, or the alert has no email | check the event's `source` in `get incident`; other events still download |
| `download mime body` → `Unexpected response ... text/html` | `base_url` reaches a web page (login, proxy) | fix `base_url` |
| Timeouts | large responses | raise `timeout` |

### `update team and assignee` — testing directly against TRAP

Run from any host that reaches TRAP (the SOAR host works):

```bash
BASE_URL="https://trap.example.com"   # asset base_url
API_KEY="<api key>"                   # asset api_key
INCIDENT_ID="134"; ASSIGNEE="kiki"; TEAM="tata"   # a real incident, TRAP user and team

curl -sk -X POST -H "Authorization: ${API_KEY}" -H "Content-Type: application/json" \
  -d "{\"assignee\": \"${ASSIGNEE}\", \"team\": \"${TEAM}\"}" \
  "${BASE_URL}/api/incidents/${INCIDENT_ID}/team_and_assignee.json" -w '\nHTTP %{http_code}\n'
```

| Response | Meaning |
|---|---|
| `200` | updated |
| `404` "the previous team and assignee are same" | nothing to change (the connector reports success) |
| `404` "no assignee found for <name>" | not a TRAP user |
| `400` "Both team and assignee are required" | one of the two missing |
| `400` `ConstraintViolationException` | rejected by TRAP's database even for a valid user + team pair; unexplained. If the same change fails in TRAP's own web UI, it is an appliance defect for Proofpoint support |

An untested alternative write path is `set incident field value`
(`/api/incidents/{id}/incident_fields.json`), a different server-side code path:

```bash
curl -sk -X POST -H "Authorization: ${API_KEY}" -H "Content-Type: application/json" \
  -d '{"fields": {"Team": "tata", "Assignee": "kiki"}}' \
  "${BASE_URL}/api/incidents/${INCIDENT_ID}/incident_fields.json?allow_data_override=true" \
  -w '\nHTTP %{http_code}\n'
```

If it succeeds where `team_and_assignee.json` fails, the connector (or
`proofpoint_trap_acknowledge`) can use it instead; if it hits the same exception, the fault is in
the write path behind both.

## API reference

`proofpoint_trap_api_reference.md` (vendor doc, sample tokens masked; not packaged). Proofpoint's
doc marks some fields optional that the appliance requires (`detail` on a comment; `team` with
`assignee`); trust the appliance.

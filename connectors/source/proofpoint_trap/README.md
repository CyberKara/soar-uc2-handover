# Proofpoint TRAP

Ingest and manage incidents from Proofpoint Threat Response Auto-Pull (TRAP) on-premises.
Classic `BaseConnector` app, Python 3.13, API-key auth (`Authorization` header). The version is the
manifest's `app_version`. HTTP calls follow SOAR's proxy settings (environment variables, global or
per asset) and certificate store, like Splunk's own apps. The playbooks that use it are UC2 in `soar-playbooks`
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
| `verify_ssl` | `true` | trusts SOAR's certificate store (**Administration > Certificate Store**); for an internal CA, import it there |
| `timeout` | `60` | seconds; 500/502/503/504 are retried |
| `poll_state` | `new` | `new`, `open` or `closed` |
| `abuse_disposition` | `Unknown` | comma-separated: Malicious, Suspicious, Spam, Bulk, Low Risk, False Negative, Known Good, Unknown (case-sensitive) |
| `sub_disposition` | empty | Needs Manual Review, Likely Harmless; applied on top of `abuse_disposition` and exists only under Unknown, so with Unknown excluded it matches nothing |
| `poll_hours` | `1` | first-poll lookback; a window over 30 days (TRAP's limit) is split into 30-day calls |
| `recheck_days` | `30` | how long after creation an ingested incident is rechecked for changes; `0` = no recheck |
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
(not after Poll Now). Each scheduled poll starts 5 minutes before it (1.0.43+): the checkpoint is
SOAR's clock while TRAP filters on its own `created_at`, so a TRAP clock up to 5 minutes behind, the
boundary second or a late TRAP commit cannot drop an incident. A re-listed incident is a duplicate
(same `source_data_identifier`) and creates nothing; a case deleted within those 5 minutes is
created again.

**Recheck (1.0.41+).** The connector keeps each case it ingests in its state, with a signature of
the incident's state and Event Info fields. After ingesting, each scheduled poll lists new and open
incidents created in the last `recheck_days` and incidents closed since the last recheck. When a
tracked incident changed (a new alert, a field edit, a close in TRAP), it adds an **Event Info
Update** artifact to the case: the Event Info fields plus `recheckTime`, severity `low`,
`run_automation: true`. Rules:

- a case closed in SOAR gets no update; its change is recorded;
- a case created or updated less than 10 minutes ago waits for the next poll;
- an incident closed in TRAP gets its last update and is no longer tracked, as is one older than
  `recheck_days` or whose case was deleted;
- a listing failure fails the poll, keeps what it ingested and changes nothing in the state;
- Poll Now ingests and tracks but does not recheck;
- cases ingested before 1.0.41 are not tracked: the connector cannot look up existing cases.

Replaces the UC2 playbook `proofpoint_trap_recheck`: on a target upgrading from it, delete it with its Timer
asset and custom list (both active would add an update per change).

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

**Missed incidents.** 1.0.42 and older start each poll exactly at the checkpoint, so an incident
whose `created_at` is already behind it when it becomes visible is never listed; 1.0.43 overlaps
by 5 minutes (above). `tools/trap_poll_gap_check.py` (read-only, Python standard library, credentials from
environment variables) prints the TRAP and SOAR clock offsets, whether TRAP lists an incident at
the exact boundary second, and every incident matching the dispositions that has no case.

| Symptom | Cause | Fix |
|---|---|---|
| No incidents ingested | filters, or no label | check `poll_state` / `abuse_disposition` / `sub_disposition` against TRAP; select the label in Ingest Settings |
| Poll failed: `ingest failed for incident(s) <ids>` (1.0.42+) | SOAR refused the case or its Event Info (reason in the poll's progress lines) | the checkpoint has moved on, so the poll will not retry: fix the cause, delete any case left without Event Info, then Poll Now with a `poll_hours` window covering the incident |
| `add comment` → HTTP 500 `Null detail` | 1.0.37 or older sent no `detail` | upgrade to 1.0.38+ |
| `list incidents` → `unsupported type for timedelta` | `hours_back` as text, 1.0.33 or older | upgrade to 1.0.34+ |
| `download mime body` → `Event <id> not found` on every event | 1.0.34 or older used a path the appliance does not have | upgrade to 1.0.35+ |
| `download mime body` → `Container None does not exist` | 1.0.35 run from the action panel | upgrade to 1.0.36+, or run it from a case |
| `download mime body` → `No original message for event <id> (HTTP 404)` | not an alert id, or the alert has no email | check the event's `source` in `get incident`; other events still download |
| `download mime body` → `Unexpected response ... text/html` | `base_url` reaches a web page (login, proxy) | fix `base_url` |
| Timeouts | large responses | raise `timeout` |

### `update team and assignee` — testing directly against TRAP

The endpoint exists on TRAP 6.x only. Run from any host that reaches TRAP (the SOAR host works).
Without `Accept: application/json` the appliance answers every call, a GET too, with 404 "unable to
route request, must be get or post":

```bash
BASE_URL="https://trap.example.com"   # asset base_url
API_KEY="<api key>"                   # asset api_key
INCIDENT_ID="134"; ASSIGNEE="kiki"; TEAM="tata"   # a real incident, TRAP user and team

curl -sSk -X POST -H "Authorization: ${API_KEY}" -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -d "{\"assignee\": \"${ASSIGNEE}\", \"team\": \"${TEAM}\"}" \
  "${BASE_URL}/api/incidents/${INCIDENT_ID}/team_and_assignee.json" -w '\nHTTP %{http_code}\n'
```

| Response | Meaning |
|---|---|
| `200` | updated |
| `404` "unable to route request, must be get or post" | TRAP 5.x (no such route), or no `Accept: application/json` |
| `404` "the previous team and assignee are same" | nothing to change (the connector reports success) |
| `404` "no assignee found for <name>" | not a TRAP user |
| `400` "Both team and assignee are required" | one of the two missing |
| `400` `ConstraintViolationException` | rejected by TRAP's database for every real change, from curl as from the connector; unexplained. If the same change fails in TRAP's own web UI, it is an appliance defect for Proofpoint support |

An untested alternative write path is `set incident field value`
(`/api/incidents/{id}/incident_fields.json`), a different server-side code path:

```bash
curl -sSk -X POST -H "Authorization: ${API_KEY}" -H "Content-Type: application/json" \
  -H "Accept: application/json" \
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

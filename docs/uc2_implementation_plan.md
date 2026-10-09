# Proofpoint TRAP Incident Triage (UC2) — Implementation Plan

Current design. How it got here (every dated change, test and investigation): `uc2_history.md`,
not shipped in the handover. Open work: the Splunk project's `docs/next-steps.md` (not shipped).

## Scope

- Every TRAP incident the connector's `on_poll` ingests becomes a SOAR case. The ingest filter
  (asset `abuse_disposition`) covers Unknown, Suspicious, Malicious, Spam, Bulk and Low Risk — not
  phishing only.
- Automation enriches and triages each case; analysts acknowledge it, close it and send themselves
  isolation-browser links. Nothing contains or blocks automatically.
- Out of scope: reputation lookups of attachments or URLs (a future MISP use case can read the
  `Email Attachment` hashes), SIEM forwarding, bulk triage, mailbox search or purge (the
  appliance has only the IMAP and SMTP mail apps).

## Architecture

| Playbook | Type | Label | Active | Role |
|---|---|---|---|---|
| `proofpoint_trap_orchestrator` | automation | `proofpoint_trap` | **yes** | Runs PB1 → PB3 → PB2 → PB8, each after the previous one finishes |
| PB1 `proofpoint_trap_detail` | automation | `proofpoint_trap` | no | Incident detail, emails, event artifacts, detail note |
| PB3 `proofpoint_trap_attachments` | automation | `proofpoint_trap` | no | Email Content notes, attachments, Cc |
| PB2 `proofpoint_trap_triage` | automation | `proofpoint_trap` | no | Severity, verdict tag, severity note |
| PB8 `proofpoint_trap_summary` | automation | `proofpoint_trap` | no | TRAP Summary note; closes the case when TRAP has closed the incident |
| PB4 `proofpoint_trap_acknowledge` | data | `proofpoint_trap` | — | Analyst: comment, assign to SOAR, set open in TRAP |
| PB5 `proofpoint_trap_close` | data | `proofpoint_trap` | — | Analyst: close in TRAP with a reason |
| PB6 `proofpoint_trap_isolation_notify` | data | `proofpoint_trap` | — | Analyst: email isolation-browser links |
| PB7 `proofpoint_trap_recheck` | automation | `proofpoint_trap_recheck` | **yes** | Timer-driven: finds ingested incidents that changed |
| CF `proofpoint_trap_extract_incident_id` | custom function | — | — | Incident ID + TRAP Severity from the latest Event Info (Update); used by PB2/PB4/PB5/PB6 |

```
TRAP on_poll ─► case "TRAP-<id>: <summary>" + Event Info artifact   (label proofpoint_trap)
                 │
                 ▼
       proofpoint_trap_orchestrator  (synchronous playbook blocks)
         1. PB1 detail       get incident, download mime body → event artifacts, detail note,
                             Enrichment Complete; TRAP comment on the first enrichment
         2. PB3 attachments  Email Content note, Email Attachment + Cc artifacts per email
         3. PB2 triage       severity, verdict tag, severity note
         4. PB8 summary      TRAP Summary note; close once if TRAP closed the incident

Timer asset (15 min) ─► case on label proofpoint_trap_recheck ─► PB7 recheck
         list incidents (new, open, closed; last 168 h) → changed + already ingested →
         MIME Body + Event Info Update on that incident's case → the orchestrator runs again

Analyst ─► PB4 acknowledge │ PB5 close │ PB6 isolation notify
```

Rules behind this shape (detail in `docs/vpe-dev/constraints.md`):

- **One active orchestrator.** Automation playbooks on one label start together on the same
  trigger and race. The four children stay inactive (an active child would also start on its
  own trigger), and no artifact a child writes runs automation, or it would start a second
  orchestrator run. The one exception is PB7's `Event Info Update`, which is meant to.
- **A VPE save never breaks a playbook.** Importers re-point action blocks to their own assets,
  which is a save. All logic sits inside Custom Code (module-level code in Global Custom Code); a
  per-item action rebuilds its `parameters` in its own Custom Code; PB4/PB5 raise their prompts
  from code blocks; alternative paths have their own blocks (PB5 `add_expired_note`); the data
  playbooks declare inputs and outputs. A save resets a data playbook's label to `*`, so each one
  stops cleanly on a case that is not TRAP's.
- **Severity holds.** A new or updated artifact raises a lower case severity to its own, and
  artifacts default to `medium`. Every REST artifact write carries `"severity": "low"`, and PB2
  runs after the last native artifact write.
- **Notes.** Markdown (`note_format="markdown"`), at most 20,000 characters (the appliance cuts at
  about 22,000; longer content is split into "Title (k/N)"), and every untrusted URL in backticks
  so it is not clickable. Only "Open in TRAP" and PB6's isolation links stay links.
- **The connector is a thin API wrapper.** State that must survive between runs (PB7's
  signatures) lives in a custom list owned by the playbook.

## Playbooks

### Orchestrator — `proofpoint_trap_orchestrator`

Four synchronous playbook blocks (`run_detail`, `run_attachments`, `run_triage`, `run_summary`),
no logic of its own. It runs at ingest and on every `Event Info Update`; each child decides for
itself whether there is work.

### PB1 — `proofpoint_trap_detail`

- **Guard** (`check_reentry`): runs when the case has no `Enrichment Complete` yet, or has at least
  as many `Event Info Update` as `Enrichment Complete` artifacts. `Enrichment Failed` is not
  counted, so a failed run is retried.
- **Fetch:** `get incident` (events expanded) and `download mime body` (every event, vaulted).
- **Artifacts** (`build_artifact_list` → `dispatch_artifact_list`, one `add artifact` per item,
  `determine_contains: False`): see Data model. Rules:
  - An address in `proofpoint_trap_excluded_email` (enabled rows) gets no artifact and never names
    the case.
  - An abuse-mailbox report lists each email twice: `abuseCopy: true` is the report, `false` the
    reported email. When both are there, the report's sender, recipient and Cc are skipped. The
    `X-PhishAlarm-Reporter` becomes a `Recipient Email` with role `reporter`.
  - When TRAP gives the report alone and it carries `X-PhishAlarm-Sender`, that header's address is
    the `Sender Email` (`senderSource: X-PhishAlarm-Sender`). The appliance writes it as
    `"Name <addr>` with an unclosed quote, which `parseaddr` misreads, so `_header_address()` takes
    the address inside the last `<…>` first.
  - An alert whose email could not be downloaded (now and on every earlier run) gets
    `Email Attachment` artifacts from TRAP's own attachment list, with PB3's identifier.
  - Only artifacts not already on the case are posted (same name and identifying value).
- **Case name:** a case TRAP gave no summary (`TRAP-<id>: No summary`) is renamed after its first
  remaining sender, `+N more` when there are several.
- **Detail note** `TRAP Detail - Incident <id>`: Open in TRAP link, summary, state, score, events,
  alerts processed, artifacts new / already present.
- **Enrichment Complete:** `message`, `alertCount`, `eventCount`, `artifactsCreated`,
  `artifactsAlreadyPresent`, `runIndex`, `incidentState`, `threatNames`.
- **TRAP comment** on the first enrichment only: the case link (SOAR base URL + `/mission/<id>`)
  in `detail`, which TRAP requires.
- **Failures:** a failed fetch or platform write adds a `TRAP Detail - Error` / `- Write failures`
  note and an `Enrichment Failed` artifact instead of `Enrichment Complete`.

### PB3 — `proofpoint_trap_attachments`

For each `MIME Body` not yet marked processed (`data.attachments_extracted`):

- reads the `.eml` over REST (`download_attachment`), never from the filesystem;
- posts an `Email Content — <file>` note: From/To/Subject/Date, Return-Path (flagged when it differs
  from From), Reply-To, X-Originating-IP, In-Reply-To, X-PhishAlarm-Sender, Received-SPF,
  DKIM-Signature, Authentication-Results, the Received chain, and the body as safe markdown
  (`_email_html_to_markdown`: scripts and styles dropped, images as placeholders, links defanged
  in code spans with URL Defense decoded, a ⚠ when link text names another host, hidden text and
  forms flagged);
- vaults each attachment (forwarded `message/rfc822` included) as an `Email Attachment` artifact
  with SHA256, MD5, size, type and a MIME-type mismatch flag;
- adds a `Recipient Email` (role `cc`) per Cc address not excluded;
- marks the `MIME Body` processed, at `low`;
- ends with one `Attachment Extraction` note.

### PB2 — `proofpoint_trap_triage`

Sets the case severity to the higher of two mappings, read from the latest `Event Info` /
`Event Info Update`:

| Source | high | medium | low |
|---|---|---|---|
| TRAP Severity | Critical | High | Informational, anything else |
| CLEAR verdict (disposition / sub-disposition) | Malicious | Suspicious, False Negative, Unknown, Unknown / Needs Manual Review | Unknown / Likely Harmless, Bulk, Spam, Low Risk, Known Good |

There is no `critical` on SOAR here. `high` is kept for TRAP's Critical, and anything unmapped
falls to `low`, so ambiguous incidents do not look urgent. The verdict becomes one tag
`trap-<verdict>` (e.g. `trap-malicious`, `trap-needs-manual-review`), replacing an earlier verdict
tag and never touching an analyst's tags. A `TRAP Triage - Severity` note is written when the
severity first applies or changes; its first line `**Severity: `old` -> `new`**` is what the next
run compares against. No writes to TRAP.

### PB8 — `proofpoint_trap_summary`

Skips until `Enrichment Complete` or `Enrichment Failed` exists. Writes one `TRAP Summary` note:
the CLEAR verdict and the alerts' threat names, then a table per artifact type (incident, senders,
recipients, domains, URLs, click IPs, MIME bodies, attachments, enrichment runs, any other type),
at most 250 rows each. Sender Email takes two tables, both led by Address (one Sender Email per
address): the message fields, then `Sender Email headers`. Later runs rewrite the same note(s) in place; parts no longer needed are
blanked as `TRAP Summary (unused)`, since a playbook cannot delete a note. When the newest
`Enrichment Complete` says `incidentState: closed`, it closes the case once and adds a
`Closed in TRAP` note; a case an analyst reopens stays open.

### PB4 — `proofpoint_trap_acknowledge` (data)

Inputs `approver` (default: the case owner, else `soar_local_admin`) and `respond_in_mins`
(default 30). Prompts for a comment, then `update team and assignee` (assignee SOAR),
`set incident field value` (state open) and `add comment`, and a `TRAP Acknowledge` note. Outputs
`status` (success / partial / failed), `incident_id`, `comment`. **On hold:** it sends `assignee`
only while the connector requires `team` too, so SOAR refuses that step on every run.

### PB5 — `proofpoint_trap_close` (data)

Same inputs as PB4. Prompts for a reason; approved → `close incident`, `add comment` (says whether
the close succeeded), a `TRAP Close` note, and the case is closed when TRAP closed. Expired or
rejected → `add_expired_note` only, no TRAP action. Outputs `status`
(success / partial / failed / expired), `incident_id`, `reason`.

### PB6 — `proofpoint_trap_isolation_notify` (data)

Input `isolation_browser_url` (default placeholder `https://www.domain.tld/browser?url=`; set the
real prefix). Requires the case to have an owner and status `open`; the owner's email comes from
`GET /rest/ph_user?_filter_username=` (inside a playbook `container['owner']` is the username).
One link per target — the case URL and each `Threat Domain` `cef.url` — as prefix +
`urllib.parse.quote(target, safe="")` (URL encoding, not base64). Sends `TRAP Incident <id> -
Isolation Browser Links` through the `smtp` asset and lists the links in a `TRAP Isolation Notify`
note. Outputs `status`, `incident_id`, `recipient_email`, `link_count`.

### PB7 — `proofpoint_trap_recheck`

Runs on each Timer tick. `list incidents` with one parameter set per state (`new`, `open`,
`closed` — SOAR drops an empty `state`, so "all" cannot be sent) over the last 168 hours. Each
incident's signature (state + the Event Info fields) is compared with custom list
`proofpoint_trap_recheck_state`:

- unseen incident → recorded, not rechecked (so the first tick does not re-enrich the backlog);
- changed and already a case → `download mime body`, then on that case a `MIME Body` per event not
  already there and an `Event Info Update` (`run_automation: True`, incident id typed
  `proofpoint trap incident id`), which re-runs the orchestrator;
- changed with no case yet → left pending until `on_poll` ingests it.

The signature code mirrors the connector's Event Info CEF; keep both in sync. Writes go over REST
with an explicit `container_id`, because the run's own case is the Timer's.

## Data model

Every artifact is labelled `event`. Free-text fields stay untyped; artifact `type` is left unset.

| Artifact | Key CEF fields (data type) | Written by |
|---|---|---|
| Event Info | `incidentId` (`proofpoint trap incident id`, connector 1.0.39+), `abuseDisposition`, `subDisposition`, `classification`, `trapSeverity`, `threatScore`, `eventIds`, `message` | connector `on_poll` |
| Event Info Update | same fields | PB7 |
| Sender Email | `emailAddress` (email), `emailRole: sender`, `senderSource`, `emailSubject`, `messageId` / `inReplyTo` (internet message id), `deliveryTime`, `bodyType`, `abuseCopy`, `emailHeaders`, `receivedSpf`, `dkimSignature`, `received`, `phishAlarmSender` | PB1 |
| Sender Domain | `sourceDnsDomain` (domain) | PB1 |
| Recipient Email | `emailAddress` (email), `emailRole`: `recipient`, `cc`, `reporter` | PB1, PB3 (cc) |
| Threat Domain | `destinationDnsDomain` (domain), `url` (url) | PB1 |
| URL Artifact | `requestURL` (url), from the incident's `hosts.url` | PB1 |
| Click Source IP | `sourceAddress` (ip) | PB1 |
| MIME Body | `vaultId` (vault id), `fileName` (file name); identifier `trap-<incident>-mime-<event>` | PB1, PB7 |
| Email Attachment | `vaultId`, `fileName`, `fileHashSha256` (sha256), `fileHashMd5` (md5), `fileSize`, `fileType`, `attachmentSource`, `mimeTypeMismatch` | PB3, PB1 (TRAP's list, no file) |
| Enrichment Complete / Failed | see PB1 | PB1 |

**TRAP API facts** (Proofpoint's own Incident API doc for Threat Response 5.12, behind their portal
login; the appliance where noted):

- States: `new`, `open`, `closed`. Dispositions (case-sensitive): Malicious, Suspicious, Spam, Bulk,
  Low Risk, False Negative, Known Good, Unknown. Sub-dispositions (Needs Manual Review, Likely
  Harmless) exist only under Unknown; asking for one with another disposition is a 400.
- A `created_*` / `closed_*` window is at most 30 days; the connector splits longer polls into
  720-hour chunks.
- `events[].emails[]`: `sender.email`, `recipient.email`, `subject`, `messageId`,
  `messageDeliveryTime` (a string or a Joda-time object), `bodyType`, `headers`, `urls`,
  `attachments`, `abuseCopy`. A reported-by-user incident has no click IP or event-level threat
  URL; `hosts` holds only `url`; `summary` is often empty.
- The doc marks fields optional that the appliance requires: `add comment` needs `detail` (else
  HTTP 500 "Null detail"), and `team` and `assignee` travel together.
- The original email: `GET /api/v1/alerts/{alert_id}/download_original_msg`
  (`Accept: message/rfc822`), where alert id = `events[].id`.
- Third-party docs (Swimlane) are wrong on several of these points; check Proofpoint's own.

## Setup Guide

1. **Connector:** install the Proofpoint TRAP app.
2. **Assets** — the playbooks ship pointed at these names; keep them, or re-point each action
   block in the VPE and save:

   | Asset | App | Settings |
   |---|---|---|
   | `proofpoint_trap_mock` | Proofpoint TRAP | `base_url`, `api_key`, `verify_ssl`; ingest label `proofpoint_trap`, polling on; `poll_state` `new`, `abuse_disposition` `Unknown,Suspicious,Malicious,Spam,Bulk,Low Risk`, `sub_disposition` empty (only meaningful with Unknown), `severity`/`sensitivity` defaults `low`/`amber` |
   | `soar8` | Phantom (SOAR) | Its automation user needs the `Automation` role, or every PB1 write returns 403 |
   | `smtp` | SMTP | PB6 only |

3. **Timer asset** `proofpoint_trap_recheck`: every 15 minutes, container label
   `proofpoint_trap_recheck` (creating the asset creates the label).
4. **Custom lists:**
   - `proofpoint_trap_recheck_state` — create it empty and leave it alone; PB7 owns it
     (`incident_id`, `signature`).
   - `proofpoint_trap_excluded_email` — `email`, `date` (DD/MM/YYYY), `reason`, `enabled`
     (`yes` applies the row). For addresses on every incident; ships with example rows only.
5. **Import** the CF (*Import Custom Function*), then the playbooks.
6. **Activate** `proofpoint_trap_orchestrator` and `proofpoint_trap_recheck`; leave PB1, PB2,
   PB3 and PB8 inactive. **Run As:** leave the default (the automation user). After any redeploy,
   read the active flags back: a redeploy keeps each playbook's own state.
7. **SOAR base URL** (Administration > Company Settings) must be the address analysts open: PB1's
   TRAP comment and PB6's case link are built from it.

## Verification

- **Lab mock:** the TRAP mock (`soar8/migration/mock-backend/mock_api_gateway.py`, kept identical
  to `soar-connectors/test/`) serves seed incidents 1001-1015. A restart anchors the latest seed's
  `created_at` at now-30s, so date a new seed after the latest one or the poll never sees it;
  restart only once the deploy is confirmed live (new ids), or the old playbooks ingest the seed.
  Admin routes: `GET /_admin/trap/incidents`, `POST /_admin/trap/reset`,
  `POST /_admin/trap/add_event`.
- **New incident:** one orchestrator run with four successful children; the detail note and the
  artifacts; an Email Content and an Attachment Extraction note; a severity note matching the
  mapping and the case at that severity; one TRAP Summary; a comment on the TRAP incident.
- **Change:** add an event to an ingested incident (`add_event`) → within one Timer tick an
  `Event Info Update`, one more orchestrator run, PB1 posting only the new artifacts. To skip the
  wait, poll the Timer asset now: `POST /rest/action_run` with `action: "on poll"`,
  `type: "ingest"` and target asset `proofpoint_trap_recheck` (Timer app).
- **Data playbooks:** run each with its inputs over REST (`POST /rest/playbook_run` with
  `inputs`) and read `outputs` back; answer prompts in the GUI.
- **Logs** on the SOAR host (as `phantom`): `spawn.log` (playbooks), `actiond.log` (actions),
  `decided.log` (code blocks).

## Known limitations

- Field names follow this UC (`emailAddress`, `messageId`, `emailSubject`), not the names community
  phishing playbooks read (`fromEmail`, `toEmail`, `emailHeaders.*`).
- Lab only: about 309 cases ingested before 2026-09-22 were never enriched (no backfill).

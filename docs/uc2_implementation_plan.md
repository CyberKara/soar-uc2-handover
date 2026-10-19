# Proofpoint TRAP Incident Triage (UC2) — Implementation Plan

Current design. How it got here (every dated change, test and investigation): `uc2_history.md`
(Part 4 holds the design before the 2026-10-15 rework, `uc2_rework_plan.md` the rework itself),
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
| `proofpoint_trap_orchestrator` | automation | `proofpoint_trap` | **yes** | Runs PB1 → PB2 → PB3 → PB4 → PB6, each after the previous one finishes |
| PB1 `proofpoint_trap_detail` | automation | `proofpoint_trap` | no | Incident-level artifacts, case name, Enrichment Complete, TRAP Run State, detail note |
| PB2 `proofpoint_trap_attachments` | automation | `proofpoint_trap` | no | Each alert's email once: attachments, Cc, Email Content and Attachment Extraction notes |
| PB3 `proofpoint_trap_triage` | automation | `proofpoint_trap` | no | Severity, verdict tag, severity note |
| PB4 `proofpoint_trap_summary` | automation | `proofpoint_trap` | no | TRAP Summary note |
| PB5 `proofpoint_trap_isolation_notify` | automation | `proofpoint_trap` | no | Analyst: email isolation-browser links |
| PB6 `proofpoint_trap_comment_add_link_to_soar_case` | automation | `proofpoint_trap` | no | TRAP comment linking the case, once |
| PB7 `proofpoint_trap_acknowledge` | automation | `proofpoint_trap` | no | Analyst: comment, assign the TRAP team and assignee, set open in TRAP |
| PB8 `proofpoint_trap_close` | automation | `proofpoint_trap` | no | Analyst: close in TRAP with a reason, then the case |
| PB9 `proofpoint_trap_recheck` | automation | `proofpoint_trap_recheck` | **yes** | Timer-driven: finds ingested incidents that changed |
| CF `proofpoint_trap_extract_incident_id` | custom function | — | — | Incident ID + TRAP Severity from the latest Event Info (Update) |
| CF `proofpoint_trap_note_upsert` | custom function | — | — | Writes a note by title, updated in place |
| CF `container_update` | custom function (Splunk community) | — | — | Case name, severity, tags in one call |

```
TRAP on_poll ─► case "TRAP-<id>: <summary>" + Event Info artifact   (label proofpoint_trap)
                 │
                 ▼
       proofpoint_trap_orchestrator  (synchronous playbook blocks)
         1. PB1 detail        get incident → new incident-level artifacts, case name,
                              Enrichment Complete, TRAP Run State, detail note
         2. PB2 attachments   per alert with no MIME Body: download → attachments, Cc,
                              Email Content note; MIME Body last (the alert's done mark)
         3. PB3 triage        severity + verdict tag, severity note
         4. PB4 summary       TRAP Summary note
         5. PB6 comment link  TRAP comment with the case link, once

Timer asset (15 min) ─► case on label proofpoint_trap_recheck ─► PB9 recheck
         list incidents (new, open, closed; last 168 h) → changed + already ingested →
         find artifacts (incidentId) → Event Info Update on that case → the orchestrator runs again

Analyst ─► Run Playbook on the case ─► PB5 isolation notify │ PB7 acknowledge │ PB8 close
```

Rules behind this shape (detail in `docs/vpe-dev/constraints.md`):

- **Every run handles every alert, without duplicates.** A child started by the orchestrator runs
  in scope "all" (measured), so there is no scope-"new" filter. PB1 posts only artifacts not on the
  case yet and skips an identical Enrichment Complete (an identical `add artifact` fails "400
  artifact already exists"); PB2 skips alerts that already have a MIME Body. A failed run is
  completed by the next run or a manual re-run in any scope.
- **One note per kind, updated in place.** Every recurring note goes through
  `proofpoint_trap_note_upsert`: unchanged content → nothing, changed → updated over REST (no native
  note update; a playbook user may not delete a note), none → created. Earlier versions are
  overwritten. Over 20,000 characters (the appliance cuts at about 22,000) → parts "Title (k/N)",
  leftovers blanked as "Title (unused)".
- **One active orchestrator.** Automation playbooks on one label start together on the same
  trigger and race; the five children stay inactive, and no artifact a child writes runs
  automation. The exception is PB9's `Event Info Update`, which is meant to.
- **Analyst playbooks are inactive automation playbooks.** A case's *Run Playbook* lists
  automation playbooks only (active or not), never Input ones.
- **A VPE save never breaks a playbook**, and an unchanged save keeps its id: the repo `.py` is
  exactly what the VPE generates (`tools/check_vpe_shape.py` compares it with a port of the VPE
  generator). Logic lives in Custom Code; a per-item action rebuilds its `parameters` there.
- **Severity holds.** A new or updated artifact raises a lower case severity to its own, and the
  native "add artifact" has no severity (`medium`); PB3 runs after every artifact write. Artifact
  updates carry `low`.
- **Notes** are markdown and keep every untrusted URL in backticks (not clickable). Only "Open in
  TRAP" and PB5's isolation links stay links.
- **REST only where no native block exists:** PB2's two Vault transfers (`download_attachment`,
  `container_attachment`), PB5's `ph_user` read, the note update in `proofpoint_trap_note_upsert`.

## Playbooks

### Orchestrator — `proofpoint_trap_orchestrator`

Five synchronous playbook blocks (`run_detail`, `run_attachments`, `run_triage`, `run_summary`,
`run_comment_link`), no logic of its own. It runs at ingest and on every `Event Info Update`.

### PB1 — `proofpoint_trap_detail`

`filter event info` (scope all) → `get trap incident` → `build artifact list` → `rename case`
(`container_update`) → `dispatch artifact list` (one `add artifact` per item, `determine_contains:
False`) → `finalize detail` → `dispatch enrichment complete` → `detail note` (note upsert).

- **Artifacts:** see Data model. An address in `proofpoint_trap_excluded_email` (enabled rows) gets
  no artifact and never names the case. An abuse-mailbox report lists each email twice
  (`abuseCopy: true` = the report): the report's sender and recipient are skipped and
  `X-PhishAlarm-Reporter` becomes a `Recipient Email` (role `reporter`). A report TRAP gives alone
  with `X-PhishAlarm-Sender` names the `Sender Email` from that header (`senderSource`); the
  appliance writes it as `"Name <addr>` with an unclosed quote, so `_header_address()` takes the
  address inside the last `<…>` first. Only artifacts not on the case (same name and identifying
  value) are posted.
- **Case name:** a case TRAP gave no summary (`TRAP-<id>: No summary`) is renamed after its first
  remaining sender, `+N more` when there are several; blank changes nothing.
- **TRAP Run State** is created once (`linkComment: none`, severity `low`).
- **Enrichment Complete** holds the incident's facts only (`message`, `alertCount`, `eventCount`,
  `incidentState`, `threatNames`): identical content is skipped, a change of TRAP state, alerts or
  threats adds one.
- **Detail note** `TRAP Detail - Incident <id>`: Open in TRAP link, summary, state, score, events,
  alerts.
- **Failures:** a failed fetch or artifact write adds a `TRAP Detail - Error` / `- Write failures`
  note and an `Enrichment Failed` artifact and stops.

### PB2 — `proofpoint_trap_attachments`

`filter event info` → `get trap incident` → `download mime body` (Custom Code: one per alert with
no MIME Body) → `read emails` → `add attachments and cc` → `upgrade attachments` → `add notes` (note
upsert, one parameter set per note) → `add mime bodies`.

- **Download OK:** reads the `.eml` over REST, vaults each attachment (forwarded `message/rfc822`
  included) as an `Email Attachment` (SHA256, MD5, size, type, MIME-type mismatch flag), adds each
  Cc of the email as a `Recipient Email` (role `cc`), writes an `Email Content — <file>` note:
  From/To/Subject/Date, Return-Path (flagged when it differs from From), Reply-To,
  X-Originating-IP, In-Reply-To, X-PhishAlarm-Sender, Received-SPF, DKIM-Signature,
  Authentication-Results, the Received chain, and the body as safe markdown
  (`_email_html_to_markdown`: scripts and styles dropped, images as placeholders, links defanged
  in code spans with URL Defense decoded, a ⚠ when link text names another host).
- **Download failed:** TRAP's own attachment list (no file, `attachmentSource: TRAP API`) and TRAP's
  Cc header; no MIME Body, so the next run tries again, and a later success upgrades those
  attachments in place (`update artifact`, severity `low`).
- A Cc is identical on both paths and skipped when its address is already on the case; a report
  gets no Cc; `proofpoint_trap_excluded_email` applies.
- **Attachment Extraction** note: one per case, every attachment with its event and source.
- **MIME Body** (`vaultId`, `fileName`, `eventId`) is written last: the alert's done mark.

### PB3 — `proofpoint_trap_triage`

`extract incident id` → `compute verdict` → `update case` (`container_update`: severity + the
full tag list as `input_json`) → `severity note` (note upsert). The severity is the higher of two
mappings, read from the latest `Event Info` / `Event Info Update`:

| Source | high | medium | low |
|---|---|---|---|
| TRAP Severity | Critical | High | Informational, anything else |
| CLEAR verdict (disposition / sub-disposition) | Malicious | Suspicious, False Negative, Unknown, Unknown / Needs Manual Review | Unknown / Likely Harmless, Bulk, Spam, Low Risk, Known Good |

There is no `critical` on SOAR here; anything unmapped falls to `low`. The verdict becomes one tag
`trap-<verdict>` (e.g. `trap-malicious`), replacing an earlier verdict tag; an analyst's tags are
kept. The note holds only the result, so it changes only when the severity or verdict does. No
writes to TRAP.

### PB4 — `proofpoint_trap_summary`

`build summary` → `summary note` (note upsert). Skips until `Enrichment Complete` or `Enrichment
Failed` exists. Reads every artifact through datapaths (`artifact:*.create_time` reads as an epoch
number). The note: the CLEAR verdict and the alerts' threat names, then a table per artifact type
(incident, senders, recipients, domains, URLs, click IPs, MIME bodies, attachments, enrichment runs,
any other type; `TRAP Run State` left out), at most 250 rows each. Sender Email takes two tables,
both led by Address. No timestamp, so an unchanged case leaves the note alone.

### PB5 — `proofpoint_trap_isolation_notify`

`extract incident id` → `isolation browser url` (format block: set the real prefix there,
placeholder `https://www.domain.tld/browser?url=`) → `build links` → `send isolation email`.
The email goes to the analyst who launched it (`playbook:launching_user.name`, email from
`GET /rest/ph_user?_filter_username=`); no case owner or status needed.
One link per distinct threat URL — `Threat Domain` `cef.url` (URLs in the emails) and `URL Artifact`
`cef.requestURL` (the incident's `hosts.url`) — as prefix + `urllib.parse.quote(target, safe="")`; a
Microsoft Safe Links URL is unwrapped first. HTML email `TRAP Incident <id> - Isolation Browser
Links` through the `smtp` asset: its first line links directly to the case, each threat URL is
shown defanged beside its isolation link. The send action's result is the record on the case (no
note). Error paths (no email for the launching analyst, blank prefix, no threat URL) add a note. Outputs `status`,
`incident_id`, `recipient_email`, `link_count`. The receiving Exchange still wraps the email's
links in Safe Links unless the tenant's policy lists the isolation-browser and SOAR hosts under
"Do not rewrite the following URLs".

### PB6 — `proofpoint_trap_comment_add_link_to_soar_case`

`extract incident id` → `run state` (filter) → `not posted` (decision on `linkComment`) →
`add comment` (TRAP; `detail` = SOAR base URL + `/mission/<id>`, which TRAP requires) →
`comment ok` → `update state` (`linkComment: posted`, severity `low`). A failed comment is retried
on the next run.

### PB7 — `proofpoint_trap_acknowledge`

`extract incident id` → `prompt comment` (native prompt to the analyst who launched it, 6
hours) → `answered` → `trap team` → `trap assignee` (format blocks: set a team that exists in
TRAP and one of its users, both preset `SOAR`; TRAP requires team and assignee together) →
`update incident assignee` → `set incident open` → `add trap comment` (the answer) → `add note`
(`TRAP Acknowledge`: the comment and each TRAP result). Unanswered → nothing done, no note.

### PB8 — `proofpoint_trap_close`

`extract incident id` → `prompt close reason` (native prompt to the analyst who launched it, 6
hours) → `approved` → `close trap incident` (`summary` + the reason as `detail`, both required)
→ `add note` (`TRAP Close`: reason and TRAP's result) → `trap closed` → `set status` (closed).
Unanswered → nothing done, no note. The case is closed only when TRAP closed the incident.

### PB9 — `proofpoint_trap_recheck`

`list incidents` (one parameter set per state `new`, `open`, `closed` — SOAR drops an empty
`state`) over the last 168 hours → `process incidents` → `find cases` (Phantom `find artifacts`,
`incidentId`) → `build updates` → `add event info updates`. Each incident's signature (state + the
Event Info fields) is compared with custom list `proofpoint_trap_recheck_state` (`incident_id`,
`signature`):

- unseen incident → recorded, not rechecked (so the first tick does not re-enrich the backlog);
- changed with a case → an `Event Info Update` on that case (`run_automation: True`, incident id
  typed `proofpoint trap incident id`, `recheckTime`), which re-runs the orchestrator;
- changed with a case closed in SOAR → recorded, no update (a closed case runs no automation, and a
  new artifact would only raise its severity);
- changed with no case yet → left pending until `on_poll` ingests it.

The signature code mirrors the connector's Event Info CEF; keep both in sync. Never closes a case
and writes no note.

## Data model

Every artifact is labelled `event`. Free-text fields stay untyped; artifact `type` is left unset.

| Artifact | Key CEF fields (data type) | Written by |
|---|---|---|
| Event Info | `incidentId` (`proofpoint trap incident id`, connector 1.0.39+), `abuseDisposition`, `subDisposition`, `classification`, `trapSeverity`, `threatScore`, `eventIds`, `message` | connector `on_poll` |
| Event Info Update | same fields + `recheckTime` | PB9 |
| Sender Email | `emailAddress` (email), `emailRole: sender`, `senderSource`, `emailSubject`, `messageId` / `inReplyTo` (internet message id), `deliveryTime`, `bodyType`, `abuseCopy`, `emailHeaders`, `receivedSpf`, `dkimSignature`, `received`, `phishAlarmSender` | PB1 |
| Sender Domain | `sourceDnsDomain` (domain) | PB1 |
| Recipient Email | `emailAddress` (email), `emailRole`: `recipient`, `reporter` (PB1), `cc` (PB2) | PB1, PB2 |
| Threat Domain | `destinationDnsDomain` (domain), `url` (url) | PB1 |
| URL Artifact | `requestURL` (url), from the incident's `hosts.url` | PB1 |
| Click Source IP | `sourceAddress` (ip) | PB1 |
| MIME Body | `vaultId` (vault id), `fileName` (file name), `eventId`; identifier `trap-<incident>-mime-<event>` | PB2 |
| Email Attachment | `vaultId`, `fileName`, `fileHashSha256` (sha256), `fileHashMd5` (md5), `fileSize`, `fileType`, `attachmentSource`, `mimeTypeMismatch`; identifier `trap-<incident>-<event>-attachment-<file>-<sha12>` | PB2 |
| Enrichment Complete / Failed | see PB1 | PB1 |
| TRAP Run State | `linkComment` (`none` / `posted`) | PB1 (created), PB6 |

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
   | `soar8` | Phantom (SOAR) | Every artifact write and `find artifacts` (PB1, PB2, PB6, PB8, PB9). Its automation user needs the `Automation` role, or every write returns 403 |
   | `smtp` | SMTP | PB5 only |

3. **Timer asset** `proofpoint_trap_recheck`: every 15 minutes, container label
   `proofpoint_trap_recheck` (creating the asset creates the label).
4. **Custom lists:**
   - `proofpoint_trap_recheck_state` — create it empty and leave it alone; PB9 owns it
     (`incident_id`, `signature`).
   - `proofpoint_trap_excluded_email` — `email`, `date` (DD/MM/YYYY), `reason`, `enabled`
     (`yes` applies the row). For addresses on every incident; ships with example rows only.
5. **Import** the three CFs (*Import Custom Function*): `proofpoint_trap_extract_incident_id`,
   `proofpoint_trap_note_upsert`, `container_update`; then the playbooks.
6. **Activate** `proofpoint_trap_orchestrator` and `proofpoint_trap_recheck` only; leave PB1–PB8
   inactive. **Run As:** leave the default (the automation user). After any redeploy, read the
   active flags back: a redeploy keeps each playbook's own state.
7. **SOAR base URL** (Administration > Company Settings) must be the address analysts open: PB6's
   TRAP comment and PB5's case link are built from it.
8. **Format blocks to set** (open the playbook, edit the block's template, save): PB5
   `isolation browser url`, PB7 `trap team` and `trap assignee`.

## Verification

- **Lab mock:** the TRAP mock (`soar8/migration/mock-backend/mock_api_gateway.py`, kept identical
  to `soar-connectors/test/`) serves seed incidents 1001-1015 and a synthetic incident every 15
  minutes. Admin routes: `GET /_admin/trap/incidents`, `POST /_admin/trap/reset`,
  `POST /_admin/trap/add_event` (an event-level `attachments` list gives a multipart email). The
  mock SMTP (`mock_smtp.py`, port 8446) has no systemd unit: start it by hand for PB5.
- **New incident:** one orchestrator run with five successful children; the artifacts, one TRAP Run
  State, one Enrichment Complete; the detail, Email Content, Attachment Extraction, severity and
  TRAP Summary notes once each; the case at the mapped severity; one comment on the TRAP incident.
- **Re-run:** a second orchestrator run on the same case adds nothing, changes no note and shows no
  failed action.
- **Change:** `add_event` on an ingested incident → within one Timer tick an `Event Info Update` and
  one more orchestrator run: PB1 posts only the new alert's artifacts, PB2 downloads only its email.
- **Analyst actions:** on a TRAP case, *Run Playbook* lists PB5/PB7/PB8; run each and answer its
  prompt. The Run button sends `POST /rest/playbook_run` `{container_id, playbook_id, scope, run}`.
- **Logs** on the SOAR host (as `phantom`): `spawn.log` (playbooks), `actiond.log` (actions),
  `decided.log` (code blocks).

## Known limitations

- Field names follow this UC (`emailAddress`, `messageId`, `emailSubject`), not the names community
  phishing playbooks read (`fromEmail`, `toEmail`, `emailHeaders.*`).
- A note updated in place keeps no earlier version.
- Lab only: about 309 cases ingested before 2026-09-22 were never enriched (no backfill).

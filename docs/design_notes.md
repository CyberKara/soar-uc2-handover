# Design notes

Background that used to sit in the connector and playbook code as long comments: why the pieces are
split the way they are, what was observed about TRAP's and SOAR's real behaviour, and what changed
between versions. The code keeps only the short "why" comments a maintainer needs next to a line;
the rest lives here. Nothing here is needed to import or run the package.

Observations dated below were made against a live TRAP appliance and a SOAR instance during
development. Identifiers from that environment (container and incident numbers, account names) are
left out on purpose.

- [Connector](#connector)
- [Playbooks](#playbooks): orchestrator, detail, attachments, triage, summary, acknowledge, close, isolation_notify, recheck
- [SOAR platform behaviours the code works around](#soar-platform-behaviours-the-code-works-around)

---

## Connector

`connectors/source/proofpoint_trap/`

### What it is, and is not

The connector is kept a thin, generic wrapper around TRAP's API. Anything derived from an incident
(URL artifacts, MIME Body artifacts, sender and recipient artifacts) is built by the playbooks, not
by `on_poll`.

- **URL artifacts** were created per `hosts.url` entry at ingestion by `on_poll`. Moved to
  `proofpoint_trap_detail` on 2026-08-18.
- **MIME Body artifacts** were built by `on_poll` (`_build_mime_artifact`) and moved to
  `proofpoint_trap_detail` on 2026-08-20. Their `source_data_identifier` format,
  `trap-{incident}-mime-{event}`, was kept exactly.
- **Post-ingestion change detection** (`_run_recheck_pass` / `_incident_signature`, state kept in
  `self._state["incident_hashes"]` and `["incident_event_ids"]`) moved to the `proofpoint_trap_recheck`
  playbook on 2026-08-18. `on_poll` is single-pass and checkpoint-only again.
  `_build_event_info_cef` is now used at first ingestion only, and deliberately excludes `hosts.url`
  (the playbook layer derives URL artifacts from its own full incident fetch).

### TRAP API behaviours

- **HTTP 404 is not always "not found".** TRAP also uses it as a business-logic signal: `update team
  and assignee` returns 404 when the requested values already match the incident's current state.
  `_process_response` therefore does not special-case 404. It falls through to the generic non-2xx
  handling, which surfaces the body's `message` / `error` field. `update team and assignee` treats that
  404 as success (same idea as `save_container`'s "duplicate container found"); any other failure
  message, including a bad assignee or a `ConstraintViolationException` from the appliance, passes
  through unchanged. See the connector README's troubleshooting section.
- **Incident-update actions** (`add user to incident`, `update incident description`, `update team and
  assignee`, `set incident field value`) are legacy `/api/incidents/{id}/...` POST endpoints, confirmed
  on 2026-08-12 against the vendor's API reference. `/api/v1/alerts` is GET-only (alert details and
  download of the original message). Earlier versions were built against a guessed
  `PATCH /api/v1/alerts?id={id}` that does not exist in the vendor documentation.
- **Original message download** needs `Accept: message/rfc822` and takes an `events[].id` (an
  incident's events are its alerts). A 200 that is a web page or a JSON body is not a message; storing
  it as `.eml` would hand `proofpoint_trap_attachments` a fake email and report success.
- **`summary` can be an empty string** on real incidents even when the key is present (observed
  2026-08-06). `dict.get`'s default only covers a missing key, so the container name and the Event Info
  artifact use an explicit fallback chain.
- **`event_ids` is present in the lightweight list response** (`expand_events=false`), confirmed
  against real data, so surfacing it needs no extra API call.
- **`get incident` with a wildcard binding.** When `incident_id` (string, list allowed) is bound
  directly to a wildcard artifact datapath such as `artifact:*.cef.incidentId`, SOAR sends one
  comma-joined string, with the literal word `None` for artifacts that lack the field. Observed
  2026-08-13: a container with six artifacts produced `"<id>, None, None, None, None, None"`. It is
  never a real JSON list, so the `isinstance(list)` branch does not fire for that binding. The action
  accepts a single value, a list or a comma-joined string.
- **Date-range cap.** TRAP's on-premises API caps the `created_after` / `created_before` range, hence
  `MAX_POLL_WINDOW_HOURS` and the chunked fetch in `_fetch_and_filter_incidents`.

### Initial severity

`DEFAULT_SEVERITY` / `DEFAULT_SENSITIVITY` only apply when the asset config omits `severity` /
`sensitivity` (same pattern as the stock Timer app). The Event Info artifact carries the raw TRAP
severity as `trapSeverity`; `proofpoint_trap_triage` promotes the container severity from it with
`phantom.set_severity()`, and the Critical / High / Informational mapping lives there, not in the
connector. (An older comment called that field `cs6`; the CEF names are now `abuseDisposition`,
`classification`, `subDisposition`, `threatScore`, `incidentId`, `eventIds`, `trapSeverity`, `message`.)

---

## Playbooks

`playbooks/source/<name>/`

The playbook `.py` files are VPE-generated. A VPE save regenerates `on_start`, the module docstring,
the native prompt blocks, and the banners and `phantom.debug` lines around each block. Anything that
must survive a save therefore lives in a block's custom code or in the Global Custom Code. This is why
several playbooks used to carry a "Design notes" comment block: the docstring is replaced on save. The
notes are below instead.

### Shared conventions

- **Naming.** Older comments refer to playbooks as PB1 to PB8: PB1 `proofpoint_trap_detail`,
  PB2 `proofpoint_trap_triage`, PB3 `proofpoint_trap_attachments`, PB4 `proofpoint_trap_acknowledge`,
  PB5 `proofpoint_trap_close`, PB6 `proofpoint_trap_isolation_notify`, PB7 `proofpoint_trap_recheck`,
  PB8 `proofpoint_trap_summary`. The playbook descriptions in the JSON still use those numbers.
- **Analyst-launched playbooks** (acknowledge, close, isolation_notify) are independent entry points:
  no chaining between them.
- **Signal artifacts** ("Enrichment Complete", "Enrichment Failed", "Event Info Update") are how the
  automation playbooks and `proofpoint_trap_recheck` tell each other what happened. `check_reentry`
  counts them to decide whether a trigger needs an enrichment run.
- **Artifacts carry no severity of their own.** An artifact created without one gets SOAR's default
  (medium) and raises a lower container severity, undoing the mapping `proofpoint_trap_triage`
  applies. Updating an artifact re-applies its severity the same way, so the attachment marker update
  sets the artifact to low.

### proofpoint_trap_orchestrator

Runs `detail`, `attachments`, `triage` and `summary` in that order on every automation trigger of the
container, one after another (each child waits for the previous). Those four playbooks stay inactive
on their own. No automation on the artifacts they create, or a second orchestrator run would start
alongside the first.

### proofpoint_trap_detail

Fetches the incident with its events, downloads each event's original email, and builds the derived
artifacts, the `TRAP Detail` note and the final "Enrichment Complete" artifact. A failed fetch or
platform write adds an error note and an "Enrichment Failed" artifact instead.

- **Failure signal.** Written with the documented synchronous signal-artifact pattern (no asset). It
  has no explicit identifier: SOAR generates one (decision 2026-08-15; accepted tradeoff, a re-run can
  add a duplicate). Named "Enrichment Failed", not "Enrichment Complete", because `check_reentry` only
  counts the latter, so a later run can retry.
- **Local `import`.** Each VPE code block is compiled and linted on its own, so a module-level import
  is invisible to it.
- **`headers`** is a free-form dict per email, contents vary by mail client. Wanted headers are
  matched case-insensitively (the vendor sample shows `MIME-Version`, not `Mime-Version`).
- **`messageDeliveryTime`** is not always a string. A captured response in the XSOAR
  ProofpointThreatResponse test fixtures (2026-08-06) showed a Joda-time-style object,
  `{"millis": 1617103759000, "zone": {...}, "chronology": {...}}`. It is stringified so no raw dict
  reaches a CEF field.
- **Threat URLs.** The connector used to create one "URL Artifact" per `hosts.url` entry; this fetch
  already carries `hosts` and is where the other derived artifacts are built, so it moved here
  (2026-08-18). `hosts.attacker` / `hosts.forensics` were the original guess (mock and Swimlane
  derived) for that object's shape; confirmed absent against real incident data on 2026-08-06, `hosts`
  only ever has `url`.
- **MIME Body artifacts.** Moved here from the connector's `on_poll` on 2026-08-20 (the connector stays
  a thin API wrapper). A failed or empty download means fewer MIME Body artifacts, not a failed
  extraction, like a missing `hosts.url`. The identifier is per event (`trap-{incident}-mime-{event}`),
  not the shared incident id: `proofpoint_trap_attachments` parses the event id back out of it, and a
  shared one would degrade every MIME Body's event id to `?` there.
- **Cc.** A field-by-field walk of a real incident payload (2026-08-06) found no structured `cc` field
  anywhere in the get-incident response. Real cc data exists only in the raw MIME, which
  `proofpoint_trap_attachments` parses. The code path stays as a harmless no-op in case `headers` ever
  carries one.
- **Threat URL domains.** Per-email `urls` list, confirmed 2026-08-06 from the real
  ProofpointThreatResponse integration's source (`get_emails_context`: `email.get("urls")`), not the
  flat event-level field first guessed.
- **Click IP / event-level `threatURL`.** A field-by-field walk of a "reported by user" incident
  (2026-08-06) confirmed neither exists on that source type; `events[]` there is just `{id, emails}`.
  Real TRAP events can also come from a richer "email flow" (Proofpoint TAP) source with more fields
  (category, severity, attackers, per a captured XSOAR fixture). Click or threat data may live there
  under `events[].attackers[].location`; unexplored. Both stay as no-ops since a TAP-sourced incident
  could arrive in principle.

### proofpoint_trap_attachments

Runs after `detail`; it has no trigger of its own. For each "MIME Body" artifact (a vaulted raw
`.eml`) it extracts:

- **File attachments**, each vaulted as an "Email Attachment" artifact (`cef.vaultId`, `fileName`,
  `fileHashSha256`, `fileType`) for analyst review and future reputation enrichment. Forwarded emails
  attached as `message/rfc822` are serialised and vaulted like any attachment; before 2026-08-12 they
  were silently skipped, because `message/rfc822` parts report `is_multipart()=True` and tripped the
  check meant for genuine `multipart/*` wrappers. A MIME-type / filename mismatch
  (`mimetypes.guess_type` versus the declared Content-Type) is flagged as a possible disguised
  executable.
- **Cc recipients**, parsed from the raw headers with `getaddresses` as "Recipient Email" artifacts
  (`emailRole='cc'`). `detail` tries this from the structured response, which real payloads never
  populate, so this is the reliable path.
- **Return-Path versus From mismatch**, a classic spoofing signal, shown in the Email Content note.
- **The rendered body** (HTML preferred, else plain text) and the auth and routing headers
  (Authentication-Results, Reply-To, X-Originating-IP, Received chain), which TRAP's structured API
  does not carry, as an "Email Content" note per event.

How the note is written: `phantom.add_note()` runs content through an undocumented tag allowlist,
probed directly on 2026-08-12. `h1`/`h2`/`p`/`b`/`ul`/`li`/`hr`/`span`/`br` survive;
`pre`/`details`/`summary`/`code`/`div`/`i` are stripped (text kept); `<a href>` keeps the tag but loses
the `href`, so links never work. The Email Content note is therefore a markdown note posted over REST,
and the body is first converted to safe markdown (`_email_html_to_markdown` in the Global Custom Code):
scripts and styles dropped, images as placeholders, links as text plus the defanged target (URL Defense
links decoded), hidden text and forms flagged, all text escaped. Nothing from the email loads or is
clickable.

It re-scans every MIME Body artifact on each run (`scope="all"`: `proofpoint_trap_recheck` may have
created them before the trigger) and skips those carrying `data.attachments_extracted`. The email is
read over REST (`download_attachment` by vault id) and attachments are stored through REST with inline
base64 content, because SOAR's validator flags any filesystem access in a playbook.

### proofpoint_trap_triage and proofpoint_trap_summary

`triage` re-applies the container severity on every trigger (new artifacts arrive at SOAR's default and
raise a lower container severity) and writes a note only when the TRAP-derived severity changes.
`summary` builds one markdown table per artifact type from every artifact on the container and rewrites
its notes in place: a playbook may not delete notes (REST `DELETE` answers 403 for the automation
user), so leftover parts are blanked as "TRAP Summary (unused)" and reused if the summary grows again.

### proofpoint_trap_acknowledge and proofpoint_trap_close

Launched by an analyst from the container after reviewing the enrichment. `acknowledge` prompts for a
comment, then writes the comment, an assignee marking the incident claimed by SOAR, and the status
change new -> open. Independent of `triage` and `close`. The prompt is raised from code because a VPE
save regenerates native prompt blocks whole and would drop the approver fallback (TRAP containers never
get an owner). See also `docs/uc2_implementation_plan.md` on the assignee / team requirement.

### proofpoint_trap_isolation_notify

Emails the container owner a set of isolation-browser links: the case's own SOAR URL plus every threat
URL found in the incident (from "Threat Domain" artifacts' `cef.url`), each behind the
`isolation_browser_url` prefix. Nothing is written back to TRAP.

- **Recipient.** TRAP containers never get an owner automatically. The approver fallback used by
  acknowledge / close cannot work here, because an email needs a real address, not just a username.
  The analyst must first set the container's own owner to themselves and its own status to "open" in
  the SOAR UI (separate from the TRAP-side assignee and status that acknowledge writes). The playbook
  fails fast, with no silent fallback, if either is missing. Owner id to email goes through
  `GET /rest/ph_user/<id>`.
- **Owner lookup.** Inside playbook execution `container['owner']` is the username, while the raw REST
  container shows the numeric id (observed 2026-08-17), so the lookup filters by username.
- **Delivery** uses a separate `smtp` asset (the `phsmtp` reference connector), developed against a mock
  SMTP backend first.
- **`isolation_browser_url`** is a playbook input, deliberately not hardcoded (a per-deployment value).
  Its default is the placeholder `https://my_isolated_browser/browser?url=`, which produces dead links
  until it is set.
- **`playbook_input:` datapaths** must be in their own `collect2` call: mixing them with other
  datapaths raises `TypeError`. The artifact read uses `scope="all"`, which is required when a playbook
  re-runs on an existing container.

### proofpoint_trap_recheck

Triggered by the Timer asset's container on label `proofpoint_trap_recheck`, not by a TRAP incident.
Each tick it re-scans the whole in-window TRAP backlog (all states) for incidents that were already
ingested but changed since: a field edit, a disposition change, a newly linked event. `on_poll`'s
checkpoint never revisits those once a container exists.

- **Origin.** Moved out of the connector's `on_poll` on 2026-08-18 (see the Connector section). The
  custom list `proofpoint_trap_recheck_state` (columns `incident_id`, `signature`) replaces the
  connector's in-memory state and is durable across runs the same way. The connector's newly linked
  event diffing was dropped for a simpler design: any detected change re-fetches and re-vaults all of
  that incident's MIME bodies, relying on identifier-based deduplication instead of tracking event ids
  per incident.
- **State list.** Row 0 is the header. It follows the read-modify-write state-list pattern used in an
  earlier, unrelated orchestrator playbook.
- **Copy of the connector.** `_build_event_info_cef` is duplicated from the connector (the cost of
  moving it). Keep both in sync.
- **Cross-container write.** `phantom.add_artifact()` writes to the current run's container, which here
  is the Timer tick's. A REST POST with an explicit `container_id` is used instead, as in
  `proofpoint_trap_attachments`. A raw REST POST does not deduplicate on `source_data_identifier`
  (verified on SOAR 8.6: the same MIME Body posted twice gives two artifacts), so the code skips what
  the container already carries.
- **State update is best effort.** It follows the dispatch attempt and does not wait for confirmation,
  matching the package's "attempted work, not platform-verified landed" convention (set when
  `finalize_event_artifacts` was removed from `detail` on 2026-08-13).

---

## SOAR platform behaviours the code works around

| Behaviour | Consequence in the code |
|-----------|------------------------|
| A VPE save regenerates `on_start`, the module docstring, prompt blocks and block banners | Logic that must survive lives in a block's custom code or the Global Custom Code (`check_reentry`, the prompt in acknowledge / close, the fan-out in `dispatch_*`) |
| SOAR's validator flags `lxml` and any filesystem access in a playbook | Standard-library HTML parsing; REST reads and base64 uploads instead of temp files |
| Each VPE code block is compiled and linted on its own | Local imports inside the block |
| `phantom.add_note()` sanitises HTML through an undocumented allowlist and drops `href` | Markdown notes posted over REST |
| A note is shown up to about 22,000 characters | Notes are capped at 20,000 and split into parts |
| A raw REST POST of an artifact does not deduplicate on `source_data_identifier` (verified on 8.6) | Code checks what the container already carries before posting |
| A playbook's automation user cannot DELETE notes (403) | Summary notes are rewritten in place; leftovers are blanked |
| `collect2` with the default scope only sees the current trigger's artifacts, not those created by earlier triggers or runs | `scope="all"` wherever earlier runs' artifacts matter |
| Mixing `playbook_input:` with other datapaths in one `collect2` raises `TypeError` | Separate `collect2` calls |
| An action SOAR refuses to dispatch (a required parameter missing) creates no `app_run` | A missing action result is reported as a failure, never as "not run" |
| A custom function gets no container object for `collect2` | `extract_incident_id` reads artifacts over REST |

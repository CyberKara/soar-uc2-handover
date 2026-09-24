> **Note:** this copy has had 5 reference(s) to the source lab's own
> internal addresses replaced with `<lab-address-redacted>`. They named
> the lab that built this package, never a target system of yours.

# Proofpoint TRAP Incident Triage (UC2) — Playbook Implementation Plan

**Status:** [x] planned | [x] built | [x] validated ✓ (on SOAR 8.5, before the 2026-09-05 rebuild)

**State as of 2026-09-22 (post-8.6-rebuild audit):** all 7 playbooks, the CF and connector v1.0.34
are live on the rebuilt 8.6 instance and match this repo. PB1's platform writes (event
artifacts, detail note, `Enrichment Complete`) failed from the rebuild until 2026-09-22 because
the `soar8` asset's automation user had no role (see the Post-Deploy table) — fixed and
verified that day. PB1 v2 (same day) surfaces a failed write with a `TRAP Detail - Write
failures` note and marks a failed enrichment `Enrichment Failed`, which the re-entry guard does
not count, so it can be retried. PB7 was live-verified later that day (Timer asset, 15 min;
see "PB7 live-verified 2026-09-22" below). Open: PB4 stays on hold. Details: `docs/next-steps.md`, "UC2 audit (2026-09-21)".

---

## Context

Second use case. Proofpoint TRAP ingests abuse-mailbox incidents — email deliveries and click events,
reported or auto-detected — containing whatever the platform's own classification lands on: phishing,
spam, malware, bulk/commercial mail, etc. Without automation, SOC analysts must manually fetch incident
details, look up IP ownership, and track their closure decisions across systems. The three-playbook
pipeline automates enrichment and structures the analyst triage decision.

**Business problem:** A TRAP incident is a high-level record — the raw SOAR container has a name but
no structured data. The analyst needs: full incident detail (who sent what, who clicked, from where),
IP context (DNS + WHOIS), and a structured closure workflow that records the decision in both SOAR and
TRAP.

**Scope (revised 2026-08-04 — merged UC10):** originally scoped as "phishing triage" with a separate
"UC10 — Spam Triage" planned as a distinct future use case sharing the same connector. That split
didn't hold up: TRAP doesn't have two separate incident streams — `Spam` and `Phishing` are values of
the same incident's `Abuse Disposition`/`Classification` fields, not mutually exclusive incident
sources (a `Spam`-classified incident can still be a phishing attempt). The pipeline itself is already
disposition-agnostic — PB1 parses `events` generically, PB3's triage doesn't branch on disposition at
all — so there was never a real "distinct flow" to build. UC10 is retired as a separate catalog entry;
its scope is just UC2's ingest filter being less artificially narrow. See `uc2_dev_notes.md` for detail.
Playbook `category` changed `"Phishing"` → `"Email Abuse"` and the `phishing` tag/artifact-description
wording was dropped to match (both `proofpoint_trap_detail` and `proofpoint_trap_triage`).

**Key design decisions:**
- Pipeline of 5 independent playbooks, not 1 monolithic playbook (revised 2026-08-12 — see
  "Restructure (2026-08-12)" below)
- Signal artifact (`enrichment_complete`) for loose coupling between PB1 and downstream automation
- `ip_enrich` **dropped from this UC 2026-08-12** — see "Restructure" below. It remains shared across
  `tenable_ad`/`es_soar_integration`/`events_crowdsec` (see UC3's implementation plan)
- PB4/PB5 are `data` type (analyst-run) — never auto-trigger; a triage/closure decision must be
  human-driven
- Ingest filter (`abuse_disposition`) covers `Unknown, Suspicious, Malicious, Spam, Bulk, Low Risk` —
  excludes `Known Good` (confirmed benign, nothing to triage) and `False Negative` (a retrospective
  miss-correction, not a new incident needing action)

**Restructure (2026-08-12):** The original 4-playbook pipeline (detail → ip_enrich → triage →
attachments) became 5 playbooks with `ip_enrich` removed and `proofpoint_trap_triage` split into three
single-purpose playbooks. Renumbered as: **PB1** `proofpoint_trap_detail` (unchanged) → **PB2**
`proofpoint_trap_triage` (trimmed to ID extraction only, retriggered from manual to automatic on
container creation — was PB3) → **PB3** `proofpoint_trap_attachments` (unchanged logic — was PB4) →
**PB4** `proofpoint_trap_acknowledge` (new — analyst-launched: comment + assign to SOAR + status
new→open on the real TRAP incident via a new Alerts API v1 connector action set) → **PB5**
`proofpoint_trap_close` (new — analyst-launched: closure reason prompt + `close incident` + comment).
PB4/PB5 are independent entry points, not chained off PB2 or each other. The old PB2 (`ip_enrich`) and
PB3 (`proofpoint_trap_triage`, full prompt/close flow) sections below are kept as historical design/
validation record — see the new PB2/PB4/PB5 sections for the current design.

**Restructure (2026-08-13):** Incident ID and severity moved from ad-hoc per-playbook logic to a single
connector-owned source of truth. Previously PB1/PB2/PB4/PB5 each independently re-parsed
`container["data"]["id"]` (4 copies of the same block, never consumed cross-playbook since `save_run_data`
is per-run), and the connector computed+set container severity itself at ingestion (`_get_severity()` /
`SEVERITY_MAP`). Now:
- `proofpoint_trap` connector v1.0.18: `on_poll` sets container severity to a neutral `DEFAULT_SEVERITY`
  at creation and exposes the raw TRAP `Severity` field as a new CEF slot (`cs6`/`cs6Label:"TRAP Severity"`)
  on the existing "Event Info" artifact, alongside the pre-existing `cs4`/`cs4Label:"Incident ID"`.
  `_get_severity()`/`SEVERITY_MAP` removed (dead once the mapping moved out of the connector).
- **PB2 (`proofpoint_trap_triage`) gained a real job**: reads `cef.cs4`/`cef.cs6` off "Event Info" via
  `phantom.collect2(..., scope="all")` and promotes container severity via `phantom.set_severity()`
  (Critical/High/Informational → high/medium/low, mapping now playbook-local). It's no longer a pure
  extract-and-stop no-op.
- **PB1/PB4/PB5** now read `incident_id` the same way (`cef.cs4` via `collect2`) instead of reparsing
  `container.data` — matches the datapath pattern `ip_enrich.py`/PB3 already used, eliminates the 4x
  duplicated extraction block.
- **Bug found + fixed during live validation**: the first deploy of this used `phantom.collect2()`
  without `scope="all"`. Because "Event Info" is created by `on_poll`, not by whatever artifact triggers
  a given PB1/PB2/PB4/PB5 run, the default scope silently never found it — PB2 always fell back to `low`
  regardless of the real TRAP severity, with no error surfaced (`phantom.error`'s note-on-failure path
  masked it as a normal early-return). `constraints.md` already documented `scope="all"` as required
  "when re-running a playbook on existing container" — missed on first pass, now applied to all 4 fixed
  `collect2()` calls. Live-verified post-fix: containers 1392/1393 (`TRAP Severity: Critical`) both
  correctly promoted to `severity: high`; PB1 enrichment unaffected (full 7-artifact set); PB4 manually
  launched against 1393, cleanly reached the real analyst prompt (left unanswered for a human, per
  standing rule — see memory `feedback_prompt_approval_ask_user`).
- Connector also gained a **`list incidents` action** (state/time-window/disposition filtering, same
  logic as `on_poll` via a new shared `_fetch_and_filter_incidents()` helper) and had its 4
  `add_user_to_incident`/`update_incident_description`/`update_incident_assignee`/`set_incident_field`
  actions **rewritten**: they were built against `PATCH /api/v1/alerts` (a guess, flagged unvalidated in
  the code), which turned out not to exist — the vendor's own API reference doc (converted to
  `proofpoint_trap_api_reference.md` this session) confirms `/api/v1/alerts` is GET-only (alert
  details + download original message); the real write endpoints are legacy
  `POST /api/incidents/{id}/{users.json,description.json,team_and_assignee.json,incident_fields.json}`.
  Connector action descriptions also normalized to consistently tag their API family. New connector
  install method: `tools/install_app.sh` (`POST /rest/app` with a JSON `{"app": base64(tgz)}` body —
  multipart upload fails on this SOAR 8.5 build).

**Fix (2026-08-13) — post-ingestion incident updates now picked up.** Closes the
"post-ingestion incident updates never picked up" gap flagged the same day (see
`next-steps.md`'s prior top entry). Original hypothesis was polling by a vendor
`updated_at` range filter — turned out not to exist: the vendor doc
(`proofpoint_trap_api_reference.md:1684`) only documents `updated_at=yyyy-mm-dd`,
a single calendar-day equality filter that must accompany `created_after` (every
request requires `created_after` or `closed_after`), never a real
`updated_after`/`updated_before` range. Rather than depend on that narrow,
day-granularity vendor filter, the fix self-detects change instead:
- **Connector (`proofpoint_trap` v1.0.21):** `on_poll` gained a second **recheck
  pass**, run every poll cycle (including Poll Now) independent of the ingest
  checkpoint. It re-queries `created_after=now-recheck_lookback_days` (new asset
  config field, default 7, capped at the vendor's 30-day range limit) with no
  `state` filter — fixing the `poll_state="new"` gap for this pass specifically,
  since a state-transitioned incident is no longer excluded. For each incident
  returned, a content signature (sorted `event_ids` + `state`, sha256) is compared
  against the last one stored per-incident in `self._state["incident_hashes"]`.
  Unchanged → skip. Changed and no container yet → ingest normally (also seeds
  the baseline hash immediately, see bug below). Changed and a container already
  exists (the actual bug case) → create a **`Recheck Requested`** signal artifact
  on the *existing* container (`run_automation=True`) instead of the old silent
  `continue`. Container-creation and artifact-building logic was extracted into
  a shared `_ingest_incident()` helper (previously only in the main loop) to
  avoid duplicating it between the two passes.
- **PB1 (`proofpoint_trap_detail`) re-entry guard — count-based, not
  existence-based:** `on_start` now counts `Enrichment Complete` vs
  `Recheck Requested` artifacts (`scope="all"`) and runs if `Enrichment Complete`
  count is 0, or if `Recheck Requested` count is `>=` it. Each run stamps its own
  `Enrichment Complete` artifact SDI'd with a run index (the `Recheck Requested`
  count at the start of that run) instead of one static SDI, so successive runs
  produce genuinely new artifacts the count can track. Applied to both real
  completion (`add_detail_note`) and the two early-failure signal paths
  (`extract_incident_id`, `create_event_artifacts`).
- **Mock backend:** new test-only `POST /_admin/trap/add_event` appends an event
  to an existing fixture incident (synthesizing a minimal one if none given),
  simulating a newly-linked alert — needed to exercise this at all, since no
  such vendor-side event exists in the seed data otherwise.

**Bug found and fixed during live validation (same day):** the first version of
the recheck pass fired a **spurious** `Recheck Requested` on every brand-new
incident, immediately after the main ingest pass had just created it —
`known_hashes` had no baseline for an incident it had never evaluated before, so
"first time seen" read as "changed." Confirmed live: container 1450 (fresh
synthetic incident 1786622009) got two `Enrichment Complete` runs before any
real change had occurred. Fixed by seeding `incident_hashes` for a newly-created
incident immediately in the main ingest loop, before the recheck pass runs later
in the same `on_poll` call.

**Live-verified end-to-end (2026-08-13, soar8 + mock, synthetic incident
1786622009 → container 1450):**
1. Fresh ingest → exactly one clean PB1 run (`enrichment-complete-0`), no
   spurious recheck — confirms the seeding fix.
2. `/_admin/trap/add_event` adds a 4th event (new recipient
   `finance.user4@company.com`) → next poll creates `Recheck Requested`, PB1
   re-runs (`enrichment-complete-1`), the new recipient gets its own new
   artifact, and **all 5 pre-existing event artifacts stay at their original
   ids — zero duplicates.** This confirms the load-bearing assumption the
   design depended on: SOAR's artifact creation genuinely no-ops on an existing
   `(container_id, source_data_identifier)` pair rather than duplicating —
   previously assumed, not verified (see the old table row this replaces).
3. Repeat poll with no further change → fully idempotent, artifact count held
   at 14 (no new `Recheck Requested`, no new PB1 run) — confirms the
   stored-hash comparison actually prevents re-recheck spam.
4. Incident moved to `state=open` (simulating PB4 acknowledging it, plus one
   more no-op event) → still caught despite `poll_state="new"` excluding it
   from the main pass — recheck pass has no state filter — third clean PB1 run
   (`enrichment-complete-2`), still zero duplicates.

Connector `app_version` 1.0.19 → 1.0.21 (1.0.20 built the recheck pass, 1.0.21
fixed the seeding bug above before either was live-verified as complete).
Committed: `soar-connectors`, `soar-playbooks`, and `splunk-lab` (mock backend)
— see `next-steps.md`'s matching entry for commit hashes. Handover mirror
(`cyberkara/soar-uc2-handover`) not yet refreshed for this change — same
standing note as every prior UC2 change, re-export via `/kara-do-uc-export`
next time this UC is touched or before an actual air-gapped deploy needs it.

**CEF field rename + PB1 native-action rebuild (2026-08-13, later).** Every
generic `cs1`-`cs6`/`cn1` CEF slot across UC2 was renamed to a descriptive
key — `Event Info`: `incidentId`/`trapSeverity`/`abuseDisposition`/
`classification`/`subDisposition`/`threatScore`/`eventIds`; `Sender Email`:
`emailRole`/`emailSubject`/`bodyType`/`messageId`/`deliveryTime`/
`abuseCopy`; `Recipient Email`/`Threat Domain`/`Email Attachment`:
`emailRole`/`url`/`mimeTypeMismatch`; `Enrichment Complete`:
`artifactsCreated`. All `*Label` companions dropped along with their slot,
matching the existing custom-key style already used for `vaultId`/
`emailAddress`/`emailHeaders`. Connector `1.0.22`. All 5 playbooks and the
connector updated to read/write the new names; `check_usercode_sync.py`
clean throughout.

`proofpoint_trap_detail` (PB1) then rebuilt to use native action blocks
(built-in `Phantom` app, asset `soar8`) instead of `phantom.requests.post()`/
`phantom.add_note()`: `dispatch_detail_note` (native `add note`) and
`dispatch_event_artifacts` (native `add artifact`, one call carrying a
dynamically-built list of per-artifact parameter sets — confirmed live that
`funcName:custom_function:var` fans out one `app_run` per list index when
paired output variables are all lists of the same length, matched by
position; not documented anywhere in this project before now, though a real
community precedent for the exact same shape exists in
`docs/vpe-extraction/code-blocks.md`'s `normalized_file_summary_output`
example — checked only after the fact). New nodes:
`prepare_detail_note`/`dispatch_detail_note`/`finalize_detail` and
`dispatch_event_artifacts`/`finalize_event_artifacts`, both action blocks
followed by an explicit code-block callback that does the real remaining
work (the `Enrichment Complete` artifact write) — confirmed this shape
reliably completes before `on_finish`, refining (not discarding)
`constraints.md`'s "synchronous platform APIs in callback chains" warning:
the actual risk is firing a native action with **no** callback of its own,
not native actions in callback chains generally.

Two real bugs found and fixed live during the rebuild: (1) the `add
artifact` action's `determine_contains` parameter defaults to `true` and
auto-guesses (wrongly) a `contains` type for any CEF field not explicitly
listed in `contains` — set `false` on every item to restore exact parity
with the old REST loop's behavior; (2) binding a native action parameter
directly to a wildcard artifact datapath (`artifact:*.cef.incidentId`) does
not send a real list to the connector — it text-joins every artifact's
resolved value with `", "`, including the literal word `"None"` for
artifacts lacking the field — connector `1.0.23` hardened
`_handle_get_incident` to comma-split and drop blank/`"none"` entries as a
defensive fallback, independent of whether `get_trap_incident`'s parameter
is ever wired that way again.

Self-audit against `docs/vpe-dev/`/`docs/vpe-extraction/` turned up
several more findings not yet acted on — full list in `next-steps.md` §58,
including that `docs/vpe-dev/removed.md` already documented the built-in
`Phantom` app and the exact "native action vs. `phantom.add_note()`"
trade-off this session re-derived live, a stale self-referencing `soar6`
asset (`phantom_server` left at unreachable `127.0.0.1:8443`) alongside the
new working `soar8` asset, `extract_incident_id` duplicated near-verbatim
across PB2/PB4/PB5 (should be a Custom Function — **fixed 2026-08-13, later
still, see "PB2/PB4/PB5 CF extraction" below**), and both
`PLAYBOOK_DEV_GUIDE.md` and the connector's own `README.md` being
significantly stale relative to the live connector.

Live-verified repeatedly against soar8 (containers 1467-1499 range,
multiple fresh polls): correct `incident_id` extraction, correct
`cef_types`/`contains` (no spurious auto-typing), correct multi-field CEF
including the nested `emailHeaders` dict surviving through
`cef_dictionary`, `Enrichment Complete` + detail note both landing on every
run, zero duplicate/incorrect artifacts. Current live state: PB1 id=377
v50, PB2 id=378 v43, PB3 id=379 v26, PB4 id=380 v15, PB5 id=381 v15;
connector `1.0.23`.

**Fix (2026-08-13, later) — recheck pass now refreshes MIME + Event Info on
a genuine change, not just the signal.** Closes the "recheck pass doesn't
fetch MIME for a newly-linked alert" row this table used to carry, plus a
second, related gap found the same day (`next-steps.md` §58): `Event
Info`'s `trapSeverity`/`abuseDisposition`/`classification`/`subDisposition`/
`threatScore`/`eventIds` were frozen at first-ingestion values forever,
since `_run_recheck_pass`'s "duplicate" branch only ever created the
`Recheck Requested` signal artifact — it never called back into
`_ingest_incident`'s artifact-building/MIME-fetch code, which returns
immediately after a duplicate `save_container` hit. Both gaps shared that
one root cause, so both are fixed in the same pass:
- **Connector (`proofpoint_trap` v1.0.24):** `_build_on_poll_artifacts`'s
  Event Info field logic extracted into `_build_event_info_cef(incident)`,
  now shared by first ingestion and the recheck pass. On a genuine
  duplicate-hit recheck, `_run_recheck_pass` (a) diffs the incident's
  current `event_ids` against a newly-tracked `self._state["incident_event_ids"]`
  baseline (seeded alongside `incident_hashes`) to find genuinely
  newly-linked event ids, fetches + vaults MIME **only** for those (not a
  full re-fetch of every event — avoids leaking duplicate, unreferenced
  Vault blobs from an artifact-POST no-op on an already-used SDI), and
  saves the resulting `MIME Body` artifacts *before* the signal artifact
  below so PB3 sees them on the same trigger cycle rather than racing it;
  (b) attaches the fresh `_build_event_info_cef()` output onto the
  `Recheck Requested` artifact's own `cef` (alongside its existing
  `message`/`incidentId`) instead of leaving it a bare notification.
  `Event Info` itself is never touched in place — SOAR's artifact POST
  confirmed (previous fix) to no-op on an existing SDI rather than update
  it, so there's no in-place-update mechanism available; the signal
  artifact carries the refresh instead, following the same "signal
  artifact" pattern `playbook-patterns.md` already documents.
- **PB2 (`proofpoint_trap_triage`):** `extract_incident_id` now reads
  `trapSeverity`/`incidentId` from whichever of `Event Info`/
  `Recheck Requested` was created **last** (collect2 returns artifacts in
  creation order, and `Recheck Requested` — when present — is always
  created after `Event Info`), instead of unconditionally taking the first
  `Event Info` row. Lets a later, genuine TRAP severity change actually
  promote container severity again, instead of promoting once at ingestion
  and never again.

**Live-verified end-to-end (2026-08-13, soar8 + mock, incident 1786622051 →
container 1504, pre-existing from automated polling, not a fresh test
container):**
1. `POST /_admin/trap/add_event` → incident now has 4 events (was 3, evt_2001-3
   + new `evt_1786622051_admin4`).
2. Manual recheck poll (`POST /rest/action_run`, `type: "poll"`, no
   `container_count` — the confirmed working recipe from `next-steps.md`
   §47, not the unreliable Poll Now REST path §46 found didn't behave the
   same as the GUI button) → exactly **one** new `MIME Body` artifact
   (`trap-1786622051-mime-evt_1786622051_admin4`, real `vaultId`) — the 3
   pre-existing MIME Body artifacts (`evt_2001`/`evt_2002`/`evt_2003`) kept
   their original artifact ids, confirming no redundant re-fetch. New
   `Recheck Requested` artifact's `cef` carries the full refreshed set:
   `eventIds: "evt_2001,evt_2002,evt_2003,evt_1786622051_admin4"`,
   `trapSeverity: "High"`, `classification: "Phishing"`,
   `subDisposition: "Needs Manual Review"`, `abuseDisposition: "Bulk"`,
   `threatScore: 75`.
3. Full pipeline re-fired correctly: PB1 created a new `Recipient Email`
   artifact for the new event's recipient and a second `Enrichment
   Complete` (index 1); PB3 found and processed the new `MIME Body`
   artifact (`data.attachments_extracted: true`, 0 attachments — the
   synthetic admin-added event has no real attachment payload, expected);
   PB2 re-ran and re-promoted container severity (`High` → `medium`, per
   the existing `severity_map`) without error. Zero duplicate artifacts
   among the 11 pre-existing ones — container went from 11 → 15 artifacts,
   exactly the 4 new ones expected.
4. Repeat poll with no further change → fully idempotent, artifact count
   held at 15 (no new `Recheck Requested`, no new PB1/PB2/PB3 runs).

Connector `app_version` 1.0.23 → 1.0.24. Committed `soar-connectors`,
`soar-playbooks`. Handover mirror (`cyberkara/soar-uc2-handover`) not yet
refreshed for this change — same standing note as every prior UC2 change.

**Simplification (2026-08-13, later still) — `finalize_event_artifacts`
node removed from PB1.** User decision: the per-`app_run` success count
`finalize_event_artifacts` computed (via `collect2` on
`dispatch_event_artifacts:action_result.status`) isn't something anyone
acts on — dropped. `dispatch_event_artifacts`'s native `add artifact`
callback now goes straight to `prepare_detail_note`; the "Artifacts
created from events" note field and `Enrichment Complete`'s
`cef.artifactsCreated` now report the **attempted** count
(`len(artifacts)`, saved directly in `create_event_artifacts`) rather than
a platform-verified **landed** count. VPE graph rewired (node 9 deleted,
edge `8→9→5` collapsed to `8→5`) alongside the `.py` change; deploy
validated clean (`validation=True`) and live-verified against soar8 + mock
(incident 1786622051, a 5th admin-added event) — full pipeline still
completes: new MIME Body, `Recheck Requested`, new `Recipient Email`,
`Enrichment Complete` (index 2), detail note correctly showing
`Artifacts created from events: 7`. Current live state: PB1 id=387 v52,
PB2 id=388 v45, PB3 id=389 v28, PB4 id=390 v17, PB5 id=391 v17; connector
`1.0.24` (unchanged by this simplification).

**Simplification (2026-08-13, later still) — `finalize_detail`'s
check-then-act race guard removed.** User decision, second one this
session on PB1: `finalize_detail` (the true last step, callback of
`dispatch_detail_note`'s native "add note" action — creates `Enrichment
Complete`) used to `collect2` the container's current artifact names and
skip creating `Enrichment Complete` if another concurrent run already had,
before ever POSTing. Dropped as redundant, not load-bearing: the artifact
itself is already keyed on a deterministic SDI
(`trap-{incident_id}-enrichment-complete-{run_index}`), and SOAR's
artifact POST is confirmed (the 2026-08-13 recheck-pass fix, above) to
no-op on an existing SDI rather than duplicate — so a real concurrent race
just costs one extra REST call that immediately no-ops, never a duplicate
artifact. `finalize_detail` now always attempts the create. **Not
touched:** `Enrichment Complete` creation itself — still the only thing
`on_start`'s count-based re-entry guard reads; removing that (a different,
earlier ask this session) would have broken the guard entirely and made
PB1 re-run on every trigger forever, so it stayed. Deploy validated clean,
live-verified against soar8 + mock (incident 1786622051, a 6th
admin-added event): new `Enrichment Complete` (index 3) created correctly,
no duplicates, repeat poll fully idempotent (held at 23 artifacts).
Current live state: PB1 id=392 v53, PB2 id=393 v46, PB3 id=394 v29, PB4
id=395 v18, PB5 id=396 v18; connector `1.0.24` (unchanged).

**Simplification (2026-08-13, later still) — `finalize_detail`'s raw REST
artifact create replaced with the native "add artifact" action.** User
decision, a follow-up correction to the previous entry: creating
`Enrichment Complete` via `phantom.requests.post()` to `/rest/artifact`
was inconsistent with how every other artifact in this playbook gets
created (`dispatch_event_artifacts`'s native "add artifact" action).
Restructured: `finalize_detail` (still "code" type) now only builds the
artifact's fields (`name`/`label`/`source_data_identifier`/
`cef_dictionary`/`contains`/`run_automation`/`determine_contains`) as
output variables, same role `create_event_artifacts` plays for event
artifacts. A new terminal node, `dispatch_enrichment_complete` (native
"add artifact" action, no callback — matches
`cyberark_rotation_orchestrator`'s own `add_note_no_targets` precedent for
a callback-less terminal `phantom.act()` call), fires the actual create.
VPE graph: node 7 (`finalize_detail`) kept, new node 9 (functionId 8,
reusing the id/functionId freed by the earlier `finalize_event_artifacts`
removal) added, edges rewired `7→9→1`. Native "add artifact" has no
`description` parameter (same pre-existing gap `create_event_artifacts`'s
own artifacts already have) — the old description text was folded into
`cef.message` instead of silently dropped. **Correction to the prior
entry's reasoning:** the native "add artifact" action does **not** no-op
silently on a duplicate SDI the way raw REST `POST /rest/artifact` does —
it returns an explicit `400 "artifact already exists"` (confirmed live,
visible on `dispatch_event_artifacts`'s own repeat-event runs). Doesn't
change the outcome (a real race still can't produce a duplicate artifact,
same as before), but "immediately no-ops" was the wrong description for
this code path specifically. Deploy validated clean, live-verified
against soar8 + mock (incident 1786622051, a 7th admin-added event): new
`Enrichment Complete` (index 4, artifact id 6963) created correctly via
the native action with the exact expected payload, 27 total artifacts, no
duplicates. Current live state: PB1 id=397 v54, PB2 id=398 v47, PB3
id=399 v30, PB4 id=400 v19, PB5 id=401 v19; connector `1.0.24`
(unchanged).

**Simplification (2026-08-13, later still) — rename + parameter cleanup,
and a real race-condition finding.** Three user-directed cleanups to PB1,
plus one significant discovery made while live-verifying them.

- **Rename:** `create_event_artifacts` → `extract_data_to_artifacts`
  throughout `proofpoint_trap_detail.py`/`.json` (function name, all
  `save_run_data`/`get_run_data` keys, VPE datapath references, comments).
  Historical narrative entries elsewhere in this doc and in
  `next-steps.md`/`uc2_dev_notes.md` still say `create_event_artifacts` —
  left as-is, matching this project's convention of not rewriting past
  journal entries.
- **`container_id` question, resolved as pre-existing/cosmetic:** user
  flagged the VPE GUI showing `[object Object]` for `dispatch_enrichment_complete`'s
  `container_id` field. Compared byte-for-byte against
  `dispatch_event_artifacts`'s own `container_id` binding (already live,
  unchanged): identical structure
  (`{'parameters': ['container:id'], 'template': '{0}'}`). Live `app_run`
  data already confirmed it resolves to the correct integer at runtime.
  Conclusion: a pre-existing VPE collapsed-parameter-preview display quirk
  for this binding shape, not something introduced by the new node — not
  investigated further.
- **`finalize_detail` simplified to only the two fields that need code:**
  `incident_id` no longer re-derived via `extract_data_to_artifacts`'s run
  data — it's already sitting plainly on `container.source_data_identifier`
  (set by the connector at ingestion), read directly. `name`/`label`/
  `contains`/`run_automation`/`determine_contains` never vary for this
  artifact, so they're now literal constants directly on the
  `dispatch_enrichment_complete` action step (JSON: `{'template': '<value>',
  'parameters': []}`, confirmed as the correct literal-binding shape via
  existing precedent — `cyberark_rotation_orchestrator`'s `add_note_no_targets`,
  `proofpoint_trap_close`/`_acknowledge`'s own literal `summary`/`field`/`value`
  params) instead of being computed and round-tripped through
  `save_run_data`/`get_run_data`. Only `source_data_identifier` (string
  concat of incident_id + run_index) and `cef_dictionary` (JSON encoding —
  the native action's parameter is a string, not a structured object)
  still need `finalize_detail` at all.
- **Real finding, not hypothetical:** live-verifying the above surfaced a
  genuine concurrent double-trigger of PB1 — two full playbook_runs
  (7199, 7201) fired within ~900ms of each other for the *same* single
  `Recheck Requested` artifact. This is the pre-existing platform race
  documented in memory `project-soar85-playbook-reentry-race` (`on_start`'s
  check-then-act guard can be raced past by a fast trigger) — not
  something this session's changes caused. But removing `finalize_detail`'s
  own race guard (see the entry above) changed the *consequence*: before,
  the second run's redundant `Enrichment Complete` create would have been
  silently skipped by that guard; now it's attempted and the native
  "add artifact" action returns an explicit `400 "artifact already
  exists"`, visible as a failed sub-action in the run history (same for
  most of that run's `dispatch_event_artifacts` calls, racing the same
  SDIs). **No duplicate artifact and no data corruption either way** — the
  SDI-based rejection still holds — but the failure is now visible where
  it used to be silent. **User decision: leave as-is.** The noisier failure
  record is an acceptable tradeoff for the simplification; not scoped for
  a fix.

Deployed and live-verified: PB1 id=402 v55; PB2/PB3/PB4/PB5 redeployed
unchanged (new ids/versions from the same `deploy.sh --use-case
proofpoint_trap` call, no content changes — this session's work stayed
scoped to PB1 only, per explicit user confirmation). Connector `1.0.24`
(unchanged).

**PB2/PB4/PB5 CF extraction + PB3 fix (2026-08-13, separate session, scoped
to PB2 and later — PB1 excluded, handled concurrently by a peer session on
this repo).** Closes the `extract_incident_id` duplication finding flagged
above: the block was near-identical across PB2 (`proofpoint_trap_triage`),
PB4 (`proofpoint_trap_acknowledge`), PB5 (`proofpoint_trap_close`), each
independently re-implementing the same "Event Info"/"Recheck Requested"
cef.incidentId scan. Extracted into a new shared custom function,
`proofpoint_trap_extract_incident_id`
(`playbooks/proofpoint_trap/custom_functions/`, zero inputs, outputs
`incident_id`/`trap_severity`), registered in `deploy.py`/`pull_soar.py`'s
`USE_CASES`. Custom functions get no `container` object the way a playbook
block does — only `phantom.get_current_container_id_()` — so the CF reads
artifacts via a direct `GET /rest/artifact?_filter_container=...` scan
(same idiom already used in `cyberark_rotation_orchestrator.py`/
`cyberark_recheck_handler.py`) rather than `phantom.collect2()`; querying by
container id this way is naturally equivalent to `scope="all"` — there's no
"new"-only REST default to get wrong here.

All three playbooks' `extract_incident_id` block became a native **utility**
block calling the CF, followed by a new bridge **code** block
(`read_incident_id`) that reads the result via
`phantom.collect2(datapath=["extract_incident_id:custom_function_result.data.*"])`
and re-exposes it through the ordinary `funcName:custom_function:incident_id`
code-block datapath convention for anything downstream (prompt `parameters`,
`get_run_data`) — exactly the `discover_targets`/`read_discover_result`
precedent already established in `cyberark_rotation_orchestrator.py`. PB2's
bridge block also carries the severity-promotion logic the old
`extract_incident_id` had (reads `trap_severity` from the same CF call,
`phantom.set_severity()` via the existing `severity_map`).

**Also fixed, found while auditing PB3 against `constraints.md`:**
`proofpoint_trap_attachments.py`'s `extract_attachments` used
`os.fdopen(tmp_fd, "wb")` on a `tempfile.mkstemp()` descriptor — a real,
already-documented anti-pattern (`constraints.md`: "No `os.fdopen()` — VPE
shows a lint warning on this usage; use `open()` instead"). Changed to
`os.close(tmp_fd)` + `open(tmp_path, "wb")`, same temp file, no behavior
change. Not a PB1-session finding — caught independently applying the same
"read the constraints doc, don't rationalize a warning" discipline PB1's
session used.

**Real bug found in `tools/deploy.py` during the first deploy attempt:**
`rebuild_cf_header_from_metadata()` (rebuilds a CF's `.py` header/docstring
from its `.json` metadata to match SOAR's GUI format before import) built
the function signature as `"def {}({}, **kwargs):".format(name, params)`
unconditionally — when `params` is empty (a CF with zero inputs, never
exercised before since both pre-existing CFs in this repo take at least
one), this produces invalid syntax: `def foo(, **kwargs):`. First deploy
attempt imported anyway (`passed_validation: true` after publish) but
silently dropped the `outputs` metadata (`GET /rest/custom_function/<id>`
showed `outputs: []` against a declared 2, confirmed by diffing against
the working `cyberark_asset_get_tagged_for_rotation` CF's own live detail,
which correctly shows its 9 declared outputs) — SOAR derives the CF's real
inputs/outputs by parsing the imported `.py`'s generated docstring, and the
malformed signature apparently broke that path even though the function
still ran fine. Fixed: build `params` as a trailing-comma-per-item string
(`"{}=None, ".format(...)`) and drop the hardcoded `, ` in the format
string, so zero inputs renders `def foo(**kwargs):` and one-plus inputs
renders identically to before. Redeployed; `GET
/rest/custom_function/63` confirmed `outputs: [...]` with both fields
present.

**Live-verified end-to-end (2026-08-13, soar8 + mock, fresh `on poll`
trigger, containers 1517/1518, incidents 1786622064/1786622065):**
- **PB2** (id=413): fired automatically on container creation.
  `custom_function_run` record for the `extract_incident_id` call shows
  `result_data.data = {"incident_id": "1786622065", "trap_severity":
  "High"}`; `read_incident_id` correctly promoted container 1518's severity
  `High`→`medium` (`severity_map`), matching the container's actual
  `severity` field via REST. (`exception_occured: true` appears on this
  `custom_function_run` record alongside `status: success` and correct
  `result_data` — confirmed this is a pre-existing platform display quirk,
  not specific to this CF: the long-deployed, previously-validated
  `cyberark_asset_get_tagged_for_rotation` CF shows the same
  `exception_occured: true`/`status: success` combination on its own past
  runs.)
- **PB4** (id=415): manually launched against container 1518, prompt
  reached a real pending approval, self-answered via
  `POST /rest/approval/{id}/respond` (dev/test mechanics check only, per
  the standing rule — see memory `feedback_prompt_approval_ask_user`).
  `update team and assignee`/`set incident field value`/`add comment` all
  succeeded; TRAP Acknowledge note correctly shows incident ID
  `1786622065` (matching container 1518, not a stale/wrong value).
- **PB5** (id=416): manually launched against container 1517 (a different
  container from the same poll, to keep PB4/PB5 verification independent),
  same self-answer pattern. `close incident`/`add comment` succeeded,
  container status set to `closed`, TRAP Closure note correctly shows
  incident ID `1786622064` (matching container 1517).
- **PB3** (id=414): confirmed still running clean post-`os.fdopen()` fix —
  `playbook_run` success on container 1518, same run as PB1/PB2's natural
  trigger, no regression from the temp-file handling change.

Current live state: PB1 id=412 v57, PB2 id=413 v50, PB3 id=414 v33, PB4
id=415 v22, PB5 id=416 v22 (PB1 redeployed unchanged as part of the same
`deploy.sh --use-case proofpoint_trap` call — no PB1 content changes this
session, per the same scoping agreement as the peer session's own PB1 work).
Connector `1.0.24` (unchanged — no connector changes this session). New CF
`proofpoint_trap_extract_incident_id` id=63 (redeployed once to pick up the
`deploy.py` fix; `id=60`/`62` from the first, outputs-broken attempt are
stale drafts left on soar8, not cleaned up). Handover mirror
(`cyberkara/soar-uc2-handover`) not yet refreshed for this change — same
standing note as every prior UC2 change.

**Fix (2026-08-13, still later) — `container_id` actually fixed at the
source, not patched around.** The 2026-08-13 rename/parameter-cleanup
entry above (`dispatch_event_artifacts` reading `container.get("id")`
directly) did **not** fix the real problem — it added a redundant
override loop in `dispatch_event_artifacts` while leaving the actual
construction site untouched: `extract_data_to_artifacts`'s `action_params`
comprehension still built each item as `artifacts[i]["container_id"]`,
indexing into a value redundantly duplicated across all 7 individual
artifact dict literals in the events loop — directly contradicting that
same function's own comment a few lines above it ("container_id stays a
single value since it's constant for every artifact in this run"). Fixed
properly: removed the per-item `"container_id": container_id,` from all 7
artifact dict literals (Sender Email, Sender Domain, Recipient Email, Cc
Recipient Email, Threat Domain ×2, Click Source IP — none of them needed
it, the field was only ever read back out for the one `action_params`
line), changed that line to use the function's own already-computed
`container_id` variable directly, and removed the now-unnecessary override
loop from `dispatch_event_artifacts` entirely. **Bug introduced and caught
during this cleanup:** a blanket regex removal of the per-item lines also
stripped `container_id` from `_create_enrichment_failure_signal`'s raw
REST payload (a genuinely different, unrelated artifact-creation path —
the enrichment-failure signal, not an event artifact) — caught by
re-reading the diff before deploying, restored before it ever went live.
Deploy validated clean (PB1 id=417 v58), live-verified against soar8 +
mock (10th admin-added event, incident 1786622051): `container_id`
resolves correctly (`1504`), 39 total artifacts, no errors.

**Simplification (2026-08-18) — connector/playbook artifact-ownership
split: `URL Artifact` moved from the connector to PB1.** User-directed
cleanup, following on from a connector-vs-playbook artifact-ownership
discussion: `on_poll`'s lightweight incident fetch (`expand_events=false`)
was creating a separate `URL Artifact` per entry in `hosts.url` directly at
ingestion — the only per-item derived artifact the connector built itself,
everything else in that category (Sender/Recipient Email, Sender/Threat
Domain, Click Source IP) was already PB1's job, built from its own full
incident fetch (`get_trap_incident`, `expand_events=true`, which also
carries `hosts` — confirmed present in both the expanded and lightweight
vendor example responses, so no data is lost by not reading it at
`on_poll` time). Rather than keep `URL Artifact` connector-side (an
inconsistent split) or fold it into `Event Info` as a CSV field (considered
and reverted — would have made it the odd one out, a joined string instead
of a real per-item artifact like every other derived artifact in this UC),
moved its creation into PB1's `extract_data_to_artifacts`, sourced from the
same `incident` dict (`hosts.url`) that function already has in hand. Same
name/`cef.requestURL`/`cef_types` shape as before, now built alongside
Threat Domain/Click Source IP using that function's existing generic
per-artifact fan-out (`dispatch_event_artifacts`) — no new code path
needed. `_build_on_poll_artifacts` (connector) now returns only `Event
Info`; `_build_event_info_cef()` is unchanged from before this entry.
Confirmed no consumer anywhere in `soar-playbooks`/`soar-connectors` read
`URL Artifact`/`cef.requestURL` before this move (grepped clean) — safe
relocation, not a deprecation. Connector `app_version` 1.0.24 → 1.0.25 (the
removal from `on_poll` alone is still a real behavior change worth the
bump, independent of where the artifact moved to). `check_usercode_sync.py
--fix` re-synced PB1's JSON `userCode` for `extract_data_to_artifacts`,
confirmed clean. **Not yet deployed to soar8 / live-verified** — code + doc
change only so far; still needs `soar-connectors/tools/build.sh` +
`install_app.sh`, `./tools/deploy.sh --use-case proofpoint_trap`, and a
real poll cycle against the mock before this entry can be marked verified.
Handover mirror (`cyberkara/soar-uc2-handover`) not yet refreshed for this
change — same standing note as every prior UC2 change.

**Fix (2026-08-18, later) — recheck signature extended to cover pure field
edits, not just event linkage/state.** `_incident_signature` previously
hashed only `event_ids` + `state` — an analyst editing `Classification`/
`Severity`/`Sub Disposition`/`Abuse Disposition`/`score` in TRAP without
linking a new event or moving the incident's workflow state went
completely undetected (confirmed this is a real, independent gap: none of
those three real-world triggers — new event, state transition, field edit
— imply either of the others). Fixed by having `_incident_signature` reuse
`_build_event_info_cef()` (already the single source of truth for what
`Event Info`/`Recheck Requested` expose) and hash `state` plus its full
output, instead of re-deriving a narrower field set. Also fixed a real mock
bug found while building the test: `POST /api/incidents/{id}/incident_fields.json`
(the endpoint `set incident field value` and, by extension, any real
external edit path this connector could observe) was writing named fields
to a dead top-level `incident[field]` key instead of the `incident_field_values`
list the connector's own `_get_field_value`/`_get_disposition` actually read
from — a write would 200 OK but be permanently invisible to any later poll.
Fixed in `migration/mock-backend/mock_api_gateway.py` to find-or-update the
matching `incident_field_values` entry. Connector `app_version` 1.0.25 →
1.0.26.

**Known one-time side effect of any future signature-format change:**
upgrading `_incident_signature`'s hash formula invalidates every
previously-stored hash in `self._state["incident_hashes"]` — the first
recheck pass after such a deploy will find a mismatch for every
still-in-window incident and fire a spurious `Recheck Requested`/full
re-enrichment across the existing backlog, even though nothing actually
changed in TRAP. Confirmed live (see below): harmless and self-correcting
(each incident's hash updates to the new format the moment it's
rechecked; a second poll was fully idempotent), but worth knowing before
ever pushing a signature-format change to a real production deployment —
it reads as a burst of unrelated change detections, not a bug.

**Live-verified end-to-end (2026-08-18, soar8 + mock, restarted
`mock-api-gateway.service` first to pick up both fixes):**
1. Manual `on poll` action_run → migration side effect observed exactly as
   predicted: containers 548/550 (pre-existing, in-window) both got a
   spurious `Recheck Requested` purely from the hash-format change (their
   `event_ids`/`state` hadn't actually changed). One of the two concurrent
   triggers on container 550 raced PB1's `on_start` guard (a **pre-existing,
   already-documented platform race** — memory `project-soar85-playbook-reentry-race`
   — surfaced here by the migration burst creating near-simultaneous
   artifacts, not caused by either of this session's fixes): `get_trap_incident`
   resolved a blank `incident_id` and failed twice (playbook_run 7643/7644),
   self-healed via the existing failure-signal path, followed immediately by
   a clean successful run (7653-7655 area).
2. Repeat poll, no further change → zero new artifacts, confirming the
   hash-format migration settled after one pass.
3. `set incident field value` (asset `proofpoint_trap_mock`, incident 1004,
   `field=Classification`, `value=Phishing`) → succeeded against the fixed
   mock endpoint.
4. Poll again → new `Recheck Requested` (artifact id 7626) correctly shows
   `classification: "Phishing"`, distinct from the prior artifact's stale
   `"Credential Theft"` — a pure field edit, with no event/state change,
   detected for the first time. PB1/PB2/PB3 (playbook_run 7653/7654/7655)
   all `success`, no race this time (single clean trigger). Container 550
   severity correctly re-promoted to `medium` via the existing severity map.

Handover mirror not yet refreshed — same standing note.

**Simplification (2026-08-18, later) — `Event Info`/`MIME Body` given the
same `label` as every other artifact in this UC.** User-directed cleanup
found while reviewing the creation/update test: `Recheck Requested`
(added 2026-08-13) explicitly sets `label: "event"`, matching every
artifact PB1 creates (Sender/Recipient Email, Threat/Sender Domain, Click
Source IP, URL Artifact), but `Event Info` and `MIME Body` — both built in
`_build_on_poll_artifacts`/`_build_mime_artifact` — never set `label` at
all, falling back to SOAR's default instead. Added `"label": "event"` to
both.

**Follow-up, same session — `Recheck Requested` renamed to `Event Info
Update`.** User decision, reversing the "leave `name` alone" call above:
`Event Info` and `Recheck Requested` didn't read as a pair in the
Artifacts tab even though they're the same conceptual data at two points
in time (initial ingestion vs. refreshed). Renamed for real, not just in
the connector — this string is functionally matched (not just displayed)
in 5 other places: PB1's `on_start` re-entry guard
(`names.count("Recheck Requested")`), the shared CF
`proofpoint_trap_extract_incident_id` (`row.get("name") in ("Event Info",
"Recheck Requested")`, used by PB2/PB4/PB5), plus comment-only references
in PB2/PB4/PB5 themselves. All 6 files updated together so the re-entry
guard and severity-promotion source-selection don't silently break.
`check_usercode_sync.py --fix` confirmed clean; `on_start` itself has no
`## Custom Code Start/End` markers in the `.py` (a fixed entry-point node,
not a GUI-editable code block) so there was nothing to desync there in
the first place. Connector `app_version` 1.0.26 → 1.0.27 (same version
covers both this and the `label` harmonization above — neither had been
deployed yet). Deployed 2026-08-18: connector installed (app id=198, v1.0.27), all 6
playbooks + CF redeployed clean (`validation=True`). Current live state:
PB1 id=650 v111, PB2 id=651 v95, PB3 id=652 v78, PB4 id=653 v67, PB5
id=654 v67, PB6 id=655 v5; CF `proofpoint_trap_extract_incident_id`
id=108. Not yet live-verified against a real poll/edit cycle post-rename.

**Architecture change (2026-08-18, later) — post-ingestion recheck moved
from the connector to a new playbook.** User decision, following an
explicit connector-vs-playbook precedent check: neither local reference
connector for this vendor (`github_recent/proofpoint-threat-protection` —
turned out to be an unrelated safelist/blocklist app; `phantom-apps/Apps/
phproofpoint` — a real TRAP-style `on_poll` connector, single-checkpoint
only, no recheck logic) nor the vendor API reference documents any
webhook/subscription/change-detection mechanism for TRAP. So there was no
external precedent either way — the deciding factor was that a
playbook-side version needs its own durable state, which a Timer-asset
automation playbook can get via a SOAR custom list (`constraints.md`: "No
timer logic in playbooks — timer asset owns the schedule", same pattern
UC1's `ask.md` originally documented before UC1 simplified its own recheck
to artifact-based retries — not applicable here since UC2's problem is
genuine periodic backlog scanning, not retry-after-failure).

**New playbook `proofpoint_trap_recheck`** (automation, trigger:
`artifact_created` on label `proofpoint_trap_recheck` — a new Timer asset,
15 min interval, GUI-created since asset creation is REST-blocked;
distinct from the real `proofpoint_trap` label so ticks don't mix into
real TRAP incident containers). 5 blocks: `on_start` → `list_incidents`
(native action, `state=""` — confirmed via `mock_api_gateway.py`'s
`parse_qs` default dropping an empty-valued query param, same as omitted,
so this means "all states" not the action's own "new" default —
`hours_back` a literal 168 constant) → `process_incidents` (code: diffs
each incident's signature — duplicated `_build_event_info_cef`/
`_incident_signature` logic from the connector, since the connector no
longer runs this itself; only incidents that changed AND already have a
container go to the recheck batch, matched by `_filter_source_data_identifier`)
→ `dispatch_mime_refetch` (native action `download mime body`, list-fanout
on `incident_id` via a real output variable, same parallel-list mechanism
as PB1's `dispatch_event_artifacts`; `event_id` deliberately omitted so it
refetches all events for a changed incident rather than tracking
newly-linked event_ids — simplification, relies on the already-proven
SDI-based artifact dedup instead) → `dispatch_updates` (code: builds
`MIME Body` + `Event Info Update` artifacts via raw REST `POST
/rest/artifact`, not `phantom.add_artifact()` — this playbook's own
`container` is the Timer tick's, not the target incident's, so this is a
genuine cross-container write, same idiom PB3 already uses for the same
reason; then persists new signatures to the custom list). New custom list
`proofpoint_trap_recheck_state` (id=5, columns `incident_id`/`signature`)
replaces the connector's `self._state["incident_hashes"]`/
`["incident_event_ids"]` — durable across playbook runs the same way, just
playbook-owned. Dropped the connector's newly-linked-event diffing
entirely (no `event_ids` column) as part of the same simplification.

**Connector simplified back down (`app_version` 1.0.27 → 1.0.28):**
`_run_recheck_pass` and `_incident_signature` removed; `_handle_on_poll`
back to single-pass/checkpoint-only (pre-2026-08-13 shape). Removed the
now-unused `recheck_lookback_days` asset config field (manifest + consts)
and the `hashlib` import. `_build_event_info_cef` unchanged, still used at
first ingestion.

Added `proofpoint_trap_recheck` to the 3 other hardcoded per-use-case
playbook lists this repo keeps (`deploy.py`, `pull_soar.py`,
`snapshot.py`) — the known gotcha documented in memory
`project-soar-deploy-manifest-hardcoded`.

Deployed 2026-08-18: connector installed (app id=198, v1.0.28), all 7
playbooks + CF redeployed clean (`validation=True`). Current live state:
PB1 id=656 v112, PB2 id=657 v96, PB3 id=658 v79, PB4 id=659 v68, PB5
id=660 v68, PB6 id=661 v6, PB7 (`proofpoint_trap_recheck`) id=662 v1; CF
id=109. Assembled server-side snapshot for PB7 confirmed matching the
intended structure.

**PB7 live-verified 2026-09-22** (13 months of "built but never run" closed).
The Timer asset was created **over REST** (`POST /rest/asset` with `app_id`,
asset id 23, 15 min interval, container label `proofpoint_trap_recheck` — which
also creates the label): the "GUI-only, asset creation is REST-blocked" note
above is wrong on 8.6, and the ingest/poll block sticks. Four things the first
real runs exposed:

1. **The first tick failed**: `list incidents` raised `unsupported type for
   timedelta hours component: str`. PB7 passes `hours_back` as a literal, and a
   VPE literal is always a string; the connector fed it straight to
   `timedelta()`, the one numeric parameter it did not put through
   `_validate_integer()`. Fixed in connector **v1.0.34**.
2. **First-sight incidents are recorded, not rechecked** (added same day). With
   an empty state list every in-window incident looked "changed", so tick one
   would have re-run PB1 across the whole backlog — on a fresh install, the
   entire history. Seeding run: 672 signatures recorded, zero rechecks.
3. **A real change is detected end to end**: the mock's
   `POST /_admin/trap/add_event` on an ingested incident → next tick built
   `Event Info Update` + the new event's `MIME Body` on that incident's
   container → PB1 re-ran on its own trigger, its duplicate artifacts came back
   `already exists` (benign, ignored), new ones landed, and a second
   `Enrichment Complete` was created because the artifact now carries the run
   index.
4. **Duplicate `MIME Body` artifacts, from two directions** (see
   `constraints.md`). First, the recheck re-posted the artifacts the container
   already had — raw REST never dedups — so each cycle duplicated every event's
   MIME and PB3 re-processed each copy; PB7 now skips SDIs already on the
   container. That left a second, subtler copy: PB7 and PB1 both build the new
   event's `MIME Body` seconds apart, and SOAR's dedup hashes artifact content
   including `cef_types`, which the two tag differently — so neither copy is
   "identical" to the platform. PB1 now skips existing SDIs too. Verified over
   three recheck cycles: one artifact per newly-linked event, no failure notes,
   `Enrichment Complete` incrementing per run.

Handover mirror not yet refreshed.

**Architecture change (2026-08-20) — MIME-body fetch moved off the connector,
severity/sensitivity exposed as asset config.** Two independent, user-directed
changes, same session.

1. **MIME fetch moved to PB1.** `on_poll`'s `fetch_mime_on_poll` toggle and its
   MIME-fetch-per-event loop removed entirely from the connector (`_ingest_incident`
   no longer takes a `fetch_mime_on_poll` param; `_download_and_vault_mime`/
   `_fetch_incident_events` stay, still used by the standalone `download mime body`
   action; the now-dead `_build_mime_artifact` helper deleted). Same
   connector-vs-playbook reasoning as the 2026-08-18 recheck-pass/URL-Artifact
   move: connector stays a thin generic API wrapper, artifact-shape decisions
   belong with the rest of PB1's derived per-item artifacts. New node 10
   (`dispatch_mime_download`, native "download mime body" action, `event_id`
   omitted → fetches every event's MIME in one call) inserted between
   `get_trap_incident` and `extract_data_to_artifacts`; the latter now also reads
   `dispatch_mime_download`'s per-event rows and builds `MIME Body` artifacts
   itself. **Real regression caught and fixed before deploy, not after:** the
   connector's old `_build_mime_artifact()` gave each `MIME Body` artifact its
   own SDI (`trap-{incident_id}-mime-{event_id}`), which `proofpoint_trap_attachments`
   (PB3) parses back apart to recover `event_id` — PB1's existing artifact-batch
   dispatch (`dispatch_event_artifacts`) reuses one shared `container:source_data_identifier`
   for every artifact in the batch, which would have silently degraded every
   PB3-recovered `event_id` to `"?"`. Fixed by giving individual artifact dicts an
   optional per-item `source_data_identifier` override (`action_params[i]` now reads
   `artifacts[i].get("source_data_identifier") or incident_id_val`) — MIME Body
   artifacts set it explicitly, everything else in the batch is unchanged. Connector
   `app_version` 1.0.28 → 1.0.29.
2. **`severity`/`sensitivity` exposed as asset config**, same pattern as the stock
   Timer app (`severity`: string, default `low`; `sensitivity`: string, `value_list`
   white/green/amber/red, default `amber`) — previously `DEFAULT_SEVERITY` was a
   connector-code constant with no `sensitivity` field at all. `_ingest_incident`
   now takes `severity`/`sensitivity` params read from asset config in `_handle_on_poll`;
   `DEFAULT_SEVERITY`/new `DEFAULT_SENSITIVITY` in `consts.py` are now just the
   fallback when the asset config omits the key, not the value always used. `severity`
   is still only the *initial* value — PB2 (`proofpoint_trap_triage`) unchanged,
   still promotes it from the real TRAP `Severity` field afterward. Connector
   `app_version` 1.0.29 → 1.0.30.

Deployed + live-verified same session: connector v1.0.30 installed (app id=198),
all 7 playbooks + CF redeployed clean (`validation=True`) — PB1 id=663 v113
through PB7 id=669 v2, CF id=110 — all automation PBs re-activated post-deploy
(deploy re-imports as a new id each time, deactivating the old one). Fresh
`on poll` (container 1724, incident 1787194892): 3 `MIME Body` artifacts created
by PB1 with correct per-event SDIs (`trap-1787194892-mime-evt_2001` etc., real
`vaultId`/`fileName`), PB3 ran clean and recovered the real `event_id` for each
(`attachments_extracted: True`, note text correctly shows `evt_2001`/`evt_2002`/
`evt_2003`, not `"?"` — confirms the SDI-override fix actually worked, not just
that nothing crashed). Container severity/sensitivity confirmed set from asset
config (`sensitivity: amber` landed as configured; `severity` observed as
`medium` after PB2's own promotion ran, consistent with unchanged PB2 behavior).
`proofpoint_trap_recheck`'s Timer asset still not created (pre-existing open
item, unrelated to this change).

**Fix (2026-08-20, later same day) — `update team and assignee`'s HTTP 404
handling was actively hiding the real cause of a production 400, found by
the user testing directly against the real airgapped Proofpoint TRAP
appliance (never reproducible against the mock — it doesn't validate
team/assignee at all, always 200s).** Real appliance behavior, confirmed
live: (1) setting `team`+`assignee` to values that already match the
incident's current state → HTTP 404, body `"the previous team and
assignee are same, not updating the incident"`; (2) a genuinely new
`assignee` with the incident's existing `team` → HTTP 400, generic `"error
updating team and assignee for the incident id .."` (cause not yet
diagnosed — likely a team-membership constraint on the real appliance,
unconfirmed). Root cause of (1) being confusing: `_process_response`'s
blanket `if status_code == 404` branch (present since the connector's
first commit, written for the more common "wrong ID" case) overrode
*every* 404 on *every* action with a generic "Not Found... verify resource
exists or base_url is correct" message, discarding the real vendor body —
the user only saw the actual message via the GUI Test dialog's raw
response, not the action's own formatted message. Removed the blanket
branch entirely; 404 now falls through to the same JSON/text/empty
handling every other status code already gets, so the real vendor message
surfaces everywhere HTTP 404 occurs across the whole connector (not scoped
to just this one action — `urlparse` import removed, now unused).
Separately, **user decision**: scenario (1) is now treated as SOAR-side
success (idempotent no-op — "already in the desired state"), matching the
existing `"duplicate container found"` idiom in `_ingest_incident` — a
new `no_op` boolean added to the action's output data
(`action_result.data.*.no_op`), distinct success message
(`"Incident {} already had this team/assignee — no change made"`).
Matters for `proofpoint_trap_acknowledge` (PB4), which sets `assignee`
unconditionally every run and would otherwise hard-fail re-running against
an already-acknowledged incident. Connector `app_version` 1.0.30→1.0.31,
built + installed on soar8, happy-path regression-checked against the mock
(still 200s cleanly) — the two real-appliance-specific paths above are
**not** verified against the mock (can't be, until/unless the mock is
extended to simulate them) and remain confirmed only against the real
airgapped appliance per the user's report. **Not committed to git.**

**Scenario (2) diagnosed further (2026-08-20, later still) — real
database-layer rejection, not a plain validation error.** Full error body
now known: `"error updating team and assignee for the incident id 134,
org.hibernate.exception.ConstraintViolationException: could not extract
resultset"`. Hibernate throws that exception class for FK/uniqueness/etc
constraint violations at the DB layer, not for application-level input
validation — TRAP's API is leaking a raw backend exception instead of
returning a clean 400 with a real message (a vendor-side bug in its own
right). Leading theory, unconfirmed: **the assignee must already be a
member of the incident's current team** — fits the trigger (new assignee +
unchanged team → violation; unchanged assignee + unchanged team → the
idempotency 404 above, no write attempted at all). **Real production risk,
not just a manual-test artifact:** `proofpoint_trap_acknowledge` (PB4)
hardcodes `assignee="SOAR"` with **no team ever specified** — if the
`"SOAR"` TRAP user isn't a member of every team an incident can land in,
PB4 will hit this exact constraint violation in production depending on
incident routing, not just when testing with an arbitrary username by
hand. **Blocked on the user checking TRAP's own team admin settings** to
confirm `"SOAR"`'s real team memberships before any playbook-side fix is
attempted (e.g., PB4 reading + sending the incident's current team
alongside assignee, or an admin-side fix adding `"SOAR"` to every team) —
do not guess at a PB4 redesign until that's confirmed. Connector-side
improvement made in the meantime: `_handle_update_incident_assignee`
detects the `ConstraintViolationException` signature in the failure
message and appends (not replaces) a plain-language hint pointing at team
membership, so the next person who hits this doesn't have to re-derive the
theory from a Java stack trace. `app_version` 1.0.31→1.0.32, built +
installed on soar8, mock-side happy path regression-checked clean again
(mock still can't exercise this — it doesn't validate team/assignee).
**Not committed to git.**

**Theory above DISPROVEN, real API contract bug found and fixed, deeper
DB-layer bug still open (2026-08-20, later still — 5 systematic tests on
the real appliance).** User ran a clean test matrix against a real incident
(assignee `toto`, team `tata`, `toto` confirmed a member of `tata`):

| # | assignee | team | Result |
|---|----------|------|--------|
| 2a | `toto` (unchanged) | `tata` (unchanged) | 404 "previous team and assignee are same" (the idempotency no-op, unchanged) |
| 2b | `kiki` (**confirmed member of `tata`**) | `tata` (unchanged) | 400 `ConstraintViolationException` |
| 2c | `usernotexist` (doesn't exist) | `tata` | 404 "no assignee found for usernotexist" (distinct message — a genuine, different 404, correctly still a failure under the no_op fix above) |
| D | `kiki` | **omitted entirely** (not sent) | 400 "Both team and assignee are required. Team: null, assignee: kiki" |
| E | `kiki` | a **different** team `kiki` also belongs to | 400 `ConstraintViolationException` — same failure even with a genuine, fully-valid change to both fields |

2b kills the team-membership theory outright — `kiki` was a confirmed
member of `tata` and still hit the identical violation. **Test D is the
real, confirmed, connector-fixable bug:** the vendor doc's own parameter
table lists `"team and assignee ... required: yes"` as one combined row —
this connector had it wrong, treating `assignee`/`team` as independently
optional with an "at least one" check. Real appliance requires **both,
always**. Fixed: manifest `assignee`/`team` both `required: true` now
(were `required: false` with a misleading "(optional if team/assignee is
set)" description each); connector's own guard replaced to match ("Both
team and assignee are required..." — same wording as the real API's own
message, found by fixing forward from the evidence instead of guessing).
`app_version` 1.0.32→1.0.33, built + installed, mock-side happy path
(both fields present) regression-checked clean.

**Consequence, not yet acted on:** `proofpoint_trap_acknowledge` (PB4)
sends `assignee` only, no `team` — it is **guaranteed to fail on the real
appliance, every single run**, not conditionally. Not fixing PB4 yet,
for two reasons: (1) even if PB4 is changed to also send the incident's
current team (the obvious fix — it doesn't want to *change* team, just
resend it), test E shows a **fully valid, correctly-shaped request with a
genuine value change still hits the same `ConstraintViolationException`**
— so a PB4 fix alone would very likely still fail, just with a different
symptom; (2) every test across this whole investigation that attempted an
actual value change — valid inputs, existing entities, correctly-shaped
request — has failed the same way. Only no-ops (2a) and clean
pre-DB-layer validation rejections (2c, D) have ever come back clean. That
pattern reads as a genuine backend defect on this TRAP instance, possibly
unrelated to team/assignee content at all, not something fixable from the
connector. **Proposed next step (not yet run):** perform the identical
(assignee, team) reassignment through TRAP's own web UI instead of the
API. UI also fails the same way → confirms a real appliance-side defect,
worth reporting to Proofpoint support, and PB4 cannot be made to work
until it's fixed upstream. UI succeeds → points at something the API path
specifically is missing (e.g. an actor/audit-context header the UI's
authenticated session provides that API-key auth doesn't) worth chasing
further. **Do not fix PB4 until this is resolved** — fixing its request
shape without fixing the underlying write failure would just change the
error message, not the outcome.

**Direct-to-TRAP troubleshooting curl added to the connector's own
`README.md`** (2026-08-20, later still) — ships inside the app `.tgz` via
`tools/build.sh` (not excluded by `exclude_files.txt`), so it travels with
the connector to the airgapped install and doesn't depend on repo access
there. Lets the same test matrix above be run directly against TRAP without
going through SOAR's Test Action dialog each time, with a table mapping
every known response (200/404 same-values/404 bad-assignee/400
missing-field/400 `ConstraintViolationException`) to its meaning. See
`soar-connectors/connectors/proofpoint_trap/README.md`'s new "diagnosing
directly against TRAP, without SOAR" subsection.

**Alternate write-path test added to the same README section, and
`_process_response`/manifest comment narrative cleaned up (2026-08-20,
later still).** User's 5-test matrix conclusion: the product's read/
validation paths (idempotency detection, unknown-user check, required-
field check) all work correctly, but every genuine write attempt fails
identically — reads as a real TRAP-side defect, not a connector or
request-shape problem. Before escalating to a Proofpoint support ticket,
one more avenue worth ruling out: `set incident field value`
(`/api/incidents/{id}/incident_fields.json`, already used successfully for
`Severity`/`Classification`/`Sub Disposition`/`Abuse Disposition`) is a
separate, more generic endpoint — untested for `Team`/`Assignee`, not
documented either way, but a genuinely different server-side code path
than `team_and_assignee.json`. Curl examples (single-field, matching the
connector's own request shape, and both-fields-in-one-call, matching the
raw API's own documented example) added to the README right after the
existing troubleshooting table. **Result not yet known** — user hasn't
run it yet. Separately: `_process_response`'s 404 handling and
`_handle_update_incident_assignee`'s comments had accumulated dated
session narrative ("confirmed live 2026-08-20", "user decision") across
several iterative fixes — rewritten as plain "why" explanations per
[[feedback-no-session-narrative-in-code-comments]]; the misleading
"assignee not a member of team" hint (from the now-disproven theory) was
removed from the runtime error message entirely rather than corrected in
place, since the real cause still isn't known. `dist/proofpoint_trap-
v1.0.33.tgz` rebuilt (no functional change, no version bump). **Not
committed to git** at the time — committed 2026-08-22 (`soar-connectors` `c9a6654`).

**Temporary verification build (2026-08-19) —
`proofpoint_trap_url_collect_verify`.** Not part of the UC2 pipeline, not
registered in `deploy.py`/`pull_soar.py`/`snapshot.py`'s `USE_CASES` (so
`deploy.sh --use-case proofpoint_trap` never touches it), `playbook_type:
data` so it never auto-fires. Built at user request to independently
reproduce, from the documented VPE block patterns alone, a native-block-
only design for URL-artifact collection the user separately built by hand
on an air-gapped SOAR instance this session has no access to — the point
being to compare the two builds for parity, not to ship this playbook.
Sequence: `start` → `filter` (`filter_event_info`, copied verbatim from
PB1 node 2) → `action` (`get_trap_incident`, copied verbatim from PB1
node 3) → `utility` (`list_demux_urls`, calls the platform-shipped
`community/list_demux` CF on `hosts.url`, fanning out one downstream run
per URL) → `format` (`format_1`, builds the per-URL `cef_dictionary` JSON
string) → `action` (`dispatch_url_artifact`, native "add artifact",
literal name/label/contains, terminal). Produces the same `URL Artifact`
shape PB1's own `extract_data_to_artifacts` now builds (see the
2026-08-18 entry above), via a structurally different route (one
add-artifact call per demuxed item instead of one batched call over a
parallel-list loop).

**Flagged, not resolved:** `community/list_demux`'s exact output field
name has never been used live anywhere in this repo — reconstructed as
`value` from the field-frequency table in
`docs/vpe-extraction/utility-blocks.md` (`data.customDatapaths.list_demux
.data.output.value`), not confirmed against a real GUI instance.
`constraints.md`'s "never invent native-block field structures" rule
applies here; noted as an open TODO (`next-steps.md`) to verify against
the user's air-gapped reference build rather than presented as canonical.

Scope still open at session end: whether to extend this build toward full
PB1 parity (re-entry guard, detail note, `Enrichment Complete` signal
artifact, and the 5 remaining artifact types — `Sender Email`/`Sender
Domain`/`Recipient Email`(to+cc)/`Threat Domain`/`Click Source IP`, all
sourced from the nested `events[].emails[]` list PB1's code loop walks,
not the flat `hosts.url` list this build already handles) is a decision
still pending the user's input, not yet made. Not committed — left
untracked pending that decision. **Update (2026-09-21):** the untracked
build was later deleted in a user-authorised cleanup (`docs/next-steps.md`)
and the 8.6 rebuild removed its live copy, so nothing is in flight; the two
questions above only matter if the build is revived.

---

## Known Limitations / Out of Scope

| Item | Reason | Future path |
|------|--------|-------------|
| Mock TRAP connector | Dev uses `proofpoint_trap_mock` (id=9) | Configure real TRAP asset in production |
| Public IPs only in mock | Private IPs don't resolve via DNS/WHOIS | Dev: use 1.1.1.1 (confirmed working) |
| No SIEM forwarding | Out of scope | Future: add Splunk action to `add_triage_note` |
| No bulk triage | One incident per PB3 run | Future: batch processing if needed |
| Extracted attachments not reputation-checked | PB4 vaults + hashes attachments but doesn't look up the SHA256 anywhere | Future: UC8 (MISP enrichment) could consume `Email Attachment` artifacts' `cef.fileHashSha256` |
| `phantom.vault_info()` return shape unverified before first live PB4 run | No playbook in this repo had called it before PB4 (see memory `project_soar85_vault_api_quirks`) | PB4 handles both plausible shapes defensively and logs on mismatch — confirm against real soar8 output on first test run, then simplify if only one shape is ever seen |

---

## Pre-conditions

**SOAR connectors installed:**
- [x] Proofpoint TRAP connector (app id=198, v1.0.13)
- [x] Generic DNS connector (app id=49)
- [x] Generic WHOIS connector (app id=185)

**Labels:**
- [x] `proofpoint_trap` label exists in SOAR Event Settings

**Assets configured:**
- [x] `proofpoint_trap_mock` (id=9): `base_url`, `api_key`, `verify_ssl=false`,
  `abuse_disposition=Unknown,Suspicious,Malicious,Spam,Bulk,Low Risk`,
  `sub_disposition` (empty — no filter; only meaningful when `abuse_disposition`
  includes `Unknown`, see `uc2_dev_notes.md`), `poll_state=new`,
  `recheck_lookback_days=7` (default, new field added 2026-08-13 with the
  post-ingestion-update fix — see "Fix (2026-08-13)" above)
- [x] `dns` (id=10): Generic DNS asset
- [x] `whois` (id=11): Generic WHOIS asset
- [x] `smtp` (id=18, added 2026-08-17): SMTP asset for PB6, `server=<lab-address-redacted>`, `port=8446`
  (mock, ansible controller), `ssl_config=None`, username/password blank — see PB6 section

**TRAP asset ingest settings (configure in SOAR UI):**
- [x] Asset `proofpoint_trap_mock` → ingest settings: label=`proofpoint_trap`, on_poll enabled —
  enabled 2026-08-03 (`ingest.poll=true`, see next-steps.md). Previously unchecked: this precondition
  was never actually completed, so UC2 had never fired automatically on soar8 — only ever via manual
  `POST /rest/action_run` triggers.

**SOAR user for prompts:**
- [x] `soar_local_admin` (id=1) exists — use this user as approver in dev, NOT `admin`

---

## Architecture

| # | Playbook | Type | Trigger | Scope |
|---|----------|------|---------|-------|
| 1 | `proofpoint_trap_detail` | automation | container created on label=`proofpoint_trap` | Fetch incident details, create artifacts |
| 2 | `proofpoint_trap_triage` | automation | container created on label=`proofpoint_trap` | Extract TRAP incident ID from container data, nothing else (was PB3, retriggered from manual 2026-08-12) |
| 3 | `proofpoint_trap_attachments` | automation | artifact created on label=`proofpoint_trap` | Parse vaulted "MIME Body" `.eml` artifacts, extract + vault file attachments (was PB4) |
| 4 | `proofpoint_trap_acknowledge` | data | analyst-run manually | Prompt for comment → assign TRAP incident to SOAR + status new→open + post comment (new 2026-08-12) |
| 5 | `proofpoint_trap_close` | data | analyst-run manually | Prompt for closure reason → `close incident` + comment (new 2026-08-12) |
| 6 | `proofpoint_trap_isolation_notify` | data | analyst-run manually | **Built + live-verified 2026-08-17.** Email the container owner a set of isolation-browser links for the container URL plus every threat URL PB1 found in the incident, so they can inspect them without direct exposure. See dedicated section below. |
| 7 | `proofpoint_trap_recheck` | automation | artifact created on label=`proofpoint_trap_recheck` (Timer asset, 15 min) | **Built 2026-08-18, live-verified 2026-09-22** (see "PB7 live-verified 2026-09-22"). Re-scans the whole in-window incident backlog (all states) for already-ingested incidents that changed since — a field edit, disposition change, or newly-linked event the checkpoint-based main pass can't see again. Moved off the connector's `on_poll`, see narrative above. |

`ip_enrich` (DNS + WHOIS enrichment) is no longer part of this UC as of 2026-08-12 — dropped from its
label set (`labels` array no longer includes `proofpoint_trap`). It's still shared across `tenable_ad`,
`es_soar_integration`, and `events_crowdsec` — see UC3's implementation plan.

**Pipeline:**
```
Proofpoint TRAP on_poll → container per incident: "TRAP-{id}: {summary}" (label: proofpoint_trap)
  └── proofpoint_trap_detail (auto, container trigger)
        → get_trap_incident → extract_data_to_artifacts (emails, domains, IPs)
        → add_detail_note + enrichment_complete signal artifact

  └── proofpoint_trap_triage (auto, container trigger — retriggered from manual 2026-08-12)
        → extract_incident_id → stop (no writes to TRAP)

  └── proofpoint_trap_attachments (auto, artifact trigger — fires on any artifact created in the
      container, including the connector-created "MIME Body" artifacts and PB1's own container-
      created trigger; re-scans + skips already-processed MIME Body artifacts each run)
        → extract_attachments → parse each unprocessed "MIME Body" vault file → vault + create
          "Email Attachment" artifact per attachment found (vaultId, fileName, fileHashSha256)

  (independent, analyst-launched from the container — neither chains off the automatic tier above
  or off each other)

  └── proofpoint_trap_acknowledge (data, analyst-run)
        → extract_incident_id → prompt_comment → process_comment
        → update_incident_assignee (assignee=SOAR) → set_incident_open (status=open)
        → add_trap_comment → add_ack_note

  └── proofpoint_trap_close (data, analyst-run)
        → extract_incident_id → prompt_close_reason → process_close_reason
        → close_trap_incident → add_trap_comment → add_close_note (sets container status=closed)

  └── proofpoint_trap_isolation_notify (data, analyst-run — requires the container itself
      already self-assigned as owner + status=open in the SOAR UI, see PB6 section)
        → extract_incident_id → resolve_recipient_and_build_links → send_isolation_email
          → add_isolation_note
```

**Design rationale — 5 playbooks instead of 1 (revised 2026-08-12):**
- PB1/PB2/PB3 always run automatically; PB4/PB5 always run manually. Combining them would require
  complex conditional logic to decide whether to wait for analyst input during an auto-triggered run.
- PB4 (acknowledge) and PB5 (close) are deliberately separate, independent entry points rather than
  one playbook with a branch — an analyst may acknowledge without closing (or vice versa on a
  reopened incident), and neither should require running the other first.
- Each playbook is independently re-runnable. PB1 can re-enrich if the incident changes. PB3 re-scans
  for unprocessed MIME Body artifacts each run. PB4/PB5 can run on any incident the analyst selects.

**Design rationale — signal artifact for pipeline coordination:**
PB1 creates an `enrichment_complete` artifact after creating all IP/domain/email artifacts. Originally
this let `ip_enrich` (dropped from this UC 2026-08-12, see "Restructure" above) trigger on the IP
artifacts it produced. With `ip_enrich` gone, nothing in this UC currently consumes the signal — it's
still created (harmless, cheap) and left available for future automation that wants to detect "PB1
finished" without polling.

**Design rationale — `data` type for PB4/PB5:**
Data playbooks cannot auto-trigger — they must be explicitly run by an analyst. This is by design: an
acknowledgement or closure decision must be human-driven. Using an automation playbook for either would
risk auto-acknowledging or auto-closing incidents. The analyst selects the container and runs PB4/PB5
from the SOAR UI.

---

## PB6: `proofpoint_trap_isolation_notify` (data) — Analyst Isolation-Link Email

**Status:** [x] planned | [x] built | [x] validated — **built + live-verified 2026-08-17.**

**Purpose:** Email the container owner a set of isolation-browser links for the container's own SOAR
URL plus every threat URL PB1 found in the incident (Proofpoint-style browser isolation — link opens
in a sandboxed browser instead of directly), so the analyst can inspect them without direct exposure.

**Trigger:** Manual run by analyst, launched from the container after reviewing PB1's enrichment.
Independent entry point, same convention as PB4/PB5 — no chaining, no writes back to TRAP.

**Inputs:** `isolation_browser_url` (playbook input, default `https://my_isolated_browser/browser?url=`)
— deliberately **not hardcoded** in the code block, per user decision (matches `constraints.md`'s "no
hardcoded asset/app names" spirit — this is a per-deployment config value, not project-fixed).

**Link format (user-specified 2026-08-13):**
```
{isolation_browser_url}{URL_ENCODED_target}
```
One link per target — the container's own SOAR URL (`{base_url}/mission/{container_id}`) plus each
unique threat URL found in the incident.

**Built flow (`playbooks/proofpoint_trap/proofpoint_trap_isolation_notify.py`):**
```
on_start → extract_incident_id (reused shared CF, subject/context line)
  → read_incident_id (code bridge, same pattern as PB4/PB5)
  → resolve_recipient_and_build_links (code):
      - precondition: container.get('owner') truthy AND container.get('status') == 'open',
        else add_note + phantom.error + return (no email sent)
      - resolve owner -> email via GET /rest/ph_user?_filter_username="<owner>" (see platform
        quirk below, NOT a path lookup by id)
      - collect_threat_urls: phantom.collect2(datapath=["artifact:*.cef.url"], scope="all"),
        dedup, drop Nones — cef.url is unique to "Threat Domain" artifacts so no separate
        artifact:*.name filter is needed
      - container_url = "{phantom.get_base_url()}/mission/{container.get('id')}"
      - isolation_browser_url read via its own separate phantom.collect2() call
        (playbook_input: datapaths can't share a collect2 call with other datapaths —
        constraints.md)
      - build one urllib.parse.quote()-encoded link per target, format subject/body
  → send_isolation_email (native action: "send email" on the new `smtp` asset, to/subject/body
    bound to resolve_recipient_and_build_links's output variables)
  → add_isolation_note (summary note: recipient, link count, send status/message)
```

**Recipient resolution — resolved 2026-08-17 (was deferred 2026-08-13):** chose option 1 from the
three drafted — require the analyst to have already self-assigned the **container itself** as owner
and set the **container's own** status to `open` in the SOAR UI (both are standard SOAR case fields,
distinct from PB4's TRAP-side `update_incident_assignee`/`set_incident_open` calls, which touch the
*remote TRAP incident's* assignee/status, not the container's). Fails fast with a note if either is
missing or the resolved user has no email — no silent fallback, since a real isolation link must reach
a real person.

**Platform quirk found live (2026-08-17):** inside a playbook's `container` dict, `container['owner']`
is the **username string**, not the numeric id the raw `GET /rest/container` REST response shows
(confirmed on container 1661: REST showed `owner: 1, owner_name: "soar_local_admin"`, but the
in-playbook `container` object's `owner` value was the string `"soar_local_admin"`, same as
`owner_name`). A first version assumed `owner` was a path-friendly numeric id and called
`GET /rest/ph_user/<owner>`, which silently 404'd/returned no `email` — found immediately on the first
live run (container 1661, `soar_local_admin` as owner) because the failure note surfaced it clearly.
Fixed to filter by username instead: `GET /rest/ph_user?_filter_username="<owner>"&page_size=1`. Not
yet added to `constraints.md`'s API Gotchas list — worth doing if another playbook ever reads
`container['owner']`.

**SMTP asset — added 2026-08-17, mock-first.** `soar-connectors/reference_connectors/phantom-apps/Apps/
phsmtp/` (already-vendored reference connector, `send email` action) tarred (`tar -C
reference_connectors/phantom-apps/Apps phsmtp`, top-level dir preserved) and installed via
`soar-connectors/tools/install_app.sh` → app id=152 on soar8. Asset `smtp` (id=18) created via
`POST /rest/asset` pointed at the new mock, `ssl_config: "None"`, username/password left blank (phsmtp's
own `_test_asset_connectivity` only sends a real test email when credentials are configured — with none
set it's a bare connect+EHLO, which the mock fully supports). One asset gotcha hit: `primary_voting`/
`secondary_voting` must be `0`/falsy (not omitted, not `true`) or `test connectivity` fails with
`"Primary owner voting scheme is invalid ... Required votes: 1, number of active users: 0"` — unrelated
to the actual SMTP connectivity, just an approval-workflow field every asset in this repo sets to `0`.
**Note for whoever builds UC9 next:** UC9's own doc (`uc9_implementation_plan.md`) had an identical
"confirm SMTP asset exists on soar8" open question for its `zscaler_dlp_user_notify` PB — this same
`smtp` asset/connector is ready to reuse, not a UC2-only asset (also added to
`export_handover.py`'s `proofpoint_trap` `template_assets` for that reason, even though UC2 itself only
uses the one `send email` action).

**Mock SMTP server — new, `migration/mock-backend/mock_smtp.py`** (port 8446). Unlike the other three
mocks in that directory (HTTPS REST fakes), this speaks real SMTP wire protocol over plain TCP — no
TLS/AUTH support, matching the asset's `ssl_config: None` + blank credentials. Received messages land
as `.eml` files under `mock-backend/received/` (gitignored) for verification. Wired into
`mock_start.sh` as a 4th server. **Firewall:** soar8 (<lab-address-redacted>) couldn't reach the new port at
first — only 8443 had a firewalld rich-rule scoped to that source IP; added the same narrowly-scoped
rule for 8446 (`source address="<lab-address-redacted>" port="8446" protocol="tcp" accept`, permanent + reload)
after confirming with the user, since it's a persistent change to the ansible-controller host's own
firewall, same pattern/scope as the existing 8443 rule.

**Data source:** reuses PB1's existing "Threat Domain" artifacts (`cef.url` = full URL as of the
2026-08-13 CEF rename — confirmed against the live `proofpoint_trap_detail.py` source 2026-08-17, the
`cs1` field name in older prose here was already stale). **Still-open gap inherited from PB1, not this
PB's bug:** live-verified end-to-end only for the container-URL link — the container used for testing
(1661) had zero "Threat Domain" artifacts with `cef.url` populated (3 pre-existing ones elsewhere on
soar8 all show `cef.url: None`, predating the 2026-08-13 CEF rename), so the multi-link/threat-URL
branch is exercised by code review and the empty-case behavior only, not a live populated case. Revisit
once a fresh incident produces a live Threat Domain artifact with `cef.url` set (see PB1 section's own
note on this same gap).

**Live-verified (2026-08-17, soar8 + mock, container 1661):**
1. No owner / status `new` → clean failure note, zero app_runs, no email sent (confirms the fail-fast
   precondition).
2. Owner auto-assigned by the platform to the acting REST user on interaction, status still `new` →
   still correctly blocked (confirms both halves of the precondition are checked, not just owner).
3. Status set to `open` → first attempt failed on email resolution (the `owner` id-vs-username bug
   above), found and fixed same session.
4. Post-fix: full success — `send_isolation_email` succeeded, note recorded recipient
   `root@localhost` (soar_local_admin's real ph_user email) and 1 link sent, `mock_smtp.py` received and
   correctly stored a `.eml` with the right subject and one correctly percent-encoded isolation link to
   `https://soar8.<lab-address-redacted>:8443/mission/1661`.

**Handover mirror not yet refreshed** — same standing note as every prior UC2 change.

---

## Connectors & Assets

| Connector | Asset | Actions Used |
|-----------|-------|-------------|
| Proofpoint TRAP | `proofpoint_trap_mock` (id=9) | `get incident`, `close incident`, `add comment`, `update team and assignee`, `set incident field value` (new 2026-08-12 — Alerts API v1). `add user to incident`/`update incident description` also added but not currently wired into any playbook. `download mime body` runs at the connector level during `on_poll` (not called directly from a playbook) — its output is consumed by PB3. |
| Generic DNS | `dns` (id=10) | No longer used by this UC (was only `ip_enrich`, dropped 2026-08-12) |
| Generic WHOIS | `whois` (id=11) | No longer used by this UC (was only `ip_enrich`, dropped 2026-08-12) |
| SMTP (`phsmtp` reference connector, app id=152) | `smtp` (id=18) | `send email` — PB6 only. Shared asset, also earmarked for UC9. |

---

## Data Model

**TRAP Incident:**
- Top-level entity with `id`, `summary`, `score`, `state`, `disposition`
- Contains `events`: child records — email deliveries (`messageDelivered`), clicks (`clickPermitted`/`clickBlocked`)
- `on_poll`: uses `expand_events=false` (lightweight container creation)
- `get incident`: defaults `expand_events=true` (full event data with emails, domains, click IPs) —
  **as of connector v1.0.19 (2026-08-13) this is a real boolean checkbox parameter**, not hardcoded;
  reverses the 2026-08-13 code-review note that called it "confirmed, left as-is". `list incidents`
  already had this exposed the same way. PB1 (`get_trap_incident`) still never sets it, so its own
  behavior is unchanged. Live-verified: `expand_events=false` correctly returns `event_ids` only, no
  nested `events` array.

**CEF Artifact Mapping:**

| Artifact Name | CEF Field | Contains Type | Source |
|--------------|-----------|---------------|--------|
| Sender Email | `emailAddress`, `cs2` subject, `cs3` bodyType, `cs6` abuseCopy, `emailHeaders` (dict, added 2026-08-13) | `email` | event.sender + email.subject/bodyType/abuseCopy/headers |
| Sender Domain | `sourceDnsDomain` | `domain` | event.sender domain |
| Recipient Email | `emailAddress` | `email` | event.recipients |
| Threat Domain | `destinationDnsDomain`, `cs1` full URL (added 2026-08-13) | `domain` | event.threat URL domain |
| Click Source IP | `sourceAddress` | `ip` | event.clickIP |
| Enrichment Complete | `message`, `cn1` (event count), `cn1Label` | — | PB1 signal |
| MIME Body | `vaultId`, `fileName` | `vault id` | PB1 (`proofpoint_trap_detail`, since 2026-08-20 — see FR-21), one per event; connector's native "download mime body" action does the fetch/vault, PB1 builds the artifact |
| Email Attachment | `vaultId`, `fileName`, `fileHashSha256` | `vault id`, `sha256` | PB3 (`proofpoint_trap_attachments`, was PB4), one per file attachment found inside a MIME Body's `.eml` |

---

## PB1: `proofpoint_trap_detail` (automation) — Incident Detail + Artifact Creation

**Status:** [x] built | [x] deployed (id=615, v104) | [x] validated ✓

**Inputs:** none (reads from container name)
**Output:** none (creates artifacts + note in container)

**Flow (current, post 2026-08-14/15/16 rework):**
```
on_start → filter_event_info (filter) → get_trap_incident (action) → extract_data_to_artifacts (code)
  → dispatch_event_artifacts (action) → prepare_detail_note (code) → dispatch_detail_note (action)
  → finalize_detail (code) → dispatch_enrichment_complete (action) → on_finish
```

**Node table:**
| Step | Type | Name | Purpose |
|------|------|------|---------|
| 0 | start | `on_start` | Count-based re-entry guard, then dispatches to `filter_event_info`. |
| 2 | filter | `filter_event_info` | Native filter block, narrows artifacts to `name == "Event Info"` so `get_trap_incident`'s `incident_id` binds to one reliable `cef.incidentId` value instead of a raw wildcard (which resolved to `"None"` on non-full-fan-out runs). |
| 3 | action | `get_trap_incident` | `phantom.act("get incident")` with `expand_events=true`. Param: `incident_id` bound to the filtered datapath. |
| 4 | code | `extract_data_to_artifacts` | Iterate events, build the artifact batch (Sender/Recipient/Cc Email, Sender/Threat Domain, Click Source IP) with per-item `name`/`label`/`cef_dictionary`/`contains` output-variable lists. `container_id`/`source_data_identifier` are single constants, not per-item. |
| 8 | action | `dispatch_event_artifacts` | Native "add artifact", one `phantom.act()` call fanning out over the batch. `container_id`→`container:id`, `source_data_identifier`→`container:source_data_identifier` (both bare-string native bindings; see finding below). |
| 5 | code | `prepare_detail_note` | Build note title/content from `get_trap_incident`'s summary/event_count/score/state + the artifact count. |
| 6 | action | `dispatch_detail_note` | Native "add note". |
| 7 | code | `finalize_detail` | Build the `enrichment_complete` signal artifact's cef_dictionary. |
| 9 | action | `dispatch_enrichment_complete` | Native "add artifact", terminal — creates the `Enrichment Complete` signal artifact. |
| 1 | end | `on_finish` | |

**Block inventory:** 4 action · 1 filter · 0 prompt · 0 decision · 4 code

**2026-08-16 session findings (PB1-only, `soar-playbooks` commits `cdfbd88`..`9faba02`):**
- **Filter block edges need `conditions:[{index:N}]`** or the VPE GUI crashes (fatal rendering error) opening any downstream node bound to the filter's output — deploy/validate_python/live-run all pass regardless; only the browser console catches it. See memory `project_soar_filter_block_edge_conditions.md`.
- **`container_id` must be a bare string `"container:id"` in the JSON**, not the general `{functionId, parameters, template}` object form every other binding uses — the object form renders as `[object Object]` in the VPE picker. Root-caused by diffing against a GUI-saved version where it rendered correctly. `source_data_identifier` bound to `container:*` does NOT have this restriction (object form renders fine there).
- **`source_data_identifier` is mandatory but does NOT need to be unique per artifact** — live-tested (two artifacts, same container_id+SDI+name, different cef): SOAR created both, no dedup/merge. Simplified from a computed `"{container_sdi}-{uuid4}"` per artifact down to a single constant (`container:source_data_identifier`, same value for the whole batch), dropping the `uuid` import and a whole output-variable list.
- **GUI open+save regenerates action-node code from templates, not just code-block `userCode`** — for a list-valued binding, the regenerated code uses `phantom.format()` with a plain template, which comma-joins the list into one string (`flatten_format_args()`) instead of fanning out. Broke `dispatch_event_artifacts` twice (GUI versions 593, 599) after routine opens; each time required redeploying known-good source. **Standing hazard for any playbook with a list-valued action-parameter binding** — see memory (new this session) for the full mechanism.
- `inputParameters` should list every native datapath a code block reads via `phantom.collect2()`, not just the ones the block can't proceed without (it doesn't gate execution — that's `advanced.join`) — `prepare_detail_note` was missing its `get_trap_incident:*` dependencies, now declared.

**Why code for `extract_data_to_artifacts`:** Creating multiple artifacts of different types from a nested
data structure (events → sender/recipients/clickIP) requires iteration and deduplication logic that no
native block can express. REST artifact creation via `phantom.requests.post()` is the correct pattern
(confirmed by community CF `artifact_create`).

**Deduplication:** `seen_emails`, `seen_domains`, `seen_ips` sets prevent duplicate artifacts when
PB1 is re-run on the same container (e.g., incident updated in TRAP). One artifact per unique value.

**Extended field extraction (added 2026-08-13, user request):** Sender Email gained `cs2`=subject,
`cs3`=bodyType, `cs6`=abuseCopy (stringified `"true"`/`"false"`, empty if the field is absent/not a
bool), and `emailHeaders` — a filtered dict pulled from `email.headers` (case-insensitive lookup) for
exactly: `To`, `Date`, `From`, `Subject`, `Return-Path`, `Content-Type`, `MIME-Version`,
`Received-SPF`, `DKIM-Signature`, `X-Google-DKIM-Signature`,
`X-MS-Exchange-CrossTenant-OriginalAttributedTenantConnectingIp` — only keys actually present survive
into the dict. Same first-occurrence-only caveat as the existing messageId/deliveryTime fields: since
Sender Email is deduped per address across the whole incident, a second email from an
already-seen sender won't refresh these. Threat Domain (both the per-email `urls[]` and event-level
`threatURL` sources) gained `cs1`=the full URL string alongside the existing domain-only
`destinationDnsDomain`. **Live-verified** (container 1431, fresh post-deploy incident): Subject/Body
Type populate correctly. `emailHeaders` initially came back empty on mock data — traced to all 14 seed
emails across the mock's 10 fixture incidents having `headers: {}` hardcoded (no code path anywhere
ever populated real values). Fixed 2026-08-13, same day: populated all 14 with realistic
To/Date/From/Subject/Return-Path/Content-Type/MIME-Version/Received-SPF/DKIM-Signature/
X-Google-DKIM-Signature/X-MS-Exchange-CrossTenant-OriginalAttributedTenantConnectingIp values derived
from each email's own sender/recipient/subject/messageId/deliveryTime; `mock-api-gateway.service`
restarted (user confirmed), re-verified live through the real playbook against incident 1001 — the
`Sender Email` artifact's `cef.emailHeaders` now shows all 11 fields. Commit `4b99c02` (splunk-lab).
Threat Domain's new `cs1` remains **unit-checked only, not live** — every mock fixture's threat URL
shares the sender's own domain, so `seen_domains` (shared between the Sender Domain and Threat Domain
dedup) always suppresses the Threat Domain artifact once Sender Domain has already claimed that domain;
this is
pre-existing dedup behavior, not something this change touched, but it means no live incident has ever
exercised a real Threat Domain artifact end-to-end on this mock data — worth keeping in mind if this
ever needs re-verifying against a real TRAP tenant. Deployed: id=315 v32. Commit `2b28531`.

---

## [HISTORICAL] `ip_enrich` (automation) — IP Enrichment (was PB2, dropped from this UC 2026-08-12)

**No longer part of UC2.** `proofpoint_trap` was removed from this playbook's `labels` array
2026-08-12 (see "Restructure" note under Context) — it no longer fires on TRAP incident artifacts.
It's still shared across `tenable_ad`/`es_soar_integration`/`events_crowdsec`; see UC3's
implementation plan for the current design. Section kept below as historical record of the
shared-playbook design while it was part of this UC.

**Status:** [x] built | [x] deployed (id=221, v9) | [x] validated ✓ (labels=proofpoint_trap+tenable_ad+es_soar_integration+events_crowdsec, prior to the 2026-08-12 removal)

**Inputs:** none (collects all `sourceAddress` artifacts from container)
**Output:** none (writes enrichment note to container)

**Flow:**
```
on_start → dns_reverse_lookup (action) + whois_ip_lookup (action) → create_enrichment (code)
```

**Node table:**
| Step | Type | Name | Purpose |
|------|------|------|---------|
| 1 | start | `on_start` | Collect all artifacts. Filter for those with `sourceAddress` CEF field in Python code (NOT via `filter_artifacts` parameter — it expects artifact objects, not a query dict). |
| 2 | action | `dns_reverse_lookup` | `lookup ip` on `dns` asset. One call per unique IP. |
| 3 | action | `whois_ip_lookup` | `whois ip` on `whois` asset. One call per unique IP. |
| 4 | code | `create_enrichment` | Collect results. Build enrichment summary note. |
| — | end | `on_finish` | |

**Block inventory:** 2 action · 0 prompt · 0 decision · 1 code

**Shared playbook — labels active (live on soar8, confirmed 2026-08-03):**
```json
"labels": ["proofpoint_trap", "tenable_ad", "es_soar_integration", "events_crowdsec"]
```
The two extra labels (`es_soar_integration`, `events_crowdsec`) were added after this doc's
original UC2/UC3 design and are picked up here to keep the doc in sync with the live playbook —
this playbook is now shared across more sources than just UC2/UC3. No TRAP-specific logic
anywhere. Works on any container with `sourceAddress` artifacts.

**Critical data path gotchas (burned in UC2 debugging):**
- DNS: `action_result.summary.hostname` (NOT `action_result.data.*.hostname` — data items are raw strings)
- WHOIS: `action_result.summary.asn`, `.registry`, `.country_code` + `action_result.data.*.nets`
- `collect2()` `filter_artifacts`: expects pre-filtered artifact object list — NOT a query dict
  → filter in Python: `[a for a in artifacts if a.get("cef", {}).get("sourceAddress")]`

---

## [HISTORICAL] `proofpoint_trap_triage` full prompt/close flow (was PB3, split 2026-08-12)

**Superseded 2026-08-12.** This section documents the original design and validation history of
`proofpoint_trap_triage` when it still contained the full extract → prompt → close/keep-open flow.
As of 2026-08-12 the playbook (now **PB2**) is trimmed to ID extraction only and retriggered
automatically on container creation; the prompt/close logic below was split into two new,
independently analyst-launched playbooks — **PB4** `proofpoint_trap_acknowledge` (comment + assign to
SOAR + status new→open) and **PB5** `proofpoint_trap_close` (closure reason + `close incident` +
comment) — see their sections further below for the current design. Kept here as historical
design/validation record (dated bug fixes, live test results) rather than rewritten in place.

### [HISTORICAL] `proofpoint_trap_triage` (data) — Analyst Triage Prompt

**Status:** [x] built | [x] deployed (id=293, v28) | [x] validated ✓ — **genuinely, for the first time,
2026-08-12, all 3 paths, including a real user-driven approval.** Close Incident (container closed +
TRAP incident closed + commented), Keep Open (container left open + note recorded — confirmed twice:
once via REST self-test, once via the actual user answering a live prompt in the SOAR UI), and Prompt
Expiry (left genuinely unanswered 30min, resolved cleanly) all confirmed complete end-to-end live.
Everything below this line predating 2026-08-12 describing this as "validated" was true only in the
sense that the prompt *rendered*; the actual decision→action flow had never once completed in this
project's history until three real bugs (found and fixed the same session) stopped blocking each
other. See
`next-steps.md` for the full narrative and memories `project_soar85_collect2_custom_function_broken` +
`feedback_prompt_approval_ask_user`.

**Inputs:** none (reads from container)
**Output:** `action_choice` (string), `reason` (string)

**Flow:**
```
on_start → extract_incident_id → prompt_analyst (prompt) → process_decision → [close: close_trap_incident (action) → prepare_close_comment (code) → add_trap_comment (action)] → add_triage_note
                                                                              [keep open: add_triage_note]
                                                                              [expired: add_triage_note]
```

**Node table:**
| Step | Type | Name | Purpose |
|------|------|------|---------|
| 1 | start | `on_start` | |
| 2 | code | `extract_incident_id` | Parse TRAP ID from container name. Expose as output variable. |
| 3 | prompt | `prompt_analyst` | Calls `phantom.prompt2()` directly (see correction below). Approver: `container.get('owner_name')`, **falls back to `soar_local_admin`** (fixed 2026-08-12 — TRAP containers never get an owner, so this was always empty, causing SOAR to reject the prompt outright before it ever reached an analyst). Message: "TRAP-{0}: {1}" with incident_id + container name. Responses: list choice "Close Incident"/"Keep Open" + free-text reason. **30min timeout** (changed from 1440min/24h 2026-08-12). |
| 4 | code | `process_decision` | Reads the answered prompt via `GET /rest/approval` (fixed 2026-08-12 — see below), **not** `phantom.collect2()`. Handles expired/no-response. Exposes `action_choice`/`reason` via `save_run_data`. |
| 5 | action | `close_trap_incident` | `phantom.act("close incident")` on `proofpoint_trap_mock`. Reads `process_decision`'s reason via `get_run_data` (fixed 2026-08-12, was broken `collect2`). Close path only. |
| 6 | code | `prepare_close_comment` | Composes the closure comment text conditioned on `close_trap_incident`'s actual result. Reads via `get_run_data` (fixed 2026-08-12, was broken `collect2`). |
| 7 | action | `add_trap_comment` | `phantom.act("add comment")` on `proofpoint_trap_mock`, reads `prepare_close_comment`'s output via `get_run_data` (fixed 2026-08-12, was broken `collect2`). Close path only. |
| 8 | code | `add_triage_note` | Build summary note. Set `phantom.set_status(status="closed")` if closed. Add `phantom.add_note()`. Reads `process_decision`'s output via `get_run_data` (fixed 2026-08-12, was broken `collect2`). |
| — | end | `on_finish` | |

**Block inventory:** 2 action · 1 prompt (see correction) · 0 decision · 4 code

**CORRECTION (2026-08-12) — the "native prompt block" claim was never accurate.** This section
previously said "native prompt block generates the correct VPE wiring... using `phantom.prompt2()` in
a code block loses all of this," as if `prompt_analyst` were genuinely SOAR-generated. It never was:
the deployed `.py` has always called `phantom.prompt2()` directly from a `@phantom.playbook_block()`
function — exactly the anti-pattern `constraints.md` warns about ("`phantom.prompt2()` inside code
block → use native prompt block instead"). Confirmed via `GET /rest/playbook/<id>.metadata.actions`,
which only ever lists genuine `phantom.act()` calls ("close incident", "add comment") — never
`prompt_analyst`. This mismatch between the JSON's `type: "prompt"` node and the `.py`'s raw
`phantom.prompt2()` call is the root cause of the `collect2` bug below. Left as-is rather than rebuilt
as a true native block (would need GUI access to regenerate correctly) — the REST-based `process_decision`
fix works regardless of this and required no GUI.

**CORRECTION (2026-08-12) — `collect2()` reading `:custom_function:` datapaths is broken on this SOAR
8.5 instance.** The previous "Output variables pattern" note here claimed downstream blocks "need" to
read `process_decision`'s output via `:custom_function:` datapaths for native-block template binding.
In reality **4 separate `phantom.collect2()` calls in this playbook** (`process_decision`,
`close_trap_incident`, `prepare_close_comment`, `add_trap_comment`, `add_triage_note` all touched this)
crashed with `RuntimeError: Unable to determine how to collect results for
{DatapathClassification.LEGACY_CUSTOM_FUNCTION_RESULT}` — confirmed by reading SOAR's own
`datapath_classifier.py`/`api_collect2.py` on the live host: that classification maps to `None` in
SOAR's own dispatch table with a `# Look into / add tests` comment. Genuinely unimplemented on the
platform, not a project bug. Fixed by switching every one of those reads to
`phantom.save_run_data()`/`get_run_data()` — the pattern already used successfully elsewhere in this
same file (`extract_incident_id`) and throughout the rest of this project. Full writeup: memory
`project_soar85_collect2_custom_function_broken`.

**Prompt expiry:** `process_decision` checks the approval's `status` field (`"approved"` vs anything
else). **Confirmed live 2026-08-12** — left a real prompt unanswered for its full 30min timeout: SOAR
resolves the approval's `status` to the literal string `"expired"` (previously unknown/unverified),
correctly falls into the "anything else" branch, produces a clean "TRAP Triage - Prompt Expired" note,
no crash. **Platform cosmetic quirk, not a bug**: the outer `playbook_run` still reports `"status":
"failed"` even on this cleanly-handled path — SOAR marks any run containing a timed-out prompt action
as failed at the platform level regardless of how gracefully the callback handled it. Don't alert on
`playbook_run.status == "failed"` alone for this playbook without also checking whether a proper
triage note exists.

**Approver gotcha:** Prompt approval in dev requires `soar_local_admin` (id=1), NOT `admin` — now also
the automatic fallback when `container.get('owner_name')` is empty (see above), so this is no longer
just a manual-approval note, it's load-bearing.

**Prompt approval workflow:** `POST /rest/approval/{id}/respond` genuinely works (confirmed 2026-08-12
— see memory `feedback_prompt_approval_ask_user` for the full correction; an earlier note here claiming
no working endpoint existed was wrong, caused by the bugs above, not a real platform gap). For real
triage decisions, always let the actual analyst answer in the SOAR UI — the REST path is for dev/test
self-verification only, never for fabricating a real decision.

---

## PB3: `proofpoint_trap_attachments` (automation) — MIME Attachment Extraction

**Renumbered from PB4 to PB3, 2026-08-12** (see "Restructure" note under Context) — logic and
validation history below are unchanged, only the UC-wide numbering shifted since `ip_enrich` (old PB2)
was dropped and the old PB3 (`proofpoint_trap_triage`) was trimmed into the automatic tier. Historical
narrative below still refers to it as "PB4" in places — that's the number it had when these notes were
written; see the Architecture table above for current numbering.

**Status:** [x] built | [x] deployed (id=294, v11) | [x] validated ✓ — **all paths confirmed live**,
including the completeness additions (2026-08-12, via a temporary debug harness — see below).

**Fix (2026-08-16) — GUI lint import gap.** User's own VPE screenshot showed `extract_attachments`
flagged with "4 Python validations warnings." Same root cause the PB1 session had already found and
documented (memory `project-soar-filter-block-edge-conditions`'s uuid/urllib.parse update): SOAR's GUI
recompiles/lints each code block in isolation and doesn't see module-level imports. This block uses
`os`/`hashlib`/`html`/`mimetypes`/`tempfile`/`email`/`email.policy`/`email.utils.getaddresses`/
`parseaddr`, none restated locally. Fixed by re-importing all of them at the top of the block's Custom
Code section (same convention `proofpoint_trap_detail.py` already uses for `urllib.parse`). No behavior
change — live-verified against a fresh `on_poll` (container 1661): pipeline still succeeds, "Email
Attachment" artifact still correctly extracted. Commit `f143a29`, deployed id=622 v73.

**Extended 2026-08-12 (same day, after a closer completeness review):**
- Fixed a real bug: forwarded emails attached as `.eml` (`message/rfc822`) were silently skipped
  entirely (they report `is_multipart()=True` — wraps one `Message` object, not raw bytes — which
  tripped the "skip container parts" check). Now serialized via `.as_bytes()` and vaulted like any
  other attachment.
- Added MIME-type/filename mismatch detection (`mimetypes.guess_type` vs declared `Content-Type`) as a
  disguised-executable signal, surfaced as `cs1`/`cs1Label` on the Email Attachment artifact.
- Added `Return-Path` vs `From` mismatch detection (envelope spoofing tell) to the Email Content note.
- Added Cc extraction from the raw MIME headers as "Recipient Email" artifacts (`cs1=cc`) — same shape
  PB1 already attempts from the structured API and never finds anything real there (see PB1's own
  comment); PB4 has the actual headers.

**Live verification (2026-08-12, same day):** synthetic-message unit tests weren't enough on their own
for something headed to production, so built a one-off debug harness (temporary code in `on_start`,
removed before final deploy) that vaults a crafted `.eml` covering all four additions at once — Cc
header (2 addresses), `Return-Path` ≠ `From`, a `.pdf`-named attachment declared
`application/x-msdownload`, and a `forwarded_original.eml` `message/rfc822` attachment — then creates
its "MIME Body" artifact and lets the real deployed playbook process it on soar8 (container 1357).
Confirmed correct, all four:
- MIME-type mismatch: `cs1` = `"declared application/x-msdownload, expected application/pdf from
  filename"` ✓
- Forwarded email: extracted as its own "Email Attachment" (`fileType: message/rfc822`), description
  prefixed "Forwarded email" ✓
- Cc: two separate "Recipient Email" artifacts, one per address, `cs1=cc` ✓
- Return-Path: note correctly showed `"does not match From (attacker@evil-phish.example.com)"` ✓

**Status (original build):** both paths confirmed live
2026-08-12 against soar8:
- **Zero-attachment path** (container 1330, `playbook_run_id=5963`): `vault_info()` succeeded, `.eml`
  parsed, 0 attachments found (matches the mock's original plain-text-only MIME output), note added,
  dedup marker set.
- **Real-attachment path** (container 1330 again, `playbook_run_id=5984`, after fixing the mock — see
  below): fed a real `multipart/mixed` `.eml` for incident 1002/`evt_2004` (attachment
  `resume_2026.docm`) via a manual `download mime body` call + hand-created MIME Body artifact.
  `extract_attachments` created an "Email Attachment" artifact with the correct `vaultId`, `fileName`,
  and a real SHA256 hash of the mock payload; note showed "Total attachments extracted: 1".

**Mock server fix required first** — the TRAP mock (`_trap_build_mime()`) never actually built a real
MIME attachment part, only a text line naming the file, so nothing had a real payload to extract.
Fixed in the live copy, **`soar8/migration/mock-backend/mock_api_gateway.py`** (this is the actual
running mock — see `migration/mock-backend/README.md`; restarted via the `mock-api-gateway.service`
systemd unit on the ansible controller, <lab-address-redacted>, with user confirmation before the restart).
**Divergence found along the way**: `soar-connectors/test/mock_api_gateway.py` is a second, stale copy
of the same file — different (older, pre-real-schema-correction) `TRAP_INCIDENTS` structure, missing
the async-service routing the live copy has. Applied the same attachment fix there too for
consistency, but it is not what soar8 actually runs; worth reconciling or deleting one copy — not done
this session, logged in `next-steps.md` #56.

**Added 2026-08-12** in response to a user question about what `download mime body`/"MIME Body"
actually contains (raw `.eml` bytes, per FR-21) and whether attachments could be pulled out of it.
Closes the FR-21 known-limitation gap ("MIME body not surfaced in playbook UI"). Extended same-day
(still 2026-08-12) to also surface the email body + auth/routing headers, after the user asked what
else was worth pulling out of the MIME content and confirmed they wanted a rendered body, not raw
source.

**Inputs:** none (reads MIME Body artifacts from container)
**Output:** none (creates "Email Attachment" artifacts, "Email Content" notes, summary note)

**Flow:**
```
on_start → extract_attachments (code)
```

**Node table:**
| Step | Type | Name | Purpose |
|------|------|------|---------|
| 1 | start | `on_start` | |
| 2 | code | `extract_attachments` | Find "MIME Body" artifacts not yet marked `data.attachments_extracted`. For each: `phantom.vault_info(vault_id=...)` → read the vaulted `.eml` from disk → parse with stdlib `email` (policy.default) → **(a)** walk parts for `Content-Disposition: attachment` → `phantom.vault_add()` each into a temp file first, SHA256 the payload → CEF "Email Attachment" artifact (`vaultId`, `fileName`, `fileHashSha256`) via REST (same idiom as PB1's `extract_data_to_artifacts`, for `cef_types` support `phantom.add_artifact()` lacks) — **(b)** `parsed.get_body(preferencelist=("html","plain"))` for the rendered body, plus `Authentication-Results`/`Reply-To`/`X-Originating-IP`/`Received` headers (none of this exists in TRAP's structured API) → one "Email Content" `phantom.add_note()` per event, formatted within the sanitizer's real tag allowlist (see below) → mark the MIME Body artifact processed. |
| — | end | `on_finish` | |

**`phantom.add_note()` HTML sanitizer — real allowlist confirmed live, not documented anywhere:**
probed directly (`h1,h2,p,b,i,ul,li,pre,details,summary,hr,a[href],code,div,span,br` sent as one
string, container 1330, cleaned up after) because the first real test silently lost every `<pre>` tag.
Confirmed via raw `POST /rest/container_note` in parallel (which preserved every tag untouched) that
this stripping is specific to `phantom.add_note()`'s own code path, not note storage in general.

| Survives | Stripped (text kept, tag dropped) | Survives but broken |
|----------|-----------------------------------|----------------------|
| `h1` `h2` `p` `b` `ul` `li` `hr` `span` `br` | `i` `pre` `details` `summary` `code` `div` | `a` — tag stays, `href` attribute is stripped, so links never work |

PB4's formatting only uses the confirmed-safe left column: plain-text body fallback uses `<p>` +
`<br>`-joined lines (not `<pre>`), the Received chain prints each hop directly (not
`<details>/<summary>`). **Known accepted limitation:** a real phishing email's own `text/html` body
(tables, images, div-based layout, links) goes through this exact same sanitizer when rendered — it
will get stripped down to bare readable text the same way, links included. Not solved here; would need
writing the HTML somewhere other than a native SOAR note to fully fix.

**Block inventory:** 0 action · 0 prompt · 0 decision · 1 code

**Why one code block, no native blocks:** email parsing and the playbook-side Vault API
(`phantom.vault_info`/`vault_add`) have no native VPE block equivalents — same rationale as PB1's
`extract_data_to_artifacts`.

**Trigger design (user-confirmed 2026-08-12):** new artifact-triggered playbook rather than folding
into PB1, matching the existing "one concern per playbook, artifact-triggered" pattern already used
by `ip_enrich` — decouples attachment extraction from PB1's container-created trigger and from any
assumption about whether MIME Body artifacts exist yet when PB1 fires.

**Re-entry / dedup:** Same shape as `ip_enrich`'s `ip_enrich_done` marker — re-scans all MIME Body
artifacts on every run (trigger fires on both container and any artifact creation per
`constraints.md`), skips ones already marked `attachments_extracted` in `artifact.data`. Attachment
artifacts themselves are deduped via `source_data_identifier` keyed on incident/event/filename/hash
prefix.

**`phantom.vault_info()` return shape — unverified, defensive by design:** no playbook in this repo
had called the playbook-side Vault API before this (see memory `project_soar85_vault_api_quirks` —
only `vault_add`'s 3-tuple return was ever confirmed, against official docs, not live). The code
handles both a 3-tuple `(success, message, entries)` and a bare list-of-dicts return, logging the raw
shape via `phantom.debug()` on anything unexpected. **First live test run must confirm which shape
soar8 actually returns** — simplify the handling once known and update this note + the quirks memory.

---

## PB4: `proofpoint_trap_acknowledge` (data) — Analyst Acknowledgement (new 2026-08-12)

**Status:** [x] built | [x] deployed (id=313, v3) | [x] validated ✓ — **genuinely, 2026-08-13**, both
halves: a real analyst answered the live prompt in the SOAR UI (container 1424, approval #12), and a
second run (container 1428, self-answered via REST on synthetic data — pure mechanics re-check, not a
fabricated decision) confirmed the downstream TRAP actions. That second run uncovered a real bug:
`update_incident_assignee`/`set_incident_field` 404'd — the connector was correctly rewritten
(v1.0.18) to call the legacy `POST /api/incidents/{id}/{team_and_assignee,incident_fields}.json`
endpoints, but the mock backend was never updated to implement them (only had `close.json`/
`comments.json`). Fixed in `soar8/migration/mock-backend/mock_api_gateway.py` (added all 4 missing
legacy POST routes — including the two unwired `add_user_to_incident`/`update_incident_description`
actions, for full contract parity), `mock-api-gateway.service` restarted on the ansible controller
(user confirmed), re-verified end-to-end: `update team and assignee` → success, `set incident field
value` → `status: open` → success, `add comment` → success; incident record confirmed via direct GET
(`assignee: SOAR`, `team: SOC`, `state: open`). The old `/api/v1/alerts` PATCH handler in the mock is
now dead code (nothing calls it since the connector rewrite) — left in place, not removed this pass.
Commit `105fb42` (splunk-lab repo). The stale second mock copy
(`soar-connectors/test/mock_api_gateway.py`, already flagged diverged — see next-steps §56) was **not**
patched with this fix — still open, see next-steps.

**Trigger:** Manual run by analyst, launched from the container after reviewing PB1-PB3's
artifacts/notes. Independent of PB2/PB3/PB5 — no chaining.

**Inputs:** none (reads from container)
**Output:** `comment` (string)

**Flow:**
```
on_start → extract_incident_id → prompt_comment (prompt) → process_comment
→ update_incident_assignee (action) → set_incident_open (action) → add_trap_comment (action)
→ add_ack_note
```

**Node table:**
| Step | Type | Name | Purpose |
|------|------|------|---------|
| 1 | start | `on_start` | |
| 2 | code | `extract_incident_id` | Same block as PB2 — duplicated since this playbook is independently manually-triggered (no chaining in this UC). |
| 3 | prompt | `prompt_comment` | `phantom.prompt2()` direct call (same established pattern as the old PB3's `prompt_analyst` — see its section's CORRECTION note on why this isn't a true native block). Approver: `container_owner`, falls back to `soar_local_admin`. One required free-text "Comment" field. 30min timeout. |
| 4 | code | `process_comment` | Reads the answered prompt via `GET /rest/approval`, not `phantom.collect2()` (same `LEGACY_CUSTOM_FUNCTION_RESULT` platform bug documented in PB2/old-PB3's history). Falls back to `"Acknowledged by SOAR"` on expiry/no-response — this playbook always proceeds to the TRAP updates, it doesn't skip them on timeout. |
| 5 | action | `update_incident_assignee` | `phantom.act("update team and assignee")` on `proofpoint_trap_mock`, `assignee="SOAR"`. New Alerts API v1 action — see "Alerts API v1" note below. |
| 6 | action | `set_incident_open` | `phantom.act("set incident field value")` on `proofpoint_trap_mock`, `field="status"`, `value="open"`. Same new action family. |
| 7 | action | `add_trap_comment` | `phantom.act("add comment")` — the existing, already-proven action, not `update incident description`. |
| 8 | code | `add_ack_note` | Summary note with the comment, prompt status, and all three action results. |
| — | end | `on_finish` | |

**Block inventory:** 3 action · 1 prompt · 0 decision · 3 code

**Stale note, corrected 2026-08-13:** this previously described `update_incident_assignee`/
`set_incident_open` as a "best-guess" `PATCH /api/v1/alerts?id={id}` contract — that was superseded by
the same day's code-review rewrite (see "Restructure (2026-08-13)" under Context): the real endpoints
are legacy `POST /api/incidents/{id}/team_and_assignee.json` and
`POST /api/incidents/{id}/incident_fields.json`, confirmed against the vendor's own API reference doc
and live-validated (this section's own Status line above already says so — this paragraph just never
got refreshed to match). The other two actions (`add user to incident`, `update incident description`)
still exist on the connector but aren't wired into this playbook.

**Why two separate action calls, not one — confirmed 2026-08-13:** `team_and_assignee.json` only
accepts `team`/`assignee` and has **no side effect on incident state** (vendor doc's own documented
response, "Updated Team and Assignee successfully," never mentions state; the mock's handler mirrors
this — writes `assignee`/`team` only, never touches `state`). Moving an incident from `new`→`open` is a
genuinely separate write, through the generic `set incident field value` action with `field="status"`
(the mock enum-validates this against `new`/`open`/`closed`, matching the vendor's real states). So
`update_incident_assignee` + `set_incident_open` as two sequential calls isn't redundant or a shortcut
waiting to be found — it's the correct shape of the real API, and no dedicated "change state" action is
needed.

**Why "SOAR" as a literal assignee string, not a SOAR platform user:** There's no SOAR-user concept on
the TRAP side — `assignee` is a marker on the TRAP incident record itself, not a reference into SOAR's
own user table. Adjust the literal if live testing shows the real API expects something else (e.g. an
email address).

---

## PB5: `proofpoint_trap_close` (data) — Analyst Closure (new 2026-08-12)

**Status:** [x] built | [x] deployed (id=314, v3) | [x] validated ✓ — **2026-08-13**, live against soar8
(container 1426, synthetic incident 1786568334, self-answered via REST — dev/test mechanics
validation, same established pattern as this UC's earlier rollup testing). Playbook run success:
`prompt_close_reason` → `close incident` → `add comment`, container status set to `closed`,
correct triage note. No new connector actions involved (reuses the already-proven `close
incident`/`add comment` actions), so no mock-backend gap here unlike PB4.

**Trigger:** Manual run by analyst, launched from the container whenever they're ready to close the
incident. Independent of PB2/PB3/PB4 — no chaining.

**Inputs:** none (reads from container)
**Output:** `reason` (string)

**Flow:**
```
on_start → extract_incident_id → prompt_close_reason (prompt) → process_close_reason
→ [success: close_trap_incident (action) → add_trap_comment (action)] → add_close_note
  [expired: add_close_note directly, no TRAP action taken]
```

**Node table:**
| Step | Type | Name | Purpose |
|------|------|------|---------|
| 1 | start | `on_start` | |
| 2 | code | `extract_incident_id` | Same block as PB2/PB4 — duplicated, no chaining. |
| 3 | prompt | `prompt_close_reason` | Same `phantom.prompt2()` direct-call pattern as PB4. One required free-text "Closure reason" field. Approver/timeout same as PB4. |
| 4 | code | `process_close_reason` | Same `GET /rest/approval` read pattern as PB4's `process_comment`. Unlike PB4, **does not** fail open on expiry — routes straight to `add_close_note` with no TRAP action, since closing without a real reason isn't the same risk profile as acknowledging. |
| 5 | action | `close_trap_incident` | Existing `close incident` action, unchanged from the old PB3 design — success path only. |
| 6 | action | `add_trap_comment` | Existing `add comment` action, closure comment conditioned on `close_trap_incident`'s actual result — same pattern as the old PB3's `prepare_close_comment`+`add_trap_comment`, collapsed into one block here. |
| 7 | code | `add_close_note` | Summary note with reason, prompt status, and action results. Sets `phantom.set_status(container, "closed")` on a successful TRAP close — same SOAR-side call the old PB3 made. |
| — | end | `on_finish` | |

**Block inventory:** 2 action · 1 prompt · 0 decision · 3 code

**No new connector actions** — reuses `close incident`/`add comment` exactly as the old PB3 did. This
playbook is a straight extraction from PB3's original close path, just re-triggered independently
instead of behind a Close/Keep-Open choice.

**Update (2026-08-13, later still) — `process_close_reason`'s Python if/else replaced with a native
decision block.** Closes the finding logged in `next-steps.md` #58: branching to two different next
blocks (`add_close_note` directly on expiry vs. `close_trap_incident` on success) inside a Python
function is exactly `constraints.md`'s decision-tree case for a native `decision` block, not `code`.
Fixed: `process_close_reason` now only computes `reason`/`prompt_status` and exposes `prompt_status` as
a proper output variable (`outputVariables: ["reason", "prompt_status"]`, matching the
`funcName:custom_function:var` datapath convention), then always calls a new node,
`check_prompt_status` (native `decision`, condition
`process_close_reason:custom_function:prompt_status == "success"`), which branches to
`close_trap_incident` (if) or `add_close_note` (else) — same `check_targets`-style decision node already
established in `cyberark_rotation_orchestrator.py`. `extract_incident_id` also converted the same session
(see "PB2/PB4/PB5 CF extraction" above) to call the shared `proofpoint_trap_extract_incident_id` CF via a
utility block + `read_incident_id` bridge block — this playbook's flow and node table below are updated
to match.

**Updated flow:**
```
on_start → extract_incident_id (utility, CF call) → read_incident_id (bridge) → prompt_close_reason (prompt) → process_close_reason
→ check_prompt_status (decision) → [if success: close_trap_incident (action) → add_trap_comment (action)] → add_close_note
                                     [else: add_close_note directly, no TRAP action taken]
```

**Updated node table (2026-08-13):**
| Step | Type | Name | Purpose |
|------|------|------|---------|
| 1 | start | `on_start` | |
| 2 | utility | `extract_incident_id` | Calls the shared `proofpoint_trap_extract_incident_id` CF. |
| 3 | code | `read_incident_id` | Bridge block reading the CF result, same pattern as PB2/PB4. |
| 4 | prompt | `prompt_close_reason` | Same `phantom.prompt2()` direct-call pattern as PB4. One required free-text "Closure reason" field. Approver/timeout same as PB4. |
| 5 | code | `process_close_reason` | Same `GET /rest/approval` read pattern as PB4's `process_comment`. Now exposes `prompt_status` as a real output variable instead of branching on it directly. |
| 6 | decision | `check_prompt_status` | **New 2026-08-13.** Routes to `close_trap_incident` (success) or `add_close_note` (anything else) — replaces the old in-Python if/else. |
| 7 | action | `close_trap_incident` | Existing `close incident` action, unchanged — success path only. |
| 8 | action | `add_trap_comment` | Existing `add comment` action, closure comment conditioned on `close_trap_incident`'s actual result. |
| 9 | code | `add_close_note` | Summary note with reason, prompt status, and action results. Sets `phantom.set_status(container, "closed")` on a successful TRAP close. |
| — | end | `on_finish` | |

**Block inventory (2026-08-13):** 2 action · 1 prompt · 1 decision · 1 utility · 3 code

**Live-verified (2026-08-13, soar8 + mock):** both `check_prompt_status` branches exercised directly
(not waiting the full 30min for a real expiry) — container 1521 approved via `POST
/rest/approval/{id}/respond {"status": "approve", ...}` correctly routed through `close_trap_incident` →
`add_trap_comment`, container closed, correct note; container 1520 **denied** (`{"status": "deny", ...}`
— not "approved", so `process_close_reason` treats it the same as an unanswered/expired prompt) correctly
routed straight to `add_close_note` with **zero** app_run entries for `close_trap_incident`/
`add_trap_comment`, container stayed `new`, note correctly shows "Prompt status: expired" / "No TRAP
action taken." Current live state: PB5 id=426 v24 (PB1-PB4 redeployed unchanged alongside it in the same
`deploy.sh --use-case proofpoint_trap` call).

---

## Files to Create / Modify

**New files** (`playbooks/proofpoint_trap/`):
- `proofpoint_trap_detail.py` + `proofpoint_trap_detail.json`
- `ip_enrich.py` + `ip_enrich.json` (dropped from this UC's label set 2026-08-12 — file stays, shared
  with `tenable_ad`/`es_soar_integration`/`events_crowdsec`)
- `proofpoint_trap_triage.py` + `proofpoint_trap_triage.json`
- `proofpoint_trap_attachments.py` + `proofpoint_trap_attachments.json` (added 2026-08-12)
- `proofpoint_trap_acknowledge.py` + `proofpoint_trap_acknowledge.json` (added 2026-08-12, PB4)
- `proofpoint_trap_close.py` + `proofpoint_trap_close.json` (added 2026-08-12, PB5)
- `custom_functions/proofpoint_trap_extract_incident_id.py` + `.json` (added 2026-08-13, later —
  shared by PB2/PB4/PB5, see "PB2/PB4/PB5 CF extraction" above)

**Modified files (2026-08-13, later — PB2/PB4/PB5 CF extraction):**
- `proofpoint_trap_triage.py`/`.json` (PB2), `proofpoint_trap_acknowledge.py`/`.json` (PB4),
  `proofpoint_trap_close.py`/`.json` (PB5) — `extract_incident_id` code block replaced by a utility
  block (calls the new CF) + bridge code block (`read_incident_id`)
- `proofpoint_trap_attachments.py`/`.json` (PB3) — `os.fdopen()` → `os.close()` + `open()`
  (`constraints.md` anti-pattern fix, no behavior change)
- `tools/deploy.py` — registered the new CF in `USE_CASES`; fixed `rebuild_cf_header_from_metadata()`'s
  zero-input CF signature bug (see above)
- `tools/pull_soar.py` — registered the new CF in `USE_CASES`

**Modified files (2026-08-12 restructure):**
- `playbooks/tenable_ad/ip_enrich.json` — removed `"proofpoint_trap"` from labels array
- `playbooks/proofpoint_trap/proofpoint_trap_triage.py`/`.json` — trimmed to ID extraction only,
  retriggered from manual (`data`) to automatic (`automation`, container created)
- `soar-connectors/connectors/proofpoint_trap/` — added `update team and assignee`,
  `set incident field value`, `add user to incident`, `update incident description` actions
  (Alerts API v1, `v1.0.16`)
- `migration/mock-backend/mock_api_gateway.py` — added `do_PATCH`/`_trap_handle_patch` for the new
  Alerts API v1 endpoint
- `tools/pull_soar.py`, `tools/deploy.py`, `tools/snapshot.py`, `tools/export_handover.py` — registry
  updates for the playbook/asset changes above

**Modified files (when UC3 is added):**
- `playbooks/tenable_ad/ip_enrich.json` — add `"tenable_ad"` to labels array

---

## Build Order

1. Build + deploy `ip_enrich` (simplest — 2 actions + 1 code; verify DNS + WHOIS work standalone)
2. Build + deploy `proofpoint_trap_detail` (automation PB — test with manual on_poll trigger)
3. Build + deploy `proofpoint_trap_triage` (data PB — test prompt approval flow)
4. Build + deploy `proofpoint_trap_attachments` (automation PB — test against a MIME Body artifact
   from a container with `fetch_mime_on_poll` enabled; confirm `phantom.vault_info()` return shape
   live, see PB3/old-PB4 section)

**2026-08-12 restructure build order (on top of the above):**
5. Rebuild `proofpoint_trap` connector (new Alerts API v1 actions) and redeploy — see
   `soar-connectors/tools/build.sh proofpoint_trap`
6. Redeploy `proofpoint_trap_triage` (now trimmed + automation-triggered) and activate it
7. Build + deploy `proofpoint_trap_acknowledge` (PB4) — test the prompt, then confirm the mock's
   `/api/v1/alerts` PATCH reflects both `assignee` and `status`
8. Build + deploy `proofpoint_trap_close` (PB5) — test against the same container, confirm
   `close incident` + comment + container status=closed
9. Confirm `ip_enrich` no longer fires on a TRAP-labeled container (regression check on the label
   removal), and still fires normally for `tenable_ad`

**Deploy command:**
```bash
./tools/deploy.sh --use-case proofpoint_trap
```

---

## Post-Deploy Configuration (SOAR UI — required)

| Item | Setting | Value | Why |
|------|---------|-------|-----|
| `proofpoint_trap_detail` | Trigger | ~~Container created only (NOT artifact)~~ **CORRECTED 2026-08-12: no such setting exists.** `playbook_trigger` only has two valid values platform-wide (`artifact_created`, `container_resolved` — confirmed in `constraints.md` and by exhausting every plausible REST field/resource this session, see `next-steps.md`); `artifact_created` always fires on both container AND artifact creation. PB1's `on_start()` re-entry guard is the real (and sufficient) safety net — verified 0 duplicates across 3 fires on one container. | — |
| `ip_enrich` | Trigger | ~~Artifact created only (NOT container)~~ **Same correction applies** — no sub-restriction exists; `ip_enrich`'s own `ip_enrich_done`-per-artifact marker is what actually prevents duplicate enrichment notes, not a trigger setting. | — |
| `proofpoint_trap_detail` | Active | Yes | Deactivated after import by default |
| `ip_enrich` | Active | Yes (still active for `tenable_ad`/`es_soar_integration`/`events_crowdsec`) | `proofpoint_trap` removed from its `labels` array 2026-08-12 — no longer fires for TRAP incidents, still fires for the other three UCs |
| `proofpoint_trap_triage` | Trigger | Container created (`artifact_created`, same platform caveat as PB1's row) | **Changed 2026-08-12** — was a `data`/manual playbook, now `automation`. Trimmed to ID extraction only (no writes to TRAP) |
| `proofpoint_trap_triage` | Active | Yes | **Changed 2026-08-12** — must now be activated post-deploy like PB1/PB3, was previously N/A as a data playbook |
| `proofpoint_trap_attachments` | Trigger | Artifact created | Default trigger — must see MIME Body artifacts appear post-container-creation |
| `proofpoint_trap_attachments` | Active | Yes | Deactivated after import by default |
| `proofpoint_trap_acknowledge` | N/A | Data PBs cannot be activated | By design — analyst runs manually from the container (new 2026-08-12) |
| `proofpoint_trap_close` | N/A | Data PBs cannot be activated | By design — analyst runs manually from the container (new 2026-08-12) |
| TRAP asset | Ingest | label=`proofpoint_trap`, on_poll enabled | Required for TRAP connector to create containers |
| TRAP asset | ~~`fetch_mime_on_poll`~~ | — | **Removed 2026-08-20** (connector v1.0.30): MIME fetch moved into PB1 (`dispatch_mime_download`); nothing to set |
| TRAP asset | `severity` / `sensitivity` | `low` / `amber` (defaults) | Initial container values; PB2 promotes severity from the raw TRAP Severity afterwards. On 8.6, containers land as `medium` regardless — open, see `next-steps.md` |
| `soar8` asset (Phantom app) | Its automation user's role | `Automation` (container edit) | PB1's native add artifact / add note run as this user. Without the role every write returns 403; PB1 v2 then adds a `TRAP Detail - Write failures` note and an `Enrichment Failed` artifact (v1 silently reported success — found 2026-09-21 after the 8.6 rebuild) |
| `proofpoint_trap_isolation_notify` | N/A | Data PBs cannot be activated | Analyst-run; needs an `smtp` asset (exported as a template) |
| `proofpoint_trap_recheck` | Trigger | Timer asset whose container label is `proofpoint_trap_recheck` (creating the asset creates the label) | PB7 runs once per Timer tick. Live-verified 2026-09-22 (asset id 23 on soar8, created over REST with `app_id` — not GUI-only) |
| `proofpoint_trap_recheck` | Active | Yes | Deactivated after import by default |
| Custom list `proofpoint_trap_recheck_state` | Must exist | Empty | PB7's durable state (`incident_id`, `signature`); it seeds itself on the first tick and rechecks from the second. Shipped with the handover package since 2026-09-22 |

**CRITICAL:** REST-created containers do NOT trigger automation playbooks. Only containers created
by `on_poll` (ingestion framework) trigger automation PBs. During development, either use the TRAP
connector's on_poll or manually run the playbook against a manually-created container.

---

## Verification

**Trigger on_poll manually:**
```bash
curl -sk -H "ph-auth-token: TOKEN" -X POST https://<SOAR_HOST>:<SOAR_PORT>/rest/action_run \
  -H "Content-Type: application/json" \
  -d '{"action":"on poll","name":"trap_poll","type":"poll","container_id":1,"targets":[{"assets":["proofpoint_trap_mock"],"parameters":[{}],"app_id":198}]}'
```

| # | Scenario | Setup | Expected |
|---|----------|-------|----------|
| 1 | PB1 incident detail | TRAP mock returns incident with events | Container gets 5 artifacts (sender email, sender domain, recipient email, threat domain, click IP); enrichment_complete artifact created; detail note added |
| 2 | PB2 IP enrichment | Container with Click Source IP artifact (sourceAddress=1.1.1.1) | ip_enrich fires on artifact creation; enrichment note: "one.one.one.one / AS13335 Cloudflare" |
| 3 | PB3 close decision | Analyst runs PB3, selects "Close Incident" | TRAP incident closed + comment added; container status=closed; triage note shows decision + reason |
| 4 | PB3 keep open | Analyst runs PB3, selects "Keep Open" | No TRAP API call; triage note shows "Keep Open" + reason; container status unchanged |
| 5 | PB3 prompt expiry | Prompt times out without response | Note: "Prompt Expired — no analyst response"; container unchanged |
| 6 | Dedup check | Run PB1 twice on same container | No duplicate artifacts created (seen_* sets prevent it) |
| 7 | Trigger isolation | PB1 active with "both" trigger | Verify PB1 does NOT re-fire when PB1 creates artifacts (confirm "container only" trigger is set) |
| 8 | PB4 attachment extraction | Container with a MIME Body artifact whose `.eml` has a real attachment | "Email Attachment" artifact created with matching `vaultId`/`fileName`/`fileHashSha256`; MIME Body artifact marked `attachments_extracted` |
| 9 | PB4 no attachments | Container with a MIME Body artifact whose `.eml` has no attachment parts | No "Email Attachment" artifact created; MIME Body still marked processed (no repeat parsing) |
| 10 | PB4 dedup | Run PB4 twice on same container | No duplicate "Email Attachment" artifacts (marker + SDI dedup) |

**Expected container 164 (validated reference):**
- 5 artifacts: Sender Email, Sender Domain, Recipient Email, Threat Domain, Click Source IP ✓
- PB2 DNS on 1.1.1.1 → `one.one.one.one` ✓
- PB2 WHOIS → AS13335 Cloudflare ✓
- PB3 prompt sent to `soar_local_admin` with Close/Keep Open ✓

**Rollup test run — 2026-08-12 (all 10 scenarios, live against soar8 + mock):**

| # | Result | Evidence |
|---|--------|----------|
| 1 | ✅ PASS | Fresh natural `on_poll` → container 1338 ("Malware attachment..."), zero manual intervention: 3 artifacts (this incident type has no click/threat-URL events, so 3 not 5 — correct for its data, not a miscount) + Enrichment Complete + detail note |
| 2 | ✅ PASS | Container 1332, `sourceAddress=1.1.1.1` → `one.one.one.one.` / AS13335 CLOUDFLARENET — exact match to the documented reference |
| 3 | ✅ PASS (2026-08-12, retested after fixes) | Original attempt found the prompt never even reached a real analyst (empty container owner → SOAR rejected the prompt call outright — see PB3 section). Fixed, then found a second bug: reading the answered prompt crashed every downstream block (`LEGACY_CUSTOM_FUNCTION_RESULT`, unimplemented on this SOAR 8.5 build). Fixed both; container 1355 confirmed full close path: `playbook_run=success`, container `status=closed`, TRAP `close_incident`+`add_comment` both succeeded, correct triage note. |
| 4 | ✅ PASS (2026-08-12) | Container 1339, same fixes: `playbook_run=success`, container stayed `status=new` (correct — Keep Open doesn't close), correct triage note with reason recorded. |
| 5 | ✅ PASS (2026-08-12) | Container 1356, left genuinely unanswered for the full 30min. Approval `status` resolved to the literal string `"expired"` (now confirmed, was previously unknown) — correctly handled: "TRAP Triage - Prompt Expired" note created, no crash, no incomplete state. One platform cosmetic quirk noted: `playbook_run` itself still shows `"failed"` even on a cleanly-handled expiry (SOAR marks any run containing a timed-out prompt action as failed at the platform level, regardless of downstream handling) — not a bug, just how SOAR reports it. |
| 6 | ✅ PASS | Reran PB1 on container 1338: artifact count 7→7, no duplicates |
| 7 | ⚠️ FINDING | PB1 fired **3 times** on container 1338, not the 1 the doc's "container created only" trigger claims. `constraints.md` itself says *"no ingestion-only trigger exists"* on this platform — the GUI post-deploy step this doc calls for may not do what it claims, or wasn't reapplied after this session's several full redeploys (each redeploy re-imports a **new** playbook id, so any one-time GUI trigger config from a prior id doesn't carry forward — worth checking whether that's even settable at all). **What actually keeps it safe:** PB1's `on_start()` re-entry guard — confirmed 0 duplicate artifacts across all 3 fires. The design's actual safety net is the code-level guard, not the documented trigger restriction. |
| 8 | ✅ PASS | Same container 1338 — fully natural (no manual step anywhere), real `resume_2026.docm` extracted, hashed, vaulted. This closes the earlier open question about whether the full pipeline works with zero manual intervention. |
| 9 | ✅ PASS | Container 1332 — 3 MIME bodies, 0 attachments found (correct — none of that incident's events carry attachments), all 3 marked processed |
| 10 | ✅ PASS | Reran PB4 on container 1338: "Email Attachment" count 1→1, no duplicates |

**Open items from this rollup — both fully RESOLVED 2026-08-12:** (1) prompt-approval via REST turned
out to genuinely work; scenarios 3/4 investigation uncovered two real bugs (empty container owner
silently killing every prompt; `collect2()` on `:custom_function:` datapaths unimplemented on this
SOAR 8.5 build) blocking the flow since this playbook was first built — both fixed, Close Incident and
Keep Open now confirmed live end-to-end. See PB3 section above and `next-steps.md` for the full story,
memories `project_soar85_collect2_custom_function_broken` + `feedback_prompt_approval_ask_user`. (2)
PB1's trigger scope — no "container created only" mechanism exists on this platform; doc corrected
above.

**Log locations:**
- PB1/PB2 execution: `/opt/phantom/var/log/phantom/spawn.log`
- PB1/PB3 actions (get incident, close incident): `/opt/phantom/var/log/phantom/actiond.log`
- Code block debug: `/opt/phantom/var/log/phantom/decided.log`

---

## FR / NFR

| ID | Requirement | Implemented By |
|----|-------------|----------------|
| FR-16 | **TRAP incident detail enrichment** — automatically fetch full incident data and create structured artifacts for each email, domain, and IP | `proofpoint_trap_detail` → `phantom.act("get incident")` with `expand_events=true` → CEF artifact creation |
| FR-17 | **IP enrichment** — automatically enrich IP artifacts with DNS reverse lookup and WHOIS data | `ip_enrich` → `lookup ip` on dns asset → `whois ip` on whois asset → enrichment note |
| FR-18 | **Analyst-driven triage prompt** — structured prompt to close or keep open a TRAP incident, with free-text reason | `proofpoint_trap_triage` → native prompt block with list choice + message response |
| FR-19 | **TRAP incident closure** — close incident and add comment with triage notes when analyst chooses "Close Incident" | `proofpoint_trap_triage` → `phantom.act("close incident")` + `phantom.act("add comment")` |
| FR-20 | **Triage summary note** — markdown note summarizing decision, TRAP results, auto-close container | `add_triage_note` → `phantom.add_note()` + `phantom.set_status(status="closed")` |
| FR-21 | **MIME body retrieval** — fetch the raw MIME (.eml) body for TRAP incident events and make it available for analyst review | `proofpoint_trap_detail` (PB1, since 2026-08-20): native "download mime body" action (`event_id` omitted → every event in one call) dispatched between `get_trap_incident` and `extract_data_to_artifacts`, which builds one "MIME Body" artifact per event (per-event SDI `trap-{incident}-mime-{event}`, read back apart by PB3). Moved off the connector's `on_poll` (the `fetch_mime_on_poll` asset-config toggle removed entirely, v1.0.28→1.0.29) — same connector-stays-thin reasoning as the 2026-08-18 recheck-pass/URL-Artifact move. See connector `README.md` and memory `project_soar85_vault_api_quirks` for the real Vault API contract this required discovering. |
| FR-22 | **Email attachment extraction** — parse each vaulted MIME body and surface any file attachments as their own vaulted, hashed artifacts | `proofpoint_trap_attachments` (PB4, added 2026-08-12) → `phantom.vault_info()` reads the vaulted `.eml` → stdlib `email` parses parts → `phantom.vault_add()` + CEF "Email Attachment" artifact per attachment (`vaultId`, `fileName`, `fileHashSha256`) |
| FR-23 | **Email content + auth headers for analyst review** — surface the rendered body and auth/routing headers that only exist in the raw MIME, not TRAP's structured API | `proofpoint_trap_attachments` (PB4, extended 2026-08-12) → `parsed.get_body()` + `Authentication-Results`/`Reply-To`/`X-Originating-IP`/`Received` headers → "Email Content" note per event, formatted within `phantom.add_note()`'s confirmed HTML tag allowlist (see PB4 section) |
| FR-24 | **Extraction completeness: forwarded emails, Cc, spoofing signals** — don't silently drop forwarded-email attachments; surface Cc and two spoofing tells (MIME-type/filename mismatch, Return-Path/From mismatch) | `proofpoint_trap_attachments` (PB4, extended 2026-08-12) → `message/rfc822` handling fix, `mimetypes.guess_type` mismatch check, `Return-Path`/`From` `parseaddr` comparison, Cc via `email.utils.getaddresses` → "Recipient Email" (cc) artifacts + `cs1` flags on Email Attachment/Email Content |

| ID | Requirement | How Achieved |
|----|-------------|--------------|
| NFR-14 | **Artifact deduplication** — enrichment playbooks don't create duplicates on re-run | `proofpoint_trap_detail`: `seen_emails`, `seen_domains`, `seen_ips` sets per run; `ip_enrich`: `seen_ips` set; `proofpoint_trap_attachments`: `attachments_extracted` marker on the MIME Body artifact + SDI on each attachment artifact |
| NFR-15 | **Reusable enrichment playbooks** — IP enrichment generic, not TRAP-specific | `ip_enrich` collects `artifact:*.cef.sourceAddress` (standard CEF); no TRAP-specific logic |
| NFR-16 | **Signal-based pipeline coordination** — playbooks communicate via signal artifacts | `proofpoint_trap_detail` creates `enrichment_complete` artifact with event count after all IP/domain/email artifacts |
| NFR-17 | **Prompt expiry handling** — expired prompts don't leave playbook incomplete | `process_decision` checks `prompt_status != "success"` → "Prompt Expired" note → clean exit |
| NFR-18 | **Native VPE block preference** — use Action/Prompt/Decision over code blocks where possible | `get_trap_incident`, `close_trap_incident`, `add_trap_comment` use genuine native action blocks. `prompt_analyst` does **not** — despite its JSON node being typed `"prompt"`, the deployed `.py` calls `phantom.prompt2()` directly, never actually SOAR-generated (**correction 2026-08-12** — this is the root cause of the `collect2` bug documented in the PB3 section; left as-is since fixing it properly would need GUI access) |

---

## Post-Build State (<SOAR_HOST>:<SOAR_PORT>)

**Both tables below are historical.** Every id changed in the 2026-09-05 SOAR 8.6 rebuild (ids
also move on GUI saves), so resolve playbooks by name. As of 2026-09-21 all 7 UC2 playbooks are at
v1 on 8.6.

| Playbook | SOAR ID | Version | Notes |
|----------|---------|---------|-------|
| `proofpoint_trap_detail` | 291 | v28 | automation, label=proofpoint_trap, active, native action: get_incident — redeployed several times 2026-08-12 alongside PB3/PB4 fixes, no functional changes of its own |
| `ip_enrich` | 292 | v28 | automation, labels=proofpoint_trap+tenable_ad+es_soar_integration+events_crowdsec, active, native: lookup_ip + whois_ip — redeployed alongside, no functional changes of its own |
| `proofpoint_trap_triage` | 293 | v28 | data (never active — by design), 2 action + 4 code (`prompt_analyst` is JSON-typed "prompt" but actually a raw `phantom.prompt2()` call, see PB3 section correction). Genuinely end-to-end validated 2026-08-12 (Close Incident + Keep Open both confirmed live) after fixing the empty-owner and `collect2` bugs. |
| `proofpoint_trap_attachments` | 294 | v11 | automation, label=proofpoint_trap, active, native: 0 action + 1 code. Full history 2026-08-12: 253→257→261[debug probe]→265 (body/header extraction)→269[debug probe]→273→278→282→286→290[debug probe]→294 (completeness features: forwarded email/Cc/mismatch/Return-Path, all live-verified). |

**Table above predates the 2026-08-12 restructure — kept as historical record (matches the
[HISTORICAL] sections' convention above). The 5-playbook IDs as of the 2026-08-13 fix (also historical, see
"Restructure (2026-08-13)" note):**

| Playbook | SOAR ID | Version | Notes |
|----------|---------|---------|-------|
| `proofpoint_trap_detail` (PB1) | 310 | v31 | automation, active |
| `proofpoint_trap_triage` (PB2) | 311 | v31 | automation, active — now does ID extraction + severity promotion (was extract-and-stop) |
| `proofpoint_trap_attachments` (PB3) | 312 | v14 | automation, active |
| `proofpoint_trap_acknowledge` (PB4) | 313 | v3 | data, analyst-run manually |
| `proofpoint_trap_close` (PB5) | 314 | v3 | data, analyst-run manually |

# UC2 — Proofpoint TRAP Incident Triage — Air-Gapped Handover Package

Generated 2026-10-08 15:05 UTC from `proofpoint_trap` (source env: `soar8`).

This package is self-contained — everything needed to deploy this use case by hand
in an environment with no network access back to this repo or to `soar8`.

*(Version française : `HANDOVER_french.md` dans ce même dossier.)*

## Contents

| Path | What |
|------|------|
| `connectors/` | Connector app package(s): proofpoint_trap-v1.0.38.tgz |
| `connectors/source/` | Same connector(s), extracted — for reading, not for import |
| `playbooks/*.tgz` (CFs) | proofpoint_trap_extract_incident_id |
| `playbooks/*.tgz` (PBs) | proofpoint_trap_detail, proofpoint_trap_triage, proofpoint_trap_attachments, proofpoint_trap_acknowledge, proofpoint_trap_close, proofpoint_trap_isolation_notify, proofpoint_trap_recheck, proofpoint_trap_summary, proofpoint_trap_orchestrator |
| `playbooks/source/` | Same CFs/playbooks, extracted — for reading, not for import |
| `assets/*.json` | Asset config templates (credentials redacted — see below) |
| `custom_lists/*.json` | Custom lists — the rows this package defines, never the source's data rows (see the custom-list section below) |
| `docs/` | Implementation plan doc, for full design context |

## [!] Upgrading over an earlier install — read this first

These apply only if this app is already installed on the target from a
previous package. On a completely fresh target, skip to Install order.

- **Connector v1.0.36 fixes `download mime body`, which failed on every event against a real TRAP appliance** (v1.0.34 and older called an endpoint TRAP does not have; v1.0.35 also failed every event when run from the asset's action panel, which has no container to store the email in — it now downloads and checks each email there, showing its size and subject, without storing it). Install it over the existing Proofpoint TRAP app: a normal in-place upgrade. The asset, its API key and every playbook stay as they are — nothing to re-import, nothing to re-enter. **Incidents processed before the upgrade keep no emails:** `proofpoint_trap_detail` marked them `Enrichment Complete` although the email download failed, and it does not run again on a completed container. New incidents, and any incident `proofpoint_trap_recheck` sees change, get their emails and attachments normally. To fetch an older incident's emails by hand, run `download mime body` on its container with the incident id: the `.eml` files land in the container's Files (Vault), but no `MIME Body` artifact is created, so `proofpoint_trap_attachments` does not process them.

- **`proofpoint_trap_detail` must be re-imported (2026-09-28) — unlike the connector upgrade above.** It now survives a save in the VPE and its re-runs post only new artifacts. Re-import it from `playbooks/` — the new copy replaces yours, including any block renamed with `_0` by an earlier save — and re-activate it. After the import you may re-point its action blocks to your own asset names and save: it no longer breaks. Two blocks have new names (`build_artifact_list`, `dispatch_artifact_list`). A re-run, which `proofpoint_trap_recheck` triggers each time an incident changes, now posts only the artifacts not already on the container instead of the whole list again, and the detail note shows "N new, M already on the container". The `Enrichment Complete` artifact adds `alertCount` (alerts processed), `eventCount` (TRAP's own count) and `artifactsAlreadyPresent`; `artifactsCreated` now counts new artifacts only.

- **Every UC2 playbook now survives a save in the VPE, and `proofpoint_trap_summary` is new (2026-09-28).** Re-import all the playbooks from `playbooks/` (the new copies replace yours) and re-activate the automation ones (`proofpoint_trap_detail`, `proofpoint_trap_triage`, `proofpoint_trap_attachments`, `proofpoint_trap_recheck`). After that you may re-point any action block to your own asset names and save. What changed: `proofpoint_trap_acknowledge` and `proofpoint_trap_close` ask the container owner, or `soar_local_admin` when the container has no owner (as before, but the fallback now survives a save); a close prompt that gets no answer still writes its note; `proofpoint_trap_attachments` no longer touches the filesystem (SOAR's own validator flagged it) and reads and stores Vault files through SOAR's REST API instead; its per-email `Email Content` note now shows the body as safe text (links shown with their real target, defanged and not clickable, a warning when a link's text names another site, images and scripts removed, hidden text and forms flagged). The acknowledge, close, isolation and attachment notes are now stored as markdown, so their bold text and headings render. `proofpoint_trap_summary` is run by hand from a container: it writes one `TRAP Summary` note with a table per artifact type and rewrites that same note on every run.

- **Re-import the custom function and all the playbooks again (2026-09-29).** Import `proofpoint_trap_extract_incident_id` with *Import Custom Function* (step 4), not the playbook importer: its header now matches the one the SOAR 8.6 editor generates, so the editor no longer reports it as modified outside the editor and it saves as a published custom function instead of a draft. Then re-import every playbook and re-activate the automation ones. What changed: `proofpoint_trap_triage` adds a `TRAP Triage - Severity` note saying which severity it set, from which TRAP value, and when an unknown value fell back to `low`. The playbooks run by hand no longer show their Start or End block as "Unconfigured" in the VPE: they take optional inputs (`proofpoint_trap_acknowledge` and `proofpoint_trap_close`: `approver`, `respond_in_mins`; `proofpoint_trap_summary`: `max_rows`; left blank, each behaves as before) and return a `status` output with the incident id and a key result. Every playbook now carries the version stamps the SOAR 8.6 editor writes.

- **Fix (2026-09-29): the packages of 2026-09-28 and 2026-09-29 shipped four playbooks without their Global Custom Code** — `proofpoint_trap_attachments`, `proofpoint_trap_acknowledge`, `proofpoint_trap_isolation_notify` and `proofpoint_trap_recheck`. The code was in each archive's `.py`, so the playbooks ran, but not in its `.json`, from which the VPE builds the playbook: *Validate Python* reported its helper functions as undefined (for example `_email_html_to_markdown`), and saving one of these playbooks deleted them, after which it fails when it runs. This package carries the code in both files. Re-import all four — required if you saved any of them after importing an earlier package — and re-activate `proofpoint_trap_attachments` and `proofpoint_trap_recheck`.

- **`proofpoint_trap_summary` now runs by itself, and `proofpoint_trap_attachments` now processes every new incident's emails (2026-09-29).** Re-import `proofpoint_trap_detail`, `proofpoint_trap_triage` and `proofpoint_trap_summary`, then **activate `proofpoint_trap_summary`** — it is an automation playbook now, with no inputs; it no longer needs an analyst to run it. When `proofpoint_trap_detail` finishes a container, its `Enrichment Complete` artifact now starts the automation playbooks again. Before, `proofpoint_trap_attachments` ran only when the container was created, before any email had been downloaded, so it processed a new incident's emails only after `proofpoint_trap_recheck` saw the incident change. On that same trigger `proofpoint_trap_summary` writes or rewrites the `TRAP Summary` note (tables show at most 250 rows each), and `proofpoint_trap_triage` sets the container severity again: new artifacts arrive at SOAR's default severity `medium` and had raised every incident mapped to `low` back to `medium`. Its severity note is added only when the severity derived from TRAP changes. Attachments extracted on that pass may appear in the summary only at its next refresh.

- **Container names, a comment in TRAP, and a link to TRAP (2026-09-29).** Install connector v1.0.37 over the existing Proofpoint TRAP app (a normal in-place upgrade: `get incident` now also returns the incident's TRAP web page), re-import `proofpoint_trap_detail` and re-activate it, and create the custom list `proofpoint_trap_excluded_senders` (see "Custom lists you fill in"). What changes: a container whose TRAP incident has no summary is named `TRAP-<id>: <first sender not in that list>` instead of `TRAP-<id>: No summary`; on an incident's first extraction SOAR adds a comment to the TRAP incident saying so, with a link to the SOAR case; and the `TRAP Detail` note has an `Open in TRAP` link to the incident. The link to SOAR uses SOAR's base URL (Administration > Company Settings): check that it is the address analysts open SOAR at, port included.

- **Long notes are split instead of cut (2026-09-29).** A SOAR note shows at most about 22,000 characters here, so no note is longer than 20,000: a longer `Email Content` or `Attachment Extraction` note from `proofpoint_trap_attachments` becomes parts `... (1/N)`, `... (2/N)`, and the `TRAP Summary` from `proofpoint_trap_summary` becomes `TRAP Summary (1/N)`... (a table that continues repeats its header; the parts are rewritten on each update). Re-import both playbooks and re-activate them. An email body is still shortened after 20,000 characters; the full message is the `.eml` in the container's files.

- **`proofpoint_trap_isolation_notify` lists its links in the container note, and every playbook description now starts with its type and number (2026-09-29).** The `TRAP Isolation Notify` note shows each isolation-browser link it emailed (the target as text, only the isolation-browser link clickable). The descriptions read `Automation playbook (PBn)` / `Data playbook (PBn)`. Re-import `proofpoint_trap_isolation_notify`; the other playbooks carry the new descriptions the next time you re-import them.

- **A container mapped to `low` now stays `low` (2026-09-30).** `proofpoint_trap_triage` sets the container severity from TRAP's, but an artifact created or updated without a severity is `medium` and raises a lower container: `proofpoint_trap_attachments` marking each `MIME Body` as processed put every `low` container back to `medium`. The playbooks now write their artifacts at `low`, which never lowers a `high` or `medium` container. Also, `proofpoint_trap_acknowledge`, `proofpoint_trap_close` and `proofpoint_trap_isolation_notify` no longer report a step that SOAR refused to start as `not run`: the note says `failed - not dispatched`, and the reason is in the playbook run's actions. Re-import these five playbooks — `proofpoint_trap_attachments`, `proofpoint_trap_recheck`, `proofpoint_trap_acknowledge`, `proofpoint_trap_close`, `proofpoint_trap_isolation_notify` — and re-activate the first two. A container already raised to `medium` returns to its mapped severity the next time `proofpoint_trap_recheck` sees its incident change.

- **One orchestrator runs the playbooks in order (2026-09-30).** The automation playbooks used to start together on the same trigger and race: attachments looked for emails `proofpoint_trap_detail` had not downloaded yet, the summary missed what the others were still writing. New automation playbook `proofpoint_trap_orchestrator` (label `proofpoint_trap`) now runs `proofpoint_trap_detail`, `proofpoint_trap_attachments`, `proofpoint_trap_triage` and `proofpoint_trap_summary` one after another, each waiting for the previous one to finish. Import it and activate it; re-import those four and **deactivate** them — this replaces every "re-activate" step for them in the notes above. `proofpoint_trap_recheck` stays active. The `Enrichment Complete` artifact no longer runs automation. If you built a `proofpoint_trap_orchestrator` yourself, the import replaces it. Also in `proofpoint_trap_detail`: a sender address in the custom list `proofpoint_trap_excluded_senders` no longer gets a `Sender Email` artifact, nor its domain a `Sender Domain` one (unless another sender shares it); artifacts already on a container stay.

- **`status` survives a save in the playbook editor (2026-10-01).** After a save in SOAR 8.6's editor, `proofpoint_trap_acknowledge`, `proofpoint_trap_close` and `proofpoint_trap_isolation_notify` returned an empty list instead of `failed` when a run stopped early, and every output they had not set came back as an empty list instead of empty. Re-pointing their action blocks to your asset names is such a save. Re-import those three (data playbooks: nothing to activate); re-point the asset names again if you had changed them.

- **`proofpoint_trap_close` keeps its note when the prompt is not approved (2026-10-01).** After a save in SOAR 8.6's editor, a close whose prompt expired or was rejected ended with no note and status `failed`: the editor made the closing note wait for the TRAP comment, which only runs on an approved close. That path now has its own block, **add expired note**. Re-import `proofpoint_trap_close` (data playbook: nothing to activate) and re-point its asset names again if you had changed them; saving it is safe.

- **The TRAP comment works on the appliance; the excluded-senders list is renamed and gains columns (2026-10-01).** On the appliance the comment step of `proofpoint_trap_detail` (**comment on trap incident**) failed with `HTTP 500 -- java.lang.NullPointerException: Null detail`: TRAP needs a comment's `detail` although its API documentation marks it optional. The playbook now sends the SOAR link as the comment's `detail`, and connector v1.0.38 always sends `detail`. Install connector v1.0.38 over the existing Proofpoint TRAP app (a normal in-place upgrade), re-import `proofpoint_trap_detail` (it stays inactive — the orchestrator runs it) and re-point its asset names if you had changed them. **The custom list `proofpoint_trap_excluded_senders` is replaced by `proofpoint_trap_excluded_email`** with the columns `email`, `date`, `reason`, `enabled` (see "Custom lists you fill in"): create it from `custom_lists/proofpoint_trap_excluded_email.json`, copy each address from the old list into a row with `enabled` = `yes`, then delete `proofpoint_trap_excluded_senders` — the playbook no longer reads it. Until the new list has your addresses, those senders are treated like any other. The list now also covers recipients and Cc. **Abuse-mailbox reports:** TRAP lists a reported email twice, the report (`abuseCopy` true: the analyzer forwarding it to the abuse mailbox) and the reported email itself (`abuseCopy` false). When an alert carries both, the report's sender, recipient and Cc get no artifact, so the artifacts show the real sender and target; the user who reported it (`X-PhishAlarm-Reporter`) appears as a `Recipient Email` with the role `reporter`.

- **A container closes when its incident is closed in TRAP (2026-10-02).** Until now only a close made from SOAR (`proofpoint_trap_close`) closed the container; a close made in TRAP was seen by `proofpoint_trap_recheck` but left the container open. `proofpoint_trap_detail` now records the incident's TRAP state on `Enrichment Complete` (field `incidentState`), and `proofpoint_trap_summary`, which the orchestrator runs last, closes the container when that state is `closed` and adds a note **Closed in TRAP**. It does so once: if an analyst reopens the container, it stays open. The summary's "Enrichment runs" table shows the TRAP state. Only incidents inside `proofpoint_trap_recheck`'s look-back window are seen. **`proofpoint_trap_recheck` only ever looked at incidents in state `new`:** it meant to list every state, but SOAR drops an empty parameter, so the connector listed its default `new` — an incident moved to `open` or `closed` in TRAP was never rechecked. It now lists `new`, `open` and `closed`. Re-import `proofpoint_trap_detail` and `proofpoint_trap_summary` (both stay inactive — the orchestrator runs them) and `proofpoint_trap_recheck` (keep it active), and re-point their asset names if you had changed them. On its first run after the upgrade, the recheck sees every incident in its window that changed state since it last saw it as `new`: each gets an update, a re-run of the enrichment, and, if closed in TRAP, a closed container — expect a burst then.

- **URLs in notes are no longer clickable (2026-10-05).** SOAR turns a URL in a note into a link unless it sits in backticks. `proofpoint_trap_summary` now puts every URL in its tables in backticks, and `proofpoint_trap_detail` does the same for the incident summary line; the email notes of `proofpoint_trap_attachments` already did. Two links stay clickable on purpose: **Open in TRAP** in the detail note and the isolation-browser links of `proofpoint_trap_isolation_notify`. Re-import `proofpoint_trap_detail` and `proofpoint_trap_summary` (both stay inactive — the orchestrator runs them) and re-point their asset names if you had changed them. Notes written before the upgrade keep their links; a summary note is rewritten at the container's next run.

- **Artifact labels and data types (2026-10-06).** Every artifact the playbooks create now has the label `event`, `Enrichment Complete` and `Enrichment Failed` included (they had labels of their own that nothing read; the playbooks find them by name). `proofpoint_trap_detail` no longer lets SOAR guess a data type for the fields it does not declare (SOAR had tagged the email role, subject, dates and the incident state as `domain` / `host name`), and declares: the sender's `messageId` as `internet message id`, a threat domain's `url` as `url`, `fileName` as `file name` on `MIME Body` and `Email Attachment`, and the `incidentId` of an `Event Info Update` as `proofpoint trap incident id` (the TRAP actions are offered on it). With only the IMAP and SMTP mail apps, `internet message id` offers no action yet; `email` and `vault id` offer SMTP's `send email`. Re-import `proofpoint_trap_detail`, `proofpoint_trap_attachments` (both stay inactive) and `proofpoint_trap_recheck` (check it is still active after the import), and re-point their asset names if you had changed them. Artifacts created before the upgrade keep their labels and data types.

- **Isolation-browser prefix (2026-10-07).** The default `isolation_browser_url` of `proofpoint_trap_isolation_notify` is now `https://www.domain.tld/browser?url=` (it was `https://my_isolated_browser/browser?url=`). It is still a placeholder: put your isolation browser's real prefix in the `isolation_browser_url` field when you launch the playbook, or set it once as the default — open the playbook in the editor, change `DEFAULT_ISOLATION_BROWSER_URL` in its Global Custom Code and save. The target URL is still URL-encoded after `?url=` (`:` and `/` become `%3A` and `%2F`, dots stay), e.g. `https://www.domain.tld/browser?url=https%3A%2F%2Fwww.google.fr%2F`. Re-import `proofpoint_trap_isolation_notify` (a data playbook: nothing to activate) and re-point its `smtp` asset name if you had changed it. If you had already set your own default in that playbook, the import replaces it: set it again.

- **Sender, headers, CLEAR verdict and attachments (2026-10-07, your feedback).** (1) When TRAP gives only the report (no copy of the reported email), as for a report sent from a shared mailbox, and the report carries the `X-PhishAlarm-Sender` header, `proofpoint_trap_detail` takes the sender from that header: it names the case `TRAP-<id>: <address>` and adds a Sender Email for it. The report's own sender and recipient (the reporting tool or the shared mailbox, and the abuse mailbox) are not used, and the user or mailbox that reported it is a Recipient Email with role `reporter`. Nothing needs adding to `proofpoint_trap_excluded_email` for this (package r24 said to list the shared mailbox there: not needed since r25). (2) Each Sender Email carries the fields `receivedSpf`, `dkimSignature`, `inReplyTo`, `received` and `phishAlarmSender`; the Email Content note shows In-Reply-To, X-PhishAlarm-Sender, Received-SPF and DKIM-Signature; the TRAP Summary has matching columns. (3) The TRAP Summary opens with the CLEAR verdict (Abuse Disposition / Sub Disposition) and the threat names of the incident's alerts. `proofpoint_trap_triage` sets the severity to the higher of TRAP Severity and the verdict (Malicious → high; Suspicious, False Negative, Unknown / Needs Manual Review or Unknown alone → medium; the rest → low) and tags the case with the verdict, e.g. `trap-needs-manual-review` or `trap-malicious`; a new verdict replaces that tag and no other tag is touched. (4) Email Attachment gets MD5 and size (`fileHashMd5`, `fileSize`); when an alert's original email cannot be downloaded, the attachments TRAP lists for it are added from TRAP's data (no file in the Vault). Re-import `proofpoint_trap_detail`, `proofpoint_trap_attachments`, `proofpoint_trap_triage` and `proofpoint_trap_summary` (all four stay inactive), and re-point their asset names if you had changed them. Cases enriched before the upgrade keep their Sender Email artifacts without the new fields.

- **X-PhishAlarm-Sender with an unclosed quote (2026-10-08, your sample).** On your appliance the header reads like `"Name <address>`: the quote before the name is never closed. Up to package r25, `proofpoint_trap_detail` then took the whole text as the address, so the case name and the Sender Email showed `Name <address>` and the Sender Domain ended with `>`. It now reads the address between the last `<` and `>` (also for `"Name" <address>`, `Name <address>` and a bare address) and ignores a value with no valid address. Re-import `proofpoint_trap_detail` (stays inactive). Cases created before keep their name and artifacts.

## Install order

1. **Install the connector app(s)** — Apps > Install App, upload each file in `connectors/`.
   (`connectors/source/` is the same code extracted for reading — don't import from there,
   the GUI needs the `.tgz`.)
2. **Configure assets from the templates in `assets/`** — Apps > Configure New Asset for
   each. Fields marked in a template's `redacted_fields` list are placeholders
   (`<<SET ME...>>`) — **you must fill these in yourself**; they were never exported
   with usable values. Two different reasons appear in that list, and each placeholder
   says which one applies:

   - **Secrets** (passwords, API keys, certificates/keys) — take these from your own
     vault/CMDB. SOAR encrypts `password`-type fields at rest, so the export process
     cannot read them back in usable form even in principle.
   - **Identities and addresses** (usernames, client/app ids, endpoint URLs) — these
     are not secret, but they belonged to the source environment and are meaningless
     here. Enter the values *your* target system expects. **An identity must match the
     credential you enter beside it** — a real password paired with a leftover username
     from the source environment authenticates as nothing and returns HTTP 401.

   **The playbooks ship pointed at the asset names below.** Either create your assets
   with these names, or keep your own names and re-point each playbook's action blocks
   to your assets in the VPE, then save: every playbook in this package is built to
   survive a save. (A save makes a manually-run playbook available on every container
   label; re-importing it restores the label.)

   | Asset name | App | Used by | Template |
   |---|---|---|---|
   | `proofpoint_trap_mock` | Proofpoint TRAP | `proofpoint_trap_acknowledge`, `proofpoint_trap_close`, `proofpoint_trap_detail`, `proofpoint_trap_recheck` | `assets/proofpoint_trap_mock.json` |
   | `smtp` | SMTP | `proofpoint_trap_isolation_notify` | `assets/smtp.json` |
   | `soar8` | Phantom | `proofpoint_trap_detail` | `assets/soar8.json` |

3. **Create the custom list(s)** from `custom_lists/*.json` — each file has the exact
   `content` array (the rows this package defines — never the source's data rows) to POST to `/rest/decided_list`:
   ```bash
   curl -sk -u '<user>:<password>' -X POST https://<target>:<port>/rest/decided_list \
     -H 'Content-Type: application/json' \
     -d @custom_lists/<list_name>.json
   ```
   (the file's top-level shape is `{"name": ..., "content": [...]}` — matches the REST
   payload directly.)
4. **Import the custom functions, then the playbooks** (in that order — playbooks reference
   CFs). `playbooks/` holds both kinds, and each goes through its own importer:
   - **Custom functions** — `playbooks/proofpoint_trap_extract_incident_id.tgz`: on the Custom Functions tab of the Playbooks
     page, the upload button whose tooltip reads *Import Custom Function*. The playbook
     importer rejects a CF archive ("failed to identify the import as a playbook").
     If the CF shows as a draft afterwards, open it in the editor and save it.
   - **Playbooks** — every other `playbooks/*.tgz`: *Import Playbook* on the Playbooks page.
   (`playbooks/source/` is the same code extracted for reading — don't import from there,
   the GUI needs the `.tgz`.)
5. **Activate automation playbooks** (`proofpoint_trap_recheck`, `proofpoint_trap_orchestrator`) and set their **Run As** user per the
   implementation plan doc's Setup Guide (see `docs/`).
   **Leave these inactive:** `proofpoint_trap_detail`, `proofpoint_trap_triage`, `proofpoint_trap_attachments`, `proofpoint_trap_summary` — an orchestrator playbook above calls them one after
   another; active, they would also start on their own, alongside it. Deactivate them if an
   earlier package had them active.

## Custom lists this use case owns

These lists are **the playbooks' own state** — create them empty (step above) and then
leave them alone. The playbook fills and maintains the rows itself; hand-written rows
are read back as real state and will make it act on things that never happened.

- `proofpoint_trap_recheck_state`: `incident_id, signature` — written by the playbook, not by you.

See the copied implementation plan doc in `docs/` for what the playbook stores and when.

## Custom lists you fill in

Settings the playbooks read. Create them (step above), then fill them in as each list's
description below says, when you need them; the use case works with them left as shipped.

- `proofpoint_trap_excluded_email`: email addresses `proofpoint_trap_detail` and `proofpoint_trap_attachments` leave out, as sender, recipient or Cc — typically an address present on every incident. Columns: `email` (the address, case does not matter), `date` (DD/MM/YYYY) and `reason` (for you only), `enabled` (`yes` to apply the row, anything else to keep it without applying it). The file ships with two example rows, `sender1@example.com` and `sender2@example.com`: replace them with your real addresses (example.com never sends real mail, so left as they are they match nothing). An excluded address gets no `Sender Email` or `Recipient Email` artifact, its domain no `Sender Domain` one (unless another sender shares it), and it never names a container: when TRAP gives an incident no summary, the container is named `TRAP-<id>: <first sender not excluded>` instead of `TRAP-<id>: No summary`. With no enabled row nothing is left out; the header row is ignored.

## Verification

After importing everything and activating automation playbooks, trigger one run manually
(e.g. the timer asset's manual poll, or per the implementation plan doc's trigger section)
and confirm: a container is created, the expected child playbook(s) run, and the custom
list(s) reflect a real result. Check `spawn.log`/`decided.log`/`actiond.log` on the target
SOAR host if anything doesn't fire as expected.

## What was deliberately NOT exported

- Real credential values for any `password`-type config field (see step 2 above).
- The source environment's own target assets and any custom-list rows — those are
  lab-specific test data, not your infrastructure. See the custom-list section above.
- Anything not explicitly listed in Contents above.

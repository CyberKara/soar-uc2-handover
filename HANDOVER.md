# UC2 — Proofpoint TRAP Incident Triage — Air-Gapped Handover Package

Generated 2026-09-29 11:25 UTC from `proofpoint_trap` (source env: `soar8`).

This package is self-contained — everything needed to deploy this use case by hand
in an environment with no network access back to this repo or to `soar8`.

*(Version française : `HANDOVER_french.md` dans ce même dossier.)*

## Contents

| Path | What |
|------|------|
| `connectors/` | Connector app package(s): proofpoint_trap-v1.0.36.tgz |
| `connectors/source/` | Same connector(s), extracted — for reading, not for import |
| `playbooks/*.tgz` (CFs) | proofpoint_trap_extract_incident_id |
| `playbooks/*.tgz` (PBs) | proofpoint_trap_detail, proofpoint_trap_triage, proofpoint_trap_attachments, proofpoint_trap_acknowledge, proofpoint_trap_close, proofpoint_trap_isolation_notify, proofpoint_trap_recheck, proofpoint_trap_summary |
| `playbooks/source/` | Same CFs/playbooks, extracted — for reading, not for import |
| `assets/*.json` | Asset config templates (credentials redacted — see below) |
| `custom_lists/*.json` | Custom list schema (header row only — see the custom-list section below) |
| `docs/` | Implementation plan doc, for full design context |

## [!] Upgrading over an earlier install — read this first

These apply only if this app is already installed on the target from a
previous package. On a completely fresh target, skip to Install order.

- **Connector v1.0.36 fixes `download mime body`, which failed on every event against a real TRAP appliance** (v1.0.34 and older called an endpoint TRAP does not have; v1.0.35 also failed every event when run from the asset's action panel, which has no container to store the email in — it now downloads and checks each email there, showing its size and subject, without storing it). Install it over the existing Proofpoint TRAP app: a normal in-place upgrade. The asset, its API key and every playbook stay as they are — nothing to re-import, nothing to re-enter. **Incidents processed before the upgrade keep no emails:** `proofpoint_trap_detail` marked them `Enrichment Complete` although the email download failed, and it does not run again on a completed container. New incidents, and any incident `proofpoint_trap_recheck` sees change, get their emails and attachments normally. To fetch an older incident's emails by hand, run `download mime body` on its container with the incident id: the `.eml` files land in the container's Files (Vault), but no `MIME Body` artifact is created, so `proofpoint_trap_attachments` does not process them.

- **`proofpoint_trap_detail` must be re-imported (2026-09-28) — unlike the connector upgrade above.** It now survives a save in the VPE and its re-runs post only new artifacts. Re-import it from `playbooks/` — the new copy replaces yours, including any block renamed with `_0` by an earlier save — and re-activate it. After the import you may re-point its action blocks to your own asset names and save: it no longer breaks. Two blocks have new names (`build_artifact_list`, `dispatch_artifact_list`). A re-run, which `proofpoint_trap_recheck` triggers each time an incident changes, now posts only the artifacts not already on the container instead of the whole list again, and the detail note shows "N new, M already on the container". The `Enrichment Complete` artifact adds `alertCount` (alerts processed), `eventCount` (TRAP's own count) and `artifactsAlreadyPresent`; `artifactsCreated` now counts new artifacts only.

- **Every UC2 playbook now survives a save in the VPE, and `proofpoint_trap_summary` is new (2026-09-28).** Re-import all the playbooks from `playbooks/` (the new copies replace yours) and re-activate the automation ones (`proofpoint_trap_detail`, `proofpoint_trap_triage`, `proofpoint_trap_attachments`, `proofpoint_trap_recheck`). After that you may re-point any action block to your own asset names and save. What changed: `proofpoint_trap_acknowledge` and `proofpoint_trap_close` ask the container owner, or `soar_local_admin` when the container has no owner (as before, but the fallback now survives a save); a close prompt that gets no answer still writes its note; `proofpoint_trap_attachments` no longer touches the filesystem (SOAR's own validator flagged it) and reads and stores Vault files through SOAR's REST API instead; its per-email `Email Content` note now shows the body as safe text (links shown with their real target, defanged and not clickable, a warning when a link's text names another site, images and scripts removed, hidden text and forms flagged). The acknowledge, close, isolation and attachment notes are now stored as markdown, so their bold text and headings render. `proofpoint_trap_summary` is run by hand from a container: it writes one `TRAP Summary` note with a table per artifact type and rewrites that same note on every run.

- **Re-import the custom function and all the playbooks again (2026-09-29).** Import `proofpoint_trap_extract_incident_id` with *Import Custom Function* (step 4), not the playbook importer: its header now matches the one the SOAR 8.6 editor generates, so the editor no longer reports it as modified outside the editor and it saves as a published custom function instead of a draft. Then re-import every playbook and re-activate the automation ones. What changed: `proofpoint_trap_triage` adds a `TRAP Triage - Severity` note saying which severity it set, from which TRAP value, and when an unknown value fell back to `low`. The playbooks run by hand no longer show their Start or End block as "Unconfigured" in the VPE: they take optional inputs (`proofpoint_trap_acknowledge` and `proofpoint_trap_close`: `approver`, `respond_in_mins`; `proofpoint_trap_summary`: `max_rows`; left blank, each behaves as before) and return a `status` output with the incident id and a key result. Every playbook now carries the version stamps the SOAR 8.6 editor writes.

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
   `content` array (header row only, never the source's data rows) to POST to `/rest/decided_list`:
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
5. **Activate automation playbooks** (`proofpoint_trap_detail`, `proofpoint_trap_triage`, `proofpoint_trap_attachments`, `proofpoint_trap_recheck`) and set their **Run As** user per the
   implementation plan doc's Setup Guide (see `docs/`).

## Custom lists this use case owns

These lists are **the playbooks' own state** — create them empty (step above) and then
leave them alone. The playbook fills and maintains the rows itself; hand-written rows
are read back as real state and will make it act on things that never happened.

- `proofpoint_trap_recheck_state`: `incident_id, signature` — written by the playbook, not by you.

See the copied implementation plan doc in `docs/` for what the playbook stores and when.

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

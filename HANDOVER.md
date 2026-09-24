# UC2 — Proofpoint TRAP Incident Triage — Air-Gapped Handover Package

Generated 2026-09-24 15:52 UTC from `proofpoint_trap` (source env: `soar8`).

This package is self-contained — everything needed to deploy this use case by hand
in an environment with no network access back to this repo or to `soar8`.

*(Version française : `HANDOVER_french.md` dans ce même dossier.)*

## Contents

| Path | What |
|------|------|
| `connectors/` | Connector app package(s): proofpoint_trap-v1.0.34.tgz |
| `connectors/source/` | Same connector(s), extracted — for reading, not for import |
| `playbooks/*.tgz` (CFs) | proofpoint_trap_extract_incident_id |
| `playbooks/*.tgz` (PBs) | proofpoint_trap_detail, proofpoint_trap_triage, proofpoint_trap_attachments, proofpoint_trap_acknowledge, proofpoint_trap_close, proofpoint_trap_isolation_notify, proofpoint_trap_recheck |
| `playbooks/source/` | Same CFs/playbooks, extracted — for reading, not for import |
| `assets/*.json` | Asset config templates (credentials redacted — see below) |
| `custom_lists/*.json` | Custom list schema (header row only — see the custom-list section below) |
| `docs/` | Implementation plan doc, for full design context |

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
3. **Create the custom list(s)** from `custom_lists/*.json` — each file has the exact
   `content` array (header row only, never the source's data rows) to POST to `/rest/decided_list`:
   ```bash
   curl -sk -u '<user>:<password>' -X POST https://<target>:<port>/rest/decided_list \
     -H 'Content-Type: application/json' \
     -d @custom_lists/<list_name>.json
   ```
   (the file's top-level shape is `{"name": ..., "content": [...]}` — matches the REST
   payload directly.)
4. **Import custom functions, then playbooks** (in that order — playbooks reference CFs)
   from `playbooks/*.tgz`, via Apps/Playbooks > Import in the target SOAR GUI.
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

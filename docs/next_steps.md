# Next steps (queued, not started)

Work queued for a later session. Nothing in this file has been executed. Each item is a
self-contained prompt: paste the "Merged prompt" block into a fresh session, answer the
"Decisions to confirm" first, then let it run.

| ID | Item | Status | Queued |
|----|------|--------|--------|
| NS-1 | Connector README + build reproducibility, and the static-audit fixes (merged from two prompts) | queued | 2026-09-30 |
| NS-2 | In-code cleanup backlog: what is still in the connector and playbook code, to trim once edits are allowed | queued, blocked on edit rights | 2026-09-30 |

---

## NS-1: README drift, reproducible connector build, and audit fixes

### How the two source prompts were merged

Prompt 1 ("README + build") and prompt 2 ("audit fixes") overlap on the connector README,
the tgz rebuild rules and the version bump, and they disagree in four places. Resolutions:

| # | Conflict | Resolution in the merged prompt |
|---|----------|---------------------------------|
| 1 | Prompt 1: "new branch off main". Prompt 2: "commit on the branch you are given". | Use the branch the session gives you (at queue time: `claude/magical-hamilton-27thg2`). Create a new branch off `main` only if none is given. No PR either way. |
| 2 | Prompt 2: "bump `app_version` from 1.0.36 to 1.0.37". Prompt 1: "`app_version` is 1.0.37; do not rebuild or replace the v1.0.37 tgz; ask before bumping". | **Checked 2026-09-30:** `app_version` is already `1.0.37` (`proofpoint_trap.json:13`) and the package is already `connectors/proofpoint_trap-v1.0.37.tgz`. Prompt 2's 1.0.36 to 1.0.37 step is stale and would be a same-version reinstall, which SOAR refuses. The next version is **1.0.38**, and prompt 1 says to ask before bumping, so this is the first decision to confirm. One bump covers every connector-side change from both prompts. Do not release a README-only 1.0.38 and then a second bump for code. |
| 3 | Prompt 1: never replace the v1.0.37 tgz. Prompt 2: "rename the tgz". | Never overwrite v1.0.37 under its own name. If the bump is approved, add `proofpoint_trap-v1.0.38.tgz` and remove `proofpoint_trap-v1.0.37.tgz` from `connectors/` (git history keeps the original byte-for-byte), so HANDOVER's Contents table lists one package. Confirm this, or keep both. |
| 4 | Prompt 1: add a build script or reword the README. Prompt 2: rebuild tarballs "in the same layout". | Do the build script first and use it for every rebuild. The README then points at this script instead of the missing `soar-connectors/tools/build.sh`. |

Other merge notes:

- **The audit predates the current snapshot.** Prompt 2's line numbers are about 10 lines off
  (for example `event_id` validation is now at `proofpoint_trap_connector.py:1033`, not :1023), and
  its "1.0.36" baseline is wrong. Re-validate every finding against current HEAD before fixing.
  Report any that no longer reproduce as "already fixed / not reproducible", not as fixed.
- **Scope of "don't touch".** `.github/` and `tools/release-connectors.sh` do not exist in this
  repo snapshot (checked 2026-09-30; there is no `tools/` or `.github/` directory). They live
  upstream. Nothing to do here except not creating files that would collide with them.
  Put the new build script outside `tools/`, for example `connectors/build_connector.sh`.
- **README is edited once**, covering the drift report (prompt 1) and finding A8 (prompt 2).
  Prompt 2's list of README faults (v1.0.13, 6 of 11 actions, `cs1`/`cs2`/`cn1`, lab path) are
  hypotheses to verify against `proofpoint_trap.json` and the connector `.py`, not facts.
- **One report at the end**, combining prompt 1's "changed vs only flagged" with prompt 2's
  per-finding status and upstream list.
- **Ordering dependency.** Finding A7 has a connector half (omit empty query params) and a playbook
  half (`proofpoint_trap_recheck`). The playbook half relies on the new connector being installed;
  say so in the upgrade note.

### Status update 2026-09-30: code-comment cleanup already done

A separate cleanup pass moved long comments out of the connector and playbook code into
`docs/design_notes.md`. It changes how NS-1 should start:

- **Line numbers in the merged prompt are stale again** (about 200 comment lines are gone). Re-locate
  every finding by the code it names, not by number.
- **A8 comment rewording is done**: the comments citing `uc2_dev_notes.md` and
  `proofpoint_trap_api_reference.md` are gone from the connector and consts, and the stale `cs6`
  comment now says `trapSeverity`. Only the VPE-generated "Bridge block" banners in acknowledge, close
  and isolation_notify still mention another project's playbook; they are not stored in the JSON, so
  they were left as generated.
- **Connector source no longer matches `proofpoint_trap-v1.0.37.tgz`.** The difference is comments and
  one docstring only (the ASTs are identical), and the tgz and `app_version` were deliberately not
  touched. Build step 1 ("prove the script on unmodified source") must therefore use the pre-cleanup
  source (`git show e0fef59:connectors/source/proofpoint_trap/...`), which still matches the tgz. The
  cleanup then ships with the 1.0.38 bump.
- **Five playbook tgz were already rebuilt** (acknowledge, attachments, detail, isolation_notify,
  recheck). A scratch builder reproduced the tar layer of all 10 shipped playbook tgz exactly: PAX
  format, mode 0644, uid/gid 0, empty user and group names, mtime 0, `.py` then `.json`. The gzip
  header carries a build-time stamp, so bytes can never match; set gzip mtime to 0 for repeatable
  builds. The same approach can seed the build script.
- **Baselines for the checks**: at this point pyflakes reports 44 findings in the connector (3 in
  attachments and detail, 2 in isolation_notify and recheck, 1 in acknowledge) and bandit reports 1
  issue in the connector. Compare against these instead of expecting zero.

### Decisions to confirm before starting (ask in one `AskUserQuestion`)

1. Bump `app_version` 1.0.37 to **1.0.38**, as a single release for all connector-side changes?
2. Remove `proofpoint_trap-v1.0.37.tgz` from `connectors/` when 1.0.38 is added (default), or keep both?
3. `proofpoint_trap_acknowledge` sends `assignee` without `team` (see B1 below): send the incident's
   current team, drop the step, or document-only?
4. An expired prompt in acknowledge still writes "Acknowledged by SOAR" and opens the incident, while
   `proofpoint_trap_close` aborts. Which behaviour is wanted?
5. Which user should the 4 automation playbooks "Run As"? Do not invent an answer.

If the user is not available, finish everything that does not depend on these, leave B as
documentation only, and do not bump the version or rebuild the connector tgz. The playbook tgz
rebuilds do not depend on the connector version and can go ahead.

---

### Merged prompt (paste from here)

Repo: `cyberkara/soar-uc2-handover`, the air-gapped Splunk SOAR handover package for "UC2,
Proofpoint TRAP incident triage". It contains the connector in `connectors/source/proofpoint_trap/`,
7 playbooks plus 1 custom function in `playbooks/source/`, asset templates in `assets/`, and
`HANDOVER.md` / `HANDOVER_french.md`. Two jobs, done in one pass: (I) fix the connector README and
make the connector package reproducible from this repo, and (II) fix the findings of a static code
audit. No TRAP or SOAR instance is available, so nothing can be tested end to end. Say so in the
report. Do not claim anything is verified that was not.

#### Rules

- Work on the branch the session gives you. If none is given, create one off `main`. Commit there.
  Do not open a PR.
- Do not touch `.github/` or `tools/release-connectors.sh` (release automation is handled
  elsewhere; they are not in this snapshot). Do not touch unrelated files.
- This repo is a generated snapshot (see the HANDOVER.md header). The plan refers to other repos,
  `soar-connectors` and `soar-playbooks`. Fix things here, and finish with a list of changes that
  must be carried upstream.
- The `.tgz` files are what actually gets imported. Today `connectors/*.tgz` and `playbooks/*.tgz`
  are byte-for-byte copies of `source/`. After any source change, rebuild the affected tarball(s)
  and diff the extracted result against source. Check the layout with `tar tzvf` first.
  - Connector tgz: a top-level `proofpoint_trap/` directory holding `README.md`, `__init__.py`,
    `logo*.svg`, `proofpoint_trap.json`, the connector `.py` and the consts `.py`. That is 7 files.
    No `__pycache__`.
  - Playbook tgz: flat `<name>.py` and `<name>.json`, mtime 1970-01-01, uid 0.
- The README ships inside the connector tgz. SOAR refuses a same-version reinstall, so never
  rebuild or replace `proofpoint_trap-v1.0.37.tgz` under its own name. Any change to the README or
  connector code means a new version. Ask before bumping `app_version`. The next version is 1.0.38
  (current is 1.0.37, verified). Use one bump for everything below.
- Playbook `.json` files embed the code in `coa.data.nodes.<n>.userCode`. Edit the `.py` and the
  matching JSON node together and confirm they agree.
- Keep edits inside the existing custom-code regions. HANDOVER.md warns that a VPE re-save
  regenerates some blocks wrongly (`dispatch_mime_refetch`, `dispatch_artifact_list`). Do not
  restructure those blocks.
- Checks: `py_compile`, `pyflakes` and `bandit`. For connector logic, stub the `phantom.*` modules
  in a scratch directory and test the changed helpers there. Do not commit scratch files. Delete
  any `__pycache__` you create.
- Audit line numbers may have shifted (they are already about 10 lines off). Re-validate each
  finding against current HEAD first.

#### Suggested order

0. Confirm the decisions above. Re-validate the findings against HEAD.
1. **Build script.** Add a small script here (suggested `connectors/build_connector.sh`) that
   produces the connector layout above from `connectors/source/proofpoint_trap/`. Prefer one script
   that can also build the flat playbook layout, so every rebuild is reproducible. Before editing any
   source, run it on the unmodified source into a scratch directory and compare the extracted result
   with the existing v1.0.37 tgz. Report honestly whether it is byte-identical or only
   content-identical (tar ordering, gzip header, mtime and owner can differ). Optionally make it fail
   if the README's `Version:` line differs from `app_version`.
2. **Connector README** (one pass, `connectors/source/proofpoint_trap/README.md`):
   - Line 7 says `Version: 1.0.13`. Set it to the release version.
   - Drift-check the rest (Min SOAR version 6.4.1, the action list, the asset fields table) against
     `proofpoint_trap.json` and `proofpoint_trap_connector.py`. Report every drift you find.
     Suspected, to verify: lists 6 of 11 actions; describes the old `cs1`/`cs2`/`cn1` Event Info
     fields where the real CEF names are `abuseDisposition`, `classification`, `subDisposition`,
     `threatScore`, `incidentId`, `eventIds`, `trapSeverity` and `message`.
   - Installation currently says to run `tools/build.sh proofpoint_trap` "from the soar-connectors
     repo root" to get `dist/proofpoint_trap-v<version>.tgz`. Neither that repo nor that script is
     here. Point it at the new script (and say where the upstream build lives). Remove the lab
     filesystem path from the Installation section.
3. **Connector code** (A1, A4, A5, A7 connector half). Stub-test each helper.
4. **Playbooks** (A2, A6, A7 playbook half, C safe change, D).
5. **Assets and documentation** (A3, A8, B minimum, C, D notes), both languages.
6. **Release mechanics**, only after approval: bump `app_version` in `proofpoint_trap.json`, update
   `utctime_updated`, build the connector tgz with the script, remove or keep the old tgz per the
   decision, rebuild the changed playbook tgzs, extract and diff each against source, then update
   HANDOVER.md **and** HANDOVER_french.md (Contents table and upgrade notes).
7. Run `py_compile`, `pyflakes`, `bandit`. Delete `__pycache__`. Commit, push, report.

#### A. Fix these (clear-cut)

1. **`on_poll` loses incidents on a failed ingest** (`proofpoint_trap_connector.py`, about :528-545
   and :583-599).
   - `_ingest_incident` returns "failed" but `last_poll_time` still advances, so that incident is
     never fetched again.
   - The `save_artifacts` result is never checked. A container without its Event Info artifact is
     never triaged, and later polls skip it as a duplicate.
   - Fix: count failures and do not advance the checkpoint past them (or hold it at the earliest
     failed incident), and check the `save_artifacts` result.
   - Constraint: a retry hits the "duplicate container" path, so make artifact creation idempotent
     there. Event Info uses a stable source data identifier (`trap-{id}-info`).
2. **`proofpoint_trap_detail` writes "Enrichment Complete" after a failed email download**
   (about :270-313 and :765-816).
   - `mime_status_rows[0][0]` reads only the first action result, so partial failures look like
     success.
   - Fix: distinguish a real failure (network, auth, 5xx, or an event that failed) from a legitimate
     "no stored message for this alert" (HTTP 404, which the connector README says is normal). Only
     the real failure produces "Enrichment Failed" instead of "Enrichment Complete", so
     `check_reentry` allows a retry.
   - Nothing re-triggers detail for an unchanged incident. Either document that, or find a safe way
     to make it retry. This relates to the existing v1.0.36 note in HANDOVER about incidents marked
     complete although the download failed. Keep them consistent.
3. **Asset templates ship lab values** (`assets/*.json`).
   - `proofpoint_trap_mock.json`: `verify_ssl: false`, `poll_hours: 4000`, `abuse_disposition: ""`.
     The empty disposition means no filter, so the first poll ingests about 166 days of every new
     incident.
   - `soar8.json`: `verify_certificate: false`, and it carries an auth token.
   - `smtp.json`: `ssl_config: "None"`, which sends mail in cleartext.
   - Set safe defaults: verification true, `poll_hours` 1, `abuse_disposition` "Unknown" (the
     connector default). For SMTP, use a clearly marked placeholder or an explicit note. Do not guess
     the valid values of another app's dropdown.
   - Add a "values to review before the first poll" section to HANDOVER.md and
     HANDOVER_french.md.
4. **`event_id` is unvalidated** (connector, about :1033-1036 and used in the path at :372).
   - `../../incidents/5/close.json?x=` was confirmed, using `requests`, to re-target the request to
     another API path with the API key. Error snippets echo the first 150 characters of the
     response body.
   - Fix: validate it (integer, or a strict `[A-Za-z0-9_-]+` pattern) and `urllib.parse.quote` it
     into the path.
5. **Inconsistent parameter coercion** (connector, about :483, :663, :690-692, :743, :897; current
   HEAD shows `container_count` at :484, `expand_events` at :664 and :752, `max_results` at
   :691, `overwrite` at :907).
   - `max_results` and `container_count` are not validated. A VPE literal arrives as a string, the
     same bug class as the `hours_back` fix in 1.0.34.
   - The booleans `expand_events` and `overwrite` are read by truthiness, so the string "false"
     counts as true.
   - Fix: use `_validate_integer` for the numbers and add a small boolean parser.
6. **Untrusted email HTML goes into `phantom.add_note` unescaped**
   (`proofpoint_trap_attachments.py`, about :313-320 and :355-356).
   - Only an undocumented platform sanitizer protects it. The headers and plain-text body are
     already escaped.
   - Fix: escape the HTML body, or convert it to text, before building the note.
7. **`proofpoint_trap_recheck` robustness.**
   - `state=""` (about :59-62) is sent as an empty `state=`. The only evidence that it means "all
     states" is the mock server. Fix in the connector: omit empty query params
     (`_fetch_and_filter_incidents` is the place).
   - Prune the state list to incidents in the current window (about :142, :160), and only after a
     successful `get_list`.
   - If `get_list` fails (about :135-145), abort the cycle. Do not treat it as a first run, because
     that swallows changes.
   - Commit a signature to state only when that incident's artifact POSTs succeeded (about
     :331-377). Check the POST response, not just whether an exception was raised.
8. **Documentation gaps.**
   - Add the Timer asset (`assets/proofpoint_trap_recheck.json`) and the labels `proofpoint_trap`
     and `proofpoint_trap_recheck` to the install steps.
   - Document that the `isolation_browser_url` playbook input defaults to the placeholder
     `https://my_isolated_browser/browser?url=`, which produces dead links.
   - Refresh the connector README (done once, in step 2 above).
   - Reword the code comments that cite `uc2_dev_notes.md` and `proofpoint_trap_api_reference.md`,
     which are not shipped.
   - Update `utctime_updated` in `proofpoint_trap.json` (currently `2026-08-20`).

#### B. Ask the user before changing these (documentation is always allowed)

1. **`proofpoint_trap_acknowledge` sends `assignee` without `team`** (about :207-212).
   - The action requires both, so the step fails on every run. `docs/uc2_implementation_plan.md`
     (about :997-1020) documents this, and adds that even a valid write may fail with a
     `ConstraintViolationException` on their lab TRAP.
   - At minimum, document it as a known failure in HANDOVER.md and HANDOVER_french.md.
   - Code-fix options: send the incident's current team, or drop the step.
   - An expired prompt still writes "Acknowledged by SOAR" and opens the incident, while
     `proofpoint_trap_close` aborts. Ask which behaviour is wanted.
2. **"Run As" user for the 4 automation playbooks.** HANDOVER.md step 5 points to a Setup Guide
   that has no such guidance. The only documented requirement is that the `soar8` asset's user needs
   a role that can edit containers (Automation). Do not invent the answer.

#### C. Cannot verify offline: document as open verification items, or make only the safe change

- `proofpoint_trap_attachments.py` (about :98) calls `collect2` without `scope="all"`. The plan
  (about :117-123) documents this exact bug class. Adding `scope="all"` should be safe because the
  `attachments_extracted` marker makes the playbook idempotent.
- Recheck's `download mime body` runs in the Timer tick's container, so `get_container_id()`
  (connector, about :1015) probably vaults the `.eml` in the tick container, not the incident's.
  Do not change this blindly. Flag it for a live check.

#### D. Low priority, only if cheap

- Sanitize attachment filenames with `os.path.basename` before `vault_add` and in the source data
  identifier (`proofpoint_trap_attachments.py`, about :190-223 and :248).
- `datetime.utcfromtimestamp` (`proofpoint_trap_detail.py`, about :219) is deprecated from Python
  3.12.
- Remove the unused and duplicated imports in `attachments.py`, `detail.py` and `close.py`.
- The 12 `verify=False` calls to SOAR's local REST API are acceptable on loopback. Note them.
- `_process_response` (connector, about :196-201) stores full response bodies and headers in action
  debug data, which may include email content. Note it.
- The Timer asset creates a container every 15 minutes with no cleanup. Document it.

#### Keep as they are

HTTPS is enforced. `verify_ssl` defaults to true in the connector. POSTs are not retried. Secrets
in the templates are redacted. The tgz contents match the source directories (re-confirm after the
rebuild).

#### Report back

- **Changed vs only flagged** (prompt 1's split), listed separately.
- **Per finding** (A1-A8, B1-B2, C, D): `fixed`, `skipped`, `needs-decision` or
  `not reproducible at HEAD`, with one line on why.
- **README drift**: every mismatch found against `proofpoint_trap.json` and the connector `.py`,
  including any not fixed.
- **Build script**: whether it reproduces the v1.0.37 layout, and whether byte-identical or
  content-identical.
- **Version handling**: what was done about the same-version reinstall problem, and what the user
  approved.
- **Unverified**: state plainly that there was no SOAR or TRAP instance, and list what that leaves
  unverified.
- **Upstream changes to carry over** to `soar-connectors` and `soar-playbooks`.


---

## NS-2: In-code cleanup backlog

**Constraint.** The connector, the playbook `.py`/`.json` files and the `.tgz` packages are treated as
read-only from now on: no further edits until the owner says otherwise. Everything below is for a
session or person who has that go-ahead. The markdown side is finished: `docs/design_notes.md` holds all
the rationale, including the notes for the comments that are still in the code, so trimming them later
loses nothing.

**Already done (pass 1, commit `3b39a78`).** Before this constraint, comments were moved out of the
connector, consts and five playbooks (37 edits, 284 comment lines to 82). It was checked to change no
behaviour, but it does touch code. If the owner does not want it, revert only the connector part with
`git checkout e0fef59 -- connectors/source/proofpoint_trap/` (the source then matches
`proofpoint_trap-v1.0.37.tgz` again), and the playbooks with `git checkout e0fef59 -- playbooks/`.

### Backlog

| ID | What to clean | Where | Note / decision needed |
|----|---------------|-------|------------------------|
| T1 | Shorten the 27 remaining comment blocks of 5+ lines to one or two lines. Their content is in `design_notes.md`. | `detail` (excluded senders, container name, post-only-new, parallel lists, failed writes, fan-out, no-automation, `check_reentry`), `recheck` (first cycle, only ingested, fan-out, tie-back, POST dedupe), `acknowledge` and `close` (prompt from code, dispatch failure), `attachments` (severity, marker update), `summary` (note parts), `triage`, `extract_incident_id` | Optional, about 150 lines of comments. They sit next to tricky code, so keep one line of "why" each. |
| T2 | "Bridge block" banners citing another project's playbook (`cyberark_rotation_orchestrator`) | `acknowledge`, `close`, `isolation_notify` (`.py` only; not stored in the JSON) | VPE-generated. Fix by a VPE re-save, or accept. Editing the `.py` alone makes it differ from what the VPE emits. |
| T3 | VPE leftovers: the `on_finish` template (45 lines), commented `phantom.debug('Action: ...` lines (14), block markers (60), banner triples (446 lines) | all playbooks | Regenerated on every save. Do not hand-edit; not worth removing. |
| T4 | Connector cosmetics: section banners (34 lines of `# ------`) and "Returns: tuple ... RetVal pattern" docstring boilerplate | `proofpoint_trap_connector.py` | Optional. Ships only with the next connector version (NS-1, 1.0.38). |
| T5 | Hard-coded fallback approver `soar_local_admin` (prompt comment and `container.get('owner_name') or 'soar_local_admin'`) | `acknowledge` (2 places), `close` (2 places) | A behaviour change, not a comment. Tie it to the "Run As user" question (NS-1, decision 5): keep, make it a required input, or drop the fallback. |
| T6 | Internal jargon: PB1 to PB8 and "UC2" in the playbook descriptions (JSON `description` and module docstring) and in some runtime text, for example the failure message "a later PB1 run can redo the enrichment" in `detail` | all playbooks | User-visible text, so it needs a naming decision first. The PB-to-name mapping is in `design_notes.md`. |
| T7 | Unused and duplicated imports, datetime deprecation, filename sanitising, and the other NS-1 section D items | `attachments`, `detail`, `close` | Already in NS-1; do them in the same pass. |
| T8 | Lab specifics in markdown (editable now, but it is the owner's design record, so ask before generalising). Matching lines at this commit: `soar_local_admin` 11, "lab" 13, long numeric ids 52, references to sibling repos and unshipped files 45 | `docs/uc2_implementation_plan.md`; also `HANDOVER.md` (one `soar_local_admin`, one "lab") and `HANDOVER_french.md` (one `soar_local_admin`) | Find them with the `git grep` under this table. |
| T9 | Lab values in the asset templates and the lab path in the connector README | `assets/*.json`, `connectors/source/proofpoint_trap/README.md` | Already in NS-1 (A3, A8). |
| T10 | Connector source versus `proofpoint_trap-v1.0.37.tgz` | connector | Differs in comments and one docstring only. Resolved by the 1.0.38 bump in NS-1; until then the shipped tgz is the older, more verbose one, which is harmless. |

To find the T8 lines:

```bash
git grep -n -i -E 'soar_local_admin|\blab\b|[0-9]{9,}|container [0-9]{3,}' -- docs 'HANDOVER*.md'
```

### How to apply an edit safely, when allowed

1. Change the `.py` and the playbook `.json` together, by **literal string replacement** (for the JSON,
   replace `json.dumps(old_block)[1:-1]` with the same for the new block, and require exactly one
   match). Never load and re-save the JSON: that reformats it, and `.gitleaksignore` is keyed to JSON
   line numbers, so the line count of each JSON file must not change.
2. Do not restructure `dispatch_mime_refetch` or `dispatch_artifact_list`, and do not re-save in the
   VPE just to tidy comments (it regenerates some blocks wrongly, per `HANDOVER.md`).
3. Rebuild only the tgz of playbooks that changed. Never rebuild the connector tgz under its current
   version (SOAR refuses a same-version reinstall).

Checks to run afterwards (all were run for pass 1):

```python
# 1. Behaviour unchanged: the syntax trees must match, docstrings aside.
#    python3 check_ast.py old.py new.py     (old.py = `git show <commit>:<path>`)
import ast, sys

def norm(path):
    tree = ast.parse(open(path, encoding="utf-8").read())
    for n in ast.walk(tree):
        if isinstance(n, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            b = n.body
            if (b and isinstance(b[0], ast.Expr) and isinstance(getattr(b[0], "value", None), ast.Constant)
                    and isinstance(b[0].value.value, str)):
                n.body = b[1:] or [ast.Pass()]
    return ast.dump(tree)

print(norm(sys.argv[1]) == norm(sys.argv[2]))
```

```python
# 2. JSON still in step with its .py: same keys, and every code string that changed is still
#    verbatim inside the .py (the Global Custom Code is at coa/data/globalCustomCode).
import json, sys
old, new, py = (json.load(open(sys.argv[1])), json.load(open(sys.argv[2])), open(sys.argv[3]).read())

def walk(o, p=""):
    if isinstance(o, dict):
        for k, v in o.items():
            yield from walk(v, p + "/" + k)
    elif isinstance(o, list):
        for i, v in enumerate(o):
            yield from walk(v, p + "[%d]" % i)
    else:
        yield p, o

a, b = dict(walk(new)), dict(walk(old))
assert set(a) == set(b), "key set differs"
print([p for p in a if a[p] != b[p] and not (isinstance(a[p], str) and a[p].strip() in py)] or "ok")
```

```bash
# 3. JSON line counts unchanged (protects .gitleaksignore):
for f in playbooks/source/*/*.json; do
  [ "$(git show HEAD:$f | wc -l)" = "$(wc -l < $f)" ] || echo "line count changed: $f"
done
# 4. Static checks: py_compile-style parse, then compare against the baselines below.
python3 -m pyflakes <file>; python3 -m bandit -q <file>
```

```python
# 5. Rebuild a playbook tgz (same layout as the shipped ones: PAX tar, mode 0644, uid/gid 0,
#    empty user/group names, mtime 0, .py then .json; gzip mtime 0 so it is repeatable).
import gzip, io, tarfile

def build(name, srcdir, out):
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as tf:
        for ext in (".py", ".json"):
            data = open("%s/%s%s" % (srcdir, name, ext), "rb").read()
            ti = tarfile.TarInfo(name + ext)
            ti.size, ti.mtime, ti.mode, ti.uid, ti.gid, ti.uname, ti.gname = len(data), 0, 0o644, 0, 0, "", ""
            tf.addfile(ti, io.BytesIO(data))
    with open(out, "wb") as f, gzip.GzipFile(filename="", mode="wb", fileobj=f, mtime=0, compresslevel=9) as gz:
        gz.write(raw.getvalue())
```

Then extract each rebuilt tgz and `diff` it against its source directory. This builder reproduces the tar
layer of all 10 shipped playbook tgz exactly.

**Baselines** (pyflakes findings and bandit issues at commit `3b39a78`; compare against these, not zero):
connector 44 and 1, consts 0 and 0, `acknowledge` 1 and 0, `attachments` 3 and 0, `detail` 3 and 0,
`isolation_notify` 2 and 0, `recheck` 2 and 0. The other playbooks were not changed and not measured.

### What stays unverified

No SOAR or TRAP instance was available, so none of this was run end to end. The checks above prove that
the code and the JSON did not change in behaviour or in step with each other. They do not prove that
SOAR imports the rebuilt playbooks.

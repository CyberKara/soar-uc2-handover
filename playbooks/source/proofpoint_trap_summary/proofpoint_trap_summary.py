"""
Data playbook (PB8) run by an analyst from a Proofpoint TRAP container. Reads every artifact on the container and writes one &#39;TRAP Summary&#39; note with a markdown table per artifact type (incident, senders, recipients, domains, URLs, click IPs, MIME bodies, attachments, enrichment runs, then any other type). Re-running it rewrites the same note in place.
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'build_summary' block
    build_summary(container=container)

    return

@phantom.playbook_block()
def build_summary(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("build_summary() called")

    ################################################################################
    # Build one markdown table per artifact type from every artifact on the container.
    ################################################################################

    id_value = container.get("id", None)
    playbook_input_max_rows = phantom.collect2(container=container, datapath=["playbook_input:max_rows"])

    playbook_input_max_rows_values = [item[0] for item in playbook_input_max_rows]

    build_summary__note_content = None

    ################################################################################
    ## Custom Code Start
    ################################################################################
    ################################################################################

    # One markdown table per artifact type, built from every artifact on the
    # container (read over REST: all of them, whichever run or playbook created
    # them). Known UC2 types get chosen columns; any other type gets a generic
    # table so nothing on the container is left out.
    # Playbook input max_rows (optional): rows shown per table, default 250.
    MAX_ROWS = 250
    raw_max_rows = next((v for v in playbook_input_max_rows_values if v not in (None, "")), None)
    if raw_max_rows is not None:
        try:
            MAX_ROWS = max(1, int(str(raw_max_rows).strip()))
        except ValueError:
            phantom.debug("Ignoring max_rows input {!r}: not a whole number".format(raw_max_rows))

    # Playbook outputs, read by on_finish. Starts as failed; each step that
    # succeeds updates it.
    playbook_output = {"status": "failed", "note_id": None, "artifact_count": None}
    phantom.save_run_data(key="playbook_output", value=json.dumps(playbook_output))

    def cell(value, limit=200):
        text = "" if value is None else str(value)
        text = " ".join(text.split())
        if len(text) > limit:
            text = text[:limit - 3] + "..."
        return text.replace("|", "\\|")

    def created(artifact):
        return (artifact.get("create_time") or "")[:16].replace("T", " ")

    def sdi_event(artifact):
        # MIME Body SDI is "trap-<incident>-mime-<event>"
        sdi = artifact.get("source_data_identifier") or ""
        return sdi.split("-mime-", 1)[1] if "-mime-" in sdi else ""

    def enrichment_result(artifact):
        return "complete" if artifact.get("name") == "Enrichment Complete" else "failed"

    cef = lambda key: (lambda a: (a.get("cef") or {}).get(key))
    sections = [
        ("Incident", ["Event Info", "Event Info Update"], [
            ("Artifact", lambda a: a.get("name")),
            ("Disposition", cef("abuseDisposition")),
            ("Sub-disposition", cef("subDisposition")),
            ("Classification", cef("classification")),
            ("TRAP severity", cef("trapSeverity")),
            ("Score", cef("threatScore")),
            ("Created", created),
        ]),
        ("Sender Email", ["Sender Email"], [
            ("Address", cef("emailAddress")),
            ("Subject", cef("emailSubject")),
            ("Delivered", cef("deliveryTime")),
            ("Message ID", cef("messageId")),
            ("Body type", cef("bodyType")),
            ("Abuse copy", cef("abuseCopy")),
        ]),
        ("Recipient Email", ["Recipient Email"], [
            ("Address", cef("emailAddress")),
            ("Role", cef("emailRole")),
        ]),
        ("Sender Domain", ["Sender Domain"], [("Domain", cef("sourceDnsDomain"))]),
        ("Threat Domain", ["Threat Domain"], [("Domain", cef("destinationDnsDomain")), ("URL", cef("url"))]),
        ("URL", ["URL Artifact"], [("URL", cef("requestURL"))]),
        ("Click Source IP", ["Click Source IP"], [("IP", cef("sourceAddress"))]),
        ("MIME Body", ["MIME Body"], [
            ("Event", sdi_event),
            ("File name", cef("fileName")),
            ("Vault ID", cef("vaultId")),
        ]),
        ("Email Attachment", ["Email Attachment"], [
            ("File name", cef("fileName")),
            ("Type", cef("fileType")),
            ("SHA256", cef("fileHashSha256")),
            ("Warning", cef("mimeTypeMismatch")),
        ]),
        ("Enrichment runs", ["Enrichment Complete", "Enrichment Failed"], [
            ("Created", created),
            ("Result", enrichment_result),
            ("Alerts", cef("alertCount")),
            ("New artifacts", cef("artifactsCreated")),
            ("Already present", cef("artifactsAlreadyPresent")),
            ("Message", cef("message")),
        ]),
    ]

    container_id = id_value
    try:
        response = phantom.requests.get(
            uri=phantom.build_phantom_rest_url("artifact"),
            params={"_filter_container": container_id, "page_size": 0, "sort": "id", "order": "asc"},
            verify=False,
        ).json()
        artifacts = response.get("data") or []
    except Exception as e:
        phantom.error("Could not read the artifacts of container {}: {}".format(container_id, str(e)))
        return

    by_name = {}
    for artifact in artifacts:
        by_name.setdefault(artifact.get("name") or "(no name)", []).append(artifact)

    incident_id = container.get("source_data_identifier") or "?"
    lines = [
        "# TRAP Summary — Incident {}".format(incident_id),
        "Updated {} UTC — {} artifacts on this container.".format(
            datetime.utcnow().strftime("%Y-%m-%d %H:%M"), len(artifacts)),
        "",
    ]

    def add_table(title, rows, columns):
        lines.append("## {} ({})".format(title, len(rows)))
        lines.append("")
        lines.append("| " + " | ".join(header for header, _ in columns) + " |")
        lines.append("|" + "---|" * len(columns))
        for artifact in rows[:MAX_ROWS]:
            lines.append("| " + " | ".join(cell(getter(artifact)) for _, getter in columns) + " |")
        if len(rows) > MAX_ROWS:
            lines.append("")
            lines.append("… {} more not shown.".format(len(rows) - MAX_ROWS))
        lines.append("")

    covered = set()
    for title, names, columns in sections:
        rows = [a for name in names for a in by_name.get(name, [])]
        covered.update(names)
        if rows:
            rows.sort(key=lambda a: a.get("id") or 0)
            add_table(title, rows, columns)

    for name in sorted(n for n in by_name if n not in covered):
        rows = by_name[name]
        add_table(name, rows, [
            ("Created", created),
            ("Fields", lambda a: ", ".join("{}={}".format(k, v) for k, v in sorted((a.get("cef") or {}).items()))),
        ])

    build_summary__note_content = "\n".join(lines)
    phantom.debug("Summary built: {} artifacts, {} types".format(len(artifacts), len(by_name)))

    playbook_output["artifact_count"] = len(artifacts)
    phantom.save_run_data(key="playbook_output", value=json.dumps(playbook_output))

    # Also saved as run data: write_summary_note's input reads this key.
    phantom.save_run_data(key="build_summary:note_content", value=json.dumps(build_summary__note_content))

    ################################################################################
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_block_result(key="build_summary:note_content", value=json.dumps(build_summary__note_content))

    phantom.save_block_result(key="build_summary_called", value="True")

    write_summary_note(container=container)

    return


@phantom.playbook_block()
def write_summary_note(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("write_summary_note() called")

    ################################################################################
    # Write the 'TRAP Summary' note: update it in place if it exists, create it otherwise.
    ################################################################################

    build_summary__note_content = json.loads(_ if (_ := phantom.get_run_data(key="build_summary:note_content")) != "" else "null")  # pylint: disable=used-before-assignment

    ################################################################################
    ## Custom Code Start
    ################################################################################
    ################################################################################

    # One summary note per container, rewritten in place on every run:
    # phantom.add_note() can only create a note, so an existing "TRAP Summary"
    # note is updated over REST and a new one is created only on the first run.
    title = "TRAP Summary"
    content = build_summary__note_content
    if not content:
        phantom.error("No summary content to write")
        return

    container_id = container.get("id")
    note_url = phantom.build_phantom_rest_url("note")
    try:
        existing = phantom.requests.get(
            uri=note_url,
            params={"_filter_container": container_id, "_filter_title": '"{}"'.format(title),
                    "sort": "id", "order": "asc", "page_size": 0},
            verify=False,
        ).json().get("data") or []
    except Exception as e:
        phantom.error("Could not list the notes of container {}: {}".format(container_id, str(e)))
        existing = []

    note_id = None
    if existing:
        note_id = existing[0]["id"]
        response = phantom.requests.post(
            uri="{}/{}".format(note_url, note_id),
            data=json.dumps({"title": title, "content": content, "note_format": "markdown"}),
            verify=False,
        )
        action = "updated"
    else:
        response = phantom.requests.post(
            uri=note_url,
            data=json.dumps({"container_id": container_id, "title": title, "content": content,
                             "note_type": "general", "note_format": "markdown"}),
            verify=False,
        )
        action = "created"

    try:
        body = response.json()
    except Exception:
        body = {}
    if response.status_code >= 300 or body.get("failed"):
        phantom.error("TRAP Summary note could not be {} (HTTP {}): {}".format(
            action, response.status_code, str(body)[:300]))
    else:
        note_id = note_id or body.get("id")
        phantom.debug("TRAP Summary note {} on container {}".format(action, container_id))
        playbook_output = json.loads(phantom.get_run_data(key="playbook_output") or "{}")
        playbook_output.update({"status": "success", "note_id": note_id})
        phantom.save_run_data(key="playbook_output", value=json.dumps(playbook_output))

    ################################################################################
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_block_result(key="write_summary_note_called", value="True")

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")

    output = {
        "status": None,
        "note_id": None,
        "artifact_count": None,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################
    ################################################################################

    # Populate the generated `output` dict; the save after Custom Code End emits it.
    # No block recorded an outcome (e.g. the run stopped early): report failed.
    raw_output = phantom.get_run_data(key="playbook_output")
    if raw_output:
        output.update(json.loads(raw_output))
    if output["status"] is None:
        output["status"] = "failed"

    ################################################################################
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_playbook_output_data(output=output)

    return


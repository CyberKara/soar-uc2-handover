"""
Automation playbook (PB8) for label &#39;proofpoint_trap&#39;. Once proofpoint_trap_detail has enriched the container (its &#39;Enrichment Complete&#39; artifact runs automation), reads every artifact on the container and writes one &#39;TRAP Summary&#39; note with a markdown table per artifact type (incident, senders, recipients, domains, URLs, click IPs, MIME bodies, attachments, enrichment runs, then any other type). Every later run rewrites the same note in place.
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

    build_summary__note_content = None

    ################################################################################
    ## Custom Code Start
    ################################################################################
    ################################################################################

    # One markdown table per artifact type, built from every artifact on the
    # container (read over REST: all of them, whichever run or playbook created
    # them). Known UC2 types get chosen columns; any other type gets a generic
    # table so nothing on the container is left out.
    MAX_ROWS = 250  # rows shown per table

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

    # This playbook runs on every automation trigger of the container. Until
    # proofpoint_trap_detail has finished (no Enrichment Complete or Enrichment
    # Failed artifact yet) there is nothing to summarise, so stop here.
    names = {artifact.get("name") for artifact in artifacts}
    if not names & {"Enrichment Complete", "Enrichment Failed"}:
        phantom.debug("proofpoint_trap_detail has not finished on this container yet -- no summary")
        return

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

    by_name = {}
    for artifact in artifacts:
        by_name.setdefault(artifact.get("name") or "(no name)", []).append(artifact)

    incident_id = container.get("source_data_identifier") or "?"
    intro = [
        "# TRAP Summary — Incident {}".format(incident_id),
        "Updated {} UTC — {} artifacts on this container.".format(
            datetime.utcnow().strftime("%Y-%m-%d %H:%M"), len(artifacts)),
        "",
    ]

    # (title, header lines, row lines, closing lines) per table
    tables = []

    def add_table(title, rows, columns):
        header = ["| " + " | ".join(h for h, _ in columns) + " |", "|" + "---|" * len(columns)]
        row_lines = ["| " + " | ".join(cell(getter(artifact)) for _, getter in columns) + " |"
                     for artifact in rows[:MAX_ROWS]]
        closing = ["", "… {} more not shown.".format(len(rows) - MAX_ROWS), ""] if len(rows) > MAX_ROWS else [""]
        tables.append(("{} ({})".format(title, len(rows)), header, row_lines, closing))

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

    # The target SOAR shows at most about 22,000 characters of a note, so the
    # summary is written as notes of at most NOTE_MAX_CHARS. A table that does
    # not fit continues in the next note under a repeat of its header, so every
    # part renders as tables.
    NOTE_MAX_CHARS = 20000

    def size_of(block):
        return sum(len(line) + 1 for line in block)

    parts, current = [], list(intro)
    for title, header, row_lines, closing in tables:
        started = False
        for row in row_lines:
            head = ["## {} (continued)".format(title), ""] + header if started else ["## {}".format(title), ""] + header
            if current and size_of(current) + size_of(head + [row]) > NOTE_MAX_CHARS - 300:
                parts.append(current)
                current = []
            elif started:
                head = []
            current += head + [row]
            started = True
        if current and size_of(current) + size_of(closing) > NOTE_MAX_CHARS - 300:
            parts.append(current)
            current = []
        current += closing
    if current:
        parts.append(current)

    total = len(parts)
    build_summary__note_content = []
    for number, part in enumerate(parts, 1):
        part_title = "TRAP Summary" if total == 1 else "TRAP Summary ({}/{})".format(number, total)
        if number > 1:
            part = ["# TRAP Summary — Incident {} ({}/{}, continued)".format(incident_id, number, total), ""] + part
        build_summary__note_content.append([part_title, "\n".join(part)])
    phantom.debug("Summary built: {} artifacts, {} types, {} note(s)".format(len(artifacts), len(by_name), total))

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

    # The summary is one note, or parts "TRAP Summary (k/N)" when it is longer
    # than a note may be (build_summary). Every run rewrites them in place:
    # part k goes to the k-th oldest existing summary note, missing ones are
    # created, and parts left over from a longer earlier summary are blanked as
    # "TRAP Summary (unused)" -- a playbook may not delete notes (REST DELETE
    # answers 403 for the automation user) -- and reused if it grows again.
    # phantom.add_note() can only create a note, hence REST.
    parts = build_summary__note_content
    if isinstance(parts, str):
        parts = [["TRAP Summary", parts]]
    if not parts:
        phantom.error("No summary content to write")
        return

    container_id = container.get("id")
    note_url = phantom.build_phantom_rest_url("note")
    try:
        existing = phantom.requests.get(
            uri=note_url,
            params={"_filter_container": container_id, "_filter_title__startswith": '"TRAP Summary"',
                    "sort": "id", "order": "asc", "page_size": 0},
            verify=False,
        ).json().get("data") or []
    except Exception as e:
        phantom.error("Could not list the notes of container {}: {}".format(container_id, str(e)))
        existing = []

    for index, (part_title, part_content) in enumerate(parts):
        if index < len(existing):
            action = "updated"
            response = phantom.requests.post(
                uri="{}/{}".format(note_url, existing[index]["id"]),
                data=json.dumps({"title": part_title, "content": part_content, "note_format": "markdown"}),
                verify=False,
            )
        else:
            action = "created"
            response = phantom.requests.post(
                uri=note_url,
                data=json.dumps({"container_id": container_id, "title": part_title, "content": part_content,
                                 "note_type": "general", "note_format": "markdown"}),
                verify=False,
            )
        try:
            body = response.json()
        except Exception:
            body = {}
        if response.status_code >= 300 or body.get("failed"):
            phantom.error("{} could not be {} (HTTP {}): {}".format(
                part_title, action, response.status_code, str(body)[:300]))
        else:
            phantom.debug("{} {} on container {}".format(part_title, action, container_id))

    for stale in existing[len(parts):]:
        response = phantom.requests.post(
            uri="{}/{}".format(note_url, stale["id"]),
            data=json.dumps({"title": "TRAP Summary (unused)",
                             "content": "Not in use: the TRAP Summary now fits in {} note(s).".format(len(parts)),
                             "note_format": "markdown"}),
            verify=False,
        )
        phantom.debug("Blanked leftover summary part {!r} (note {}): HTTP {}".format(
            stale.get("title"), stale["id"], response.status_code))

    ################################################################################
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_block_result(key="write_summary_note_called", value="True")

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################
    ################################################################################

    # This function is called after all actions are completed.
    # summary of all the action and/or all details of actions
    # can be collected here.

    # summary_json = phantom.get_summary()
    # if 'result' in summary_json:
        # for action_result in summary_json['result']:
            # if 'action_run_id' in action_result:
                # action_results = phantom.get_action_results(action_run_id=action_result['action_run_id'], result_data=False, flatten=False)
                # phantom.debug(action_results)

    ################################################################################
    ################################################################################
    ## Custom Code End
    ################################################################################

    return


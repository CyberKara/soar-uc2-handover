"""
Automation playbook (PB4), left inactive: proofpoint_trap_orchestrator runs it after proofpoint_trap_triage. Writes the TRAP Summary in place: the CLEAR verdict, then one table per artifact type.
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
    # Build the summary from every artifact on the case (datapath reads).
    ################################################################################

    build_summary__note_title = None
    build_summary__note_content = None

    ################################################################################
    ## Custom Code Start
    ################################################################################
    ################################################################################

    # Every artifact on the case, whichever run or playbook created it, read
    # through datapaths (scope "all"). Known UC2 types get chosen columns; any
    # other type gets a generic table, so nothing is left out.
    MAX_ROWS = 250  # rows shown per table
    rows = phantom.collect2(container=container, datapath=[
        "artifact:*.id", "artifact:*.name", "artifact:*.create_time", "artifact:*.source_data_identifier", "artifact:*.cef"],
        scope="all")
    artifacts = [{"id": row[0], "name": row[1], "create_time": row[2] or "", "source_data_identifier": row[3],
                  "cef": row[4] if isinstance(row[4], dict) else {}} for row in rows or [] if row and row[0]]

    # Until proofpoint_trap_detail has finished (no Enrichment Complete or
    # Enrichment Failed yet) there is nothing to summarise.
    names = {artifact.get("name") for artifact in artifacts}
    if not names & {"Enrichment Complete", "Enrichment Failed"}:
        phantom.debug("proofpoint_trap_detail has not finished on this container yet -- no summary")
        return

    import re

    def cell(value, limit=200):
        text = "" if value is None else str(value)
        text = " ".join(text.split())
        if len(text) > limit:
            text = text[:limit - 3] + "..."
        # A URL in a note is clickable unless it sits in backticks.
        text = re.sub(r"(?:[a-z][a-z0-9+.-]*://|www\.)[^\s`]*[^\s`,;.)]",
                      lambda m: "`" + m.group(0) + "`", text.replace("`", "'"), flags=re.I)
        return text.replace("|", "\\|")

    def created(artifact):
        # artifact:*.create_time reads as an epoch number (REST gives ISO text).
        value = artifact.get("create_time")
        if isinstance(value, (int, float)):
            return datetime.utcfromtimestamp(value / 1000 if value > 1e11 else value).strftime("%Y-%m-%d %H:%M")
        return str(value or "")[:16].replace("T", " ")

    def sdi_event(artifact):
        # cef.eventId, else the identifier "trap-<incident>-mime-<event>"
        sdi = artifact.get("source_data_identifier") or ""
        return (artifact.get("cef") or {}).get("eventId") or (sdi.split("-mime-", 1)[1] if "-mime-" in sdi else "")

    def enrichment_result(artifact):
        return "complete" if artifact.get("name") == "Enrichment Complete" else "failed"

    def dkim_short(artifact):
        # DKIM-Signature is long (the signature itself); the signing domain
        # and selector are what an analyst compares with the sender.
        value = (artifact.get("cef") or {}).get("dkimSignature") or ""
        tags = dict(re.findall(r"(?:^|;)\s*([ds])=([^;\s]+)", value))
        return "; ".join("{}={}".format(k, tags[k]) for k in ("d", "s") if k in tags) or value

    def file_size(artifact):
        size = (artifact.get("cef") or {}).get("fileSize")
        try:
            size = int(size)
        except (TypeError, ValueError):
            return size
        return "{:,} KB ({} bytes)".format(round(size / 1024), size) if size >= 1024 else "{} bytes".format(size)

    cef = lambda key: (lambda a: (a.get("cef") or {}).get(key))
    # Received is a whole routing line; the column keeps it short so the
    # summary stays within the note size limit. The full chain is in the
    # Email Content note.
    def shortened(value, limit):
        text = " ".join(str(value or "").split())
        return text[:limit - 3] + "..." if len(text) > limit else text

    cef_short = lambda key, limit: (lambda a: shortened((a.get("cef") or {}).get(key), limit))
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
        # Split so neither table is too wide; Address ties the rows together
        # (proofpoint_trap_detail writes one Sender Email per address).
        ("Sender Email headers", ["Sender Email"], [
            ("Address", cef("emailAddress")),
            ("Address source", cef("senderSource")),
            ("In-Reply-To", cef("inReplyTo")),
            ("X-PhishAlarm-Sender", cef("phishAlarmSender")),
            ("Received-SPF", cef_short("receivedSpf", 80)),
            ("DKIM", dkim_short),
            ("Received", cef_short("received", 80)),
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
            ("Size", file_size),
            ("SHA256", cef("fileHashSha256")),
            ("MD5", cef("fileHashMd5")),
            ("Source", cef("attachmentSource")),
            ("Warning", cef("mimeTypeMismatch")),
        ]),
        ("Enrichment runs", ["Enrichment Complete", "Enrichment Failed"], [
            ("Created", created),
            ("Result", enrichment_result),
            ("Alerts", cef("alertCount")),
            ("TRAP state", cef("incidentState")),
            ("Message", cef("message")),
        ]),
    ]

    by_name = {}
    for artifact in artifacts:
        if artifact.get("name") == "TRAP Run State":
            continue
        by_name.setdefault(artifact.get("name") or "(no name)", []).append(artifact)

    incident_id = container.get("source_data_identifier") or "?"
    # No timestamp: the note is rewritten only when its content changes.
    intro = [
        "# TRAP Summary — Incident {}".format(incident_id),
        "{} artifacts on this case.".format(sum(len(v) for v in by_name.values())),
        "",
    ]

    # The verdict first: TRAP's CLEAR analysis (Abuse Disposition / Sub
    # Disposition) from the latest Event Info or Event Info Update, and the
    # threat names of the incident's alerts from the latest Enrichment
    # Complete -- a file a detection source condemned is named there.
    info = (by_name.get("Event Info Update") or []) + (by_name.get("Event Info") or [])
    info = max(info, key=lambda a: a.get("id") or 0) if info else None
    info_cef = (info or {}).get("cef") or {}
    verdict = " / ".join(str(v) for v in (info_cef.get("abuseDisposition"), info_cef.get("subDisposition")) if v)
    intro += ["**CLEAR verdict:** {}  ".format(cell(verdict) if verdict else "not available")]
    completes = by_name.get("Enrichment Complete") or []
    threat_names = ((max(completes, key=lambda a: a.get("id") or 0).get("cef") or {}).get("threatNames")
                    if completes else "")
    intro += ["**Threats named by the alerts:** {}".format(cell(threat_names, 600) if threat_names else "none"), ""]

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

    lines = list(intro)
    for title, header, row_lines, closing in tables:
        lines += ["## {}".format(title), ""] + header + row_lines + closing
    build_summary__note_title = "TRAP Summary"
    build_summary__note_content = "\n".join(lines)
    phantom.debug("Summary built: {} artifacts, {} types".format(len(artifacts), len(by_name)))
    phantom.save_run_data(key="build_summary:note_title", value=json.dumps(build_summary__note_title))
    phantom.save_run_data(key="build_summary:note_content", value=json.dumps(build_summary__note_content))

    ################################################################################
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_block_result(key="build_summary:note_title", value=json.dumps(build_summary__note_title))
    phantom.save_block_result(key="build_summary:note_content", value=json.dumps(build_summary__note_content))

    phantom.save_block_result(key="build_summary_called", value="True")

    summary_note(container=container)

    return


@phantom.playbook_block()
def summary_note(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("summary_note() called")

    ################################################################################
    # Write the TRAP Summary, updated in place; split into parts k/N over 20,000 characters 
    # (shared custom function).
    ################################################################################

    id_value = container.get("id", None)
    build_summary__note_title = json.loads(_ if (_ := phantom.get_run_data(key="build_summary:note_title")) != "" else "null")  # pylint: disable=used-before-assignment
    build_summary__note_content = json.loads(_ if (_ := phantom.get_run_data(key="build_summary:note_content")) != "" else "null")  # pylint: disable=used-before-assignment

    parameters = []

    parameters.append({
        "title": build_summary__note_title,
        "content": build_summary__note_content,
        "container_id": id_value,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="local/proofpoint_trap_note_upsert", parameters=parameters, name="summary_note")

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

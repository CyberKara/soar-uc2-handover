"""
Automation playbook (PB2) for label proofpoint_trap, left inactive: proofpoint_trap_orchestrator runs it after proofpoint_trap_attachments, at ingest and on each Event Info Update. Reads the TRAP incident ID, the raw TRAP Severity and the CLEAR verdict (Abuse Disposition / Sub Disposition) off the latest Event Info artifact and sets the container&#39;s severity to the higher of the two each run, since new artifacts arrive at SOAR&#39;s default severity and raise a lower one. Tags the container with the verdict (e.g. trap-malicious, trap-needs-manual-review), replacing an earlier verdict tag. Adds a TRAP Triage - Severity note when that severity first applies or changes. No writes back to TRAP. Analyst-driven actions (acknowledge, close) live in separate manually-launched playbooks: proofpoint_trap_acknowledge, proofpoint_trap_close.
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'extract_incident_id' block
    extract_incident_id(container=container)

    return

@phantom.playbook_block()
def extract_incident_id(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("extract_incident_id() called")

    ################################################################################
    # Extract TRAP incident ID (+ raw TRAP Severity) via the shared proofpoint_trap_extract_incident_id 
    # custom function.
    ################################################################################

    parameters = [{}]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="local/proofpoint_trap_extract_incident_id", parameters=parameters, name="extract_incident_id", callback=read_incident_id)

    return


@phantom.playbook_block()
def read_incident_id(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("read_incident_id() called")

    ################################################################################
    # Bridge block: read extract_incident_id CF result (incident_id + trap_severity) 
    # and promote container severity.
    ################################################################################

    extract_incident_id__result = phantom.collect2(container=container, datapath=["extract_incident_id:custom_function_result.data.incident_id","extract_incident_id:custom_function_result.data.trap_severity"])

    extract_incident_id_data_incident_id = [item[0] for item in extract_incident_id__result]
    extract_incident_id_data_trap_severity = [item[1] for item in extract_incident_id__result]

    read_incident_id__incident_id = None

    ################################################################################
    ## Custom Code Start
    ################################################################################
    ################################################################################


    result_rows = phantom.collect2(
        container=container,
        datapath=["extract_incident_id:custom_function_result.data.incident_id", "extract_incident_id:custom_function_result.data.trap_severity"],
    )
    incident_id_val, trap_severity = result_rows[0] if result_rows else (None, None)

    if not incident_id_val:
        phantom.error("Could not find Incident ID (cef.incidentId) on the 'Event Info' artifact")
        phantom.add_note(
            container=container,
            note_type="general",
            title="TRAP Triage - Error",
            content="Could not find Incident ID on the 'Event Info' artifact"
        )
        return

    read_incident_id__incident_id = str(incident_id_val)
    phantom.debug("Extracted incident ID: {}".format(read_incident_id__incident_id))

    severity_map = {"Critical": "high", "High": "medium", "Informational": "low"}
    previous_severity = container.get("severity")
    trap_mapped = severity_map.get(trap_severity, "low")

    # The CLEAR verdict (Abuse Disposition + Sub Disposition) of the latest
    # Event Info / Event Info Update also sets a severity; the container gets
    # the higher of the two, so the verdict can raise a case, never lower it
    # (user decision 2026-10-07). A sub-disposition exists only under Unknown.
    disposition_map = {
        "Malicious": "high",
        "Suspicious": "medium",
        "False Negative": "medium",
        "Unknown": "medium",
        "Bulk": "low",
        "Spam": "low",
        "Low Risk": "low",
        "Known Good": "low",
    }
    sub_disposition_map = {"Needs Manual Review": "medium", "Likely Harmless": "low"}
    info_rows = phantom.collect2(
        container=container,
        datapath=["artifact:*.name", "artifact:*.id", "artifact:*.cef.abuseDisposition", "artifact:*.cef.subDisposition"],
        scope="all",
    )
    info_rows = sorted(
        [row for row in (info_rows or []) if row and row[0] in ("Event Info", "Event Info Update")],
        key=lambda row: row[1] or 0,
    )
    disposition = str(info_rows[-1][2] or "").strip() if info_rows else ""
    sub_disposition = str(info_rows[-1][3] or "").strip() if info_rows else ""
    if disposition == "Unknown" and sub_disposition in sub_disposition_map:
        disposition_mapped = sub_disposition_map[sub_disposition]
    else:
        disposition_mapped = disposition_map.get(disposition)
    verdict = " / ".join(v for v in (disposition, sub_disposition) if v)

    severity_rank = {"low": 1, "medium": 2, "high": 3}
    mapped_severity = trap_mapped
    if disposition_mapped and severity_rank[disposition_mapped] > severity_rank[trap_mapped]:
        mapped_severity = disposition_mapped
    phantom.set_severity(container=container, severity=mapped_severity)
    phantom.debug(
        "Promoted container severity to '{}' (TRAP Severity: '{}', CLEAR verdict: '{}')".format(
            mapped_severity, trap_severity, verdict
        )
    )

    if trap_severity in severity_map:
        reason = "TRAP Severity `{}` maps to SOAR `{}`.".format(trap_severity, trap_mapped)
    else:
        reason = (
            "TRAP Severity `{}` is not in the mapping (Critical, High, Informational), "
            "so it counts as `low`.".format(trap_severity)
        )
    if disposition_mapped:
        reason += " CLEAR verdict `{}` maps to `{}`; the higher of the two applies.".format(verdict, disposition_mapped)
    else:
        reason += " CLEAR verdict `{}` is not in the mapping, so TRAP Severity alone applies.".format(verdict or "none")

    # One tag per verdict, so analysts can filter the queue on it: the
    # sub-disposition under Unknown (the only disposition that has one, as
    # for the severity above), else the disposition, as "trap-<words>"
    # (trap-needs-manual-review, trap-malicious). A changed verdict replaces
    # the old tag. Only these verdict tags are ever removed, never a tag an
    # analyst set.
    def _verdict_tag(value):
        return "trap-" + "-".join(str(value).lower().split())

    verdict_tags = {_verdict_tag(v) for v in list(disposition_map) + list(sub_disposition_map)}
    tag_value = sub_disposition if (disposition == "Unknown" and sub_disposition) else disposition
    current_tag = _verdict_tag(tag_value) if tag_value else None
    tags_ok, tags_message, live_tags = phantom.get_tags(container=container)
    if not tags_ok:
        phantom.debug("Could not read the container's tags: {}".format(tags_message))
    live_tags = live_tags or []
    stale_tags = [t for t in live_tags if t in verdict_tags and t != current_tag]
    if stale_tags:
        removed_ok, removed_message = phantom.remove_tags(container=container, tags=stale_tags)
        if not removed_ok:
            phantom.error("Could not remove verdict tags {}: {}".format(stale_tags, removed_message))
    if current_tag and current_tag not in live_tags:
        added_ok, added_message = phantom.add_tags(container=container, tags=[current_tag])
        if not added_ok:
            phantom.error("Could not add verdict tag {}: {}".format(current_tag, added_message))
    # proofpoint_trap_orchestrator runs this playbook on every automation trigger
    # of the container (ingest, each Event Info Update), after detail and
    # attachments have written their artifacts, and it re-applies the
    # severity each time: new artifacts arrive at SOAR's default severity
    # (medium) and raise a lower container severity. The note records the
    # severity derived from TRAP, so it is written the first time and then only
    # when that value differs from the one in the latest note.
    note_title = "TRAP Triage - Severity"
    last_noted = None
    try:
        latest = phantom.requests.get(
            uri=phantom.build_phantom_rest_url("note"),
            params={"_filter_container": container.get("id"), "_filter_title": '"{}"'.format(note_title),
                    "sort": "id", "order": "desc", "page_size": 1},
            verify=False,
        ).json().get("data") or []
        first_line = ((latest[0].get("content") or "") if latest else "").split("\n", 1)[0]
        if "-> `" in first_line:
            last_noted = first_line.split("-> `", 1)[1].split("`", 1)[0]
    except Exception as e:
        phantom.debug("Could not read the latest severity note: {}".format(str(e)))
    if last_noted != mapped_severity:
        phantom.add_note(
            container=container,
            note_type="general",
            title=note_title,
            content="**Severity: `{}` -> `{}`**\n\n{}\n\nTRAP incident ID: {}\n\nTRAP Severity: Critical -> high, High -> medium, Informational -> low, anything else -> low.\n\nCLEAR verdict: Malicious -> high; Suspicious, False Negative, Unknown / Needs Manual Review (or no sub-disposition) -> medium; Unknown / Likely Harmless, Bulk, Spam, Low Risk, Known Good -> low.".format(
                previous_severity, mapped_severity, reason, read_incident_id__incident_id
            ),
            note_format="markdown"
        )
    else:
        phantom.debug("Severity {} already noted -- re-applied (container had {}), no new note".format(
            mapped_severity, previous_severity))

    # Also saved as run data, so a consumer never depends on how the VPE names it.
    phantom.save_run_data(key="read_incident_id:incident_id", value=json.dumps(read_incident_id__incident_id))

    ################################################################################
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_block_result(key="read_incident_id__inputs:0:extract_incident_id:custom_function_result.data.incident_id", value=json.dumps(extract_incident_id_data_incident_id))
    phantom.save_block_result(key="read_incident_id__inputs:1:extract_incident_id:custom_function_result.data.trap_severity", value=json.dumps(extract_incident_id_data_trap_severity))

    phantom.save_block_result(key="read_incident_id:incident_id", value=json.dumps(read_incident_id__incident_id))

    phantom.save_block_result(key="read_incident_id_called", value="True")

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


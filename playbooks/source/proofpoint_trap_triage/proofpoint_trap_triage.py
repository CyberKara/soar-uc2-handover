"""
Automation playbook (PB3), left inactive: proofpoint_trap_orchestrator runs it after proofpoint_trap_attachments, once every artifact is written. Sets the case severity from TRAP&#39;s severity and CLEAR verdict, keeps one verdict tag, and writes the severity note in place.
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
    # Read the TRAP incident ID and severity (shared custom function).
    ################################################################################

    parameters = [{}]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="local/proofpoint_trap_extract_incident_id", parameters=parameters, name="extract_incident_id", callback=compute_verdict)

    return


@phantom.playbook_block()
def compute_verdict(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("compute_verdict() called")

    ################################################################################
    # Compute the severity, the case's tag list and the severity note; no writes.
    ################################################################################

    compute_verdict__severity = None
    compute_verdict__input_json = None
    compute_verdict__note_title = None
    compute_verdict__note_content = None

    ################################################################################
    ## Custom Code Start
    ################################################################################
    ################################################################################

    rows = phantom.collect2(container=container, datapath=[
        "extract_incident_id:custom_function_result.data.incident_id",
        "extract_incident_id:custom_function_result.data.trap_severity"])
    incident_id, trap_severity = rows[0] if rows else (None, None)
    if not incident_id:
        phantom.error("Could not find Incident ID (cef.incidentId) on the 'Event Info' artifact")
        phantom.add_note(container=container, note_type="general", title="TRAP Triage - Error",
                         content="Could not find Incident ID on the 'Event Info' artifact")
        return

    # TRAP Severity sets one severity, the CLEAR verdict (Abuse Disposition +
    # Sub Disposition) of the latest Event Info / Event Info Update another; the
    # case gets the higher, so the verdict can raise a case, never lower it. A
    # sub-disposition exists only under Unknown.
    severity_map = {"Critical": "high", "High": "medium", "Informational": "low"}
    trap_mapped = severity_map.get(trap_severity, "low")
    disposition_map = {"Malicious": "high", "Suspicious": "medium", "False Negative": "medium", "Unknown": "medium",
                       "Bulk": "low", "Spam": "low", "Low Risk": "low", "Known Good": "low"}
    sub_disposition_map = {"Needs Manual Review": "medium", "Likely Harmless": "low"}
    info_rows = phantom.collect2(container=container, datapath=[
        "artifact:*.name", "artifact:*.id", "artifact:*.cef.abuseDisposition", "artifact:*.cef.subDisposition"], scope="all")
    info_rows = sorted([row for row in info_rows or [] if row and row[0] in ("Event Info", "Event Info Update")],
                       key=lambda row: row[1] or 0)
    disposition = str(info_rows[-1][2] or "").strip() if info_rows else ""
    sub_disposition = str(info_rows[-1][3] or "").strip() if info_rows else ""
    if disposition == "Unknown" and sub_disposition in sub_disposition_map:
        disposition_mapped = sub_disposition_map[sub_disposition]
    else:
        disposition_mapped = disposition_map.get(disposition)
    verdict = " / ".join(v for v in (disposition, sub_disposition) if v)
    rank = {"low": 1, "medium": 2, "high": 3}
    severity = disposition_mapped if disposition_mapped and rank[disposition_mapped] > rank[trap_mapped] else trap_mapped

    if trap_severity in severity_map:
        reason = "TRAP Severity `{}` maps to SOAR `{}`.".format(trap_severity, trap_mapped)
    else:
        reason = ("TRAP Severity `{}` is not in the mapping (Critical, High, Informational), "
                  "so it counts as `low`.".format(trap_severity))
    if disposition_mapped:
        reason += " CLEAR verdict `{}` maps to `{}`; the higher of the two applies.".format(verdict, disposition_mapped)
    else:
        reason += " CLEAR verdict `{}` is not in the mapping, so TRAP Severity alone applies.".format(verdict or "none")

    # One verdict tag, "trap-<words>", so analysts can filter the queue on it:
    # the sub-disposition under Unknown, else the disposition. The tag list
    # sent is the case's own minus old verdict tags plus the current one, so a
    # tag an analyst set is kept; it goes as input_json, which can also send
    # an empty list and keeps a tag's spaces.
    def _verdict_tag(value):
        return "trap-" + "-".join(str(value).lower().split())

    verdict_tags = {_verdict_tag(v) for v in list(disposition_map) + list(sub_disposition_map)}
    tag_value = sub_disposition if (disposition == "Unknown" and sub_disposition) else disposition
    current_tag = _verdict_tag(tag_value) if tag_value else None
    tags_ok, tags_message, live_tags = phantom.get_tags(container=container)
    if not tags_ok:
        phantom.debug("Could not read the container's tags: {}".format(tags_message))
    tags = [t for t in (live_tags or []) if t not in verdict_tags or t == current_tag]
    if current_tag and current_tag not in tags:
        tags.append(current_tag)

    # Re-applied on every run (new artifacts arrive at medium and raise a lower
    # severity); the note holds only the result, so it changes only with it.
    compute_verdict__severity = severity
    compute_verdict__input_json = json.dumps({"tags": tags})
    compute_verdict__note_title = "TRAP Triage - Severity"
    compute_verdict__note_content = "**Severity: `{}`**\n\n{}\n\nTRAP incident ID: {}".format(severity, reason, incident_id)
    for key, value in (("severity", compute_verdict__severity), ("input_json", compute_verdict__input_json),
                       ("note_title", compute_verdict__note_title), ("note_content", compute_verdict__note_content)):
        phantom.save_run_data(key="compute_verdict:" + key, value=json.dumps(value))

    ################################################################################
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_block_result(key="compute_verdict:severity", value=json.dumps(compute_verdict__severity))
    phantom.save_block_result(key="compute_verdict:input_json", value=json.dumps(compute_verdict__input_json))
    phantom.save_block_result(key="compute_verdict:note_title", value=json.dumps(compute_verdict__note_title))
    phantom.save_block_result(key="compute_verdict:note_content", value=json.dumps(compute_verdict__note_content))

    phantom.save_block_result(key="compute_verdict_called", value="True")

    update_case(container=container)

    return


@phantom.playbook_block()
def update_case(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("update_case() called")

    ################################################################################
    # Set the severity and the full tag list in one step (shared custom function).
    ################################################################################

    id_value = container.get("id", None)
    compute_verdict__severity = json.loads(_ if (_ := phantom.get_run_data(key="compute_verdict:severity")) != "" else "null")  # pylint: disable=used-before-assignment
    compute_verdict__input_json = json.loads(_ if (_ := phantom.get_run_data(key="compute_verdict:input_json")) != "" else "null")  # pylint: disable=used-before-assignment

    parameters = []

    parameters.append({
        "name": None,
        "tags": None,
        "label": None,
        "owner": None,
        "status": None,
        "severity": compute_verdict__severity,
        "input_json": compute_verdict__input_json,
        "description": None,
        "sensitivity": None,
        "container_input": id_value,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="local/container_update", parameters=parameters, name="update_case", callback=severity_note)

    return


@phantom.playbook_block()
def severity_note(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("severity_note() called")

    ################################################################################
    # Write the severity note, updated in place (shared custom function).
    ################################################################################

    id_value = container.get("id", None)
    compute_verdict__note_title = json.loads(_ if (_ := phantom.get_run_data(key="compute_verdict:note_title")) != "" else "null")  # pylint: disable=used-before-assignment
    compute_verdict__note_content = json.loads(_ if (_ := phantom.get_run_data(key="compute_verdict:note_content")) != "" else "null")  # pylint: disable=used-before-assignment

    parameters = []

    parameters.append({
        "title": compute_verdict__note_title,
        "content": compute_verdict__note_content,
        "container_id": id_value,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="local/proofpoint_trap_note_upsert", parameters=parameters, name="severity_note")

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

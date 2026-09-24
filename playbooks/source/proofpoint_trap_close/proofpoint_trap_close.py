"""
Proofpoint TRAP Close (PB5)

Data playbook manually launched by an analyst from the container whenever
they're ready to close out the incident. Prompts for a closure reason, then
closes the TRAP incident and posts the closing comment. Independent of
proofpoint_trap_triage/proofpoint_trap_acknowledge — no chaining.

Trigger: Manual run by analyst
"""


import phantom.rules as phantom
import json
from datetime import datetime


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    extract_incident_id(container=container)

    return


@phantom.playbook_block()
def extract_incident_id(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("extract_incident_id() called")

    ################################################################################
    # Calls the shared proofpoint_trap_extract_incident_id custom function
    # (playbooks/proofpoint_trap/custom_functions/) instead of re-parsing
    # cef.incidentId inline -- this exact block used to be duplicated
    # near-verbatim across PB2/PB4/PB5 (see next-steps.md #58). The CF itself
    # reads the "Event Info"/"Event Info Update" artifacts via a direct REST
    # scan (see its own docstring for why not phantom.collect2() -- custom
    # functions get no container object to pass it).
    ################################################################################

    parameters = [{}]

    phantom.custom_function(custom_function="local/proofpoint_trap_extract_incident_id", parameters=parameters, name="extract_incident_id", callback=read_incident_id)

    return


@phantom.playbook_block()
def read_incident_id(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("read_incident_id() called")

    ################################################################################
    # Bridge block reading extract_incident_id's CF result (same pattern as
    # cyberark_rotation_orchestrator.py's discover_targets -> read_discover_result
    # pair -- a native utility block's own output needs a following code block
    # to branch/save on it).
    ################################################################################

    read_incident_id__incident_id = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    result_rows = phantom.collect2(
        container=container,
        datapath=["extract_incident_id:custom_function_result.data.incident_id"],
    )
    incident_id_val = result_rows[0][0] if result_rows else None

    if not incident_id_val:
        phantom.error("Could not find Incident ID (cef.incidentId) on the 'Event Info' artifact")
        phantom.add_note(
            container=container,
            note_type="general",
            title="TRAP Close - Error",
            content="Could not find Incident ID on the 'Event Info' artifact"
        )
        return

    read_incident_id__incident_id = str(incident_id_val)
    phantom.debug("Extracted incident ID: {}".format(read_incident_id__incident_id))

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="read_incident_id:incident_id", value=json.dumps(read_incident_id__incident_id))

    prompt_close_reason(container=container)

    return


@phantom.playbook_block()
def prompt_close_reason(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("prompt_close_reason() called")

    ################################################################################
    # Native prompt block — asks the analyst for a closure reason.
    # Approver: container_owner, falls back to soar_local_admin (same
    # fallback pattern used elsewhere in UC2 — TRAP containers never get an
    # owner assigned). Timeout: 30 min.
    ################################################################################

    user = container.get('owner_name', None) or 'soar_local_admin'
    role = None
    message = """**TRAP Incident {0}**
Container: {1}

Closing this incident will close it in Proofpoint TRAP and post your
closure reason as a comment. Provide a closure reason."""

    parameters = [
        "read_incident_id:custom_function:incident_id",
        "container:name",
    ]

    response_types = [
        {
            "prompt": "Closure reason",
            "options": {
                "type": "message",
                "required": True,
            },
        },
    ]

    phantom.prompt2(container=container, user=user, role=role, message=message, respond_in_mins=30, name="prompt_close_reason", parameters=parameters, response_types=response_types, callback=process_close_reason)

    return


@phantom.playbook_block()
def process_close_reason(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("process_close_reason() called")

    ################################################################################
    # Read analyst's prompt response via REST /rest/approval — not
    # phantom.collect2(), which is confirmed broken for this classification
    # on this SOAR 8.5 instance (see proofpoint_trap_triage.py's dated
    # comment on the same bug).
    ################################################################################

    process_close_reason__reason = None
    process_close_reason__prompt_status = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    run_id = phantom.get_playbook_run_id_()

    reason = "No reason provided"
    prompt_status = "expired"

    try:
        approval_url = phantom.build_phantom_rest_url("approval") + \
            "?_filter_playbook_run={}&_filter_name=\"prompt_close_reason\"&sort=id&order=desc&page_size=1".format(run_id)
        approvals = phantom.requests.get(uri=approval_url, verify=False).json().get("data") or []
    except Exception as e:
        phantom.error("Could not fetch approval record for playbook_run {}: {}".format(run_id, str(e)))
        approvals = []

    if approvals:
        approval = approvals[0]
        responses = approval.get("responses") or []
        if approval.get("status") == "approved" and responses and responses[0]:
            reason = responses[0]
            prompt_status = "success"
        else:
            phantom.debug("Approval status '{}' for playbook_run {} -- treating as expired/no response".format(approval.get("status"), run_id))
    else:
        phantom.error("No approval record found for playbook_run {}".format(run_id))

    phantom.debug("Closure reason: '{}', status: {}".format(reason, prompt_status))

    process_close_reason__reason = reason
    process_close_reason__prompt_status = prompt_status

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="process_close_reason:reason", value=json.dumps(process_close_reason__reason))
    phantom.save_run_data(key="process_close_reason:prompt_status", value=json.dumps(prompt_status))

    check_prompt_status(container=container)

    return


@phantom.playbook_block()
def check_prompt_status(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("check_prompt_status() called")

    ################################################################################
    # Native decision block — routes on process_close_reason's prompt_status
    # output variable instead of branching in Python (constraints.md decision
    # tree: "Branch on a condition? -> decision", not code). Replaces the old
    # if/else that lived inside process_close_reason itself (see next-steps.md
    # #58's PB5 finding).
    ################################################################################

    prompt_succeeded = phantom.decision(
        container=container,
        conditions=[
            ["process_close_reason:custom_function:prompt_status", "==", "success"]
        ])

    if prompt_succeeded:
        close_trap_incident(action=action, success=success, container=container, results=results, handle=handle)
        return

    add_close_note(action=action, success=success, container=container, results=results, handle=handle)

    return


@phantom.playbook_block()
def close_trap_incident(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("close_trap_incident() called")

    ################################################################################
    # Native action block — closes the incident in Proofpoint TRAP.
    ################################################################################

    read_incident_id__incident_id = json.loads(phantom.get_run_data(key="read_incident_id:incident_id"))
    reason = json.loads(phantom.get_run_data(key="process_close_reason:reason") or '""')

    parameters = [{
        "incident_id": read_incident_id__incident_id,
        "summary": "Closed by SOAR analyst",
        "detail": reason,
    }]

    phantom.act("close incident", parameters=parameters, name="close_trap_incident", assets=["proofpoint_trap_mock"], callback=add_trap_comment)

    return


@phantom.playbook_block()
def add_trap_comment(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("add_trap_comment() called")

    ################################################################################
    # Native action block — adds the closure comment to the TRAP incident.
    ################################################################################

    read_incident_id__incident_id = json.loads(phantom.get_run_data(key="read_incident_id:incident_id"))
    reason = json.loads(phantom.get_run_data(key="process_close_reason:reason") or '""')

    close_data = phantom.collect2(container=container, datapath=["close_trap_incident:action_result.status"])
    close_status = close_data[0][0] if close_data and close_data[0][0] else "unknown"

    if close_status == "success":
        comment_text = "Incident closed by SOAR analyst.\nReason: {}\nClose status: {}".format(reason, close_status)
    else:
        comment_text = "SOAR analyst attempted to close this incident but close_incident did not succeed (status: {}).\nReason: {}".format(close_status, reason)

    phantom.save_run_data(key="add_trap_comment:comment_text", value=json.dumps(comment_text))

    parameters = [{
        "incident_id": read_incident_id__incident_id,
        "summary": "SOAR Closure Comment",
        "detail": comment_text,
    }]

    phantom.act("add comment", parameters=parameters, name="add_trap_comment", assets=["proofpoint_trap_mock"], callback=add_close_note)

    return


@phantom.playbook_block()
def add_close_note(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("add_close_note() called")

    ################################################################################
    # Add a summary note with the closure reason and action results, and set
    # the SOAR container status to closed once the TRAP close succeeds.
    ################################################################################

    ################################################################################
    ## Custom Code Start
    ################################################################################

    incident_id = json.loads(phantom.get_run_data(key="read_incident_id:incident_id"))
    reason = json.loads(phantom.get_run_data(key="process_close_reason:reason") or '""')
    prompt_status = json.loads(phantom.get_run_data(key="process_close_reason:prompt_status") or '""')

    note_lines = [
        "# TRAP Closure",
        "**Incident ID:** {}".format(incident_id),
        "**Reason:** {}".format(reason),
        "**Prompt status:** {}".format(prompt_status),
        "**Time:** {}".format(datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
    ]

    if prompt_status == "success":
        close_data = phantom.collect2(container=container, datapath=["close_trap_incident:action_result.status"])
        close_status = close_data[0][0] if close_data and close_data[0][0] else "not run"

        comment_data = phantom.collect2(container=container, datapath=["add_trap_comment:action_result.status"])
        comment_status = comment_data[0][0] if comment_data and comment_data[0][0] else "not run"

        note_lines.append("")
        note_lines.append("## TRAP Actions")
        note_lines.append("**close_incident:** {}".format(close_status))
        note_lines.append("**add_comment:** {}".format(comment_status))

        if close_status == "success":
            phantom.set_status(container=container, status="closed")
            note_lines.append("")
            note_lines.append("Container status set to **closed**.")
    else:
        note_lines.append("")
        note_lines.append("Analyst prompt expired without response. No TRAP action taken.")

    note_content = "\n".join(note_lines)

    phantom.add_note(
        container=container,
        note_type="general",
        title="TRAP Close - {}".format(datetime.now().strftime("%Y-%m-%d %H:%M")),
        content=note_content
    )

    phantom.debug("Close note added")

    ################################################################################
    ## Custom Code End
    ################################################################################

    return


def on_finish(container, summary):
    phantom.debug("on_finish() called")
    return

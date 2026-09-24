"""
Proofpoint TRAP Acknowledge (PB4)

Data playbook manually launched by an analyst from the container, once
they've reviewed the artifacts/enrichment notes PB1-PB3 produced. Prompts
for a comment, then writes three things to the real TRAP incident: the
comment, an assignee marking it claimed by SOAR, and a status change from
new to open. Independent of proofpoint_trap_triage/proofpoint_trap_close —
no chaining.

Trigger: Manual run by analyst
"""


import phantom.rules as phantom
import json
from datetime import datetime


ACK_ASSIGNEE = "SOAR"
ACK_FALLBACK_COMMENT = "Acknowledged by SOAR"


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
            title="TRAP Acknowledge - Error",
            content="Could not find Incident ID on the 'Event Info' artifact"
        )
        return

    read_incident_id__incident_id = str(incident_id_val)
    phantom.debug("Extracted incident ID: {}".format(read_incident_id__incident_id))

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="read_incident_id:incident_id", value=json.dumps(read_incident_id__incident_id))

    prompt_comment(container=container)

    return


@phantom.playbook_block()
def prompt_comment(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("prompt_comment() called")

    ################################################################################
    # Native prompt block — asks the analyst for an acknowledgement comment.
    # Approver: container_owner, falls back to soar_local_admin (same
    # fallback pattern as the old prompt_analyst block — TRAP containers
    # never get an owner assigned). Timeout: 30 min.
    ################################################################################

    user = container.get('owner_name', None) or 'soar_local_admin'
    role = None
    message = """**TRAP Incident {0}**
Container: {1}

Acknowledging this incident will add your comment to the TRAP incident,
assign it to SOAR, and move its status from new to open."""

    parameters = [
        "read_incident_id:custom_function:incident_id",
        "container:name",
    ]

    response_types = [
        {
            "prompt": "Comment",
            "options": {
                "type": "message",
                "required": True,
            },
        },
    ]

    phantom.prompt2(container=container, user=user, role=role, message=message, respond_in_mins=30, name="prompt_comment", parameters=parameters, response_types=response_types, callback=process_comment)

    return


@phantom.playbook_block()
def process_comment(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("process_comment() called")

    ################################################################################
    # Read analyst's prompt response via REST /rest/approval — not
    # phantom.collect2(), which is confirmed broken for this classification
    # on this SOAR 8.5 instance (see proofpoint_trap_triage.py's dated
    # comment on the same bug, and process_decision's original fix).
    ################################################################################

    process_comment__comment = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    run_id = phantom.get_playbook_run_id_()

    comment = ACK_FALLBACK_COMMENT
    prompt_status = "expired"

    try:
        approval_url = phantom.build_phantom_rest_url("approval") + \
            "?_filter_playbook_run={}&_filter_name=\"prompt_comment\"&sort=id&order=desc&page_size=1".format(run_id)
        approvals = phantom.requests.get(uri=approval_url, verify=False).json().get("data") or []
    except Exception as e:
        phantom.error("Could not fetch approval record for playbook_run {}: {}".format(run_id, str(e)))
        approvals = []

    if approvals:
        approval = approvals[0]
        responses = approval.get("responses") or []
        if approval.get("status") == "approved" and responses and responses[0]:
            comment = responses[0]
            prompt_status = "success"
        else:
            phantom.debug("Approval status '{}' for playbook_run {} -- treating as expired/no response".format(approval.get("status"), run_id))
    else:
        phantom.error("No approval record found for playbook_run {}".format(run_id))

    phantom.debug("Analyst comment: '{}', status: {}".format(comment, prompt_status))

    process_comment__comment = comment

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="process_comment:comment", value=json.dumps(process_comment__comment))
    phantom.save_run_data(key="process_comment:prompt_status", value=json.dumps(prompt_status))

    update_incident_assignee(container=container)

    return


@phantom.playbook_block()
def update_incident_assignee(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("update_incident_assignee() called")

    ################################################################################
    # Native action block — assigns the TRAP incident to SOAR.
    ################################################################################

    read_incident_id__incident_id = json.loads(phantom.get_run_data(key="read_incident_id:incident_id"))

    parameters = [{
        "incident_id": read_incident_id__incident_id,
        "assignee": ACK_ASSIGNEE,
    }]

    phantom.act("update team and assignee", parameters=parameters, name="update_incident_assignee", assets=["proofpoint_trap_mock"], callback=set_incident_open)

    return


@phantom.playbook_block()
def set_incident_open(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("set_incident_open() called")

    ################################################################################
    # Native action block — moves the TRAP incident status from new to open.
    ################################################################################

    read_incident_id__incident_id = json.loads(phantom.get_run_data(key="read_incident_id:incident_id"))

    parameters = [{
        "incident_id": read_incident_id__incident_id,
        "field": "status",
        "value": "open",
    }]

    phantom.act("set incident field value", parameters=parameters, name="set_incident_open", assets=["proofpoint_trap_mock"], callback=add_trap_comment)

    return


@phantom.playbook_block()
def add_trap_comment(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("add_trap_comment() called")

    ################################################################################
    # Native action block — adds the analyst's (or fallback) comment to the
    # TRAP incident.
    ################################################################################

    read_incident_id__incident_id = json.loads(phantom.get_run_data(key="read_incident_id:incident_id"))
    comment = json.loads(phantom.get_run_data(key="process_comment:comment") or '""')

    parameters = [{
        "incident_id": read_incident_id__incident_id,
        "summary": "SOAR Acknowledgement",
        "detail": comment,
    }]

    phantom.act("add comment", parameters=parameters, name="add_trap_comment", assets=["proofpoint_trap_mock"], callback=add_ack_note)

    return


@phantom.playbook_block()
def add_ack_note(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("add_ack_note() called")

    ################################################################################
    # Add a summary note with the acknowledgement comment and action results.
    ################################################################################

    ################################################################################
    ## Custom Code Start
    ################################################################################

    incident_id = json.loads(phantom.get_run_data(key="read_incident_id:incident_id"))
    comment = json.loads(phantom.get_run_data(key="process_comment:comment") or '""')
    prompt_status = json.loads(phantom.get_run_data(key="process_comment:prompt_status") or '""')

    assignee_data = phantom.collect2(container=container, datapath=["update_incident_assignee:action_result.status"])
    assignee_status = assignee_data[0][0] if assignee_data and assignee_data[0][0] else "not run"

    status_data = phantom.collect2(container=container, datapath=["set_incident_open:action_result.status"])
    status_status = status_data[0][0] if status_data and status_data[0][0] else "not run"

    comment_data = phantom.collect2(container=container, datapath=["add_trap_comment:action_result.status"])
    comment_status = comment_data[0][0] if comment_data and comment_data[0][0] else "not run"

    note_lines = [
        "# TRAP Acknowledgement",
        "**Incident ID:** {}".format(incident_id),
        "**Comment:** {}".format(comment),
        "**Prompt status:** {}".format(prompt_status),
        "**Time:** {}".format(datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
        "",
        "## TRAP Actions",
        "**update_incident_assignee:** {}".format(assignee_status),
        "**set_incident_open:** {}".format(status_status),
        "**add_comment:** {}".format(comment_status),
    ]

    note_content = "\n".join(note_lines)

    phantom.add_note(
        container=container,
        note_type="general",
        title="TRAP Acknowledge - {}".format(datetime.now().strftime("%Y-%m-%d %H:%M")),
        content=note_content
    )

    phantom.debug("Acknowledge note added")

    ################################################################################
    ## Custom Code End
    ################################################################################

    return


def on_finish(container, summary):
    phantom.debug("on_finish() called")
    return

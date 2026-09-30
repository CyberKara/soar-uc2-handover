"""
Data playbook (PB4) manually launched by an analyst from the container once they&#39;ve reviewed the artifacts/notes PB1-PB3 produced. Prompts for a comment, then assigns the TRAP incident to SOAR, moves its status from new to open, and posts the comment. Independent of proofpoint_trap_triage/proofpoint_trap_close.
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


################################################################################
## Global Custom Code Start
################################################################################



# Manual playbook: once the analyst has reviewed the enrichment, prompts for a comment, then writes it to the
# TRAP incident together with an assignee marking it claimed by SOAR and the status change new -> open.
# Independent of proofpoint_trap_triage and proofpoint_trap_close: no chaining.

ACK_ASSIGNEE = "SOAR"
ACK_FALLBACK_COMMENT = "Acknowledged by SOAR"
################################################################################
## Global Custom Code End
################################################################################

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
def prompt_comment(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("prompt_comment() called")

    ################################################################################
    # Ask the analyst for an acknowledgement comment (approver: container owner, else 
    # soar_local_admin).
    ################################################################################

    playbook_input_approver = phantom.collect2(container=container, datapath=["playbook_input:approver"])
    playbook_input_respond_in_mins = phantom.collect2(container=container, datapath=["playbook_input:respond_in_mins"])

    playbook_input_approver_values = [item[0] for item in playbook_input_approver]
    playbook_input_respond_in_mins_values = [item[0] for item in playbook_input_respond_in_mins]

    ################################################################################
    ## Custom Code Start
    ################################################################################
    ################################################################################

    # The prompt is raised from code, not from a native prompt block: a VPE save
    # regenerates prompt blocks whole (they have no Custom Code), which would drop
    # this approver fallback -- TRAP containers never get an owner assigned. The
    # callback continues the flow; the return below stops the generated call to
    # process_comment from also running right away.

    # Playbook inputs (optional): approver replaces the owner fallback and
    # respond_in_mins the 30-minute timeout.
    approver = next((v for v in playbook_input_approver_values if v not in (None, "")), None)
    user = str(approver).strip() if approver else (container.get('owner_name', None) or 'soar_local_admin')
    respond_in_mins = 30
    raw_minutes = next((v for v in playbook_input_respond_in_mins_values if v not in (None, "")), None)
    if raw_minutes is not None:
        try:
            respond_in_mins = max(1, int(str(raw_minutes).strip()))
        except ValueError:
            phantom.debug("Ignoring respond_in_mins input {!r}: not a whole number".format(raw_minutes))
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

    phantom.prompt2(container=container, user=user, role=role, message=message, respond_in_mins=respond_in_mins, name="prompt_comment", parameters=parameters, response_types=response_types, callback=process_comment)

    return

    ################################################################################
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_block_result(key="prompt_comment_called", value="True")

    process_comment(container=container)

    return


@phantom.playbook_block()
def process_comment(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("process_comment() called")

    ################################################################################
    # Read analyst's prompt response.
    ################################################################################

    process_comment__comment = None

    ################################################################################
    ## Custom Code Start
    ################################################################################
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

    # Also saved as run data: the action blocks and the note read these keys.
    phantom.save_run_data(key="process_comment:comment", value=json.dumps(process_comment__comment))
    phantom.save_run_data(key="process_comment:prompt_status", value=json.dumps(prompt_status))

    ################################################################################
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_block_result(key="process_comment:comment", value=json.dumps(process_comment__comment))

    phantom.save_block_result(key="process_comment_called", value="True")

    update_incident_assignee(container=container)

    return


@phantom.playbook_block()
def update_incident_assignee(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("update_incident_assignee() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Assign the TRAP incident to SOAR.
    ################################################################################

    read_incident_id__incident_id = json.loads(_ if (_ := phantom.get_run_data(key="read_incident_id:incident_id")) != "" else "null")  # pylint: disable=used-before-assignment

    parameters = []

    if read_incident_id__incident_id is not None:
        parameters.append({
            "assignee": "SOAR",
            "incident_id": read_incident_id__incident_id,
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################
    ################################################################################

    # Built from run data, so the call does not depend on how the VPE names its
    # generated variables. Sends assignee only -- the connector requires team as
    # well, a known bug that stays on hold until the TRAP web-UI reassignment test.
    read_incident_id__incident_id = json.loads(phantom.get_run_data(key="read_incident_id:incident_id") or "null")

    parameters = [{
        "incident_id": read_incident_id__incident_id,
        "assignee": ACK_ASSIGNEE,
    }]

    ################################################################################
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("update team and assignee", parameters=parameters, name="update_incident_assignee", assets=["proofpoint_trap_mock"], callback=set_incident_open)

    return


@phantom.playbook_block()
def set_incident_open(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("set_incident_open() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Move the TRAP incident status from new to open.
    ################################################################################

    read_incident_id__incident_id = json.loads(_ if (_ := phantom.get_run_data(key="read_incident_id:incident_id")) != "" else "null")  # pylint: disable=used-before-assignment

    parameters = []

    if read_incident_id__incident_id is not None:
        parameters.append({
            "field": "status",
            "value": "open",
            "incident_id": read_incident_id__incident_id,
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################
    ################################################################################

    # Built from run data, so the call does not depend on how the VPE names its
    # generated variables.
    read_incident_id__incident_id = json.loads(phantom.get_run_data(key="read_incident_id:incident_id") or "null")

    parameters = [{
        "incident_id": read_incident_id__incident_id,
        "field": "status",
        "value": "open",
    }]

    ################################################################################
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("set incident field value", parameters=parameters, name="set_incident_open", assets=["proofpoint_trap_mock"], callback=add_trap_comment)

    return


@phantom.playbook_block()
def add_trap_comment(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_trap_comment() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Add the analyst's acknowledgement comment to the TRAP incident.
    ################################################################################

    process_comment__comment = json.loads(_ if (_ := phantom.get_run_data(key="process_comment:comment")) != "" else "null")  # pylint: disable=used-before-assignment
    read_incident_id__incident_id = json.loads(_ if (_ := phantom.get_run_data(key="read_incident_id:incident_id")) != "" else "null")  # pylint: disable=used-before-assignment

    parameters = []

    if read_incident_id__incident_id is not None:
        parameters.append({
            "detail": process_comment__comment,
            "summary": "SOAR Acknowledgement",
            "incident_id": read_incident_id__incident_id,
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################
    ################################################################################

    # Built from run data, so the call does not depend on how the VPE names its
    # generated variables.
    read_incident_id__incident_id = json.loads(phantom.get_run_data(key="read_incident_id:incident_id") or "null")
    comment = json.loads(phantom.get_run_data(key="process_comment:comment") or '""')

    parameters = [{
        "incident_id": read_incident_id__incident_id,
        "summary": "SOAR Acknowledgement",
        "detail": comment,
    }]

    ################################################################################
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("add comment", parameters=parameters, name="add_trap_comment", assets=["proofpoint_trap_mock"], callback=add_ack_note)

    return


@phantom.playbook_block()
def add_ack_note(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_ack_note() called")

    ################################################################################
    # Add acknowledgement summary note to container.
    ################################################################################

    update_incident_assignee_result_data = phantom.collect2(container=container, datapath=["update_incident_assignee:action_result.status"], action_results=results)
    set_incident_open_result_data = phantom.collect2(container=container, datapath=["set_incident_open:action_result.status"], action_results=results)
    add_trap_comment_result_data = phantom.collect2(container=container, datapath=["add_trap_comment:action_result.status"], action_results=results)
    process_comment__comment = json.loads(_ if (_ := phantom.get_run_data(key="process_comment:comment")) != "" else "null")  # pylint: disable=used-before-assignment

    update_incident_assignee_result_item_0 = [item[0] for item in update_incident_assignee_result_data]
    set_incident_open_result_item_0 = [item[0] for item in set_incident_open_result_data]
    add_trap_comment_result_item_0 = [item[0] for item in add_trap_comment_result_data]

    ################################################################################
    ## Custom Code Start
    ################################################################################
    ################################################################################

    incident_id = json.loads(phantom.get_run_data(key="read_incident_id:incident_id"))
    comment = json.loads(phantom.get_run_data(key="process_comment:comment") or '""')
    prompt_status = json.loads(phantom.get_run_data(key="process_comment:prompt_status") or '""')

    # All three actions are dispatched unconditionally above, so a missing
    # action_result does NOT mean the step was skipped: when SOAR refuses to
    # dispatch (a manifest-required parameter missing, the case of this
    # playbook's own assignee+team bug) no app_run is created at all and
    # collect2 finds nothing, while the playbook run records the attempt as
    # failed. Report that as a failure with where to read the reason, never as
    # "not run".
    NO_RESULT = "failed - not dispatched (reason in the playbook run's actions)"

    assignee_data = phantom.collect2(container=container, datapath=["update_incident_assignee:action_result.status"])
    assignee_status = assignee_data[0][0] if assignee_data and assignee_data[0][0] else NO_RESULT

    status_data = phantom.collect2(container=container, datapath=["set_incident_open:action_result.status"])
    status_status = status_data[0][0] if status_data and status_data[0][0] else NO_RESULT

    comment_data = phantom.collect2(container=container, datapath=["add_trap_comment:action_result.status"])
    comment_status = comment_data[0][0] if comment_data and comment_data[0][0] else NO_RESULT

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
        content=note_content,
        note_format="markdown",  # the content is markdown; add_note() defaults to html
    )

    phantom.debug("Acknowledge note added")

    # Playbook outputs, read by on_finish: success when all three TRAP actions
    # succeeded, partial when some did, failed when none did.
    trap_results = [assignee_status, status_status, comment_status]
    succeeded = trap_results.count("success")
    playbook_output = {
        "status": "success" if succeeded == len(trap_results) else ("partial" if succeeded else "failed"),
        "incident_id": incident_id,
        "comment": comment,
    }
    phantom.save_run_data(key="playbook_output", value=json.dumps(playbook_output))

    ################################################################################
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_block_result(key="add_ack_note__inputs:0:process_comment:custom_function:comment", value=json.dumps(process_comment__comment))
    phantom.save_block_result(key="add_ack_note__inputs:1:update_incident_assignee:action_result.status", value=json.dumps(update_incident_assignee_result_item_0))
    phantom.save_block_result(key="add_ack_note__inputs:2:set_incident_open:action_result.status", value=json.dumps(set_incident_open_result_item_0))
    phantom.save_block_result(key="add_ack_note__inputs:3:add_trap_comment:action_result.status", value=json.dumps(add_trap_comment_result_item_0))

    phantom.save_block_result(key="add_ack_note_called", value="True")

    return


@phantom.playbook_block()
def read_incident_id(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("read_incident_id() called")

    ################################################################################
    # Bridge block: read extract_incident_id CF result (same pattern as cyberark_rotation_orchestrator.py 
    # read_discover_result).
    ################################################################################

    extract_incident_id__result = phantom.collect2(container=container, datapath=["extract_incident_id:custom_function_result.data.incident_id"])

    extract_incident_id_data_incident_id = [item[0] for item in extract_incident_id__result]

    read_incident_id__incident_id = None

    ################################################################################
    ## Custom Code Start
    ################################################################################
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

    # Also saved as run data: later blocks read this key in their own Custom Code.
    phantom.save_run_data(key="read_incident_id:incident_id", value=json.dumps(read_incident_id__incident_id))

    ################################################################################
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_block_result(key="read_incident_id__inputs:0:extract_incident_id:custom_function_result.data.incident_id", value=json.dumps(extract_incident_id_data_incident_id))

    phantom.save_block_result(key="read_incident_id:incident_id", value=json.dumps(read_incident_id__incident_id))

    phantom.save_block_result(key="read_incident_id_called", value="True")

    prompt_comment(container=container)

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")

    output = {
        "status": None,
        "incident_id": None,
        "comment": None,
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


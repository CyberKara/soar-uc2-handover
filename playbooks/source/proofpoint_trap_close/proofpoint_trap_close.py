"""
Data playbook (PB5), run by an analyst. Prompts for a closure reason, then closes the TRAP incident and posts the reason as a comment.
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

    phantom.custom_function(custom_function="local/proofpoint_trap_extract_incident_id", parameters=parameters, name="extract_incident_id", callback=read_incident_id)

    return


@phantom.playbook_block()
def prompt_close_reason(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("prompt_close_reason() called")

    ################################################################################
    # Ask the analyst for a closure reason (approver: container owner, else soar_local_admin).
    ################################################################################

    playbook_input_approver = phantom.collect2(container=container, datapath=["playbook_input:approver"])
    playbook_input_respond_in_mins = phantom.collect2(container=container, datapath=["playbook_input:respond_in_mins"])

    playbook_input_approver_values = [item[0] for item in playbook_input_approver]
    playbook_input_respond_in_mins_values = [item[0] for item in playbook_input_respond_in_mins]

    ################################################################################
    ## Custom Code Start
    ################################################################################
    ################################################################################
    ################################################################################

    # The prompt is raised from code, not from a native prompt block: a VPE save
    # regenerates prompt blocks whole (they have no Custom Code), which would drop
    # this approver fallback -- TRAP containers never get an owner assigned. The
    # callback continues the flow; the return below stops the generated call to
    # process_close_reason from also running right away.

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

    phantom.prompt2(container=container, user=user, role=role, message=message, respond_in_mins=respond_in_mins, name="prompt_close_reason", parameters=parameters, response_types=response_types, callback=process_close_reason)

    return

    ################################################################################
    ################################################################################
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_block_result(key="prompt_close_reason__inputs:0:playbook_input:approver", value=json.dumps(playbook_input_approver_values))
    phantom.save_block_result(key="prompt_close_reason__inputs:1:playbook_input:respond_in_mins", value=json.dumps(playbook_input_respond_in_mins_values))

    phantom.save_block_result(key="prompt_close_reason_called", value="True")

    process_close_reason(container=container)

    return


@phantom.playbook_block()
def process_close_reason(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("process_close_reason() called")

    ################################################################################
    # Read analyst's prompt response.
    ################################################################################

    process_close_reason__reason = None
    process_close_reason__prompt_status = None

    ################################################################################
    ## Custom Code Start
    ################################################################################
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

    # Also saved as run data: the blocks after the decision read these keys.
    phantom.save_run_data(key="process_close_reason:reason", value=json.dumps(process_close_reason__reason))
    phantom.save_run_data(key="process_close_reason:prompt_status", value=json.dumps(process_close_reason__prompt_status))

    ################################################################################
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_block_result(key="process_close_reason:reason", value=json.dumps(process_close_reason__reason))
    phantom.save_block_result(key="process_close_reason:prompt_status", value=json.dumps(process_close_reason__prompt_status))

    phantom.save_block_result(key="process_close_reason_called", value="True")

    check_prompt_status(container=container)

    return


@phantom.playbook_block()
def close_trap_incident(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("close_trap_incident() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Run close_incident action on Proofpoint TRAP.
    ################################################################################

    process_close_reason__reason = json.loads(_ if (_ := phantom.get_run_data(key="process_close_reason:reason")) != "" else "null")  # pylint: disable=used-before-assignment
    read_incident_id__incident_id = json.loads(_ if (_ := phantom.get_run_data(key="read_incident_id:incident_id")) != "" else "null")  # pylint: disable=used-before-assignment

    parameters = []

    if process_close_reason__reason is not None and read_incident_id__incident_id is not None:
        parameters.append({
            "detail": process_close_reason__reason,
            "summary": "Closed by SOAR analyst",
            "incident_id": read_incident_id__incident_id,
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################
    ################################################################################

    # Built from run data, so the call does not depend on how the VPE names its
    # generated variables.
    read_incident_id__incident_id = json.loads(phantom.get_run_data(key="read_incident_id:incident_id") or "null")
    reason = json.loads(phantom.get_run_data(key="process_close_reason:reason") or '""')

    parameters = [{
        "incident_id": read_incident_id__incident_id,
        "summary": "Closed by SOAR analyst",
        "detail": reason,
    }]

    ################################################################################
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("close incident", parameters=parameters, name="close_trap_incident", assets=["proofpoint_trap_mock"], callback=add_trap_comment)

    return


@phantom.playbook_block()
def add_trap_comment(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_trap_comment() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Add closure comment to TRAP incident.
    ################################################################################

    process_close_reason__reason = json.loads(_ if (_ := phantom.get_run_data(key="process_close_reason:reason")) != "" else "null")  # pylint: disable=used-before-assignment
    read_incident_id__incident_id = json.loads(_ if (_ := phantom.get_run_data(key="read_incident_id:incident_id")) != "" else "null")  # pylint: disable=used-before-assignment

    parameters = []

    if read_incident_id__incident_id is not None:
        parameters.append({
            "detail": process_close_reason__reason,
            "summary": "SOAR Closure Comment",
            "incident_id": read_incident_id__incident_id,
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################
    ################################################################################

    # The comment says whether the TRAP close succeeded, so it is built here from
    # close_trap_incident's result rather than bound directly.
    read_incident_id__incident_id = json.loads(phantom.get_run_data(key="read_incident_id:incident_id") or "null")
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

    ################################################################################
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("add comment", parameters=parameters, name="add_trap_comment", assets=["proofpoint_trap_mock"], callback=add_close_note)

    return


@phantom.playbook_block()
def add_close_note(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_close_note() called")

    ################################################################################
    # Add closure summary note to container.
    ################################################################################

    close_trap_incident_result_data = phantom.collect2(container=container, datapath=["close_trap_incident:action_result.status"], action_results=results)
    add_trap_comment_result_data = phantom.collect2(container=container, datapath=["add_trap_comment:action_result.status"], action_results=results)
    process_close_reason__reason = json.loads(_ if (_ := phantom.get_run_data(key="process_close_reason:reason")) != "" else "null")  # pylint: disable=used-before-assignment

    close_trap_incident_result_item_0 = [item[0] for item in close_trap_incident_result_data]
    add_trap_comment_result_item_0 = [item[0] for item in add_trap_comment_result_data]

    ################################################################################
    ## Custom Code Start
    ################################################################################
    ################################################################################
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
        # Both actions were dispatched on this branch, so a missing
        # action_result is a failure, not a skipped step: when SOAR refuses to
        # dispatch an action (a manifest-required parameter missing) no app_run
        # is created and collect2 finds nothing, while the playbook run records
        # the attempt as failed.
        NO_RESULT = "failed - not dispatched (reason in the playbook run's actions)"

        close_data = phantom.collect2(container=container, datapath=["close_trap_incident:action_result.status"])
        close_status = close_data[0][0] if close_data and close_data[0][0] else NO_RESULT

        comment_data = phantom.collect2(container=container, datapath=["add_trap_comment:action_result.status"])
        comment_status = comment_data[0][0] if comment_data and comment_data[0][0] else NO_RESULT

        note_lines.append("")
        note_lines.append("## TRAP Actions")
        note_lines.append("**close_incident:** {}".format(close_status))
        note_lines.append("**add_comment:** {}".format(comment_status))

        if close_status == "success":
            phantom.set_status(container=container, status="closed")
            note_lines.append("")
            note_lines.append("Container status set to **closed**.")

        succeeded = [close_status, comment_status].count("success")
        outcome = "success" if succeeded == 2 else ("partial" if succeeded else "failed")
    else:
        note_lines.append("")
        note_lines.append("Analyst prompt expired without response. No TRAP action taken.")
        outcome = "expired"

    note_content = "\n".join(note_lines)

    phantom.add_note(
        container=container,
        note_type="general",
        title="TRAP Close - {}".format(datetime.now().strftime("%Y-%m-%d %H:%M")),
        content=note_content,
        note_format="markdown",  # the content is markdown; add_note() defaults to html
    )

    phantom.debug("Close note added")

    # Playbook outputs, read by on_finish.
    playbook_output = {"status": outcome, "incident_id": incident_id, "reason": reason}
    phantom.save_run_data(key="playbook_output", value=json.dumps(playbook_output))

    ################################################################################
    ################################################################################
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_block_result(key="add_close_note__inputs:0:process_close_reason:custom_function:reason", value=json.dumps(process_close_reason__reason))
    phantom.save_block_result(key="add_close_note__inputs:1:close_trap_incident:action_result.status", value=json.dumps(close_trap_incident_result_item_0))
    phantom.save_block_result(key="add_close_note__inputs:2:add_trap_comment:action_result.status", value=json.dumps(add_trap_comment_result_item_0))

    phantom.save_block_result(key="add_close_note_called", value="True")

    return


@phantom.playbook_block()
def read_incident_id(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("read_incident_id() called")

    ################################################################################
    # Read the incident ID from the custom function result.
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
            title="TRAP Close - Error",
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

    prompt_close_reason(container=container)

    return


@phantom.playbook_block()
def check_prompt_status(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("check_prompt_status() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["process_close_reason:custom_function:prompt_status", "==", "success"]
        ],
        conditions_dps=[
            ["process_close_reason:custom_function:prompt_status", "==", "success"]
        ],
        name="check_prompt_status:condition_1",
        delimiter=",")

    # call connected blocks if condition 1 matched
    if found_match_1:
        close_trap_incident(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    add_expired_note(action=action, success=success, container=container, results=results, handle=handle)

    return


@phantom.playbook_block()
def add_expired_note(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_expired_note() called")

    ################################################################################
    # Add a closure note when the prompt got no approval: no TRAP action taken.
    ################################################################################

    ################################################################################
    ## Custom Code Start
    ################################################################################
    ################################################################################
    ################################################################################


    # The prompt got no approval (expired or rejected): no TRAP action ran.
    # Its own block, not a second input into add_close_note: the 8.6 VPE
    # regenerates a join over two inputs that waits for BOTH paths, ignoring
    # notRequiredJoins, so this path would end without a note after a save.
    incident_id = json.loads(phantom.get_run_data(key="read_incident_id:incident_id"))
    reason = json.loads(phantom.get_run_data(key="process_close_reason:reason") or '""')
    prompt_status = json.loads(phantom.get_run_data(key="process_close_reason:prompt_status") or '""')

    note_lines = [
        "# TRAP Closure",
        "**Incident ID:** {}".format(incident_id),
        "**Reason:** {}".format(reason),
        "**Prompt status:** {}".format(prompt_status),
        "**Time:** {}".format(datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
        "",
        "Analyst prompt expired without response. No TRAP action taken.",
    ]

    phantom.add_note(
        container=container,
        note_type="general",
        title="TRAP Close - {}".format(datetime.now().strftime("%Y-%m-%d %H:%M")),
        content="\n".join(note_lines),
        note_format="markdown",  # the content is markdown; add_note() defaults to html
    )

    phantom.debug("Expired-prompt note added")

    # Playbook outputs, read by on_finish.
    playbook_output = {"status": "expired", "incident_id": incident_id, "reason": reason}
    phantom.save_run_data(key="playbook_output", value=json.dumps(playbook_output))

    ################################################################################
    ################################################################################
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_block_result(key="add_expired_note_called", value="True")

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")

    output = {
        "status": [],
        "incident_id": [],
        "reason": [],
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################
    ################################################################################
    ################################################################################

    # Populate the generated `output` dict; the save after Custom Code End emits it.
    # No block recorded an outcome (e.g. the run stopped early): report failed.
    raw_output = phantom.get_run_data(key="playbook_output")
    if raw_output:
        output.update(json.loads(raw_output))
    # The 8.6 VPE initialises every output above to [] (8.5 wrote None), so an
    # output no block set is normalised to null here, whichever form a save wrote.
    for key, value in output.items():
        if value == []:
            output[key] = None
    if output["status"] is None:
        output["status"] = "failed"

    ################################################################################
    ################################################################################
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_playbook_output_data(output=output)

    return


"""
Automation playbook (PB8), kept inactive: an analyst runs it from the case with Run Playbook. Asks the analyst who launched it for a close reason, closes the TRAP incident with it, adds a close note and closes the case once TRAP has closed the incident. An unanswered prompt does nothing.
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
    # Read the TRAP incident ID (shared custom function).
    ################################################################################

    parameters = [{}]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="local/proofpoint_trap_extract_incident_id", parameters=parameters, name="extract_incident_id", callback=prompt_close_reason)

    return


@phantom.playbook_block()
def prompt_close_reason(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("prompt_close_reason() called")

    ################################################################################
    # Ask the analyst who launched the playbook for the close reason (30 minutes).
    ################################################################################

    # set approver and message variables for phantom.prompt call

    user = phantom.collect2(container=container, datapath=["playbook:launching_user.name"])[0][0]
    role = None
    message = """**TRAP incident {0}**\n\nYour reason closes this incident in TRAP and is posted as its close detail; the case is closed once TRAP has closed it."""

    # parameter list for template variable replacement
    parameters = [
        "extract_incident_id:custom_function_result.data.incident_id"
    ]

    # responses
    response_types = [
        {
            "prompt": "Close reason",
            "options": {
                "type": "message",
                "required": True,
            },
        }
    ]

    phantom.prompt2(container=container, user=user, role=role, message=message, respond_in_mins=30, name="prompt_close_reason", parameters=parameters, response_types=response_types, callback=approved)

    return


@phantom.playbook_block()
def approved(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("approved() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["prompt_close_reason:action_result.status", "==", "success"]
        ],
        conditions_dps=[
            ["prompt_close_reason:action_result.status", "==", "success"]
        ],
        name="approved:condition_1",
        delimiter=",")

    # call connected blocks if condition 1 matched
    if found_match_1:
        close_trap_incident(action=action, success=success, container=container, results=results, handle=handle)
        return

    return


@phantom.playbook_block()
def close_trap_incident(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("close_trap_incident() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Close the TRAP incident; the reason goes as its detail (TRAP requires summary 
    # and detail).
    ################################################################################

    prompt_close_reason_result_data = phantom.collect2(container=container, datapath=["prompt_close_reason:action_result.summary.responses.0","prompt_close_reason:action_result.parameter.context.artifact_id"], action_results=results)
    extract_incident_id__result = phantom.collect2(container=container, datapath=["extract_incident_id:custom_function_result.data.incident_id"])

    parameters = []

    # build parameters list for 'close_trap_incident' call
    for prompt_close_reason_result_item in prompt_close_reason_result_data:
        for extract_incident_id__result_item in extract_incident_id__result:
            if prompt_close_reason_result_item[0] is not None and extract_incident_id__result_item[0] is not None:
                parameters.append({
                    "detail": prompt_close_reason_result_item[0],
                    "summary": "Closed by SOAR analyst",
                    "incident_id": extract_incident_id__result_item[0],
                    "context": {'artifact_id': prompt_close_reason_result_item[1]},
                })

    ################################################################################
    ## Custom Code Start
    ################################################################################
    ################################################################################

    # One close, built from the custom function and the prompt's answer.
    incident = phantom.collect2(container=container, datapath=["extract_incident_id:custom_function_result.data.incident_id"])
    answer = phantom.collect2(container=container, datapath=["prompt_close_reason:action_result.summary.responses.0"])
    parameters = [{
        "incident_id": incident[0][0] if incident and incident[0] else None,
        "summary": "Closed by SOAR analyst",
        "detail": answer[0][0] if answer and answer[0] else "",
    }]

    ################################################################################
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("close incident", parameters=parameters, name="close_trap_incident", assets=["proofpoint_trap_mock"], callback=add_note)

    return


@phantom.playbook_block()
def add_note(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_note() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Add the close note: the reason and TRAP's result.
    ################################################################################

    id_value = container.get("id", None)

    parameters = []

    parameters.append({
        "title": "TRAP Close",
        "container_id": id_value,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################
    ################################################################################

    # A missing action result is a failure, not a skipped step: SOAR refusing to
    # dispatch creates no app_run, and the playbook run records it as failed.
    answer = phantom.collect2(container=container, datapath=["prompt_close_reason:action_result.summary.responses.0"])
    closed = phantom.collect2(container=container, datapath=["close_trap_incident:action_result.status"])
    incident = phantom.collect2(container=container, datapath=["extract_incident_id:custom_function_result.data.incident_id"])
    status = closed[0][0] if closed and closed[0] and closed[0][0] else "failed - not dispatched (reason in the playbook run's actions)"
    lines = ["# TRAP Closure",
             "**Incident ID:** {}".format(incident[0][0] if incident and incident[0] else "?"),
             "**Reason:** {}".format(answer[0][0] if answer and answer[0] else ""),
             "**TRAP close incident:** {}".format(status),
             "**Case:** {}".format("closed" if status == "success" else "left open")]
    parameters = [{"title": "TRAP Close", "content": "\n".join(lines), "container_id": container.get("id")}]

    ################################################################################
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("add note", parameters=parameters, name="add_note", assets=["soar8"], callback=trap_closed)

    return


@phantom.playbook_block()
def trap_closed(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("trap_closed() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["close_trap_incident:action_result.status", "==", "success"]
        ],
        conditions_dps=[
            ["close_trap_incident:action_result.status", "==", "success"]
        ],
        name="trap_closed:condition_1",
        delimiter=",")

    # call connected blocks if condition 1 matched
    if found_match_1:
        set_status(action=action, success=success, container=container, results=results, handle=handle)
        return

    return


@phantom.playbook_block()
def set_status(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("set_status() called")

    ################################################################################
    # Close the case.
    ################################################################################

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.set_status(container=container, status="closed")

    container = phantom.get_container(container.get('id', None))

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

"""
Automation playbook (PB7), kept inactive: an analyst runs it from the case with Run Playbook. Asks the analyst who launched it for a comment, then assigns the TRAP incident to the team and assignee set in the format blocks trap team and trap assignee, moves it from new to open, posts the comment and adds a note. An unanswered prompt does nothing.
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

    phantom.custom_function(custom_function="local/proofpoint_trap_extract_incident_id", parameters=parameters, name="extract_incident_id", callback=prompt_comment)

    return


@phantom.playbook_block()
def prompt_comment(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("prompt_comment() called")

    ################################################################################
    # Ask the analyst who launched the playbook for an acknowledgement comment (6 
    # hours).
    ################################################################################

    # set approver and message variables for phantom.prompt call

    user = phantom.collect2(container=container, datapath=["playbook:launching_user.name"])[0][0]
    role = None
    message = """**TRAP incident {0}**\n\nYour comment is posted on the TRAP incident, which is assigned to the SOAR team and moved from new to open."""

    # parameter list for template variable replacement
    parameters = [
        "extract_incident_id:custom_function_result.data.incident_id"
    ]

    # responses
    response_types = [
        {
            "prompt": "Comment",
            "options": {
                "type": "message",
                "required": True,
            },
        }
    ]

    phantom.prompt2(container=container, user=user, role=role, message=message, respond_in_mins=360, name="prompt_comment", parameters=parameters, response_types=response_types, callback=answered)

    return


@phantom.playbook_block()
def answered(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("answered() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["prompt_comment:action_result.status", "==", "success"]
        ],
        conditions_dps=[
            ["prompt_comment:action_result.status", "==", "success"]
        ],
        name="answered:condition_1",
        delimiter=",")

    # call connected blocks if condition 1 matched
    if found_match_1:
        trap_team(action=action, success=success, container=container, results=results, handle=handle)
        return

    return


@phantom.playbook_block()
def update_incident_assignee(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("update_incident_assignee() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Assign the TRAP incident to the team and assignee set in the two format blocks.
    ################################################################################

    extract_incident_id__result = phantom.collect2(container=container, datapath=["extract_incident_id:custom_function_result.data.incident_id"])
    trap_team = phantom.get_format_data(name="trap_team")
    trap_assignee = phantom.get_format_data(name="trap_assignee")

    parameters = []

    # build parameters list for 'update_incident_assignee' call
    for extract_incident_id__result_item in extract_incident_id__result:
        if extract_incident_id__result_item[0] is not None:
            parameters.append({
                "team": trap_team,
                "assignee": trap_assignee,
                "incident_id": extract_incident_id__result_item[0],
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

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
    # Move the TRAP incident from new to open.
    ################################################################################

    extract_incident_id__result = phantom.collect2(container=container, datapath=["extract_incident_id:custom_function_result.data.incident_id"])

    parameters = []

    # build parameters list for 'set_incident_open' call
    for extract_incident_id__result_item in extract_incident_id__result:
        if extract_incident_id__result_item[0] is not None:
            parameters.append({
                "field": "status",
                "value": "open",
                "incident_id": extract_incident_id__result_item[0],
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

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
    # Post the analyst's comment on the TRAP incident.
    ################################################################################

    prompt_comment_result_data = phantom.collect2(container=container, datapath=["prompt_comment:action_result.summary.responses.0","prompt_comment:action_result.parameter.context.artifact_id"], action_results=results)
    extract_incident_id__result = phantom.collect2(container=container, datapath=["extract_incident_id:custom_function_result.data.incident_id"])

    parameters = []

    # build parameters list for 'add_trap_comment' call
    for prompt_comment_result_item in prompt_comment_result_data:
        for extract_incident_id__result_item in extract_incident_id__result:
            if extract_incident_id__result_item[0] is not None:
                parameters.append({
                    "detail": prompt_comment_result_item[0],
                    "summary": "SOAR Acknowledgement",
                    "incident_id": extract_incident_id__result_item[0],
                    "context": {'artifact_id': prompt_comment_result_item[1]},
                })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("add comment", parameters=parameters, name="add_trap_comment", assets=["proofpoint_trap_mock"], callback=add_note)

    return


@phantom.playbook_block()
def add_note(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_note() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Add the acknowledgement note: the comment and TRAP's results.
    ################################################################################

    id_value = container.get("id", None)

    parameters = []

    parameters.append({
        "title": "TRAP Acknowledge",
        "container_id": id_value,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################
    ################################################################################

    # A missing action result is a failure, not a skipped step: SOAR refusing to
    # dispatch creates no app_run, and the playbook run records it as failed.
    def _status(block):
        rows = phantom.collect2(container=container, datapath=["{}:action_result.status".format(block)])
        return rows[0][0] if rows and rows[0] and rows[0][0] else "failed - not dispatched (reason in the playbook run's actions)"

    answer = phantom.collect2(container=container, datapath=["prompt_comment:action_result.summary.responses.0"])
    incident = phantom.collect2(container=container, datapath=["extract_incident_id:custom_function_result.data.incident_id"])
    lines = ["# TRAP Acknowledgement",
             "**Incident ID:** {}".format(incident[0][0] if incident and incident[0] else "?"),
             "**Comment:** {}".format(answer[0][0] if answer and answer[0] else ""),
             "**TRAP team and assignee:** {}".format(_status("update_incident_assignee")),
             "**TRAP set open:** {}".format(_status("set_incident_open")),
             "**TRAP add comment:** {}".format(_status("add_trap_comment"))]
    parameters = [{"title": "TRAP Acknowledge", "content": "\n".join(lines), "container_id": container.get("id")}]

    ################################################################################
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("add note", parameters=parameters, name="add_note", assets=["soar8"])

    return


@phantom.playbook_block()
def trap_team(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("trap_team() called")

    ################################################################################
    # TRAP team the incident is assigned to: set your own (a team that exists in TRAP).
    ################################################################################

    template = """SOAR"""

    # parameter list for template variable replacement
    parameters = []

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="trap_team")

    trap_assignee(container=container)

    return


@phantom.playbook_block()
def trap_assignee(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("trap_assignee() called")

    ################################################################################
    # TRAP user the incident is assigned to: set your own (a user of that team in 
    # TRAP).
    ################################################################################

    template = """SOAR"""

    # parameter list for template variable replacement
    parameters = []

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="trap_assignee")

    update_incident_assignee(container=container)

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

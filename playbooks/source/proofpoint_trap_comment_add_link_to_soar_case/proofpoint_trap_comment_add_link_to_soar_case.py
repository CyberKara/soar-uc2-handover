"""
Automation playbook (PB6), left inactive: proofpoint_trap_orchestrator runs it last. Comments on the TRAP incident with a link to this SOAR case, once: TRAP Run State&#39;s linkComment records it, and a failed comment is retried on the next run.
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

    phantom.custom_function(custom_function="local/proofpoint_trap_extract_incident_id", parameters=parameters, name="extract_incident_id", callback=run_state)

    return


@phantom.playbook_block()
def run_state(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("run_state() called")

    ################################################################################
    # Keep only the TRAP Run State artifact.
    ################################################################################

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.name", "==", "TRAP Run State"]
        ],
        conditions_dps=[
            ["artifact:*.name", "==", "TRAP Run State"]
        ],
        name="run_state:condition_1",
        scope="all",
        delimiter=",")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        not_posted(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def not_posted(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("not_posted() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["filtered-data:run_state:condition_1:artifact:*.cef.linkComment", "!=", "posted"]
        ],
        conditions_dps=[
            ["filtered-data:run_state:condition_1:artifact:*.cef.linkComment", "!=", "posted"]
        ],
        name="not_posted:condition_1",
        scope="all",
        delimiter=",")

    # call connected blocks if condition 1 matched
    if found_match_1:
        add_comment(action=action, success=success, container=container, results=results, handle=handle)
        return

    return


@phantom.playbook_block()
def add_comment(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_comment() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Comment on the TRAP incident with a link to this SOAR case.
    ################################################################################

    extract_incident_id__result = phantom.collect2(container=container, datapath=["extract_incident_id:custom_function_result.data.incident_id"])

    parameters = []

    # build parameters list for 'add_comment' call
    for extract_incident_id__result_item in extract_incident_id__result:
        if extract_incident_id__result_item[0] is not None:
            parameters.append({
                "summary": "Extracted by SOAR automation",
                "incident_id": extract_incident_id__result_item[0],
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################
    ################################################################################

    # The link is SOAR's configured base URL (Administration > Company Settings)
    # plus /mission/<container id>, the case page. TRAP needs detail even though
    # its API doc marks it optional: a comment without it fails "Null detail".
    base_url = (phantom.get_base_url() or "").rstrip("/")
    case_link = "{}/mission/{}".format(base_url, container.get("id")) if base_url else "case {}".format(container.get("id"))
    for params in parameters:
        params["detail"] = "This incident has been extracted by SOAR automation, please review it in SOAR: {}".format(case_link)

    ################################################################################
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("add comment", parameters=parameters, name="add_comment", assets=["proofpoint_trap_mock"], callback=comment_ok)

    return


@phantom.playbook_block()
def comment_ok(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("comment_ok() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["add_comment:action_result.status", "==", "success"]
        ],
        conditions_dps=[
            ["add_comment:action_result.status", "==", "success"]
        ],
        name="comment_ok:condition_1",
        delimiter=",")

    # call connected blocks if condition 1 matched
    if found_match_1:
        update_state(action=action, success=success, container=container, results=results, handle=handle)
        return

    return


@phantom.playbook_block()
def update_state(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("update_state() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Record the posted comment on TRAP Run State (linkComment = posted).
    ################################################################################

    filtered_artifact_0_data_run_state = phantom.collect2(container=container, datapath=["filtered-data:run_state:condition_1:artifact:*.id","filtered-data:run_state:condition_1:artifact:*.id"], scope="all")

    parameters = []

    # build parameters list for 'update_state' call
    for filtered_artifact_0_item_run_state in filtered_artifact_0_data_run_state:
        if filtered_artifact_0_item_run_state[0] is not None:
            parameters.append({
                "severity": "low",
                "artifact_id": filtered_artifact_0_item_run_state[0],
                "context": {'artifact_id': filtered_artifact_0_item_run_state[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################
    ################################################################################

    # Severity low: an update re-applies the artifact's severity to the case.
    for params in parameters:
        params["cef_json"] = json.dumps({"linkComment": "posted"})

    ################################################################################
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("update artifact", parameters=parameters, name="update_state", assets=["soar8"])

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

"""
Automation playbook for label proofpoint_trap, the only UC2 playbook started at ingest and on each Event Info Update from proofpoint_trap_recheck. Runs proofpoint_trap_detail, proofpoint_trap_attachments, proofpoint_trap_triage and proofpoint_trap_summary one after another, each waiting for the previous one to finish, so the attachments are extracted from the emails detail has just downloaded, the severity is applied after the last artifact is written, and the summary sees everything. Those four playbooks stay inactive: this playbook calls them.
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'run_detail' block
    run_detail(container=container)

    return

@phantom.playbook_block()
def run_detail(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("run_detail() called")

    ################################################################################
    # Fetch the TRAP incident, download its emails and create the event artifacts, the detail note and Enrichment Complete.
    ################################################################################

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "local/proofpoint_trap_detail", returns the playbook_run_id
    playbook_run_id = phantom.playbook("local/proofpoint_trap_detail", container=container, name="run_detail", callback=run_attachments)

    return


@phantom.playbook_block()
def run_attachments(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("run_attachments() called")

    ################################################################################
    # Extract attachments, Cc recipients and the Email Content note from each email detail downloaded.
    ################################################################################

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "local/proofpoint_trap_attachments", returns the playbook_run_id
    playbook_run_id = phantom.playbook("local/proofpoint_trap_attachments", container=container, name="run_attachments", callback=run_triage)

    return


@phantom.playbook_block()
def run_triage(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("run_triage() called")

    ################################################################################
    # Set the container severity from TRAP, after every artifact has been written.
    ################################################################################

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "local/proofpoint_trap_triage", returns the playbook_run_id
    playbook_run_id = phantom.playbook("local/proofpoint_trap_triage", container=container, name="run_triage", callback=run_summary)

    return


@phantom.playbook_block()
def run_summary(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("run_summary() called")

    ################################################################################
    # Write or rewrite the TRAP Summary note from every artifact on the container.
    ################################################################################

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "local/proofpoint_trap_summary", returns the playbook_run_id
    playbook_run_id = phantom.playbook("local/proofpoint_trap_summary", container=container, name="run_summary", callback=run_summary_callback)

    return


@phantom.playbook_block()
def run_summary_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("run_summary_callback() called")

    
    # Downstream End block cannot be called directly, since execution will call on_finish automatically.
    # Using placeholder callback function so child playbook is run synchronously.


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


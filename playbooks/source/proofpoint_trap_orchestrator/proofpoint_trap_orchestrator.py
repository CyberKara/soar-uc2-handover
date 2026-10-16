"""
Automation playbook for label proofpoint_trap, the only UC2 playbook active at ingest. Runs proofpoint_trap_detail, proofpoint_trap_attachments, proofpoint_trap_triage, proofpoint_trap_summary and proofpoint_trap_comment_add_link_to_soar_case in turn, each after the previous one finishes; those five stay inactive.
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
    # Fetch the TRAP incident, create the incident-level artifacts, Enrichment Complete 
    # and the detail note.
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
    # Download each new alert's email: attachments, Cc, the Email Content and Attachment 
    # Extraction notes.
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
    # Set the case severity and verdict tag, after every artifact has been written.
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
    # Write the TRAP Summary in place.
    ################################################################################

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "local/proofpoint_trap_summary", returns the playbook_run_id
    playbook_run_id = phantom.playbook("local/proofpoint_trap_summary", container=container, name="run_summary", callback=run_comment_link)

    return


@phantom.playbook_block()
def run_comment_link(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("run_comment_link() called")

    ################################################################################
    # Comment on the TRAP incident with a link to this case, once.
    ################################################################################

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "local/proofpoint_trap_comment_add_link_to_soar_case", returns the playbook_run_id
    playbook_run_id = phantom.playbook("local/proofpoint_trap_comment_add_link_to_soar_case", container=container, name="run_comment_link", callback=run_comment_link_callback)

    return


@phantom.playbook_block()
def run_comment_link_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("run_comment_link_callback() called")

    
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

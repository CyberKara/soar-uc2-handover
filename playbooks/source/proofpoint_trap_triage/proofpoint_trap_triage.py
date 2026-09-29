"""
Automation playbook (PB2) triggered on container creation. Reads the TRAP incident ID and raw TRAP Severity off the Event Info artifact and promotes the container&#39;s severity from TRAP&#39;s own Severity (the connector creates the container at a neutral default). No writes back to TRAP. Analyst-driven actions (acknowledge, close) live in separate manually-launched playbooks: proofpoint_trap_acknowledge, proofpoint_trap_close.
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
def read_incident_id(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("read_incident_id() called")

    ################################################################################
    # Bridge block: read extract_incident_id CF result (incident_id + trap_severity) 
    # and promote container severity.
    ################################################################################

    extract_incident_id__result = phantom.collect2(container=container, datapath=["extract_incident_id:custom_function_result.data.incident_id","extract_incident_id:custom_function_result.data.trap_severity"])

    extract_incident_id_data_incident_id = [item[0] for item in extract_incident_id__result]
    extract_incident_id_data_trap_severity = [item[1] for item in extract_incident_id__result]

    read_incident_id__incident_id = None

    ################################################################################
    ## Custom Code Start
    ################################################################################
    ################################################################################


    result_rows = phantom.collect2(
        container=container,
        datapath=["extract_incident_id:custom_function_result.data.incident_id", "extract_incident_id:custom_function_result.data.trap_severity"],
    )
    incident_id_val, trap_severity = result_rows[0] if result_rows else (None, None)

    if not incident_id_val:
        phantom.error("Could not find Incident ID (cef.incidentId) on the 'Event Info' artifact")
        phantom.add_note(
            container=container,
            note_type="general",
            title="TRAP Triage - Error",
            content="Could not find Incident ID on the 'Event Info' artifact"
        )
        return

    read_incident_id__incident_id = str(incident_id_val)
    phantom.debug("Extracted incident ID: {}".format(read_incident_id__incident_id))

    severity_map = {"Critical": "high", "High": "medium", "Informational": "low"}
    previous_severity = container.get("severity")
    mapped_severity = severity_map.get(trap_severity, "low")
    phantom.set_severity(container=container, severity=mapped_severity)
    phantom.debug(
        "Promoted container severity to '{}' (TRAP Severity: '{}')".format(
            mapped_severity, trap_severity
        )
    )

    if trap_severity in severity_map:
        reason = "TRAP Severity `{}` maps to SOAR `{}`.".format(trap_severity, mapped_severity)
    else:
        reason = (
            "TRAP Severity `{}` is not in the mapping (Critical, High, Informational), "
            "so the default `low` was applied.".format(trap_severity)
        )
    # This playbook runs on every automation trigger of the container (ingest,
    # each Enrichment Complete, each Event Info Update) and re-applies the
    # severity each time: new artifacts arrive at SOAR's default severity
    # (medium) and raise a lower container severity. The note records the
    # severity derived from TRAP, so it is written the first time and then only
    # when that value differs from the one in the latest note.
    note_title = "TRAP Triage - Severity"
    last_noted = None
    try:
        latest = phantom.requests.get(
            uri=phantom.build_phantom_rest_url("note"),
            params={"_filter_container": container.get("id"), "_filter_title": '"{}"'.format(note_title),
                    "sort": "id", "order": "desc", "page_size": 1},
            verify=False,
        ).json().get("data") or []
        first_line = ((latest[0].get("content") or "") if latest else "").split("\n", 1)[0]
        if "-> `" in first_line:
            last_noted = first_line.split("-> `", 1)[1].split("`", 1)[0]
    except Exception as e:
        phantom.debug("Could not read the latest severity note: {}".format(str(e)))
    if last_noted != mapped_severity:
        phantom.add_note(
            container=container,
            note_type="general",
            title=note_title,
            content="**Severity: `{}` -> `{}`**\n\n{}\n\nTRAP incident ID: {}\n\nMapping: Critical -> high, High -> medium, Informational -> low, anything else -> low.".format(
                previous_severity, mapped_severity, reason, read_incident_id__incident_id
            ),
            note_format="markdown"
        )
    else:
        phantom.debug("Severity {} already noted -- re-applied (container had {}), no new note".format(
            mapped_severity, previous_severity))

    # Also saved as run data, so a consumer never depends on how the VPE names it.
    phantom.save_run_data(key="read_incident_id:incident_id", value=json.dumps(read_incident_id__incident_id))

    ################################################################################
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_block_result(key="read_incident_id__inputs:0:extract_incident_id:custom_function_result.data.incident_id", value=json.dumps(extract_incident_id_data_incident_id))
    phantom.save_block_result(key="read_incident_id__inputs:1:extract_incident_id:custom_function_result.data.trap_severity", value=json.dumps(extract_incident_id_data_trap_severity))

    phantom.save_block_result(key="read_incident_id:incident_id", value=json.dumps(read_incident_id__incident_id))

    phantom.save_block_result(key="read_incident_id_called", value="True")

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


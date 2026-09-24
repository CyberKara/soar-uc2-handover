"""
Proofpoint TRAP Triage (PB2)

Automation playbook triggered on container creation. Reads the Incident ID
and raw TRAP Severity off the "Event Info" artifact (cef.incidentId/trapSeverity, set by
the connector's on_poll) and promotes container severity from TRAP's own
Severity field via phantom.set_severity() — the connector only creates the
container at a neutral default. No writes back to TRAP. Downstream,
analyst-driven actions (acknowledge, close) live in their own separate,
manually-launched playbooks (proofpoint_trap_acknowledge,
proofpoint_trap_close).

Trigger: Automatic on container creation
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
    # cef.incidentId/trapSeverity inline -- this exact block used to be
    # duplicated near-verbatim across PB2/PB4/PB5 (see next-steps.md #58).
    # The CF itself reads the "Event Info"/"Event Info Update" artifacts via
    # a direct REST scan (see its own docstring for why not phantom.collect2()
    # -- custom functions get no container object to pass it).
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
    # to branch/save on it). Promotes container severity from TRAP's own
    # Severity field (cef.trapSeverity) -- the connector only sets a neutral
    # DEFAULT_SEVERITY at ingestion (see proofpoint_trap_connector.py
    # _handle_on_poll) -- this is where the real value lands. Mapping
    # duplicated here (small, playbook-local) since playbooks can't import
    # the connector's consts.py.
    ################################################################################

    read_incident_id__incident_id = None

    ################################################################################
    ## Custom Code Start
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
    mapped_severity = severity_map.get(trap_severity, "low")
    phantom.set_severity(container=container, severity=mapped_severity)
    phantom.debug(
        "Promoted container severity to '{}' (TRAP Severity: '{}')".format(
            mapped_severity, trap_severity
        )
    )

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="read_incident_id:incident_id", value=json.dumps(read_incident_id__incident_id))

    return


def on_finish(container, summary):
    phantom.debug("on_finish() called")
    return

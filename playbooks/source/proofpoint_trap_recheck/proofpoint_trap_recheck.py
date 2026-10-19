"""
Automation playbook (PB9) for label proofpoint_trap_recheck, run by its Timer asset. Finds ingested TRAP incidents that changed and adds an Event Info Update to their case, which runs proofpoint_trap_orchestrator again. Never closes a case and writes no note.
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


################################################################################
## Global Custom Code Start
################################################################################



import hashlib

STATE_LIST_NAME = "proofpoint_trap_recheck_state"
DEFAULT_LOOKBACK_HOURS = 168  # 7 days


def _get_field_value(incident, field_name):
    for field in incident.get("incident_field_values", []) or []:
        if field.get("name") == field_name:
            return field.get("value", "")
    return ""


def _build_event_info_cef(incident):
    # Same fields as the connector's _build_event_info_cef; keep both in sync.
    inc_id = incident.get("id", "")
    disposition = _get_field_value(incident, "Abuse Disposition")
    sub_disposition = _get_field_value(incident, "Sub Disposition")
    classification = _get_field_value(incident, "Classification")
    trap_severity = _get_field_value(incident, "Severity")
    score = incident.get("score", 0)
    message = incident.get("summary") or incident.get("description") or ""
    event_ids = ",".join(str(x) for x in (incident.get("event_ids") or []))

    return {
        "abuseDisposition": disposition,
        "classification": classification,
        "subDisposition": sub_disposition,
        "threatScore": score,
        "incidentId": str(inc_id),
        "eventIds": event_ids,
        "trapSeverity": trap_severity,
        "message": message,
    }


def _incident_signature(incident):
    state = incident.get("state", "")
    event_info = _build_event_info_cef(incident)
    payload = json.dumps({"state": state, "event_info": event_info}, sort_keys=True)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()
################################################################################
## Global Custom Code End
################################################################################

@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'list_incidents' block
    list_incidents(container=container)

    return

@phantom.playbook_block()
def list_incidents(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("list_incidents() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # List all TRAP incidents (any state) created within the lookback window.
    ################################################################################

    parameters = []

    parameters.append({
        "state": "",
        "hours_back": 168,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################
    ################################################################################

    # This pass must see open and closed incidents too. One parameter set per
    # state: SOAR drops an empty parameter, so state "" would list only the
    # connector's default (new). Several sets = one app_run, one result each.
    parameters = [
        {"state": state, "hours_back": str(DEFAULT_LOOKBACK_HOURS)}
        for state in ("new", "open", "closed")
    ]

    ################################################################################
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("list incidents", parameters=parameters, name="list_incidents", assets=["proofpoint_trap_mock"], callback=process_incidents)

    return


@phantom.playbook_block()
def process_incidents(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("process_incidents() called")

    ################################################################################
    # Find ingested incidents whose signature changed since the last tick (state in 
    # a custom list).
    ################################################################################

    process_incidents__incident_id = None

    ################################################################################
    ## Custom Code Start
    ################################################################################
    ################################################################################

    result_data = phantom.collect2(container=container, datapath=["list_incidents:action_result.status", "list_incidents:action_result.data"])
    # One action result per state listed (new, open, closed). If any failed,
    # skip the cycle: a half-listed cycle is not worth acting on.
    if not result_data or any(row[0] != "success" for row in result_data):
        phantom.error("list_incidents failed -- skipping this recheck cycle")
        return

    incidents, seen = [], set()
    for row in result_data:
        for incident in row[1] or []:
            key = str(incident.get("id", ""))
            if key and key not in seen:
                seen.add(key)
                incidents.append(incident)

    # State: proofpoint_trap_recheck_state (incident_id, signature); row 0 is the header.
    known = {}
    ok, _message, rows = phantom.get_list(list_name=STATE_LIST_NAME)
    for row in (rows or []) if ok else []:
        if row and len(row) >= 2 and row[0] != "incident_id":
            known[row[0]] = row[1]

    # An incident not seen before is recorded, not rechecked: on the first tick
    # that is the whole window, afterwards one on_poll has just ingested.
    new_state, changed = dict(known), []
    for incident in incidents:
        inc_id = str(incident.get("id", ""))
        signature = _incident_signature(incident)
        if inc_id not in known:
            new_state[inc_id] = signature
        elif known[inc_id] != signature:
            changed.append({"incident_id": inc_id, "signature": signature, "event_info_cef": _build_event_info_cef(incident)})
    phantom.debug("Recheck: {} incident(s) in the window, {} changed".format(len(incidents), len(changed)))

    process_incidents__incident_id = [item["incident_id"] for item in changed]
    phantom.save_run_data(key="process_incidents:changed", value=json.dumps(changed))
    phantom.save_run_data(key="process_incidents:new_state", value=json.dumps(new_state))
    phantom.save_run_data(key="process_incidents:incident_id", value=json.dumps(process_incidents__incident_id))

    ################################################################################
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_block_result(key="process_incidents:incident_id", value=json.dumps(process_incidents__incident_id))

    phantom.save_block_result(key="process_incidents_called", value="True")

    find_cases(container=container)

    return


@phantom.playbook_block()
def find_cases(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("find_cases() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Find the case of each changed incident by its Event Info incidentId.
    ################################################################################

    process_incidents__incident_id = json.loads(_ if (_ := phantom.get_run_data(key="process_incidents:incident_id")) != "" else "null")  # pylint: disable=used-before-assignment

    parameters = []

    if process_incidents__incident_id is not None:
        parameters.append({
            "values": process_incidents__incident_id,
            "cef_key": "incidentId",
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################
    ################################################################################

    # One search per changed incident; reads the run data, not the generated variables.
    incident_ids = json.loads(phantom.get_run_data(key="process_incidents:incident_id") or "null") or []
    parameters = [{"values": inc_id, "cef_key": "incidentId", "exact_match": True} for inc_id in incident_ids]
    if not parameters:
        build_updates(container=container)
        return

    ################################################################################
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("find artifacts", parameters=parameters, name="find_cases", assets=["soar8"], callback=build_updates)

    return


@phantom.playbook_block()
def build_updates(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("build_updates() called")

    ################################################################################
    # Build one Event Info Update per changed incident whose case is open (a closed 
    # case gets none), then save the signatures.
    ################################################################################

    build_updates__container_id = None
    build_updates__cef_dictionary = None
    build_updates__source_data_identifier = None

    ################################################################################
    ## Custom Code Start
    ################################################################################
    ################################################################################

    # The case of each incident: the container of an Event Info carrying its
    # incidentId. A changed incident with no case keeps its old signature, so
    # the change is still pending once on_poll has ingested it. Every column is
    # read from the hits themselves (matched = the incident id): collect2 lines
    # up a parameter and the hits of several results by position, not per result.
    containers = {}
    for row in phantom.collect2(container=container, datapath=[
            "find_cases:action_result.data.*.matched", "find_cases:action_result.data.*.container",
            "find_cases:action_result.data.*.name"]) or []:
        if row and row[0] and row[1] and row[2] in ("Event Info", "Event Info Update"):
            containers.setdefault(str(row[0]), row[1])

    changed = json.loads(phantom.get_run_data(key="process_incidents:changed") or "[]")
    new_state = json.loads(phantom.get_run_data(key="process_incidents:new_state") or "{}")
    tick = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    updates = []
    for item in changed:
        inc_id = item["incident_id"]
        if inc_id not in containers:
            continue
        new_state[inc_id] = item["signature"]
        # A case closed in SOAR runs no automation, so an update there would do
        # nothing but raise the closed case's severity: record the change, add none.
        case = phantom.get_container(containers[inc_id]) or {}
        if str(case.get("status") or "").lower() == "closed":
            phantom.debug("Case {} of TRAP incident {} is closed: no Event Info Update".format(containers[inc_id], inc_id))
            continue
        cef = dict(item["event_info_cef"])
        cef["message"] = "TRAP incident {} changed since last enrichment".format(inc_id)
        # The tick time makes each update new content, so an incident that
        # changes back to an earlier state still runs the orchestrator.
        cef["recheckTime"] = tick
        updates.append({"container_id": containers[inc_id], "cef": cef,
                        "source_data_identifier": "trap-{}-recheck-{}".format(inc_id, tick)})

    build_updates__container_id = [u["container_id"] for u in updates]
    build_updates__cef_dictionary = [json.dumps(u["cef"]) for u in updates]
    build_updates__source_data_identifier = [u["source_data_identifier"] for u in updates]
    for key, value in (("container_id", build_updates__container_id), ("cef_dictionary", build_updates__cef_dictionary),
                       ("source_data_identifier", build_updates__source_data_identifier)):
        phantom.save_run_data(key="build_updates:" + key, value=json.dumps(value))
    phantom.debug("{} Event Info Update(s) to create".format(len(updates)))

    # Saved now, for the updates about to be created (attempted, not verified).
    content = [["incident_id", "signature"]] + [[k, v] for k, v in sorted(new_state.items())]
    phantom.set_list(list_name=STATE_LIST_NAME, values=content)

    ################################################################################
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_block_result(key="build_updates:container_id", value=json.dumps(build_updates__container_id))
    phantom.save_block_result(key="build_updates:cef_dictionary", value=json.dumps(build_updates__cef_dictionary))
    phantom.save_block_result(key="build_updates:source_data_identifier", value=json.dumps(build_updates__source_data_identifier))

    phantom.save_block_result(key="build_updates_called", value="True")

    add_event_info_updates(container=container)

    return


@phantom.playbook_block()
def add_event_info_updates(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_event_info_updates() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Create the Event Info Update artifacts; each starts the orchestrator on its 
    # case.
    ################################################################################

    build_updates__container_id = json.loads(_ if (_ := phantom.get_run_data(key="build_updates:container_id")) != "" else "null")  # pylint: disable=used-before-assignment
    build_updates__cef_dictionary = json.loads(_ if (_ := phantom.get_run_data(key="build_updates:cef_dictionary")) != "" else "null")  # pylint: disable=used-before-assignment
    build_updates__source_data_identifier = json.loads(_ if (_ := phantom.get_run_data(key="build_updates:source_data_identifier")) != "" else "null")  # pylint: disable=used-before-assignment

    parameters = []

    if build_updates__source_data_identifier is not None:
        parameters.append({
            "name": "Event Info Update",
            "label": "event",
            "container_id": build_updates__container_id,
            "cef_dictionary": build_updates__cef_dictionary,
            "source_data_identifier": build_updates__source_data_identifier,
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################
    ################################################################################

    # One update per changed incident, on its own case; run_automation starts
    # the orchestrator there. The connector's data type for a TRAP incident id
    # lets the TRAP actions be offered on the artifact.
    containers = json.loads(phantom.get_run_data(key="build_updates:container_id") or "null") or []
    cefs = json.loads(phantom.get_run_data(key="build_updates:cef_dictionary") or "null") or []
    sdis = json.loads(phantom.get_run_data(key="build_updates:source_data_identifier") or "null") or []
    parameters = [{"name": "Event Info Update", "label": "event", "contains": json.dumps({"incidentId": ["proofpoint trap incident id"]}),
                   "determine_contains": False, "run_automation": True, "container_id": containers[i],
                   "cef_dictionary": cefs[i], "source_data_identifier": sdis[i]} for i in range(len(sdis))]
    if not parameters:
        return

    ################################################################################
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("add artifact", parameters=parameters, name="add_event_info_updates", assets=["soar8"])

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

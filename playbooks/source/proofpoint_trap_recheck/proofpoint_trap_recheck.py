"""
Automation playbook (PB7) for label proofpoint_trap_recheck, run by its Timer asset, not by TRAP incidents. Periodically re-scans the whole in-window TRAP incident backlog (all states) for already-ingested incidents that changed since ingestion -- a field edit, disposition change, or newly-linked event that on_poll&#39;s checkpoint-based main pass can&#39;t see again once a container exists.
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


################################################################################
## Global Custom Code Start
################################################################################



# Timer-driven: re-scans the whole in-window TRAP backlog (all states) for incidents that were already ingested
# but changed since (field edit, disposition change, newly linked event), which on_poll's checkpoint never revisits.
# Durable state is the custom list proofpoint_trap_recheck_state (incident_id, signature). Any detected change
# re-fetches and re-vaults all of the incident's MIME bodies; artifacts the container already carries are skipped,
# so no per-incident event tracking is needed.
# Trigger: container created on label 'proofpoint_trap_recheck' (the Timer asset).

import hashlib

STATE_LIST_NAME = "proofpoint_trap_recheck_state"
DEFAULT_LOOKBACK_HOURS = 168  # 7 days, matches the connector's old default


def _get_field_value(incident, field_name):
    for field in incident.get("incident_field_values", []) or []:
        if field.get("name") == field_name:
            return field.get("value", "")
    return ""


def _build_event_info_cef(incident):
    # Copy of proofpoint_trap_connector.py's _build_event_info_cef: keep both in sync.
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

    # state "" means every state -- this pass must see open and closed incidents
    # too, the ones the on_poll main pass no longer looks at. Built here as well
    # as in the block's bindings, so an empty value can never be dropped and
    # fall back to the action's own default ("new").
    parameters = [{
        "state": "",
        "hours_back": str(DEFAULT_LOOKBACK_HOURS),
    }]

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
    # Diff each listed incident's signature against the recheck state list; incidents 
    # that changed and already have a container go to the recheck batch.
    ################################################################################

    list_incidents_result_data = phantom.collect2(container=container, datapath=["list_incidents:action_result.status","list_incidents:action_result.data"], action_results=results)

    list_incidents_result_item_0 = [item[0] for item in list_incidents_result_data]
    list_incidents_result_item_1 = [item[1] for item in list_incidents_result_data]

    process_incidents__incident_id = None

    ################################################################################
    ## Custom Code Start
    ################################################################################
    ################################################################################


    result_data = phantom.collect2(
        container=container,
        datapath=[
            "list_incidents:action_result.status",
            "list_incidents:action_result.data",
        ]
    )

    if not result_data or result_data[0][0] != "success":
        phantom.error("list_incidents failed -- skipping this recheck cycle")
        return

    incidents = result_data[0][1] or []
    phantom.debug("Recheck cycle: {} incident(s) in window".format(len(incidents)))

    # Read prior state. Row 0 is the header ("incident_id"); skip it.
    known_signatures = {}
    read_success, _read_msg, rows = phantom.get_list(list_name=STATE_LIST_NAME)
    if read_success and rows:
        for row in rows:
            if row and len(row) >= 2 and row[0] != "incident_id":
                known_signatures[row[0]] = row[1]

    to_recheck = []  # [{incident_id, container_id, new_signature, event_info_cef}]
    new_state = dict(known_signatures)

    if not known_signatures:
        phantom.debug("No prior state -- recording signatures this cycle, nothing to recheck")

    for incident in incidents:
        inc_id = str(incident.get("id", ""))
        if not inc_id:
            continue
        sig = _incident_signature(incident)

        # An incident this playbook has not seen before is RECORDED, not
        # rechecked. On the first cycle that is the whole window -- otherwise a
        # fresh deployment re-runs proofpoint_trap_detail over the entire
        # backlog on tick one. Afterwards it is an incident on_poll has just
        # ingested, which proofpoint_trap_detail has already enriched on its
        # own trigger. Rechecks start when a known incident comes back with a
        # different signature.
        if inc_id not in known_signatures:
            new_state[inc_id] = sig
            continue

        if known_signatures[inc_id] == sig:
            continue  # unchanged since last recheck cycle -- nothing to do

        # Only incidents ALREADY ingested (have a container) are this
        # playbook's job -- first-time ingestion stays on_poll's main pass.
        # An incident with no container yet is either brand new (on_poll
        # will pick it up on its own schedule) or outside on_poll's own
        # filters entirely (not this playbook's call to override that).
        try:
            resp = phantom.requests.get(
                uri=phantom.build_phantom_rest_url("container"),
                params={"_filter_source_data_identifier": '"{}"'.format(inc_id), "page_size": 1},
                verify=False,
            ).json()
            existing = resp.get("data") or []
        except Exception as e:
            phantom.debug("Container lookup failed for incident {}: {}".format(inc_id, str(e)))
            continue

        if not existing:
            # Known incident that changed but has no container: nothing to
            # write the update onto. Leave its recorded signature alone so the
            # change is still pending the next time round, once on_poll has
            # ingested it.
            continue

        container_id = existing[0]["id"]
        to_recheck.append({
            "incident_id": inc_id,
            "container_id": container_id,
            "event_info_cef": _build_event_info_cef(incident),
        })
        new_state[inc_id] = sig

    phantom.debug("{} incident(s) changed and already have a container".format(len(to_recheck)))

    phantom.save_run_data(key="process_incidents:to_recheck", value=json.dumps(to_recheck))
    phantom.save_run_data(key="process_incidents:new_state", value=json.dumps(new_state))

    # The changed incidents' ids, also as the block's output (dispatch_mime_refetch
    # binds to it for the VPE view; its own Custom Code reads to_recheck).
    process_incidents__incident_id = [row["incident_id"] for row in to_recheck]

    ################################################################################
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_block_result(key="process_incidents__inputs:0:list_incidents:action_result.status", value=json.dumps(list_incidents_result_item_0))
    phantom.save_block_result(key="process_incidents__inputs:1:list_incidents:action_result.data", value=json.dumps(list_incidents_result_item_1))

    phantom.save_block_result(key="process_incidents:incident_id", value=json.dumps(process_incidents__incident_id))

    phantom.save_block_result(key="process_incidents_called", value="True")

    dispatch_mime_refetch(container=container)

    return


@phantom.playbook_block()
def dispatch_mime_refetch(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("dispatch_mime_refetch() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Re-fetch and vault all MIME bodies for each changed incident.
    ################################################################################

    process_incidents__incident_id = json.loads(_ if (_ := phantom.get_run_data(key="process_incidents:incident_id")) != "" else "null")  # pylint: disable=used-before-assignment

    parameters = []

    if process_incidents__incident_id is not None:
        parameters.append({
            "incident_id": process_incidents__incident_id,
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################
    ################################################################################

    # One "download mime body" per changed incident. The VPE builds ONE parameter
    # set whose incident_id is the whole list; replace it with one set per
    # incident -- the generated phantom.act() below then runs one app_run per set
    # on this block's selected asset, and a VPE save keeps this section. Reads the
    # run data rather than the generated variable, so a regenerated name cannot
    # break it.
    to_recheck = json.loads(phantom.get_run_data(key="process_incidents:to_recheck") or "null") or []
    parameters = [{"incident_id": row["incident_id"]} for row in to_recheck]

    if not parameters:
        # Nothing changed this cycle: phantom.act() has nothing to dispatch, so
        # go straight to the state update.
        phantom.debug("Nothing to recheck this cycle")
        dispatch_updates(container=container)
        return

    ################################################################################
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("download mime body", parameters=parameters, name="dispatch_mime_refetch", assets=["proofpoint_trap_mock"], callback=dispatch_updates)

    return


@phantom.playbook_block()
def dispatch_updates(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("dispatch_updates() called")

    ################################################################################
    # Build MIME Body + Event Info Update artifacts on each changed incident's container 
    # (raw REST, cross-container write), then persist the new signatures to the recheck 
    # state list.
    ################################################################################

    dispatch_mime_refetch_result_data = phantom.collect2(container=container, datapath=["dispatch_mime_refetch:action_result.parameter.incident_id","dispatch_mime_refetch:action_result.data.*.event_id","dispatch_mime_refetch:action_result.data.*.vault_id","dispatch_mime_refetch:action_result.data.*.file_name"], action_results=results)

    dispatch_mime_refetch_parameter_incident_id = [item[0] for item in dispatch_mime_refetch_result_data]
    dispatch_mime_refetch_result_item_1 = [item[1] for item in dispatch_mime_refetch_result_data]
    dispatch_mime_refetch_result_item_2 = [item[2] for item in dispatch_mime_refetch_result_data]
    dispatch_mime_refetch_result_item_3 = [item[3] for item in dispatch_mime_refetch_result_data]

    ################################################################################
    ## Custom Code Start
    ################################################################################
    ################################################################################

    try:
        to_recheck = json.loads(phantom.get_run_data(key="process_incidents:to_recheck") or "[]")
    except Exception:
        to_recheck = []

    # dispatch_mime_refetch fanned out one app_run per to_recheck row
    # (same order as the parameters list built in process_incidents) --
    # action_result.parameter.incident_id ties each app_run's MIME results
    # back to the right incident, since app_runs aren't guaranteed to
    # complete in dispatch order.
    mime_rows = phantom.collect2(
        container=container,
        datapath=[
            "dispatch_mime_refetch:action_result.parameter.incident_id",
            "dispatch_mime_refetch:action_result.data.*.event_id",
            "dispatch_mime_refetch:action_result.data.*.vault_id",
            "dispatch_mime_refetch:action_result.data.*.file_name",
        ],
    )

    mime_by_incident = {}
    for row in (mime_rows or []):
        if not row or not row[0]:
            continue
        inc_id, event_id, vault_id, file_name = row[0], row[1], row[2], row[3]
        if not event_id or not vault_id:
            continue
        mime_by_incident.setdefault(str(inc_id), []).append((event_id, vault_id, file_name))

    # phantom.add_artifact() writes to the current run's container, which here is the Timer tick's, not the
    # incident's. Use a REST POST with an explicit container_id instead (as proofpoint_trap_attachments does).
    total_artifacts = 0
    for row in to_recheck:
        inc_id = row["incident_id"]
        container_id = row["container_id"]
        event_info_cef = row["event_info_cef"]

        # A raw REST POST does NOT no-op on a duplicate source_data_identifier
        # (verified on 8.6: the same MIME Body posted twice yields two
        # artifacts), so without this every recheck piles another copy of every
        # event's MIME onto the container -- and proofpoint_trap_attachments
        # re-processes each copy. Skip what the container already carries.
        existing_mime_sdis = set()
        try:
            existing_resp = phantom.requests.get(
                uri=phantom.build_phantom_rest_url("artifact"),
                params={
                    "_filter_container": container_id,
                    "_filter_name": '"MIME Body"',
                    "page_size": 0,
                },
                verify=False,
            ).json()
            existing_mime_sdis = {
                a.get("source_data_identifier") for a in (existing_resp.get("data") or [])
            }
        except Exception as e:
            phantom.debug("Could not list existing MIME Body artifacts on container {}: {}".format(container_id, str(e)))

        for event_id, vault_id, file_name in mime_by_incident.get(inc_id, []):
            if "trap-{}-mime-{}".format(inc_id, event_id) in existing_mime_sdis:
                phantom.debug("MIME Body for incident {} event {} already on container {} -- skipping".format(inc_id, event_id, container_id))
                continue
            mime_artifact = {
                "name": "MIME Body",
                "source_data_identifier": "trap-{}-mime-{}".format(inc_id, event_id),
                "label": "event",
                "cef": {"vaultId": vault_id, "fileName": file_name},
                "cef_types": {"vaultId": ["vault id"]},
                "container_id": container_id,
                "run_automation": False,
                # An artifact created without a severity gets SOAR's default
                # (medium) and RAISES a lower container severity, undoing the
                # mapping proofpoint_trap_triage applies. UC2 artifacts carry
                # enrichment data, never a severity of their own.
                "severity": "low",
            }
            try:
                resp = phantom.requests.post(
                    uri=phantom.build_phantom_rest_url("artifact"),
                    data=json.dumps(mime_artifact),
                    verify=False,
                ).json()
                if not (resp.get("success") or resp.get("id")):
                    phantom.debug("Failed to create MIME Body artifact for incident {} event {}: {}".format(inc_id, event_id, resp.get("message", "")))
            except Exception as e:
                phantom.debug("Error creating MIME Body artifact for incident {} event {}: {}".format(inc_id, event_id, str(e)))
            total_artifacts += 1

        sig_suffix = hashlib.sha256(json.dumps(event_info_cef, sort_keys=True).encode("utf-8")).hexdigest()[:16]
        update_cef = dict(event_info_cef)
        update_cef["message"] = "TRAP incident {} changed since last enrichment".format(inc_id)
        update_artifact = {
            "name": "Event Info Update",
            "source_data_identifier": "trap-{}-recheck-{}".format(inc_id, sig_suffix),
            "label": "event",
            "cef": update_cef,
            "container_id": container_id,
            "run_automation": True,
            "severity": "low",  # never raise the container severity, see above
        }
        try:
            resp = phantom.requests.post(
                uri=phantom.build_phantom_rest_url("artifact"),
                data=json.dumps(update_artifact),
                verify=False,
            ).json()
            if not (resp.get("success") or resp.get("id")):
                phantom.debug("Failed to create Event Info Update for incident {}: {}".format(inc_id, resp.get("message", "")))
        except Exception as e:
            phantom.debug("Error creating Event Info Update for incident {}: {}".format(inc_id, str(e)))
        total_artifacts += 1

    phantom.debug("Created {} artifact(s) across {} rechecked incident(s)".format(total_artifacts, len(to_recheck)))

    # Update state only after the artifact dispatch attempt above. Best effort: the writes are attempted, not confirmed.
    try:
        new_state = json.loads(phantom.get_run_data(key="process_incidents:new_state") or "{}")
        content = [["incident_id", "signature"]] + [[k, v] for k, v in sorted(new_state.items())]
        phantom.set_list(list_name=STATE_LIST_NAME, values=content)
    except Exception as e:
        phantom.debug("Failed to update recheck state list: {}".format(str(e)))

    ################################################################################
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_block_result(key="dispatch_updates__inputs:0:dispatch_mime_refetch:action_result.parameter.incident_id", value=json.dumps(dispatch_mime_refetch_parameter_incident_id))
    phantom.save_block_result(key="dispatch_updates__inputs:1:dispatch_mime_refetch:action_result.data.*.event_id", value=json.dumps(dispatch_mime_refetch_result_item_1))
    phantom.save_block_result(key="dispatch_updates__inputs:2:dispatch_mime_refetch:action_result.data.*.vault_id", value=json.dumps(dispatch_mime_refetch_result_item_2))
    phantom.save_block_result(key="dispatch_updates__inputs:3:dispatch_mime_refetch:action_result.data.*.file_name", value=json.dumps(dispatch_mime_refetch_result_item_3))

    phantom.save_block_result(key="dispatch_updates_called", value="True")

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


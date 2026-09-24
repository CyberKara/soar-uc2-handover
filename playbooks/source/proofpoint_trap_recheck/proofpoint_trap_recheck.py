"""
Proofpoint TRAP Recheck

Automation playbook triggered on container creation for label
'proofpoint_trap_recheck' (a Timer asset tick, not a real TRAP incident
container). Periodically re-scans the whole in-window TRAP incident
backlog (all states, not just poll_state="new") for incidents that have
already been ingested into SOAR but changed since -- a field edit,
disposition change, or newly-linked event that on_poll's own checkpoint-
based main pass would never see again once an incident has a container.

Moved out of the connector's on_poll 2026-08-18 (previously
_run_recheck_pass/_incident_signature) -- see uc2_implementation_plan.md's
"fold into pb" entry for the reasoning. Custom list
`proofpoint_trap_recheck_state` (columns: incident_id, signature) replaces
the connector's self._state["incident_hashes"]/["incident_event_ids"]
persistent state -- durable across playbook runs the same way, just
playbook-owned instead of connector-owned. Dropped the connector's
newly-linked-event diffing in favor of a simpler design: any detected
change re-fetches/re-vaults ALL of that incident's MIME bodies, relying on
the already-proven SDI-based artifact dedup (native "add artifact" 400s
harmlessly on a duplicate SDI) instead of tracking per-incident event_ids.

Trigger: Container created on label 'proofpoint_trap_recheck' (Timer asset)
"""


import phantom.rules as phantom
import json
import hashlib
from datetime import datetime, timedelta

STATE_LIST_NAME = "proofpoint_trap_recheck_state"
DEFAULT_LOOKBACK_HOURS = 168  # 7 days, matches the connector's old default


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    list_incidents(container=container)

    return


@phantom.playbook_block()
def list_incidents(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("list_incidents() called")

    ################################################################################
    # state="" -- confirmed (mock_api_gateway.py's parse_qs default drops an
    # empty-valued query param, same as omitted) to mean "all states", not
    # the action's own "new" default -- this pass must see open/closed
    # incidents too, the exact gap the main on_poll pass can't cover.
    # hours_back a literal constant, not playbook-input-driven -- kept
    # simple deliberately, see module docstring.
    ################################################################################

    parameters = [{
        "state": "",
        "hours_back": str(DEFAULT_LOOKBACK_HOURS),
    }]

    phantom.act("list incidents", parameters=parameters, name="list_incidents", assets=["proofpoint_trap_mock"], callback=process_incidents)

    return


def _get_field_value(incident, field_name):
    for field in incident.get("incident_field_values", []) or []:
        if field.get("name") == field_name:
            return field.get("value", "")
    return ""


def _build_event_info_cef(incident):
    # Duplicated from proofpoint_trap_connector.py's _build_event_info_cef
    # -- the cost of moving this off the connector (see this playbook's
    # module docstring). Keep both in sync if either changes.
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


@phantom.playbook_block()
def process_incidents(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("process_incidents() called")

    ################################################################################
    ## Custom Code Start
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

    # Read prior state. Row 0 is the header ("incident_id") -- skip it,
    # same convention as cyberark_rotation_orchestrator's STATE_LIST_NAME
    # read-modify-write pattern.
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

    action_params = [{"incident_id": row["incident_id"]} for row in to_recheck]

    phantom.save_run_data(key="process_incidents:to_recheck", value=json.dumps(to_recheck))
    phantom.save_run_data(key="process_incidents:new_state", value=json.dumps(new_state))
    phantom.save_run_data(key="process_incidents:action_params", value=json.dumps(action_params))

    # Real output variable (not just save_run_data) so dispatch_mime_refetch
    # (a native action node) can bind its list-fan-out parameter to it
    # directly -- constraints.md's "output variables, not save_run_data,
    # when data feeds native blocks downstream" rule, same convention as
    # extract_data_to_artifacts's __name/__label/etc in proofpoint_trap_detail.py.
    process_incidents__incident_id = [row["incident_id"] for row in to_recheck]

    ################################################################################
    ## Custom Code End
    ################################################################################

    dispatch_mime_refetch(container=container)

    return


@phantom.playbook_block()
def dispatch_mime_refetch(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("dispatch_mime_refetch() called")

    ################################################################################
    # Native action block ("download mime body"), one parameter set per
    # changed incident, built by process_incidents. Same empty-list-skip
    # pattern as proofpoint_trap_detail.py's dispatch_event_artifacts --
    # phantom.act() with an empty parameters list has nothing to dispatch,
    # so skip straight to the next block instead.
    ################################################################################

    action_params = json.loads(phantom.get_run_data(key="process_incidents:action_params") or "[]")

    if not action_params:
        phantom.debug("Nothing to recheck this cycle")
        dispatch_updates(container=container)
        return

    phantom.act("download mime body", parameters=action_params, name="dispatch_mime_refetch", assets=["proofpoint_trap_mock"], callback=dispatch_updates)

    return


@phantom.playbook_block()
def dispatch_updates(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("dispatch_updates() called")

    ################################################################################
    ## Custom Code Start
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

    # phantom.add_artifact() targets the CURRENT run's own container in
    # every existing usage in this repo -- this playbook's own `container`
    # is the Timer tick's container, not the target TRAP incident's, so
    # this is a genuine cross-container write. Raw REST POST instead, same
    # idiom PB3 (proofpoint_trap_attachments) already uses for exactly this
    # reason -- container_id goes explicitly in the body, no ambiguity
    # about execution context.
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

    # Update state only after the artifact dispatch attempt above -- best
    # effort, matching this UC's existing "attempted work, not
    # platform-verified landed" convention (see PB1's finalize_event_artifacts
    # removal, uc2_implementation_plan.md 2026-08-13).
    try:
        new_state = json.loads(phantom.get_run_data(key="process_incidents:new_state") or "{}")
        content = [["incident_id", "signature"]] + [[k, v] for k, v in sorted(new_state.items())]
        phantom.set_list(list_name=STATE_LIST_NAME, values=content)
    except Exception as e:
        phantom.debug("Failed to update recheck state list: {}".format(str(e)))

    ################################################################################
    ## Custom Code End
    ################################################################################

    return


def on_finish(container, summary):
    phantom.debug("on_finish() called")
    return

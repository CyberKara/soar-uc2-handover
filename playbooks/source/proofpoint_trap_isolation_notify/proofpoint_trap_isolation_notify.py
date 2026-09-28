"""
Email the container owner isolation-browser links for the container URL and every threat URL found in the TRAP incident.
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


################################################################################
## Global Custom Code Start
################################################################################



# Design notes (kept here because a VPE save replaces the module docstring):
# Proofpoint TRAP Isolation Notify (PB6)
#
# Data playbook manually launched by an analyst from the container, once
# they've reviewed PB1's enrichment. Emails the container owner a set of
# isolation-browser links -- the container's own SOAR URL plus every threat
# URL PB1 found in the incident (from "Threat Domain" artifacts' cef.url) --
# each wrapped behind a configurable remote-browser-isolation prefix so the
# analyst can preview them without direct exposure. Independent entry point,
# same convention as PB4/PB5 -- no chaining, no writes back to TRAP.
#
# Recipient resolution (design decision, see uc2_implementation_plan.md's
# PB6 section): TRAP containers never get an owner assigned automatically --
# the same gap PB4/PB5 work around with a prompt-approval fallback. Email
# delivery can't use that fallback (a real address is required, not just a
# SOAR username), so this playbook requires the analyst to have already
# self-assigned the *container itself* as owner AND moved the *container's
# own* status to "open" in the SOAR UI (distinct from PB4's TRAP-side
# assignee/status calls, which touch the remote TRAP incident, not the
# container's own owner/status fields) -- fails fast with no silent fallback
# if either is missing, since an isolation link must reach a real person.
# Owner id -> email via GET /rest/ph_user/<id>.
#
# Delivery: new "smtp" asset (phsmtp reference connector,
# soar-connectors/reference_connectors/phantom-apps/Apps/phsmtp/), mock-first
# against migration/mock-backend/mock_smtp.py -- see that file's docstring.
#
# Trigger: Manual run by analyst
# Playbook input: isolation_browser_url (default:
# https://my_isolated_browser/browser?url=) -- deliberately not hardcoded,
# per constraints.md's no-hardcoded-config rule; this is a per-deployment
# value, not project-fixed.

import urllib.parse

DEFAULT_ISOLATION_BROWSER_URL = "https://my_isolated_browser/browser?url="
################################################################################
## Global Custom Code End
################################################################################

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
    # Extract TRAP incident ID via the shared proofpoint_trap_extract_incident_id 
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
    # Bridge block: read extract_incident_id CF result (same pattern as cyberark_rotation_orchestrator.py 
    # read_discover_result).
    ################################################################################

    extract_incident_id__result = phantom.collect2(container=container, datapath=["extract_incident_id:custom_function_result.data.incident_id"])

    extract_incident_id_data_incident_id = [item[0] for item in extract_incident_id__result]

    read_incident_id__incident_id = None

    ################################################################################
    ## Custom Code Start
    ################################################################################
    ################################################################################


    result_rows = phantom.collect2(
        container=container,
        datapath=["extract_incident_id:custom_function_result.data.incident_id"],
    )
    incident_id_val = result_rows[0][0] if result_rows else None

    if not incident_id_val:
        phantom.error("Could not find Incident ID (cef.incidentId) on the 'Event Info' artifact")
        phantom.add_note(
            container=container,
            note_type="general",
            title="TRAP Isolation Notify - Error",
            content="Could not find Incident ID on the 'Event Info' artifact"
        )
        return

    read_incident_id__incident_id = str(incident_id_val)
    phantom.debug("Extracted incident ID: {}".format(read_incident_id__incident_id))

    # Also saved as run data: later blocks read this key in their own Custom Code.
    phantom.save_run_data(key="read_incident_id:incident_id", value=json.dumps(read_incident_id__incident_id))

    ################################################################################
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_block_result(key="read_incident_id__inputs:0:extract_incident_id:custom_function_result.data.incident_id", value=json.dumps(extract_incident_id_data_incident_id))

    phantom.save_block_result(key="read_incident_id:incident_id", value=json.dumps(read_incident_id__incident_id))

    phantom.save_block_result(key="read_incident_id_called", value="True")

    resolve_recipient_and_build_links(container=container)

    return


@phantom.playbook_block()
def resolve_recipient_and_build_links(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("resolve_recipient_and_build_links() called")

    ################################################################################
    # Fail-fast owner+status precondition, resolve owner id -> email via GET /rest/ph_user, 
    # collect unique Threat Domain cef.url values, build isolation-wrapped links for 
    # the container URL + each threat URL, format email subject/body.
    ################################################################################

    read_incident_id__incident_id = json.loads(_ if (_ := phantom.get_run_data(key="read_incident_id:incident_id")) != "" else "null")  # pylint: disable=used-before-assignment

    resolve_recipient_and_build_links__recipient_email = None
    resolve_recipient_and_build_links__subject = None
    resolve_recipient_and_build_links__body = None

    ################################################################################
    ## Custom Code Start
    ################################################################################
    ################################################################################


    incident_id = json.loads(phantom.get_run_data(key="read_incident_id:incident_id") or '""')

    owner_id = container.get("owner")
    status = container.get("status")

    if not owner_id or status != "open":
        msg = (
            "Container has no assigned owner or is not status 'open' "
            "(owner={}, status={}) -- self-assign this container as owner "
            "and set its status to Open in the SOAR UI first, so a real "
            "recipient can be resolved.".format(owner_id, status)
        )
        phantom.error(msg)
        phantom.add_note(
            container=container,
            note_type="general",
            title="TRAP Isolation Notify - Error",
            content=msg
        )
        return

    # container['owner'] is the username string inside playbook execution
    # context, NOT the numeric REST-API id the raw GET /rest/container
    # response shows (confirmed live 2026-08-17, container 1661: REST showed
    # owner=1/owner_name="soar_local_admin", but this block saw
    # owner="soar_local_admin") -- filter by username instead of assuming a
    # path-friendly numeric id.
    try:
        resp = phantom.requests.get(
            uri=phantom.build_phantom_rest_url("ph_user") + '?_filter_username="{}"&page_size=1'.format(owner_id),
            verify=False,
        ).json()
        rows = resp.get("data") or []
        recipient_email = rows[0].get("email") if rows else None
    except Exception as e:
        recipient_email = None
        phantom.debug("Could not fetch ph_user for owner '{}': {}".format(owner_id, str(e)))

    if not recipient_email:
        msg = "Could not resolve an email address for owner user id {}".format(owner_id)
        phantom.error(msg)
        phantom.add_note(
            container=container,
            note_type="general",
            title="TRAP Isolation Notify - Error",
            content=msg
        )
        return

    # playbook_input: must be its own collect2 call -- mixing playbook_input:
    # datapaths with other datapaths in one collect2 call throws TypeError
    # (constraints.md).
    input_rows = phantom.collect2(container=container, datapath=["playbook_input:isolation_browser_url"])
    isolation_browser_url = (input_rows[0][0] if input_rows and input_rows[0][0] else None) or DEFAULT_ISOLATION_BROWSER_URL

    # Threat Domain artifacts are the only ones with cef.url set -- collect
    # across the whole container (scope="all", required when re-running on
    # an existing container per constraints.md) and drop the Nones instead
    # of also fetching artifact:*.name to filter by.
    url_rows = phantom.collect2(container=container, datapath=["artifact:*.cef.url"], scope="all")
    threat_urls = sorted({row[0] for row in url_rows if row and row[0]}) if url_rows else []

    soar_base = phantom.get_base_url() or ""
    container_url = "{}/mission/{}".format(soar_base, container.get("id"))

    targets = [("Container", container_url)] + [("Threat URL", u) for u in threat_urls]
    link_lines = [
        "- {}: {}{}".format(label, isolation_browser_url, urllib.parse.quote(target, safe=""))
        for label, target in targets
    ]

    resolve_recipient_and_build_links__recipient_email = recipient_email
    resolve_recipient_and_build_links__subject = "TRAP Incident {} - Isolation Browser Links".format(incident_id or "unknown")
    resolve_recipient_and_build_links__body = (
        "Isolation-browser links for TRAP incident {}.\n\n"
        "Open these instead of the raw URLs -- each opens in a sandboxed "
        "browser rather than directly:\n\n{}\n"
    ).format(incident_id or "unknown", "\n".join(link_lines))

    phantom.debug("Resolved recipient {}, {} link(s)".format(recipient_email, len(targets)))

    # Also saved as run data: send_isolation_email and add_isolation_note read
    # these keys in their own Custom Code (link_count is not a block output).
    phantom.save_run_data(key="resolve_recipient_and_build_links:recipient_email", value=json.dumps(resolve_recipient_and_build_links__recipient_email))
    phantom.save_run_data(key="resolve_recipient_and_build_links:subject", value=json.dumps(resolve_recipient_and_build_links__subject))
    phantom.save_run_data(key="resolve_recipient_and_build_links:body", value=json.dumps(resolve_recipient_and_build_links__body))
    phantom.save_run_data(key="resolve_recipient_and_build_links:link_count", value=str(len(targets)))

    ################################################################################
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_block_result(key="resolve_recipient_and_build_links__inputs:0:read_incident_id:custom_function:incident_id", value=json.dumps(read_incident_id__incident_id))

    phantom.save_block_result(key="resolve_recipient_and_build_links:recipient_email", value=json.dumps(resolve_recipient_and_build_links__recipient_email))
    phantom.save_block_result(key="resolve_recipient_and_build_links:subject", value=json.dumps(resolve_recipient_and_build_links__subject))
    phantom.save_block_result(key="resolve_recipient_and_build_links:body", value=json.dumps(resolve_recipient_and_build_links__body))

    phantom.save_block_result(key="resolve_recipient_and_build_links_called", value="True")

    send_isolation_email(container=container)

    return


@phantom.playbook_block()
def send_isolation_email(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("send_isolation_email() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Sends the isolation-link email via the smtp asset (phsmtp reference connector).
    ################################################################################

    resolve_recipient_and_build_links__recipient_email = json.loads(_ if (_ := phantom.get_run_data(key="resolve_recipient_and_build_links:recipient_email")) != "" else "null")  # pylint: disable=used-before-assignment
    resolve_recipient_and_build_links__body = json.loads(_ if (_ := phantom.get_run_data(key="resolve_recipient_and_build_links:body")) != "" else "null")  # pylint: disable=used-before-assignment
    resolve_recipient_and_build_links__subject = json.loads(_ if (_ := phantom.get_run_data(key="resolve_recipient_and_build_links:subject")) != "" else "null")  # pylint: disable=used-before-assignment

    parameters = []

    if resolve_recipient_and_build_links__recipient_email is not None and resolve_recipient_and_build_links__body is not None:
        parameters.append({
            "to": resolve_recipient_and_build_links__recipient_email,
            "body": resolve_recipient_and_build_links__body,
            "subject": resolve_recipient_and_build_links__subject,
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################
    ################################################################################

    # Built from the run data resolve_recipient_and_build_links saved, so the
    # send does not depend on how the VPE names its generated variables.
    parameters = [{
        "to": json.loads(phantom.get_run_data(key="resolve_recipient_and_build_links:recipient_email") or "null"),
        "subject": json.loads(phantom.get_run_data(key="resolve_recipient_and_build_links:subject") or "null"),
        "body": json.loads(phantom.get_run_data(key="resolve_recipient_and_build_links:body") or "null"),
    }]

    ################################################################################
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("send email", parameters=parameters, name="send_isolation_email", assets=["smtp"], callback=add_isolation_note)

    return


@phantom.playbook_block()
def add_isolation_note(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_isolation_note() called")

    ################################################################################
    # Add a summary note recording who the links were sent to and whether the send 
    # succeeded.
    ################################################################################

    send_isolation_email_result_data = phantom.collect2(container=container, datapath=["send_isolation_email:action_result.status","send_isolation_email:action_result.message"], action_results=results)
    read_incident_id__incident_id = json.loads(_ if (_ := phantom.get_run_data(key="read_incident_id:incident_id")) != "" else "null")  # pylint: disable=used-before-assignment
    resolve_recipient_and_build_links__recipient_email = json.loads(_ if (_ := phantom.get_run_data(key="resolve_recipient_and_build_links:recipient_email")) != "" else "null")  # pylint: disable=used-before-assignment

    send_isolation_email_result_item_0 = [item[0] for item in send_isolation_email_result_data]
    send_isolation_email_result_message = [item[1] for item in send_isolation_email_result_data]

    ################################################################################
    ## Custom Code Start
    ################################################################################
    ################################################################################

    incident_id = json.loads(phantom.get_run_data(key="read_incident_id:incident_id") or '""')
    recipient_email = json.loads(phantom.get_run_data(key="resolve_recipient_and_build_links:recipient_email") or 'null')
    link_count = phantom.get_run_data(key="resolve_recipient_and_build_links:link_count") or "0"

    send_data = phantom.collect2(container=container, datapath=["send_isolation_email:action_result.status", "send_isolation_email:action_result.message"])
    send_status = send_data[0][0] if send_data and send_data[0][0] else "not run"
    send_message = send_data[0][1] if send_data and len(send_data[0]) > 1 and send_data[0][1] else ""

    note_content = "\n".join([
        "# TRAP Isolation Notify",
        "**Incident ID:** {}".format(incident_id),
        "**Recipient:** {}".format(recipient_email),
        "**Links sent:** {}".format(link_count),
        "**Send status:** {}".format(send_status),
        "**Send message:** {}".format(send_message),
    ])

    phantom.add_note(
        container=container,
        note_type="general",
        title="TRAP Isolation Notify",
        content=note_content
    )

    phantom.debug("Isolation notify note added")

    ################################################################################
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_block_result(key="add_isolation_note__inputs:0:read_incident_id:custom_function:incident_id", value=json.dumps(read_incident_id__incident_id))
    phantom.save_block_result(key="add_isolation_note__inputs:1:resolve_recipient_and_build_links:custom_function:recipient_email", value=json.dumps(resolve_recipient_and_build_links__recipient_email))
    phantom.save_block_result(key="add_isolation_note__inputs:2:send_isolation_email:action_result.status", value=json.dumps(send_isolation_email_result_item_0))
    phantom.save_block_result(key="add_isolation_note__inputs:3:send_isolation_email:action_result.message", value=json.dumps(send_isolation_email_result_message))

    phantom.save_block_result(key="add_isolation_note_called", value="True")

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")

    ################################################################################
    ## Custom Code Start
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
    ## Custom Code End
    ################################################################################

    return


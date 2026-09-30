"""
Data playbook (PB6) run by an analyst from a Proofpoint TRAP container. Emails the container owner isolation-browser links for the container URL and every threat URL found in the TRAP incident, and lists the same links in its TRAP Isolation Notify note.
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


################################################################################
## Global Custom Code Start
################################################################################



# Manual playbook: emails the container owner isolation-browser links (the case's own SOAR URL plus every threat
# URL found in the incident), each behind the isolation_browser_url prefix. Nothing is written back to TRAP.
# The analyst must first make themself the container's owner and set its status to "open": TRAP containers get
# no owner automatically and the email needs a real address (owner -> email via /rest/ph_user/<id>), so the
# playbook fails fast instead of falling back. Delivery goes through the smtp asset.
# isolation_browser_url defaults to a placeholder (https://my_isolated_browser/browser?url=): set it per
# deployment, or the links are dead.

import urllib.parse

DEFAULT_ISOLATION_BROWSER_URL = "https://my_isolated_browser/browser?url="
# The target SOAR shows at most about 22,000 characters of a note, so no note
# is posted longer than this; a longer one is split by _note_parts().
_NOTE_MAX_CHARS = 20000


def _note_parts(title, content, limit=_NOTE_MAX_CHARS):
    """[(title, content)] for one note, or numbered parts "title (k/N)" cut at
    line boundaries when content is longer than limit. A line longer than the
    limit is cut inside itself. Parts after the first open with a heading."""
    if len(content) <= limit:
        return [(title, content)]
    budget = limit - 300  # room for the heading added to later parts
    chunks, current, size = [], [], 0
    for line in content.split("\n"):
        for piece in [line[i:i + budget] for i in range(0, len(line), budget)] or [""]:
            if current and size + len(piece) + 1 > budget:
                chunks.append("\n".join(current))
                current, size = [], 0
            current.append(piece)
            size += len(piece) + 1
    if current:
        chunks.append("\n".join(current))
    total = len(chunks)
    return [("{} ({}/{})".format(title, n, total),
             chunk if n == 1 else "# {} ({}/{}, continued)\n\n{}".format(title, n, total, chunk))
            for n, chunk in enumerate(chunks, 1)]
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

    # Playbook outputs, read by on_finish (status stays failed until the email is sent).
    playbook_output = {"status": "failed", "incident_id": read_incident_id__incident_id}
    phantom.save_run_data(key="playbook_output", value=json.dumps(playbook_output))

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

    # container['owner'] is the owner's username inside playbook execution (the REST API shows a numeric id),
    # so filter ph_user by username.
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

    # playbook_input must be its own collect2 call: mixing it with other datapaths raises TypeError.
    input_rows = phantom.collect2(container=container, datapath=["playbook_input:isolation_browser_url"])
    isolation_browser_url = (input_rows[0][0] if input_rows and input_rows[0][0] else None) or DEFAULT_ISOLATION_BROWSER_URL

    # Threat Domain artifacts are the only ones with cef.url set: collect across the whole container
    # (scope="all", needed on re-runs) and drop the Nones.
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
    # The links themselves, for the container note (add_isolation_note).
    phantom.save_run_data(key="resolve_recipient_and_build_links:links", value=json.dumps([
        [label, target, "{}{}".format(isolation_browser_url, urllib.parse.quote(target, safe=""))]
        for label, target in targets
    ]))

    playbook_output = json.loads(phantom.get_run_data(key="playbook_output") or "{}")
    playbook_output.update({"recipient_email": recipient_email, "link_count": len(targets)})
    phantom.save_run_data(key="playbook_output", value=json.dumps(playbook_output))

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

    # The send is dispatched unconditionally, so a missing action_result is a
    # failure, not a skipped step: when SOAR refuses to dispatch an action (a
    # manifest-required parameter missing) no app_run is created and collect2
    # finds nothing, while the playbook run records the attempt as failed.
    send_data = phantom.collect2(container=container, datapath=["send_isolation_email:action_result.status", "send_isolation_email:action_result.message"])
    send_status = send_data[0][0] if send_data and send_data[0][0] else "failed - not dispatched (reason in the playbook run's actions)"
    send_message = send_data[0][1] if send_data and len(send_data[0]) > 1 and send_data[0][1] else ""

    playbook_output = json.loads(phantom.get_run_data(key="playbook_output") or "{}")
    playbook_output["status"] = "success" if send_status == "success" else "failed"
    phantom.save_run_data(key="playbook_output", value=json.dumps(playbook_output))

    note_lines = [
        "# TRAP Isolation Notify",
        "**Incident ID:** {}".format(incident_id),
        "**Recipient:** {}".format(recipient_email),
        "**Links sent:** {}".format(link_count),
        "**Send status:** {}".format(send_status),
        "**Send message:** {}".format(send_message),
    ]
    # The same links the email carries. Only the isolation-browser link is
    # clickable; the target (a threat URL) is shown as code so it cannot be
    # clicked directly.
    links = json.loads(phantom.get_run_data(key="resolve_recipient_and_build_links:links") or "[]")
    if links:
        note_lines += ["", "## Isolation-browser links", ""]
        note_lines += ["- **{}** `{}` — [open in the isolation browser]({})".format(
            label, str(target).replace("`", "'"), isolation_link) for label, target, isolation_link in links]

    for part_title, part_content in _note_parts("TRAP Isolation Notify", "\n".join(note_lines)):
        phantom.add_note(
            container=container,
            note_type="general",
            title=part_title,
            content=part_content,
            note_format="markdown",  # the content is markdown; add_note() defaults to html
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

    output = {
        "status": None,
        "incident_id": None,
        "recipient_email": None,
        "link_count": None,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################
    ################################################################################

    # Populate the generated `output` dict; the save after Custom Code End emits it.
    # No block recorded an outcome (e.g. the run stopped early): report failed.
    raw_output = phantom.get_run_data(key="playbook_output")
    if raw_output:
        output.update(json.loads(raw_output))
    if output["status"] is None:
        output["status"] = "failed"

    ################################################################################
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_playbook_output_data(output=output)

    return


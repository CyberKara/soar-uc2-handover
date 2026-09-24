"""
Proofpoint TRAP Isolation Notify (PB6)

Data playbook manually launched by an analyst from the container, once
they've reviewed PB1's enrichment. Emails the container owner a set of
isolation-browser links -- the container's own SOAR URL plus every threat
URL PB1 found in the incident (from "Threat Domain" artifacts' cef.url) --
each wrapped behind a configurable remote-browser-isolation prefix so the
analyst can preview them without direct exposure. Independent entry point,
same convention as PB4/PB5 -- no chaining, no writes back to TRAP.

Recipient resolution (design decision, see uc2_implementation_plan.md's
PB6 section): TRAP containers never get an owner assigned automatically --
the same gap PB4/PB5 work around with a prompt-approval fallback. Email
delivery can't use that fallback (a real address is required, not just a
SOAR username), so this playbook requires the analyst to have already
self-assigned the *container itself* as owner AND moved the *container's
own* status to "open" in the SOAR UI (distinct from PB4's TRAP-side
assignee/status calls, which touch the remote TRAP incident, not the
container's own owner/status fields) -- fails fast with no silent fallback
if either is missing, since an isolation link must reach a real person.
Owner id -> email via GET /rest/ph_user/<id>.

Delivery: new "smtp" asset (phsmtp reference connector,
soar-connectors/reference_connectors/phantom-apps/Apps/phsmtp/), mock-first
against migration/mock-backend/mock_smtp.py -- see that file's docstring.

Trigger: Manual run by analyst
Playbook input: isolation_browser_url (default:
https://my_isolated_browser/browser?url=) -- deliberately not hardcoded,
per constraints.md's no-hardcoded-config rule; this is a per-deployment
value, not project-fixed.
"""


import phantom.rules as phantom
import json
import urllib.parse


DEFAULT_ISOLATION_BROWSER_URL = "https://my_isolated_browser/browser?url="


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    extract_incident_id(container=container)

    return


@phantom.playbook_block()
def extract_incident_id(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("extract_incident_id() called")

    ################################################################################
    # Calls the shared proofpoint_trap_extract_incident_id custom function --
    # same pattern as PB2/PB4/PB5, gives the email a real incident ID for
    # its subject/context line even though this playbook writes nothing
    # back to TRAP.
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
    # pair, and this UC's own PB4/PB5).
    ################################################################################

    read_incident_id__incident_id = None

    ################################################################################
    ## Custom Code Start
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

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="read_incident_id:incident_id", value=json.dumps(read_incident_id__incident_id))

    resolve_recipient_and_build_links(container=container)

    return


@phantom.playbook_block()
def resolve_recipient_and_build_links(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("resolve_recipient_and_build_links() called")

    ################################################################################
    # Precondition (fail fast, no silent fallback -- see module docstring):
    # container must have a real owner AND status "open". Resolves owner id
    # -> email via GET /rest/ph_user/<id>, collects every unique threat URL
    # from PB1's "Threat Domain" artifacts (cef.url -- confirmed live field
    # name, not cs1, against proofpoint_trap_detail.py 2026-08-16), builds
    # one isolation-wrapped link per target (container URL + each threat
    # URL), and formats the email subject/body. On any failure, adds a note
    # and returns without calling send_isolation_email -- no email is sent.
    ################################################################################

    resolve_recipient_and_build_links__recipient_email = None
    resolve_recipient_and_build_links__subject = None
    resolve_recipient_and_build_links__body = None

    ################################################################################
    ## Custom Code Start
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

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="resolve_recipient_and_build_links:recipient_email", value=json.dumps(resolve_recipient_and_build_links__recipient_email))
    phantom.save_run_data(key="resolve_recipient_and_build_links:subject", value=json.dumps(resolve_recipient_and_build_links__subject))
    phantom.save_run_data(key="resolve_recipient_and_build_links:body", value=json.dumps(resolve_recipient_and_build_links__body))
    phantom.save_run_data(key="resolve_recipient_and_build_links:link_count", value=str(len(targets)))

    send_isolation_email(container=container)

    return


@phantom.playbook_block()
def send_isolation_email(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("send_isolation_email() called")

    ################################################################################
    # Native action block -- sends the isolation-link email via the "smtp"
    # asset (phsmtp reference connector, mock-first against
    # migration/mock-backend/mock_smtp.py).
    ################################################################################

    resolve_recipient_and_build_links__recipient_email = json.loads(phantom.get_run_data(key="resolve_recipient_and_build_links:recipient_email") or 'null')
    resolve_recipient_and_build_links__subject = json.loads(phantom.get_run_data(key="resolve_recipient_and_build_links:subject") or 'null')
    resolve_recipient_and_build_links__body = json.loads(phantom.get_run_data(key="resolve_recipient_and_build_links:body") or 'null')

    parameters = [{
        "to": resolve_recipient_and_build_links__recipient_email,
        "subject": resolve_recipient_and_build_links__subject,
        "body": resolve_recipient_and_build_links__body,
    }]

    phantom.act("send email", parameters=parameters, name="send_isolation_email", assets=["smtp"], callback=add_isolation_note)

    return


@phantom.playbook_block()
def add_isolation_note(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("add_isolation_note() called")

    ################################################################################
    # Add a summary note recording who the links were sent to and whether
    # the send succeeded.
    ################################################################################

    ################################################################################
    ## Custom Code Start
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
    ## Custom Code End
    ################################################################################

    return


def on_finish(container, summary):
    phantom.debug("on_finish() called")
    return

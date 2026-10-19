"""
Automation playbook (PB5), kept inactive: an analyst runs it from the case with Run Playbook. Emails the analyst who launched it one isolation-browser link per threat URL on the case; the send action&#39;s result is the record on the case.
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


################################################################################
## Global Custom Code Start
################################################################################
################################################################################



import html
import urllib.parse

def _unwrap_safelinks(url):
    """The URL behind Microsoft Safe Links (<region>.safelinks.protection.outlook.com/?url=<encoded>),
    unwrapped as many times as it was wrapped; any other URL is returned unchanged."""
    for _ in range(5):
        parts = urllib.parse.urlsplit(url)
        if not (parts.hostname or "").lower().endswith(".safelinks.protection.outlook.com"):
            break
        inner = urllib.parse.parse_qs(parts.query).get("url")
        if not inner or not inner[0]:
            break
        url = inner[0]
    return url


def _defang(url):
    """A URL shown as text that no mail client turns into a link."""
    return url.replace("http", "hxxp", 1).replace(".", "[.]")
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
    # Read the TRAP incident ID (shared custom function).
    ################################################################################

    parameters = [{}]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="local/proofpoint_trap_extract_incident_id", parameters=parameters, name="extract_incident_id", callback=isolation_browser_url)

    return


@phantom.playbook_block()
def build_links(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("build_links() called")

    ################################################################################
    # Find the launching analyst's email, build the isolation links.
    ################################################################################

    build_links__recipient_email = None
    build_links__subject = None
    build_links__body = None

    ################################################################################
    ## Custom Code Start
    ################################################################################
    ################################################################################


    rows = phantom.collect2(container=container, datapath=["extract_incident_id:custom_function_result.data.incident_id"])
    incident_id = str(rows[0][0]) if rows and rows[0] and rows[0][0] else ""
    phantom.save_run_data(key="playbook_output", value=json.dumps({"status": "failed", "incident_id": incident_id}))

    # The links go to the analyst who launched the playbook (Run Playbook on the
    # case): no owner or status needed. Look the user up by username for the email.
    launcher_rows = phantom.collect2(container=container, datapath=["playbook:launching_user.name"])
    launcher = launcher_rows[0][0] if launcher_rows and launcher_rows[0] and launcher_rows[0][0] else ""
    recipient_email = None
    if launcher:
        try:
            resp = phantom.requests.get(
                uri=phantom.build_phantom_rest_url("ph_user") + '?_filter_username="{}"&page_size=1'.format(launcher),
                verify=False,
            ).json()
            users = resp.get("data") or []
            recipient_email = users[0].get("email") if users else None
        except Exception as e:
            phantom.debug("Could not fetch ph_user for '{}': {}".format(launcher, str(e)))

    if not recipient_email:
        msg = "Could not resolve an email address for the user who launched the playbook ({})".format(launcher or "unknown")
        phantom.error(msg)
        phantom.add_note(
            container=container,
            note_type="general",
            title="TRAP Isolation Notify - Error",
            content=msg
        )
        return

    # The prefix lives in the format block isolation_browser_url, where an
    # operator sets it without touching code.
    browser_prefix = (phantom.get_format_data(name="isolation_browser_url") or "").strip()
    if not browser_prefix:
        msg = "The isolation-browser prefix is empty: set it in the format block 'isolation browser url'."
        phantom.error(msg)
        phantom.add_note(
            container=container,
            note_type="general",
            title="TRAP Isolation Notify - Error",
            content=msg
        )
        return

    # Threat URLs come from two artifacts: Threat Domain cef.url (URLs in the
    # emails) and URL Artifact cef.requestURL (the incident's hosts.url, often
    # the only ones on a real incident). scope="all" is required when
    # re-running on an existing container (constraints.md). A URL the mail
    # system already wrapped in Safe Links is unwrapped first, or the isolation
    # browser would go through Safe Links before reaching it; the set drops a
    # URL both artifacts carry.
    url_rows = phantom.collect2(container=container, datapath=["artifact:*.name", "artifact:*.cef.url", "artifact:*.cef.requestURL"], scope="all") or []
    threat_urls = sorted({_unwrap_safelinks(url) for row in url_rows if row
                          for name, url in (("Threat Domain", row[1]), ("URL Artifact", row[2]))
                          if row[0] == name and url})

    if not threat_urls:
        phantom.add_note(
            container=container,
            note_type="general",
            title="TRAP Isolation Notify",
            content="No threat URL on this case: no email sent.",
            note_format="markdown",
        )
        playbook_output = json.loads(phantom.get_run_data(key="playbook_output") or "{}")
        playbook_output.update({"status": "skipped", "recipient_email": recipient_email, "link_count": 0})
        phantom.save_run_data(key="playbook_output", value=json.dumps(playbook_output))
        return

    # The case link is direct: it is SOAR's own page, not a target to isolate.
    soar_base = phantom.get_base_url() or ""
    container_url = "{}/mission/{}".format(soar_base, container.get("id"))

    targets = [("Threat URL", u) for u in threat_urls]
    link_items = [
        '<li>{}: <code>{}</code> &mdash; <a href="{}">open in the isolation browser</a></li>'.format(
            label, html.escape(_defang(target)),
            html.escape(browser_prefix + urllib.parse.quote(target, safe=""), quote=True))
        for label, target in targets
    ]

    build_links__recipient_email = recipient_email
    build_links__subject = "TRAP Incident {} - Isolation Browser Links".format(incident_id or "unknown")
    # Must start with <html>: the SMTP app sends HTML (plus a text copy) only then.
    # The line breaks are what the app's text copy keeps as lines.
    build_links__body = (
        "<html><body>\n"
        '<p>Isolation-browser links for <a href="{}">TRAP incident {}</a>.</p>\n'
        "<p>Open these instead of the raw URLs -- each opens in a sandboxed "
        "browser rather than directly:</p>\n"
        "<ul>\n{}\n</ul>\n"
        "</body></html>"
    ).format(html.escape(container_url, quote=True), html.escape(str(incident_id or "unknown")), "\n".join(link_items))

    phantom.debug("Resolved recipient {}, {} link(s)".format(recipient_email, len(targets)))

    # Also saved as run data: send_isolation_email reads these keys.
    phantom.save_run_data(key="build_links:recipient_email", value=json.dumps(build_links__recipient_email))
    phantom.save_run_data(key="build_links:subject", value=json.dumps(build_links__subject))
    phantom.save_run_data(key="build_links:body", value=json.dumps(build_links__body))

    playbook_output = json.loads(phantom.get_run_data(key="playbook_output") or "{}")
    playbook_output.update({"recipient_email": recipient_email, "link_count": len(targets)})
    phantom.save_run_data(key="playbook_output", value=json.dumps(playbook_output))

    ################################################################################
    ################################################################################
    ################################################################################
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_block_result(key="build_links:recipient_email", value=json.dumps(build_links__recipient_email))
    phantom.save_block_result(key="build_links:subject", value=json.dumps(build_links__subject))
    phantom.save_block_result(key="build_links:body", value=json.dumps(build_links__body))

    phantom.save_block_result(key="build_links_called", value="True")

    send_isolation_email(container=container)

    return


@phantom.playbook_block()
def send_isolation_email(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("send_isolation_email() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Send the isolation-link email; its result is the record on the case.
    ################################################################################

    build_links__recipient_email = json.loads(_ if (_ := phantom.get_run_data(key="build_links:recipient_email")) != "" else "null")  # pylint: disable=used-before-assignment
    build_links__body = json.loads(_ if (_ := phantom.get_run_data(key="build_links:body")) != "" else "null")  # pylint: disable=used-before-assignment
    build_links__subject = json.loads(_ if (_ := phantom.get_run_data(key="build_links:subject")) != "" else "null")  # pylint: disable=used-before-assignment

    parameters = []

    if build_links__recipient_email is not None and build_links__body is not None:
        parameters.append({
            "to": build_links__recipient_email,
            "body": build_links__body,
            "subject": build_links__subject,
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################
    ################################################################################

    # Built from the run data build_links saved, so the send does not depend
    # on how the VPE names its generated variables.
    parameters = [{
        "to": json.loads(phantom.get_run_data(key="build_links:recipient_email") or "null"),
        "subject": json.loads(phantom.get_run_data(key="build_links:subject") or "null"),
        "body": json.loads(phantom.get_run_data(key="build_links:body") or "null"),
    }]

    ################################################################################
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("send email", parameters=parameters, name="send_isolation_email", assets=["smtp"])

    return


@phantom.playbook_block()
def isolation_browser_url(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("isolation_browser_url() called")

    ################################################################################
    # Isolation-browser URL prefix: set your own; each target URL is appended.
    ################################################################################

    template = """https://www.domain.tld/browser?url="""

    # parameter list for template variable replacement
    parameters = []

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="isolation_browser_url")

    build_links(container=container)

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")

    output = {
        "status": [],
        "incident_id": [],
        "recipient_email": [],
        "link_count": [],
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################
    ################################################################################

    # Populate the generated `output` dict; the save after Custom Code End emits
    # it. status follows the send action's result: success only when it sent.
    raw_output = phantom.get_run_data(key="playbook_output")
    if raw_output:
        output.update(json.loads(raw_output))
    sent = phantom.collect2(container=container, datapath=["send_isolation_email:action_result.status"])
    if sent and sent[0] and sent[0][0]:
        output["status"] = "success" if sent[0][0] == "success" else "failed"
    # The 8.6 VPE initialises every output above to [] (8.5 wrote None), so an
    # output no block set is normalised to null here, whichever form a save wrote.
    for key, value in output.items():
        if value == []:
            output[key] = None
    if output["status"] is None:
        output["status"] = "failed"

    ################################################################################
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_playbook_output_data(output=output)

    return

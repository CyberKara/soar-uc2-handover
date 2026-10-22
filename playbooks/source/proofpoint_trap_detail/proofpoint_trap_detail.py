"""
Automation playbook (PB1), left inactive: proofpoint_trap_orchestrator runs it first. Fetches the TRAP incident, creates the incident-level artifacts not on the case yet, names a case TRAP left without a summary, records Enrichment Complete and writes the detail note in place.
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'filter_event_info' block
    filter_event_info(container=container)

    return

@phantom.playbook_block()
def filter_event_info(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("filter_event_info() called")

    ################################################################################
    # Keep only the Event Info artifact, whose cef.incidentId both TRAP actions use.
    ################################################################################

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.name", "==", "Event Info"]
        ],
        conditions_dps=[
            ["artifact:*.name", "==", "Event Info"]
        ],
        name="filter_event_info:condition_1",
        scope="all",
        delimiter=",")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        get_trap_incident(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def get_trap_incident(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("get_trap_incident() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Fetch the full incident, with its events, from Proofpoint TRAP.
    ################################################################################

    filtered_artifact_0_data_filter_event_info = phantom.collect2(container=container, datapath=["filtered-data:filter_event_info:condition_1:artifact:*.cef.incidentId","filtered-data:filter_event_info:condition_1:artifact:*.id"], scope="all")

    parameters = []

    # build parameters list for 'get_trap_incident' call
    for filtered_artifact_0_item_filter_event_info in filtered_artifact_0_data_filter_event_info:
        if filtered_artifact_0_item_filter_event_info[0] is not None:
            parameters.append({
                "incident_id": filtered_artifact_0_item_filter_event_info[0],
                "context": {'artifact_id': filtered_artifact_0_item_filter_event_info[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("get incident", parameters=parameters, name="get_trap_incident", assets=["proofpoint_trap_mock"], callback=build_artifact_list)

    return


@phantom.playbook_block()
def build_artifact_list(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("build_artifact_list() called")

    ################################################################################
    # Build the incident-level artifacts not on the case yet, the case name and the 
    # detail note.
    ################################################################################

    source_data_identifier_value = container.get("source_data_identifier", None)
    get_trap_incident_result_data = phantom.collect2(container=container, datapath=["get_trap_incident:action_result.status","get_trap_incident:action_result.data"], action_results=results)

    get_trap_incident_result_item_0 = [item[0] for item in get_trap_incident_result_data]
    get_trap_incident_result_item_1 = [item[1] for item in get_trap_incident_result_data]

    build_artifact_list__name = None
    build_artifact_list__label = None
    build_artifact_list__source_data_identifier = None
    build_artifact_list__cef_dictionary = None
    build_artifact_list__contains = None
    build_artifact_list__incident_id = None
    build_artifact_list__count = None
    build_artifact_list__alert_count = None
    build_artifact_list__event_count = None
    build_artifact_list__already_present = None
    build_artifact_list__case_name = None
    build_artifact_list__note_title = None
    build_artifact_list__note_content = None

    ################################################################################
    ## Custom Code Start
    ################################################################################
    ################################################################################

    def _create_enrichment_failure_signal(msg):
        # Synchronous signal artifact (playbook-patterns.md); the next run retries.
        success, message, artifact_id = phantom.add_artifact(
            container=container,
            raw_data={},
            cef_data={
                "message": "TRAP incident {} detail extraction failed: {}".format(incident_id, msg),
                "artifactsCreated": 0,
            },
            label="event",
            name="Enrichment Failed",
            severity="low",
            run_automation=False,
        )
        if not success:
            phantom.error("Failed to create Enrichment Failed artifact: {}".format(message))

    # Collect get_incident result
    result_data = phantom.collect2(
        container=container,
        datapath=[
            "get_trap_incident:action_result.status",
            "get_trap_incident:action_result.data",
        ]
    )

    # The incident id from the container, so the failure paths below have it
    # even when the fetch failed.
    sdi_rows = phantom.collect2(container=container, datapath=["container:source_data_identifier"])
    incident_id = sdi_rows[0][0] if sdi_rows and sdi_rows[0] and sdi_rows[0][0] else "unknown"

    if not result_data or result_data[0][0] != "success":
        msg = "get_incident failed"
        phantom.error(msg)
        phantom.add_note(
            container=container, note_type="general",
            title="TRAP Detail - Error", content=msg
        )
        _create_enrichment_failure_signal(msg)
        return

    # result_data[0][1] is the list of data items; take the first
    incident_list = result_data[0][1]
    if isinstance(incident_list, list) and incident_list:
        incident = incident_list[0]
    elif isinstance(incident_list, dict):
        incident = incident_list
    else:
        msg = "No incident data returned"
        phantom.error(msg)
        phantom.add_note(
            container=container, note_type="general",
            title="TRAP Detail - Error", content=msg
        )
        _create_enrichment_failure_signal(msg)
        return

    import urllib.parse  # local: a save drops module-level imports outside Global Custom Code

    # Headers kept from each email's free-form headers dict, matched without
    # case (casing varies by mail client).
    _WANTED_HEADERS = [
        "To", "Date", "From", "Subject", "Return-Path", "Content-Type",
        "MIME-Version", "Received-SPF", "DKIM-Signature",
        "X-Google-DKIM-Signature",
        "X-MS-Exchange-CrossTenant-OriginalAttributedTenantConnectingIp",
        "In-Reply-To", "Received", "X-PhishAlarm-Sender",
    ]

    def _extract_selected_headers(headers):
        lower_map = {k.lower(): v for k, v in headers.items()}
        result = {}
        for name in _WANTED_HEADERS:
            val = lower_map.get(name.lower())
            if val is not None:
                result[name] = val
        return result

    # Also flat fields on the Sender Email: the artifact search and
    # proofpoint_trap_summary do not show the nested emailHeaders.
    _FLAT_HEADER_FIELDS = (
        ("Received-SPF", "receivedSpf"),
        ("DKIM-Signature", "dkimSignature"),
        ("In-Reply-To", "inReplyTo"),
        ("Received", "received"),
        ("X-PhishAlarm-Sender", "phishAlarmSender"),
    )

    from email.header import decode_header, make_header  # local import, same reason as urllib.parse above

    def _header_value(headers, name):
        # A header with a non-ASCII character can arrive RFC 2047-encoded as a
        # whole (=?utf-8?b?...?=), address included: decode it before reading it.
        for header_name, header_value in (headers or {}).items():
            if str(header_name).lower() == name.lower():
                text = str(header_value or "")
                try:
                    text = str(make_header(decode_header(text)))
                except Exception:
                    pass
                return " ".join(text.split())
        return ""

    def _flat_header_cef(headers):
        flat = {}
        for header_name, cef_name in _FLAT_HEADER_FIELDS:
            value = _header_value(headers, header_name)
            if value:
                flat[cef_name] = value
        return flat

    from email.utils import parseaddr  # local import, same reason as urllib.parse above
    import re

    def _header_address(value):
        # On the appliance X-PhishAlarm-Sender reads `"Name <addr>`, with an
        # unclosed quote, and parseaddr returns the whole text as the address.
        # Take the address inside the last <...> first, else parseaddr's, and
        # keep it only if it is one plain address. An apostrophe is valid before
        # the @ (jean.d'arc@...), so only quotes around the whole address go.
        value = str(value or "")
        bracketed = re.findall(r"<([^<>\s]+)>", value)
        candidate = (bracketed[-1] if bracketed else parseaddr(value)[1]).strip().strip('"')
        if len(candidate) > 1 and candidate[0] == candidate[-1] == "'":
            candidate = candidate[1:-1]
        return candidate if re.fullmatch(r"[^@\s<>\",;]+@[^@\s<>\"',;]+\.[^@\s<>\"',;]+", candidate) else ""

    def _stringify_delivery_time(value):
        # messageDeliveryTime can be a Joda-time object ({"millis": ..., "zone": ...})
        # instead of a string; never put a dict into a CEF field.
        if isinstance(value, dict):
            millis = value.get("millis")
            if isinstance(millis, (int, float)):
                from datetime import datetime as _dt
                return _dt.utcfromtimestamp(millis / 1000.0).strftime("%Y-%m-%dT%H:%M:%SZ")
            return str(value)
        return value or ""

    events = incident.get("events", [])
    phantom.debug("Processing {} events from incident {}".format(len(events), incident.get("id", "?")))

    # proofpoint_trap_excluded_email (email, date, reason, enabled): an address
    # in an enabled row gets no Sender/Recipient Email or Sender Domain and never
    # names the container. Compared without case; a missing list excludes nothing.
    excluded_addresses = set()
    list_ok, list_message, list_rows = phantom.get_list(list_name="proofpoint_trap_excluded_email")
    if list_ok:
        for row in list_rows or []:
            row = list(row or []) + [None] * 4
            address = str(row[0] or "").strip().lower()
            enabled = str(row[3] or "").strip().lower()
            if "@" in address and enabled == "yes":
                excluded_addresses.add(address)
    else:
        phantom.debug("No proofpoint_trap_excluded_email list ({}): every sender counts".format(list_message))
    skipped_addresses = set()

    # Separate dedup sets per role so an address playing both sender and
    # recipient across different alerts gets an artifact for each role,
    # not just whichever one was seen first.
    seen_sender_emails = set()
    seen_recipient_emails = set()
    seen_cc_emails = set()
    seen_reporter_emails = set()
    report_copies_skipped = 0
    seen_domains = set()
    seen_ips = set()
    threat_names = []
    artifacts = []
    id_value = container.get("id")
    # The incident id the connector set on the container.
    sdi_rows = phantom.collect2(container=container, datapath=["container:source_data_identifier"])
    incident_id_val = sdi_rows[0][0] if sdi_rows and sdi_rows[0] and sdi_rows[0][0] else incident.get("id")

    # Incident-level threat URLs (on real incidents hosts holds only url).
    hosts = incident.get("hosts") or {}
    for url_val in hosts.get("url") or []:
        artifacts.append({
            "name": "URL Artifact",
            "description": "Threat URL from incident {}".format(incident_id_val),
            "label": "event",
            "cef": {"requestURL": url_val},
            "cef_types": {"requestURL": ["url"]},
            "run_automation": False,
        })

    for event in events:
        event_id = event.get("id", "")
        emails = event.get("emails", [])
        # An abuse-mailbox report lists the email twice: abuseCopy true is the
        # report, false the reported email. When both are there, the report's
        # sender, recipient and Cc get no artifact, and X-PhishAlarm-Reporter
        # becomes a Recipient Email, role "reporter". When TRAP gives the report
        # alone with an X-PhishAlarm-Sender header (a report from a shared
        # mailbox), that header names the Sender Email and the report is
        # otherwise handled as a report copy. The header also stands in when the
        # reported email's own sender field holds no address (a report of an
        # email sent to a shared mailbox).
        has_reported_email = any((e or {}).get("abuseCopy") is False for e in emails)
        event_header_raw = next((v for v in (_header_value((e or {}).get("headers") or {}, "X-PhishAlarm-Sender")
                                             for e in emails) if _header_address(v)), "")
        event_header_sender = _header_address(event_header_raw)

        for email in emails:
            subject = email.get("subject", "")
            message_id = email.get("messageId", "")
            delivery_time = _stringify_delivery_time(email.get("messageDeliveryTime"))
            headers = email.get("headers") or {}
            report_copy = email.get("abuseCopy") is True and has_reported_email
            raw_header_sender = _header_value(headers, "X-PhishAlarm-Sender")
            header_sender = _header_address(raw_header_sender)
            sender_from_header = (email.get("abuseCopy") is not False and not has_reported_email
                                  and "@" in header_sender)
            treat_as_report = report_copy or sender_from_header

            if treat_as_report:
                if report_copy:
                    report_copies_skipped += 1
                reporter = ""
                for header_name, header_value in headers.items():
                    if str(header_name).lower() == "x-phishalarm-reporter":
                        reporter = str(header_value or "").strip()
                if reporter and reporter.lower() in excluded_addresses:
                    skipped_addresses.add(reporter.lower())
                elif reporter and reporter.lower() not in seen_reporter_emails:
                    seen_reporter_emails.add(reporter.lower())
                    artifacts.append({
                        "name": "Recipient Email",
                        "description": "User who reported alert {} (subject: {})".format(event_id, subject),
                        "label": "event",
                        "cef": {
                            "emailAddress": reporter,
                            "emailRole": "reporter",
                        },
                        "cef_types": {"emailAddress": ["email"]},
                        "run_automation": False,
                    })

            # Sender email
            sender = email.get("sender") or {}
            named_by_header = sender_from_header
            if sender_from_header:
                from_addr = header_sender
            else:
                from_addr = "" if report_copy else sender.get("email", "")
                if email.get("abuseCopy") is False and "@" not in str(from_addr or "") and event_header_sender:
                    from_addr = event_header_sender
                    named_by_header = True
            if from_addr and from_addr.strip().lower() in excluded_addresses:
                skipped_addresses.add(from_addr.strip().lower())
            elif from_addr and from_addr not in seen_sender_emails:
                seen_sender_emails.add(from_addr)
                body_type = email.get("bodyType", "")
                abuse_copy = email.get("abuseCopy")
                abuse_copy_str = "true" if abuse_copy is True else ("false" if abuse_copy is False else "")
                selected_headers = _extract_selected_headers(headers)
                sender_cef = {
                    "emailAddress": from_addr,
                    "emailRole": "sender",
                    "emailSubject": subject,
                    "bodyType": body_type,
                    "messageId": message_id,
                    "deliveryTime": delivery_time,
                    "abuseCopy": abuse_copy_str,
                    "emailHeaders": selected_headers,
                }
                if named_by_header:
                    sender_cef["senderSource"] = "X-PhishAlarm-Sender"
                sender_cef.update(_flat_header_cef(headers))
                if named_by_header and not sender_from_header:
                    sender_cef["phishAlarmSender"] = event_header_raw
                artifacts.append({
                    "name": "Sender Email",
                    "description": "{} from alert {} (subject: {})".format(
                        "Sender named by X-PhishAlarm-Sender" if named_by_header else "Sender", event_id, subject),
                    "label": "event",
                    "cef": sender_cef,
                    "cef_types": {"emailAddress": ["email"], "messageId": ["internet message id"],
                                  "inReplyTo": ["internet message id"]},
                    "run_automation": False,
                })
                # Extract domain from sender
                domain = from_addr.split("@")[-1] if "@" in from_addr else ""
                if domain and domain not in seen_domains:
                    seen_domains.add(domain)
                    artifacts.append({
                        "name": "Sender Domain",
                        "description": "Domain from sender {}".format(from_addr),
                        "label": "event",
                        "cef": {"sourceDnsDomain": domain},
                        "cef_types": {"sourceDnsDomain": ["domain"]},
                        "run_automation": False,
                    })

            # Recipient email
            recipient = email.get("recipient") or {}
            to_addr = "" if treat_as_report else recipient.get("email", "")
            if to_addr and to_addr.strip().lower() in excluded_addresses:
                skipped_addresses.add(to_addr.strip().lower())
            elif to_addr and to_addr not in seen_recipient_emails:
                seen_recipient_emails.add(to_addr)
                artifacts.append({
                    "name": "Recipient Email",
                    "description": "Recipient from alert {} (subject: {})".format(event_id, subject),
                    "label": "event",
                    "cef": {
                        "emailAddress": to_addr,
                        "emailRole": "recipient",
                    },
                    "cef_types": {"emailAddress": ["email"]},
                    "run_automation": False,
                })

            # Threat URL domains, from each email's urls list.
            for url_val in email.get("urls") or []:
                url_domain = urllib.parse.urlparse(url_val).hostname
                if url_domain and url_domain not in seen_domains:
                    seen_domains.add(url_domain)
                    artifacts.append({
                        "name": "Threat Domain",
                        "description": "Domain from URL in alert {} (subject: {})".format(event_id, subject),
                        "label": "event",
                        "cef": {
                            "destinationDnsDomain": url_domain,
                            "url": url_val,
                        },
                        "cef_types": {"destinationDnsDomain": ["domain"], "url": ["url"]},
                        "run_automation": False,
                    })

        # Click IP and event-level threatURL: absent from reported-by-user
        # incidents; kept for incidents from other sources (e.g. Proofpoint TAP).
        threat_url = event.get("threatURL", "")
        if threat_url:
            url_domain = urllib.parse.urlparse(threat_url).hostname
            if url_domain and url_domain not in seen_domains:
                seen_domains.add(url_domain)
                artifacts.append({
                    "name": "Threat Domain",
                    "description": "Domain from threat URL in alert {}".format(event_id),
                    "label": "event",
                    "cef": {
                        "destinationDnsDomain": url_domain,
                        "url": threat_url,
                    },
                    "cef_types": {"destinationDnsDomain": ["domain"], "url": ["url"]},
                    "run_automation": False,
                })

        click_ip = event.get("clickIP", "")
        if click_ip and click_ip not in seen_ips:
            seen_ips.add(click_ip)
            artifacts.append({
                "name": "Click Source IP",
                "description": "IP that clicked threat URL in alert {}".format(event_id),
                "label": "event",
                "cef": {"sourceAddress": click_ip},
                "cef_types": {"sourceAddress": ["ip"]},
                "run_automation": False,
            })

        # An alert from a detection source (e.g. Proofpoint TAP) names its
        # threat; an abuse-mailbox report does not. An attachment record
        # carries no verdict of its own, so a condemned file shows up here.
        # proofpoint_trap_summary prints these beside the CLEAR verdict.
        threat_name = str(event.get("threatname") or event.get("malwareName") or "").strip()
        if threat_name:
            details = [str(event.get(key)) for key in ("category", "source") if event.get(key)]
            threat_label = "{} ({})".format(threat_name, ", ".join(details)) if details else threat_name
            if threat_label not in threat_names:
                threat_names.append(threat_label)

    if report_copies_skipped:
        phantom.debug("{} abuse-mailbox report cop(y/ies): no sender/recipient artifact for them".format(
            report_copies_skipped))
    if skipped_addresses:
        phantom.debug("{} address(es) in proofpoint_trap_excluded_email: no artifact for them".format(
            len(skipped_addresses)))

    # Real TRAP incidents often have no summary or description, and the
    # connector then names the container "TRAP-<id>: No summary" (it lists
    # incidents without their events, so it has no sender yet). Name it after
    # the sender instead: the first sender address, in alert order, that has a
    # Sender Email artifact (so never one in proofpoint_trap_excluded_email).
    # Only that fallback name is replaced, so a real summary or an earlier
    # rename is never overwritten. rename_case applies it; blank changes nothing.
    build_artifact_list__case_name = ""
    fallback_name = "TRAP-{}: No summary".format(incident_id)
    if (container.get("name") or "") == fallback_name:
        candidates = [a["cef"]["emailAddress"] for a in artifacts if a["name"] == "Sender Email"]
        if candidates:
            build_artifact_list__case_name = "TRAP-{}: {}".format(incident_id, candidates[0])
            if len(candidates) > 1:
                build_artifact_list__case_name += " (+{} more)".format(len(candidates) - 1)
        else:
            phantom.debug("No sender outside proofpoint_trap_excluded_email: name stays {!r}".format(fallback_name))

    # Post only what is not on the container yet: a re-run rebuilds the list
    # from the whole incident. "Already there" = same name and identifying
    # value; the same set drops a repeat within this run.
    def _artifact_key(name, cef, sdi):
        if name in ("Sender Email", "Recipient Email"):
            return (name, cef.get("emailAddress"), cef.get("emailRole"))
        if name == "Sender Domain":
            return (name, cef.get("sourceDnsDomain"))
        if name == "Threat Domain":
            return (name, cef.get("destinationDnsDomain"))
        if name == "URL Artifact":
            return (name, cef.get("requestURL"))
        if name == "Click Source IP":
            return (name, cef.get("sourceAddress"))
        return None

    existing_rows = phantom.collect2(
        container=container,
        datapath=[
            "artifact:*.name",
            "artifact:*.source_data_identifier",
            "artifact:*.cef.emailAddress",
            "artifact:*.cef.emailRole",
            "artifact:*.cef.sourceDnsDomain",
            "artifact:*.cef.destinationDnsDomain",
            "artifact:*.cef.requestURL",
            "artifact:*.cef.sourceAddress",
        ],
        scope="all",
    )
    existing_keys = set()
    for row in (existing_rows or []):
        if not row or not row[0]:
            continue
        existing_key = _artifact_key(row[0], {
            "emailAddress": row[2], "emailRole": row[3], "sourceDnsDomain": row[4],
            "destinationDnsDomain": row[5], "requestURL": row[6], "sourceAddress": row[7],
        }, row[1])
        if existing_key is not None:
            existing_keys.add(existing_key)

    new_artifacts = []
    run_keys = set()
    already_present = 0
    for a in artifacts:
        key = _artifact_key(a["name"], a.get("cef", {}), a.get("source_data_identifier"))
        if key is not None:
            if key in run_keys:
                continue
            run_keys.add(key)
            if key in existing_keys:
                already_present += 1
                continue
        new_artifacts.append(a)
    artifacts = new_artifacts

    phantom.debug("Creating {} new artifacts from events ({} already on the container)".format(
        len(artifacts), already_present))

    # Parallel lists, one entry per artifact in the same order.
    # dispatch_artifact_list turns them into one "add artifact" call per
    # artifact, each with the container's source_data_identifier.
    build_artifact_list__name = [a["name"] for a in artifacts]
    build_artifact_list__label = [a.get("label", "event") for a in artifacts]
    build_artifact_list__source_data_identifier = [
        a.get("source_data_identifier") or incident_id_val for a in artifacts
    ]
    build_artifact_list__cef_dictionary = [json.dumps(a.get("cef", {})) for a in artifacts]
    build_artifact_list__contains = [json.dumps(a.get("cef_types", {})) for a in artifacts]
    # The fetched incident's id, and how many new artifacts this run posts --
    # attempted, not confirmed; finalize_detail checks the writes.
    build_artifact_list__incident_id = incident_id_val
    build_artifact_list__count = len(artifacts)
    # Alerts (TRAP "events") this run processed, and the incident's own
    # event_count as TRAP reports it -- the two can differ.
    build_artifact_list__alert_count = len(events)
    build_artifact_list__event_count = incident.get("event_count")
    # Artifacts this run found already on the container and did not post again.
    build_artifact_list__already_present = already_present

    # The detail note: the same content on every run while TRAP reports the
    # same incident, so proofpoint_trap_note_upsert leaves it alone.
    summary = re.sub(r"(?:[a-z][a-z0-9+.-]*://|www\.)[^\s`]*[^\s`,;.)]",
                     lambda m: "`" + m.group(0) + "`", str(incident.get("summary") or "").replace("`", "'"), flags=re.I)
    incident_url = incident.get("incident_url") or ""
    trap_link = "**Open in TRAP:** [incident {}]({})\n".format(incident_id_val, incident_url) if incident_url else ""
    summary_line = "**Summary:** {}\n".format(summary) if summary.strip() and summary != "None" else ""
    build_artifact_list__note_title = "TRAP Detail - Incident {}".format(incident_id_val)
    build_artifact_list__note_content = (
        "# TRAP Incident Detail\n"
        "**Incident ID:** {}\n"
        "{}"
        "{}"
        "**State:** {} | **Score:** {} | **Events:** {}\n"
        "**Alerts:** {}"
    ).format(incident_id_val, trap_link, summary_line, incident.get("state") or "?", incident.get("score") or "?",
             incident.get("event_count") if incident.get("event_count") is not None else "?", len(events))

    # Also saved as run data: the downstream blocks read these keys with
    # phantom.get_run_data().
    for output_key, output_value in (
        ("name", build_artifact_list__name),
        ("label", build_artifact_list__label),
        ("source_data_identifier", build_artifact_list__source_data_identifier),
        ("cef_dictionary", build_artifact_list__cef_dictionary),
        ("contains", build_artifact_list__contains),
        ("incident_id", build_artifact_list__incident_id),
        ("count", build_artifact_list__count),
        ("alert_count", build_artifact_list__alert_count),
        ("event_count", build_artifact_list__event_count),
        ("already_present", build_artifact_list__already_present),
        ("case_name", build_artifact_list__case_name),
        ("note_title", build_artifact_list__note_title),
        ("note_content", build_artifact_list__note_content),
    ):
        phantom.save_run_data(key="build_artifact_list:" + output_key, value=json.dumps(output_value))
    # The incident's TRAP workflow state (new/open/closed) as fetched now;
    # finalize_detail records it on Enrichment Complete, where
    # proofpoint_trap_summary reads it to close a container TRAP has closed.
    phantom.save_run_data(key="build_artifact_list:incident_state", value=json.dumps(incident.get("state")))
    # Threat names of the incident's alerts; finalize_detail records them on
    # Enrichment Complete for proofpoint_trap_summary's verdict line.
    phantom.save_run_data(key="build_artifact_list:threat_names", value=json.dumps(threat_names))

    ################################################################################
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_block_result(key="build_artifact_list__inputs:0:get_trap_incident:action_result.status", value=json.dumps(get_trap_incident_result_item_0))
    phantom.save_block_result(key="build_artifact_list__inputs:1:get_trap_incident:action_result.data", value=json.dumps(get_trap_incident_result_item_1))
    phantom.save_block_result(key="build_artifact_list__inputs:2:container:source_data_identifier", value=json.dumps(source_data_identifier_value))

    phantom.save_block_result(key="build_artifact_list:name", value=json.dumps(build_artifact_list__name))
    phantom.save_block_result(key="build_artifact_list:label", value=json.dumps(build_artifact_list__label))
    phantom.save_block_result(key="build_artifact_list:source_data_identifier", value=json.dumps(build_artifact_list__source_data_identifier))
    phantom.save_block_result(key="build_artifact_list:cef_dictionary", value=json.dumps(build_artifact_list__cef_dictionary))
    phantom.save_block_result(key="build_artifact_list:contains", value=json.dumps(build_artifact_list__contains))
    phantom.save_block_result(key="build_artifact_list:incident_id", value=json.dumps(build_artifact_list__incident_id))
    phantom.save_block_result(key="build_artifact_list:count", value=json.dumps(build_artifact_list__count))
    phantom.save_block_result(key="build_artifact_list:alert_count", value=json.dumps(build_artifact_list__alert_count))
    phantom.save_block_result(key="build_artifact_list:event_count", value=json.dumps(build_artifact_list__event_count))
    phantom.save_block_result(key="build_artifact_list:already_present", value=json.dumps(build_artifact_list__already_present))
    phantom.save_block_result(key="build_artifact_list:case_name", value=json.dumps(build_artifact_list__case_name))
    phantom.save_block_result(key="build_artifact_list:note_title", value=json.dumps(build_artifact_list__note_title))
    phantom.save_block_result(key="build_artifact_list:note_content", value=json.dumps(build_artifact_list__note_content))

    phantom.save_block_result(key="build_artifact_list_called", value="True")

    rename_case(container=container)

    return


@phantom.playbook_block()
def finalize_detail(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("finalize_detail() called")

    ################################################################################
    # Check the writes; create TRAP Run State once; build Enrichment Complete, or 
    # record the failure and stop.
    ################################################################################

    source_data_identifier_value = container.get("source_data_identifier", None)
    dispatch_artifact_list_result_data = phantom.collect2(container=container, datapath=["dispatch_artifact_list:action_result.status","dispatch_artifact_list:action_result.message"], action_results=results)
    build_artifact_list__alert_count = json.loads(_ if (_ := phantom.get_run_data(key="build_artifact_list:alert_count")) != "" else "null")  # pylint: disable=used-before-assignment
    build_artifact_list__event_count = json.loads(_ if (_ := phantom.get_run_data(key="build_artifact_list:event_count")) != "" else "null")  # pylint: disable=used-before-assignment
    build_artifact_list__already_present = json.loads(_ if (_ := phantom.get_run_data(key="build_artifact_list:already_present")) != "" else "null")  # pylint: disable=used-before-assignment

    dispatch_artifact_list_result_item_0 = [item[0] for item in dispatch_artifact_list_result_data]
    dispatch_artifact_list_result_message = [item[1] for item in dispatch_artifact_list_result_data]

    finalize_detail__cef_dictionary = None

    ################################################################################
    ## Custom Code Start
    ################################################################################
    ################################################################################

    sdi_rows = phantom.collect2(container=container, datapath=["container:source_data_identifier"])
    incident_id = sdi_rows[0][0] if sdi_rows and sdi_rows[0] and sdi_rows[0][0] else "unknown"

    # A failed platform write must not read as success. If an event artifact
    # write failed, record an error note and an "Enrichment Failed" artifact
    # through the synchronous API (which runs as the playbook, not through the
    # asset whose write just failed) and stop before "Enrichment Complete": the
    # next run retries. build_artifact_list skips what is already on the
    # container, but a concurrent run can post the same artifact between that
    # check and this run's write; SOAR rejects it with "already exists", which
    # is expected, not a failed write.
    event_rows = phantom.collect2(
        container=container,
        datapath=[
            "dispatch_artifact_list:action_result.status",
            "dispatch_artifact_list:action_result.message",
        ],
    )
    event_statuses = [row[0] for row in (event_rows or []) if row]
    failed_event_writes = sum(
        1 for row in (event_rows or [])
        if row and row[0] == "failed" and "already exists" not in str(row[1] or "").lower()
    )
    if failed_event_writes:
        msg = "TRAP incident {}: {} of {} event-artifact writes failed".format(
            incident_id, failed_event_writes, len(event_statuses))
        phantom.error(msg)
        phantom.add_note(container=container, note_type="general", title="TRAP Detail - Write failures", content=msg)
        signal_ok, signal_message, _signal_id = phantom.add_artifact(
            container=container,
            raw_data={},
            cef_data={"message": msg, "artifactsCreated": 0},
            label="event",
            name="Enrichment Failed",
            severity="low",
            run_automation=False,
        )
        if not signal_ok:
            phantom.error("Failed to create Enrichment Failed artifact: {}".format(signal_message))
        return

    # TRAP Run State: one per case, holding the state later UC2 playbooks keep
    # (linkComment: the TRAP comment linking this case, "none" until posted).
    # Created here once, through the synchronous API, at severity low.
    names = [row[0] for row in (phantom.collect2(container=container, datapath=["artifact:*.name"], scope="all") or [])
             if row and row[0]]
    if "TRAP Run State" not in names:
        state_ok, state_message, _state_id = phantom.add_artifact(
            container=container,
            raw_data={},
            cef_data={"linkComment": "none"},
            label="event",
            name="TRAP Run State",
            severity="low",
            identifier="{}-run-state".format(incident_id),
            run_automation=False,
        )
        if not state_ok:
            phantom.error("Failed to create TRAP Run State artifact: {}".format(state_message))

    # Enrichment Complete holds the incident's facts only, no per-run counter:
    # every run builds the same content while TRAP reports the same incident,
    # so "add artifact" returns the existing one; a new TRAP state, alert or
    # threat adds one, which records the change. "add artifact" has no
    # description parameter, so the summary goes into cef.message.
    # incidentState: the incident's TRAP state when this run fetched it.
    # threatNames: the alerts' threat names, "; "-joined ("" when none).
    alert_count = json.loads(phantom.get_run_data(key="build_artifact_list:alert_count") or "null")
    event_count = json.loads(phantom.get_run_data(key="build_artifact_list:event_count") or "null")
    incident_state = json.loads(phantom.get_run_data(key="build_artifact_list:incident_state") or "null")
    threat_names = json.loads(phantom.get_run_data(key="build_artifact_list:threat_names") or "null") or []
    finalize_detail__cef_dictionary = json.dumps({
        "message": "TRAP incident {} detail extraction complete.".format(incident_id),
        "alertCount": alert_count,
        "eventCount": event_count,
        "incidentState": incident_state or "",
        "threatNames": "; ".join(threat_names),
    })

    # Also saved as run data: dispatch_enrichment_complete reads this key.
    phantom.save_run_data(key="finalize_detail:cef_dictionary", value=json.dumps(finalize_detail__cef_dictionary))

    ################################################################################
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_block_result(key="finalize_detail__inputs:0:container:source_data_identifier", value=json.dumps(source_data_identifier_value))
    phantom.save_block_result(key="finalize_detail__inputs:1:dispatch_artifact_list:action_result.status", value=json.dumps(dispatch_artifact_list_result_item_0))
    phantom.save_block_result(key="finalize_detail__inputs:2:dispatch_artifact_list:action_result.message", value=json.dumps(dispatch_artifact_list_result_message))
    phantom.save_block_result(key="finalize_detail__inputs:3:build_artifact_list:custom_function:alert_count", value=json.dumps(build_artifact_list__alert_count))
    phantom.save_block_result(key="finalize_detail__inputs:4:build_artifact_list:custom_function:event_count", value=json.dumps(build_artifact_list__event_count))
    phantom.save_block_result(key="finalize_detail__inputs:5:build_artifact_list:custom_function:already_present", value=json.dumps(build_artifact_list__already_present))

    phantom.save_block_result(key="finalize_detail:cef_dictionary", value=json.dumps(finalize_detail__cef_dictionary))

    phantom.save_block_result(key="finalize_detail_called", value="True")

    dispatch_enrichment_complete(container=container)

    return


@phantom.playbook_block()
def dispatch_artifact_list(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("dispatch_artifact_list() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Create the event artifacts, one add artifact call per artifact.
    ################################################################################

    id_value = container.get("id", None)
    build_artifact_list__name = json.loads(_ if (_ := phantom.get_run_data(key="build_artifact_list:name")) != "" else "null")  # pylint: disable=used-before-assignment
    build_artifact_list__label = json.loads(_ if (_ := phantom.get_run_data(key="build_artifact_list:label")) != "" else "null")  # pylint: disable=used-before-assignment
    build_artifact_list__contains = json.loads(_ if (_ := phantom.get_run_data(key="build_artifact_list:contains")) != "" else "null")  # pylint: disable=used-before-assignment
    build_artifact_list__cef_dictionary = json.loads(_ if (_ := phantom.get_run_data(key="build_artifact_list:cef_dictionary")) != "" else "null")  # pylint: disable=used-before-assignment
    build_artifact_list__source_data_identifier = json.loads(_ if (_ := phantom.get_run_data(key="build_artifact_list:source_data_identifier")) != "" else "null")  # pylint: disable=used-before-assignment

    parameters = []

    if build_artifact_list__source_data_identifier is not None:
        parameters.append({
            "name": build_artifact_list__name,
            "label": build_artifact_list__label,
            "contains": build_artifact_list__contains,
            "container_id": id_value,
            "cef_dictionary": build_artifact_list__cef_dictionary,
            "source_data_identifier": build_artifact_list__source_data_identifier,
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################
    ################################################################################

    # One parameter set per artifact (the VPE builds one set of whole lists).
    # Here because a save keeps Custom Code; reads the run data, not the
    # generated variables.
    artifact_names = json.loads(phantom.get_run_data(key="build_artifact_list:name") or "null") or []
    artifact_labels = json.loads(phantom.get_run_data(key="build_artifact_list:label") or "null") or []
    artifact_sdis = json.loads(phantom.get_run_data(key="build_artifact_list:source_data_identifier") or "null") or []
    artifact_cefs = json.loads(phantom.get_run_data(key="build_artifact_list:cef_dictionary") or "null") or []
    artifact_contains = json.loads(phantom.get_run_data(key="build_artifact_list:contains") or "null") or []

    # determine_contains False: "add artifact" otherwise guesses a data type
    # for every CEF field not listed in "contains" (it tagged emailRole
    # "recipient" and email subjects as domain / host name). build_artifact_list
    # lists every field that has a data type; the rest stay untyped.
    parameters = []
    for index, artifact_name in enumerate(artifact_names):
        parameters.append({
            "name": artifact_name,
            "label": artifact_labels[index],
            "contains": artifact_contains[index],
            "determine_contains": False,
            "container_id": container.get("id"),
            "cef_dictionary": artifact_cefs[index],
            "source_data_identifier": artifact_sdis[index],
        })

    if not parameters:
        # Nothing to create (every artifact is already on the case):
        # phantom.act() has nothing to dispatch, so go straight on.
        phantom.debug("No event artifacts to create this run")
        finalize_detail(container=container)
        return

    ################################################################################
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("add artifact", parameters=parameters, name="dispatch_artifact_list", assets=["soar8"], callback=finalize_detail)

    return


@phantom.playbook_block()
def dispatch_enrichment_complete(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("dispatch_enrichment_complete() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Create the Enrichment Complete artifact.
    ################################################################################

    id_value = container.get("id", None)
    source_data_identifier_value = container.get("source_data_identifier", None)
    finalize_detail__cef_dictionary = json.loads(_ if (_ := phantom.get_run_data(key="finalize_detail:cef_dictionary")) != "" else "null")  # pylint: disable=used-before-assignment

    parameters = []

    if source_data_identifier_value is not None:
        parameters.append({
            "name": "Enrichment Complete",
            "label": "event",
            "container_id": id_value,
            "cef_dictionary": finalize_detail__cef_dictionary,
            "source_data_identifier": source_data_identifier_value,
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # No automation on this artifact. proofpoint_trap_orchestrator calls this
    # playbook and then, once it has finished, proofpoint_trap_attachments,
    # proofpoint_trap_triage and proofpoint_trap_summary; an artifact running
    # automation here would start a second orchestrator run alongside the
    # first, and those playbooks would again run side by side.
    # No data-type guessing either: none of this artifact's fields has one
    # (it tagged incidentState "new" as domain / host name).
    for params in parameters:
        params["run_automation"] = False
        params["determine_contains"] = False

    # While TRAP reports the same incident an identical Enrichment Complete is
    # already on the case, and "add artifact" would fail with "artifact already
    # exists" (HTTP 400). Skip the write then, and go on to the detail note.
    fields = ("message", "alertCount", "eventCount", "incidentState", "threatNames")
    wanted = json.loads(json.loads(phantom.get_run_data(key="finalize_detail:cef_dictionary") or '""') or "{}")
    rows = phantom.collect2(
        container=container,
        datapath=["artifact:*.name"] + ["artifact:*.cef.{}".format(field) for field in fields],
        scope="all",
    )
    as_text = lambda value: "" if value is None else str(value)
    if any(row and row[0] == "Enrichment Complete"
           and all(as_text(row[i + 1]) == as_text(wanted.get(field)) for i, field in enumerate(fields))
           for row in rows or []):
        phantom.debug("Enrichment Complete unchanged: not written again")
        detail_note(container=container)
        return

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("add artifact", parameters=parameters, name="dispatch_enrichment_complete", assets=["soar8"], callback=detail_note)

    return


@phantom.playbook_block()
def rename_case(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("rename_case() called")

    ################################################################################
    # Name a case TRAP left without a summary after its sender (shared custom function; 
    # blank changes nothing).
    ################################################################################

    id_value = container.get("id", None)
    build_artifact_list__case_name = json.loads(_ if (_ := phantom.get_run_data(key="build_artifact_list:case_name")) != "" else "null")  # pylint: disable=used-before-assignment

    parameters = []

    parameters.append({
        "name": build_artifact_list__case_name,
        "tags": None,
        "label": None,
        "owner": None,
        "status": None,
        "severity": None,
        "input_json": None,
        "description": None,
        "sensitivity": None,
        "container_input": id_value,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="local/container_update", parameters=parameters, name="rename_case", callback=dispatch_artifact_list)

    return


@phantom.playbook_block()
def detail_note(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("detail_note() called")

    ################################################################################
    # Write the detail note, updated in place (shared custom function).
    ################################################################################

    id_value = container.get("id", None)
    build_artifact_list__note_title = json.loads(_ if (_ := phantom.get_run_data(key="build_artifact_list:note_title")) != "" else "null")  # pylint: disable=used-before-assignment
    build_artifact_list__note_content = json.loads(_ if (_ := phantom.get_run_data(key="build_artifact_list:note_content")) != "" else "null")  # pylint: disable=used-before-assignment

    parameters = []

    parameters.append({
        "title": build_artifact_list__note_title,
        "content": build_artifact_list__note_content,
        "container_id": id_value,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="local/proofpoint_trap_note_upsert", parameters=parameters, name="detail_note")

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################
    ################################################################################

    # Surface a failed Enrichment Complete write instead of letting the run
    # read as a clean success; the next run writes it again.
    signal_rows = phantom.collect2(
        container=container,
        datapath=[
            "dispatch_enrichment_complete:action_result.status",
            "dispatch_enrichment_complete:action_result.message",
        ],
    )
    signal_failed = [
        row for row in (signal_rows or [])
        if row and row[0] == "failed" and "already exists" not in str(row[1] or "").lower()
    ]
    if signal_failed:
        msg = "Enrichment Complete signal write failed; a later PB1 run can redo the enrichment"
        phantom.error(msg)
        phantom.add_note(container=container, note_type="general", title="TRAP Detail - Write failures", content=msg)

    ################################################################################
    ################################################################################
    ## Custom Code End
    ################################################################################

    return

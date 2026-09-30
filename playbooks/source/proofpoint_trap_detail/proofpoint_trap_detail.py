"""
Automation playbook (PB1) for label proofpoint_trap, left inactive: proofpoint_trap_orchestrator runs it first. Fetches the TRAP incident with its events, downloads each event&#39;s original email, and creates the derived artifacts (sender/recipient emails, domains, threat URLs, click IPs, MIME bodies), a detail note linking to the incident in TRAP, and a final Enrichment Complete artifact. Creates no sender artifact for an address in the custom list proofpoint_trap_excluded_senders, renames a container TRAP gave no summary after its first remaining sender, and on the incident&#39;s first enrichment comments on the TRAP incident with a link to the SOAR case. A failed fetch or platform write adds an error note and an Enrichment Failed artifact instead, so a later run can retry. Assets are selected in each action block, never in code, so an importer can point them at their own asset names.
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'check_reentry' block
    check_reentry(container=container)

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

    phantom.act("get incident", parameters=parameters, name="get_trap_incident", assets=["proofpoint_trap_mock"], callback=dispatch_mime_download)

    return


@phantom.playbook_block()
def build_artifact_list(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("build_artifact_list() called")

    ################################################################################
    # Build the artifacts to create from the incident's events and emails.
    ################################################################################

    source_data_identifier_value = container.get("source_data_identifier", None)
    get_trap_incident_result_data = phantom.collect2(container=container, datapath=["get_trap_incident:action_result.status","get_trap_incident:action_result.data"], action_results=results)
    dispatch_mime_download_result_data = phantom.collect2(container=container, datapath=["dispatch_mime_download:action_result.status","dispatch_mime_download:action_result.data.*.event_id","dispatch_mime_download:action_result.data.*.vault_id","dispatch_mime_download:action_result.data.*.file_name"], action_results=results)

    get_trap_incident_result_item_0 = [item[0] for item in get_trap_incident_result_data]
    get_trap_incident_result_item_1 = [item[1] for item in get_trap_incident_result_data]
    dispatch_mime_download_result_item_0 = [item[0] for item in dispatch_mime_download_result_data]
    dispatch_mime_download_result_item_1 = [item[1] for item in dispatch_mime_download_result_data]
    dispatch_mime_download_result_item_2 = [item[2] for item in dispatch_mime_download_result_data]
    dispatch_mime_download_result_item_3 = [item[3] for item in dispatch_mime_download_result_data]

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

    ################################################################################
    ## Custom Code Start
    ################################################################################
    ################################################################################

    def _create_enrichment_failure_signal(msg):
        # Synchronous signal artifact, no asset; SOAR generates the identifier, so a re-run can add a duplicate.
        # Named "Enrichment Failed", not "Enrichment Complete": check_reentry only counts the latter, so a
        # later run can retry.
        success, message, artifact_id = phantom.add_artifact(
            container=container,
            raw_data={},
            cef_data={
                "message": "TRAP incident {} detail extraction failed: {}".format(incident_id, msg),
                "artifactsCreated": 0,
            },
            label="enrichment_failed",
            name="Enrichment Failed",
            severity="low",
            run_automation=False,
        )
        if not success:
            phantom.error("Failed to create enrichment_failed artifact: {}".format(message))

    # Collect get_incident result
    result_data = phantom.collect2(
        container=container,
        datapath=[
            "get_trap_incident:action_result.status",
            "get_trap_incident:action_result.data",
        ]
    )

    # incident_id from the container's own native source_data_identifier
    # field, independent of whether the fetch below succeeded, so the
    # failure-signal paths still have a real ID for their message/SDI
    # instead of "unknown".
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

    import urllib.parse  # local: each VPE code block is compiled on its own, so a module-level import is not visible

    # Headers is a free-form dict per email: pick the wanted ones case-insensitively, since real casing
    # varies ("MIME-Version", not "Mime-Version").
    _WANTED_HEADERS = [
        "To", "Date", "From", "Subject", "Return-Path", "Content-Type",
        "MIME-Version", "Received-SPF", "DKIM-Signature",
        "X-Google-DKIM-Signature",
        "X-MS-Exchange-CrossTenant-OriginalAttributedTenantConnectingIp",
    ]

    def _extract_selected_headers(headers):
        lower_map = {k.lower(): v for k, v in headers.items()}
        result = {}
        for name in _WANTED_HEADERS:
            val = lower_map.get(name.lower())
            if val is not None:
                result[name] = val
        return result

    def _stringify_delivery_time(value):
        # messageDeliveryTime can arrive as a Joda-time-style object ({"millis": ..., "zone": ...}) instead of
        # a string; stringify it so no raw dict ends up in a CEF field.
        if isinstance(value, dict):
            millis = value.get("millis")
            if isinstance(millis, (int, float)):
                from datetime import datetime as _dt
                return _dt.utcfromtimestamp(millis / 1000.0).strftime("%Y-%m-%dT%H:%M:%SZ")
            return str(value)
        return value or ""

    events = incident.get("events", [])
    phantom.debug("Processing {} events from incident {}".format(len(events), incident.get("id", "?")))

    # Sender addresses the operator wants left out: the custom list
    # proofpoint_trap_excluded_senders, one address per row, compared without
    # case (e.g. a mailbox present on every incident). An address in it gets
    # no Sender Email artifact, gives no Sender Domain, and never names the
    # container. A missing or empty list excludes nothing.
    excluded_senders = set()
    list_ok, list_message, list_rows = phantom.get_list(list_name="proofpoint_trap_excluded_senders")
    if list_ok:
        for row in list_rows or []:
            for value in row or []:
                if value and "@" in str(value):
                    excluded_senders.add(str(value).strip().lower())
    else:
        phantom.debug("No proofpoint_trap_excluded_senders list ({}): every sender counts".format(list_message))
    skipped_senders = set()

    # Separate dedup sets per role so an address playing both sender and
    # recipient across different alerts gets an artifact for each role,
    # not just whichever one was seen first.
    seen_sender_emails = set()
    seen_recipient_emails = set()
    seen_cc_emails = set()
    seen_domains = set()
    seen_ips = set()
    artifacts = []
    id_value = container.get("id")
    # incident_id from the container's own native source_data_identifier
    # field (set by the connector at ingestion), not re-derived from the
    # fetched incident's own "id" field -- same value, one fewer redundant
    # re-parse of the API response.
    sdi_rows = phantom.collect2(container=container, datapath=["container:source_data_identifier"])
    incident_id_val = sdi_rows[0][0] if sdi_rows and sdi_rows[0] and sdi_rows[0][0] else incident.get("id")

    # Incident-level (not per-event) threat URLs. hosts only ever carries `url`.
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

    # MIME Body artifacts. A failed or empty download means fewer artifacts, not a failed extraction.
    mime_status_rows = phantom.collect2(
        container=container,
        datapath=["dispatch_mime_download:action_result.status"],
    )
    mime_status = mime_status_rows[0][0] if mime_status_rows and mime_status_rows[0] else "failed"

    if mime_status == "success":
        mime_rows = phantom.collect2(
            container=container,
            datapath=[
                "dispatch_mime_download:action_result.data.*.event_id",
                "dispatch_mime_download:action_result.data.*.vault_id",
                "dispatch_mime_download:action_result.data.*.file_name",
            ],
        )
        # MIME Body artifacts already on the container (from an earlier run, or
        # built by proofpoint_trap_recheck for a new event) are dropped by the
        # "already on the container" filter below, by source_data_identifier.
        for row in (mime_rows or []):
            mime_event_id, vault_id, file_name = row[0], row[1], row[2]
            if not vault_id:
                continue
            artifacts.append({
                "name": "MIME Body",
                "description": "Raw MIME body from incident {} event {}".format(incident_id_val, mime_event_id),
                "label": "event",
                "cef": {"vaultId": vault_id, "fileName": file_name},
                "cef_types": {"vaultId": ["vault id"]},
                "run_automation": False,
                # Per-event SDI, not the shared incident_id_val: proofpoint_trap_attachments parses
                # "trap-{incident}-mime-{event}" back out of it to recover the event id.
                "source_data_identifier": "trap-{}-mime-{}".format(incident_id_val, mime_event_id),
            })
    else:
        phantom.debug(
            "MIME download for incident {} did not succeed ({}) -- no MIME "
            "Body artifacts this run".format(incident_id_val, mime_status)
        )

    for event in events:
        event_id = event.get("id", "")
        emails = event.get("emails", [])

        for email in emails:
            subject = email.get("subject", "")
            message_id = email.get("messageId", "")
            delivery_time = _stringify_delivery_time(email.get("messageDeliveryTime"))
            headers = email.get("headers") or {}

            # Sender email
            sender = email.get("sender") or {}
            from_addr = sender.get("email", "")
            if from_addr and from_addr.strip().lower() in excluded_senders:
                skipped_senders.add(from_addr.strip().lower())
            elif from_addr and from_addr not in seen_sender_emails:
                seen_sender_emails.add(from_addr)
                body_type = email.get("bodyType", "")
                abuse_copy = email.get("abuseCopy")
                abuse_copy_str = "true" if abuse_copy is True else ("false" if abuse_copy is False else "")
                selected_headers = _extract_selected_headers(headers)
                artifacts.append({
                    "name": "Sender Email",
                    "description": "Sender from alert {} (subject: {})".format(event_id, subject),
                    "label": "event",
                    "cef": {
                        "emailAddress": from_addr,
                        "emailRole": "sender",
                        "emailSubject": subject,
                        "bodyType": body_type,
                        "messageId": message_id,
                        "deliveryTime": delivery_time,
                        "abuseCopy": abuse_copy_str,
                        "emailHeaders": selected_headers,
                    },
                    "cef_types": {"emailAddress": ["email"]},
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
            to_addr = recipient.get("email", "")
            if to_addr and to_addr not in seen_recipient_emails:
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

            # Cc: best-effort from the raw headers. The get-incident response has no structured cc field; real cc
            # data is only in the raw MIME, which proofpoint_trap_attachments parses.
            cc_raw = headers.get("Cc") or headers.get("CC") or headers.get("cc") or ""
            for cc_addr in [a.strip() for a in cc_raw.split(",") if a.strip()]:
                if cc_addr not in seen_cc_emails:
                    seen_cc_emails.add(cc_addr)
                    artifacts.append({
                        "name": "Recipient Email",
                        "description": "Cc recipient from alert {} (subject: {})".format(event_id, subject),
                        "label": "event",
                        "cef": {
                            "emailAddress": cc_addr,
                            "emailRole": "cc",
                        },
                        "cef_types": {"emailAddress": ["email"]},
                        "run_automation": False,
                    })

            # Threat URL domains: the per-email `urls` list.
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
                        "cef_types": {"destinationDnsDomain": ["domain"]},
                        "run_automation": False,
                    })

        # Click IP / event-level threatURL: absent on "reported by user" incidents; kept as harmless no-ops
        # for other incident sources.
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
                    "cef_types": {"destinationDnsDomain": ["domain"]},
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

    if skipped_senders:
        phantom.debug("{} sender address(es) in proofpoint_trap_excluded_senders: no artifact for them".format(
            len(skipped_senders)))

    # Real TRAP incidents often have no summary or description, and the
    # connector then names the container "TRAP-<id>: No summary" (it lists
    # incidents without their events, so it has no sender yet). Name it after
    # the sender instead: the first sender address, in alert order, that has a
    # Sender Email artifact (so never one in proofpoint_trap_excluded_senders).
    # Only that fallback name is replaced, so a real summary or an earlier
    # rename is never overwritten.
    fallback_name = "TRAP-{}: No summary".format(incident_id)
    if (container.get("name") or "") == fallback_name:
        candidates = [a["cef"]["emailAddress"] for a in artifacts if a["name"] == "Sender Email"]
        if candidates:
            new_name = "TRAP-{}: {}".format(incident_id, candidates[0])
            if len(candidates) > 1:
                new_name += " (+{} more)".format(len(candidates) - 1)
            rename = phantom.requests.post(
                uri=phantom.build_phantom_rest_url("container", container.get("id")),
                data=json.dumps({"name": new_name}),
                verify=False,
            )
            if rename.status_code < 300:
                phantom.debug("Container renamed to {!r}".format(new_name))
            else:
                phantom.error("Could not rename the container to {!r} (HTTP {}): {}".format(
                    new_name, rename.status_code, rename.text[:200]))
        else:
            phantom.debug("No sender outside proofpoint_trap_excluded_senders: name stays {!r}".format(fallback_name))

    # Post only what is not on the container yet. A re-run (proofpoint_trap_recheck
    # flags a changed incident, usually one that gained alerts) rebuilds the list
    # from the whole incident; without this it re-posted every artifact each
    # time, hundreds on a large incident, each one an "add artifact" action that
    # SOAR then rejected as a duplicate -- or kept twice when the content
    # differed slightly (MIME Body built by both this playbook and
    # proofpoint_trap_recheck). An artifact is "already there" when one with the
    # same name and the same identifying value exists; the same set also drops a
    # repeat within this run (e.g. a URL listed twice in hosts.url).
    def _artifact_key(name, cef, sdi):
        if name == "MIME Body":
            return (name, sdi)
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
    # artifact. Every artifact uses the container's source_data_identifier
    # except MIME Body, which carries its own per-event one
    # (proofpoint_trap_attachments parses the event id back out of it).
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

    # Also saved as run data: the downstream blocks read these keys with
    # phantom.get_run_data() in their own custom code.
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
    ):
        phantom.save_run_data(key="build_artifact_list:" + output_key, value=json.dumps(output_value))

    ################################################################################
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_block_result(key="build_artifact_list__inputs:0:get_trap_incident:action_result.status", value=json.dumps(get_trap_incident_result_item_0))
    phantom.save_block_result(key="build_artifact_list__inputs:1:get_trap_incident:action_result.data", value=json.dumps(get_trap_incident_result_item_1))
    phantom.save_block_result(key="build_artifact_list__inputs:2:container:source_data_identifier", value=json.dumps(source_data_identifier_value))
    phantom.save_block_result(key="build_artifact_list__inputs:3:dispatch_mime_download:action_result.status", value=json.dumps(dispatch_mime_download_result_item_0))
    phantom.save_block_result(key="build_artifact_list__inputs:4:dispatch_mime_download:action_result.data.*.event_id", value=json.dumps(dispatch_mime_download_result_item_1))
    phantom.save_block_result(key="build_artifact_list__inputs:5:dispatch_mime_download:action_result.data.*.vault_id", value=json.dumps(dispatch_mime_download_result_item_2))
    phantom.save_block_result(key="build_artifact_list__inputs:6:dispatch_mime_download:action_result.data.*.file_name", value=json.dumps(dispatch_mime_download_result_item_3))

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

    phantom.save_block_result(key="build_artifact_list_called", value="True")

    dispatch_artifact_list(container=container)

    return


@phantom.playbook_block()
def prepare_detail_note(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("prepare_detail_note() called")

    ################################################################################
    # Build the detail note's title and content.
    ################################################################################

    get_trap_incident_result_data = phantom.collect2(container=container, datapath=["get_trap_incident:action_result.data.*.summary","get_trap_incident:action_result.data.*.event_count","get_trap_incident:action_result.data.*.score","get_trap_incident:action_result.data.*.state"], action_results=results)

    get_trap_incident_result_item_0 = [item[0] for item in get_trap_incident_result_data]
    get_trap_incident_result_item_1 = [item[1] for item in get_trap_incident_result_data]
    get_trap_incident_result_item_2 = [item[2] for item in get_trap_incident_result_data]
    get_trap_incident_result_item_3 = [item[3] for item in get_trap_incident_result_data]

    prepare_detail_note__note_title = None
    prepare_detail_note__note_content = None

    ################################################################################
    ## Custom Code Start
    ################################################################################
    ################################################################################

    incident_id = json.loads(phantom.get_run_data(key="build_artifact_list:incident_id") or '"unknown"')
    artifact_count = json.loads(phantom.get_run_data(key="build_artifact_list:count") or "0")
    already_present = json.loads(phantom.get_run_data(key="build_artifact_list:already_present") or "0")
    alert_count = json.loads(phantom.get_run_data(key="build_artifact_list:alert_count") or "null")

    # Read without action_results: this block also runs when
    # dispatch_artifact_list had nothing to create, and then there are no
    # callback results to narrow by.
    result_data = phantom.collect2(
        container=container,
        datapath=[
            "get_trap_incident:action_result.data.*.summary",
            "get_trap_incident:action_result.data.*.event_count",
            "get_trap_incident:action_result.data.*.score",
            "get_trap_incident:action_result.data.*.state",
        ]
    )

    summary = result_data[0][0] if result_data else "?"
    event_count = result_data[0][1] if result_data else "?"
    score = result_data[0][2] if result_data else "?"
    state = result_data[0][3] if result_data else "?"

    # The incident's page in the TRAP web UI (connector 1.0.37+); omitted when absent.
    url_rows = phantom.collect2(container=container, datapath=["get_trap_incident:action_result.data.*.incident_url"])
    incident_url = url_rows[0][0] if url_rows and url_rows[0] and url_rows[0][0] else ""
    trap_link = "**Open in TRAP:** [incident {}]({})\n".format(incident_id, incident_url) if incident_url else ""

    prepare_detail_note__note_title = "TRAP Detail - Incident {}".format(incident_id)
    prepare_detail_note__note_content = (
        "# TRAP Incident Detail\n"
        "**Incident ID:** {}\n"
        "{}"
        "**Summary:** {}\n"
        "**State:** {} | **Score:** {} | **Events:** {}\n"
        "**Alerts processed:** {}\n"
        "**Artifacts from events:** {} new, {} already on the container\n\n"
        "Event artifacts (emails, domains, IPs) have been created on this container."
    ).format(incident_id, trap_link, summary, state, score, event_count,
             alert_count if alert_count is not None else "?", artifact_count, already_present)

    # Also saved as run data: dispatch_detail_note reads these keys.
    phantom.save_run_data(key="prepare_detail_note:note_title", value=json.dumps(prepare_detail_note__note_title))
    phantom.save_run_data(key="prepare_detail_note:note_content", value=json.dumps(prepare_detail_note__note_content))

    ################################################################################
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_block_result(key="prepare_detail_note__inputs:0:get_trap_incident:action_result.data.*.summary", value=json.dumps(get_trap_incident_result_item_0))
    phantom.save_block_result(key="prepare_detail_note__inputs:1:get_trap_incident:action_result.data.*.event_count", value=json.dumps(get_trap_incident_result_item_1))
    phantom.save_block_result(key="prepare_detail_note__inputs:2:get_trap_incident:action_result.data.*.score", value=json.dumps(get_trap_incident_result_item_2))
    phantom.save_block_result(key="prepare_detail_note__inputs:3:get_trap_incident:action_result.data.*.state", value=json.dumps(get_trap_incident_result_item_3))

    phantom.save_block_result(key="prepare_detail_note:note_title", value=json.dumps(prepare_detail_note__note_title))
    phantom.save_block_result(key="prepare_detail_note:note_content", value=json.dumps(prepare_detail_note__note_content))

    phantom.save_block_result(key="prepare_detail_note_called", value="True")

    dispatch_detail_note(container=container)

    return


@phantom.playbook_block()
def dispatch_detail_note(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("dispatch_detail_note() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Add the detail note to the container.
    ################################################################################

    prepare_detail_note__note_title = json.loads(_ if (_ := phantom.get_run_data(key="prepare_detail_note:note_title")) != "" else "null")  # pylint: disable=used-before-assignment
    prepare_detail_note__note_content = json.loads(_ if (_ := phantom.get_run_data(key="prepare_detail_note:note_content")) != "" else "null")  # pylint: disable=used-before-assignment

    parameters = []

    if prepare_detail_note__note_title is not None:
        parameters.append({
            "title": prepare_detail_note__note_title,
            "content": prepare_detail_note__note_content,
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("add note", parameters=parameters, name="dispatch_detail_note", assets=["soar8"], callback=finalize_detail)

    return


@phantom.playbook_block()
def finalize_detail(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("finalize_detail() called")

    ################################################################################
    # Check the event-artifact and note writes; on success build the Enrichment Complete 
    # artifact, on a failure record it and stop.
    ################################################################################

    source_data_identifier_value = container.get("source_data_identifier", None)
    dispatch_detail_note_result_data = phantom.collect2(container=container, datapath=["dispatch_detail_note:action_result.status"], action_results=results)
    dispatch_artifact_list_result_data = phantom.collect2(container=container, datapath=["dispatch_artifact_list:action_result.status","dispatch_artifact_list:action_result.message"], action_results=results)
    check_reentry__run_index = json.loads(_ if (_ := phantom.get_run_data(key="check_reentry:run_index")) != "" else "null")  # pylint: disable=used-before-assignment
    build_artifact_list__alert_count = json.loads(_ if (_ := phantom.get_run_data(key="build_artifact_list:alert_count")) != "" else "null")  # pylint: disable=used-before-assignment
    build_artifact_list__event_count = json.loads(_ if (_ := phantom.get_run_data(key="build_artifact_list:event_count")) != "" else "null")  # pylint: disable=used-before-assignment
    build_artifact_list__already_present = json.loads(_ if (_ := phantom.get_run_data(key="build_artifact_list:already_present")) != "" else "null")  # pylint: disable=used-before-assignment

    dispatch_detail_note_result_item_0 = [item[0] for item in dispatch_detail_note_result_data]
    dispatch_artifact_list_result_item_0 = [item[0] for item in dispatch_artifact_list_result_data]
    dispatch_artifact_list_result_message = [item[1] for item in dispatch_artifact_list_result_data]

    finalize_detail__cef_dictionary = None

    ################################################################################
    ## Custom Code Start
    ################################################################################
    ################################################################################

    sdi_rows = phantom.collect2(container=container, datapath=["container:source_data_identifier"])
    incident_id = sdi_rows[0][0] if sdi_rows and sdi_rows[0] and sdi_rows[0][0] else "unknown"
    artifact_count = json.loads(phantom.get_run_data(key="build_artifact_list:count") or "0")

    note_result = phantom.collect2(container=container, datapath=["dispatch_detail_note:action_result.status"])
    note_status = note_result[0][0] if note_result and note_result[0] else "unknown"
    phantom.debug("Native add note action result: {}".format(note_status))

    # A failed platform write must not read as success. If the event artifacts
    # or the detail note failed, record an error note and an "Enrichment
    # Failed" artifact through the synchronous API (which runs as the playbook,
    # not through the asset whose write just failed) and stop before "Enrichment
    # Complete" is written, so check_reentry lets a later run retry.
    # build_artifact_list skips what is already on the container, but a
    # concurrent run (or proofpoint_trap_recheck) can post the same artifact
    # between that check and this run's write; SOAR rejects it with "already
    # exists", which is expected, not a failed write.
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
    if failed_event_writes or note_status == "failed":
        msg = "TRAP incident {}: {} of {} event-artifact writes failed; detail note write {}".format(
            incident_id, failed_event_writes, len(event_statuses), note_status)
        phantom.error(msg)
        phantom.add_note(container=container, note_type="general", title="TRAP Detail - Write failures", content=msg)
        signal_ok, signal_message, _signal_id = phantom.add_artifact(
            container=container,
            raw_data={},
            cef_data={"message": msg, "artifactsCreated": 0},
            label="enrichment_failed",
            name="Enrichment Failed",
            severity="low",
            run_automation=False,
        )
        if not signal_ok:
            phantom.error("Failed to create enrichment_failed artifact: {}".format(signal_message))
        return

    # "add artifact" has no description parameter, so the summary goes into
    # cef.message. runIndex makes each run's Enrichment Complete artifact
    # distinct content, so a re-run's signal is not rejected as a duplicate of
    # the previous one -- check_reentry's count depends on that.
    run_index = json.loads(phantom.get_run_data(key="check_reentry:run_index") or "0") or 0
    # alertCount: alerts (TRAP "events") this run processed -- what drives
    # the artifact count. eventCount: the incident's event_count as TRAP
    # reports it. artifactsCreated: new artifacts this run posted;
    # artifactsAlreadyPresent: ones it found on the container and skipped.
    alert_count = json.loads(phantom.get_run_data(key="build_artifact_list:alert_count") or "null")
    event_count = json.loads(phantom.get_run_data(key="build_artifact_list:event_count") or "null")
    already_present = json.loads(phantom.get_run_data(key="build_artifact_list:already_present") or "0")

    finalize_detail__cef_dictionary = json.dumps({
        "message": "TRAP incident {} detail extraction complete. {} alerts, {} new artifacts, {} already on the container.".format(
            incident_id, alert_count if alert_count is not None else "?", artifact_count, already_present),
        "alertCount": alert_count,
        "eventCount": event_count,
        "artifactsCreated": int(artifact_count),
        "artifactsAlreadyPresent": int(already_present),
        "runIndex": int(run_index),
    })

    # Also saved as run data: dispatch_enrichment_complete reads this key.
    phantom.save_run_data(key="finalize_detail:cef_dictionary", value=json.dumps(finalize_detail__cef_dictionary))

    ################################################################################
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_block_result(key="finalize_detail__inputs:0:dispatch_detail_note:action_result.status", value=json.dumps(dispatch_detail_note_result_item_0))
    phantom.save_block_result(key="finalize_detail__inputs:1:container:source_data_identifier", value=json.dumps(source_data_identifier_value))
    phantom.save_block_result(key="finalize_detail__inputs:2:dispatch_artifact_list:action_result.status", value=json.dumps(dispatch_artifact_list_result_item_0))
    phantom.save_block_result(key="finalize_detail__inputs:3:dispatch_artifact_list:action_result.message", value=json.dumps(dispatch_artifact_list_result_message))
    phantom.save_block_result(key="finalize_detail__inputs:4:check_reentry:custom_function:run_index", value=json.dumps(check_reentry__run_index))
    phantom.save_block_result(key="finalize_detail__inputs:5:build_artifact_list:custom_function:alert_count", value=json.dumps(build_artifact_list__alert_count))
    phantom.save_block_result(key="finalize_detail__inputs:6:build_artifact_list:custom_function:event_count", value=json.dumps(build_artifact_list__event_count))
    phantom.save_block_result(key="finalize_detail__inputs:7:build_artifact_list:custom_function:already_present", value=json.dumps(build_artifact_list__already_present))

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

    # The parameters the VPE builds above are ONE set whose every field is a
    # whole list. "add artifact" has to run once per artifact, so this replaces
    # them with one set per list item; phantom.act() below then runs one app_run
    # per set, on whichever asset this block selects. The fan-out lives here,
    # in this block's custom code, because that is the part a VPE save keeps
    # verbatim -- the generated code above is rebuilt from the bindings on
    # every save. It reads the run data directly rather than the generated
    # variables, so it does not depend on how the VPE names them.
    artifact_names = json.loads(phantom.get_run_data(key="build_artifact_list:name") or "null") or []
    artifact_labels = json.loads(phantom.get_run_data(key="build_artifact_list:label") or "null") or []
    artifact_sdis = json.loads(phantom.get_run_data(key="build_artifact_list:source_data_identifier") or "null") or []
    artifact_cefs = json.loads(phantom.get_run_data(key="build_artifact_list:cef_dictionary") or "null") or []
    artifact_contains = json.loads(phantom.get_run_data(key="build_artifact_list:contains") or "null") or []

    parameters = []
    for index, artifact_name in enumerate(artifact_names):
        parameters.append({
            "name": artifact_name,
            "label": artifact_labels[index],
            "contains": artifact_contains[index],
            "container_id": container.get("id"),
            "cef_dictionary": artifact_cefs[index],
            "source_data_identifier": artifact_sdis[index],
        })

    if not parameters:
        # Nothing to create (an incident with no events): phantom.act() has
        # nothing to dispatch, so go straight to the detail note.
        phantom.debug("No event artifacts to create this run")
        prepare_detail_note(container=container)
        return

    ################################################################################
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("add artifact", parameters=parameters, name="dispatch_artifact_list", assets=["soar8"], callback=prepare_detail_note)

    return


@phantom.playbook_block()
def dispatch_enrichment_complete(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("dispatch_enrichment_complete() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Create the Enrichment Complete artifact, the playbook's last step.
    ################################################################################

    id_value = container.get("id", None)
    source_data_identifier_value = container.get("source_data_identifier", None)
    finalize_detail__cef_dictionary = json.loads(_ if (_ := phantom.get_run_data(key="finalize_detail:cef_dictionary")) != "" else "null")  # pylint: disable=used-before-assignment

    parameters = []

    if source_data_identifier_value is not None:
        parameters.append({
            "name": "Enrichment Complete",
            "label": "enrichment_complete",
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
    for params in parameters:
        params["run_automation"] = False

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("add artifact", parameters=parameters, name="dispatch_enrichment_complete", assets=["soar8"], callback=comment_on_trap_incident)

    return


@phantom.playbook_block()
def dispatch_mime_download(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("dispatch_mime_download() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Download and vault the original email of every event on the incident.
    ################################################################################

    filtered_artifact_0_data_filter_event_info = phantom.collect2(container=container, datapath=["filtered-data:filter_event_info:condition_1:artifact:*.cef.incidentId","filtered-data:filter_event_info:condition_1:artifact:*.id"], scope="all")

    parameters = []

    # build parameters list for 'dispatch_mime_download' call
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

    phantom.act("download mime body", parameters=parameters, name="dispatch_mime_download", assets=["proofpoint_trap_mock"], callback=build_artifact_list)

    return


@phantom.playbook_block()
def check_reentry(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("check_reentry() called")

    ################################################################################
    # Decide whether this trigger needs an enrichment run.
    ################################################################################

    check_reentry__run_index = None

    ################################################################################
    ## Custom Code Start
    ################################################################################
    ################################################################################

    # proofpoint_trap_orchestrator runs this playbook on every automation
    # trigger of the container (ingest, each Event Info Update), so this block
    # decides whether this trigger needs an enrichment run. It is a
    # code block rather than code in on_start because the VPE regenerates
    # on_start on every save and would drop it.
    #
    # Runs when no "Enrichment Complete" exists yet, or when there are at least
    # as many "Event Info Update" artifacts (written by proofpoint_trap_recheck
    # on a changed incident) as "Enrichment Complete" ones. "Enrichment Failed"
    # is not counted, so a failed run can be retried. scope="all" because the
    # artifacts that decide this were created by earlier triggers.
    rows = phantom.collect2(container=container, datapath=["artifact:*.name"], scope="all")
    names = [row[0] for row in (rows or []) if row and row[0]]
    enrichment_complete_count = names.count("Enrichment Complete")
    event_info_update_count = names.count("Event Info Update")

    if enrichment_complete_count > 0 and event_info_update_count < enrichment_complete_count:
        phantom.debug(
            "Enrichment already complete ({} run(s)) with no unconsumed Event Info Update "
            "artifact ({} total) -- skipping".format(enrichment_complete_count, event_info_update_count)
        )
        return

    # This run's index: 0 on the first run, then the number of Event Info
    # Update artifacts seen so far. finalize_detail puts it into this run's
    # Enrichment Complete artifact, so each run's signal is new content and the
    # count above can move past 1.
    check_reentry__run_index = event_info_update_count
    phantom.save_run_data(key="check_reentry:run_index", value=json.dumps(check_reentry__run_index))

    ################################################################################
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_block_result(key="check_reentry:run_index", value=json.dumps(check_reentry__run_index))

    phantom.save_block_result(key="check_reentry_called", value="True")

    filter_event_info(container=container)

    return


@phantom.playbook_block()
def comment_on_trap_incident(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("comment_on_trap_incident() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Comment on the TRAP incident with a link to this SOAR case, on the first enrichment only.
    ################################################################################

    build_artifact_list__incident_id = json.loads(_ if (_ := phantom.get_run_data(key="build_artifact_list:incident_id")) != "" else "null")  # pylint: disable=used-before-assignment

    parameters = []

    if build_artifact_list__incident_id is not None:
        parameters.append({
            "summary": "Extracted by SOAR automation",
            "incident_id": build_artifact_list__incident_id,
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################
    ################################################################################

    # Tell TRAP that SOAR has taken the incident, with a link to this case. Only
    # on the incident's first enrichment (check_reentry's run index 0): a re-run
    # after proofpoint_trap_recheck flags a change posts nothing. The link is
    # SOAR's configured base URL (Administration > Company Settings) plus
    # /mission/<container id>, the case page.
    run_index = json.loads(phantom.get_run_data(key="check_reentry:run_index") or "null")
    incident_id = json.loads(phantom.get_run_data(key="build_artifact_list:incident_id") or "null")
    if run_index != 0 or incident_id is None:
        phantom.debug("Not the incident's first enrichment (run index {}): no TRAP comment".format(run_index))
        return

    base_url = (phantom.get_base_url() or "").rstrip("/")
    case_link = "{}/mission/{}".format(base_url, container.get("id")) if base_url else "case {}".format(container.get("id"))
    parameters = [{
        "incident_id": incident_id,
        "summary": "This incident has been extracted by SOAR automation, please review it in SOAR: {}".format(case_link),
    }]

    ################################################################################
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("add comment", parameters=parameters, name="comment_on_trap_incident", assets=["proofpoint_trap_mock"])

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################
    ################################################################################

    # dispatch_enrichment_complete has no callback, so its result is only
    # visible here. Surface a failure instead of letting the run read as a
    # clean success; with no "Enrichment Complete" artifact, check_reentry
    # already lets a later run redo the enrichment.
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


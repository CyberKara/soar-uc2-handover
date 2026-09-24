"""
Proofpoint TRAP Detail

Automation playbook triggered on container creation for label 'proofpoint_trap'.
Fetches full incident details (with expanded events) from Proofpoint TRAP,
downloads + vaults the raw MIME body for every event, then creates enriched
artifacts: email addresses, domains, click IPs, threat URLs, MIME bodies.

Creates a final 'Enrichment Complete' artifact on success. When the TRAP fetch
or a platform write fails it instead adds an error note and an 'Enrichment
Failed' artifact, which the re-entry guard does not count, so a later run can
retry.

Trigger: Container created on label 'proofpoint_trap'
"""


import phantom.rules as phantom
import json
import urllib.parse
from datetime import datetime


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # Count-based re-entry guard (was existence-based — see
    # uc2_implementation_plan.md's Known Limitations "post-ingestion
    # incident updates" entry). scope="all" required: "Enrichment Complete"/
    # "Event Info Update" are created by proofpoint_trap_recheck (PB7) or a prior
    # run of this playbook, not by whatever artifact triggers this
    # particular run (see constraints.md). "Enrichment Failed" is
    # deliberately NOT counted, so a run that failed (TRAP fetch or a
    # platform write) can be retried by a later run.
    rows = phantom.collect2(container=container, datapath=["artifact:*.name"], scope="all")
    names = [row[0] for row in (rows or []) if row and row[0]]
    enrichment_complete_count = names.count("Enrichment Complete")
    recheck_requested_count = names.count("Event Info Update")

    if enrichment_complete_count > 0 and recheck_requested_count < enrichment_complete_count:
        phantom.debug(
            "Enrichment already complete ({} run(s)) with no unconsumed Event Info Update "
            "artifact ({} total) -- skipping".format(enrichment_complete_count, recheck_requested_count)
        )
        return

    # recheck_requested_count doubles as this run's index: 0 for the very
    # first run, then the count of Event Info Update artifacts seen so far
    # for every re-run after that. Each Enrichment Complete artifact this
    # run creates is SDI'd with this index so it's a genuinely new artifact
    # instead of colliding with a prior run's — that's what lets the count
    # comparison above ever move past 1.
    phantom.save_run_data(key="on_start:run_index", value=str(recheck_requested_count))

    filter_event_info(container=container)

    return


@phantom.playbook_block()
def filter_event_info(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("filter_event_info() called")

    ################################################################################
    # Native filter block -- narrows artifacts to name == "Event Info" so
    # get_trap_incident's incident_id parameter (node 3's JSON) binds to
    # filtered-data:filter_event_info:condition_1:artifact:*.cef.incidentId,
    # a single reliable value, instead of the raw wildcard
    # artifact:*.cef.incidentId it used to bind to directly. That raw
    # wildcard resolved to the literal string "None" whenever this playbook
    # ran on anything other than a full container-level artifact_created
    # fan-out. Found live 2026-08-14. SOAR resolves the filter itself from
    # the JSON conditions at dispatch time, not via code in this function --
    # this body is a readable reflection, not what actually executes.
    ################################################################################

    get_trap_incident(container=container)

    return


@phantom.playbook_block()
def get_trap_incident(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("get_trap_incident() called")

    ################################################################################
    # Fetch full incident details from TRAP with expand_events=true.
    # incident_id bound to the filtered Event Info datapath in this block's
    # VPE config (see proofpoint_trap_detail.json node 3) -- SOAR resolves
    # that binding itself at dispatch time, not via code in this function;
    # this body independently re-derives the same value (filtered to
    # name == "Event Info") as a readable reflection.
    ################################################################################

    rows = phantom.collect2(
        container=container,
        datapath=["artifact:*.name", "artifact:*.cef.incidentId"],
        scope="all",
    )
    incident_ids = [row[1] for row in (rows or []) if row and row[0] == "Event Info" and row[1]]
    incident_id_value = str(incident_ids[0]) if incident_ids else ""

    parameters = [{
        "incident_id": incident_id_value,
    }]

    phantom.act("get incident", parameters=parameters, name="get_trap_incident", assets=["proofpoint_trap_mock"], callback=dispatch_mime_download)

    return


@phantom.playbook_block()
def dispatch_mime_download(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("dispatch_mime_download() called")

    ################################################################################
    # Native action block (Proofpoint TRAP app, "download mime body") --
    # fetches + vaults the raw MIME (.eml) for every event on this incident
    # in one call (event_id omitted). Moved off the connector's on_poll
    # (removed 2026-08-20, user decision: connector stays a thin generic
    # API wrapper, MIME-fetch belongs with the rest of PB1's derived
    # per-item artifacts, same reasoning already applied to the URL
    # Artifact move 2026-08-18). incident_id bound to the same filtered
    # Event Info datapath get_trap_incident uses -- SOAR resolves that
    # binding itself at dispatch time (node 10's JSON), not via code in
    # this function; this body independently re-derives the same value as
    # a readable reflection, same pattern as get_trap_incident above.
    ################################################################################

    rows = phantom.collect2(
        container=container,
        datapath=["artifact:*.name", "artifact:*.cef.incidentId"],
        scope="all",
    )
    incident_ids = [row[1] for row in (rows or []) if row and row[0] == "Event Info" and row[1]]
    incident_id_value = str(incident_ids[0]) if incident_ids else ""

    parameters = [{
        "incident_id": incident_id_value,
    }]

    phantom.act("download mime body", parameters=parameters, name="dispatch_mime_download", assets=["proofpoint_trap_mock"], callback=extract_data_to_artifacts)

    return


@phantom.playbook_block()
def extract_data_to_artifacts(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("extract_data_to_artifacts() called")

    ################################################################################
    # Parse events from get_incident result, create email/domain/IP artifacts
    ################################################################################

    extract_data_to_artifacts__name = None
    extract_data_to_artifacts__label = None
    extract_data_to_artifacts__cef_dictionary = None
    extract_data_to_artifacts__contains = None
    extract_data_to_artifacts__incident_id = None
    extract_data_to_artifacts__count = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    def _create_enrichment_failure_signal(msg):
        # Uses the documented "Signal artifact pattern" (playbook-patterns.md)
        # instead of a raw REST POST -- synchronous, no asset. No explicit
        # identifier -- SOAR auto-generates one (user decision 2026-08-15,
        # accepted tradeoff: duplicate artifacts possible on re-run).
        # Named "Enrichment Failed", not "Enrichment Complete": on_start's
        # re-entry guard only counts the latter, so a later run can retry.
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

    import urllib.parse  # local import — GUI edits recompile/lint each code block in
                          # isolation, a shared module-level import isn't visible to it
                          # (see uc2_dev_notes.md)

    # Headers is a free-form dict per email (no fixed schema, contents vary
    # by mail client) -- pull only these specific ones when present, doing a
    # case-insensitive match since real-world casing varies (vendor sample
    # shows "MIME-Version", not "Mime-Version").
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
        # messageDeliveryTime isn't always a plain string — a real captured
        # response (XSOAR ProofpointThreatResponse test fixture, 2026-08-06)
        # showed it as a full Joda-time-style object instead:
        # {"millis": 1617103759000, "zone": {...}, "chronology": {...}, ...}.
        # Stringifying defensively here avoids putting a raw dict into a CEF
        # field value.
        if isinstance(value, dict):
            millis = value.get("millis")
            if isinstance(millis, (int, float)):
                from datetime import datetime as _dt
                return _dt.utcfromtimestamp(millis / 1000.0).strftime("%Y-%m-%dT%H:%M:%SZ")
            return str(value)
        return value or ""

    events = incident.get("events", [])
    phantom.debug("Processing {} events from incident {}".format(len(events), incident.get("id", "?")))

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

    # Incident-level (not per-event) threat URLs. Moved here 2026-08-18 from
    # the connector's on_poll, which used to create one "URL Artifact" per
    # entry in hosts.url directly at ingestion -- this fetch (get_trap_incident,
    # expand_events=true) also carries hosts, and this is where the rest of
    # the incident's derived per-item artifacts already get built, so it
    # joins them here instead of staying connector-side. hosts.attacker /
    # hosts.forensics were the original (mock/Swimlane-derived) guess for
    # this object's shape -- CONFIRMED ABSENT 2026-08-06 against real
    # incident data -- hosts only ever has `url`.
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

    # MIME Body artifacts -- moved here 2026-08-20 from the connector's
    # on_poll (removed, user decision: connector stays a thin generic API
    # wrapper, MIME-fetch belongs with the rest of PB1's derived per-item
    # artifacts, same reasoning as the URL Artifact move above). A failed
    # or empty download just means fewer MIME Body artifacts, not a hard
    # failure of this whole extraction -- mirrors how the hosts.url
    # handling above tolerates a missing/empty field.
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
        # On a re-run (proofpoint_trap_recheck triggers one on a changed
        # incident) the container already carries MIME Body artifacts for the
        # events seen before, and PB7 has just built the new event's. SOAR does
        # not dedup them away: its content hash covers cef_types, which the two
        # builders set differently, so the same MIME lands twice. Skip what is
        # already there, by source_data_identifier.
        existing_rows = phantom.collect2(
            container=container,
            datapath=["artifact:*.name", "artifact:*.source_data_identifier"],
            scope="all",
        )
        existing_mime_sdis = {
            row[1] for row in (existing_rows or [])
            if row and row[0] == "MIME Body" and row[1]
        }
        for row in (mime_rows or []):
            mime_event_id, vault_id, file_name = row[0], row[1], row[2]
            if not vault_id:
                continue
            if "trap-{}-mime-{}".format(incident_id_val, mime_event_id) in existing_mime_sdis:
                continue
            artifacts.append({
                "name": "MIME Body",
                "description": "Raw MIME body from incident {} event {}".format(incident_id_val, mime_event_id),
                "label": "event",
                "cef": {"vaultId": vault_id, "fileName": file_name},
                "cef_types": {"vaultId": ["vault id"]},
                "run_automation": False,
                # Per-event SDI, NOT the shared incident_id_val every other
                # artifact in this batch uses -- proofpoint_trap_attachments
                # (PB3) parses "trap-{incident}-mime-{event}" back out of
                # this exact field to recover event_id (see its own
                # comment); a shared SDI would degrade every MIME Body's
                # event_id to "?" there. Format matches the connector's old
                # (now-removed) _build_mime_artifact() exactly, just built
                # here now.
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
            if from_addr and from_addr not in seen_sender_emails:
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

            # Cc — best-effort from raw headers. A full field-by-field walk of a
            # real incident payload (2026-08-06) confirmed no structured `cc`
            # field exists anywhere in the get-incident response -- if a real
            # tenant ever has cc data, it would only be inside the raw MIME
            # body (a separate data path: the `download mime body` action /
            # vault attachment, not this structured response), which is out
            # of scope for this function. Left as a harmless no-op rather than
            # removed, in case `headers` ever does carry one on some tenant.
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

            # Threat URL domains — CONFIRMED (2026-08-06) via the real
            # ProofpointThreatResponse integration's own source
            # (get_emails_context: email.get("urls")), not just docs/guesses.
            # Per-email list, not the flat event-level field this originally
            # guessed at.
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

        # Click IP / event-level threatURL — a full field-by-field walk of a
        # real "reported by user" incident (2026-08-06) confirmed neither
        # exists on that source type; `events[]` there is just {id, emails}.
        # Real TRAP events also come from a richer "email flow" (Proofpoint
        # TAP) source with additional fields (category/severity/attackers/
        # etc., per a captured XSOAR integration fixture) that this lab
        # doesn't ingest -- click/threat data may live there instead, under
        # `events[].attackers[].location`, unexplored. Both left as harmless
        # no-ops rather than removed, since a TAP-sourced incident could
        # arrive here in principle even though none has yet.
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

    phantom.debug("Creating {} artifacts from events".format(len(artifacts)))

    # Native "add artifact" action parameters (Phantom app, asset "soar8"),
    # one call per event artifact via dispatch_event_artifacts. Exposed as
    # parallel per-field LISTS (not one list-of-dicts blob) so that block's
    # JSON can map each field to a real output variable
    # (extract_data_to_artifacts:custom_function:<field>) -- declared before
    # the loop and .append()-ed inside it, the canonical parallel-output-
    # variable-list shape (matches community playbook
    # Splunk_Attack_Analyzer_Dynamic_Analysis's normalized_file_summary_output,
    # see code-blocks.md).
    #
    # Fields that vary per artifact get a list: name, cef_dictionary,
    # contains (cef_types differs by artifact type -- email/domain/ip).
    # container_id is a single constant (bound to container:id on node 8's
    # JSON) -- container_id confirmed live 2026-08-15
    # it's technically omittable (falls back to the run's own container
    # context), but left explicit since the VPE editor flags the action node
    # "Unconfigured" without it (found live 2026-08-16). run_automation/
    # determine_contains are omitted, falling back to the action's own
    # declared `false` defaults -- that omission does not trigger the same
    # "Unconfigured" flag.
    #
    # source_data_identifier is genuinely mandatory on this action --
    # confirmed live 2026-08-15 omitting it entirely fails with "Required
    # parameters are not specified or are blank: ['source_data_identifier']".
    # A per-artifact uuid4 suffix was used earlier to guarantee uniqueness,
    # but a live dedup test (2026-08-16: two artifacts posted to the same
    # container with identical container_id + source_data_identifier + name,
    # differing only in cef content) created two distinct artifacts with no
    # merge/collision -- SOAR does not dedup on this key combination, so
    # reusing the container's own source_data_identifier is safe for most of
    # this batch. MIME Body artifacts are the one exception (per-item
    # override via artifacts[i]["source_data_identifier"]) -- see the
    # comment where they're built above; proofpoint_trap_attachments (PB3)
    # parses that per-event SDI back apart, so it can't collapse to the
    # shared incident_id_val like everything else here.
    extract_data_to_artifacts__name = []
    extract_data_to_artifacts__label = []
    extract_data_to_artifacts__cef_dictionary = []
    extract_data_to_artifacts__contains = []

    for a in artifacts:
        extract_data_to_artifacts__name.append(a["name"])
        extract_data_to_artifacts__label.append(a.get("label", "event"))
        extract_data_to_artifacts__cef_dictionary.append(json.dumps(a.get("cef", {})))
        extract_data_to_artifacts__contains.append(json.dumps(a.get("cef_types", {})))

    action_params = [
        {
            "container_id": id_value,
            "name": extract_data_to_artifacts__name[i],
            "label": extract_data_to_artifacts__label[i],
            "source_data_identifier": artifacts[i].get("source_data_identifier") or incident_id_val,
            "cef_dictionary": extract_data_to_artifacts__cef_dictionary[i],
            "contains": extract_data_to_artifacts__contains[i],
        }
        for i in range(len(artifacts))
    ]

    phantom.save_run_data(key="extract_data_to_artifacts:action_params", value=json.dumps(action_params))
    phantom.save_run_data(key="extract_data_to_artifacts:name", value=json.dumps(extract_data_to_artifacts__name))
    phantom.save_run_data(key="extract_data_to_artifacts:label", value=json.dumps(extract_data_to_artifacts__label))
    phantom.save_run_data(key="extract_data_to_artifacts:cef_dictionary", value=json.dumps(extract_data_to_artifacts__cef_dictionary))
    phantom.save_run_data(key="extract_data_to_artifacts:contains", value=json.dumps(extract_data_to_artifacts__contains))
    # Ground-truth incident_id from the actually-fetched incident (not the
    # pre-fetch artifact scan above) -- downstream blocks read this instead
    # of re-deriving it a second time.
    phantom.save_run_data(key="extract_data_to_artifacts:incident_id", value=json.dumps(incident_id_val))
    # Attempted count, not verified-success count -- dispatch_event_artifacts
    # no longer checks per-app_run status after the native "add artifact"
    # call (see its comment), so this is how many artifacts were built here,
    # not how many the platform confirmed landing.
    phantom.save_run_data(key="extract_data_to_artifacts:count", value=str(len(artifacts)))

    # Also exposed as real output variables (not just run_data) so native
    # blocks downstream can bind to them directly via
    # extract_data_to_artifacts:custom_function:* datapaths, per
    # constraints.md's "output variables, not save_run_data, when data
    # feeds native blocks downstream" rule.
    extract_data_to_artifacts__incident_id = incident_id_val
    extract_data_to_artifacts__count = len(artifacts)

    ################################################################################
    ## Custom Code End
    ################################################################################

    dispatch_event_artifacts(container=container)

    return


@phantom.playbook_block()
def dispatch_event_artifacts(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("dispatch_event_artifacts() called")

    ################################################################################
    # Native action block (Phantom app, "add artifact") -- one parameter set
    # per event artifact, built by extract_data_to_artifacts. Fires one app_run
    # per item under this single dispatch. Per-app_run success is not
    # checked (dropped the former finalize_event_artifacts verification
    # step, per-item failure isn't treated as actionable here) -- callback
    # goes straight to prepare_detail_note, which reads the attempted count
    # extract_data_to_artifacts already saved.
    ################################################################################

    action_params = json.loads(phantom.get_run_data(key="extract_data_to_artifacts:action_params") or "[]")

    if not action_params:
        # Nothing to create this run (e.g. incident had no events) --
        # phantom.act() with an empty parameters list has nothing to
        # dispatch, so skip straight to the next block.
        phantom.debug("No event artifacts to create this run")
        prepare_detail_note(container=container)
        return

    phantom.act("add artifact", parameters=action_params, name="dispatch_event_artifacts", assets=["soar8"], callback=prepare_detail_note)

    return


@phantom.playbook_block()
def prepare_detail_note(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("prepare_detail_note() called")

    ################################################################################
    # Build the summary note's title/content, exposed as output variables
    # for the native "add note" action block (dispatch_detail_note) to bind
    # to -- EXPERIMENT (2026-08-13): testing constraints.md's callback-chain
    # claim for real instead of just trusting it. finalize_detail (that
    # action's callback) does the enrichment_complete artifact creation
    # that used to happen synchronously right after phantom.add_note() in a
    # single block -- if that artifact still reliably lands and the
    # playbook_run only completes after it does, the native action is fine
    # here; if it's missing/racy, the documented rule holds and this gets
    # reverted.
    ################################################################################

    prepare_detail_note__note_title = None
    prepare_detail_note__note_content = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    incident_id = json.loads(phantom.get_run_data(key="extract_data_to_artifacts:incident_id") or '"unknown"')
    artifact_count = phantom.get_run_data(key="extract_data_to_artifacts:count") or "0"

    # Collect incident summary from get_incident
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

    prepare_detail_note__note_title = "TRAP Detail - Incident {}".format(incident_id)
    prepare_detail_note__note_content = (
        "# TRAP Incident Detail\n"
        "**Incident ID:** {}\n"
        "**Summary:** {}\n"
        "**State:** {} | **Score:** {} | **Events:** {}\n"
        "**Artifacts created from events:** {}\n\n"
        "Event artifacts (emails, domains, IPs) have been created on this container."
    ).format(incident_id, summary, state, score, event_count, artifact_count)

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="prepare_detail_note:note_title", value=json.dumps(prepare_detail_note__note_title))
    phantom.save_run_data(key="prepare_detail_note:note_content", value=json.dumps(prepare_detail_note__note_content))

    dispatch_detail_note(container=container)

    return


@phantom.playbook_block()
def dispatch_detail_note(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("dispatch_detail_note() called")

    ################################################################################
    # Native action block (Phantom app, "add note") -- title/content come
    # from prepare_detail_note's output variables. This is the block under
    # test: a native action at the tail of a callback chain, same shape
    # constraints.md warns about.
    ################################################################################

    note_title = json.loads(phantom.get_run_data(key="prepare_detail_note:note_title") or '"unknown"')
    note_content = json.loads(phantom.get_run_data(key="prepare_detail_note:note_content") or '""')

    parameters = [{
        "title": note_title,
        "content": note_content,
    }]

    phantom.act("add note", parameters=parameters, name="dispatch_detail_note", assets=["soar8"], callback=finalize_detail)

    return


@phantom.playbook_block()
def finalize_detail(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("finalize_detail() called")

    ################################################################################
    # Builds the Enrichment Complete artifact's fields as output variables
    # for the native "add artifact" action block (dispatch_enrichment_complete)
    # to bind to -- same native-action pattern dispatch_event_artifacts
    # already uses, replacing the old raw REST POST (removed 2026-08-13,
    # user decision).
    ################################################################################

    finalize_detail__cef_dictionary = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # incident_id from the container's own native source_data_identifier
    # field (set by the connector at ingestion) -- declared as a real input
    # datapath (container:source_data_identifier) instead of reached into
    # implicitly via container.get(), same as container:id already is on
    # dispatch_event_artifacts/dispatch_enrichment_complete.
    sdi_rows = phantom.collect2(container=container, datapath=["container:source_data_identifier"])
    incident_id = sdi_rows[0][0] if sdi_rows and sdi_rows[0] and sdi_rows[0][0] else "unknown"
    artifact_count = phantom.get_run_data(key="extract_data_to_artifacts:count") or "0"

    note_result = phantom.collect2(container=container, datapath=["dispatch_detail_note:action_result.status"])
    note_status = note_result[0][0] if note_result and note_result[0] else "unknown"
    phantom.debug("Native add note action result: {}".format(note_status))

    # A failed platform write must not read as success. If the event
    # artifacts or the detail note failed, record an error note and an
    # "Enrichment Failed" signal through the synchronous API (which runs as
    # the playbook, not through the soar8 asset that just failed) and stop
    # before "Enrichment Complete" is written, so the re-entry guard lets a
    # later run retry.
    # A re-run (after proofpoint_trap_recheck flags a change) re-posts artifacts
    # an earlier run already created; SOAR rejects those with "already exists",
    # which is the dedup this UC relies on -- not a failed write.
    event_rows = phantom.collect2(
        container=container,
        datapath=[
            "dispatch_event_artifacts:action_result.status",
            "dispatch_event_artifacts:action_result.message",
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

    # name/label/contains/run_automation/determine_contains/
    # source_data_identifier never vary for this artifact -- those are
    # literal defaults / omitted on the action step itself
    # (dispatch_enrichment_complete) instead of being routed through here.
    # Only cef_dictionary (JSON encoding -- native "add artifact" takes cef
    # as a string, not a structured object) actually needs code.
    # Native "add artifact" has no "description" parameter (same gap
    # extract_data_to_artifacts's own event artifacts already have -- see
    # dispatch_event_artifacts) -- folded the old description text into
    # cef.message instead so it isn't lost outright.
    # runIndex makes each run's Enrichment Complete artifact distinct content,
    # so a re-run's signal is not rejected as a duplicate of the previous one --
    # what on_start's count-based guard assumes (it compares how many
    # "Enrichment Complete" artifacts exist against "Event Info Update" ones).
    run_index = phantom.get_run_data(key="on_start:run_index") or "0"

    finalize_detail__cef_dictionary = json.dumps({
        "message": "TRAP incident {} detail extraction complete. {} artifacts created.".format(incident_id, artifact_count),
        "artifactsCreated": int(artifact_count),
        "runIndex": int(run_index),
    })

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="finalize_detail:cef_dictionary", value=json.dumps(finalize_detail__cef_dictionary))

    dispatch_enrichment_complete(container=container)

    return


@phantom.playbook_block()
def dispatch_enrichment_complete(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("dispatch_enrichment_complete() called")

    ################################################################################
    # Native action block (Phantom app, "add artifact") -- creates the
    # Enrichment Complete signal artifact. True last step of PB1; no
    # callback -- terminal, matches cyberark_rotation_orchestrator's own
    # add_note_no_targets precedent (a phantom.act() call with no callback
    # param). SOAR reaches on_finish once every branch completes.
    # name/label/contains/run_automation/determine_contains are literal
    # constants here and in the JSON node's parameter config. container_id
    # bound to container:id -- technically omittable (falls back to the
    # run's own container context, confirmed live 2026-08-15), but left
    # explicit since the VPE editor flags the action node "Unconfigured"
    # without it (found live 2026-08-16). source_data_identifier bound
    # directly to container:source_data_identifier (single artifact per run,
    # container's own native field maps 1:1) -- only cef_dictionary is
    # genuinely computed, from finalize_detail's run data.
    ################################################################################

    sdi_rows = phantom.collect2(container=container, datapath=["container:source_data_identifier"])
    source_data_identifier = sdi_rows[0][0] if sdi_rows and sdi_rows[0] and sdi_rows[0][0] else ""
    cef_dictionary = json.loads(phantom.get_run_data(key="finalize_detail:cef_dictionary") or '""')

    parameters = [{
        "container_id": container.get("id"),
        "name": "Enrichment Complete",
        "label": "enrichment_complete",
        "source_data_identifier": source_data_identifier,
        "cef_dictionary": cef_dictionary,
        "contains": "{}",
        "run_automation": False,
        "determine_contains": False,
    }]

    phantom.act("add artifact", parameters=parameters, name="dispatch_enrichment_complete", assets=["soar8"])

    return


def on_finish(container, summary):
    phantom.debug("on_finish() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # dispatch_enrichment_complete is terminal (no callback), so its result
    # is only visible here. Surface a failure instead of letting the run read
    # as a clean success; with no "Enrichment Complete" artifact the re-entry
    # guard already lets a later run redo the enrichment.
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
    ## Custom Code End
    ################################################################################

    return
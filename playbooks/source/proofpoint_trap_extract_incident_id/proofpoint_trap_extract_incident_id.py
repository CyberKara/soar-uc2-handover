def proofpoint_trap_extract_incident_id(**kwargs):
    """
    Read the TRAP incident ID and raw TRAP Severity off the container's Event Info/Event Info Update artifacts.
    
    Args:
    
    Returns a JSON-serializable object that implements the configured data paths:
        incident_id: TRAP incident ID, or None if not found.
        trap_severity: Raw TRAP Severity value, or None if not found/not present.
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    from phantom.decided.context import get_current_container_id_

    outputs = {"incident_id": None, "trap_severity": None}

    container_id = get_current_container_id_()
    if not container_id:
        phantom.debug("proofpoint_trap_extract_incident_id: no current container id available")
        assert json.dumps(outputs)
        return outputs

    try:
        url = phantom.build_phantom_rest_url("artifact")
        resp = phantom.requests.get(
            uri=url,
            params={"_filter_container": container_id, "page_size": 0},
            verify=False,
        ).json()
    except Exception as e:
        phantom.debug("proofpoint_trap_extract_incident_id: artifact lookup failed: {}".format(str(e)))
        assert json.dumps(outputs)
        return outputs

    rows = resp.get("data") or []
    rows = sorted(rows, key=lambda a: a.get("id") or 0)

    candidates = [
        row for row in rows
        if row.get("name") in ("Event Info", "Event Info Update") and (row.get("cef") or {}).get("incidentId")
    ]

    if candidates:
        cef = candidates[-1].get("cef") or {}
        outputs["incident_id"] = str(cef["incidentId"])
        outputs["trap_severity"] = cef.get("trapSeverity")
        phantom.debug("Extracted incident ID: {}".format(outputs["incident_id"]))
    else:
        phantom.debug("Could not find Incident ID (cef.incidentId) on any 'Event Info'/'Event Info Update' artifact")

    assert json.dumps(outputs)
    return outputs

# File: proofpoint_trap_connector.py
import json
import sys
from datetime import datetime, timedelta, timezone

import requests
import urllib3
from requests.adapters import HTTPAdapter

import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult
from phantom.vault import Vault

from proofpoint_trap_consts import *


class ProofpointTrapConnector(BaseConnector):

    def __init__(self):
        super(ProofpointTrapConnector, self).__init__()
        self._state = None
        self._session = None
        self._base_url = None
        self._verify = False
        self._timeout = DEFAULT_TIMEOUT

    def initialize(self):
        self._state = self.load_state()
        if not isinstance(self._state, dict):
            self.debug_print("Resetting corrupted state file")
            self._state = {"app_version": self.get_app_json().get("app_version")}

        config = self.get_config()
        self._base_url = config.get(BASE_URL_KEY, "").rstrip("/")
        self._verify = config.get(VERIFY_SSL_KEY, True)
        self._timeout = config.get(TIMEOUT_KEY, DEFAULT_TIMEOUT)
        api_key = config.get(API_KEY_KEY, "")

        if not self._base_url.lower().startswith("https://"):
            self.save_progress(
                "Config Error: base_url must use https:// — plain HTTP would expose "
                "the API key in transit. Received: {!r}".format(self._base_url[:50])
            )
            return phantom.APP_ERROR

        self._session = requests.Session()
        retry = urllib3.Retry(
            total=MAX_RETRIES,
            backoff_factor=1,
            status_forcelist=RETRYABLE_STATUS_CODES,
        )
        adapter = HTTPAdapter(max_retries=retry)
        self._session.mount("http://", adapter)
        self._session.mount("https://", adapter)
        self._session.headers.update({
            "Authorization": api_key,
            "Content-Type": "application/json",
            "Accept": "application/json",
        })

        return phantom.APP_SUCCESS

    def finalize(self):
        if self._session:
            self._session.close()
        self.save_state(self._state)
        return phantom.APP_SUCCESS

    def handle_action(self, param):
        action_id = self.get_action_identifier()
        self.debug_print("action_id", action_id)

        action_mapping = {
            "test_connectivity": self._handle_test_connectivity,
            "on_poll": self._handle_on_poll,
            "list_incidents": self._handle_list_incidents,
            "get_incident": self._handle_get_incident,
            "close_incident": self._handle_close_incident,
            "add_comment": self._handle_add_comment,
            "download_mime_body": self._handle_download_mime_body,
            "add_user_to_incident": self._handle_add_user_to_incident,
            "update_incident_description": self._handle_update_incident_description,
            "update_incident_assignee": self._handle_update_incident_assignee,
            "set_incident_field": self._handle_set_incident_field,
        }

        action = action_mapping.get(action_id)
        if action:
            return action(param)

        return phantom.APP_ERROR

    def handle_exception(self, exception):
        self.set_status(
            phantom.APP_ERROR,
            "Unhandled exception: {}".format(
                self._get_error_message_from_exception(exception)
            ),
        )
        return phantom.APP_ERROR

    # ------------------------------------------------------------------
    # Utility helpers
    # ------------------------------------------------------------------

    def _get_error_message_from_exception(self, e):
        error_code = None
        error_message = "Error message unavailable"
        try:
            if hasattr(e, "args") and e.args:
                if len(e.args) > 1:
                    error_code = e.args[0]
                    error_message = e.args[1]
                elif len(e.args) == 1:
                    error_message = e.args[0]
        except Exception:
            pass
        if not error_code:
            return "Error Message: {}".format(error_message)
        return "Error Code: {}. Error Message: {}".format(error_code, error_message)

    # ------------------------------------------------------------------
    # Input validation helpers
    # ------------------------------------------------------------------

    def _validate_integer(self, action_result, parameter, key, allow_zero=False):
        try:
            if not float(parameter).is_integer():
                raise ValueError()
            parameter = int(parameter)
        except Exception:
            action_result.set_status(
                phantom.APP_ERROR,
                "Invalid integer value for '{}' parameter".format(key),
            )
            return None
        if allow_zero:
            if parameter < 0:
                action_result.set_status(
                    phantom.APP_ERROR,
                    "'{}' must be a non-negative integer".format(key),
                )
                return None
        else:
            if parameter <= 0:
                action_result.set_status(
                    phantom.APP_ERROR,
                    "'{}' must be a positive integer".format(key),
                )
                return None
        return parameter

    # ------------------------------------------------------------------
    # HTTP helpers
    # ------------------------------------------------------------------

    def _fail(self, action_result, msg):
        """Set error status on action_result or self (when on_poll has no action_result)."""
        if action_result is not None:
            return action_result.set_status(phantom.APP_ERROR, msg)
        return self.set_status(phantom.APP_ERROR, msg)

    def _make_rest_call(self, method, url, action_result=None, **kwargs):
        """Execute an HTTP call and process the response.

        Returns:
            tuple: (status, data) — RetVal pattern. data is the parsed body
            on success, None on failure.
        """
        try:
            response = self._session.request(
                method, url, timeout=self._timeout, verify=self._verify, **kwargs
            )
        except requests.exceptions.SSLError:
            return self._fail(action_result, ERR_SSL), None
        except requests.exceptions.ConnectionError:
            return self._fail(action_result, ERR_CONNECTION.format(self._base_url)), None
        except requests.exceptions.Timeout:
            return self._fail(action_result, ERR_TIMEOUT.format(self._timeout)), None
        except Exception as e:
            return self._fail(
                action_result, "API Error: Unexpected error \u2014 {}".format(str(e))
            ), None

        return self._process_response(response, action_result)

    def _process_response(self, response, action_result=None):
        """Parse an HTTP response with content-type detection.

        Returns:
            tuple: (status, data) — RetVal pattern.
        """
        if action_result is not None:
            action_result.add_debug_data({
                'r_status_code': response.status_code,
                'r_text': response.text,
                'r_headers': dict(response.headers),
            })

        status_code = response.status_code
        content_type = response.headers.get('Content-Type', '')

        if status_code in (401, 403):
            return self._fail(action_result, ERR_AUTH), None

        # 404 is deliberately NOT special-cased as "not found" here -- TRAP
        # also uses it for business-logic signals unrelated to a missing
        # resource (e.g. update team and assignee returns 404 when the
        # requested values already match the incident's current state).
        # Falls through to the same JSON/text/empty handling as every other
        # non-2xx status, which already surfaces the real body's
        # message/error field when present.

        if 'json' in content_type:
            return self._process_json_response(response, action_result)

        if 'html' in content_type:
            return self._fail(
                action_result,
                "Unexpected HTML response (HTTP {}) \u2014 check base_url".format(status_code)
            ), None

        if not response.text:
            if 200 <= status_code < 300:
                return phantom.APP_SUCCESS, {}
            return self._fail(
                action_result, "Empty response (HTTP {})".format(status_code)
            ), None

        if 200 <= status_code < 300:
            return phantom.APP_SUCCESS, response.text

        return self._fail(
            action_result,
            "API Error: HTTP {} \u2014 {}".format(status_code, response.text[:200])
        ), None

    def _process_json_response(self, response, action_result):
        """Parse a JSON response and map HTTP errors to descriptive messages."""
        try:
            data = response.json()
        except ValueError as e:
            return self._fail(
                action_result,
                "Unable to parse JSON response. Error: {}".format(str(e))
            ), None

        status_code = response.status_code
        if 200 <= status_code < 300:
            return phantom.APP_SUCCESS, data

        if isinstance(data, dict):
            msg = data.get("message") or data.get("error") or response.text[:200]
        else:
            msg = response.text[:200]
        return self._fail(
            action_result,
            "API Error: HTTP {} \u2014 {}".format(status_code, msg)
        ), None

    # ------------------------------------------------------------------
    # Disposition helpers
    # ------------------------------------------------------------------

    def _get_disposition(self, incident):
        for field in incident.get("incident_field_values", []):
            if field.get("name") == "Abuse Disposition":
                return field.get("value", "")
        return ""

    def _get_field_value(self, incident, field_name):
        for field in incident.get("incident_field_values", []):
            if field.get("name") == field_name:
                return field.get("value", "")
        return ""

    def _passes_disposition_filter(self, incident, allowed_dispositions):
        if not allowed_dispositions:
            return True
        disposition = self._get_disposition(incident)
        return disposition in allowed_dispositions

    def _passes_sub_disposition_filter(self, incident, allowed_sub_dispositions):
        if not allowed_sub_dispositions:
            return True
        sub_disposition = self._get_field_value(incident, "Sub Disposition")
        return sub_disposition in allowed_sub_dispositions

    def _fetch_and_filter_incidents(self, action_result, state, window_start, window_end,
                                     allowed_dispositions, allowed_sub_dispositions,
                                     expand_events="false"):
        """Fetch incidents in <=30-day chunks (TRAP's date-range cap, see
        MAX_POLL_WINDOW_HOURS) and apply the same client-side Abuse/Sub
        Disposition filtering as on_poll. Shared by on_poll and the
        'list incidents' action so both stay in sync.

        Returns:
            tuple: (status, incidents) — RetVal pattern; incidents is a
            disposition-filtered list on success, None on failure.
        """
        url = "{}{}".format(self._base_url, INCIDENTS_PATH)
        incidents_by_id = {}
        chunk_start = window_start
        while chunk_start < window_end:
            chunk_end = min(chunk_start + timedelta(hours=MAX_POLL_WINDOW_HOURS), window_end)
            params = {
                "state": state,
                "created_after": chunk_start.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "created_before": chunk_end.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "expand_events": expand_events,
            }

            ret_val, chunk_incidents = self._make_rest_call(
                "GET", url, action_result, params=params
            )
            if phantom.is_fail(ret_val):
                # _make_rest_call already set a detailed message on
                # action_result (or self, when action_result is None) — just
                # propagate the failure, don't clobber it with a generic one.
                return ret_val, None

            if isinstance(chunk_incidents, list):
                for inc in chunk_incidents:
                    inc_id = inc.get("id")
                    if inc_id is not None:
                        incidents_by_id[inc_id] = inc

            chunk_start = chunk_end

        incidents = list(incidents_by_id.values())
        filtered = [
            inc for inc in incidents
            if self._passes_disposition_filter(inc, allowed_dispositions)
            and self._passes_sub_disposition_filter(inc, allowed_sub_dispositions)
        ]
        return phantom.APP_SUCCESS, filtered

    # ------------------------------------------------------------------
    # MIME body helpers (shared by the on-demand action and on_poll)
    # ------------------------------------------------------------------

    def _fetch_incident_events(self, incident_id):
        """Fetch the full incident (expand_events=true) and return its events list."""
        url = "{}{}".format(self._base_url, INCIDENT_DETAIL_PATH.format(incident_id))
        ret_val, incident = self._make_rest_call(
            "GET", url, None, params={"expand_events": "true"}
        )
        if phantom.is_fail(ret_val) or not isinstance(incident, dict):
            return []
        return incident.get("events", []) or []

    def _download_and_vault_mime(self, incident_id, event_id, container_id):
        """Download raw MIME for one event and store it in the Vault.

        Returns:
            tuple: (status, vault_id, file_name, error_message) — RetVal
            pattern; vault_id/file_name are None on failure.
        """
        url = "{}{}".format(
            self._base_url, INCIDENT_EVENT_MIME_PATH.format(incident_id, event_id)
        )
        try:
            response = self._session.request(
                "GET", url, timeout=self._timeout, verify=self._verify
            )
        except requests.exceptions.SSLError:
            return phantom.APP_ERROR, None, None, ERR_SSL
        except requests.exceptions.ConnectionError:
            return phantom.APP_ERROR, None, None, ERR_CONNECTION.format(self._base_url)
        except requests.exceptions.Timeout:
            return phantom.APP_ERROR, None, None, ERR_TIMEOUT.format(self._timeout)
        except Exception as e:
            return phantom.APP_ERROR, None, None, "API Error: Unexpected error — {}".format(str(e))

        if response.status_code == 404:
            return phantom.APP_ERROR, None, None, ERR_EVENT_NOT_FOUND.format(event_id, incident_id)
        if response.status_code in (401, 403):
            return phantom.APP_ERROR, None, None, ERR_AUTH
        if response.status_code != 200:
            return phantom.APP_ERROR, None, None, "API Error: HTTP {}".format(response.status_code)

        file_name = "trap-{}-{}.eml".format(incident_id, event_id)
        try:
            vault_result = Vault.create_attachment(
                file_contents=response.content,
                container_id=container_id,
                file_name=file_name,
            )
        except Exception as e:
            return phantom.APP_ERROR, None, None, "Vault error: {}".format(str(e))

        if not vault_result.get("succeeded"):
            return phantom.APP_ERROR, None, None, "Vault error: {}".format(vault_result.get("message"))

        return phantom.APP_SUCCESS, vault_result.get("vault_id"), file_name, None

    # ------------------------------------------------------------------
    # Action: test connectivity
    # ------------------------------------------------------------------

    def _handle_test_connectivity(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        self.save_progress("Testing connectivity to Proofpoint TRAP")

        now = datetime.now(timezone.utc)
        one_hour_ago = (now - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")

        url = "{}{}".format(self._base_url, INCIDENTS_PATH)
        params = {
            "state": "new",
            "created_after": one_hour_ago,
            "expand_events": "false",
        }

        ret_val, data = self._make_rest_call("GET", url, action_result, params=params)
        if phantom.is_fail(ret_val):
            self.save_progress("Connectivity test failed")
            return action_result.get_status()

        count = len(data) if isinstance(data, list) else 0
        self.save_progress(
            "Connectivity test passed — {} incidents found in last hour".format(count)
        )
        return action_result.set_status(phantom.APP_SUCCESS, "Connectivity test passed")

    # ------------------------------------------------------------------
    # Action: on poll
    # ------------------------------------------------------------------

    def _handle_on_poll(self, param):
        config = self.get_config()
        poll_state = config.get(POLL_STATE_KEY, DEFAULT_POLL_STATE)
        poll_hours = config.get(POLL_HOURS_KEY, DEFAULT_POLL_HOURS)
        disposition_csv = config.get(ABUSE_DISPOSITION_KEY, DEFAULT_ABUSE_DISPOSITION)
        allowed_dispositions = set(
            d.strip() for d in disposition_csv.split(",") if d.strip()
        )
        sub_disposition_csv = config.get(SUB_DISPOSITION_KEY, DEFAULT_SUB_DISPOSITION)
        allowed_sub_dispositions = set(
            d.strip() for d in sub_disposition_csv.split(",") if d.strip()
        )

        # Determine time window (Poll Now ignores checkpoint)
        now = datetime.now(timezone.utc)
        if self.is_poll_now():
            max_containers = param.get("container_count", 5)
            window_start = now - timedelta(hours=poll_hours)
        else:
            max_containers = 0  # no limit for scheduled polls
            last_poll = self._state.get("last_poll_time")
            if last_poll:
                window_start = datetime.strptime(
                    last_poll, "%Y-%m-%dT%H:%M:%SZ"
                ).replace(tzinfo=timezone.utc)
            else:
                window_start = now - timedelta(hours=poll_hours)

        self.save_progress(
            "Polling TRAP — state={}, disposition={}, sub_disposition={}, since={}".format(
                poll_state, disposition_csv, sub_disposition_csv or "(any)",
                window_start.strftime("%Y-%m-%dT%H:%M:%SZ")
            )
        )

        # Fetch incidents in <=30-day chunks, filtered by disposition/sub disposition
        ret_val, filtered = self._fetch_and_filter_incidents(
            None, poll_state, window_start, now,
            allowed_dispositions, allowed_sub_dispositions,
        )
        if phantom.is_fail(ret_val):
            return self.get_status()

        # Apply container limit for Poll Now
        if max_containers:
            filtered = filtered[:max_containers]

        self.save_progress(
            "{} incidents to ingest{}".format(
                len(filtered),
                " (Poll Now, limit {})".format(max_containers) if self.is_poll_now() else ""
            )
        )

        # Get container label from ingest config
        container_label = config.get("ingest", {}).get("container_label")
        severity = config.get(SEVERITY_KEY, DEFAULT_SEVERITY)
        sensitivity = config.get(SENSITIVITY_KEY, DEFAULT_SENSITIVITY)

        # Create containers
        created = 0
        for incident in filtered:
            status, container_id = self._ingest_incident(incident, container_label, severity, sensitivity)
            if status == "created":
                created += 1
            elif status == "duplicate":
                self.debug_print("Duplicate container skipped for incident {}".format(incident.get("id", "")))

        # Post-ingestion incident updates (a field edit, disposition change,
        # or newly-linked event on an already-ingested incident) are no
        # longer detected here -- moved to the proofpoint_trap_recheck
        # playbook 2026-08-18 (Timer-asset triggered, custom list
        # `proofpoint_trap_recheck_state` for durable state). See
        # uc2_implementation_plan.md's "fold into pb" entry for the
        # reasoning. on_poll is single-pass/checkpoint-only again.

        # Update poll checkpoint (skip on Poll Now — manual polls don't advance cursor)
        if not self.is_poll_now():
            self._state["last_poll_time"] = now.strftime("%Y-%m-%dT%H:%M:%SZ")

        self.save_progress(
            "on_poll complete — {} containers created".format(created)
        )
        return self.set_status(phantom.APP_SUCCESS)

    def _ingest_incident(self, incident, container_label, severity, sensitivity):
        """Create a container + artifacts for one incident.

        Returns:
            tuple: (status, container_id). status is "created", "duplicate",
            or "failed". container_id is set for "created" and "duplicate"
            (save_container returns the existing container's id on a
            duplicate hit), None for "failed".
        """
        inc_id = incident.get("id", "")
        # summary comes back empty on real incidents even when the key is
        # present (confirmed 2026-08-06 against real data) -- dict.get's
        # default only covers a MISSING key, not an empty-string value,
        # so this needs an explicit fallback chain, not just .get(..., default)
        summary = incident.get("summary") or incident.get("description") or "No summary"

        container = {
            "name": "TRAP-{}: {}".format(inc_id, summary),
            "description": incident.get("description", ""),
            "source_data_identifier": str(inc_id),
            # Initial value only — proofpoint_trap_triage (PB2) promotes
            # this from the raw TRAP Severity field (trapSeverity below).
            "severity": severity,
            "sensitivity": sensitivity,
            "status": "new",
            "start_time": incident.get("created_at", ""),
            "data": incident,
        }
        if container_label:
            container["label"] = container_label

        ret_val, msg, container_id = self.save_container(container)

        if phantom.is_fail(ret_val):
            self.debug_print("Failed to save container for incident {}: {}".format(inc_id, msg))
            return "failed", None

        if "duplicate container found" in msg.lower():
            return "duplicate", container_id

        # Create artifacts — run_automation set on last artifact only
        artifacts = self._build_on_poll_artifacts(incident, container_id)

        if artifacts:
            artifacts[-1]["run_automation"] = True
            self.save_artifacts(artifacts)

        return "created", container_id

    def _build_event_info_cef(self, incident):
        """CEF field dict for the "Event Info" artifact — score, disposition,
        sub disposition, classification, severity, event_ids. Used at first
        ingestion only -- post-ingestion change detection (the old
        _run_recheck_pass/_incident_signature, which used to reuse this too)
        moved to the proofpoint_trap_recheck playbook 2026-08-18. Deliberately
        excludes `hosts.url` — the playbook layer derives URL artifacts from
        its own full incident fetch, not on_poll."""
        inc_id = incident.get("id", "")
        disposition = self._get_disposition(incident)
        sub_disposition = self._get_field_value(incident, "Sub Disposition")
        classification = self._get_field_value(incident, "Classification")
        trap_severity = self._get_field_value(incident, "Severity")
        score = incident.get("score", 0)
        # Same empty-summary fallback as the container name (see _handle_on_poll)
        message = incident.get("summary") or incident.get("description") or ""
        # event_ids is present even in the lightweight list response (expand_events=false)
        # -- confirmed against real data, no extra API call needed to surface it here.
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

    def _build_on_poll_artifacts(self, incident, container_id):
        inc_id = incident.get("id", "")

        return [{
            "name": "Event Info",
            "container_id": container_id,
            "source_data_identifier": "trap-{}-info".format(inc_id),
            "label": "event",
            "cef": self._build_event_info_cef(incident),
        }]

    # ------------------------------------------------------------------
    # Action: list incidents
    # ------------------------------------------------------------------

    def _handle_list_incidents(self, param):
        """List/search TRAP incidents by state, time window, and Abuse/Sub
        Disposition — same filtering on_poll uses for ingestion, exposed as
        an on-demand action instead of the fixed ingest config."""
        action_result = self.add_action_result(ActionResult(dict(param)))

        state = param.get("state", DEFAULT_POLL_STATE)

        disposition_csv = param.get("abuse_disposition", "")
        allowed_dispositions = set(
            d.strip() for d in disposition_csv.split(",") if d.strip()
        )
        sub_disposition_csv = param.get("sub_disposition", "")
        allowed_sub_dispositions = set(
            d.strip() for d in sub_disposition_csv.split(",") if d.strip()
        )
        expand_events = "true" if param.get("expand_events", False) else "false"

        now = datetime.now(timezone.utc)
        # Validated like every other numeric parameter here: a VPE literal
        # arrives as a string, which timedelta() rejects outright.
        window_hours = self._validate_integer(
            action_result, param.get("hours_back", DEFAULT_POLL_HOURS), "hours_back"
        )
        if window_hours is None:
            return action_result.get_status()
        window_start = now - timedelta(hours=window_hours)

        self.save_progress(
            "Listing TRAP incidents — state={}, disposition={}, sub_disposition={}, since={}".format(
                state, disposition_csv or "(any)", sub_disposition_csv or "(any)",
                window_start.strftime("%Y-%m-%dT%H:%M:%SZ")
            )
        )

        ret_val, filtered = self._fetch_and_filter_incidents(
            action_result, state, window_start, now,
            allowed_dispositions, allowed_sub_dispositions,
            expand_events=expand_events,
        )
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        max_results = param.get("max_results", 0)
        if max_results:
            filtered = filtered[:max_results]

        for incident in filtered:
            action_result.add_data(incident)

        action_result.update_summary({"total_incidents": len(filtered)})
        return action_result.set_status(
            phantom.APP_SUCCESS,
            "{} incident(s) found".format(len(filtered)),
        )

    # ------------------------------------------------------------------
    # Action: get incident
    # ------------------------------------------------------------------

    def _handle_get_incident(self, param):
        """Retrieve one or more TRAP incidents. Accepts str or list."""
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Accept a single value, a real list, or a comma-joined string. The
        # last form is what SOAR actually sends when this parameter
        # (data_type=string, allow_list=true) is bound directly to a
        # wildcard artifact datapath (e.g. "artifact:*.cef.incidentId")
        # instead of an extracted scalar output variable: it text-joins
        # every artifact's resolved value with ", ", including the literal
        # word "None" for artifacts that don't have that CEF field — never
        # a real JSON list, so the isinstance(list) branch below never
        # fires for that binding. Confirmed live 2026-08-13: a 6-artifact
        # container produced "1786622023, None, None, None, None, None".
        raw_input = param.get("incident_id")
        if isinstance(raw_input, list):
            raw_ids = [x for x in raw_input if x not in (None, "")]
        elif isinstance(raw_input, str) and "," in raw_input:
            raw_ids = [
                part.strip() for part in raw_input.split(",")
                if part.strip() and part.strip().lower() != "none"
            ]
            if not raw_ids:
                return action_result.set_status(
                    phantom.APP_ERROR,
                    "'incident_id' resolved to no usable value(s): {!r}".format(raw_input)
                )
        elif raw_input not in (None, ""):
            raw_ids = [raw_input]
        else:
            return action_result.set_status(
                phantom.APP_ERROR, "Required parameter 'incident_id' is missing"
            )

        # Default True preserves prior hardcoded behavior for existing callers
        # (e.g. proofpoint_trap_detail never sets this param).
        expand_events = "true" if param.get("expand_events", True) else "false"

        succeeded, failed = 0, 0
        last_event_count = 0
        errors = []

        for raw_id in raw_ids:
            incident_id = self._validate_integer(action_result, raw_id, "incident_id")
            if incident_id is None:
                failed += 1
                errors.append("invalid id '{}'".format(raw_id))
                continue

            url = "{}{}".format(self._base_url, INCIDENT_DETAIL_PATH.format(incident_id))
            ret_val, incident = self._make_rest_call(
                "GET", url, action_result, params={"expand_events": expand_events}
            )
            if phantom.is_fail(ret_val):
                failed += 1
                errors.append("id={}: {}".format(incident_id, action_result.get_message()))
                continue

            action_result.add_data(incident)
            last_event_count = incident.get("event_count", 0)
            succeeded += 1

        action_result.update_summary({
            "succeeded": succeeded,
            "failed": failed,
            "total": len(raw_ids),
            "event_count": last_event_count,
        })

        if succeeded == 0:
            return action_result.set_status(
                phantom.APP_ERROR,
                "All {} incident lookups failed: {}".format(
                    failed, "; ".join(errors)[:500]
                )
            )
        return action_result.set_status(
            phantom.APP_SUCCESS,
            "{}/{} incidents retrieved".format(succeeded, len(raw_ids))
        )

    # ------------------------------------------------------------------
    # Action: close incident
    # ------------------------------------------------------------------

    def _handle_close_incident(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        incident_id = self._validate_integer(action_result, param.get("incident_id"), "incident_id")
        if incident_id is None:
            return action_result.get_status()
        summary = param.get("summary", "")
        detail = param.get("detail", "")

        url = "{}{}".format(self._base_url, INCIDENT_CLOSE_PATH.format(incident_id))
        body = {"summary": summary, "detail": detail}

        ret_val, _ = self._make_rest_call("POST", url, action_result, json=body)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data({"success": True})
        action_result.update_summary({"incident_id": incident_id})
        return action_result.set_status(
            phantom.APP_SUCCESS,
            "Incident {} closed".format(incident_id),
        )

    # ------------------------------------------------------------------
    # Action: add comment
    # ------------------------------------------------------------------

    def _handle_add_comment(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        incident_id = self._validate_integer(action_result, param.get("incident_id"), "incident_id")
        if incident_id is None:
            return action_result.get_status()
        summary = param.get("summary", "")
        detail = param.get("detail", "")

        url = "{}{}".format(self._base_url, INCIDENT_COMMENT_PATH.format(incident_id))
        body = {"summary": summary}
        if detail:
            body["detail"] = detail

        ret_val, _ = self._make_rest_call("POST", url, action_result, json=body)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data({"success": True})
        action_result.update_summary({"incident_id": incident_id})
        return action_result.set_status(
            phantom.APP_SUCCESS,
            "Comment added to incident {}".format(incident_id),
        )

    # ------------------------------------------------------------------
    # Incident-update actions — confirmed 2026-08-12 against the vendor's
    # own API reference (proofpoint_trap_api_reference.md): all four are
    # legacy /api/incidents/{id}/... POST endpoints, NOT /api/v1/alerts
    # (which is GET-only — alert details + download original message).
    # Previously built against a PATCH /api/v1/alerts?id={id} guess that
    # doesn't exist in the vendor doc; corrected below.
    # ------------------------------------------------------------------

    # ------------------------------------------------------------------
    # Action: add user to incident
    # ------------------------------------------------------------------

    def _handle_add_user_to_incident(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        incident_id = self._validate_integer(action_result, param.get("incident_id"), "incident_id")
        if incident_id is None:
            return action_result.get_status()
        targets = [t.strip() for t in param.get("targets", "").split(",") if t.strip()]
        attackers = [a.strip() for a in param.get("attackers", "").split(",") if a.strip()]
        if not targets and not attackers:
            return action_result.set_status(
                phantom.APP_ERROR, "At least one of 'targets' or 'attackers' is required"
            )

        url = "{}{}".format(self._base_url, INCIDENT_USERS_PATH.format(incident_id))
        body = {"targets": targets, "attackers": attackers}

        ret_val, _ = self._make_rest_call("POST", url, action_result, json=body)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data({"success": True})
        action_result.update_summary({"incident_id": incident_id})
        return action_result.set_status(
            phantom.APP_SUCCESS,
            "Users added to incident {} (targets={}, attackers={})".format(
                incident_id, targets, attackers
            ),
        )

    # ------------------------------------------------------------------
    # Action: update incident description
    # ------------------------------------------------------------------

    def _handle_update_incident_description(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        incident_id = self._validate_integer(action_result, param.get("incident_id"), "incident_id")
        if incident_id is None:
            return action_result.get_status()
        description = param.get("description", "")
        overwrite = param.get("overwrite", False)

        url = "{}{}".format(self._base_url, INCIDENT_DESCRIPTION_PATH.format(incident_id))
        body = {"description": description, "overwrite": overwrite}

        ret_val, _ = self._make_rest_call("POST", url, action_result, json=body)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data({"success": True})
        action_result.update_summary({"incident_id": incident_id})
        return action_result.set_status(
            phantom.APP_SUCCESS,
            "Description {} on incident {}".format(
                "overwritten" if overwrite else "appended", incident_id
            ),
        )

    # ------------------------------------------------------------------
    # Action: update team and assignee
    # ------------------------------------------------------------------

    def _handle_update_incident_assignee(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        incident_id = self._validate_integer(action_result, param.get("incident_id"), "incident_id")
        if incident_id is None:
            return action_result.get_status()
        assignee = param.get("assignee", "")
        team = param.get("team", "")

        # Both required together -- the appliance rejects a request with
        # only one set. This check just fails fast with the same message
        # the appliance itself returns.
        if not assignee or not team:
            return action_result.set_status(
                phantom.APP_ERROR,
                "Both team and assignee are required. Team: {}, assignee: {}".format(
                    team or "null", assignee or "null"
                ),
            )

        body = {"assignee": assignee, "team": team}

        url = "{}{}".format(self._base_url, INCIDENT_TEAM_ASSIGNEE_PATH.format(incident_id))

        ret_val, _ = self._make_rest_call("POST", url, action_result, json=body)
        if phantom.is_fail(ret_val):
            # HTTP 404 here isn't "resource not found" -- TRAP uses it as an
            # idempotency signal when the requested team/assignee already
            # match the incident's current state, treated as success rather
            # than a hard failure (same idiom as save_container's
            # "duplicate container found"). Any other failure message
            # (including a bad/unknown assignee, or a ConstraintViolationException
            # from the appliance's own backend -- see README.md's
            # troubleshooting section) passes through unchanged.
            raw_msg = action_result.get_message() or ""
            if "previous team and assignee are same" not in raw_msg.lower():
                return action_result.get_status()
            action_result.add_data({"success": True, "no_op": True})
            action_result.update_summary({"incident_id": incident_id})
            return action_result.set_status(
                phantom.APP_SUCCESS,
                "Incident {} already had this team/assignee — no change made".format(incident_id),
            )

        action_result.add_data({"success": True, "no_op": False})
        action_result.update_summary({"incident_id": incident_id})
        return action_result.set_status(
            phantom.APP_SUCCESS,
            "Team/assignee updated on incident {}".format(incident_id),
        )

    # ------------------------------------------------------------------
    # Action: set incident field value
    # ------------------------------------------------------------------

    def _handle_set_incident_field(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        incident_id = self._validate_integer(action_result, param.get("incident_id"), "incident_id")
        if incident_id is None:
            return action_result.get_status()
        field = param.get("field", "")
        value = param.get("value", "")
        if not field:
            return action_result.set_status(phantom.APP_ERROR, "'field' is required")

        url = "{}{}".format(self._base_url, INCIDENT_FIELDS_PATH.format(incident_id))
        body = {"fields": {field: value}}

        ret_val, _ = self._make_rest_call(
            "POST", url, action_result, params={"allow_data_override": "true"}, json=body
        )
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data({"success": True})
        action_result.update_summary({"incident_id": incident_id})
        return action_result.set_status(
            phantom.APP_SUCCESS,
            "Field '{}' set to '{}' on incident {}".format(field, value, incident_id),
        )

    # ------------------------------------------------------------------
    # Action: download mime body
    # ------------------------------------------------------------------

    def _handle_download_mime_body(self, param):
        """Download the raw MIME body for one event, or all events on an
        incident when event_id is omitted, and store each in the Vault."""
        action_result = self.add_action_result(ActionResult(dict(param)))

        incident_id = self._validate_integer(action_result, param.get("incident_id"), "incident_id")
        if incident_id is None:
            return action_result.get_status()

        container_id = self.get_container_id()
        raw_event_id = param.get("event_id")

        if raw_event_id not in (None, ""):
            event_ids = [raw_event_id]
        else:
            events = self._fetch_incident_events(incident_id)
            event_ids = [e.get("id") for e in events if e.get("id")]
            if not event_ids:
                return action_result.set_status(
                    phantom.APP_ERROR,
                    "Incident {} has no events to fetch MIME for".format(incident_id),
                )

        succeeded, failed = 0, 0
        errors = []

        for event_id in event_ids:
            ret_val, vault_id, file_name, err = self._download_and_vault_mime(
                incident_id, event_id, container_id
            )
            if phantom.is_fail(ret_val):
                failed += 1
                errors.append("event {}: {}".format(event_id, err))
                continue

            action_result.add_data({
                "event_id": event_id,
                "vault_id": vault_id,
                "file_name": file_name,
            })
            succeeded += 1

        action_result.update_summary({
            "succeeded": succeeded,
            "failed": failed,
            "total": len(event_ids),
        })

        if succeeded == 0:
            return action_result.set_status(
                phantom.APP_ERROR,
                "All {} MIME downloads failed: {}".format(failed, "; ".join(errors)[:500]),
            )
        return action_result.set_status(
            phantom.APP_SUCCESS,
            "{}/{} MIME bodies downloaded".format(succeeded, len(event_ids)),
        )


def main():
    import argparse

    argparser = argparse.ArgumentParser()
    argparser.add_argument("input_test_json", help="Input Test JSON file")
    args = argparser.parse_args()

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)

    connector = ProofpointTrapConnector()
    connector.print_progress_message = True
    ret_val = connector._handle_action(json.dumps(in_json), None)
    print(json.dumps(json.loads(ret_val), indent=4))

    sys.exit(0)


if __name__ == "__main__":
    main()

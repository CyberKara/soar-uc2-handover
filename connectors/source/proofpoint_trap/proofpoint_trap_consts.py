# proofpoint_trap_consts.py
"""Constants for Proofpoint TRAP SOAR Connector."""

# Asset config keys
BASE_URL_KEY = "base_url"
API_KEY_KEY = "api_key"
VERIFY_SSL_KEY = "verify_ssl"
TIMEOUT_KEY = "timeout"
POLL_STATE_KEY = "poll_state"
ABUSE_DISPOSITION_KEY = "abuse_disposition"
SUB_DISPOSITION_KEY = "sub_disposition"
POLL_HOURS_KEY = "poll_hours"
SEVERITY_KEY = "severity"
SENSITIVITY_KEY = "sensitivity"

# API paths
INCIDENTS_PATH = "/api/incidents"
INCIDENT_DETAIL_PATH = "/api/incidents/{}.json"
INCIDENT_CLOSE_PATH = "/api/incidents/{}/close.json"
INCIDENT_COMMENT_PATH = "/api/incidents/{}/comments.json"
# Alert API: an incident's events[] are its alerts, so this takes an
# events[].id. Needs "Accept: message/rfc822" (vendor doc, "Download
# Original Abuse Messages").
ALERT_ORIGINAL_MSG_PATH = "/api/v1/alerts/{}/download_original_msg"
INCIDENT_USERS_PATH = "/api/incidents/{}/users.json"
INCIDENT_DESCRIPTION_PATH = "/api/incidents/{}/description.json"
INCIDENT_TEAM_ASSIGNEE_PATH = "/api/incidents/{}/team_and_assignee.json"
INCIDENT_FIELDS_PATH = "/api/incidents/{}/incident_fields.json"

# Defaults
DEFAULT_TIMEOUT = 60
DEFAULT_POLL_STATE = "new"
DEFAULT_ABUSE_DISPOSITION = "Unknown"
DEFAULT_SUB_DISPOSITION = ""  # empty = no Sub Disposition filtering
DEFAULT_POLL_HOURS = 1
MAX_RETRIES = 3
RETRYABLE_STATUS_CODES = [500, 502, 503, 504]

# On-prem Threat Response caps a created_after/created_before window at 30 days
MAX_POLL_WINDOW_HOURS = 24 * 30

# Initial container severity/sensitivity when the asset sets none;
# proofpoint_trap_triage maps the TRAP Severity to the real one later.
DEFAULT_SEVERITY = "low"
DEFAULT_SENSITIVITY = "amber"

# Error messages
ERR_CONNECTION = "API Error: Unable to connect to Proofpoint TRAP at {}"
ERR_SSL = "API Error: SSL error — check verify_ssl setting"
ERR_TIMEOUT = "API Error: Request timed out after {} seconds"
ERR_AUTH = "Auth Error: Invalid API key — verify key in TRAP System Settings"
ERR_EVENT_NOT_FOUND = "No original message for event {} (HTTP 404) -- not an alert id, or the alert has no stored message"

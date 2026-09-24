"""
Proofpoint TRAP Attachment Extraction

Automation playbook triggered on artifact creation for label 'proofpoint_trap'.
Scans the container for 'MIME Body' artifacts (vaulted raw .eml, created by the
proofpoint_trap connector's on_poll — see FR-21), parses each one for:
  - file attachments — vaulted as their own artifact (name 'Email Attachment',
    cef.vaultId + cef.fileName + cef.fileHashSha256 + cef.fileType) for
    downstream analyst review / future reputation enrichment (UC8). Includes
    forwarded emails attached as message/rfc822 (the raw embedded message is
    serialized and vaulted like any other attachment — these were silently
    skipped before 2026-08-12 because message/rfc822 parts report
    is_multipart()=True, tripping the "skip container parts" check meant for
    genuine multipart/* wrappers). Flags a MIME-type/filename mismatch
    (mimetypes.guess_type vs the part's declared Content-Type) as a possible
    disguised-executable signal.
  - Cc recipients — parsed directly from the raw MIME headers (getaddresses),
    as 'Recipient Email' artifacts (emailRole='cc'), matching PB1's existing
    artifact shape. PB1 attempts this too but only from the structured API's
    headers dict, which real payloads never populate (see its own comment) —
    this is the reliable path.
  - Return-Path vs From mismatch — envelope sender vs displayed sender is a
    classic spoofing signal, surfaced in the Email Content note.
  - the rendered email body (HTML preferred, falls back to plain text) and
    auth/routing headers (Authentication-Results, Reply-To, X-Originating-IP,
    Received chain) — none of this exists in TRAP's structured "get incident"
    API, only in the raw MIME — added as an "Email Content" note per event so
    an analyst can read the actual message without downloading the .eml.

    phantom.add_note() sanitizes content through a real (undocumented) tag
    allowlist, confirmed live 2026-08-12 by probing it directly: h1/h2/p/b/
    ul/li/hr/span/br survive; pre/details/summary/code/div/i are silently
    stripped (text kept, tag dropped); <a href=...> keeps the <a> tag but
    strips the href attribute, so links never work. Formatting below only
    uses the confirmed-safe tags — no <pre>, no <details>, no links. A raw
    HTML body from a real phishing email (tables, images, div layouts) will
    still get stripped down to bare readable text by this same sanitizer;
    that's a platform limitation, not something this playbook can route
    around short of writing HTML to a note some other way.

Re-scans all MIME Body artifacts on every run (same pattern as ip_enrich) and
skips any already marked processed via a data.attachments_extracted marker —
tolerates the "artifact_created fires on container AND artifact creation"
platform behavior (constraints.md) without needing to distinguish trigger type.

Trigger: Artifact created, label 'proofpoint_trap'
"""


import phantom.rules as phantom
import json
import hashlib
import html
import email
import email.policy
import mimetypes
import os
import tempfile
from email.utils import getaddresses, parseaddr


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    extract_attachments(container=container)

    return


@phantom.playbook_block()
def extract_attachments(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("extract_attachments() called")

    ################################################################################
    # Find MIME Body artifacts not yet processed, parse each .eml from the vault,
    # and vault out any file attachments as their own artifacts.
    ################################################################################

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Local re-imports — GUI edits recompile/lint each code block in isolation
    # and don't see module-level imports (same gap already documented for
    # urllib.parse/uuid elsewhere in this UC's playbooks).
    import os
    import hashlib
    import html
    import mimetypes
    import tempfile
    import email
    import email.policy
    from email.utils import getaddresses, parseaddr

    container_id = container.get("id")

    mime_rows = phantom.collect2(
        container=container,
        datapath=["artifact:*.name", "artifact:*.id", "artifact:*.cef.vaultId", "artifact:*.cef.fileName"],
    )

    mime_artifacts = [
        {"artifact_id": row[1], "vault_id": row[2], "file_name": row[3]}
        for row in (mime_rows or [])
        if row[0] == "MIME Body" and row[2]
    ]

    if not mime_artifacts:
        phantom.debug("No MIME Body artifacts on this container yet")
        return

    total_extracted = 0
    per_email_summary = []

    for mime in mime_artifacts:
        artifact_id = mime["artifact_id"]

        # Skip artifacts already processed (re-entry guard — see module docstring)
        try:
            resp = phantom.requests.get(uri=phantom.build_phantom_rest_url("artifact", artifact_id), verify=False).json()
            current_data = resp.get("data") if isinstance(resp.get("data"), dict) else {}
        except Exception as e:
            phantom.debug("Could not read artifact {}: {}".format(artifact_id, str(e)))
            continue

        if current_data.get("attachments_extracted"):
            continue

        source_file_name = mime["file_name"] or "trap-{}.eml".format(artifact_id)
        # source_data_identifier on the MIME Body artifact is "trap-{incident_id}-mime-{event_id}"
        # (see proofpoint_trap_connector.py _build_mime_artifact) — recover both IDs from it.
        sdi = resp.get("source_data_identifier") or ""
        sdi_parts = sdi.split("-mime-")
        incident_id = sdi_parts[0].replace("trap-", "", 1) if sdi_parts else "?"
        event_id = sdi_parts[1] if len(sdi_parts) > 1 else "?"

        try:
            vi_result = phantom.vault_info(vault_id=mime["vault_id"])
        except Exception as e:
            phantom.debug("vault_info() raised for vault_id {}: {}".format(mime["vault_id"], str(e)))
            continue

        # phantom.vault_info()'s return shape isn't independently verified anywhere
        # in this repo yet (see memory project_soar85_vault_api_quirks — only the
        # official-docs signature was confirmed, not a live return value). Handle
        # both the documented 3-tuple form (success, message, info_list) and a
        # bare list-of-dicts return defensively, and log the raw shape on mismatch
        # so a real run pins this down for good.
        vault_entries = None
        if isinstance(vi_result, tuple) and len(vi_result) == 3:
            vi_success, vi_message, vi_entries = vi_result
            if vi_success:
                vault_entries = list(vi_entries) if vi_entries else []
            else:
                phantom.debug("vault_info failed for vault_id {}: {}".format(mime["vault_id"], vi_message))
        elif isinstance(vi_result, (list, tuple)):
            vault_entries = list(vi_result)
        else:
            phantom.debug("Unexpected vault_info() return type {} for vault_id {}: {!r}".format(type(vi_result), mime["vault_id"], vi_result))

        if not vault_entries:
            continue

        first_entry = vault_entries[0]
        file_path = first_entry.get("path") if isinstance(first_entry, dict) else None
        if not file_path or not os.path.exists(file_path):
            phantom.debug("No usable local path from vault_info for vault_id {}: {!r}".format(mime["vault_id"], first_entry))
            continue

        try:
            with open(file_path, "rb") as fp:
                parsed = email.message_from_binary_file(fp, policy=email.policy.default)
        except Exception as e:
            phantom.debug("Failed to parse MIME body {}: {}".format(source_file_name, str(e)))
            continue

        extracted_this_email = 0
        for part in parsed.walk():
            content_type = part.get_content_type()
            is_forwarded_email = content_type == "message/rfc822"

            # message/rfc822 (a forwarded/embedded email) reports
            # is_multipart()=True since it wraps one Message object rather
            # than raw bytes — skip genuine multipart/* container parts, but
            # not this one.
            if part.is_multipart() and not is_forwarded_email:
                continue

            filename = part.get_filename()
            disposition = (part.get_content_disposition() or "").lower()
            if not filename or disposition != "attachment":
                continue

            if is_forwarded_email:
                try:
                    embedded = part.get_payload()[0]
                    payload = embedded.as_bytes()
                except Exception as e:
                    phantom.debug("Could not serialize forwarded message {}: {}".format(filename, str(e)))
                    continue
            else:
                payload = part.get_payload(decode=True)

            if not payload:
                continue

            sha256 = hashlib.sha256(payload).hexdigest()

            guessed_type, _ = mimetypes.guess_type(filename)
            type_mismatch = bool(guessed_type) and guessed_type != content_type

            tmp_fd, tmp_path = tempfile.mkstemp(prefix="trap_attach_")
            os.close(tmp_fd)
            try:
                with open(tmp_path, "wb") as tmp_fp:
                    tmp_fp.write(payload)

                success_va, msg_va, attachment_vault_id = phantom.vault_add(
                    container=container_id,
                    file_location=tmp_path,
                    file_name=filename,
                )
            finally:
                try:
                    os.remove(tmp_path)
                except OSError:
                    pass

            if not success_va:
                phantom.debug("vault_add failed for {}: {}".format(filename, msg_va))
                continue

            attachment_cef = {
                "vaultId": attachment_vault_id,
                "fileName": filename,
                "fileHashSha256": sha256,
                "fileType": content_type,
            }
            if type_mismatch:
                attachment_cef["mimeTypeMismatch"] = "declared {}, expected {} from filename".format(content_type, guessed_type)

            attachment_artifact = {
                "name": "Email Attachment",
                "description": "{}Attachment '{}' from TRAP incident {} event {}".format(
                    "Forwarded email " if is_forwarded_email else "", filename, incident_id, event_id
                ),
                "source_data_identifier": "trap-{}-{}-attachment-{}-{}".format(incident_id, event_id, filename, sha256[:12]),
                "label": "event",
                "cef": attachment_cef,
                "cef_types": {"vaultId": ["vault id"], "fileHashSha256": ["sha256"]},
                "container_id": container_id,
                "run_automation": False,
            }
            try:
                resp2 = phantom.requests.post(
                    uri=phantom.build_phantom_rest_url("artifact"),
                    data=json.dumps(attachment_artifact),
                    verify=False,
                ).json()
                if resp2.get("success") or resp2.get("id"):
                    extracted_this_email += 1
                    total_extracted += 1
                else:
                    phantom.debug("Failed to create attachment artifact: {}".format(resp2.get("message", "")))
            except Exception as e:
                phantom.debug("Error creating attachment artifact: {}".format(str(e)))

        # Cc recipients — from the raw MIME headers, not TRAP's structured API
        # (PB1 also tries this from the structured response's headers dict but
        # real payloads never populate it there, per its own comment; same
        # artifact shape/SDI pattern here so a duplicate from PB1 would just
        # dedupe cleanly if that ever changes).
        cc_addrs = sorted({addr for _, addr in getaddresses(parsed.get_all("Cc") or []) if addr})
        for cc_addr in cc_addrs:
            cc_artifact = {
                "name": "Recipient Email",
                "description": "Cc recipient from TRAP incident {} event {}".format(incident_id, event_id),
                "source_data_identifier": "trap-{}-{}-cc-{}".format(incident_id, event_id, cc_addr),
                "label": "event",
                "cef": {
                    "emailAddress": cc_addr,
                    "emailRole": "cc",
                },
                "cef_types": {"emailAddress": ["email"]},
                "container_id": container_id,
                "run_automation": False,
            }
            try:
                phantom.requests.post(
                    uri=phantom.build_phantom_rest_url("artifact"),
                    data=json.dumps(cc_artifact),
                    verify=False,
                )
            except Exception as e:
                phantom.debug("Error creating Cc artifact for {}: {}".format(cc_addr, str(e)))

        # Rendered body + auth/routing headers — only exist in the raw MIME,
        # not in TRAP's structured "get incident" response.
        try:
            body_part = parsed.get_body(preferencelist=("html", "plain"))
        except Exception as e:
            body_part = None
            phantom.debug("get_body() failed for {}: {}".format(source_file_name, str(e)))

        body_html = None
        if body_part is not None:
            try:
                body_content = body_part.get_content()
            except Exception as e:
                body_content = None
                phantom.debug("Could not decode body for {}: {}".format(source_file_name, str(e)))
            if body_content:
                if body_part.get_content_type() == "text/html":
                    body_html = body_content
                else:
                    # <pre> is stripped by phantom.add_note()'s sanitizer (see
                    # docstring) — use <p>/<br>, the confirmed-safe equivalent
                    # for preserving line breaks in plain text.
                    body_html = "<p>{}</p>".format(html.escape(body_content).replace("\n", "<br>\n"))

        auth_results = parsed.get_all("Authentication-Results") or []
        received_chain = parsed.get_all("Received") or []
        reply_to = parsed.get("Reply-To", "")
        x_originating_ip = parsed.get("X-Originating-IP", "")
        return_path = parsed.get("Return-Path", "")
        from_header = parsed.get("From", "")

        _, return_path_addr = parseaddr(return_path)
        _, from_addr = parseaddr(from_header)
        return_path_mismatch = bool(return_path_addr) and bool(from_addr) and return_path_addr.lower() != from_addr.lower()

        header_lines = ["<h1>Email Content — {} (event {})</h1>".format(html.escape(source_file_name), html.escape(event_id))]
        if return_path:
            mismatch_note = " — <b>does not match From ({})</b>".format(html.escape(from_addr)) if return_path_mismatch else ""
            header_lines.append("<p><b>Return-Path:</b> {}{}</p>".format(html.escape(return_path), mismatch_note))
        if reply_to:
            header_lines.append("<p><b>Reply-To:</b> {}</p>".format(html.escape(reply_to)))
        if x_originating_ip:
            header_lines.append("<p><b>X-Originating-IP:</b> {}</p>".format(html.escape(x_originating_ip)))
        if auth_results:
            header_lines.append("<p><b>Authentication-Results:</b></p><ul>")
            for ar in auth_results:
                header_lines.append("<li>{}</li>".format(html.escape(ar)))
            header_lines.append("</ul>")
        if received_chain:
            # <details>/<summary> (for a collapsible view) and <pre> are both
            # stripped by phantom.add_note()'s sanitizer (see docstring) —
            # print the chain directly instead.
            header_lines.append("<p><b>Received chain ({} hop(s)):</b></p>".format(len(received_chain)))
            for hop in received_chain:
                header_lines.append("<p>{}</p>".format(html.escape(hop).replace("\n", "<br>\n")))

        note_html = "\n".join(header_lines)
        if body_html:
            note_html += "\n<hr>\n" + body_html
        else:
            note_html += "\n<p><i>No readable body part found in this MIME message.</i></p>"

        try:
            phantom.add_note(
                container=container,
                note_type="general",
                title="Email Content — {}".format(source_file_name),
                content=note_html,
            )
        except Exception as e:
            phantom.debug("Could not add Email Content note for {}: {}".format(source_file_name, str(e)))

        per_email_summary.append("**{}** (event {}): {} attachment(s)".format(source_file_name, event_id, extracted_this_email))

        # Mark this MIME Body artifact processed regardless of whether it had
        # attachments, so future artifact-created triggers on this container
        # don't re-parse it.
        merged_data = dict(current_data)
        merged_data["attachments_extracted"] = True
        merged_data["attachments_extracted_count"] = extracted_this_email
        try:
            phantom.requests.post(
                uri=phantom.build_phantom_rest_url("artifact", artifact_id),
                data=json.dumps({"data": merged_data}),
                verify=False,
            )
        except Exception as e:
            phantom.debug("Could not mark MIME Body artifact {} as processed: {}".format(artifact_id, str(e)))

    if per_email_summary:
        note_content = (
            "# Email Attachment Extraction\n"
            "**Total attachments extracted:** {}\n\n"
            "{}"
        ).format(total_extracted, "\n".join("- " + line for line in per_email_summary))
        phantom.add_note(
            container=container,
            note_type="general",
            title="Attachment Extraction",
            content=note_content,
        )

    phantom.debug("Attachment extraction complete: {} attachment(s) across {} MIME body/bodies".format(total_extracted, len(mime_artifacts)))

    ################################################################################
    ## Custom Code End
    ################################################################################

    return


def on_finish(container, summary):
    phantom.debug("on_finish() called")
    return

"""
Automation playbook triggered on artifact creation for label &#39;proofpoint_trap&#39;. Scans the container for &#39;MIME Body&#39; artifacts (vaulted raw .eml, created by the connector&#39;s on_poll -- see FR-21), parses each one for file attachments, and vaults each attachment as its own &#39;Email Attachment&#39; artifact (vaultId, fileName, fileHashSha256).
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


################################################################################
## Global Custom Code Start
################################################################################



# Safe markdown rendering of an email body for the "Email Content" note.
# Nothing from the email may load or be clickable in the analyst's browser:
# scripts/styles/iframes are dropped, images become placeholders, every link is
# shown as its text plus the defanged real target in a code span, and all text
# is escaped so email content cannot inject markup into the note.
# Standard library only (html.parser): SOAR's validator flags lxml.
import re
import html as _html_mod
from html.parser import HTMLParser

_URL_RE = re.compile(r"(?:https?|ftp)://[^\s<>\"'`]+", re.I)
_SKIP_TAGS = {"script", "style", "head", "title", "noscript", "template", "iframe", "object", "embed", "svg", "meta", "link"}
_BLOCK_TAGS = {"html", "body", "p", "div", "section", "article", "header", "footer", "center", "blockquote", "main", "aside", "nav",
               "table", "tbody", "thead", "tfoot", "tr", "ul", "ol", "li", "h1", "h2", "h3", "h4", "h5", "h6", "form", "hr", "pre", "address"}
_VOID_TAGS = {"br", "img", "hr", "meta", "link", "input", "area", "base", "col", "embed", "source", "track", "wbr", "param"}
_HIDDEN_STYLE_RE = re.compile(r"display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0(?:px|pt|em|%)?\s*(?:;|$)|opacity\s*:\s*0(?:\.0+)?\s*(?:;|$)", re.I)
_MAX_BODY_CHARS = 20000


def _defang(url):
    url = (url or "").strip()
    url = re.sub(r"^http", "hxxp", url, flags=re.I)
    url = re.sub(r"^ftp", "fxp", url, flags=re.I)
    m = re.match(r"^([a-z]+://)([^/?#]*)(.*)$", url, re.I)
    if m:
        url = m.group(1) + m.group(2).replace(".", "[.]") + m.group(3)
    return url


def _code(text):
    return "`" + (text or "").replace("`", "'").replace("\n", " ") + "`"


def _md_escape(text):
    text = _html_mod.escape(text or "", quote=False)
    return re.sub(r"([\\`*_\[\]#|])", r"\\\1", text)


def _md_text(text):
    """Escape plain text for markdown, turning bare URLs into defanged code spans."""
    out, pos = [], 0
    for m in _URL_RE.finditer(text or ""):
        out.append(_md_escape(text[pos:m.start()]))
        out.append(_code(_defang(m.group(0))))
        pos = m.end()
    out.append(_md_escape((text or "")[pos:]))
    return "".join(out)


def _urldefense_original(url):
    """The original URL behind a Proofpoint URL Defense link (v2 fully, v3 up to
    its '*' placeholders), or None when the link is not a URL Defense one."""
    import urllib.parse
    m = re.match(r"^https?://urldefense(?:\.proofpoint)?\.com/v2/url\?(.*)$", url or "", re.I)
    if m:
        u = urllib.parse.parse_qs(m.group(1)).get("u", [""])[0]
        return urllib.parse.unquote(u.replace("-", "%").replace("_", "/")) or None
    m = re.match(r"^https?://urldefense\.com/v3/__(.+?)__;", url or "", re.I)
    if m:
        return m.group(1)
    return None


def _host(value):
    m = re.match(r"^\s*(?:[a-z]+://)?([^/\s?#:]+)", value or "", re.I)
    return m.group(1).lower() if m else ""


class _Tree(HTMLParser):
    def __init__(self):
        HTMLParser.__init__(self, convert_charrefs=True)
        self.root = {"tag": "root", "attrs": {}, "children": []}
        self.stack = [self.root]

    def handle_starttag(self, tag, attrs):
        node = {"tag": tag, "attrs": dict(attrs), "children": []}
        self.stack[-1]["children"].append(node)
        if tag not in _VOID_TAGS:
            self.stack.append(node)

    def handle_startendtag(self, tag, attrs):
        self.stack[-1]["children"].append({"tag": tag, "attrs": dict(attrs), "children": []})

    def handle_endtag(self, tag):
        for i in range(len(self.stack) - 1, 0, -1):
            if self.stack[i]["tag"] == tag:
                del self.stack[i:]
                return

    def handle_data(self, data):
        self.stack[-1]["children"].append(data)


def _is_hidden(node):
    attrs = node.get("attrs") or {}
    return "hidden" in attrs or bool(_HIDDEN_STYLE_RE.search(attrs.get("style") or ""))


def _has_block(node):
    for child in node.get("children") or []:
        if isinstance(child, dict) and (child["tag"] in _BLOCK_TAGS or child["tag"] == "br" or _has_block(child)):
            return True
    return False


def _has_tag(node, tag):
    for child in node.get("children") or []:
        if isinstance(child, dict) and (child["tag"] == tag or _has_tag(child, tag)):
            return True
    return False


def _inline(node, notes):
    """Render a node's content as one line of escaped markdown."""
    parts = []
    for child in node.get("children") or []:
        if isinstance(child, str):
            parts.append(_md_text(re.sub(r"\s+", " ", child)))
            continue
        tag = child["tag"]
        if tag in _SKIP_TAGS:
            continue
        if _is_hidden(child):
            hidden = re.sub(r"\s+", " ", _plain(child)).strip()
            if hidden:
                parts.append(" [hidden] " + _md_escape(hidden[:300]) + " ")
            continue
        if tag == "br":
            parts.append(" ")
        elif tag == "img":
            parts.append(_image(child))
        elif tag == "a":
            parts.append(_link(child, notes))
        elif tag in ("b", "strong"):
            inner = _inline(child, notes).strip()
            parts.append("**" + inner + "**" if inner else "")
        elif tag in ("i", "em"):
            inner = _inline(child, notes).strip()
            parts.append("*" + inner + "*" if inner else "")
        elif tag == "input":
            if (child["attrs"].get("type") or "").lower() == "password":
                parts.append(" [password field] ")
        else:
            parts.append(_inline(child, notes))
    return re.sub(r"[ \t]+", " ", "".join(parts))


def _plain(node):
    out = []
    for child in node.get("children") or []:
        if isinstance(child, str):
            out.append(child)
        elif child["tag"] not in _SKIP_TAGS:
            out.append(" " + _plain(child) + " ")
    return "".join(out)


def _image(node):
    attrs = node.get("attrs") or {}
    src = (attrs.get("src") or "").strip()
    alt = re.sub(r"\s+", " ", attrs.get("alt") or "").strip()
    label = "[image" + (": " + _md_escape(alt[:80]) if alt else "") + "]"
    if src.lower().startswith(("http://", "https://", "//")):
        return " " + label + " " + _code(_defang(src if not src.startswith("//") else "https:" + src)) + " "
    if src.lower().startswith("cid:"):
        return " " + label.replace("[image", "[inline image", 1) + " "
    if src.lower().startswith("data:"):
        return " " + label.replace("[image", "[embedded image", 1) + " "
    return " " + label + " "


def _link(node, notes):
    href = ((node.get("attrs") or {}).get("href") or "").strip()
    text = _inline(node, notes).strip()
    raw_text = re.sub(r"\s+", " ", _plain(node)).strip()
    low = href.lower()
    if low.startswith("javascript:"):
        return (text + " " if text else "") + "[javascript link removed]"
    if low.startswith("mailto:"):
        return (text + " " if text else "") + "(mail to " + _code(href[7:]) + ")"
    if not low.startswith(("http://", "https://", "ftp://", "//")):
        return text
    target = _defang(href if not href.startswith("//") else "https:" + href)
    original = _urldefense_original(href)
    if original:
        target += " (URL Defense, original: " + _defang(original) + ")"
    shown_host, real_host = _host(raw_text), _host((original or href).lstrip("/"))
    looks_like_url = bool(re.match(r"^\s*(?:[a-z]+://|www\.)|^[\w-]+(?:\.[\w-]+)+(?:/|\s*$)", raw_text, re.I))
    related = real_host.endswith("." + shown_host) or shown_host.endswith("." + real_host)
    if looks_like_url and shown_host and real_host and shown_host != real_host and not related:
        notes.append("Link text shows {} but goes to {}".format(_code(shown_host), _code(_defang("http://" + real_host)[7:])))
        return (text or "") + " → " + _code(target) + " ⚠"
    if text and raw_text.rstrip("/") not in (href.rstrip("/"), (original or "").rstrip("/")):
        return text + " → " + _code(target)
    return _code(target)


def _blocks(node, notes, out):
    """Append rendered markdown blocks (paragraph strings) for a node's children."""
    line = []

    def flush():
        text = re.sub(r"[ \t]+", " ", "".join(line)).strip()
        if text:
            out.append(text)
        del line[:]

    for child in node.get("children") or []:
        if isinstance(child, str):
            line.append(_md_text(re.sub(r"\s+", " ", child)))
            continue
        tag = child["tag"]
        if tag in _SKIP_TAGS:
            continue
        if _is_hidden(child):
            hidden = re.sub(r"\s+", " ", _plain(child)).strip()
            if hidden:
                line.append(" [hidden] " + _md_escape(hidden[:300]) + " ")
            continue
        if tag not in _BLOCK_TAGS and tag != "br":
            if tag == "img":
                line.append(_image(child))
            elif tag == "a":
                line.append(_link(child, notes))
            elif tag in ("b", "strong"):
                inner = _inline(child, notes).strip()
                line.append("**" + inner + "**" if inner else "")
            elif tag in ("i", "em"):
                inner = _inline(child, notes).strip()
                line.append("*" + inner + "*" if inner else "")
            elif tag == "input":
                if (child["attrs"].get("type") or "").lower() == "password":
                    line.append(" [password field] ")
            else:
                # inline wrapper (span, font, i, u, ...) that may hold blocks
                if _has_block(child):
                    flush()
                    _blocks(child, notes, out)
                else:
                    line.append(_inline(child, notes))
            continue
        flush()
        if tag == "br":
            continue
        if tag == "hr":
            out.append("---")
        elif tag in ("h1", "h2", "h3", "h4", "h5", "h6"):
            text = _inline(child, notes).strip()
            if text:
                out.append("**" + text + "**")
        elif tag in ("ul", "ol"):
            items, n = [], 0
            for item in child["children"]:
                if isinstance(item, dict) and item["tag"] == "li":
                    n += 1
                    text = _inline(item, notes).strip()
                    if text:
                        items.append(("{}. ".format(n) if tag == "ol" else "- ") + text)
            if items:
                out.append("\n".join(items))
        elif tag == "table":
            _table(child, notes, out)
        elif tag == "form":
            action = (child["attrs"].get("action") or "").strip()
            out.append("[form" + (" submits to " + _code(_defang(action)) if action else "") + "]")
            _blocks(child, notes, out)
        elif tag == "pre":
            for text_line in _plain(child).splitlines():
                if text_line.strip():
                    out.append(_md_text(text_line.strip()))
        else:
            _blocks(child, notes, out)
    flush()


def _rows(table):
    rows = []
    for child in table["children"]:
        if not isinstance(child, dict):
            continue
        if child["tag"] == "tr":
            rows.append(child)
        elif child["tag"] in ("tbody", "thead", "tfoot"):
            rows.extend(_rows(child))
    return rows


def _table(table, notes, out):
    rows = _rows(table)
    cells = [[c for c in r["children"] if isinstance(c, dict) and c["tag"] in ("td", "th")] for r in rows]
    width = max([len(c) for c in cells] or [0])
    if _has_tag(table, "table") or width < 2 or len(rows) < 2:
        # a layout table (nested, or a single column): flatten it to lines
        for row in rows:
            for cell in row["children"]:
                if isinstance(cell, dict):
                    _blocks(cell, notes, out)
        return
    grid = []
    for row_cells in cells:
        texts = [_inline(c, notes).strip().replace("\n", " ") for c in row_cells]
        grid.append(texts + [""] * (width - len(texts)))
    out.append("\n".join(["| " + " | ".join(grid[0]) + " |", "|" + "---|" * width]
                         + ["| " + " | ".join(r) + " |" for r in grid[1:]]))


def _email_html_to_markdown(html_text):
    tree = _Tree()
    try:
        tree.feed(html_text or "")
        tree.close()
    except Exception:
        return _email_text_to_markdown(re.sub(r"<[^>]+>", " ", html_text or ""))
    notes, out = [], []
    _blocks(tree.root, notes, out)
    body = "\n\n".join(out)
    if len(body) > _MAX_BODY_CHARS:
        body = body[:_MAX_BODY_CHARS] + "\n\n… (truncated, {} more characters)".format(len(body) - _MAX_BODY_CHARS)
    if notes:
        body = "\n".join("⚠ " + n for n in sorted(set(notes))) + "\n\n" + body
    return body


def _email_text_to_markdown(text):
    lines = [_md_text(line.rstrip()) for line in (text or "").splitlines()]
    body = "  \n".join(lines).strip()
    if len(body) > _MAX_BODY_CHARS:
        body = body[:_MAX_BODY_CHARS] + "\n\n… (truncated, {} more characters)".format(len(body) - _MAX_BODY_CHARS)
    return body
################################################################################
## Global Custom Code End
################################################################################

@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'extract_attachments' block
    extract_attachments(container=container)

    return

@phantom.playbook_block()
def extract_attachments(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("extract_attachments() called")

    ################################################################################
    # Find MIME Body artifacts not yet processed, parse each .eml from the vault, 
    # and vault out any file attachments as their own artifacts.
    ################################################################################

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.name","artifact:*.id","artifact:*.cef.vaultId","artifact:*.cef.fileName"])

    container_artifact_header_item_0 = [item[0] for item in container_artifact_data]
    container_artifact_header_item_1 = [item[1] for item in container_artifact_data]
    container_artifact_cef_item_2 = [item[2] for item in container_artifact_data]
    container_artifact_cef_item_3 = [item[3] for item in container_artifact_data]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Design notes (kept here because a VPE save replaces the module docstring):
    # Proofpoint TRAP Attachment Extraction
    #
    # Automation playbook triggered on artifact creation for label 'proofpoint_trap'.
    # Scans the container for 'MIME Body' artifacts (vaulted raw .eml, created by the
    # proofpoint_trap connector's on_poll — see FR-21), parses each one for:
    # - file attachments — vaulted as their own artifact (name 'Email Attachment',
    # cef.vaultId + cef.fileName + cef.fileHashSha256 + cef.fileType) for
    # downstream analyst review / future reputation enrichment (UC8). Includes
    # forwarded emails attached as message/rfc822 (the raw embedded message is
    # serialized and vaulted like any other attachment — these were silently
    # skipped before 2026-08-12 because message/rfc822 parts report
    # is_multipart()=True, tripping the "skip container parts" check meant for
    # genuine multipart/* wrappers). Flags a MIME-type/filename mismatch
    # (mimetypes.guess_type vs the part's declared Content-Type) as a possible
    # disguised-executable signal.
    # - Cc recipients — parsed directly from the raw MIME headers (getaddresses),
    # as 'Recipient Email' artifacts (emailRole='cc'), matching PB1's existing
    # artifact shape. PB1 attempts this too but only from the structured API's
    # headers dict, which real payloads never populate (see its own comment) —
    # this is the reliable path.
    # - Return-Path vs From mismatch — envelope sender vs displayed sender is a
    # classic spoofing signal, surfaced in the Email Content note.
    # - the rendered email body (HTML preferred, falls back to plain text) and
    # auth/routing headers (Authentication-Results, Reply-To, X-Originating-IP,
    # Received chain) — none of this exists in TRAP's structured "get incident"
    # API, only in the raw MIME — added as an "Email Content" note per event so
    # an analyst can read the actual message without downloading the .eml.
    #
    # phantom.add_note() sanitizes content through a real (undocumented) tag
    # allowlist, confirmed live 2026-08-12 by probing it directly: h1/h2/p/b/
    # ul/li/hr/span/br survive; pre/details/summary/code/div/i are silently
    # stripped (text kept, tag dropped); <a href=...> keeps the <a> tag but
    # strips the href attribute, so links never work. So the Email Content
    # note is not written with add_note() any more: it is a markdown note
    # posted over REST, and the body is converted to SAFE markdown first
    # (_email_html_to_markdown in the Global Custom Code) -- scripts/styles
    # dropped, images as placeholders, links shown as text plus the defanged
    # target (URL Defense links decoded), hidden text and forms flagged, all
    # email text escaped. Nothing from the email loads or is clickable.
    #
    # Re-scans all MIME Body artifacts on every run (same pattern as ip_enrich) and
    # skips any already marked processed via a data.attachments_extracted marker —
    # tolerates the "artifact_created fires on container AND artifact creation"
    # platform behavior (constraints.md) without needing to distinguish trigger type.
    #
    # Trigger: Artifact created, label 'proofpoint_trap'


    # Local re-imports — GUI edits recompile/lint each code block in isolation
    # and don't see module-level imports (same gap already documented for
    # urllib.parse/uuid elsewhere in this UC's playbooks).
    import base64
    import hashlib
    import html
    import mimetypes
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

        # Read the email's bytes over REST (download_attachment by vault id)
        # rather than opening the vault file's local path: SOAR's validator flags
        # any filesystem access in a playbook (no-filesystem-access), and the
        # REST route does not depend on this node holding the file.
        try:
            download = phantom.requests.get(
                uri=phantom.build_phantom_rest_url("download_attachment"),
                params={"vault_id": mime["vault_id"]},
                verify=False,
            )
        except Exception as e:
            phantom.debug("Could not download vault file {}: {}".format(mime["vault_id"], str(e)))
            continue
        if download.status_code != 200 or not download.content:
            phantom.debug("Vault download for {} returned HTTP {} ({} bytes)".format(
                mime["vault_id"], download.status_code, len(download.content or b"")))
            continue

        try:
            parsed = email.message_from_bytes(download.content, policy=email.policy.default)
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

            # Store the attachment through REST with its content inline
            # (container_attachment, base64) instead of writing a temp file for
            # phantom.vault_add(): no filesystem access in the playbook.
            try:
                upload = phantom.requests.post(
                    uri=phantom.build_phantom_rest_url("container_attachment"),
                    data=json.dumps({
                        "container_id": container_id,
                        "file_content": base64.b64encode(payload).decode("ascii"),
                        "file_name": filename,
                        "metadata": {"contains": ["vault id"]},
                    }),
                    verify=False,
                ).json()
            except Exception as e:
                phantom.debug("Vault upload failed for {}: {}".format(filename, str(e)))
                continue
            attachment_vault_id = upload.get("vault_id")
            if not upload.get("succeeded") or not attachment_vault_id:
                phantom.debug("Vault upload failed for {}: {}".format(filename, upload.get("message")))
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

        # The body is shown as safe markdown: nothing from the email loads or is
        # clickable in the analyst's browser (see _email_html_to_markdown in the
        # Global Custom Code).
        body_md = None
        body_kind = None
        if body_part is not None:
            try:
                body_content = body_part.get_content()
            except Exception as e:
                body_content = None
                phantom.debug("Could not decode body for {}: {}".format(source_file_name, str(e)))
            if body_content:
                if body_part.get_content_type() == "text/html":
                    body_md = _email_html_to_markdown(body_content)
                    body_kind = "HTML, shown as safe text: links defanged and not clickable, images and scripts removed"
                else:
                    body_md = _email_text_to_markdown(body_content)
                    body_kind = "plain text, URLs defanged"

        auth_results = parsed.get_all("Authentication-Results") or []
        received_chain = parsed.get_all("Received") or []
        reply_to = parsed.get("Reply-To", "")
        x_originating_ip = parsed.get("X-Originating-IP", "")
        return_path = parsed.get("Return-Path", "")
        from_header = parsed.get("From", "")

        _, return_path_addr = parseaddr(return_path)
        _, from_addr = parseaddr(from_header)
        return_path_mismatch = bool(return_path_addr) and bool(from_addr) and return_path_addr.lower() != from_addr.lower()

        lines = ["# Email Content — {} (event {})".format(_md_escape(source_file_name), _md_escape(event_id)), ""]
        for label, value in (("From", from_header), ("To", parsed.get("To", "")),
                             ("Subject", parsed.get("Subject", "")), ("Date", parsed.get("Date", ""))):
            if value:
                lines.append("**{}:** {}  ".format(label, _md_text(" ".join(str(value).split()))))
        if return_path:
            mismatch_note = " — **does not match From ({})**".format(_md_text(from_addr)) if return_path_mismatch else ""
            lines.append("**Return-Path:** {}{}  ".format(_md_text(str(return_path)), mismatch_note))
        if reply_to:
            lines.append("**Reply-To:** {}  ".format(_md_text(str(reply_to))))
        if x_originating_ip:
            lines.append("**X-Originating-IP:** {}  ".format(_md_text(str(x_originating_ip))))
        if auth_results:
            lines += ["", "**Authentication-Results:**", ""]
            lines += ["- " + _md_text(" ".join(str(ar).split())) for ar in auth_results]
        if received_chain:
            lines += ["", "**Received chain ({} hop(s)):**".format(len(received_chain)), ""]
            lines += ["{}. {}".format(n, _md_text(" ".join(str(hop).split()))) for n, hop in enumerate(received_chain, 1)]
        lines += ["", "---", ""]
        if body_md:
            lines += ["**Body** ({})".format(body_kind), "", body_md]
        else:
            lines.append("*No readable body part found in this MIME message.*")

        # Posted over REST as a markdown note: phantom.add_note()'s HTML
        # sanitizer mangled real email bodies, and markdown notes render
        # cleanly (tables included).
        try:
            note_resp = phantom.requests.post(
                uri=phantom.build_phantom_rest_url("note"),
                data=json.dumps({
                    "container_id": container_id,
                    "title": "Email Content — {}".format(source_file_name),
                    "content": "\n".join(lines),
                    "note_type": "general",
                    "note_format": "markdown",
                }),
                verify=False,
            )
            if note_resp.status_code >= 300:
                phantom.debug("Could not add Email Content note for {}: HTTP {} {}".format(
                    source_file_name, note_resp.status_code, note_resp.text[:200]))
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
            note_format="markdown",  # the content is markdown; add_note() defaults to html
        )

    phantom.debug("Attachment extraction complete: {} attachment(s) across {} MIME body/bodies".format(total_extracted, len(mime_artifacts)))

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_block_result(key="extract_attachments__inputs:0:artifact:*.name", value=json.dumps(container_artifact_header_item_0))
    phantom.save_block_result(key="extract_attachments__inputs:1:artifact:*.id", value=json.dumps(container_artifact_header_item_1))
    phantom.save_block_result(key="extract_attachments__inputs:2:artifact:*.cef.vaultId", value=json.dumps(container_artifact_cef_item_2))
    phantom.save_block_result(key="extract_attachments__inputs:3:artifact:*.cef.fileName", value=json.dumps(container_artifact_cef_item_3))

    phantom.save_block_result(key="extract_attachments_called", value="True")

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################
    ################################################################################

    # This function is called after all actions are completed.
    # summary of all the action and/or all details of actions
    # can be collected here.

    # summary_json = phantom.get_summary()
    # if 'result' in summary_json:
        # for action_result in summary_json['result']:
            # if 'action_run_id' in action_result:
                # action_results = phantom.get_action_results(action_run_id=action_result['action_run_id'], result_data=False, flatten=False)
                # phantom.debug(action_results)

    ################################################################################
    ################################################################################
    ## Custom Code End
    ################################################################################

    return


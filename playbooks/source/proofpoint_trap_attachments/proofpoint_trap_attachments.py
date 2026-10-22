"""
Automation playbook (PB2), left inactive: proofpoint_trap_orchestrator runs it after proofpoint_trap_detail. Downloads the email of every alert that has no MIME Body yet, extracts its attachments and Cc recipients (from TRAP&#39;s own lists when the download fails), writes the Email Content and Attachment Extraction notes in place, and records each downloaded alert&#39;s MIME Body last.
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

    # call 'filter_event_info' block
    filter_event_info(container=container)

    return

@phantom.playbook_block()
def filter_event_info(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("filter_event_info() called")

    ################################################################################
    # Keep only the Event Info artifact, whose cef.incidentId the TRAP actions use.
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
    # Fetch the incident with its alerts: TRAP's attachment list and headers are the 
    # fallback data.
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

    phantom.act("get incident", parameters=parameters, name="get_trap_incident", assets=["proofpoint_trap_mock"], callback=download_mime_body)

    return


@phantom.playbook_block()
def download_mime_body(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("download_mime_body() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Download the email of every alert that has no MIME Body yet.
    ################################################################################

    filtered_artifact_0_data_filter_event_info = phantom.collect2(container=container, datapath=["filtered-data:filter_event_info:condition_1:artifact:*.cef.incidentId","filtered-data:filter_event_info:condition_1:artifact:*.id"], scope="all")

    parameters = []

    # build parameters list for 'download_mime_body' call
    for filtered_artifact_0_item_filter_event_info in filtered_artifact_0_data_filter_event_info:
        if filtered_artifact_0_item_filter_event_info[0] is not None:
            parameters.append({
                "incident_id": filtered_artifact_0_item_filter_event_info[0],
                "context": {'artifact_id': filtered_artifact_0_item_filter_event_info[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################
    ################################################################################

    # One download per alert that has no MIME Body yet. proofpoint_trap_attachments
    # writes the MIME Body last, as the alert's "done" mark: a finished alert is
    # never fetched again, one whose earlier run failed is fetched again.
    incident_rows = phantom.collect2(container=container, datapath=["get_trap_incident:action_result.data"])
    records = incident_rows[0][0] if incident_rows and incident_rows[0] else None
    incident = records[0] if isinstance(records, list) and records else (records if isinstance(records, dict) else {})
    event_ids = [str(event.get("id")) for event in incident.get("events") or [] if event.get("id")]

    done = set()
    for row in phantom.collect2(container=container, datapath=["artifact:*.name", "artifact:*.source_data_identifier", "artifact:*.cef.eventId"], scope="all") or []:
        if row and row[0] == "MIME Body":
            sdi = str(row[1] or "")
            done.add(str(row[2]) if row[2] else (sdi.split("-mime-", 1)[1] if "-mime-" in sdi else ""))
    pending = [event_id for event_id in event_ids if event_id not in done]
    phantom.save_run_data(key="download_mime_body:pending", value=json.dumps(pending))

    incident_id = parameters[0]["incident_id"] if parameters else None
    if not pending or not incident_id:
        phantom.debug("No alert without a MIME Body ({} alert(s), {} done)".format(len(event_ids), len(done)))
        read_emails(container=container)
        return
    try:
        incident_id = int(incident_id)
    except (TypeError, ValueError):
        pass
    parameters = [{"incident_id": incident_id, "event_id": event_id} for event_id in pending]

    ################################################################################
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("download mime body", parameters=parameters, name="download_mime_body", assets=["proofpoint_trap_mock"], callback=read_emails)

    return


@phantom.playbook_block()
def read_emails(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("read_emails() called")

    ################################################################################
    # Read each downloaded email: attachments to the Vault, Cc, the Email Content 
    # note; TRAP's lists when the download failed.
    ################################################################################

    read_emails__name = None
    read_emails__label = None
    read_emails__contains = None
    read_emails__cef_dictionary = None
    read_emails__source_data_identifier = None
    read_emails__upgrade_artifact_id = None
    read_emails__upgrade_cef_json = None
    read_emails__upgrade_cef_types = None
    read_emails__note_title = None
    read_emails__note_content = None
    read_emails__mime_cef = None
    read_emails__mime_contains = None
    read_emails__mime_sdi = None

    ################################################################################
    ## Custom Code Start
    ################################################################################
    ################################################################################

    # Local imports: a save drops module-level imports outside Global Custom Code.
    import base64
    import hashlib
    import mimetypes
    import email
    import email.policy
    from email.utils import getaddresses, parseaddr
    from email.header import decode_header, make_header

    container_id = container.get("id")
    incident_rows = phantom.collect2(container=container, datapath=["get_trap_incident:action_result.data"])
    records = incident_rows[0][0] if incident_rows and incident_rows[0] else None
    incident = records[0] if isinstance(records, list) and records else (records if isinstance(records, dict) else {})
    incident_id = str(incident.get("id") or container.get("source_data_identifier") or "")
    events = {str(event.get("id")): event for event in incident.get("events") or [] if event.get("id")}
    pending = json.loads(phantom.get_run_data(key="download_mime_body:pending") or "[]")

    # proofpoint_trap_excluded_email (email, date, reason, enabled): an address in
    # an enabled row gets no Cc Recipient Email. A missing list excludes nothing.
    excluded = set()
    list_ok, list_message, list_rows = phantom.get_list(list_name="proofpoint_trap_excluded_email")
    if list_ok:
        for row in list_rows or []:
            row = list(row or []) + [None] * 4
            address = str(row[0] or "").strip().lower()
            if "@" in address and str(row[3] or "").strip().lower() == "yes":
                excluded.add(address)
    else:
        phantom.debug("No proofpoint_trap_excluded_email list ({}): every address counts".format(list_message))

    # What the case already holds, so nothing is posted twice: an attachment by
    # its identifier (the same on both paths), a Cc by its address.
    attachments = {}
    cc_known = set()
    for row in phantom.collect2(container=container, datapath=[
            "artifact:*.name", "artifact:*.id", "artifact:*.source_data_identifier", "artifact:*.cef.vaultId",
            "artifact:*.cef.emailAddress", "artifact:*.cef.emailRole", "artifact:*.cef.fileName",
            "artifact:*.cef.attachmentSource"], scope="all") or []:
        if not row:
            continue
        if row[0] == "Email Attachment" and row[2]:
            attachments[row[2]] = {"id": row[1], "vault": row[3], "file": row[6], "source": row[7]}
        elif row[0] == "Recipient Email" and row[5] == "cc" and row[4]:
            cc_known.add(str(row[4]).lower())

    downloaded = {}
    for row in phantom.collect2(container=container, datapath=[
            "download_mime_body:action_result.parameter.event_id", "download_mime_body:action_result.status",
            "download_mime_body:action_result.data"]) or []:
        if row and row[0] and row[1] == "success":
            for record in row[2] or []:
                if isinstance(record, dict) and record.get("vault_id"):
                    downloaded[str(row[0])] = (record["vault_id"], record.get("file_name") or "trap-{}-{}.eml".format(incident_id, row[0]))

    def _is_report(event):
        # An abuse-mailbox report lists the email twice (abuseCopy true = the
        # report); a report from a shared mailbox comes alone, naming the sender
        # in X-PhishAlarm-Sender. A report's Cc are the reporter's, not the
        # reported email's: none is kept (same rule as proofpoint_trap_detail).
        # The header can arrive RFC 2047-encoded as a whole, address included.
        emails = event.get("emails") or []
        has_reported_email = any((e or {}).get("abuseCopy") is False for e in emails)
        for item in emails:
            headers = (item or {}).get("headers") or {}
            header_sender = next((str(v) for k, v in headers.items() if str(k).lower() == "x-phishalarm-sender"), "")
            try:
                header_sender = str(make_header(decode_header(header_sender)))
            except Exception:
                pass
            if (item or {}).get("abuseCopy") is True and has_reported_email:
                return True
            if (item or {}).get("abuseCopy") is not False and not has_reported_email and "@" in header_sender:
                return True
        return False

    new_artifacts, upgrades, notes, mime_bodies = [], [], [], []
    planned = set()

    def _attachment(event_id, cef, types):
        sdi = "trap-{}-{}-attachment-{}-{}".format(incident_id, event_id, cef["fileName"], cef["fileHashSha256"][:12])
        known = attachments.get(sdi)
        if known:
            if cef.get("vaultId") and not known["vault"]:
                upgrades.append({"artifact_id": known["id"], "cef": cef, "types": types})
            return
        if sdi in planned:
            return
        planned.add(sdi)
        new_artifacts.append({"name": "Email Attachment", "label": "event", "contains": types, "cef": cef,
                              "source_data_identifier": sdi})
        attachments[sdi] = {"id": None, "vault": cef.get("vaultId"), "file": cef["fileName"], "source": cef["attachmentSource"]}

    def _cc(event_id, address):
        address = (address or "").strip()
        if not address or address.lower() in excluded or address.lower() in cc_known:
            return
        cc_known.add(address.lower())
        new_artifacts.append({"name": "Recipient Email", "label": "event", "contains": {"emailAddress": ["email"]},
                              "cef": {"emailAddress": address, "emailRole": "cc"},
                              "source_data_identifier": "trap-{}-{}-cc-{}".format(incident_id, event_id, address)})

    for event_id in pending:
        event = events.get(event_id) or {}
        report = _is_report(event)
        parsed = None
        if event_id in downloaded:
            vault_id, file_name = downloaded[event_id]
            # The email's bytes over REST, not the vault file's path: the
            # validator flags any filesystem access in a playbook.
            try:
                response = phantom.requests.get(uri=phantom.build_phantom_rest_url("download_attachment"),
                                                params={"vault_id": vault_id}, verify=False)
                if response.status_code == 200 and response.content:
                    parsed = email.message_from_bytes(response.content, policy=email.policy.default)
                else:
                    phantom.debug("Vault download for {} returned HTTP {}".format(vault_id, response.status_code))
            except Exception as err:
                phantom.debug("Could not read email {} of alert {}: {}".format(vault_id, event_id, err))

        if parsed is None:
            # No email: TRAP's attachment list (name, type, size, hashes; no
            # file) and TRAP's Cc header. No MIME Body, so the next run tries
            # the download again; a later success upgrades these attachments.
            for item in event.get("emails") or []:
                for attachment in (item or {}).get("attachments") or []:
                    real_name = attachment.get("realnamePII")
                    if isinstance(real_name, dict):
                        real_name = real_name.get("secret")
                    file_name = str(real_name or attachment.get("realname") or attachment.get("safename")
                                    or attachment.get("filename") or "").strip()
                    sha256 = str(attachment.get("sha256") or "").strip().lower()
                    if not file_name or not sha256:
                        continue
                    cef = {"fileName": file_name, "fileType": attachment.get("contentType") or "", "fileHashSha256": sha256,
                           "attachmentSource": "TRAP API (original email not available)"}
                    types = {"fileName": ["file name"], "fileHashSha256": ["sha256"]}
                    if attachment.get("md5"):
                        cef["fileHashMd5"] = str(attachment.get("md5")).strip().lower()
                        types["fileHashMd5"] = ["md5"]
                    if attachment.get("size") is not None:
                        cef["fileSize"] = attachment.get("size")
                    _attachment(event_id, cef, types)
                if not report:
                    headers = (item or {}).get("headers") or {}
                    cc_raw = next((str(v) for k, v in headers.items() if str(k).lower() == "cc"), "")
                    for _name, address in getaddresses([cc_raw]):
                        _cc(event_id, address)
            continue

        for part in parsed.walk():
            content_type = part.get_content_type()
            is_forwarded_email = content_type == "message/rfc822"
            # message/rfc822 wraps one Message, so is_multipart() is True for it:
            # skip real multipart/* containers only.
            if part.is_multipart() and not is_forwarded_email:
                continue
            filename = part.get_filename()
            if not filename or (part.get_content_disposition() or "").lower() != "attachment":
                continue
            try:
                payload = part.get_payload()[0].as_bytes() if is_forwarded_email else part.get_payload(decode=True)
            except Exception as err:
                phantom.debug("Could not read attachment {}: {}".format(filename, err))
                continue
            if not payload:
                continue
            # Into the Vault through REST with the content inline: no file on disk.
            try:
                upload = phantom.requests.post(
                    uri=phantom.build_phantom_rest_url("container_attachment"),
                    data=json.dumps({"container_id": container_id, "file_content": base64.b64encode(payload).decode("ascii"),
                                     "file_name": filename, "metadata": {"contains": ["vault id"]}}),
                    verify=False,
                ).json()
            except Exception as err:
                phantom.debug("Vault upload failed for {}: {}".format(filename, err))
                continue
            if not upload.get("succeeded") or not upload.get("vault_id"):
                phantom.debug("Vault upload failed for {}: {}".format(filename, upload.get("message")))
                continue
            guessed_type, _ = mimetypes.guess_type(filename)
            # MD5 and size as TRAP shows them; usedforsecurity=False: a FIPS host refuses a plain md5().
            cef = {"vaultId": upload["vault_id"], "fileName": filename, "fileHashSha256": hashlib.sha256(payload).hexdigest(),
                   "fileHashMd5": hashlib.md5(payload, usedforsecurity=False).hexdigest(), "fileSize": len(payload),
                   "fileType": content_type, "attachmentSource": "original email"}
            if guessed_type and guessed_type != content_type:
                cef["mimeTypeMismatch"] = "declared {}, expected {} from filename".format(content_type, guessed_type)
            _attachment(event_id, cef, {"vaultId": ["vault id"], "fileHashSha256": ["sha256"], "fileHashMd5": ["md5"],
                                        "fileName": ["file name"]})

        if not report:
            for _name, address in getaddresses(parsed.get_all("Cc") or []):
                _cc(event_id, address)

        # The body as safe markdown: nothing from the email loads or is
        # clickable (see _email_html_to_markdown in Global Custom Code).
        body_md, body_kind = None, None
        try:
            body_part = parsed.get_body(preferencelist=("html", "plain"))
            body_content = body_part.get_content() if body_part is not None else None
        except Exception as err:
            body_part, body_content = None, None
            phantom.debug("Could not decode the body of {}: {}".format(file_name, err))
        if body_content:
            if body_part.get_content_type() == "text/html":
                body_md = _email_html_to_markdown(body_content)
                body_kind = "HTML, shown as safe text: links defanged and not clickable, images and scripts removed"
            else:
                body_md = _email_text_to_markdown(body_content)
                body_kind = "plain text, URLs defanged"

        return_path = parsed.get("Return-Path", "")
        from_header = parsed.get("From", "")
        return_path_addr, from_addr = parseaddr(return_path)[1], parseaddr(from_header)[1]
        lines = ["# Email Content — {} (event {})".format(_md_escape(file_name), _md_escape(event_id)), ""]
        for label, value in (("From", from_header), ("To", parsed.get("To", "")),
                             ("Subject", parsed.get("Subject", "")), ("Date", parsed.get("Date", ""))):
            if value:
                lines.append("**{}:** {}  ".format(label, _md_text(" ".join(str(value).split()))))
        if return_path:
            mismatch = (" — **does not match From ({})**".format(_md_text(from_addr))
                        if return_path_addr and from_addr and return_path_addr.lower() != from_addr.lower() else "")
            lines.append("**Return-Path:** {}{}  ".format(_md_text(str(return_path)), mismatch))
        for label in ("Reply-To", "X-Originating-IP"):
            if parsed.get(label, ""):
                lines.append("**{}:** {}  ".format(label, _md_text(str(parsed.get(label)))))
        for header_name in ("In-Reply-To", "X-PhishAlarm-Sender", "Received-SPF", "DKIM-Signature"):
            for header_value in parsed.get_all(header_name) or []:
                lines.append("**{}:** {}  ".format(header_name, _md_text(" ".join(str(header_value).split()))))
        auth_results = parsed.get_all("Authentication-Results") or []
        if auth_results:
            lines += ["", "**Authentication-Results:**", ""]
            lines += ["- " + _md_text(" ".join(str(value).split())) for value in auth_results]
        received_chain = parsed.get_all("Received") or []
        if received_chain:
            lines += ["", "**Received chain ({} hop(s)):**".format(len(received_chain)), ""]
            lines += ["{}. {}".format(n, _md_text(" ".join(str(hop).split()))) for n, hop in enumerate(received_chain, 1)]
        lines += ["", "---", ""]
        lines += ["**Body** ({})".format(body_kind), "", body_md] if body_md else ["*No readable body part found in this MIME message.*"]
        notes.append(["Email Content — {}".format(file_name), "\n".join(lines)])
        mime_bodies.append({"cef": {"vaultId": vault_id, "fileName": file_name, "eventId": event_id},
                            "source_data_identifier": "trap-{}-mime-{}".format(incident_id, event_id)})

    # One Attachment Extraction note per case, over every attachment on it, so
    # it reads the same on a run that adds nothing.
    rows = []
    for sdi, item in sorted(attachments.items()):
        event_part = sdi.split("-attachment-", 1)[0]
        event_id = event_part[len("trap-{}-".format(incident_id)):] if event_part.startswith("trap-{}-".format(incident_id)) else ""
        rows.append("| {} | `{}` | {} |".format(event_id, str(item["file"] or "").replace("`", "'").replace("|", "\\|"),
                                               "file in the Vault" if item["vault"] else item["source"] or ""))
    if rows or mime_bodies or attachments:
        content = "# Email Attachment Extraction\n**Attachments on this case:** {}\n\n".format(len(rows))
        content += "\n".join(["| Event | File | Source |", "|---|---|---|"] + rows) if rows else "No attachment in the emails."
        notes.append(["Attachment Extraction", content])

    read_emails__name = [a["name"] for a in new_artifacts]
    read_emails__label = [a["label"] for a in new_artifacts]
    read_emails__contains = [json.dumps(a["contains"]) for a in new_artifacts]
    read_emails__cef_dictionary = [json.dumps(a["cef"]) for a in new_artifacts]
    read_emails__source_data_identifier = [a["source_data_identifier"] for a in new_artifacts]
    read_emails__upgrade_artifact_id = [u["artifact_id"] for u in upgrades]
    read_emails__upgrade_cef_json = [json.dumps(u["cef"]) for u in upgrades]
    read_emails__upgrade_cef_types = [json.dumps(u["types"]) for u in upgrades]
    read_emails__note_title = [n[0] for n in notes]
    read_emails__note_content = [n[1] for n in notes]
    read_emails__mime_cef = [json.dumps(m["cef"]) for m in mime_bodies]
    read_emails__mime_contains = [json.dumps({"vaultId": ["vault id"], "fileName": ["file name"]}) for m in mime_bodies]
    read_emails__mime_sdi = [m["source_data_identifier"] for m in mime_bodies]
    for key, value in (("name", read_emails__name), ("label", read_emails__label), ("contains", read_emails__contains),
                       ("cef_dictionary", read_emails__cef_dictionary), ("source_data_identifier", read_emails__source_data_identifier),
                       ("upgrade_artifact_id", read_emails__upgrade_artifact_id), ("upgrade_cef_json", read_emails__upgrade_cef_json),
                       ("upgrade_cef_types", read_emails__upgrade_cef_types), ("note_title", read_emails__note_title),
                       ("note_content", read_emails__note_content), ("mime_cef", read_emails__mime_cef),
                       ("mime_contains", read_emails__mime_contains), ("mime_sdi", read_emails__mime_sdi)):
        phantom.save_run_data(key="read_emails:" + key, value=json.dumps(value))
    phantom.debug("{} alert(s): {} new artifact(s), {} upgrade(s), {} note(s), {} MIME Body(ies)".format(
        len(pending), len(new_artifacts), len(upgrades), len(notes), len(mime_bodies)))

    ################################################################################
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_block_result(key="read_emails:name", value=json.dumps(read_emails__name))
    phantom.save_block_result(key="read_emails:label", value=json.dumps(read_emails__label))
    phantom.save_block_result(key="read_emails:contains", value=json.dumps(read_emails__contains))
    phantom.save_block_result(key="read_emails:cef_dictionary", value=json.dumps(read_emails__cef_dictionary))
    phantom.save_block_result(key="read_emails:source_data_identifier", value=json.dumps(read_emails__source_data_identifier))
    phantom.save_block_result(key="read_emails:upgrade_artifact_id", value=json.dumps(read_emails__upgrade_artifact_id))
    phantom.save_block_result(key="read_emails:upgrade_cef_json", value=json.dumps(read_emails__upgrade_cef_json))
    phantom.save_block_result(key="read_emails:upgrade_cef_types", value=json.dumps(read_emails__upgrade_cef_types))
    phantom.save_block_result(key="read_emails:note_title", value=json.dumps(read_emails__note_title))
    phantom.save_block_result(key="read_emails:note_content", value=json.dumps(read_emails__note_content))
    phantom.save_block_result(key="read_emails:mime_cef", value=json.dumps(read_emails__mime_cef))
    phantom.save_block_result(key="read_emails:mime_contains", value=json.dumps(read_emails__mime_contains))
    phantom.save_block_result(key="read_emails:mime_sdi", value=json.dumps(read_emails__mime_sdi))

    phantom.save_block_result(key="read_emails_called", value="True")

    add_attachments_and_cc(container=container)

    return


@phantom.playbook_block()
def add_attachments_and_cc(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_attachments_and_cc() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Create the Email Attachment and Cc Recipient Email artifacts.
    ################################################################################

    id_value = container.get("id", None)
    read_emails__name = json.loads(_ if (_ := phantom.get_run_data(key="read_emails:name")) != "" else "null")  # pylint: disable=used-before-assignment
    read_emails__label = json.loads(_ if (_ := phantom.get_run_data(key="read_emails:label")) != "" else "null")  # pylint: disable=used-before-assignment
    read_emails__contains = json.loads(_ if (_ := phantom.get_run_data(key="read_emails:contains")) != "" else "null")  # pylint: disable=used-before-assignment
    read_emails__cef_dictionary = json.loads(_ if (_ := phantom.get_run_data(key="read_emails:cef_dictionary")) != "" else "null")  # pylint: disable=used-before-assignment
    read_emails__source_data_identifier = json.loads(_ if (_ := phantom.get_run_data(key="read_emails:source_data_identifier")) != "" else "null")  # pylint: disable=used-before-assignment

    parameters = []

    if read_emails__source_data_identifier is not None:
        parameters.append({
            "name": read_emails__name,
            "label": read_emails__label,
            "contains": read_emails__contains,
            "container_id": id_value,
            "cef_dictionary": read_emails__cef_dictionary,
            "source_data_identifier": read_emails__source_data_identifier,
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################
    ################################################################################

    # One parameter set per artifact (the VPE builds one set of whole lists);
    # reads the run data, not the generated variables. determine_contains
    # False: every typed field is in contains, the rest stay untyped.
    names = json.loads(phantom.get_run_data(key="read_emails:name") or "null") or []
    labels = json.loads(phantom.get_run_data(key="read_emails:label") or "null") or []
    contains = json.loads(phantom.get_run_data(key="read_emails:contains") or "null") or []
    cefs = json.loads(phantom.get_run_data(key="read_emails:cef_dictionary") or "null") or []
    sdis = json.loads(phantom.get_run_data(key="read_emails:source_data_identifier") or "null") or []
    parameters = [{"name": names[i], "label": labels[i], "contains": contains[i], "determine_contains": False,
                   "run_automation": False, "container_id": container.get("id"), "cef_dictionary": cefs[i],
                   "source_data_identifier": sdis[i]} for i in range(len(sdis))]
    if not parameters:
        upgrade_attachments(container=container)
        return

    ################################################################################
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("add artifact", parameters=parameters, name="add_attachments_and_cc", assets=["soar8"], callback=upgrade_attachments)

    return


@phantom.playbook_block()
def upgrade_attachments(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("upgrade_attachments() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Give a TRAP-listed attachment its file once a later download succeeds.
    ################################################################################

    read_emails__upgrade_cef_json = json.loads(_ if (_ := phantom.get_run_data(key="read_emails:upgrade_cef_json")) != "" else "null")  # pylint: disable=used-before-assignment
    read_emails__upgrade_artifact_id = json.loads(_ if (_ := phantom.get_run_data(key="read_emails:upgrade_artifact_id")) != "" else "null")  # pylint: disable=used-before-assignment
    read_emails__upgrade_cef_types = json.loads(_ if (_ := phantom.get_run_data(key="read_emails:upgrade_cef_types")) != "" else "null")  # pylint: disable=used-before-assignment

    parameters = []

    if read_emails__upgrade_artifact_id is not None:
        parameters.append({
            "cef_json": read_emails__upgrade_cef_json,
            "severity": "low",
            "artifact_id": read_emails__upgrade_artifact_id,
            "cef_types_json": read_emails__upgrade_cef_types,
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################
    ################################################################################

    # One update per attachment; severity low: an update re-applies the
    # artifact's severity to the case, like creating it.
    ids = json.loads(phantom.get_run_data(key="read_emails:upgrade_artifact_id") or "null") or []
    cefs = json.loads(phantom.get_run_data(key="read_emails:upgrade_cef_json") or "null") or []
    types = json.loads(phantom.get_run_data(key="read_emails:upgrade_cef_types") or "null") or []
    parameters = [{"artifact_id": ids[i], "severity": "low", "cef_json": cefs[i], "cef_types_json": types[i]}
                  for i in range(len(ids))]
    if not parameters:
        add_notes(container=container)
        return

    ################################################################################
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("update artifact", parameters=parameters, name="upgrade_attachments", assets=["soar8"], callback=add_notes)

    return


@phantom.playbook_block()
def add_notes(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_notes() called")

    ################################################################################
    # Write the Email Content and Attachment Extraction notes in place (shared custom 
    # function).
    ################################################################################

    id_value = container.get("id", None)
    read_emails__note_title = json.loads(_ if (_ := phantom.get_run_data(key="read_emails:note_title")) != "" else "null")  # pylint: disable=used-before-assignment
    read_emails__note_content = json.loads(_ if (_ := phantom.get_run_data(key="read_emails:note_content")) != "" else "null")  # pylint: disable=used-before-assignment

    parameters = []

    parameters.append({
        "title": read_emails__note_title,
        "content": read_emails__note_content,
        "container_id": id_value,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################
    ################################################################################

    # One parameter set per note.
    titles = json.loads(phantom.get_run_data(key="read_emails:note_title") or "null") or []
    contents = json.loads(phantom.get_run_data(key="read_emails:note_content") or "null") or []
    parameters = [{"container_id": container.get("id"), "title": titles[i], "content": contents[i]}
                  for i in range(len(titles))]
    if not parameters:
        add_mime_bodies(container=container)
        return

    ################################################################################
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="local/proofpoint_trap_note_upsert", parameters=parameters, name="add_notes", callback=add_mime_bodies)

    return


@phantom.playbook_block()
def add_mime_bodies(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_mime_bodies() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Record each downloaded alert's MIME Body, its done mark, last.
    ################################################################################

    id_value = container.get("id", None)
    read_emails__mime_contains = json.loads(_ if (_ := phantom.get_run_data(key="read_emails:mime_contains")) != "" else "null")  # pylint: disable=used-before-assignment
    read_emails__mime_cef = json.loads(_ if (_ := phantom.get_run_data(key="read_emails:mime_cef")) != "" else "null")  # pylint: disable=used-before-assignment
    read_emails__mime_sdi = json.loads(_ if (_ := phantom.get_run_data(key="read_emails:mime_sdi")) != "" else "null")  # pylint: disable=used-before-assignment

    parameters = []

    if read_emails__mime_sdi is not None:
        parameters.append({
            "name": "MIME Body",
            "label": "event",
            "contains": read_emails__mime_contains,
            "container_id": id_value,
            "cef_dictionary": read_emails__mime_cef,
            "source_data_identifier": read_emails__mime_sdi,
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################
    ################################################################################

    # One MIME Body per downloaded alert, written last: it marks the alert done.
    cefs = json.loads(phantom.get_run_data(key="read_emails:mime_cef") or "null") or []
    contains = json.loads(phantom.get_run_data(key="read_emails:mime_contains") or "null") or []
    sdis = json.loads(phantom.get_run_data(key="read_emails:mime_sdi") or "null") or []
    parameters = [{"name": "MIME Body", "label": "event", "contains": contains[i], "determine_contains": False,
                   "run_automation": False, "container_id": container.get("id"), "cef_dictionary": cefs[i],
                   "source_data_identifier": sdis[i]} for i in range(len(sdis))]
    if not parameters:
        return

    ################################################################################
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("add artifact", parameters=parameters, name="add_mime_bodies", assets=["soar8"])

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

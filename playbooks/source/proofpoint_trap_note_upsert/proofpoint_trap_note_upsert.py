def proofpoint_trap_note_upsert(container_id=None, title=None, content=None, **kwargs):
    """
    Write a case note by title, updated in place: nothing when the content is unchanged, an update when it changed, a new note when none exists. Content over 20,000 characters is split into parts "title (k/N)"; parts left over from a longer earlier version are blanked as "title (unused)".
    
    Args:
        container_id (CEF type: phantom container id): Case to write the note on.
        title: Note title; identifies the note on the case.
        content: Note content, markdown.
    
    Returns a JSON-serializable object that implements the configured data paths:
        changed: True when a note was created, updated or blanked.
        note_ids: Ids of the notes holding the content, in part order.
        parts: Number of notes the content takes.
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import re
    import phantom.rules as phantom

    # The target SOAR cuts a note at about 22,000 characters.
    NOTE_MAX_CHARS = 20000
    TABLE_SEPARATOR = re.compile(r"^\|[\s:|-]+\|?\s*$")

    if isinstance(container_id, dict):
        container_id = container_id.get("id")
    if isinstance(container_id, (list, tuple)):
        container_id = container_id[0] if container_id else None
    container_id = int(container_id)
    if not isinstance(title, str) or not title.strip():
        raise ValueError("title must be a non-empty string")
    title = title.strip()
    content = content if isinstance(content, str) else ""

    def _chunks(text):
        # Cut at line boundaries; a table cut in two repeats its header in the next part.
        if len(text) <= NOTE_MAX_CHARS:
            return [text]
        budget = NOTE_MAX_CHARS - 300
        lines = text.split("\n")
        chunks, current, size = [], [], 0
        head, head_at = [], -1
        for i, line in enumerate(lines):
            if line.startswith("|"):
                starts_table = i == 0 or not lines[i - 1].startswith("|")
                if starts_table and i + 1 < len(lines) and TABLE_SEPARATOR.match(lines[i + 1]):
                    head, head_at = [line, lines[i + 1]], i
            else:
                head, head_at = [], -1
            for piece in [line[j:j + budget] for j in range(0, len(line), budget)] or [""]:
                if current and size + len(piece) + 1 > budget:
                    chunks.append("\n".join(current))
                    current = list(head) if head and i >= head_at + 2 else []
                    size = sum(len(l) + 1 for l in current)
                current.append(piece)
                size += len(piece) + 1
        if current:
            chunks.append("\n".join(current))
        return chunks

    chunks = _chunks(content)
    total = len(chunks)
    if total == 1:
        parts = [(title, chunks[0])]
    else:
        parts = [("{} ({}/{})".format(title, n, total),
                  chunk if n == 1 else "# {} ({}/{}, continued)\n\n{}".format(title, n, total, chunk))
                 for n, chunk in enumerate(chunks, 1)]

    # This CF's own notes on the case: "title", "title (k/N)", "title (unused)".
    own_title = re.compile(r"^{}( \(\d+/\d+\)| \(unused\))?$".format(re.escape(title)))
    existing = []
    for page in phantom.get_notes(container=container_id):
        if not page.get("success"):
            raise RuntimeError("Could not list the notes of container {}: {}".format(container_id, page.get("message")))
        data = page.get("data")
        for note in (data if isinstance(data, list) else [data]):
            if isinstance(note, dict) and note.get("note_type", "general") == "general" \
                    and own_title.match(note.get("title") or ""):
                existing.append(note)
    existing.sort(key=lambda note: note.get("id") or 0)

    # A note cannot be deleted by a playbook user (REST DELETE answers 403) and
    # no native block updates one, hence REST for the update.
    note_url = phantom.build_phantom_rest_url("note")

    def _same(note, part_title, part_content):
        stored = (note.get("content") or "").replace("\r\n", "\n").rstrip()
        return note.get("title") == part_title and stored == part_content.replace("\r\n", "\n").rstrip()

    def _update(note_id, part_title, part_content):
        response = phantom.requests.post(
            uri="{}/{}".format(note_url, note_id),
            data=json.dumps({"title": part_title, "content": part_content, "note_format": "markdown"}),
            verify=False,
        )
        try:
            body = response.json()
        except ValueError:
            body = {}
        if response.status_code >= 300 or body.get("failed"):
            raise RuntimeError("Note {} could not be updated (HTTP {}): {}".format(
                note_id, response.status_code, str(body)[:300]))

    changed = False
    note_ids = []
    for index, (part_title, part_content) in enumerate(parts):
        if index < len(existing):
            note = existing[index]
            if not _same(note, part_title, part_content):
                _update(note["id"], part_title, part_content)
                changed = True
            note_ids.append(note["id"])
        else:
            success, message, note_id = phantom.add_note(
                container=container_id, title=part_title, content=part_content,
                note_format="markdown", note_type="general")
            if not success:
                raise RuntimeError("Note {!r} could not be created: {}".format(part_title, message))
            note_ids.append(note_id)
            changed = True

    unused_title = "{} (unused)".format(title)
    unused_content = "Not in use: {} now fits in {} note(s).".format(title, len(parts))
    for note in existing[len(parts):]:
        if not _same(note, unused_title, unused_content):
            _update(note["id"], unused_title, unused_content)
            changed = True

    phantom.debug("{}: {} part(s), changed={}, notes {}".format(title, len(parts), changed, note_ids))
    outputs = {"changed": changed, "note_ids": note_ids, "parts": len(parts)}

    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs

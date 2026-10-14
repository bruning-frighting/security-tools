"""Deterministic writers.

The Phase 0 gate is "running it twice on the same input gives identical output hashes", so
every writer here is byte-stable:

* ``sort_keys=True`` and fixed separators for JSON
* explicit ``\\n`` line terminator, never the platform default
* UTF-8 without BOM
* no wall-clock timestamps anywhere in the outputs -- the only time recorded is the
  ``retrieved_at`` of the pinned source, which is an *input* read from sources.lock.json
"""

import csv
import hashlib
import io
import json
import os


def write_json(path, obj):
    text = json.dumps(obj, sort_keys=True, indent=2, ensure_ascii=False) + "\n"
    _write_text(path, text)
    return sha256_file(path)


def write_csv(path, header, rows):
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n", quoting=csv.QUOTE_MINIMAL)
    w.writerow(header)
    for r in rows:
        w.writerow(r)
    _write_text(path, buf.getvalue())
    return sha256_file(path)


def _write_text(path, text):
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def join_list(values, sep="|"):
    """Stable scalar rendering of a list for CSV cells."""
    return sep.join(str(v) for v in (values or []))

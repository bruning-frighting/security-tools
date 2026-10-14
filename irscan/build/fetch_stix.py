#!/usr/bin/env python3
"""Fetch the pinned ATT&CK STIX bundle and verify it against build/sources.lock.json.

Build-time only. The scan-time binary never downloads anything.

    python build/fetch_stix.py                 # fetch if missing, then verify
    python build/fetch_stix.py --verify-only   # verify what is already on disk
    python build/fetch_stix.py --repin         # record the fetched hash into the lock file

Exit codes: 0 ok, 2 hash/version mismatch, 3 network or IO failure.
"""

import argparse
import datetime
import hashlib
import json
import os
import sys
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
LOCK = os.path.join(HERE, "sources.lock.json")
DEFAULT_CACHE = os.path.join(HERE, "cache")


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--cache-dir", default=DEFAULT_CACHE)
    ap.add_argument("--verify-only", action="store_true")
    ap.add_argument("--repin", action="store_true",
                    help="write the observed hash/size/time into sources.lock.json")
    args = ap.parse_args(argv)

    with open(LOCK, "r", encoding="utf-8") as fh:
        lock = json.load(fh)
    pin = lock["attack_stix"]

    os.makedirs(args.cache_dir, exist_ok=True)
    dest = os.path.join(args.cache_dir, os.path.basename(pin["url"]))

    if not os.path.exists(dest):
        if args.verify_only:
            print("MISSING: %s" % dest, file=sys.stderr)
            return 3
        print("fetching %s" % pin["url"])
        try:
            with urllib.request.urlopen(pin["url"], timeout=300) as resp, \
                    open(dest, "wb") as out:
                while True:
                    chunk = resp.read(1 << 20)
                    if not chunk:
                        break
                    out.write(chunk)
        except (urllib.error.URLError, OSError) as exc:
            # Per the honesty rules: a blocked network is recorded, never worked around.
            print("NETWORK FAILURE: %s" % exc, file=sys.stderr)
            print(
                "If network access to the STIX repository is blocked, place a locally supplied "
                "enterprise-attack JSON at:\n  %s\nand re-run with --verify-only (or --repin "
                "if you are deliberately changing the pin)." % dest,
                file=sys.stderr,
            )
            return 3
    else:
        print("using cached %s" % dest)

    actual = sha256_file(dest)
    size = os.path.getsize(dest)

    if args.repin:
        pin["sha256"] = actual
        pin["size_bytes"] = size
        pin["retrieved_at"] = (
            datetime.datetime.now(datetime.timezone.utc)
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z")
        )
        try:
            with open(dest, "r", encoding="utf-8") as fh:
                bundle = json.load(fh)
            for obj in bundle.get("objects", []):
                if obj.get("type") == "x-mitre-collection":
                    pin["version"] = obj.get("x_mitre_version", pin["version"])
                    pin["collection_id"] = obj.get("id", pin.get("collection_id"))
                    pin["collection_modified"] = obj.get("modified")
                    break
        except (OSError, ValueError) as exc:
            print("WARNING: could not read collection metadata: %s" % exc, file=sys.stderr)
        with open(LOCK, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(lock, fh, indent=2, ensure_ascii=False, sort_keys=False)
            fh.write("\n")
        print("REPINNED version=%s sha256=%s size=%d" % (pin["version"], actual, size))
        return 0

    ok = True
    if actual != pin["sha256"]:
        print("HASH MISMATCH\n  expected %s\n  actual   %s" % (pin["sha256"], actual),
              file=sys.stderr)
        ok = False
    if size != pin["size_bytes"]:
        print("SIZE MISMATCH expected %d actual %d" % (pin["size_bytes"], size),
              file=sys.stderr)
        ok = False

    if not ok:
        return 2

    print("OK  version=%s  sha256=%s  size=%d" % (pin["version"], actual, size))
    print("    %s" % dest)
    print("    attribution: %s" % pin["license"]["required_attribution"])
    return 0


if __name__ == "__main__":
    sys.exit(main())

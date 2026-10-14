#!/usr/bin/env python3
"""Entry point for the build-time ATT&CK registry builder.

    python build/build_registry.py
    python build/build_registry.py --check-determinism   # Phase 0 gate

The determinism check builds twice into separate temp directories and compares every output
hash. That is the Phase 0 gate: "running it twice on the same input gives identical output
hashes".
"""

import argparse
import json
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from registry_builder import build as builder  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
LOCK = os.path.join(HERE, "sources.lock.json")
OVERLAY = os.path.join(ROOT, "data", "overlay")
OUT = os.path.join(ROOT, "data", "registry")
EMBED = os.path.join(ROOT, "internal", "registry", "embedded", "registry_embed.json")


def _default_stix_path():
    with open(LOCK, "r", encoding="utf-8") as fh:
        lock = json.load(fh)
    return os.path.join(HERE, "cache", os.path.basename(lock["attack_stix"]["url"]))


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--stix", default=None, help="path to the pinned STIX bundle")
    ap.add_argument("--out", default=OUT)
    ap.add_argument("--embed-out", default=EMBED,
                    help="compact registry written into the Go package tree for //go:embed")
    ap.add_argument("--check-determinism", action="store_true")
    args = ap.parse_args(argv)

    stix = args.stix or _default_stix_path()
    if not os.path.exists(stix):
        print("FATAL: STIX bundle not found at %s\nRun build/fetch_stix.py first." % stix,
              file=sys.stderr)
        return 3

    result = builder.build(stix, LOCK, OVERLAY, args.out, args.embed_out)
    _report(result, args.out)

    if args.check_determinism:
        print("\n=== Phase 0 gate: determinism ===")
        tmp_a = tempfile.mkdtemp(prefix="irscan-reg-a-")
        tmp_b = tempfile.mkdtemp(prefix="irscan-reg-b-")
        try:
            a = builder.build(stix, LOCK, OVERLAY, tmp_a,
                              os.path.join(tmp_a, "registry_embed.json"))["hashes"]
            b = builder.build(stix, LOCK, OVERLAY, tmp_b,
                              os.path.join(tmp_b, "registry_embed.json"))["hashes"]
            same = a == b
            for name in sorted(set(a) | set(b)):
                mark = "OK  " if a.get(name) == b.get(name) else "DIFF"
                print("  %s %-28s %s" % (mark, name, a.get(name, "<missing>")))
            print("  GATE: %s" % ("PASS - two runs byte-identical" if same else "FAIL"))
            if not same:
                return 1
        finally:
            shutil.rmtree(tmp_a, ignore_errors=True)
            shutil.rmtree(tmp_b, ignore_errors=True)

    # Gate: no in-scope technique may lack a class or a status.
    unclassified = result["counts"]["U_host_unclassified"]
    if unclassified:
        print("\nGATE FAIL: %d in-scope techniques lack a testability class or status"
              % unclassified, file=sys.stderr)
        return 1

    return 0


def _report(result, out_dir):
    c = result["counts"]
    print("=== irscan ATT&CK registry built -> %s ===" % out_dir)
    print("\n-- universes (denominators) --")
    for k in ("U_bundle", "U_active", "U_host", "U_impl", "U_impl_technique_os_pairs"):
        print("  %-28s %d" % (k, c[k]))
    print("  %-28s %d revoked / %d deprecated / %d both"
          % ("inactive", c["revoked"], c["deprecated"], c["revoked_and_deprecated"]))
    print("  %-28s %d top-level / %d sub"
          % ("U_host shape", c["U_host_top_level"], c["U_host_subtechniques"]))
    print("  %-28s %d top-level / %d sub"
          % ("U_impl shape", c["U_impl_top_level"], c["U_impl_subtechniques"]))

    print("\n-- U_host by testability class --")
    for k, v in c["U_host_by_testability_class"].items():
        print("  %-28s %4d   (%.1f%% of U_host=%d)" % (k, v, 100.0 * v / c["U_host"], c["U_host"]))

    print("\n-- U_host by rule fired --")
    for k, v in c["U_host_by_testability_rule"].items():
        print("  %-28s %4d" % (k, v))

    print("\n-- U_host by baseline status --")
    for k, v in c["U_host_by_baseline_status"].items():
        print("  %-28s %4d" % (k, v))

    print("\n-- U_impl by testability class --")
    for k, v in c["U_impl_by_testability_class"].items():
        print("  %-28s %4d   (%.1f%% of U_impl=%d)" % (k, v, 100.0 * v / c["U_impl"], c["U_impl"]))

    print("\n-- U_impl by tactic (a technique in 2 scope tactics counts in both here, "
          "but once in U_impl) --")
    for k, v in c["U_impl_by_tactic"].items():
        print("  %-28s %4d" % (k, v))
    print("\n-- U_impl by OS (technique,OS pairs) --")
    for k, v in c["U_impl_by_os"].items():
        print("  %-28s %4d" % (k, v))

    print("\n-- data quality --")
    print("  parse anomalies             %d" % len(result["anomalies"]))
    for a in result["anomalies"][:20]:
        print("      %s: %s" % (a["technique_id"], a["issue"]))
    us = result["unclassified_log_sources"]
    print("  unclassified log sources    %d distinct" % len(us))
    for name, n in sorted(us.items(), key=lambda kv: (-kv[1], kv[0]))[:20]:
        print("      %-44s x%d" % (name, n))
    print("  UNDETERMINED classes        %d" % c["U_host_undetermined_class"])

    print("\n-- output hashes --")
    for k, v in sorted(result["hashes"].items()):
        print("  %-28s %s" % (k, v))


if __name__ == "__main__":
    sys.exit(main())

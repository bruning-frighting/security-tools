#!/usr/bin/env python3
"""Reviewer utility: inspect the built registry without opening a 50 MB JSON by hand.

    python build/query_registry.py T1547.001 T1055 T1003.001
    python build/query_registry.py --class UNDETERMINED
    python build/query_registry.py --class OFF_HOST --scope impl
    python build/query_registry.py --tactic persistence --os linux --brief
    python build/query_registry.py --verify-ids T1547.001=Registry Run Keys / Startup Folder

Exists so the independent review pass can recompute and spot-check from the artefact itself
rather than trusting the build log.
"""

import argparse
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REG = os.path.join(ROOT, "data", "registry", "attack_registry.json")


def load(path=REG):
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("ids", nargs="*", help="technique IDs to show in full")
    ap.add_argument("--registry", default=REG)
    ap.add_argument("--class", dest="cls", help="filter by testability_class")
    ap.add_argument("--status", help="filter by baseline_implementation_status")
    ap.add_argument("--tactic", help="filter by tactic shortname")
    ap.add_argument("--os", dest="osname", help="filter by os_scope entry (windows|linux)")
    ap.add_argument("--scope", choices=["all", "host", "impl"], default="host")
    ap.add_argument("--brief", action="store_true")
    args = ap.parse_args(argv)

    reg = load(args.registry)
    techs = reg["techniques"]
    by_id = {t["technique_id"]: t for t in techs}

    print("registry: ATT&CK v%s  sha256(source)=%s"
          % (reg["source"]["version"], reg["source"]["sha256"][:16] + "..."))

    if args.ids:
        for tid in args.ids:
            t = by_id.get(tid)
            if not t:
                print("\n%s  NOT IN REGISTRY" % tid)
                continue
            print("\n=== %s  %s ===" % (t["technique_id"], t["name"]))
            for k in ("tactics", "tactic_ids", "platforms", "os_scope", "is_subtechnique",
                      "parent_id", "parent_id_source", "active", "revoked", "deprecated",
                      "revoked_by_id", "in_registry_scope", "in_implementation_scope",
                      "testability_class", "testability_rule", "log_source_categories",
                      "telemetry_dependencies", "baseline_implementation_status", "url"):
                print("  %-34s %s" % (k, t.get(k)))
            print("  %-34s %s" % ("testability_reason", t.get("testability_reason")))
            print("  %-34s %s" % ("baseline_rationale",
                                  t.get("baseline_implementation_rationale")))
            print("  %-34s %s" % ("data_components", ", ".join(t.get("data_components") or [])))
            print("  %-34s %s" % ("log_sources",
                                  ", ".join(sorted({l["name"] for l in t.get("log_sources") or []}))))
            print("  %-34s %s" % ("detection_strategies",
                                  ", ".join(s["id"] or "?" for s in t.get("detection_strategies") or [])))
        return 0

    sel = techs
    if args.scope == "host":
        sel = [t for t in sel if t["in_registry_scope"]]
    elif args.scope == "impl":
        sel = [t for t in sel if t["in_implementation_scope"]]
    if args.cls:
        sel = [t for t in sel if t["testability_class"] == args.cls]
    if args.status:
        sel = [t for t in sel if t["baseline_implementation_status"] == args.status]
    if args.tactic:
        sel = [t for t in sel if args.tactic in (t["tactics"] or [])]
    if args.osname:
        sel = [t for t in sel if args.osname in (t["os_scope"] or [])]

    print("matched %d (scope=%s)\n" % (len(sel), args.scope))
    for t in sel:
        if args.brief:
            print("  %-12s %-52s %-16s %s"
                  % (t["technique_id"], (t["name"] or "")[:50],
                     t["testability_class"], ",".join(t["os_scope"])))
        else:
            print("  %-12s %-50s %-16s %-12s %s"
                  % (t["technique_id"], (t["name"] or "")[:48], t["testability_class"],
                     t["baseline_implementation_status"], t["testability_reason"][:100]))
    return 0


if __name__ == "__main__":
    sys.exit(main())

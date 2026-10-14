"""Build the bundled irscan ATT&CK registry from a pinned STIX bundle.

Outputs (all deterministic, all under data/registry/):
    attack_registry.json          the bundled registry consumed by the Go binary
    attack_registry.csv           same content, flat, for review in a spreadsheet
    registry_meta.json            source pin, counts, every coverage denominator
    revoked_deprecated.csv        inactive objects, reported separately per the Phase 0 gate
    classification_audit.csv      one row per in-scope technique: which rule fired and why
"""

import collections
import json
import os

from . import classify, emit, scope
from .stixload import Bundle, _sort_key

SCHEMA_VERSION = "1"


def _load_json(path):
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def build(stix_path, lock_path, overlay_dir, out_dir, embed_path=None):
    lock = _load_json(lock_path)
    taxonomy = _load_json(os.path.join(overlay_dir, "log_source_taxonomy.json"))
    families = _load_json(os.path.join(overlay_dir, "technique_families.json"))
    overrides = _load_json(os.path.join(overlay_dir, "testability_overrides.json"))

    pinned = lock["attack_stix"]

    # Fail loudly if the bundle on disk is not the pinned one. The deployment model depends on
    # the registry being traceable to a known hash, so a mismatch is fatal, not a warning.
    actual = emit.sha256_file(stix_path)
    if actual != pinned["sha256"]:
        raise SystemExit(
            "FATAL: STIX bundle hash mismatch.\n  expected %s\n  actual   %s\n"
            "Run build/fetch_stix.py, or update build/sources.lock.json deliberately."
            % (pinned["sha256"], actual)
        )

    bundle = Bundle(stix_path)
    version = bundle.attack_version()
    if not version:
        raise SystemExit("FATAL: bundle has no x-mitre-collection version; refusing to guess.")
    if version != pinned["version"]:
        raise SystemExit(
            "FATAL: bundle version %r != pinned version %r" % (version, pinned["version"])
        )

    techniques = bundle.techniques()

    anomalies = []
    unclassified_sources = collections.Counter()

    records = []
    for t in techniques:
        tb = classify.classify_testability(t, taxonomy, families, overrides)
        for name in tb["unclassified_log_sources"]:
            unclassified_sources[name] += 1

        status, rationale = classify.baseline_implementation_status(t, tb)

        active = not (t["revoked"] or t["deprecated"])
        host_platforms = sorted(set(t["platforms"]) & set(scope.HOST_PLATFORMS))
        in_registry_scope = active and bool(host_platforms)
        in_impl_scope = in_registry_scope and bool(
            set(t["tactics"]) & set(scope.IMPLEMENTATION_TACTICS)
        )

        if active and not t["tactics"]:
            anomalies.append(
                {"technique_id": t["technique_id"], "issue": "active technique has no tactics"}
            )
        # Only an ACTIVE sub-technique missing its parent is a defect. ATT&CK deliberately
        # drops subtechnique-of for revoked subs, so flagging those was a false positive.
        if active and t["is_subtechnique"] and t.get("parent_id_source") != "relationship":
            anomalies.append(
                {
                    "technique_id": t["technique_id"],
                    "issue": "active sub-technique has no subtechnique-of relationship "
                             "(parent resolved via %s)" % (t.get("parent_id_source") or "none"),
                }
            )
        if not t["name"]:
            anomalies.append({"technique_id": t["technique_id"], "issue": "missing name"})

        rec = dict(t)
        rec.update(tb)
        rec["os_scope"] = [scope.PLATFORM_TO_OS[p] for p in host_platforms]
        rec["active"] = active
        rec["in_registry_scope"] = in_registry_scope
        rec["in_implementation_scope"] = in_impl_scope
        rec["baseline_implementation_status"] = status
        rec["baseline_implementation_rationale"] = rationale
        records.append(rec)

    counts = _counts(records)
    tactics = sorted(
        (
            {
                "id": bundle.tactic_id_by_shortname.get(sn),
                "shortname": sn,
                "name": bundle.tactic_name_by_shortname.get(sn),
                "in_implementation_scope": sn in scope.IMPLEMENTATION_TACTICS,
            }
            for sn in bundle.tactic_id_by_shortname
        ),
        key=lambda d: d["id"] or "",
    )

    registry = {
        "schema_version": SCHEMA_VERSION,
        "source": pinned,
        "scope": {
            "implementation_tactics": list(scope.IMPLEMENTATION_TACTICS),
            "host_platforms": list(scope.HOST_PLATFORMS),
            "note": (
                "ATT&CK v20.0 renamed TA0005 'Defense Evasion' to 'Stealth' and split out "
                "TA0112 'Defense Impairment'. The spec's 'Defense Evasion' scope is resolved "
                "to the union of both. See DECISIONS.md C-001/D-002."
            ),
        },
        "tactics": tactics,
        "counts": counts,
        "techniques": records,
    }

    os.makedirs(out_dir, exist_ok=True)
    hashes = {}

    hashes["attack_registry.json"] = emit.write_json(
        os.path.join(out_dir, "attack_registry.json"), registry
    )

    csv_header = [
        "technique_id", "name", "is_subtechnique", "parent_id", "tactics", "tactic_ids",
        "platforms", "os_scope", "active", "revoked", "deprecated", "revoked_by_id",
        "in_registry_scope", "in_implementation_scope", "testability_class",
        "testability_rule", "baseline_implementation_status", "log_source_categories",
        "telemetry_dependencies", "detection_strategy_ids", "url",
    ]
    csv_rows = [
        [
            r["technique_id"], r["name"], r["is_subtechnique"], r["parent_id"] or "",
            emit.join_list(r["tactics"]), emit.join_list(r["tactic_ids"]),
            emit.join_list(r["platforms"]), emit.join_list(r["os_scope"]),
            r["active"], r["revoked"], r["deprecated"], r["revoked_by_id"] or "",
            r["in_registry_scope"], r["in_implementation_scope"], r["testability_class"],
            r["testability_rule"], r["baseline_implementation_status"],
            emit.join_list(r["log_source_categories"]),
            emit.join_list(r["telemetry_dependencies"]),
            emit.join_list([s["id"] for s in r["detection_strategies"]]),
            r["url"] or "",
        ]
        for r in records
    ]
    hashes["attack_registry.csv"] = emit.write_csv(
        os.path.join(out_dir, "attack_registry.csv"), csv_header, csv_rows
    )

    inactive = [r for r in records if not r["active"]]
    hashes["revoked_deprecated.csv"] = emit.write_csv(
        os.path.join(out_dir, "revoked_deprecated.csv"),
        ["technique_id", "name", "state", "revoked_by_id", "revoked_by_name", "modified"],
        [
            [
                r["technique_id"], r["name"],
                "revoked" if r["revoked"] else "deprecated",
                r["revoked_by_id"] or "", r["revoked_by_name"] or "", r["modified"] or "",
            ]
            for r in sorted(inactive, key=lambda r: _sort_key(r["technique_id"]))
        ],
    )

    audit = [r for r in records if r["in_registry_scope"]]
    hashes["classification_audit.csv"] = emit.write_csv(
        os.path.join(out_dir, "classification_audit.csv"),
        [
            "technique_id", "name", "tactics", "os_scope", "testability_class",
            "testability_rule", "baseline_implementation_status",
            "testability_reason", "baseline_implementation_rationale",
        ],
        [
            [
                r["technique_id"], r["name"], emit.join_list(r["tactics"]),
                emit.join_list(r["os_scope"]), r["testability_class"], r["testability_rule"],
                r["baseline_implementation_status"], r["testability_reason"],
                r["baseline_implementation_rationale"],
            ]
            for r in audit
        ],
    )

    # --- compact registry for Go //go:embed -------------------------------------------
    # Same single source of truth as attack_registry.json, but without the review-only fields
    # (log sources, detection strategies, data components, long reasons). Written into the Go
    # package tree because //go:embed cannot reach outside its own package directory.
    if embed_path:
        embed = {
            "schema_version": SCHEMA_VERSION,
            "source": {
                "version": pinned["version"],
                "sha256": pinned["sha256"],
                "url": pinned["url"],
                "retrieved_at": pinned["retrieved_at"],
                "attribution": pinned["license"]["required_attribution"],
            },
            "scope": registry["scope"],
            "tactics": tactics,
            "counts": counts,
            "techniques": [
                {
                    k: r[k]
                    for k in (
                        "technique_id", "name", "tactics", "tactic_ids", "platforms",
                        "os_scope", "is_subtechnique", "parent_id", "active", "revoked",
                        "deprecated", "revoked_by_id", "in_registry_scope",
                        "in_implementation_scope", "testability_class",
                        "baseline_implementation_status",
                        "baseline_implementation_rationale",
                        "url",
                    )
                }
                for r in records
            ],
        }
        hashes["registry_embed.json"] = emit.write_json(embed_path, embed)

    meta = {
        "schema_version": SCHEMA_VERSION,
        "source": pinned,
        "builder": {
            "note": (
                "Outputs contain no wall-clock timestamp by design, so that two runs on the "
                "same input are byte-identical (Phase 0 gate). The only time recorded is the "
                "pinned source's retrieved_at, which is an input."
            ),
        },
        "scope": registry["scope"],
        "counts": counts,
        "stix_object_type_counts": bundle.type_counts(),
        "parse_anomalies": sorted(anomalies, key=lambda a: (a["technique_id"], a["issue"])),
        "unclassified_log_sources": [
            {"name": k, "occurrences": v}
            for k, v in sorted(unclassified_sources.items(), key=lambda kv: (-kv[1], kv[0]))
        ],
        "output_sha256": hashes,
    }
    # registry_meta.json records the hashes of the other outputs, so it is written last and
    # its own hash is reported by the caller rather than embedded in itself.
    meta_hash = emit.write_json(os.path.join(out_dir, "registry_meta.json"), meta)

    return {"counts": counts, "hashes": dict(hashes, **{"registry_meta.json": meta_hash}),
            "anomalies": anomalies, "unclassified_log_sources": dict(unclassified_sources),
            "meta": meta}


def _counts(records):
    """Every denominator the coverage metrics need, computed once, from one source."""
    active = [r for r in records if r["active"]]
    host = [r for r in records if r["in_registry_scope"]]
    impl = [r for r in records if r["in_implementation_scope"]]

    def dist(rows, key):
        return dict(sorted(collections.Counter(r[key] for r in rows).items()))

    per_tactic = collections.Counter()
    for r in impl:
        for t in r["tactics"]:
            if t in scope.IMPLEMENTATION_TACTICS:
                per_tactic[t] += 1

    per_os = collections.Counter()
    for r in impl:
        for o in r["os_scope"]:
            per_os[o] += 1

    return {
        # --- universes (PLAN.md section 4) ---
        "U_bundle": len(records),
        "U_active": len(active),
        "U_host": len(host),
        "U_impl": len(impl),
        "U_impl_technique_os_pairs": sum(len(r["os_scope"]) for r in impl),
        # --- inactive, reported separately ---
        "revoked": sum(1 for r in records if r["revoked"]),
        "deprecated": sum(1 for r in records if r["deprecated"]),
        "revoked_and_deprecated": sum(
            1 for r in records if r["revoked"] and r["deprecated"]
        ),
        # --- shape ---
        "U_host_top_level": sum(1 for r in host if not r["is_subtechnique"]),
        "U_host_subtechniques": sum(1 for r in host if r["is_subtechnique"]),
        "U_impl_top_level": sum(1 for r in impl if not r["is_subtechnique"]),
        "U_impl_subtechniques": sum(1 for r in impl if r["is_subtechnique"]),
        # --- distributions ---
        "U_host_by_testability_class": dist(host, "testability_class"),
        "U_host_by_testability_rule": dist(host, "testability_rule"),
        "U_host_by_baseline_status": dist(host, "baseline_implementation_status"),
        "U_impl_by_testability_class": dist(impl, "testability_class"),
        "U_impl_by_baseline_status": dist(impl, "baseline_implementation_status"),
        "U_impl_by_tactic": dict(sorted(per_tactic.items())),
        "U_impl_by_os": dict(sorted(per_os.items())),
        # --- gate evidence: every in-scope technique must carry a class and a status ---
        "U_host_unclassified": sum(
            1 for r in host
            if r["testability_class"] not in scope.TESTABILITY_CLASSES
            or not r["baseline_implementation_status"]
        ),
        "U_host_undetermined_class": sum(
            1 for r in host if r["testability_class"] == "UNDETERMINED"
        ),
    }

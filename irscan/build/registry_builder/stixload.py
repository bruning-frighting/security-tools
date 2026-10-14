"""Load a pinned ATT&CK Enterprise STIX 2.1 bundle and resolve it into flat technique records.

Deliberately stdlib-only (DECISIONS.md D-008): the build must run anywhere without pip.

Version-agnostic by design (DECISIONS.md D-005). ATT&CK v20.0 removed ``x_mitre_detection`` and
``x_mitre_data_sources`` from ``attack-pattern`` objects and moved detection content into
``x-mitre-detection-strategy`` / ``x-mitre-analytic`` objects. v19 and earlier carry the old
fields. This module reads whichever representation is present.
"""

import json
from collections import defaultdict

ATTACK_SOURCE = "mitre-attack"


def _external_id(obj):
    """Return the mitre-attack external_id (e.g. 'T1547.001', 'TA0003'), or None."""
    for ref in obj.get("external_references") or []:
        if ref.get("source_name") == ATTACK_SOURCE:
            return ref.get("external_id")
    return None


def _attack_url(obj):
    for ref in obj.get("external_references") or []:
        if ref.get("source_name") == ATTACK_SOURCE:
            return ref.get("url")
    return None


class Bundle:
    """Indexed view over a STIX bundle."""

    def __init__(self, path):
        with open(path, "r", encoding="utf-8") as fh:
            raw = json.load(fh)

        self.bundle_id = raw.get("id")
        self.objects = raw.get("objects") or []
        self.by_stix_id = {o["id"]: o for o in self.objects if "id" in o}

        self._by_type = defaultdict(list)
        for o in self.objects:
            self._by_type[o.get("type")].append(o)

        self.collection = (self._by_type.get("x-mitre-collection") or [None])[0]

        # tactic shortname -> TA id, and shortname -> display name
        self.tactic_id_by_shortname = {}
        self.tactic_name_by_shortname = {}
        for t in self._by_type.get("x-mitre-tactic", []):
            sn = t.get("x_mitre_shortname")
            if sn:
                self.tactic_id_by_shortname[sn] = _external_id(t)
                self.tactic_name_by_shortname[sn] = t.get("name")

        self._index_relationships()
        self._index_detection()

    # -- metadata ------------------------------------------------------------------
    def attack_version(self):
        if self.collection:
            return self.collection.get("x_mitre_version")
        # Fall back to the max attack-spec version seen, which is not the same thing;
        # surfaced as None so the caller must fail loudly rather than guess.
        return None

    def collection_modified(self):
        return self.collection.get("modified") if self.collection else None

    def type_counts(self):
        return {k: len(v) for k, v in sorted(self._by_type.items()) if k}

    # -- relationships -------------------------------------------------------------
    def _index_relationships(self):
        self.parent_of = {}          # sub stix id -> parent stix id
        self.children_of = defaultdict(list)
        self.revoked_by = {}         # stix id -> stix id

        for r in self._by_type.get("relationship", []):
            rt = r.get("relationship_type")
            src, tgt = r.get("source_ref"), r.get("target_ref")
            if not src or not tgt:
                continue
            if rt == "subtechnique-of":
                self.parent_of[src] = tgt
                self.children_of[tgt].append(src)
            elif rt == "revoked-by":
                self.revoked_by[src] = tgt

    # -- detection content ---------------------------------------------------------
    def _index_detection(self):
        """Resolve, per attack-pattern, the detection strategies / analytics / log sources.

        v20 shape:  x-mitre-detection-strategy --detects--> attack-pattern
                    strategy.x_mitre_analytic_refs -> x-mitre-analytic
                    analytic.x_mitre_log_source_references[] -> {name, channel, data component}
                    data-component.x_mitre_log_sources[]      -> {name, channel}
        """
        self.strategies_for = defaultdict(list)   # ap stix id -> [strategy obj]
        for r in self._by_type.get("relationship", []):
            if r.get("relationship_type") != "detects":
                continue
            src = self.by_stix_id.get(r.get("source_ref"))
            if src and src.get("type") == "x-mitre-detection-strategy":
                self.strategies_for[r.get("target_ref")].append(src)

        self.analytic_by_id = {
            o["id"]: o for o in self._by_type.get("x-mitre-analytic", [])
        }
        self.data_component_by_id = {
            o["id"]: o for o in self._by_type.get("x-mitre-data-component", [])
        }

    def detection_for(self, ap):
        """Return (strategies, log_sources, data_components, analytic_platforms) for one AP.

        log_sources is a sorted list of {"name","channel"} dicts, deduplicated.
        """
        strategies, log_sources, components, platforms = [], set(), set(), set()

        for strat in self.strategies_for.get(ap["id"], []):
            strategies.append(
                {"id": _external_id(strat), "name": strat.get("name")}
            )
            for aref in strat.get("x_mitre_analytic_refs") or []:
                an = self.analytic_by_id.get(aref)
                if not an:
                    continue
                for p in an.get("x_mitre_platforms") or []:
                    platforms.add(p)
                for ls in an.get("x_mitre_log_source_references") or []:
                    name = (ls.get("name") or "").strip()
                    if name:
                        log_sources.add((name, (ls.get("channel") or "").strip()))
                    # Record the data component's NAME only. Deliberately do NOT expand the
                    # component's own x_mitre_log_sources: a component such as "File
                    # Modification" carries dozens of log sources spanning every platform, so
                    # expanding it attributes evidence to a technique that its analytics never
                    # cite. Measured effect of expanding: 492/511 in-scope techniques collapsed
                    # to MIXED (96.3%), which is a meaningless classification. The analytic's
                    # own log_source_references are the precise signal.
                    dc = self.data_component_by_id.get(
                        ls.get("x_mitre_data_component_ref")
                    )
                    if dc:
                        components.add(dc.get("name"))

        # Pre-v20 fallback: techniques carried x_mitre_data_sources as "Source: Component"
        for ds in ap.get("x_mitre_data_sources") or []:
            if ":" in ds:
                src, comp = ds.split(":", 1)
                log_sources.add((src.strip(), comp.strip()))
                components.add(comp.strip())
            else:
                log_sources.add((ds.strip(), ""))

        return (
            sorted(strategies, key=lambda s: (s["id"] or "", s["name"] or "")),
            [
                {"name": n, "channel": c}
                for n, c in sorted(log_sources)
            ],
            sorted(c for c in components if c),
            sorted(platforms),
        )

    # -- techniques ----------------------------------------------------------------
    def techniques(self):
        """Yield one flat dict per attack-pattern, with relationships resolved.

        Deterministic: output order is sorted by technique ID.
        """
        aps = self._by_type.get("attack-pattern", [])
        out = []
        for ap in aps:
            tid = _external_id(ap)
            if not tid:
                # An attack-pattern with no ATT&CK ID cannot be addressed by the tool.
                # Surfaced by build.py as a parse anomaly rather than dropped quietly.
                continue

            parent_stix = self.parent_of.get(ap["id"])
            parent_obj = self.by_stix_id.get(parent_stix) if parent_stix else None

            # ATT&CK drops the subtechnique-of relationship for revoked sub-techniques (all 13
            # T1562.* subs, T1053.001, T1070.001/.002, T1547.011 in v20.0). Falling back to the
            # ID-derived parent keeps the family linkage intact for traceability; how the parent
            # was resolved is recorded so the fallback is never mistaken for STIX-asserted data.
            parent_id = _external_id(parent_obj) if parent_obj else None
            parent_source = "relationship" if parent_id else None
            if not parent_id and ap.get("x_mitre_is_subtechnique") and "." in (tid or ""):
                parent_id = tid.split(".", 1)[0]
                parent_source = "derived_from_id"

            revoked_stix = self.revoked_by.get(ap["id"])
            revoked_obj = self.by_stix_id.get(revoked_stix) if revoked_stix else None

            tactics = sorted(
                {
                    kcp.get("phase_name")
                    for kcp in ap.get("kill_chain_phases") or []
                    if kcp.get("kill_chain_name") == ATTACK_SOURCE and kcp.get("phase_name")
                }
            )

            strategies, log_sources, components, an_platforms = self.detection_for(ap)

            out.append(
                {
                    "technique_id": tid,
                    "stix_id": ap["id"],
                    "name": ap.get("name"),
                    "is_subtechnique": bool(ap.get("x_mitre_is_subtechnique")),
                    "parent_id": parent_id,
                    "parent_name": parent_obj.get("name") if parent_obj else None,
                    "parent_id_source": parent_source,
                    "sub_technique_ids": sorted(
                        filter(
                            None,
                            (
                                _external_id(self.by_stix_id[c])
                                for c in self.children_of.get(ap["id"], [])
                                if c in self.by_stix_id
                            ),
                        )
                    ),
                    "tactics": tactics,
                    "tactic_ids": sorted(
                        filter(
                            None,
                            (self.tactic_id_by_shortname.get(t) for t in tactics),
                        )
                    ),
                    "platforms": sorted(ap.get("x_mitre_platforms") or []),
                    "revoked": bool(ap.get("revoked")),
                    "deprecated": bool(ap.get("x_mitre_deprecated")),
                    "revoked_by_id": _external_id(revoked_obj) if revoked_obj else None,
                    "revoked_by_name": revoked_obj.get("name") if revoked_obj else None,
                    "attack_technique_version": ap.get("x_mitre_version"),
                    "created": ap.get("created"),
                    "modified": ap.get("modified"),
                    "url": _attack_url(ap),
                    "detection_strategies": strategies,
                    "log_sources": log_sources,
                    "data_components": components,
                    "analytic_platforms": an_platforms,
                }
            )

        out.sort(key=lambda t: _sort_key(t["technique_id"]))
        return out


def _sort_key(tid):
    """Sort T1547 before T1547.001 and T1003.002 before T1003.010 (numeric, not lexical)."""
    base, _, sub = tid.partition(".")
    try:
        bnum = int(base.lstrip("T") or 0)
    except ValueError:
        bnum = 0
    snum = int(sub) if sub.isdigit() else -1
    return (bnum, snum, tid)

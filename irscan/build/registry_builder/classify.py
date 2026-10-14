"""Deterministic testability classification and baseline implementation status.

Two separate jobs, kept separate on purpose:

* ``classify_testability`` answers "what kind of evidence does this technique leave, and can a
  read-only retrospective host scan reach it?"  This is an evidence-reach judgement.
* ``baseline_implementation_status`` answers "what should the registry claim about this
  technique before any check inventory is consulted?"  The Go side computes the *effective*
  status by joining this baseline with the real check inventory, so the registry never gets to
  claim IMPLEMENTED on its own (DECISIONS.md D-009).

Every rule records which rule fired, so no classification is anonymous.
"""

from . import scope


# --------------------------------------------------------------------------------------
# log-source categorisation
# --------------------------------------------------------------------------------------
def categorise_log_sources(log_sources, taxonomy):
    """Map log-source names to evidence categories.

    Returns (categories:set, unclassified:sorted list).
    Unclassified names are returned rather than defaulted, so the build can report them.
    """
    exact = taxonomy.get("exact") or {}
    prefixes = taxonomy.get("prefixes") or {}

    cats, unknown = set(), set()
    for ls in log_sources:
        raw = (ls.get("name") or "").strip()
        if not raw:
            continue
        key = raw.lower()
        if key in exact:
            cats.add(exact[key])
            continue
        prefix = key.split(":", 1)[0].strip()
        if prefix in prefixes:
            cats.add(prefixes[prefix])
            continue
        unknown.add(raw)
    return cats, sorted(unknown)


def _family_hit(technique_id, parent_id, table):
    """Family tables are keyed by top-level ID, but allow an exact sub-technique key too."""
    if technique_id in table:
        return technique_id, table[technique_id]
    top = parent_id or technique_id.split(".", 1)[0]
    if top in table:
        return top, table[top]
    return None, None


# --------------------------------------------------------------------------------------
# testability
# --------------------------------------------------------------------------------------
def classify_testability(tech, taxonomy, families, overrides):
    """Return a dict: class, reason, rule, plus the signals the decision rested on.

    Rule order is fixed and documented. First match wins.
    """
    tid = tech["technique_id"]
    parent = tech.get("parent_id")
    platforms = set(tech.get("platforms") or [])
    host_platforms = platforms & set(scope.HOST_PLATFORMS)

    cats, unknown_sources = categorise_log_sources(tech.get("log_sources") or [], taxonomy)

    # R0 -- inactive objects are not classified; they are excluded from every live denominator.
    if tech["revoked"] or tech["deprecated"]:
        why = "revoked" if tech["revoked"] else "deprecated"
        target = tech.get("revoked_by_id")
        reason = "ATT&CK object is %s%s; excluded from all live denominators." % (
            why,
            " and superseded by %s" % target if target else "",
        )
        return _res("NOT_CLASSIFIED_INACTIVE", reason, "R0-inactive", cats, unknown_sources)

    # R1 -- platform mismatch. The only honest route to NOT_APPLICABLE later on.
    if not host_platforms:
        reason = (
            "ATT&CK platforms are [%s]; neither Windows nor Linux, so the technique cannot "
            "apply to a Windows/Linux host scan." % ", ".join(sorted(platforms) or ["none"])
        )
        return _res("OFF_HOST", reason, "R1-platform-mismatch", cats, unknown_sources)

    # R2 -- explicit reviewed override.
    ov = (overrides.get("overrides") or {}).get(tid)
    if ov:
        return _res(
            ov["class"],
            "Reviewed override: %s" % ov.get("reason", "(no reason recorded)"),
            "R2-override",
            cats,
            unknown_sources,
        )

    # Signals
    art_key, art_reason = _family_hit(tid, parent, families.get("artifact_family") or {})
    mem_key, mem_reason = _family_hit(tid, parent, families.get("memory_family") or {})
    net_key, net_reason = _family_hit(tid, parent, families.get("network_family") or {})

    artifact_from_sources = bool(cats & set(scope.ARTIFACT_CATEGORIES))
    artifact = bool(art_key) or artifact_from_sources

    win_tel = bool(cats & set(scope.WIN_TELEMETRY_CATEGORIES)) and "Windows" in host_platforms
    lin_tel = bool(cats & set(scope.LINUX_TELEMETRY_CATEGORIES)) and "Linux" in host_platforms
    agnostic_tel = bool(cats & set(scope.OS_AGNOSTIC_TELEMETRY_CATEGORIES))
    host_tel = win_tel or lin_tel or agnostic_tel

    deps = sorted(cats & set(scope.DEPENDENT_TELEMETRY_CATEGORIES))

    def artifact_text():
        if art_key:
            return "artifact family %s: %s" % (art_key, art_reason)
        return "STIX log sources include durable host state (category 'artifact')"

    def tel_text():
        bits = []
        if win_tel:
            bits.append("Windows event/ETW telemetry")
        if lin_tel:
            bits.append("Linux audit/journal telemetry")
        if agnostic_tel:
            bits.append("OS-agnostic activity telemetry")
        return ", ".join(bits)

    # R3 -- both durable state and telemetry.
    if artifact and host_tel:
        return _res(
            "MIXED",
            "Durable host state plus telemetry. Artifact: %s. Telemetry: %s."
            % (artifact_text(), tel_text()),
            "R3-artifact-and-telemetry",
            cats, unknown_sources, deps,
        )

    # R4 -- durable state only.
    if artifact:
        return _res(
            "HOST_ARTIFACT",
            "Durable host state readable by a current-state scan. %s." % artifact_text(),
            "R4-artifact-only",
            cats, unknown_sources, deps,
        )

    # R5 -- telemetry only. Checked BEFORE the memory/network families on purpose: if usable
    # host telemetry exists, saying "needs memory forensics" would understate what is possible
    # and would wrongly push the technique to UNSUPPORTED.
    if host_tel:
        extra = ""
        if deps:
            extra = (
                " Telemetry depends on %s, which a stock host will not have."
                % " and ".join(deps)
            )
        return _res(
            "HOST_TELEMETRY",
            "No durable artifact identified; detection depends on host logs (%s) having been "
            "enabled and retained.%s" % (tel_text() or "unspecified host telemetry", extra),
            "R5-telemetry-only",
            cats, unknown_sources, deps,
        )

    # R6 -- volatile-only.
    if mem_key:
        return _res(
            "MEMORY_ONLY",
            "Evidence is volatile and no host log source was resolved. Memory family %s: %s"
            % (mem_key, mem_reason),
            "R6-memory-family",
            cats, unknown_sources, deps,
        )

    # R7 -- network-only.
    if net_key:
        return _res(
            "NETWORK_ONLY",
            "Evidence is on the wire and no host log source was resolved. Network family %s: %s"
            % (net_key, net_reason),
            "R7-network-family",
            cats, unknown_sources, deps,
        )

    # R8 -- every resolved source is off-host.
    if cats and cats <= set(scope.OFF_HOST_CATEGORIES) | set(scope.NETWORK_CATEGORIES):
        if cats & set(scope.OFF_HOST_CATEGORIES):
            return _res(
                "OFF_HOST",
                "All resolved log sources are off-host (%s); evidence lives on another system."
                % ", ".join(sorted(cats)),
                "R8-offhost-sources",
                cats, unknown_sources, deps,
            )
        return _res(
            "NETWORK_ONLY",
            "All resolved log sources require network sensor visibility (%s)."
            % ", ".join(sorted(cats)),
            "R8-network-sources",
            cats, unknown_sources, deps,
        )

    # R9 -- pre-compromise tactics only.
    tactics = set(tech.get("tactics") or [])
    if tactics and tactics <= set(scope.PRE_COMPROMISE_TACTICS):
        return _res(
            "NO_HOST_EVIDENCE",
            "Technique sits only in pre-compromise tactics (%s); the activity happens off the "
            "victim host." % ", ".join(sorted(tactics)),
            "R9-pre-compromise",
            cats, unknown_sources, deps,
        )

    # R10 -- rules exhausted. Made visible instead of guessed.
    return _res(
        "UNDETERMINED",
        "No artifact family, no host-local log source and no off-host/network/volatile signal "
        "could be resolved from the pinned STIX data. Requires analyst review; tracked as a "
        "Phase 2d work item.",
        "R10-undetermined",
        cats, unknown_sources, deps,
    )


def _res(cls, reason, rule, cats, unknown, deps=()):
    return {
        "testability_class": cls,
        "testability_reason": reason,
        "testability_rule": rule,
        "log_source_categories": sorted(cats),
        "unclassified_log_sources": list(unknown),
        "telemetry_dependencies": list(deps),
    }


# --------------------------------------------------------------------------------------
# baseline implementation status
# --------------------------------------------------------------------------------------
def baseline_implementation_status(tech, testability):
    """The registry's claim *before* the check inventory is consulted.

    Never returns IMPLEMENTED or PARTIAL: only the Go check inventory may assert those, and
    only through the per-check quality gate (DECISIONS.md D-009).
    """
    cls = testability["testability_class"]
    tid = tech["technique_id"]

    if cls == "NOT_CLASSIFIED_INACTIVE":
        why = "revoked" if tech["revoked"] else "deprecated"
        target = tech.get("revoked_by_id")
        return (
            "NOT_APPLICABLE",
            "ATT&CK object is %s%s. Retained in the registry for traceability and reported "
            "separately; excluded from all coverage denominators."
            % (why, ", superseded by %s" % target if target else ""),
        )

    if testability["testability_rule"] == "R1-platform-mismatch":
        return (
            "NOT_APPLICABLE",
            "Platform mismatch: ATT&CK platforms are [%s]. irscan scans Windows and Linux "
            "hosts, so this technique cannot occur on an in-scope host. This is the only "
            "non-inactive route to NOT_APPLICABLE." % ", ".join(tech.get("platforms") or []),
        )

    in_impl_scope = bool(set(tech.get("tactics") or []) & set(scope.IMPLEMENTATION_TACTICS))

    if cls in scope.UNREACHABLE_CLASSES:
        return (
            "UNSUPPORTED",
            "Evidence class %s: %s This is an evidence-reach limit of read-only retrospective "
            "host scanning, not a difficulty judgement -- hence UNSUPPORTED, not "
            "NOT_APPLICABLE." % (cls, testability["testability_reason"]),
        )

    if cls == "UNDETERMINED":
        return (
            "PLANNED",
            "Testability classification could not be derived from the pinned STIX data. "
            "Held as PLANNED pending analyst review rather than assigned a confident class.",
        )

    if not in_impl_scope:
        return (
            "PLANNED",
            "Scannable (evidence class %s) but outside the spec's implementation scope "
            "(technique tactics: %s; implementation scope: %s). Deferred, not excluded: it "
            "remains visible in coverage and gap reports."
            % (
                cls,
                ", ".join(tech.get("tactics") or []),
                ", ".join(scope.IMPLEMENTATION_TACTICS),
            ),
        )

    return (
        "PLANNED",
        "In implementation scope and scannable (evidence class %s), but no check in this "
        "build maps to it yet. Not a difficulty judgement and not out of scope -- building "
        "a check for it is future work. If a later build adds a gate-passing check for this "
        "technique, the coverage report's effective status overrides this baseline and "
        "reports IMPLEMENTED or PARTIAL instead." % cls,
    )

"""Scope constants for the irscan ATT&CK registry.

Everything in this module is a *scope decision*, not data read from STIX. Each constant
cites the DECISIONS.md entry that justifies it.
"""

# --- Implementation scope (DECISIONS.md C-001 / D-002) -----------------------------------
#
# The spec scopes implementation to "Persistence, Defense Evasion and Credential Access".
# ATT&CK v20.0 has no tactic named "Defense Evasion": TA0005 was renamed "Stealth" and a new
# TA0112 "Defense Impairment" was split out. The spec's intent is therefore the union of both.
IMPLEMENTATION_TACTICS = (
    "credential-access",
    "defense-impairment",
    "persistence",
    "stealth",
)

# Tactic shortnames that are pre-compromise / off-target by definition. Used only to explain
# a NO_HOST_EVIDENCE classification, never to exclude a technique from the registry.
PRE_COMPROMISE_TACTICS = ("reconnaissance", "resource-development")

# --- Host scope ------------------------------------------------------------------------
# irscan is a Windows/Linux host scanner. A technique whose ATT&CK platforms include neither
# is NOT_APPLICABLE by platform mismatch -- the one honest use of NOT_APPLICABLE.
HOST_PLATFORMS = ("Linux", "Windows")

PLATFORM_TO_OS = {
    "Linux": "linux",
    "Windows": "windows",
}

# --- Testability classes (PLAN.md 3.1) --------------------------------------------------
TESTABILITY_CLASSES = (
    "HOST_ARTIFACT",
    "HOST_TELEMETRY",
    "MIXED",
    "MEMORY_ONLY",
    "NETWORK_ONLY",
    "OFF_HOST",
    "NO_HOST_EVIDENCE",
    # Not in PLAN.md 3.1's evidence taxonomy: a visible "the rules could not decide" marker.
    # Techniques landing here are reported as a Phase 2d work item rather than silently
    # absorbed into a confident-looking class.
    "UNDETERMINED",
    # Assigned to revoked/deprecated objects, which are excluded from every live denominator.
    "NOT_CLASSIFIED_INACTIVE",
)

# Classes where a retrospective host scan can, in principle, find something.
SCANNABLE_CLASSES = ("HOST_ARTIFACT", "MIXED", "HOST_TELEMETRY")

# Classes where this tool's evidence reach cannot support the technique. UNSUPPORTED, never
# NOT_APPLICABLE -- difficulty and evidence-reach are not the same as inapplicability.
UNREACHABLE_CLASSES = ("MEMORY_ONLY", "NETWORK_ONLY", "OFF_HOST", "NO_HOST_EVIDENCE")

# --- implementation_status (PLAN.md 3.2) ------------------------------------------------
IMPLEMENTATION_STATUSES = (
    "IMPLEMENTED",
    "PARTIAL",
    "PLANNED",
    "UNSUPPORTED",
    "NOT_APPLICABLE",
)

# --- Log-source categories that count as host-local telemetry for a given OS ------------
WIN_TELEMETRY_CATEGORIES = ("win_telemetry",)
LINUX_TELEMETRY_CATEGORIES = ("linux_telemetry",)
# OS-agnostic telemetry signals. 'edr' and 'integrity_baseline' are host-local but depend on a
# product or a pre-existing baseline that a stock host will not have; they are recorded as
# telemetry_dependencies so reports can say so rather than implying the data is just there.
OS_AGNOSTIC_TELEMETRY_CATEGORIES = ("generic_telemetry", "edr", "integrity_baseline")
DEPENDENT_TELEMETRY_CATEGORIES = ("edr", "integrity_baseline")

OFF_HOST_CATEGORIES = ("cloud_offhost", "other_platform", "external")
NETWORK_CATEGORIES = ("network",)
ARTIFACT_CATEGORIES = ("artifact",)

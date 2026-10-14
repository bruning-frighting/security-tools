"""Build-time ATT&CK registry builder for irscan.

Build-time only. Nothing in this package ships to a target host and nothing here runs during a
scan -- the scan consumes the generated, hash-pinned registry embedded in the Go binary.

Stdlib only, by decision (DECISIONS.md D-008).
"""

__all__ = ["build", "classify", "emit", "scope", "stixload"]

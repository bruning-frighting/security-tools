# Release notes

## v0.1.0-phase1 — 2026-10-14

First working build, produced in one development session through Phases 0–2d of `PLAN.md`,
followed by Phase 3 and an independent adversarial review pass by a separate agent. **Not
production-ready** — see `README.md` "Validation status" and `DECISIONS.md` for blockers.

### Binaries

Built reproducibly with `bash build/go.sh dist` from Go 1.27.2 (`linux/amd64`, cross-compiling
the Windows target), `-trimpath -buildvcs=false`, version/commit stamped via `-ldflags`.
`-buildvcs=false` is deliberate: `dist/` was accidentally committed to git in earlier phases
(caught and fixed by the independent review — see `STATUS.md`), which made Go's default VCS
stamping embed a flipping `vcs.modified` flag and produce a different hash on every rebuild
from identical source. With it fixed, three consecutive rebuilds from the same source produce
byte-identical output — verified directly, not assumed.

| File | SHA-256 |
|---|---|
| `dist/irscan-linux-amd64` | `06ad42f75bfc04ba02395541ed71be25b4686dec0212c94a86b718f25e4784e4` |
| `dist/irscan-windows-amd64.exe` | `6cc1a3f50a691fdc2582ef4fc8ae1c7c13e3a8cbc70d1b49964f90b572fb7e88` |

The Linux binary has been **executed** against a live host (WSL2 Kali GNU/Linux Rolling
2026.1, unprivileged) — see `STATUS.md` for every recorded run. The Windows binary has been
**built and `go vet`-checked only**; it has never run. See blocker B-001 in `DECISIONS.md`.

### Bundled ATT&CK data

MITRE ATT&CK Enterprise **v20.0** (STIX 2.1), pinned, hash-verified, attributed in `NOTICE`.

- Source: `https://github.com/mitre-attack/attack-stix-data`
- Bundle SHA-256: `81113ba98afa2928f3dcff62022539f7ce30c315c32e14422f11ff95ce534352`
- Retrieved: `2026-10-14T03:19:23Z`

### Checks: 19 implemented, all passing the full per-check quality gate

| OS | Count | Tactics covered |
|---|---|---|
| Linux | 11 | persistence, stealth, defense-impairment, credential-access |
| Windows | 8 | persistence, defense-impairment, credential-access |

Full list with ATT&CK mappings, validation status and lab evidence: `STATUS.md` Phases 1–2c.
11 of 19 checks are `LAB_VERIFIED` (all on Linux, against a real host); the remaining 8
(all Windows) are `FIXTURE_TESTED`, capped by B-001.

### Coverage (computed by `irscan attack --report coverage`, not hand-maintained)

| Metric | Value |
|---|---|
| M1 registry completeness | 867/867 = 100.0% |
| M2 classification completeness | 511/511 = 100.0% |
| M3 implementation coverage | 39/296 = 13.2% |
| M4 partial coverage | 5/296 = 1.7% |
| M5 validation (`LAB_VERIFIED`) | 11/19 = 57.9% (`FIXTURE_TESTED` 8/19 reported beside it, never added in) |

Per-tactic M3: persistence 23/91, defense-impairment 9/35, stealth 4/141, credential-access
5/58. See `STATUS.md` for the full breakdown including (technique, OS) pairs.

### What changed in this release vs. a naive first attempt — recorded because it's the point

Every phase in `STATUS.md` documents real defects found by fixtures or real-host runs and
fixed before the phase gate was accepted, including two that would have shipped **false
positives on every clean host of that kind**: a Linux check that flagged 43 symlinks (mode
bits are always `lrwxrwxrwx`) and 6 masked systemd units (`-> /dev/null`, which *disables* a
unit) as persistence; and a Windows scheduled-task check that flagged Microsoft's own stock
`\Microsoft\Windows\*` maintenance tasks for being hidden and running as SYSTEM, which is
their normal, correct state. Both were found by writing a negative fixture reflecting real
legitimate software *before* accepting the check, per the spec's requirement.

### Known gaps in this release

- No Sigma execution, no container/Trivy module (explicitly out of scope).
- No remediation of any kind, anywhere (by design).
- Malware module: interface exists, explicitly `NOT IMPLEMENTED` (`DECISIONS.md` D-007) — no
  scanner was invented.
- 464 of 511 in-scope-applicable techniques remain `PLANNED` (classified, scannable, not yet
  built) — see `STATUS.md` Phase 2d for the full honest tally, including the 3 genuinely
  `UNSUPPORTED` techniques and why.

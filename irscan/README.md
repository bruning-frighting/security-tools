# irscan — MITRE ATT&CK Host Artifact & Technique Scanner

A portable, read-only, retrospective host artifact scanner for incident response. An
operator logs into a live (possibly compromised) customer server, drops a folder, and runs
one binary. There is no installation, no runtime dependency on the target, and no network
access at scan time. The bundled MITRE ATT&CK registry, overlay documentation and default
allowlist are produced at build time and embedded in the binary.

**This is not a production-ready product.** It is a working prototype built and tested in one
development session, in the environment described in [STATUS.md](STATUS.md). Read that
file, and [DECISIONS.md](DECISIONS.md), before relying on anything here. In particular: **no
Windows binary built by this project has ever been executed** — see "Validation status" below
and blocker B-001 in `DECISIONS.md`.

---

## What this tool fundamentally cannot do

Read this before reading anything else. A retrospective scan sees **current state plus
whatever logs happen to survive**. It cannot see:

- Anything that existed only in volatile memory and is now gone.
- Anything whose only evidence was a log that was never enabled, has rolled over, or was
  cleared before the scan ran.
- Anything whose evidence lives entirely off-host — an identity provider, a cloud control
  plane, a mail gateway, a network sensor.
- Anything an adversary with sufficient privilege chose to remove, **including artifacts this
  tool itself depends on**.

**On a possibly-compromised host, absence of a finding is not evidence of absence, and any
artifact this tool reports may have been tampered with before the scan ever ran.** Every
report `irscan` produces repeats this notice. Treat results as one input to an investigation,
corroborated against off-host evidence wherever that is possible — a comparison against a
known-good peer host, a remote log collector, or EDR telemetry will all tell you things this
tool structurally cannot.

Missing logs or missing privileges are reported as `INSUFFICIENT_DATA` or `PARTIAL_DATA`,
**never** as `NOT_DETECTED`. A check that cannot answer says so; it never reports a blind spot
as a clean result. This rule is enforced in code (`model.CheckResult.Validate`), not just by
convention, and the test suite asserts it directly.

---

## Deployment model

```
irscan attack --os linux --output /path/to/evidence
```

- Read-only. Never deletes, quarantines, kills or modifies anything on the scanned host.
- Never opens sensitive process memory (LSASS and equivalents) — this is enforced by a test
  that scans the source of every host-facing package for the relevant API names.
- Writes **only** inside the `--output` directory (`internal/safety.OutputGuard`).
- Low CPU/IO priority, per-collector timeouts, file-count and file-size limits, network
  filesystems skipped by default.
- Every report carries a `scan_id` and a self-identification block (process name, PID, user)
  so an analyst can exclude the scan's own activity from subsequent log review.
- Raw host data is never persisted. The evidence manifest holds bounded, often-redacted
  excerpts plus SHA-256 hashes — see `internal/model.EvidenceRef`.
- Credential-related checks never record a secret value — only its location, a pattern-type
  label, and metadata (`internal/check.RedactedEvidence`).

## Commands

```
irscan attack  [flags]           run the ATT&CK host artifact checks
irscan all     --scope S [flags] run every available module (attack + malware)
irscan malware                   registered, explicitly NOT IMPLEMENTED (see below)
irscan modules                   list modules and their availability
irscan version                   print version, commit and binary hash
```

Flags for `attack` / `all`:

| Flag | Meaning |
|---|---|
| `--os <windows\|linux>` | target OS (default: this host's OS) |
| `--output <dir>` | output directory — the only place irscan writes |
| `--technique <IDs>` | comma-separated ATT&CK technique IDs to restrict to |
| `--tactic <names>` | comma-separated tactic shortnames |
| `--check <IDs>` | comma-separated check IDs |
| `--allowlist <file>` | scoped, expiring suppression entries (see below) |
| `--root <path>` | treat `<path>` as the filesystem root (offline/triage images) |
| `--synthetic` | mark `--root` as a fixture tree, not a mounted real root |
| `--dry-run` | list the collectors that would run and the privileges each needs; reads nothing |
| `--report coverage` | print the coverage-and-gaps report; does not scan |
| `--scope <id>` (for `all` only) | required — `all` must be an explicit, approved decision |

```
irscan malware
```

There is no malware-scanning module in this repository. Running `irscan malware` prints why
and exits non-zero — it does **not** silently return an empty, "clean" result. See
`DECISIONS.md` D-007 for why nothing was invented here, and `internal/module/module.go` for
the interface a real module would implement.

---

## The six coverage metrics

> **These metric definitions are a reconstruction.** The task that produced this tool named an
> authoritative specification document that was not present in the session, and referred to
> "the spec's six coverage metrics" without enumerating them in the restated requirements.
> This set was derived from the stated properties (separate, each with an explicit numerator
> and denominator, never merged into one score) — see `DECISIONS.md` D-001. If the real
> specification becomes available, re-check these against it.

| | Numerator | Denominator |
|---|---|---|
| **M1** Registry completeness | techniques parsed with all required fields resolved | every technique in the pinned STIX bundle |
| **M2** Classification completeness | in-scope techniques with a resolved testability class and status | all techniques applicable to Windows/Linux |
| **M3** Implementation coverage | techniques with ≥1 check that passes the full quality gate | in-scope techniques (persistence/stealth/defense-impairment/credential-access) |
| **M4** Partial coverage | techniques whose best check is `PARTIAL` | same denominator as M3 |
| **M5** Validation coverage | checks observed running on a real OS (`LAB_VERIFIED`) | all defined checks |
| **M6** Runtime data availability | checks returning `DETECTED`/`NOT_DETECTED` | checks actually executed in *this* scan |

Run `irscan attack --report coverage` to compute these live from the bundled registry and the
real check inventory — they are not hand-maintained numbers. `M5` additionally reports
`FIXTURE_TESTED` beside it; that count is **never** added into `M5` itself.

A technique belonging to several tactics is counted **once** in the global M3/M4 denominators;
a per-tactic and a per-(technique, OS) breakdown are reported alongside the global figure, as
required by the spec restatement.

---

## Reports

Three outputs, kept strictly separate so the signal doesn't drown in the noise:

| File | Contents |
|---|---|
| `findings.{json,md}` | `suspicious_indicator` and above, not suppressed by the allowlist |
| `inventory.{json,md}` | every observed artifact, grouped — existence is not suspicion |
| `coverage_and_gaps.{json,md}` | the six metrics, plus every non-implemented technique and why |
| `evidence_manifest.json` | bounded, redacted excerpts and SHA-256 hashes referenced by findings |
| `scan_manifest.json` | provenance: binary hash, ATT&CK version/hash, sources collected and unavailable, errors, timings, self-identification |

Suppressed findings are **counted at the top of the findings report and listed in an
appendix** — never silently hidden. An allowlist entry requires scope (a path glob plus a
signer or a SHA-256 — a path alone is rejected, since an attacker can write to a path too),
reason, owner and an expiry date; see `internal/allowlist`.

---

## Validation status — read this before trusting a "LAB_VERIFIED" claim

| | Linux checks | Windows checks |
|---|---|---|
| Can `go build`/`go vet` for the target | yes | yes |
| Has the compiled binary ever *run* | **yes** — against the live filesystem of WSL2 Kali GNU/Linux Rolling 2026.1, unprivileged | **no** |
| Validation status ceiling | `LAB_VERIFIED` (achieved for most Linux checks — see `STATUS.md` for the exact list and scan evidence) | `FIXTURE_TESTED` |

**Why no Windows execution happened:** the build host in the session that produced this tool
has Smart App Control enabled (`VerifiedAndReputablePolicyState = 1`), which blocks execution
of any unsigned binary, and there was no other Windows host or code-signing certificate
available. This is recorded as blocker **B-001** in `DECISIONS.md` and was never worked
around — disabling a host security control to make an unsigned build runnable would itself be
the kind of action this tool exists to flag. A test, `TestWindowsChecksAreNotLabVerified`,
fails the build if any Windows-only check in this repository ever claims `LAB_VERIFIED`.

Because every check is a pure function over data objects (collectors are abstracted behind
`internal/collect` interfaces, with `FakeRegistry`/`FakeTelemetry`/`ErrorFS` implementations),
Windows check **logic** is still fully unit-tested on Linux — only the native
`//go:build windows` collector shims (the registry reader in
`internal/collect/winreg_windows.go`) are compile-and-vet-verified only.

`FIXTURE_TESTED` checks additionally record `fixture_provenance`: `synthetic` for hand-built
fixtures, or `captured_real_host` for a fixture captured from a real host by a separate
harness and replayed through the real check logic. Per `DECISIONS.md` D-004,
`captured_real_host` is still capped at `FIXTURE_TESTED` — the collector itself did not run,
so its privilege-handling, error paths and timeouts remain unexercised.

---

## Building

Stdlib-only Go (no third-party runtime dependency to license or audit — see
`build/sources.lock.json`, which records an intentionally empty `go_modules` list) plus
stdlib-only Python for the build-time registry builder.

```sh
# 1. Fetch and verify the pinned ATT&CK STIX bundle (hash-checked; network required once)
python build/fetch_stix.py

# 2. Build the registry (deterministic; the gate checks this)
python build/build_registry.py --check-determinism

# 3. Generate test fixtures
python testdata/make_fixtures.py

# 4. Build, vet and test (any platform with Go 1.27+; Windows cross-compiles cleanly
#    from Linux, which is how this repository's Windows binary was produced)
go build ./...
go vet ./...
go test ./...

# 5. Cross-compile both release binaries with version/commit stamped in, and hash them
bash build/go.sh dist      # -> dist/irscan-linux-amd64, dist/irscan-windows-amd64.exe, dist/SHA256SUMS
```

`irscan version` prints the running binary's own SHA-256, so a report can always be tied back
to the exact build that produced it. `build/sources.lock.json` pins the ATT&CK STIX source
(URL, version, SHA-256, retrieval time) and both Go toolchain archive hashes; a mismatch
between the bundle on disk and the pinned hash is a **fatal** build error, not a warning.

If network access to the STIX repository is blocked, `fetch_stix.py` prints the exact path a
locally supplied `enterprise-attack-<version>.json` should be placed at, and does not attempt
to work around the block.

---

## Project layout

```
build/                  build-time only: STIX fetch + verify, registry builder (Python, stdlib)
data/registry/           generated, bundled: attack_registry.json/csv, revoked/deprecated, audit trail
data/overlay/            curated classification inputs: log-source taxonomy, evidence families, overrides
internal/model/          data contracts (Outcome, Finding, CheckResult) + the rules that govern them
internal/safety/         resource limits, timeouts, the write-confinement guard
internal/collect/        collector interfaces + real (Linux/Windows) and fake implementations
internal/registry/       embedded-registry loader (//go:embed)
internal/check/          the Check interface, Env, the per-check quality gate, mapping validation
internal/checks/         the 19 implemented checks + the gate/invariant test suite
internal/coverage/       the six coverage metrics
internal/report/         the three report types + evidence/scan manifests
internal/module/         module interface, the attack module, the not-implemented malware module
internal/allowlist/      scoped, expiring, non-silent suppression
cmd/irscan/               the CLI
testdata/fixtures/        generated fixtures (python testdata/make_fixtures.py)
dist/                     release binaries + SHA256SUMS (git-ignored, build-time only)
PLAN.md DECISIONS.md STATUS.md    the working record of this build: what was decided, what was verified, where
```

---

## Known limitations (see `STATUS.md` and `DECISIONS.md` for the full, evidence-backed list)

- **Scope**: 19 checks exist against a 296-technique implementation scope (persistence,
  stealth, defense-impairment, credential-access). `irscan attack --report coverage` reports
  the exact current numbers — see the table above for how to read them, and `STATUS.md` for
  the number as of the last recorded build.
- **No Sigma execution, no container/Trivy module**: explicitly out of scope per the task that
  produced this tool.
- **No remediation of any kind**, anywhere, by design.
- **Windows runtime is unverified** — see "Validation status" above.
- **Credential checks are artifact-based and bounded to a named list of known locations**, not
  a filesystem-wide keyword search. This was a deliberate scoping decision after measuring
  that a naive search produces overwhelming false-positive noise on a real development host —
  see `STATUS.md` Phase 2c.
- **Mapped drive letters on Windows are not detected as remote filesystems** (only UNC paths
  are); this is a stated, not hidden, gap in `internal/collect/mounts_other.go`.

## License and attribution

This tool bundles MITRE ATT&CK® data under MITRE's terms of use; the required attribution and
full provenance (version, source URL, SHA-256, retrieval time) are in [NOTICE](NOTICE) and in
every generated report. ATT&CK® is a registered trademark of The MITRE Corporation; this
project is not affiliated with or endorsed by MITRE. See `NOTICE` for MITRE's own coverage
disclaimer, which is directly relevant to how the numbers in this tool's reports should be
read.

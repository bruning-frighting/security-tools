# PLAN.md — `irscan`: MITRE ATT&CK Host Artifact & Technique Scanner

Status of this document: written at session start, before Phase 0 code. Updated only when the
plan changes; changes are logged in `DECISIONS.md`.

---

## 0. Important note on the authoritative input

The task names an attached spec, **"MANDATORY MODULE: MITRE ATT&CK HOST ARTIFACT & TECHNIQUE
SCANNER"**. **That document was not present in this session** — not in the working directory
(`C:\Users\thong\Downloads`), not in the project `.claude` directory, and no file in the working
tree matches its title or the string `irscan`.

Consequence: this plan is built from the *task prompt's* restatement of the spec, which is
detailed and self-consistent. Wherever the prompt refers to spec content it does not reproduce —
most importantly **"the spec's six coverage metrics"** — I have reconstructed a definition,
marked it as a reconstruction, and recorded it as an open item (`DECISIONS.md` D-001). If the
real spec is supplied later, the reconstructed parts must be re-checked against it. Nothing in
this plan claims to quote the spec.

---

## 1. Mission and deployment model

`irscan` is a **retrospective, read-only host artifact scanner**. An incident responder logs into
a live customer server, drops a portable folder, runs one binary, and collects an evidence
package mapped to MITRE ATT&CK.

Non-negotiable deployment constraints:

| Constraint | Implementation consequence |
|---|---|
| No installation | Single self-contained executable |
| No runtime dependencies on the target | Static binary, no interpreter, no shared libs |
| No internet access at runtime | ATT&CK registry + overlay + default allowlist **embedded at build time** |
| Never modify the host | Read-only opens; no delete/quarantine/kill/write outside `--output` |
| Production safety | Low CPU/IO priority, per-collector timeouts, file count/size caps, skip network filesystems |
| Self-identifying | Every report carries `scan_id`; the tool tags its own activity so analysts can exclude it |

### What this tool fundamentally cannot do

Stated up front because it governs the whole classification scheme. A retrospective host scan
sees **current state plus whatever logs survive**. It therefore cannot see:

- Anything that lived only in volatile memory and is now gone.
- Anything whose only evidence was a log that was never enabled, has rolled over, or was cleared.
- Anything whose evidence lives off-host (identity provider, cloud control plane, mail gateway,
  network sensors).
- Anything an adversary with sufficient privilege chose to remove — **including the artifacts this
  tool reads**. On a possibly-compromised host, absence of a finding is not evidence of absence,
  and present artifacts may have been tampered with. Every report states this.

---

## 2. Scope

### 2.1 Registry scope

**All** Enterprise ATT&CK tactics, techniques and sub-techniques for Windows and Linux, generated
from official STIX — never hand-typed. Pinned source recorded with version, retrieval time, URL
and SHA-256 in `build/sources.lock.json`.

Pinned input: **ATT&CK Enterprise v20.0**, `enterprise-attack-20.0.json`, from
`mitre-attack/attack-stix-data` (the official versioned STIX 2.1 distribution).

### 2.2 ATT&CK v20.0 tactic restructuring — affects the spec's scope wording

**v20.0 changed the tactic names the spec relies on.** Verified directly in the pinned bundle
(`x-mitre-tactic` objects) and cross-checked against MITRE's v20 release material:

- `TA0005` is no longer "Defense Evasion". In v20.0 `TA0005` is **"Stealth"** (shortname `stealth`).
- A **new** tactic `TA0112` **"Defense Impairment"** (shortname `defense-impairment`) exists.
- `T1562` "Impair Defenses" is **no longer an active technique**. Its subject matter now lives in
  `T1685` Disable or Modify Tools, `T1686` Disable or Modify System Firewall, `T1687` Exploitation
  for Defense Impairment, `T1688` Safe Mode Boot, `T1689` Downgrade Attack, `T1690` Prevent
  Command History Logging.

The spec's implementation scope "Persistence, Defense Evasion and Credential Access" is therefore
resolved to these **four** v20.0 tactic shortnames:

```
persistence           (TA0003)
stealth               (TA0005)   <- successor to the name "Defense Evasion"
defense-impairment    (TA0112)   <- split out of the old Defense Evasion
credential-access     (TA0006)
```

This is a widening relative to a literal reading of the spec, not a narrowing: every technique
that would have been in scope under pre-v20 "Defense Evasion" remains in scope. Recorded as
D-002. The spec's four named Defense-Evasion focus areas map as:

| Spec focus area | v20.0 techniques |
|---|---|
| impair defenses | `T1685.*`, `T1686.*`, `T1690` (tactic `defense-impairment`) |
| indicator removal | `T1070.*` (tactic `stealth`), `T1685.004/.005/.006` |
| hidden artifacts | `T1564.*` (tactic `stealth`) |
| trust subversion | `T1553.*` (tactic `defense-impairment`) |

### 2.3 Implementation scope

Checks are written **only** for the four tactics above. Every other technique stays in the
registry and stays visible in reports, classified `UNSUPPORTED`, `PLANNED` or `NOT_APPLICABLE`
with a rationale.

### 2.4 Out of scope

Container/Trivy module; Sigma execution (gated behind Phases 0–2 completing); **remediation of
any kind**. CLI commands are created only when working code stands behind them.

### 2.5 Malware module

The working directory was inspected. There is **no malware-scanning module** in the repository
(`svanm_ir_toolkit.zip` is an unrelated 3-file IR helper: `ir_tool.py`, `README.md`,
`services.example.json`). Therefore: build the unified CLI shell and a module interface, register
a clearly marked **not-implemented** malware command, and **do not invent a malware scanner**.

---

## 3. Classification scheme

### 3.1 Testability class (why a technique is or is not host-scannable)

Assigned to every in-scope technique. Rule-based and deterministic, derived from STIX
(`x-mitre-data-component` → `x_mitre_log_sources`, `detects` relationships, platforms, tactic)
plus a small explicit, reviewed override table. Never random hand-typing.

| Class | Meaning |
|---|---|
| `HOST_ARTIFACT` | A persistent on-disk / registry / config artifact survives execution. Retrospectively scannable. |
| `HOST_TELEMETRY` | Needs host logs (Security, Sysmon, PowerShell, auditd) that may not be enabled or retained. |
| `MIXED` | Both an artifact path and a telemetry path exist. |
| `MEMORY_ONLY` | Evidence is volatile; needs live memory forensics. |
| `NETWORK_ONLY` | Needs network visibility (pcap/flow/proxy) unavailable on-host retrospectively. |
| `OFF_HOST` | Evidence lives on another system (IdP, cloud control plane, mail gateway, peer host). |
| `NO_HOST_EVIDENCE` | Leaves no reliable host-side evidence (e.g. purely external reconnaissance). |

### 3.2 `implementation_status`

`IMPLEMENTED` · `PARTIAL` · `PLANNED` · `UNSUPPORTED` · `NOT_APPLICABLE`

Assignment rules, applied strictly:

- `NOT_APPLICABLE` is **only** for (a) platform mismatch — the technique's platforms include
  neither Windows nor Linux, so it cannot apply to a Windows/Linux host scan — or (b) revoked /
  deprecated objects. **Difficulty is never grounds for `NOT_APPLICABLE`.**
- `UNSUPPORTED` — in scope and applicable, but the evidence this tool can reach cannot support it
  (`MEMORY_ONLY`, `NETWORK_ONLY`, `OFF_HOST`, `NO_HOST_EVIDENCE`). Requires a written rationale.
- `PLANNED` — scannable in principle, not built yet. Requires a written rationale.
- `PARTIAL` — a check exists but fails some part of the per-check quality gate, or covers only
  part of the technique. **Excluded from Implementation coverage.**
- `IMPLEMENTED` — at least one check that passes the full per-check quality gate.

### 3.3 `validation_status`

`UNTESTED` · `FIXTURE_TESTED` · `LAB_VERIFIED`

`LAB_VERIFIED` requires the check to have **run against a real OS of the right kind and been
observed**. Only `LAB_VERIFIED` counts toward validation coverage; `FIXTURE_TESTED` is reported
separately and never summed in.

Because fixture quality varies, each check additionally records `fixture_provenance`:
`synthetic` (hand-built fixture) or `captured_real_host` (fixture captured from a real host by a
separate harness, then replayed through the check). `captured_real_host` is **still
`FIXTURE_TESTED`** — it does not upgrade to `LAB_VERIFIED`, because the collector did not run.
See D-004.

### 3.4 Scan outcomes

`DETECTED` · `NOT_DETECTED` · `INSUFFICIENT_DATA` · `PARTIAL_DATA` · `PERMISSION_DENIED` ·
`NOT_TESTED` · `ERROR`

Hard rule enforced in code and in tests: **missing logs or missing privileges must never produce
`NOT_DETECTED`.**

### 3.5 Finding levels

`observed_artifact` · `suspicious_indicator` · `corroborated` · `confirmed_test_detection`

No severity or confidence scores are emitted without documented criteria. Escalation above
`observed_artifact` requires a **second independent signal named in the check's documented
criteria** — not a heuristic hunch.

---

## 4. The six coverage metrics

> **Reconstructed, not quoted** — see §0 and D-001. Each is reported with an explicit numerator
> and denominator. They are never merged into a single score.

Denominator universes, all computed from the registry:

- `U_bundle` — every `attack-pattern` in the pinned bundle.
- `U_active` — `U_bundle` minus revoked and deprecated.
- `U_host` — `U_active` whose platforms include Windows **or** Linux. *(the in-scope universe)*
- `U_impl` — `U_host` whose tactic list intersects the four implementation-scope tactics.

| # | Metric | Numerator | Denominator |
|---|---|---|---|
| M1 | Registry completeness | techniques parsed with all required fields resolved | `U_bundle` |
| M2 | Classification completeness | in-scope techniques carrying both a testability class and an `implementation_status` | `U_host` |
| M3 | Implementation coverage | techniques with ≥1 gate-passing `IMPLEMENTED` check | `U_impl` |
| M4 | Partial coverage | techniques whose best check is `PARTIAL` | `U_impl` |
| M5 | Validation coverage | checks with `validation_status = LAB_VERIFIED` | all defined checks |
| M6 | Runtime data availability *(per scan)* | checks executed that returned a determinate outcome (`DETECTED`/`NOT_DETECTED`) | checks executed in that scan |

Rules:
- A technique in several tactics is counted **once** in every global denominator (tactics are
  stored as a list). M3 and M4 are additionally reported as **(technique, OS)** pairs, and broken
  out per tactic.
- M5 reports `FIXTURE_TESTED` and `UNTESTED` numerators over the same denominator, printed beside
  M5 but never added to it.
- Every printed percentage states its denominator inline.
- **Not one of the six, reported separately:** per-check precision = `actionable / reviewed`
  findings, computed by an offline command, always printing both raw numbers.

---

## 5. Architecture

```
Collector ──► in-memory data objects ──► Check ──► Finding ──► Report
```

Raw host data is **never persisted**. Only the evidence manifest is persisted: bounded excerpts
plus SHA-256 hashes.

### 5.1 Testability without a real host

- Filesystem access goes through a **configurable root path**, so a fixture tree substitutes for `/`.
- Windows registry, services, scheduled tasks and event logs are reached through **interfaces**
  that fake collectors implement.
- **Checks only ever see data objects.** No check touches the OS.

This is also what makes Windows check logic testable in this environment (see §7).

### 5.2 Check ↔ technique mapping

Many-to-many through an **explicit mapping table**. A generic check is never attached to an
unrelated technique; each mapping entry states why the check is evidence for that technique.

### 5.3 Layout

```
irscan/
  PLAN.md  DECISIONS.md  STATUS.md  README.md  NOTICE
  build/
    fetch_stix.py            # pinned download + hash verify
    sources.lock.json        # url, version, sha256, retrieved_at
    registry_builder/        # Python, build-time only
  data/
    registry/                # generated + bundled: JSON, CSV, meta, revoked/deprecated
    overlay/                 # per-check analyst documentation; testability overrides
    allowlist/               # default allowlist + example
  internal/
    model/ registry/ collect/ check/ mapping/ report/ safety/ module/
  cmd/irscan/
  testdata/fixtures/
  dist/
```

### 5.4 Implementation language

**Go** for runner and collectors (single static binary, cross-compiled Windows + Linux);
**Python** build-time only (registry builder) and for offline report post-processing. Prefer
native APIs and direct file/registry parsing over spawning child processes. See D-003 for why Go
survived the environment constraints.

---

## 6. Noise reduction

Three **separate** outputs, never mixed:

1. **Findings** — `suspicious_indicator` and above only.
2. **Inventory** — grouped `observed_artifact` rows.
3. **Coverage & Gaps** — every non-detected, insufficient, unsupported, untested and error row.

Rules:
- **One artifact is one finding.** Dedup key = host + artifact identity. A finding carries *all*
  matching technique IDs and checks.
- Telemetry checks **aggregate by entity** — count, time window, top sources, sample events —
  never one finding per event.
- Every finding is triage-ready: what and where; which documented criteria matched; benign
  explanations to rule out; next pivot; evidence reference with hash.
- Allowlist entries require scope (path + signature or hash), reason, owner and expiry.
  Suppressed items are **counted at the top of the report and listed in an appendix** — never
  silently hidden.
- Package ownership or a valid signature is **context only, never proof of benign**.
- Findings carry `analyst_disposition`: `actionable` / `benign` / `needs_more_data`.
- Known noisy areas — Run keys, services, scheduled tasks, systemd units, cron, Defender
  exclusions, log clearing — must have documented false-positive handling **before** their checks
  may count as `IMPLEMENTED`.

---

## 7. Validation strategy, and what this environment allows

Benign fixtures and controlled simulations only. **No real malware, no real credential-dumping
tools.** Credential checks record path, pattern type and metadata — **never the secret value**.

Every `IMPLEMENTED` check must have four test cases: **positive**, **negative** (reflecting common
legitimate software), **no-data**, **permission-denied**.

A **telemetry matrix** (Sysmon on/off, command-line auditing on/off, auditd on/off) proves the
`INSUFFICIENT_DATA` path works.

### Environment reality (measured, see STATUS.md for evidence)

| Capability | State |
|---|---|
| Host OS | Windows 11 Home Single Language, build 26200, **non-elevated** |
| **Smart App Control** | **ON** (`VerifiedAndReputablePolicyState = 1`) — blocks execution of *any* unsigned binary |
| Go toolchain on Windows | **Cannot run** — blocked by Application Control |
| Go toolchain in WSL2 | go1.27.2 linux/amd64, working |
| Linux for validation | WSL2 Kali GNU/Linux Rolling 2026.1, kernel 6.6.87.2, real systemd units + cron.d present |
| Network at build time | Reachable (STIX + Go downloads verified by hash) |

Therefore:

- **Linux checks → can reach `LAB_VERIFIED`**, run against the real WSL2 Kali filesystem through
  the configurable root. The WSL2 caveat (not a conventional production init environment) is
  stated per check.
- **Windows checks → capped at `FIXTURE_TESTED`.** No compiled `irscan.exe` can execute on this
  host, and disabling Smart App Control is out of scope, destructive to the user's security
  posture, and beyond my privileges. Recorded as a blocker.
- To make Windows fixtures as honest as possible, a **separate PowerShell capture harness** (not
  part of the shipped tool; PowerShell is signed and runs here) dumps *real* Windows artifact
  state from this host into the tool's data-object JSON format, which is then replayed through the
  real check logic on Linux. These fixtures are tagged `fixture_provenance:
  captured_real_host`. **They remain `FIXTURE_TESTED`.**
- Because checks are pure functions over data objects (§5.1), Windows **check logic** is fully
  unit-tested on Linux. Only the thin `//go:build windows` native-API collector shims are
  compile-and-vet-only.

Atomic Red Team reachability will be probed; if reachable, in-scope techniques with atomic tests
are recorded per OS. Otherwise fixtures are written by hand.

License, version, source and hash are recorded for every bundled dependency and dataset. ATT&CK
terms of use are checked and the required attribution is included (`NOTICE`).

---

## 8. Per-check quality gate

A check counts as `IMPLEMENTED` only if **all** of these hold. Anything less is `PARTIAL` or
`PLANNED` and is excluded from M3.

1. Overlay entry: behavior, artifacts, logic, false positives, limitations, references.
2. Collector privileges and failure modes documented.
3. All four test cases present and passing.
4. Escalation criteria documented.
5. False-positive handling documented.
6. An honest `validation_status`.

---

## 9. Phase plan (self-gated)

| Phase | Work | Gate |
|---|---|---|
| **0** | Registry builder: STIX → registry JSON + CSV | Two runs on same input produce identical output hashes; counts and denominators documented; every in-scope technique has a testability class; revoked/deprecated reported separately |
| **1** | Core models, collector interfaces, evidence manifest, 3 report types, cross-compiled binaries, 3–5 pilot checks incl. one telemetry check | Pilot checks pass all four test cases; Linux binary runs; Windows binary built + statically checked with the limit stated; per-check effort recorded |
| **2a** | Persistence — Linux and Windows | Per-check quality gate |
| **2b** | Defense Evasion — impair defenses, indicator removal, hidden artifacts, trust subversion | Per-check quality gate |
| **2c** | Credential Access — artifact-based and telemetry-based | Per-check quality gate |
| **2d** | Remaining in-scope techniques → `UNSUPPORTED` / `PLANNED` with rationale | Registry has **no unclassified technique** |
| **3** | Unified CLI, coverage reports, README with retrospective-scanning limitations, build + release notes | Commands backed by working code; reproducible build documented |
| **Review** | Independent adversarial review | Re-run suite; recompute all coverage from registry+results; no technique implemented without a passing gate; ATT&CK IDs/names/platforms spot-checked vs STIX; no `LAB_VERIFIED` that only ran on fixtures; read-only confirmed |

Priority within Phase 2, by strength of current-state evidence: **Persistence** first, then
**impair-defenses and indicator-removal**, then **credential artifacts**.

Depth over breadth. If budget runs out, stop at the last phase whose gate fully passed and report
what remains. Coverage numbers are never padded.

---

## 10. CLI surface (built only when code stands behind it)

```
irscan attack  --os <windows|linux> --technique <ID>... --tactic <name>...
irscan attack  --report coverage
irscan all     --scope <approved> --output <dir>
irscan <any>   --dry-run        # lists collectors that would run + privileges each needs
irscan malware                  # registered, explicitly NOT IMPLEMENTED
```

---

## 11. Hard stops (recorded, skipped, reported — never worked around)

- Credentials or access to real hosts.
- Running real malware or real credential-dumping tools.
- Destructive action outside the sandbox.
- Bypassing a network restriction — **or a host security control**, which is why Smart App
  Control is treated as a blocker rather than an obstacle to defeat.

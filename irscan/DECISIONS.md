# DECISIONS.md

Every non-trivial decision: what was decided, what else was considered, why, and **what would
change the decision**. Append-only; entries are not rewritten, they are superseded.

Legend: **D-nnn** decision · **C-nnn** spec/prompt conflict · **B-nnn** blocker

---

## D-001 — The authoritative spec document is missing; "six coverage metrics" are reconstructed

**Decision.** Proceed using the task prompt's restatement of the spec as the working
specification. Reconstruct the "six coverage metrics" the prompt refers to but does not
enumerate, label the reconstruction clearly in `PLAN.md` §4 and in every generated report, and
treat it as an open item.

**Context.** The prompt names an attached spec, *"MANDATORY MODULE: MITRE ATT&CK HOST ARTIFACT &
TECHNIQUE SCANNER"*, and declares it the source of truth. It was not present in this session.
Searched: `C:\Users\thong\Downloads` (full listing), the project `.claude` directory, and a
content search for `MANDATORY MODULE`, `HOST ARTIFACT & TECHNIQUE SCANNER` and `irscan` across
the working tree — no match. `svanm_ir_toolkit.zip` was opened and is unrelated.

**Alternatives considered.**
- *Stop and ask for the spec.* Rejected: the prompt forbids asking questions and the hard-stop
  list does not include a missing document. The prompt's restatement is detailed enough to build
  against.
- *Invent six metrics and present them as the spec's.* Rejected outright — that would be a
  fabrication of the kind the honesty rules prohibit.

**Why this is safe.** The prompt's restatement covers scope, data contracts, noise reduction,
validation rules, the phase plan and the per-check gate. The only genuinely missing item is the
*enumeration* of the six metrics; their required *properties* are specified (separate, each with
numerator and denominator, never merged).

**What would change it.** Supply of the real spec. Then §4 of `PLAN.md` and the coverage report
headers must be re-checked against it and corrected.

---

## C-001 / D-002 — ATT&CK v20.0 removed the tactic name "Defense Evasion"

**Conflict.** The spec scopes implementation to "Persistence, Defense Evasion and Credential
Access". In the pinned data there is **no tactic named Defense Evasion**.

**Verified facts** (two independent sources):
1. Pinned bundle `enterprise-attack-20.0.json`, `x-mitre-tactic` objects: `TA0005` →
   `x_mitre_shortname: stealth`, name **"Stealth"**; `TA0112` → `defense-impairment`, name
   **"Defense Impairment"**. 15 tactics total.
2. Live official site <https://attack.mitre.org/tactics/enterprise/> lists `TA0005 Stealth` and
   `TA0112 Defense Impairment`, and contains no "Defense Evasion" entry.
   Retrieved 2026-10-14.

Also verified: `T1562` "Impair Defenses" is not an active technique in v20.0. The v20 release
notes <https://attack.mitre.org/resources/updates/updates-october-2026/> list
`T1685.007 Disable or Modify Tools: Impair Autonomous Defenses` as new, corroborating that
`T1685` is the live parent. `T1562`'s exact STIX status (revoked vs deprecated, and its
`revoked-by` target if any) is resolved by the registry builder and published in
`data/registry/revoked_deprecated.csv` rather than asserted here.

**Decision.** Resolve spec "Defense Evasion" to the **union** of v20.0 `stealth` (TA0005) and
`defense-impairment` (TA0112). Implementation scope is therefore four tactic shortnames:
`persistence`, `stealth`, `defense-impairment`, `credential-access`.

**Alternatives considered.**
- *Pin ATT&CK v19.2 instead,* where `TA0005` is still "Defense Evasion" and `x_mitre_detection`
  text still exists on techniques. Rejected: the prompt requires the official STIX data and
  recording its version; deliberately pinning a superseded release to preserve a label the
  framework has retired would misrepresent current ATT&CK. Kept as a documented fallback — the
  builder is version-agnostic and `build/sources.lock.json` can pin v19.2 if v20.0 data problems
  emerge.
- *Scope to `stealth` only.* Rejected: it would silently drop trust subversion (`T1553.*`) and
  impair-defenses (`T1685/T1686/T1690`), which the spec explicitly names as focus areas.

**Why the union.** It is a widening, never a narrowing: every technique in scope under the
pre-v20 "Defense Evasion" remains in scope. Under-scoping would hide techniques the spec demands.

**What would change it.** The real spec pinning a specific ATT&CK version; or MITRE revising the
tactic structure again.

---

## D-003 — Stack stays Go, built inside WSL2, despite Application Control

**Decision.** Go for the runner and collectors (single static binary, cross-compiled for Windows
and Linux); Python for build-time tooling only. The Go toolchain runs **inside WSL2**, not on the
Windows host.

**Context — measured, not assumed.**
- `go` was not installed. Downloaded `go1.27.2.windows-amd64.zip`, SHA-256 verified against
  go.dev metadata (`1314008898bd…fe04f`, matched). Extraction succeeded; **execution failed**:
  `An Application Control policy has blocked this file`.
- Root cause identified: `HKLM\SYSTEM\CurrentControlSet\Control\CI\Policy` →
  `VerifiedAndReputablePolicyState = 1`, i.e. **Smart App Control is ON**. `go.exe` is
  `NotSigned`. Clearing Mark-of-the-Web with `Unblock-File` succeeded and did **not** help,
  confirming the block is signature/reputation-based, not zone-based.
- `go1.27.2.linux-amd64.tar.gz` installed into WSL2 Kali, SHA-256 verified
  (`ecbadb99…45fe5`, matched): `go version go1.27.2 linux/amd64` runs. drvfs write to the repo
  path confirmed working.

**Alternatives considered.**
- *Disable Smart App Control.* **Rejected as a hard stop.** It requires elevation I do not have,
  it is a one-way change on Windows 11, and weakening a user's host security control to make my
  own build artifact runnable is exactly the sort of action the autonomy rules forbid.
- *Switch the runner to Python.* Would allow running collectors natively on this Windows host and
  thus genuine Windows lab verification — the one real advantage, and it is significant.
  **Rejected** because it breaks the dominant deployment constraint: "no installation, no runtime
  dependencies on the target". A source deployment needs an interpreter on the customer server; a
  PyInstaller bundle is itself unsigned and so would be blocked on any Application-Control host
  anyway, gaining nothing in portability while losing the single-static-binary property.
- *Switch to C#/.NET single-file.* Rejected: same unsigned-binary problem, and a heavier runtime
  story on Linux targets.

**Consequences, accepted and recorded.**
- Linux checks can reach `LAB_VERIFIED` (real WSL2 Kali filesystem).
- **Windows checks are capped at `FIXTURE_TESTED`** — see B-001.
- Architecture is adapted to recover as much as possible: checks are pure functions over data
  objects, so Windows **check logic** is unit-tested on Linux; only thin `//go:build windows`
  native-API collector shims are compile-and-vet-only.

**What would change it.** An available signed build, a Windows host without Application Control,
or a real Windows VM I am authorised to run — any of which would let Windows checks be lab
verified and would not change the language choice.

---

## D-004 — Fixtures captured from a real host stay `FIXTURE_TESTED`

**Decision.** Add a `fixture_provenance` field (`synthetic` | `captured_real_host`) to each
check's validation record. A fixture captured from a real Windows host by a separate PowerShell
harness and replayed through the real check logic is tagged `captured_real_host` but **remains
`FIXTURE_TESTED`**. It does **not** count toward M5 validation coverage.

**Rationale.** `LAB_VERIFIED` is defined as the check having *run against a real OS of the right
kind and been observed*. With captured fixtures the **collector did not run** — so the collector's
privilege handling, API behaviour, error paths and timeouts are all unexercised. Calling that
`LAB_VERIFIED` would inflate validation coverage with untested collection code, which the prompt
explicitly prohibits.

**Alternatives considered.**
- *Count captured-real-host as `LAB_VERIFIED`.* Rejected: dishonest, and the review pass is
  required to catch exactly this.
- *Add a fifth status, e.g. `REPLAY_VERIFIED`.* Rejected: the prompt fixes the enum to three
  values. A provenance sub-field conveys the same information without redefining the contract.

**What would change it.** Nothing short of running the compiled collector on a real Windows host.

---

## D-005 — Pin ATT&CK v20.0, hash-locked, with a version-agnostic builder

**Decision.** Pin **ATT&CK Enterprise v20.0** from the official versioned STIX 2.1 distribution
`mitre-attack/attack-stix-data`.

- URL: `https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-20.0.json`
- Retrieved: 2026-10-14 (UTC offset recorded in `build/sources.lock.json`)
- Size: 55,271,014 bytes · SHA-256 `81113ba98afa2928f3dcff62022539f7ce30c315c32e14422f11ff95ce534352`
- Collection object reports `x_mitre_version: 20.0`, `modified: 2026-10-13T17:53:10.145Z`

**Alternatives considered.**
- *`mitre/cti` repo.* Rejected: STIX 2.0 and superseded by `attack-stix-data`, which is the
  distribution MITRE versions and publishes an `index.json` for.
- *Track `master`/latest unpinned.* Rejected: destroys reproducibility, which is the Phase 0 gate.
- *v19.2* (released 2026-08-05). Considered because v20.0 is only one day old at pin time and
  because v19.x still carries `x_mitre_detection` text. Rejected as primary — see C-001 — but
  retained as a supported alternate pin.

**Builder must be version-agnostic.** v20.0 removed `x_mitre_detection`, `x_mitre_data_sources`,
`x_mitre_defense_bypassed` and `x_mitre_permissions_required` from `attack-pattern` objects
(measured: 0 of 867 carry any of them) and introduced `x-mitre-detection-strategy` (705) and
`x-mitre-analytic` (1,770) objects carrying `x_mitre_log_source_references`. The builder reads
whichever representation is present so a v19 pin still works.

**What would change it.** A newer ATT&CK release, a data defect found in v20.0, or the real spec
naming a version.

---

## D-006 — Testability class is rule-derived, with a small reviewed override table

**Decision.** Compute each technique's testability class deterministically from STIX — resolved
detection strategies / analytics and their `x_mitre_log_sources`, plus platforms and tactic — and
allow a small, explicit, documented override table in
`data/overlay/testability_overrides.yaml` for cases the rules get wrong.

**Rationale.** The prompt requires the registry to be generated, never hand-typed, but testability
is an analytic judgement that cannot be read directly out of STIX. Rules keep it reproducible
(Phase 0 gate requires byte-identical reruns); the override table keeps it correctable and
auditable. Every override records a reason, so no classification is anonymous.

**Alternatives considered.**
- *Hand-classify all ~700 in-scope techniques.* Rejected: unreviewable, non-reproducible, and the
  prompt forbids hand-typing the registry.
- *Rules only, no overrides.* Rejected: guarantees known-wrong classifications with no remedy,
  which would push techniques toward false `UNSUPPORTED`/`NOT_APPLICABLE` labels.

**What would change it.** If overrides grow past roughly 10% of in-scope techniques, the rules are
wrong and should be rewritten rather than patched.

---

## D-007 — No malware module exists; build the interface, not a scanner

**Decision.** Build the unified CLI shell and a module interface. Register `irscan malware` as a
command that reports **NOT IMPLEMENTED** and exits non-zero. Do not write a malware scanner.

**Context.** Repository inspected. No malware module present. `svanm_ir_toolkit.zip` contains only
`README.md`, `services.example.json`, `ir_tool.py` and is unrelated to malware scanning.

**Alternatives considered.**
- *Omit the command entirely.* Rejected: the prompt explicitly requires a clearly marked
  not-implemented malware command.
- *Wrap a signature engine / hash-reputation lookup and call it malware scanning.* Rejected: the
  prompt forbids inventing one, and it would need network access at runtime, violating the
  deployment model.

**What would change it.** A real malware module appearing in the repository — it would then be
integrated through the module interface rather than reimplemented.

---

## B-001 — BLOCKER: no Windows runtime verification on this host

**Blocker.** Smart App Control is ON and I am not elevated. No unsigned binary executes. The
compiled `irscan.exe` therefore cannot be run, so **no Windows check can legitimately reach
`LAB_VERIFIED` in this session**.

**Not worked around.** Disabling the control would be bypassing a host security control — on the
prompt's hard-stop list.

**Mitigations applied** (none of which claim lab verification):
- Windows binary is cross-compiled and statically checked (`go build`, `go vet`); the limit is
  stated wherever the binary is mentioned.
- Windows check logic is unit-tested on Linux via the data-object abstraction.
- Real Windows artifact state is captured by a signed-PowerShell harness into fixtures tagged
  `captured_real_host` (D-004).

**Reported in.** `STATUS.md`, the final report, and the README limitations section.

**What would clear it.** A Windows host without Application Control, a code-signing certificate,
or an authorised Windows VM.

---

## B-002 — BLOCKER: no real Windows Server, no domain, no elevation

**Blocker.** Checks that need elevation (Security event log, `HKLM\SECURITY`, service ACLs,
`SeBackupPrivilege` paths) or a domain controller (`T1003.003` NTDS, `T1003.006` DCSync,
`T1556.001`) cannot be exercised even as privileged collections here. The session has no
credentials and no authorised access to real hosts.

**Consequence.** Such checks are built and fixture-tested only, and their collectors'
`PERMISSION_DENIED` paths are tested by *running unprivileged on this host*, which is a genuine
negative test of the permission path — recorded as such, and not as coverage of the detection.

**Not worked around.** No credential acquisition, no privilege escalation attempts.

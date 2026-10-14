# STATUS.md

Updated after every phase. States what was done, what was **verified** (with evidence and the
environment it was verified in), what failed, and what remains.

**Reading rule:** "verified" here always names an environment. Anything not run is called
unverified, never implied to work.

---

## Environment of record

Everything below was executed in this environment unless stated otherwise.

| | |
|---|---|
| Host OS | Microsoft Windows 11 Home Single Language, build 26200 |
| Privilege | `KAIZ3N\thong`, **not elevated** (`IsInRole(Administrator) = False`) |
| Smart App Control | **ON** — `HKLM\SYSTEM\CurrentControlSet\Control\CI\Policy\VerifiedAndReputablePolicyState = 1` |
| Linux | WSL2 **Kali GNU/Linux Rolling 2026.1**, kernel `6.6.87.2-microsoft-standard-WSL2`, user `kali` (uid 1000, in `sudo` group) |
| Go | `go1.27.2 linux/amd64`, installed at `/home/kali/toolchain/go` **inside WSL2** |
| Python | CPython 3.14.5 (Windows), stdlib only |
| Network | Available at build time; `raw.githubusercontent.com` and `go.dev` reachable |
| git | 2.x, repository initialised at `C:\Users\thong\Downloads\irscan` |

---

## Phase 0 — ATT&CK registry builder — **GATE PASSED**

### What was done

- `build/fetch_stix.py` — fetches the pinned ATT&CK STIX bundle, verifies SHA-256 and size
  against `build/sources.lock.json`, and treats a mismatch as fatal. Records the required MITRE
  attribution. Has `--verify-only` and an explicit `--repin`; on network failure it prints the
  path at which a locally supplied bundle may be placed rather than silently working around the
  block.
- `build/sources.lock.json` — pins ATT&CK Enterprise **v20.0**, URL, size, SHA-256,
  `retrieved_at`, licence and required attribution; also records both Go toolchain archive
  hashes and an intentionally empty runtime-dependency list.
- `build/registry_builder/` — stdlib-only package:
  `stixload.py` (bundle indexing, relationship resolution), `classify.py` (testability rules +
  baseline status), `scope.py` (scope constants, each citing its DECISIONS.md entry),
  `emit.py` (byte-deterministic writers), `build.py` (orchestration + all denominators).
- `build/build_registry.py` — CLI with `--check-determinism` implementing the Phase 0 gate.
- `build/query_registry.py` — reviewer utility so the review pass can recompute and spot-check
  from the built artefact rather than trusting the build log.
- `data/overlay/log_source_taxonomy.json` — maps ATT&CK v20 log-source names to evidence
  categories. Key set enumerated **mechanically** from the bundle (399 distinct names, 146
  prefixes), not invented.
- `data/overlay/technique_families.json` — curated artifact / memory / network family signals,
  keyed by top-level technique ID, each with a stated reason.
- `data/overlay/testability_overrides.json` — 2 reviewed overrides, each with a reason.
- `NOTICE` — MITRE attribution, licence terms, MITRE's own coverage disclaimer, toolchain hashes.

### Generated and bundled (`data/registry/`)

| File | Rows | SHA-256 |
|---|---|---|
| `attack_registry.json` | 867 techniques | `c7be7ff4f8d690ea6cbabbab2eacdbf10680a8c073e6049d9c585ee3b17d4c83` |
| `attack_registry.csv` | 867 + header | `098c56f7599514d4b354f027c87f680a5f206f27f5e0bcc04b9369a3c94cb2c0` |
| `revoked_deprecated.csv` | 161 + header | `4e44cd3f0c068327a65e3c47f5c4b331023fc49f62a967e9abd3798d3b594154` |
| `classification_audit.csv` | 511 + header | `c6cce454cd41d5a340a6318b68ebce4d7a81518eafe224c14a4c0963189fddc9` |
| `registry_meta.json` | — | `99c6a9c5bfbdadb4cfc57772bcc06066259f6ffa121addb5b9a68bd3d945d517` |

`registry_meta.json` records the hashes of the other four outputs; its own hash is listed here
because a file cannot contain its own digest. Row counts independently confirm the
denominators: 867 = `U_bundle`, 161 = inactive, 511 = `U_host`.

### Gate evidence — all four criteria

Command: `python build/build_registry.py --check-determinism` (Windows, CPython 3.14.5).

1. **Two runs on the same input give identical output hashes** — `GATE: PASS - two runs
   byte-identical`. All five outputs matched across two builds into separate temp directories.
   Achieved by: `sort_keys=True`, fixed `\n` line terminators, UTF-8 without BOM, and **no
   wall-clock timestamp anywhere in the outputs** — the only recorded time is the pinned
   source's `retrieved_at`, which is an input.
2. **Counts and denominators documented** — computed in one place (`build._counts`) and written
   to `registry_meta.json`:

   | Universe | Count |
   |---|---|
   | `U_bundle` — all attack-patterns | **867** |
   | `U_active` — minus revoked/deprecated | **706** |
   | `U_host` — active ∧ (Windows ∨ Linux) | **511** (179 top-level, 332 sub) |
   | `U_impl` — `U_host` ∧ 4 scope tactics | **296** (69 top-level, 227 sub) |
   | `U_impl` as (technique, OS) pairs | **436** (windows 269, linux 167) |

   Per-tactic `U_impl` (a technique in two scope tactics counts in both here, but **once** in
   `U_impl`): stealth 141, persistence 91, credential-access 58, defense-impairment 35.
3. **Every in-scope technique has a testability class** — `UNDETERMINED = 0`,
   `U_host_unclassified = 0`. Distribution over `U_host = 511`: MIXED 203 (39.7%),
   HOST_TELEMETRY 304 (59.5%), HOST_ARTIFACT 1 (0.2%), OFF_HOST 3 (0.6%).
4. **Revoked and deprecated reported separately** — 149 revoked + 12 deprecated + 0 both = 161
   rows in `revoked_deprecated.csv`, excluded from every live denominator, retained in the
   registry for traceability with their `revoked_by` target resolved.

Data quality: **0 parse anomalies, 0 unclassified log sources.**

### Defects found and fixed during Phase 0

1. **Classifier over-attribution (serious).** The first build classified **492 of 511 (96.3%)**
   in-scope techniques as `MIXED` — a meaningless result. Cause: `detection_for()` expanded each
   referenced data component's *entire* `x_mitre_log_sources` list, so a component like "File
   Modification" injected dozens of cross-platform log sources into techniques whose analytics
   never cite them. Fix: use only the analytic's own `x_mitre_log_source_references`; keep the
   component *name* for context. Result: MIXED fell to 203 (39.7%) with
   HOST_TELEMETRY at 304. Rationale is recorded in a code comment at the fix site.
2. **False parse anomalies.** 16 sub-techniques were flagged as missing their `subtechnique-of`
   relationship. All 16 are revoked (all 13 `T1562.*`, plus `T1053.001`, `T1070.001/.002`,
   `T1547.011`); ATT&CK deliberately drops that relationship on revocation. Fix: derive the
   parent from the ID as a fallback, record **how** it was resolved in `parent_id_source`, and
   flag an anomaly only for *active* sub-techniques. Anomalies: 16 → 0.
3. **Three unclassified log sources** (`FirmwareLogs:Update` ×116, `network:runtime` ×116,
   `network:auth` ×55) — added `firmwarelogs` and `network` prefixes. Also reclassified the `fs:`
   prefix from `artifact` to `generic_telemetry`: `fs:fileevents`/`fs:fsusage` are file-event
   telemetry, not durable state. Unclassified: 3 → 0.
4. **Two `UNDETERMINED` techniques** — `T1698` / `T1699` (Indirect / Direct Prompt Injection).
   ATT&CK v20.0 ships **no** detection strategy or log source for either, so no rule could fire.
   Resolved with reviewed overrides to `OFF_HOST` (evidence is the LLM application's own
   prompt/tool-call records, not host state), each with a written reason. Both are tactic
   `execution`, so outside implementation scope regardless.

### Verified facts established (cited, not assumed)

- **ATT&CK v20.0 has no "Defense Evasion" tactic.** `TA0005` is **"Stealth"**; `TA0112`
  **"Defense Impairment"** is new. Confirmed in the pinned bundle's `x-mitre-tactic` objects
  *and* independently on <https://attack.mitre.org/tactics/enterprise/> (retrieved 2026-10-14),
  which lists 15 tactics and no "Defense Evasion". Scope consequence recorded as C-001/D-002.
- **`T1562` "Impair Defenses" and all 13 of its sub-techniques are revoked**, each with an
  explicit `revoked-by` target (`T1562` → `T1685` Disable or Modify Tools; `T1562.002` →
  `T1685.001`; `T1562.004` → `T1686`; `T1562.009` → `T1688`; `T1562.010` → `T1689`;
  `T1562.003` → `T1690`; and so on). Read from the bundle's `revoked-by` relationships.
- **ATT&CK v20.0 dropped `x_mitre_detection`, `x_mitre_data_sources`,
  `x_mitre_defense_bypassed` and `x_mitre_permissions_required` from `attack-pattern` objects**
  — measured: 0 of 867 carry any of them. Detection content moved to 705
  `x-mitre-detection-strategy` and 1,770 `x-mitre-analytic` objects. The builder reads either
  representation, so a v19 pin still works.
- 508 of the 511 in-scope techniques have at least one detection strategy.

### What is NOT yet true

- No scanner exists yet. The registry's `baseline_implementation_status` is `PLANNED` for 508
  in-scope techniques and `UNSUPPORTED` for 3. **Nothing is `IMPLEMENTED`** — by construction,
  the registry builder cannot emit `IMPLEMENTED` or `PARTIAL` (D-009); only the Go check
  inventory can, and only through the per-check quality gate.
- Coverage metrics M3–M6 are therefore all `0 / 296` or undefined at this point. Not padded.

---

## Phase 1 — Skeleton and pilot — **GATE PASSED**

### What was built

~9,700 lines of Go (36 files, standard library only) plus ~1,850 lines of build-time Python.

| Package | Lines | Role |
|---|---|---|
| `internal/model` | 604 | Data contracts; **enforces** "missing data is never NOT_DETECTED" |
| `internal/safety` | 199 | Limits, budgets, timeouts, write-confinement guard, network-FS detection |
| `internal/collect` | 2,492 | Collector interfaces, root-relocatable FS, Linux collectors, Windows registry, fakes |
| `internal/check` | 1,011 | Check interface, Env, quality gate, mapping validator, evidence helpers |
| `internal/checks` | 3,087 | The five pilot checks + the gate/invariant test suite |
| `internal/registry` | 210 | Embedded ATT&CK registry loader |
| `internal/coverage` | 414 | The six metrics |
| `internal/report` | 594 | Three separate reports + evidence and scan manifests |
| `internal/module` | 390 | Module interface, attack module, not-implemented malware module |
| `internal/allowlist` | 167 | Scoped, expiring, non-silent suppression |
| `cmd/irscan` | 537 | CLI |

### The five pilot checks

| Check | ATT&CK | OS | Kind | Validation |
|---|---|---|---|---|
| `LNX-PERSIST-SYSTEMD-001` | T1543.002, T1543, T1053.006(partial) | linux | artifact | **LAB_VERIFIED** |
| `LNX-PERSIST-CRON-001` | T1053.003, T1053 | linux | artifact | **LAB_VERIFIED** |
| `LNX-PERSIST-SSHKEY-001` | T1098.004, T1098 | linux | artifact | **LAB_VERIFIED** |
| `LNX-DEFIMP-AUDITD-001` | T1685.004, T1685 | linux | **telemetry** | **LAB_VERIFIED** |
| `WIN-PERSIST-RUNKEY-001` | T1547.001, T1547, T1112(partial) | windows | artifact | FIXTURE_TESTED (capped by B-001) |

### Gate evidence

1. **All pilot checks pass all four test cases.** 5 checks × 4 cases = 20 case assertions, plus
   7 supporting tests. `go test ./...` → `ok irscan/internal/checks`. The gate is
   **machine-verified**: each check supplies its four cases as data and a generic runner
   executes them, so a check cannot self-certify. `check.EvaluateGate` additionally verifies
   overlay completeness, documented privileges and failure modes, escalation criteria,
   false-positive handling and an honest validation status.
2. **The Linux binary runs.** `dist/irscan-linux-amd64` executed against the **live** WSL2
   Kali root filesystem, unprivileged (uid 1000), scan_id
   `irscan-20261014T044834Z-7b0a0cd0`. Result: 441 real systemd units and 89 real cron
   entries inventoried, 0 false positives, outcomes `NOT_DETECTED=1, PARTIAL_DATA=2,
   INSUFFICIENT_DATA=1`.
3. **The Windows binary is built and statically checked only.** `GOOS=windows go build` and
   `GOOS=windows go vet` both pass; `dist/irscan-windows-amd64.exe` is produced.
   **It has never been executed** — Smart App Control blocks unsigned binaries on the only
   Windows host available (B-001). This limit is stated in the README, in `M5`'s note, and
   enforced by `TestWindowsChecksAreNotLabVerified`.
4. **Effort per pilot check** — measured as source size and defects found. Wall-clock
   authoring time was *not* instrumented, so none is claimed.

   | Check | impl. lines | defects found by its own fixtures / lab run |
   |---|---|---|
   | systemd | ~380 (in `persist_lnx.go`, 728 total with cron) | 2 (symlink mode bits; masked units) |
   | cron | ~350 (same file) | 2 (whole-command `/tmp` match; `perl -e` pattern) |
   | sshkey | 349 | 1 (denied-vs-absent in home directories) |
   | auditd | 581 | 1 (criteria evaluated against unread data) |
   | runkey | 530 | 1 (Startup folder is itself under `%ProgramData%`) |

   Shared: `common.go` 315, test suite 584, fixtures 50 files.

### Defects found and fixed in Phase 1

Every one of these was found by a test case or the real-host run, not by inspection.

1. **Windows check silently excluded from the build (most serious).** The check lived in
   `internal/checks/persist_windows.go`; Go treats a `_windows.go` filename suffix as an
   implicit `GOOS` build constraint, so the file was dropped from the Linux build, the check
   was never registered, and the gate suite passed while testing **4 of 5** checks. Nothing
   errored. Fixed by renaming to `persist_win.go`, and locked in by two new tests:
   `TestExpectedChecksAreRegistered` (asserts the inventory by name) and
   `TestNoAccidentalPlatformConstrainedCheckFiles` (rejects the filename pattern).
2. **False positives manufactured from unreadable data.** The auditd check concluded
   "configured but no rules" when the truth was "`/etc/audit` is mode 0750 and this scan is
   unprivileged". Caught by the permission-denied fixture. Fixed by having the collector
   distinguish *read it, found nothing* from *could not read it*
   (`ConfigReadable`, `RuleFilesRead`, `LogStateKnown`, `PermissionError`) and gating every
   criterion on it.
3. **43 false positives on a clean host: symlink permission bits.** A symlink's own mode is
   always `lrwxrwxrwx`, so the world-writable criterion fired on every symlinked unit.
4. **6 false positives on a clean host: masked units.** `/etc/systemd/system/X.service ->
   /dev/null` is systemd's standard way to **disable** a unit — the opposite of persistence —
   and was being reported as vendor shadowing.
5. **1 false positive on a clean host: stock Debian `apt-compat`.** `eval $(apt-config shell
   ...)` matched the encoded-execution pattern. Narrowed to `eval $(curl|wget|fetch ...)`.
6. **Negative-fixture precision bugs, caught before the lab run.** Matching `/tmp` anywhere
   in a command flagged the benign `curl -s -o /tmp/metrics.json` monitoring pattern; and
   `perl -e 'sleep int(rand(43200))'` (the real certbot cron line) matched the interpreter
   clause. Both narrowed to inspect the *executable*, not the whole command string.
7. **Misleading `PARTIAL_DATA` reason.** The report said "truncated by safety limit" when the
   real cause was a permission denial. Split into distinct `Truncated` and `Incomplete`
   source states so the analyst is told the true cause of a visibility gap.
8. **`Exists()` collapsed denied and absent.** An unprivileged scan of root's `0700` home
   reported "no SSH keys" instead of "could not look". Now uses `Stat` and branches on
   `ErrPermission`.

   False positives on the live host: **44 → 0**, with every fixture positive still detecting.

### Observed real-host behaviour (the point of the lab run)

| Check | Outcome | Why — exactly as reported by the tool |
|---|---|---|
| `LNX-PERSIST-SYSTEMD-001` | `NOT_DETECTED` | 441 units read in full; nothing matched |
| `LNX-PERSIST-CRON-001` | `PARTIAL_DATA` | "partially readable: cron tables" — genuine denial on `/var/spool/cron/crontabs` |
| `LNX-PERSIST-SSHKEY-001` | `PARTIAL_DATA` | `/etc/shadow` and `/root/.ssh` unreadable unprivileged |
| `LNX-DEFIMP-AUDITD-001` | `INSUFFICIENT_DATA` | audit subsystem genuinely absent — **real** confirmation of the no-data path |

M6 for that scan: **1/4 = 25.0%** (denominator: checks executed). Three of four checks could
not give a determinate answer on a stock unprivileged host — which is the honest picture of
what retrospective host scanning sees, and precisely what the metric exists to show.

### Coverage at end of Phase 1 (computed by the tool, not by hand)

| Metric | Value |
|---|---|
| M1 registry completeness | 867/867 = 100.0% (U_bundle = 867) |
| M2 classification completeness | 511/511 = 100.0% (U_host = 511) |
| M3 implementation coverage | **10/296 = 3.4%** (U_impl = 296) |
| M4 partial coverage | 2/296 = 0.7% (U_impl = 296) |
| M5 validation coverage (LAB_VERIFIED) | 4/5 = 80.0% — beside it, not added in: FIXTURE_TESTED 1/5, UNTESTED 0/5 |
| M6 runtime data availability | per scan; 1/4 on the run above |

M3 per tactic: persistence 8/91, defense-impairment 2/35, stealth 0/141, credential-access
0/58. These numbers are low and are not padded.

### Built artefacts

`dist/irscan-linux-amd64` and `dist/irscan-windows-amd64.exe`, built reproducibly with
`-trimpath` from Go 1.27.2 in WSL2; hashes in `dist/SHA256SUMS`. The Windows binary is
**unverified at runtime**.

---

## Phase 2a — Persistence (Linux and Windows) — **GATE PASSED**

Six checks added, taking the inventory to **11**. Every one passes the full per-check quality
gate (`check.EvaluateGate` plus its four executed test cases).

| Check | ATT&CK (non-partial) | OS | Validation |
|---|---|---|---|
| `LNX-PERSIST-SHELLRC-001` | T1546.004, T1546 | linux | **LAB_VERIFIED** |
| `LNX-PERSIST-RCSCRIPT-001` | T1037.004, T1037 | linux | **LAB_VERIFIED** |
| `LNX-PERSIST-ACCOUNT-001` | T1136.001, T1136, T1098.007, T1098 (T1078.003 partial) | linux | **LAB_VERIFIED** |
| `WIN-PERSIST-SERVICE-001` | T1543.003, T1543 | windows | FIXTURE_TESTED (B-001) |
| `WIN-PERSIST-SCHTASK-001` | T1053.005, T1053 | windows | FIXTURE_TESTED (B-001) |
| `WIN-PERSIST-REGLOADPOINT-001` | T1547.004, T1547.002, T1547.005, T1547, T1546.010, T1546.012, T1546, T1556.002 | windows | FIXTURE_TESTED (B-001) |

Two reusable collectors were added, both deliberately derived from the registry and
filesystem interfaces rather than from new native APIs — which is what keeps them
fixture-testable under B-001:

- `collect.WindowsServices` reads `HKLM\SYSTEM\CurrentControlSet\Services`, resolves
  `ImagePath` quoting and the `\??\` / `\SystemRoot\` prefixes, and **also reads
  `Parameters\ServiceDll`** — the svchost service-DLL hijack an ImagePath-only review misses.
- `collect.WindowsScheduledTasks` parses Task Scheduler XML, decoding UTF-16LE/BE and UTF-8.

`WIN-PERSIST-REGLOADPOINT-001` covers six sub-techniques in one check because they are one
evidence shape (a named registry value compared against a documented default). Attribution
is **per artifact**: the `Userinit` finding cites T1547.004 only, the `Notification Packages`
finding cites T1556.002 only, the IFEO finding cites T1546.012 only. The positive fixture
asserts all three independently.

### Defects found and fixed in Phase 2a

1. **Microsoft's own scheduled tasks are hidden AND run as SYSTEM.** `TASK-C3` as first
   written fired on `\Microsoft\Windows\UpdateOrchestrator\Schedule Scan` and
   `\Microsoft\Windows\Defrag\ScheduledDefrag` — i.e. on every Windows host. Caught by the
   negative fixture. The criterion now additionally requires the task to be **outside** the
   `\Microsoft\` namespace, and the Limitations section states plainly that this is noise
   reduction, not a boundary: a task planted under `\Microsoft\Windows\` evades it.
2. **A real false positive on the live host: Debian's `postgres` account.** The postgresql
   package creates `postgres` with `/bin/bash`, so `ACCT-C3` fired on every PostgreSQL host.
   Fixed with a documented known-shell-bearing-accounts list that applies **only** when the
   account is not uid 0 and not in a privileged group, so it cannot launder a backdoor named
   after a service; the account still appears in Inventory.
3. **Go's XML decoder rejected real Task Scheduler files.** Task XML declares
   `encoding="UTF-16"`, which `encoding/xml` refuses without a `CharsetReader` even after the
   bytes have been converted. Fixed with a pass-through `CharsetReader`. Without this, every
   real task file would have been reported as a parse error.
4. **Scheduled-task criterion inspected only `<Command>`.** The usual shape is
   `Command=powershell.exe` with the staged payload path in `<Arguments>`, so the
   transient-directory criterion missed it. Now evaluated against the full action, while
   still only descending into arguments for known interpreters so a task that merely *writes*
   to `%TEMP%` does not match (that case is in the negative fixture).
5. **The read-only guard test was too crude.** It banned the substring `lsass`, and so failed
   on documentation prose explaining why LSA registry load points matter. Naming a process in
   a comment is not reading its memory; the guard now bans the actual APIs
   (`OpenProcess`, `ReadProcessMemory`, `MiniDumpWriteDump`, `process_vm_readv`, `ptrace`,
   `/proc/self/mem`).

### Real-host validation (live WSL2 Kali, unprivileged)

`scan_id irscan-20261014T051011Z-46209192`, 7 Linux checks executed, **598 inventory items,
0 findings, 0 false positives**. Outcomes: `NOT_DETECTED=2, PARTIAL_DATA=4,
INSUFFICIENT_DATA=1`; M6 = 2/7 = 28.6%. The four `PARTIAL_DATA` results are genuine and
correctly explained (`/etc/shadow`, `/root/.ssh`, `/var/spool/cron/crontabs` and other users'
dotfiles are unreadable without root).

### Coverage after Phase 2a

| Metric | Phase 1 | Phase 2a |
|---|---|---|
| M3 implementation coverage | 10/296 = 3.4% | **25/296 = 8.4%** |
| M4 partial coverage | 2/296 | 3/296 = 1.0% |
| M5 validation (LAB_VERIFIED) | 4/5 = 80.0% | **7/11 = 63.6%** (FIXTURE_TESTED 4/11 beside it, never added in) |

M3 per tactic: **persistence 23/91**, defense-impairment 2/35, stealth 0/141,
credential-access 0/58. (technique, OS) pairs: linux 15/167, windows 13/269.

M5 *fell* in percentage terms because the three new Windows checks cannot be lab verified
under B-001. That is the honest direction for that metric and it is not adjusted.

---

## Phase 2b — Defense Evasion (stealth + defense-impairment) — **GATE PASSED**

Six checks added, taking the inventory to **17**. Three reusable implementations
(`scriptFileCheck`, `regPolicyCheck`, plus direct checks) share collection logic across
several ATT&CK sub-techniques; attribution stays **per artifact** in every case.

| Check | ATT&CK (non-partial) | OS | Validation |
|---|---|---|---|
| `LNX-DEFIMP-HISTORY-001` | T1690, T1070 (T1070.003 partial) | linux | **LAB_VERIFIED** |
| `LNX-STEALTH-LOGSINK-001` | T1685.006, T1685 (T1070 partial) | linux | **LAB_VERIFIED** |
| `LNX-STEALTH-HIDDEN-001` | T1564.001, T1564 | linux | **LAB_VERIFIED** |
| `WIN-DEFIMP-DEFENDER-001` | T1685.007, T1685, T1564.012, T1564 | windows | FIXTURE_TESTED (B-001) |
| `WIN-DEFIMP-FIREWALL-001` | T1686.003, T1686 | windows | FIXTURE_TESTED (B-001) |
| `WIN-DEFIMP-EVENTLOG-001` | T1685.001, T1685 | windows | FIXTURE_TESTED (B-001) |

### Real-host reconnaissance before writing checks

Rather than guess at noise sources, the live WSL2 Kali host was inspected first
(`/var/log`, `/tmp`, `/var/tmp`, `.bashrc`) specifically to find what a naive design would
false-positive on. This paid off immediately:

| Measured on the real host | Consequence for the design |
|---|---|
| 150 dot-prefixed files in `/tmp` (JIT/runtime cache `.so` files), 0 of them executable | `LNX-STEALTH-HIDDEN-001`'s criterion is narrowed to **hidden + executable**, not merely hidden |
| 5 legitimately zero-byte logs (`btmp`, `lastlog`, `bootstrap.log`...), one with a populated rotated sibling | `LNX-STEALTH-LOGSINK-001` never uses file size as a criterion; only symlink-to-sink, redirected directory, or wrong file type |
| The real `.bashrc` contains the comment *"see HISTSIZE and HISTFILESIZE in bash(1)"* plus `HISTSIZE=1000` | `LNX-DEFIMP-HISTORY-001`'s patterns are line-anchored to real assignments/builtins, never a bare substring match |

All three predictions were then confirmed empirically: the real-host scan (below) produced
**zero findings** from these three checks, exactly as designed.

### Defects found and fixed in Phase 2b

1. **RE2 has no backreferences.** `histFileSinkPattern`/`histSizeZeroPattern` were first
   written with `\2`/`\3` backreferences for quote matching; Go's `regexp` (RE2) rejects
   that at compile time — the package failed to even `init()`. Fixed by enumerating each
   quote style as an alternation instead of referencing an earlier group.
2. **A literal `...` directory name is unrepresentable through the Win32 API.** The fixture
   generator runs on Windows (this host); `os.makedirs` silently normalises away trailing
   dots in a path component, so the all-dots regression fixture for `HID-C3`/`HID-C4` could
   not be created directly. Fixed with the same indirection already used for symlinks: the
   generator writes a `renames.json` manifest, and the Go test harness — which always runs
   on Linux — renames the safely-named directory into place before applying modes.

### Real-host validation (live WSL2 Kali, unprivileged)

`scan_id irscan-20261014T071031Z-0f3b1211`, 10 Linux checks executed, **605 inventory
items, 0 findings, 0 false positives**. `LNX-STEALTH-HIDDEN-001` and `LNX-PERSIST-ACCOUNT-001`
genuinely returned `PARTIAL_DATA` (some `/tmp` subtrees and parts of `/etc/passwd`-derived
data remain unreadable unprivileged); `LNX-PERSIST-RCSCRIPT-001`, `LNX-PERSIST-SYSTEMD-001`
and `LNX-STEALTH-LOGSINK-001` returned clean `NOT_DETECTED`.

### Coverage after Phase 2b

| Metric | Phase 2a | Phase 2b |
|---|---|---|
| M3 implementation coverage | 25/296 = 8.4% | **35/296 = 11.8%** |
| M4 partial coverage | 3/296 | 4/296 = 1.4% |
| M5 validation (LAB_VERIFIED) | 7/11 = 63.6% | **10/17 = 58.8%** (FIXTURE_TESTED 7/17 beside it) |

M3 per tactic: persistence 23/91, **defense-impairment 9/35**, **stealth 4/141**,
**credential-access 1/58** (the last entirely as a side effect of
`WIN-PERSIST-REGLOADPOINT-001`'s `T1556.002` mapping, which carries both tactics). (technique,
OS) pairs: linux 20/167, windows 20/269.

---

## Phase 2c — Credential Access — **GATE PASSED**

Two checks added, taking the inventory to **19**.

| Check | ATT&CK (non-partial) | OS | Validation |
|---|---|---|---|
| `LNX-CRED-FILES-001` | T1552.001, T1552.004, T1552 (T1552.003 partial) | linux | **LAB_VERIFIED** |
| `WIN-CRED-UNSECURED-001` | T1552.002, T1552.001, T1552 | windows | FIXTURE_TESTED (B-001) |

### Scoping, done before writing code

Before designing the Linux check, the live host was searched for what a naive
"grep for password/secret" design would actually match. The result ruled that design out
immediately: a case-insensitive recursive grep for `password` across `/home`, `/root` and
`/etc` returned hundreds of hits from `node_modules`, vulnerability-scanner templates
(nuclei), documentation, and the source code of other security tools — not one of them a
real credential. A similar grep for a PEM private-key header matched almost exclusively test
fixtures, CVE proof-of-concept payloads and Go's own stdlib test data. `.netrc`,
`.aws/credentials` and `.pgpass` were all genuinely absent (a clean baseline).

Consequently `LNX-CRED-FILES-001` never does a filesystem-wide keyword search. It reads a
short, **named** list of well-known credential-bearing files, recognises secret-bearing
**fields by name** (not by the English word "password"), and looks for private keys only in
`~/.ssh` and `/etc/ssh` — the locations an SSH client/server actually use. Every credential
check in this phase follows the spec's redaction rule strictly: `check.RedactedEvidence` is
used everywhere a secret might appear, and no finding's `Title` or `WhatAndWhere` ever embeds
matched content — only path, pattern type, and count.

### Real-host validation (live WSL2 Kali, unprivileged) — a genuine true positive

`scan_id irscan-20261014T072001Z-6c221b5b`, 11 checks executed, 607 inventory items,
**1 reportable finding**. The finding: `/home/kali/.bash_history` matched the
`mysql -p<password>` inline-credential idiom 11 times and an attached-Authorization-header
idiom once. This is a real, correct detection — the host is a penetration-testing
workstation whose user has typed engagement credentials directly on the command line — and
the check reported only the **pattern type and match count**, never the commands or the
secrets themselves, exactly as the overlay's false-positive handling and the redaction rule
require. `WIN-CRED-UNSECURED-001` could not be run (no Windows execution under B-001) but
passed all four fixture cases, including per-artifact attribution (`T1552.002` for the
Winlogon/PuTTY registry values, `T1552.001` for the unattend.xml `<Password>` element) in a
single fixture run.

### Coverage after Phase 2c

| Metric | Phase 2b | Phase 2c |
|---|---|---|
| M3 implementation coverage | 35/296 = 11.8% | **39/296 = 13.2%** |
| M4 partial coverage | 4/296 | 5/296 = 1.7% |
| M5 validation (LAB_VERIFIED) | 10/17 = 58.8% | **11/19 = 57.9%** (FIXTURE_TESTED 8/19 beside it) |

M3 per tactic: persistence 23/91, defense-impairment 9/35, stealth 4/141,
**credential-access 5/58** (up from 1/58 — the new sub-techniques plus the carried-over
T1556.002 mapping from Phase 2a). Figures recomputed directly from
`irscan attack --report coverage` output, not hand-calculated.

---

## Phase 2d — Classify all remaining in-scope techniques — **GATE PASSED**

**Gate: the registry has no unclassified technique.** This was already satisfied in Phase 0
and remains true: **M2 = 511/511 = 100.0%** (every `U_host` technique carries a resolved
`testability_class` and a `baseline_implementation_status`), **`UNDETERMINED` = 0**.
Re-verified after Phase 2c: `python build/build_registry.py --check-determinism` still
passes the byte-identical-rerun gate.

### What this phase actually did

The classification itself is rule-derived (`build/registry_builder/classify.py`), not
hand-typed, so there was no backlog of techniques to individually classify — Phase 0 already
classified all 511. What Phase 2d did:

1. **Re-verified the gate holds** with 19 real checks now built (it does: M2 unchanged,
   determinism unchanged).
2. **Tightened the PLANNED rationale text** for in-scope techniques with zero mapped checks.
   The old text ("the effective status is computed by joining this baseline with the Go
   check inventory") read as internal engineering process rather than an answer to the
   analyst's actual question. It now reads: *"...but no check in this build maps to it yet.
   Not a difficulty judgement and not out of scope -- building a check for it is future
   work."* Regenerated the registry, re-verified the determinism gate still passes with the
   new text, rebuilt both binaries against the refreshed embed, reran the full test suite and
   the real-host scan — all identical in behavior, only the rationale prose changed.

   Consequence for the Phase 0 table above: regenerating the registry changed the rationale
   text embedded in `attack_registry.json`, `classification_audit.csv` and `registry_meta.json`,
   which changes their hashes even though every count is unchanged. That table records the
   hashes as they were at the end of Phase 0, before this regeneration -- it is a historical
   record, not the current state. As of this regeneration the hashes are: `attack_registry.json`
   `54e9459062b9ea06515c0ba758a50099bb8760ee89aaa5acf18c410ebc3b2960`,
   `classification_audit.csv` `a5c7658ef4369de8bbd3709972b42d1d06fab35276d3115f7b1af73bb0ba4e42`,
   `registry_meta.json` `4ce57e800483ef4a8db07911b0f17a6dc75aecde7fb68b1018d1f694c9d1dea0`.
   `attack_registry.csv` and `revoked_deprecated.csv` are unaffected (unchanged hashes) because
   the rationale text that changed isn't part of either CSV. (Recorded during the independent
   review pass, 2026-10-14, by re-running `python build/build_registry.py --check-determinism`
   and hashing `data/registry/*` directly.)
3. **Spot-checked honesty of the `UNSUPPORTED` classifications** rather than trusting the
   rule engine blindly. Within `U_host` (511), only **3 techniques are `UNSUPPORTED`**:
   `T1213.002` SharePoint, `T1698` Indirect Prompt Injection, `T1699` Direct Prompt Injection
   — all three `OFF_HOST`, evidence living in a SaaS/application layer this tool cannot
   reach. **`NOT_APPLICABLE` = 0** within `U_host` by construction (a platform mismatch
   excludes a technique from `U_host` entirely, so it never needs `NOT_APPLICABLE` inside
   this universe). The remaining **508 are honestly `PLANNED`**.
4. **Checked that the memory/network evidence-family design decision (D-006) was actually
   right**, not just plausible. `T1055` Process Injection and `T1003.001` LSASS Memory were
   *expected* to land as `MEMORY_ONLY` per the hand-curated family table in
   `technique_families.json`. They instead resolved to `HOST_TELEMETRY` / `MIXED`, because
   their own ATT&CK v20.0 detection strategies cite Sysmon/ETW/auditd telemetry (Sysmon Event
   ID 8 for `CreateRemoteThread`, for instance) — which is a real, telemetry-based detection
   path independent of reading the injected memory itself. The rule order documented in
   `classify.py` (§R5, telemetry checked *before* the memory/network family) exists
   specifically so this doesn't get mis-classified, and verifying it against these two
   concrete techniques confirms the rule does what it was designed to do.

### Honest summary of where the registry stands

| | Count | Share of `U_host` (511) |
|---|---|---|
| Effectively `IMPLEMENTED` (checks pass full gate) | 39 | 7.6% |
| Effectively `PARTIAL` | 5 | 1.0% |
| `UNSUPPORTED` (evidence-reach limit, all `OFF_HOST`) | 3 | 0.6% |
| `NOT_APPLICABLE` within `U_host` | 0 | 0% |
| `PLANNED` (scannable, not yet built) | 464 | 90.8% |

No number here is padded by relabeling a hard technique as inapplicable: `NOT_APPLICABLE` is
used only for the one honest case (platform mismatch), and it never fires inside `U_host` by
definition.

---

## Phase 3 — Unified CLI, coverage reports, README, build/release notes — **GATE PASSED**

The CLI shell was actually built incrementally starting in Phase 1 (`cmd/irscan`); Phase 3
closed out what remained: `README.md`, `RELEASE_NOTES.md`, and a close read of the actual
rendered output of every report type, which found and fixed two real defects.

### CLI surface verified end-to-end

- `irscan attack --os <windows|linux> [--technique ...] [--tactic ...] [--check ...]`
- `irscan attack --report coverage` — static, no scan, no `--output` required
- `irscan all --scope <id> --output <dir>` — **verified it refuses to run without `--scope`**
  (`irscan all --output /tmp/x` with no scope → clean error, exit 1)
- `--dry-run` for both OS targets — verified it correctly lists only the 8 Windows checks
  with their real source/privilege strings when `--os windows` is passed (even though it
  cannot execute them), and correctly explains why each Linux check is `NOT RUN`
- `irscan malware` — verified it exits non-zero with the D-007 explanation, never returns an
  empty "clean" result
- `irscan attack --report bogus` — verified a clean, specific error rather than a stack trace

### Defects found by reading the actual rendered reports, not just grepping for success

1. **The scan manifest never recorded who ran the scan.** `scan_manifest.json` /
   `findings.md` / `inventory.md` headers all printed `scanned as \`\`` (empty) regardless of
   the real user, because `cmd/irscan/main.go`'s `buildManifest` built `model.HostInfo`
   independently of `internal/check.NewEnv` and simply never set `ScanUser` or `Elevated`.
   Caught by reading the actual output of a real scan, not by a unit test — nothing asserted
   this field was non-empty. Fixed by extracting the logic into a single shared function,
   `check.BuildHostInfo`, called from both `NewEnv` (per-check) and the CLI (the manifest), so
   the two can no longer independently disagree about who ran the scan.
2. **A Markdown table in `inventory.md` rendered a broken separator row** (`|---|---|---||---|`
   — one fewer `---|` segment than header columns, from a redundant leading `|---|` appended
   after an already-terminated `strings.Repeat` block). Fixed to build the separator from a
   single column count. Re-verified the fixed output renders a correct 6-column separator.

Both were only found because the actual report files were read end-to-end after a real scan,
not inferred from the Go tests passing — the test suite had no assertion that would have
caught either one. Recorded here as a reminder for the review pass: tests passing is not the
same as the output being right.

### Final sanity pass on `coverage_and_gaps.md`

- `Inconsistencies` section is empty (no registry/check mapping disagreement) — confirmed by
  its absence in the rendered output (the renderer only prints the section when non-empty).
- Gap count: **472** = 511 (`U_host`) − 39 (effectively `IMPLEMENTED`), matching M3 exactly.
- Spot-checked several `PARTIAL` rows (`T1053.006`, `T1070.003`, `T1078.003`) — each correctly
  names the specific check providing partial coverage and states why it's excluded from M3.

---

## Independent adversarial review — **COMPLETE**

Performed by a **separate agent** with no prior involvement in building the tool, per the
task's requirement to delegate the review rather than self-certify. It was briefed to verify,
not confirm: re-run the full suite, recompute every coverage number itself from source (not
trust the tool's own printout), check for a self-certification path in the implementation
gate, spot-check ATT&CK IDs/names/platforms against the raw pinned STIX bundle, confirm no
`LAB_VERIFIED` check was fixture-only, and audit read-only-ness across the *entire* `internal/`
and `cmd/` tree (not just the three directories the existing test covers).

### Result on each of the six required checks

1. **Full test suite** — pass. 19 checks × 4 cases = 76 subtests, plus 9 supporting tests, all
   passing and confirmed non-vacuous by reading their source (e.g. `TestWindowsChecksAreNotLabVerified` actually iterates conditionally rather than trivially passing).
   **Gap noted, left open**: only `internal/checks` has test files; `internal/coverage`,
   `internal/report`, `internal/registry`, `internal/module`, `internal/safety`,
   `internal/allowlist` and `cmd/irscan` have none. Correct and worth recording as a limitation
   — those packages are presently exercised only by manual review and real-host runs, not CI.
2. **Coverage recomputed independently** — exact match. The reviewer extracted all 56
   `TechniqueMapping` entries directly from `internal/checks/*.go` source (not the built
   binary) and independently derived M1–M5, every per-tactic and per-OS breakdown — all
   matched the tool's own printout and `STATUS.md`'s prose to the digit.
3. **No self-certification path to IMPLEMENTED** — confirmed. `coverage.effectiveStatus` is
   the only function that can return `model.Implemented`, and it only does so for a
   `CheckRef` with `GatePassing && !Partial`, where `GatePassing` is computed fresh per report
   from `check.EvaluateGate`, never read from a check's own declaration.
4. **ATT&CK ID/name/platform spot-check** — 32 technique IDs checked directly against the raw
   STIX bundle (more than double the 15 required), covering every scope tactic and both OSes,
   plus the revoked `T1562`/`T1562.002` sanity case. Zero mismatches.
5. **No fixture-only `LAB_VERIFIED` claim** — confirmed. All 11 `LAB_VERIFIED` checks are
   Linux-only with specific, checkable `LabEvidence`. The reviewer ran the Linux binary fresh
   against the live WSL2 host themselves and confirmed all 11 appear in that run's
   `scan_manifest.json`, and that the one real finding (`.bash_history` credential idiom) still
   matches what Phase 2c recorded, with secrets still correctly redacted.
6. **Read-only** — confirmed via a full-tree grep (broader than the existing
   `TestCollectorsAndChecksAreReadOnly`, which only scans three directories). Two write-capable
   calls exist in the whole `internal/`+`cmd/` tree, both in `internal/report/report.go`
   (`MkdirAll`, `WriteFile`), both gated through `safety.OutputGuard.Check()`. No `exec.Command`
   anywhere. The Windows registry reader opens `KEY_READ` only.

### Defects found and fixed

1. **Dead boolean condition in M1** (`internal/coverage/coverage.go`): `len(t.Platforms) >= 0`
   can never be false, so that conjunct silently validated nothing. Fixed to `> 0`. Confirmed
   it had zero effect on the current M1 value (867/867 — no technique in the bundle actually
   has an empty platform list), but it was a real logic bug, not just a style issue.
2. **Self-contradicting count in `RELEASE_NOTES.md`**: said "10 of 19... LAB_VERIFIED" in prose
   two lines above a table correctly stating "11/19 = 57.9%". 11 is correct (independently
   re-verified above). Fixed the prose.
3. **Tracked `dist/` breaking binary-level reproducibility** (the most substantive finding).
   `README.md`/`PLAN.md` both describe `dist/` as "git-ignored, build-time only", but the
   `.gitignore` entry was never actually added, so three built files were committed during
   earlier phases. Because they were tracked, every rebuild changed tracked content, and Go's
   default `-buildvcs=true` stamps a `vcs.modified` flag read from `git status` — which
   flipped depending on prior build state. The reviewer proved this empirically: three
   consecutive `go.sh dist` runs from byte-identical source produced **three different Linux
   binary hashes**. They added `dist/` to `.gitignore` (stopping further drift) but correctly
   left the git-index operation (`git rm --cached`) and the `go build` flag change to me,
   flagging both as remaining. I completed both afterward: ran
   `git rm -r --cached dist/`, added `-buildvcs=false` to `build/go.sh dist` (version/commit
   are already stamped explicitly via `-ldflags`, so nothing is lost), and **re-verified by
   running three consecutive builds myself** — all three now produce byte-identical hashes for
   both binaries. The `RELEASE_NOTES.md` and gate-evidence hashes throughout this document were
   re-captured after this fix.
4. **Stale registry hashes in the Phase 0 table above** (found by the reviewer, independently
   re-verified by me afterward by re-running `python build/build_registry.py
   --check-determinism` and comparing the printed hashes byte-for-byte against the note added
   to Phase 2d): Phase 2d's rationale-text change altered `attack_registry.json`,
   `classification_audit.csv` and `registry_meta.json`'s hashes (counts unchanged) after the
   Phase 0 table was written. The Phase 0 table is left as a historical record; the current
   hashes are noted inline in Phase 2d.

All four fixes were re-verified end-to-end after being applied: `go build`/`go vet`/`go test`
all still pass, a fresh real-host scan against live WSL2 Kali still produces the same 11
checks run / 1 finding / 607 inventory items as before, and `irscan attack --report coverage`
still prints M1=867/867, M2=511/511, M3=39/296, M4=5/296, M5=11/19 — identical to pre-review.

### Overall verdict (reviewer's own words, independently re-checked by me)

> "STATUS.md's substantive claims are honest and accurate... The defects I found are real but
> narrow: one dead boolean condition (no numeric effect), one self-contradicting sentence in
> release notes, and a build-hygiene gap... that the project's own Phase 0 determinism gate
> doesn't cover because that gate is scoped to the registry, not the binary. None of these
> inflate coverage, fake validation, or hide a check — which is the class of dishonesty this
> review was most meant to catch."

I concur with this verdict after independently re-verifying the reviewer's four fixes and the
hash claims underlying them.

---

## Persistence-tactic deep audit (requested follow-up, 2026-10-14)

Requested explicitly: is Persistence coverage complete, and does the detection *logic* match
what MITRE's own Analytic / Detection Strategy objects (the `x-mitre-analytic` /
`x-mitre-detection-strategy` STIX objects new in v20.0) actually recommend? Done by direct
data comparison, not inspection by eye: a script filtered the pinned registry for every
technique carrying the `persistence` tactic and applicable to Windows/Linux, cross-referenced
against the exact `TechniqueMapping` entries extracted from `internal/checks/*.go` source, and
a second script dumped the real `detection_strategies` + `log_sources` fields the registry
carries per technique (sourced from MITRE's own `x-mitre-analytic` objects) for every
technique this tool claims to cover.

### 1. Registry completeness vs. MITRE — confirmed correct

Live `https://attack.mitre.org/tactics/TA0003/` lists **22** top-level Persistence techniques.
The pinned registry has **20** applicable to Windows/Linux. The two missing —
`T1671` Cloud Application Integration (`platforms: [Office Suite, SaaS]`) and `T1525` Implant
Internal Image (`platforms: [Containers, IaaS]`) — are confirmed correctly excluded: neither
applies to a Windows/Linux host scan, and both are classified `NOT_APPLICABLE` by the one
honest route to that status (platform mismatch), not by difficulty. Registry completeness for
Persistence: **confirmed, 20/20.**

### 2. Coverage count — 26 of 91 Persistence techniques, confirmed by direct extraction

`U_host ∩ persistence` = **91** techniques. Extracting `TechniqueMapping` entries straight from
source (not trusting memory of what was built) gives **26** distinct technique IDs covered
(non-partial), across 10 checks (6 Linux, 4 Windows). This matches the tool's own
`persistence 23/91` M3 figure once revoked-mapping and partial-only entries are excluded
correctly (23 non-partial IDs land inside `U_impl`'s stricter implementation-scope filter; the
26 above is the broader "any non-partial mapping" count before that filter, which is the right
number for a tactic-scoped audit).

### 3. Detection logic vs. MITRE's own Analytic/Detection Strategy data

For all ~19 covered sub-techniques, MITRE's own `detection_strategies`/`log_sources` fields were
pulled directly from the registry and read side-by-side with each check's actual logic.
Two findings:

- **Thematic, not a bug, but worth stating plainly: every MITRE detection strategy for these
  techniques is primarily TELEMETRY-based** (Sysmon EventCode 1/6/7/11/13/14, Security 4657/
  4697/4698/4702/4720/4728.../4624, `auditd:SYSCALL`/`EXECVE`), while every `irscan` persistence
  check is ARTIFACT-based (reads current on-disk/registry state). This is the correct and
  honest consequence of `testability_class: MIXED` for all of them — both an artifact and a
  telemetry signal exist per MITRE's own data, and this build has so far implemented only the
  artifact half. Each check's `Limitations` already says this explicitly (e.g. "only Sysmon
  registry events... would show it, and neither may be enabled") — the audit's contribution is
  confirming that statement is accurate for every single covered technique, not just the ones
  it was written for, and that no check is *silently* missing a telemetry cross-check it could
  easily add. **No check queries `env.Telemetry` for technique-specific corroboration today**;
  the one telemetry-based check (`LNX-DEFIMP-AUDITD-001`) checks audit-subsystem *health*, not
  per-technique event content. This is accurately scoped as a real, named limitation, not
  something misrepresented as covered.
- **Concrete, fixed: `T1547.004` Winlogon Helper DLL.** MITRE's Detection Strategy `DET0404`
  names three Winlogon registry locations to watch: *"Shell, Notify, or Userinit."*
  `WIN-PERSIST-REGLOADPOINT-001` read Shell and Userinit but never `Notify`. Fixed: added
  `HKLM\...\Winlogon\Notify\<package>` (`DLLName` value) to the check's `loadPoints` table,
  using the same subkey-enumeration shape already built for Image File Execution Options
  (`NoLegitimateDefault: true` — on any modern Windows build this key is normally empty, so a
  populated `DLLName` is itself the artifact, same logic as the IFEO `Debugger` value). Added a
  fixture case, a new criterion wording for `RLP-C4`, an Overlay artifact-list entry citing
  `DET0404` directly, and a `References` citation. Re-ran the full suite (now 4 findings
  expected in the positive fixture, up from 3) — passes. `go vet` clean for both targets.
  Rebuilt and re-ran the real-host scan: unchanged (this is a Windows-only check, so the
  Linux-host real run was never exercising this code path either way; `M3`/persistence figures
  are unchanged because `T1547.004` was already counted as covered — this fix improves the
  *depth* of an already-counted technique, not the *count*).

### 4. Reporting nuance surfaced (not a bug — the design already accounts for it)

5 of the 26 covered technique IDs (`T1037`, `T1098`, `T1098.007`, `T1136`, `T1136.001`) have
`os_scope: [linux, windows]` but are, in practice, covered **only on the Linux side** — no
Windows check maps to them (Windows account/group management via `net.exe`/SAM is not
implemented). The flat technique-level M3 count treats these as covered the moment any
non-partial mapping exists, regardless of OS completeness; the separate **(technique, OS)
pairs** metric — required by the spec and already implemented — is what correctly shows the
Windows side of these 5 as not implemented. Confirmed the pairs metric does this correctly;
flagging here only so the distinction is explicit rather than implicit in a second table.

---

## Blockers carried forward

| ID | Blocker | Effect |
|---|---|---|
| **B-001** | Smart App Control ON + not elevated ⇒ no unsigned binary can execute on this host | `irscan.exe` cannot be **run** here. **No Windows check can reach `LAB_VERIFIED` this session.** Not worked around — bypassing a host security control is a hard stop. |
| **B-002** | No real Windows Server, no domain, no elevation | Checks needing elevation or a DC (`T1003.003`, `T1003.006`, `T1556.001`, Security-log reads) cannot be exercised privileged. Their `PERMISSION_DENIED` path *is* genuinely testable here by running unprivileged. |
| **D-001** | Authoritative spec document absent from the session | The "six coverage metrics" are a documented **reconstruction**, flagged in `PLAN.md` §4 and in report headers. |

---

## Hard stops encountered

| What | Decision |
|---|---|
| Disabling Smart App Control to run the Go toolchain / built binary on Windows | **Refused.** Requires elevation I lack, is irreversible on Windows 11, and weakens the user's host security posture. Recorded as B-001; Go moved into WSL2 instead. |

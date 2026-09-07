# Remediation implementation evidence

Specification: `docs/superpowers/specs/2026-09-05-codebase-remediation-spec.md`

Branch: `fix/codebase-remediation`; baseline: `c53e818296d227aed45c26764af78b1cdbb2b10e`.

Implementation is underway. Startup repairs are verified locally; broader authentication and networking acceptance remains unfinished.

## Stage ledger

| Stage | Status | Evidence / next action |
| --- | --- | --- |
| A: foundation | Portable checks passed | Python 3.11/3.12 tests, CLI, frontend build/lint/tests and dependency audit pass. Remote Linux CI remains unrun. |
| B: authentication | Partial | Private credential/session migration, REST/CSRF/login limits, local reset, authenticated sockets and browser session integration implemented. Additional failure/race/browser coverage and HTTPS installation remain pending. |
| C: reconciliation | Pending | Depends on A/B. |
| D: inline enforcement | Pending | Requires isolated Linux traffic fixture. |
| E: accounting | Pending | Requires C/D. |
| F: lifecycle/install/UI | Pending | Requires B–E. |
| G: full acceptance | Pending | Requires all earlier stages and per-issue audit. |

## Execution decisions

- Work in the existing checkout on the expressly requested new branch; preserve the untracked specification.
- Use independent implementation agents for frontend and backend foundation as required by the applied subagent development skill. Review their changes before closing the stage.
- Environment currently supplies Windows/Python 3.14. The specified Python 3.11/3.12 and Node 22 targets need separate verification. `wsl --list --quiet` returned WSL installation help rather than a usable Linux distribution; Docker is not on PATH. Linux enforcement acceptance remains pending. No host networking changes are authorized by the test workflow.
- All stages agree on persisted desired state and the contracts in spec section 5. Foundation config/app creation is consumed by authentication; authenticated services are consumed by reconciliation; owned resource/reconciler contracts are consumed by inline enforcement and accounting; lifecycle integration consumes all services. No incompatible design requirements identified in preflight. Stage A's bootstrap check will be replaced by persisted credential validation in B so a rotated password is not overwritten by environment seeds.

## Issue evidence

| Issue | Status | Evidence / remaining acceptance |
| --- | --- | --- |
| R01 startup syntax | Verified locally | Source compilation, alternate-cwd CLI and explicit listener/component option regression checks pass on Python 3.11/3.12. |
| R02 auth import | Verified locally | App/auth import without networking; missing auth rejected; persisted Basic credentials exercise protected settings routes. |
| R03 content verdicts | Pending | Inline queue engine and real traffic checks required. |
| R04 password persistence | Partial | Private credential migration with backup and seed precedence; rotation/current-password/byte-limit/old-session tests pass. Further DB failure and full browser/restart acceptance pending. |
| R05 configuration | Pending | Typed config underway; installer and persisted auth remain. |
| R06 WebSocket auth | Partial | ASGI test rejects missing session/wrong origin, receives pong after login, and sees socket close on logout. Bounded queues and expiry verification implemented; slow-client and broader failure tests pending. |
| R07 event thread safety | Pending | Bounded ingestion and exactly-once persisted IDs required. |
| R08 directional limits | Pending | Classifiers and measured Linux throughput required. |
| R09 command failures | Pending | Typed failures, rollback and failure injection required. |
| R10 restart recovery | Pending | Persisted intent reconciliation and Linux restart tests required. |
| R11 interception | Pending | Independent protection reasons and same-LAN tests required. |
| R12 resource ownership | Pending | Owned inventory and foreign resource preservation required. |
| R13 dashboard serving | Pending | Static/SPA routes and real browser checks required. |
| R14 frontend quality | Partial | Strict build/lint and locked install pass; tooling advisories resolved. Production browser loading remains pending. |
| R15 reconnect | Partial | Single close handler, exponential retry, authentication guard, cleanup and stable subscriptions implemented. Fake timer tests cover connected-close/reconnect/logout/StrictMode; repeated failure/subscription/browser coverage pending. |
| R16 bandwidth history | Pending | Kernel deltas, persistence/retention and charts required. |
| R17 full snapshots | Pending | Persisted snapshot contract and offline/upsert checks required. |
| R18 browser login | Partial | Cookie session restore/login, legacy-storage removal, no Basic headers, centralized expiry and confirmed logout implemented. Component tests reject stale storage and 500/503; browser/reload/offline acceptance pending. |
| R19 truthful mutations | Pending | Reconciliation, tombstones and UI state required. |
| R20 rule normalization | Pending | Canonical values, constraints/migrations and API tests required. |
| R21 lifecycle | Pending | Owned reverse cleanup and bounded worker stop required. |
| R22 catalog | Pending | Versioned JSON import and custom preservation required. |
| R23 reproducibility | Partial | Universal Python constraints and portable CI added; test suites, clean matrix execution and Linux CI still required. |
| R24 discovery | Pending | Off-loop bounded scans and gateway/local target guards required. |

## Foundation verification log

- Created isolated dependency environments using uv 0.12.10: Python 3.12.14 in `backend/.venv`, Python 3.11.16 in `.venv-py311` (Windows x64).
- Generated universal `backend/constraints.txt` from runtime/developer inputs. Installed each with the documented `python -m pip install -r backend/requirements.txt -r backend/requirements-dev.txt -c backend/constraints.txt`: both exited 0. `python -m pip check` in both environments reported no broken requirements.
- Added `.github/workflows/ci.yml` for Python 3.11/3.12 on Ubuntu 24.04 and Node 22. This workflow has not yet run remotely; local Windows results do not establish the Linux matrix.
- Initial frontend installation exposed seven npm advisories (five moderate, one high, one critical). Dependency remediation and actual Node 22 checks are underway; do not treat the initial passing build as closure of the frontend foundation.

## Authentication implementation and resumed verification

- Foundation review agents stopped because of an account usage limit. Root continued local review and verification. The Python 3.11 guard initially blocked the interpreter's harmless Windows `ver` query; warming the interpreter platform cache before application-command guards fixed that failure. Both supported versions subsequently passed 21 foundation tests.
- Added regression tests before correcting cwd-dependent paths and configuration error input disclosure. Relative configured paths now resolve against the explicit config directory; validation diagnostics hide input values.
- Upgraded frontend tooling and router dependencies to resolve the discovered advisories. `npm audit --json` now reports zero findings. The initial affected advisories were GHSA-5xrq-8626-4rwp (Vitest), GHSA-fx2h-pf6j-xcff / GHSA-4w7w-66w2-5vf9 / GHSA-v6wh-96g9-6wx3 (Vite), GHSA-67mh-4wv8-2f99 (esbuild), GHSA-wrjc-x8rr-h8h6 / GHSA-337j-9hxr-rhxg (React Router). No force/suppression fix used.
- Added `backend/db/migrations.py`, private credential/session tables, `backend/core/auth_service.py`, auth API and local `--reset-password`. Migration tests exercise old settings in an actual SQLite database, backup preservation, seed precedence, foreign keys, idempotence and restart. Session/API tests exercise real bcrypt, SQLite, cookies, CSRF, reserved keys, password rotation, logout, expiry, and the fifth failed-login threshold.
- WebSocket ASGI test was first observed accepting an unauthenticated client. After the repair it rejects missing sessions/wrong origins, receives a pong for a valid session, and closes that same socket on logout. Queued messages revalidate the session before sending; slow sends have a timeout. Broader failure/concurrency coverage is still pending.
- Browser auth tests were first observed accepting stale credentials and server failures. Four auth tests now pass. Two socket tests cover authentication gating, established disconnect/reconnect, logout, StrictMode cleanup and ping timers. The empty-chart smoke test also passes (7 frontend tests total).
- Expected remaining tooling output: upstream Starlette/httpx and AnyIO deprecation warnings; Vite flags the approximately 611 kB application bundle. These are recorded, not suppressed. Full browser/production delivery checks remain pending.
- Root independently ran Node 22.23.2 against ESLint, TypeScript, Vite 8.2.2 and Vitest 5.0.0 after the session/socket edits: lint, compile, production build and all 7 component tests passed.
- Additional backend checks now exercise a failed credential commit (old password/session survive), a rotated password across a real DB close/reopen with the original environment seed, slow-socket isolation, and the fixed reviewed schema in `backend/tests/fixtures/legacy.sql`. Bootstrap also now seeds an already initialized database if it still has no credential, while preserving every existing credential.
- Latest checkpoint: `python -m pytest backend/tests -q --tb=short --basetemp <unique backend/.pytest-tmp-* directory>` passed **38 tests** on **both Python 3.12.14 and 3.11.16**. `git diff --check` found no whitespace errors. This is a portable authentication/foundation checkpoint, not all-issues acceptance.

## Command failure handling checkpoint

- Added a bounded command runner with typed nonzero, unavailable-executable and timeout outcomes, plus an asynchronous thread wrapper. Four command tests passed.
- DeviceBlocker now uses the asynchronous runner, rejects setup/probe failures, retains tracked blocks after failed deletion and reports failed shutdown. It no longer flushes the existing chain during setup or shutdown. Six injected-runner tests passed, including permission failure and failed cleanup regressions.
- Restored the local Linux ioctl imports for MAC and netmask lookup after the utility import refactor.
- Python 3.12 full backend run passed 47 tests before the final shutdown edit; the six blocker tests passed after that edit. Full post-edit matrix validation remains pending.
- R09 remains partial: other network adapters and API reconciliation still require conversion. R12 and R21 remain pending: exact resource ownership, restart inventory, reverse cleanup and Linux acceptance are not established by these tests.

## Dashboard delivery checkpoint

- R13 is partial: the API now serves installed assets and known SPA routes from an absolute configured directory, while preserving missing-asset/API 404s and GET-only fallback. Missing installations return an explicit 503; API_ONLY=true disables dashboard routes. STATIC_DIR resolves relative to the configuration file.
- The installer now requires Node 22/npm, uses npm ci and locked Python constraints, builds/copies assets and checks index.html. README and environment example describe the deployment paths and API-only option. Git Bash syntax validation passed; the privileged installer has not been executed.
- Seven static delivery tests passed, including traversal, reserved routes and absent assets. Full backend suite after the blocker and dashboard changes: 55 passed on both Python 3.11 and 3.12, with the same two upstream deprecation warnings. Actual production browser execution and Linux install acceptance remain pending.

## Discovery and device snapshot checkpoint

- R17 partial: scan updates now return the full persisted device list, retaining offline rows and saved names/protection flags. Single frontend device updates now insert unknown devices as well as replace existing ones.
- Failed scans raise instead of becoming successful empty scans. The manual scan API returns 503 without storage updates or broadcasts. Periodic scan failures use the existing error path and skip callbacks.
- R24 partial: ARP exchange and reverse lookup run off the event loop; scans exclude local and gateway MACs and the gateway IP. Bounded DNS resolution, scan concurrency, stronger topology/target validation and Linux acceptance remain pending.
- Three discovery tests initially accompanied a full Python3.12 run: 58 passed. A subsequent API failure regression brings the targeted discovery set to four passing tests. Python3.11 has not yet been rerun for this checkpoint. Existing naive UTC model defaults emit deprecation warnings in the new DB coverage.
- Node22 frontend suite: eight tests pass, including retaining an offline device while inserting a newly discovered device from a WebSocket update. ESLint passes. Browser-level scan/offline acceptance remains pending.

## Canonical application catalog checkpoint

- R22 partial: removed the hard-coded seed subset. Startup imports the configured versioned JSON catalog, validates schema/identifiers/domains/IP ranges before mutation, refreshes built-ins idempotently and preserves custom records. Catalog version is recorded in settings. Removed built-in identifiers remain as empty signatures so existing references are not deleted.
- Added lowercase/IDNA/trailing-dot/leading-wildcard normalization for catalog entries. This utility is not yet applied to all user rule paths (R20 remains pending).
- Two database catalog tests passed within the full Python3.12 backend run of 61 tests. Seven additional domain normalization/rejection cases subsequently passed (nine targeted catalog tests total). The shipped catalog successfully imports in the existing database/auth tests. Upstream and legacy naive-UTC deprecations remain visible.
- Remaining R22 acceptance: explicit unresolved-rule presentation, live matcher refresh semantics, API/display-name and advertised-app coverage checks. No inline traffic enforcement claim follows from catalog import tests.

## Shared domain matching checkpoint

- R20 partial: catalog, domain-rule request validation, domain add/remove and matcher queries now use a shared lowercase/IDNA/trailing-dot normalizer. Only exact domains and leading wildcards are accepted; wildcard matching includes apex/descendants and excludes suffix lookalikes. Equivalent in-memory domain rules deduplicate and remove consistently.
- Reloading catalog signatures refreshes already-resolved in-memory app rules and drops stale signature data. A database-backed regression first reproduced the stale matcher and passes after the fix.
- Sixteen targeted catalog/content tests pass on Python3.12. Persisted-rule uniqueness/migration, invalid legacy rule handling and concurrency remain pending. Explicit catalog reload is covered; automatic live file watching is not implemented. These are policy-matching tests, not evidence of actual packet drops (R03 remains pending).
- Full backend suite after shared normalization/catalog refresh: 75 passed on Python3.11, with two upstream warnings.

## Rule editor checkpoint

- R19 partial: rule editor callbacks now return promises. Save/delete operations are awaited, submissions are serialized while pending, errors remain visible and failed requests preserve selected app/domain input. DeviceDetail propagates mutation errors to the editor rather than swallowing them.
- A UI regression first reproduced the immediate domain-field clearing; it now verifies retained input, one request while pending and the displayed rejection. All nine frontend tests passed under Node22. TypeScript and ESLint subsequently passed after correcting a test query option and removing redundant catch/rethrow wrappers.
- This does not establish truthful applied-state semantics: backend desired/applied reconciliation, pending/error responses and corresponding status presentation remain required. The editor currently treats a fulfilled API promise as accepted; network enforcement acceptance remains pending.

## Traffic command checkpoint

- R09 partial: TrafficController now uses the asynchronous bounded command runner for tc, ip and iptables operations. IFB setup failures propagate; failed limit removal retains tracking, and replacement stops when removal fails.
- R12 partial: removed the routine that enumerated and deleted every PREROUTING MARK rule. Mark cleanup now deletes only exact MAC/mark specifications in this controller's tracked limits. Seven traffic/command tests pass, including a regression that reproduced the foreign MARK deletion.
- Exact tracked specifications are not complete ownership proof. Persistent resource identity, partial application retry/rollback, foreign qdisc preservation and restart cleanup remain required. The legacy IFB implementation still lacks a download classifier and must be replaced by the planned directional adapter; R08 remains pending.
- Full Python3.12 backend suite after the traffic command changes: 78 passed; existing upstream/naive-UTC deprecation warnings remain.

## Lifecycle failure checkpoint

- R21 partial: application shutdown attempts every registered cleanup step and closes the database even if earlier cleanup raises; failures are returned together instead of hiding later cleanup work. A regression verifies two independent failures and the full cleanup sequence.
- ARP service records the original IP forwarding state and restores either enabled or disabled state on stop. Failed forwarding reads/enables/restoration raise errors; inability to read the original state is no longer interpreted as disabled. Two injected-state tests cover both initial values.
- Three lifecycle tests pass. Remaining: actual acquired-resource registration/reverse rollback, cancellation handling, bounded quiet-capture stop, restart/crash state recovery and Linux shutdown acceptance. This checkpoint does not establish R21 completion.
- Full Python3.12 backend suite after lifecycle changes: 81 passed, with existing deprecation warnings.

## Quiet capture shutdown checkpoint

- R21 partial: passive capture now wakes every 0.5 seconds on a quiet interface, joins its worker during stop and reports a two-second join timeout without discarding the live handle. Restart is refused until the previous capture handle has been stopped. Worker failure clears running status and is logged/reported through stop.
- Two regressions reproduced quiet-worker leakage and stale running state after capture failure. Five targeted capture/lifecycle tests pass. Periodic Scapy capture reopening may introduce observation gaps; a persistent socket/wakeup adapter and Linux capture acceptance remain necessary. This passive capture change is not the inline enforcement worker required by R03.
- Full Python3.12 backend suite after capture shutdown changes: 83 passed; existing deprecation warnings remain.

## Packet event pipeline checkpoint

- R07 partial: capture callbacks submit immutable access events to a bounded thread-safe queue. An asyncio consumer batches writes (100 events or one second by default), retries a batch three times using stable IDs, accounts for overflow/persistence losses and drains before database shutdown. No callback calls create_task from the capture thread.
- Schema v2 adds a nullable unique access-log event ID while retaining legacy log IDs/data. The SQLite sink commits batches before broadcasting and uses conflict-safe insertion to prevent duplicate log rows after retry.
- Passive DNS/TLS callbacks now record observed traffic as allowed instead of falsely labeling policy matches blocked. Only the future inline worker may submit actual blocked verdict events; R03 enforcement is still pending.
- Ten event/migration/lifecycle tests passed, then four targeted packet-event tests passed including actual worker-thread callback delivery, immutable payloads, overflow, retry identity, DB deduplication and passive action truthfulness.
- Remaining: API/UI visibility of event metrics, stronger shutdown/cancellation/sustained-load supervision, isolation of unknown-device events within a batch, broadcast retry deduplication and real inline-verdict integration. Bounded queue tests do not establish full R07/R03 acceptance.
- Full Python3.12 backend suite before the final added callback test: 86 passed; the four-test event subset passed afterward.

## Event failure isolation checkpoint

- Unknown-device events now increment loss counts without rolling back known-device events in the batch. Persistence outcomes distinguish saved events, lost events and failed notifications.
- Conflict-safe inserts return newly inserted IDs; retries no longer broadcast duplicate stored events. Notification errors are counted separately from storage failure, preventing committed rows from being reported as lost.
- System stats expose event queue depth, in-flight events, persisted/lost/retry counts and notification failures through the running worker. UI presentation remains pending.
- Five packet-event tests pass, including regressions that first reproduced batch loss and duplicate notifications. Cancellation/stress coverage and durable notification recovery remain pending.
- Full Python3.11 backend suite after event isolation and stats wiring: 88 passed, with two upstream warnings.

## Persisted canonical rules checkpoint

- Schema v3 adds canonical rule identity, uniqueness per device/type/value and legacy validation diagnostics. Equivalent legacy domain/app rules merge into the oldest ID with active intent preserved. Duplicate bandwidth rules share one identity; active duplicate limits merge using the stricter rate in each direction. Invalid legacy rules remain stored with a diagnostic instead of being deleted or crashing matcher loading.
- Atomic SQLite upserts now back all three rule creation routes. Concurrent equivalent domain writes return the same rule ID. App/domain values are canonicalized before writes; invalid MACs on rule routes return422. Domain/app mutations reload matching from authoritative active rows instead of removing by string.
- Validation: five migration tests passed, a full Python3.12 suite passed90 before the final input-validation addition, and ten targeted content/migration tests passed afterward. Existing deprecation warnings remain.
- R20 remains partial: wider deletion/restart/concurrent API acceptance, legacy MAC equivalence, invalid-rule UI diagnostics and complete input bounds still need verification. Migration uses nullable added SQLite columns for compatibility; raw SQL identity-bypass guards are not yet implemented. R19 desired/applied reconciliation remains pending.

## Interception target guard checkpoint

- R24 partial: ARP target addition and DHCP address updates reject the gateway IP, gateway/appliance MACs, multicast/loopback/unspecified/reserved IPv4 addresses and non-unicast MACs before sending packets or changing target state.
- Monitoring API validates targets before saving monitoring intent, including the general device update route when the device has an address. A regression verifies a gateway request returns422 without writing the device.
- Ten target/lifecycle tests pass on Python3.12. Remaining: appliance-IP/topology/subnet checks, offline protected-device handling, guards across all block/rule paths and full reconciler integration. Linux topology acceptance remains pending.

## Installer configuration preservation checkpoint

- R05 partial: installer uses a tested exclusive-create helper for initial configuration and preserves existing configuration bytes on rerun. It applies owner-only file permissions and rejects symlink/non-file configuration paths. Both service definitions now pass the explicit env-file path.
- Fresh configurations use the shipped template and detected interface. Password instructions use hidden-input reset; README now describes mandatory authentication, persisted credential precedence, HTTPS origins and explicit loopback development instead of passwordless login.
- Two portable install-config tests passed (fresh template/interface and rerun preservation); Git Bash syntax validation passed. Linux permission/systemd installation, interrupted writes and full rerun deployment acceptance remain pending.

## Traffic queue ownership checkpoint

- R12 partial: traffic initialization now inspects qdiscs and refuses to replace existing configured queues. Untouched default noqueue entries are allowed. Successful qdisc additions are recorded and rollback/shutdown deletes only those recorded interface/location/handle specifications after checking the current kind.
- Shutdown before initialization makes no kernel calls. Partial-start rollback removes only successfully created queues; a changed queue kind causes cleanup refusal while retaining the ownership record.
- Seven traffic-command tests pass, covering foreign queue preservation, no-start cleanup, partial acquisition and changed-kind refusal. Persistent identity/restart recovery, child-resource inventory, same-kind replacement detection and IFB link ownership remain pending. This does not complete R12 or directional shaping (R08).
- Full Python3.11 backend suite after queue ownership, canonical rules, target guards and installer helper changes: 104 passed, with two upstream warnings.

## Directional bandwidth and reconciliation checkpoint

- R08 partial: replaced the IFB/MARK design with distinct source/destination IPv4 flower classifiers and independent HTB classes on the appliance egress path. Upload and download use separate rates and class IDs. New-limit partial failures remove acquired filters/classes in reverse order; failed updates restore the prior address and rates. Nine bandwidth/traffic tests pass. Real Linux throughput and classifier-counter measurements remain required.
- R10/R11/R19 partial: schema v4 stores per-device interception, blocking, content and bandwidth results. A per-MAC reconciler serializes changes, returns `pending` for unknown addresses, persists sanitized `error` results, replays every saved device at startup, and invalidates stale `applied` state before replay. Full blocking suspends bandwidth resources without deleting saved rules and removal reapplies the rule.
- Startup now prepares traffic control, resets/replays intent, and only then starts ARP interception. ARP targets can be staged without sending spoof packets before forwarding is enabled. Scan callbacks and manual scans invoke reconciliation so newly discovered and changed addresses retry pending work.
- Device and rule APIs include enforcement state. Mutations return HTTP 202 for accepted pending intent and HTTP 503 with `ENFORCEMENT_APPLY_FAILED` plus current component state when application fails. The dashboard labels pending/failed device protection separately, exposes migrated-rule validation errors and rule apply failures, and permits offline intent for later discovery.
- Current portable evidence: full backend suites pass 120 tests on Python3.12 and Python3.11. Node22 ESLint, TypeScript, all 11 frontend tests and the Vite production build pass; npm audit reports zero vulnerabilities. Git Bash accepts the installer syntax. The known approximately 612 kB bundle warning and Python3.12 deprecation warnings remain visible.
- Still open: the content component intentionally reports unavailable until the NFQUEUE inline engine exists; retry supervision beyond scan/startup, exact persistent kernel ownership, bandwidth accounting, coverage notices, production browser acceptance and disposable Linux namespace measurements remain required. This checkpoint does not complete R03, R08, R10, R11, R12, R16, R19, R21 or R24.

## Inline content enforcement checkpoint

- R03 partial: added an owned `PARENTAL_CONTENT` forwarding chain and a bounded NFQUEUE worker. Rules queue DNS over UDP/TCP and TLS over TCP for managed source addresses, force QUIC fallback by dropping managed UDP/443, and omit queue bypass so a missing userspace verdict does not silently allow intercepted traffic. Startup starts the worker before installing the forwarding hook; shutdown removes managed rules and the hook before stopping the worker.
- The pure inspector canonicalizes DNS names, reassembles TCP DNS and split/out-of-order TLS ClientHello records, extracts SNI across TLS records, bounds undecided flows by count/bytes/time, expires cached allow decisions, invalidates them on content-policy changes, and clears state on TCP FIN/RST. Malformed, exhausted and prematurely closed undecided flows fail closed.
- Firewall inventory accepts and removes only exact rules carrying `parental-control:content:*` ownership comments. Foreign rules in the named chain cause startup refusal. Partial rule installation rolls back exact additions. Unrelated bandwidth changes do not reinstall content rules or invalidate established content decisions.
- Block events originate after the queue worker has dropped every retained packet for the decision. Schema v5 and the access API/UI expose the matching rule ID, inspected protocol and verdict reason. A coverage notice describes IPv4 scope, DNS/SNI visibility, UDP/443 fallback and bypass limits.
- Dependency and installation metadata now include NetfilterQueue and its Linux build packages. CI installs the native library before Python dependencies.
- Portable evidence: 144 backend tests pass on Python 3.11 and Python 3.12. Fourteen Node22 frontend tests, ESLint, TypeScript/Vite production build and npm audit pass; installer shell syntax passes. The existing approximately 614 kB bundle warning and Python 3.12/upstream deprecation warnings remain.
- R03 remains partial until a disposable Linux namespace proves real kernel queue binding and actual UDP DNS, TCP DNS, split TLS/SNI and QUIC behavior. The portable tests use packet bytes and fake queue/firewall adapters; they do not prove privileged Linux enforcement or bypass resistance.

## Bandwidth telemetry checkpoint

- R16 portable implementation: the traffic controller reads byte totals only from the two owned HTB classes assigned to each active limit. The upload class maps to `bytes_sent`; the destination classifier's download class maps to `bytes_received`. Foreign/default class counters are ignored, and missing or malformed owned counters fail the poll instead of producing invented data.
- A supervised five-second accounting worker baselines counters at startup and whenever the device address/class identity changes. It persists only nonnegative deltas, handles directional counter resets independently, clears inactive baselines, and retains uncommitted deltas across database failures. Committed deltas are broadcast with matching values and UTC timestamps; broadcast, poll and prune failures have separate health counters.
- The worker prunes access and bandwidth records older than the configured 30-day retention window on the hourly maintenance cadence. Shutdown is bounded and cancels a stalled kernel poll while reporting the timeout. System stats expose accounting health alongside event-pipeline health.
- Portable evidence: counter mapping, baseline/no-traffic behavior, increments, resets, address reuse, persistence failure recovery, retention, poll recovery and bounded stop are covered. Full suites pass 150 tests on Python 3.11 and Python 3.12. All 14 Node22 frontend tests, TypeScript and ESLint pass.
- R16 still requires disposable-Linux controlled transfers compared with real `tc` counters, API/chart inspection and IP-header accounting documentation. The current evidence does not establish real kernel counter behavior or directional throughput accuracy.

## Discovery topology and deletion recovery checkpoint

- R24 portable coverage now probes interface MAC/IP, route and subnet off the event loop. Reverse DNS uses a bounded worker pool with per-result deadlines, so stalled names do not delay publishing discovered MAC/IP records; the pool can be shut down and recreated for repeated service cycles.
- Startup verifies that detected/configured appliance and gateway addresses belong to the selected subnet. Interception validation rejects the appliance IP, gateway IP/MAC, local MAC, subnet network/broadcast addresses and out-of-subnet addresses. The same guard now runs before bandwidth, app and domain rule persistence as well as block/monitor mutations.
- R19 deletion recovery now marks a rule inactive while kernel removal reconciles. A successful removal deletes the row; a failed removal reactivates saved intent, returns the structured 503 state and does not broadcast a false `deleted` update.
- Full portable suites pass 157 tests on Python 3.11 and Python 3.12. Remaining R24 acceptance includes multi-interface and real Linux topology tests plus proof that long-lived resolver calls terminate at process shutdown. Remaining R19 work includes full cross-route mutation serialization, DB failure injection and restart/concurrency acceptance.

## Full-block ownership and cleanup-state checkpoint

- R12 partial: `DeviceBlocker` now inventories its dedicated chain, refuses any foreign entry, removes only stale rules with exact `parental-control:block:*` comments, and installs one exact commented FORWARD hook. Per-device DROP rules carry deterministic ownership comments. INPUT is no longer modified. Startup rollback removes a newly acquired chain after hook failure, while shutdown removes only tracked blocks, the exact hook and the owned chain without flushing.
- R09/R19 partial: absent bandwidth removal is idempotent success. Unexpected bandwidth apply/remove exceptions and false removal results are converted to sanitized persisted component errors. The reconciler no longer reports every component inactive when stale block/content/bandwidth/interception cleanup fails after desired intent is removed.
- Full portable suites pass 163 tests on Python 3.11 and Python 3.12. Linux snapshot comparison, missing-rule retry, partial full-block cleanup failures and crash recovery remain required; this checkpoint does not complete R09 or R12.

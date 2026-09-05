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

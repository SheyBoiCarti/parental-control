# Parental Control remediation specification and agent handoff

**Date:** 2026-09-05

**Reviewed revision:** `c53e818296d227aed45c26764af78b1cdbb2b10e`

**Status:** Implementation underway on `fix/codebase-remediation`; see `docs/remediation-results.md` for verified progress and remaining acceptance.
**Goal:** Make installation, authentication, device management, traffic enforcement, reporting, and recovery behave as advertised, with reproducible evidence for every repaired defect.

## 1. Instructions for the implementing agent

Read this entire document, the repository's current instructions, and the referenced source before editing. Line numbers below identify the reviewed revision; use symbols if lines have moved. Preserve unrelated user changes. Implement the stages in section 7 in dependency order. Each stage must add failing regression tests, implement the fixes, run its checks, and record the results before progressing.

This document supplies the requirements and design decisions needed to execute the work without the original review conversation. Do not stop after fixing startup or replacing missing enforcement with mock behavior. Do not mark an issue resolved merely because an API returns success or a unit test sees the expected command string. Network enforcement requires the isolated Linux acceptance tests in section 8.

Use the applicable `superpowers:executing-plans` skill when available. Delegation is optional only when authorized by the executing session; this document does not require additional agents. The current deliverable is this specification, not permission to deploy or disrupt a live network.

Create `docs/remediation-results.md` during implementation. For each issue ID, record changed files, test command, actual result, and remaining limitations. Keep implementation checkboxes pending until their acceptance criteria pass. If Linux integration testing is unavailable, complete portable work and report the affected criteria as unverified; do not claim full completion.

### Scope and evidence

The original review covered FastAPI/Python, React/TypeScript, SQLite models, network components, installation, and systemd definitions. The Windows review environment did not run privileged network operations or a complete frontend build.

Evidence labels used here:

- **Reproduced:** A syntax/import check or an isolated execution demonstrated the failure. Network calls were replaced by fakes where stated.
- **Source-confirmed:** The implementation or missing connection between components is directly visible in the reviewed source. End-to-end impact still needs Linux/browser verification.
- **Additional inspection finding:** A related defect found while inspecting or preparing this handoff. These are included so the handoff covers more than the shortened review response.

No dependency vulnerability scan, penetration test, or claim of universal VPN/encrypted-DNS blocking was made. Missing dependency locks are a reproducibility finding, not evidence of a particular CVE.

## 2. Architecture and boundaries

Retain FastAPI, React, SQLite, Scapy discovery, and Linux traffic control. Add focused modules for authentication state, lifecycle reconciliation, owned firewall resources, inline enforcement, and accounting. Avoid a framework rewrite.

### 2.1 Desired state versus applied state

SQLite holds desired device settings and rules. A reconciler applies them to the network and records an explicit result. Existing `is_blocked`, `is_monitored`, and rule `is_active` values describe intent; they must not be presented as proof that protection is operating.

Add `enforcement` to device responses and rule responses. It contains `state` (`pending`, `applied`, `error`, or `inactive`), `last_error` (sanitized text or null), and `updated_at` (UTC ISO timestamp). Device responses also include per-component states for interception, blocking, content filtering, and bandwidth. Runtime state is reset/recomputed on startup; an old `applied` value must never survive as unverified truth.

Successful immediate application returns HTTP 200/201 and `applied`. Accepted intent awaiting device discovery returns HTTP 202 and `pending`. Application failure returns HTTP 503 with a stable error code and current desired/applied states. The UI must display pending/error states and never celebrate failed enforcement. A component being inactive because it is not requested is not an error.

The reconciler must serialize changes per normalized MAC, make repeated application idempotent, and retry pending work when discovery, addresses, rules, or component health change. Full-device blocking takes precedence over content and bandwidth rules without deleting those rules. Removing the full block reapplies remaining requirements.

### 2.2 Authentication decision

Use one persisted administrator credential source and server-side browser sessions. Store the administrator password hash and a credential version in dedicated database records, not publicly retrievable general settings. Seed an empty database from `AUTH_USERNAME` and `AUTH_PASSWORD_HASH`; subsequent restarts must not overwrite a password changed in the application. Migrate an existing `Setting.password_hash` with precedence over the original environment bootstrap hash, because that setting represents the user's later password change.

Provide a local CLI command to set/reset the administrator password when no credential exists. Without a configured credential, refuse normal network-exposed startup with an actionable message. Do not retain the current accept-any-credentials mode. Do not add an unauthenticated remote setup endpoint.

Browser authentication uses a random opaque session token in an HttpOnly cookie. Store only its hash server-side. Set SameSite=Strict, Path=/, and Secure for HTTPS. Sessions expire after 8 hours, are invalidated on logout/password change, and are checked for REST and WebSocket access. Cookie-authenticated mutations require a session-bound CSRF token and allowed Origin. Never put a password, session token, or password hash in localStorage or a WebSocket URL.

Preserve HTTP Basic support for explicit API clients, validating against the same current credential record. Basic must not exempt requests carrying a browser Origin from origin checks. Non-loopback deployments require HTTPS configuration; an explicitly named development-only insecure option may support local development and must not be the installer default. Use exact configured origins rather than wildcard credentialed CORS. Configure trusted proxy handling explicitly if TLS terminates upstream.

### 2.3 Supported network behavior

The existing product is an IPv4 ARP interception appliance on the same Ethernet broadcast domain as its devices. This remediation must make that topology work. It does not turn ARP interception into a tamper-proof router or guarantee control of traffic that bypasses the appliance.

Any device with monitoring, a full block, or an active content/bandwidth rule requires interception independently of the observation toggle. The gateway and appliance itself must never be valid managed targets. Unknown device IPs produce pending state. Address changes trigger classifier and target reconciliation.

Implement actual inline content decisions using application-owned iptables chains and an NFQUEUE-backed engine before traffic leaves the appliance. Scapy passive capture remains an observation tool, not the authority for whether a packet was blocked. Queue only relevant traffic from managed devices. A packet is logged as blocked only after an actual drop/reject verdict is applied; rule matches alone are not blocked events.

The initial supported filtering contract is ordinary DNS over UDP/TCP port 53 and TLS ClientHello SNI over TCP port 443. Restricted devices' UDP/443 traffic must be blocked explicitly to prevent QUIC from silently bypassing that contract; explain the fallback in product documentation. Handle split TCP DNS messages and fragmented TLS ClientHello records with bounded per-flow reassembly. Use a 64 KiB inspection budget per flow, a 5-second inspection deadline, and at most 1,024 concurrent undecided flows by default. For devices with content restrictions, malformed/over-budget/timed-out undecidable inspected flows are dropped with a distinct reason; unrelated traffic must not be queued or affected. Do not label an allowed unmatched domain as an app block.

The worker must issue verdicts before releasing protected data. Handle retransmissions, connection expiration, worker failure, and queue overload explicitly. For already intercepted protected traffic, worker failure must not silently enable queue bypass; publish an error and retain restrictive handling until recovery or explicit removal of the protection. Clean shutdown restores direct network access and reports protection inactive. After process/host failure and ARP cache expiry, appliance bypass remains a documented topology limitation.

IPv6, encrypted ClientHello, encrypted DNS, VPN tunneling, nonstandard application ports, MAC spoofing, and alternate gateways are not guaranteed controlled by this IPv4 design. Show a persistent coverage notice in Settings and device protection views; do not claim complete network blocking across protocols. Do not infer absence of IPv6 bypass from tests using only IPv4. A router/bridge enforcement redesign is a separate project, not an undocumented addition to this repair.

NFQUEUE supplies userspace verdicts; `NF_DROP` is an actual drop, whereas returning a match from Python is not enforcement. See the primary [Netfilter verdict documentation](https://netfilter.org/projects/libnetfilter_queue/doxygen/html/group__nfq__verd.html). Verify the selected Python binding and queue dependency installation on the Linux target before adopting them.

### 2.4 Resource ownership and lifecycle

All firewall chains, hooks, accounting rules, and traffic-control handles must be identifiable as owned by this application. Do not flush shared chains, delete arbitrary MARK rules, replace another service's root qdisc, or clear other services' marks. Reserve and mask only the application's mark bits if marks are used. Inventory existing resources before changes; if an incompatible root qdisc exists, fail with a useful error instead of replacing it.

Prefer destination/source IPv4 classifiers on the appliance's egress path for this single-interface topology: destination device IP identifies download, source device IP identifies upload. Use separate classes/filters for the two directions and a documented handle allocator. Avoid the current unclassified IFB download path; remove IFB setup if it is no longer needed. If the executing agent retains IFB, it must prove hook ordering and directional classification with the same acceptance tests, not just create classes.

Startup and shutdown must manage partially initialized components. Record original forwarding settings and restore only settings this application changed. Never start interception before forwarding and required enforcement are ready. Stop background workers with explicit wakeup/stop APIs and bounded waits rather than waiting for unrelated network traffic.

## 3. Complete issue register

### R01 — Backend entry point cannot compile

**Priority:** P0. **Evidence:** Reproduced. **Source:** `backend/main.py:302-334`, `main()`.

**Cause/impact:** `API_PORT` and `API_HOST` are read before their `global` declaration. Compiling the source raises `SyntaxError: name 'API_PORT' is used prior to global declaration`; no startup path works.

**Fix:** Prefer passing validated host/port/interface options into the application/server configuration instead of mutating module globals. At minimum remove the illegal declaration order. Argument parsing and `--help` must work without root, database writes, packet capture, or network commands.

**Acceptance:** Compile every backend source. Run `python backend/main.py --help` as a non-root user. Test that explicit host/port/interface options reach the server/component factory and override configuration defaults.

### R02 — Authentication dependency raises during import

**Priority:** P0. **Evidence:** Reproduced. **Source:** `backend/api/auth.py:57`, `optional_auth()`.

**Cause/impact:** `Security(security, auto_error=False)` passes a parameter not accepted by FastAPI's dependency wrapper. Importing the API raises `TypeError`, even after R01 is corrected.

**Fix:** Put `auto_error=False` on an `HTTPBasic` instance when optional Basic parsing is actually required, then pass that instance to `Security`. Remove unused optional authentication if the R04 design makes it unnecessary. Missing credentials on protected endpoints must still be rejected.

**Acceptance:** Import the auth module and construct the app in a temporary test configuration without side effects. Missing/malformed/incorrect authentication returns a controlled 401, not 500; valid authentication reaches a protected test route.

### R03 — Content blocking only records matches

**Priority:** P1. **Evidence:** Source-confirmed. **Sources:** `backend/main.py:_setup_packet_callbacks`, `backend/core/content_blocker.py:should_block`, `backend/core/packet_analyzer.py`.

**Cause/impact:** Matching DNS/SNI callbacks merely log `blocked`. No packet drop, DNS blocking response, or inline forwarding decision exists. Even repairing logging does not enforce rules.

**Fix:** Implement section 2.3's inline engine. Keep matching pure and separate from packet verdicts. Publish an enforcement event containing normalized MAC, domain, rule ID, action, protocol, reason, and timestamp only after the relevant verdict. Enforce rule changes on existing cached decisions; do not let a previously allowed flow bypass a newly applied block indefinitely. Log any deliberate connection invalidation as such. Do not solve this by only resolving domain IPs: shared hosting, caches, and new addresses make that insufficient.

**Acceptance:** In isolated Linux networking, blocked UDP DNS, TCP DNS, and blocked TLS SNI fail while allowed equivalents succeed. Include split ClientHello, retransmission, mixed-case domain, apex/subdomain wildcard, malformed input, queue-worker failure, rule removal, already-open flow policy change, and UDP/443 cases. Check actual upstream receipt/connection outcome and verdict-derived logs, not console messages.

### R04 — Changed passwords do not affect login; hashes leak through settings

**Priority:** P1. **Evidence:** Source-confirmed. **Sources:** `backend/api/routes/settings.py:98-125`, `backend/api/auth.py:9-45`, general settings GET/PUT routes.

**Cause/impact:** Password changes update `Setting.password_hash`; authentication reads the import-time environment hash. Old credentials remain valid or checking remains disabled. General settings responses expose the stored hash and generic writes can modify reserved credential keys.

**Fix:** Implement section 2.2's canonical credential store and bootstrap/migration precedence. Require a valid current session plus current-password verification for password changes. Keep the existing minimum of 8 characters and reject passwords exceeding bcrypt's 72 UTF-8-byte input limit with 422; never silently truncate. Hash off the event loop. Commit the new hash/version atomically, invalidate all sessions and associated sockets, and require login again. Exclude credentials/session data from generic settings reads and reject writes to reserved keys. Provide a local reset command with hidden password entry.

**Acceptance:** Set password A, change to B, prove A fails and B succeeds immediately and after restart. Prove old cookies and open sockets are invalidated. Exercise no-bootstrap credential, environment/bootstrap versus saved-setting migration precedence, failed DB commit, Unicode byte limits, reserved settings keys, and response/log redaction.

### R05 — `.env` and documented network overrides are ineffective

**Priority:** P1. **Evidence:** Source-confirmed. **Sources:** `backend/config.py`, `backend/main.py`, `backend/core/device_manager.py:initialize`, `scripts/install.sh:112-149`, `systemd/parental-control.service`, `README.md`.

**Cause/impact:** Configuration only calls `os.getenv`; neither entry point nor service loads `.env`. The installer writes a file that is ignored. The documented `.env.example` is absent. `GATEWAY_IP`/`NETWORK_SUBNET` are defined but not applied to device initialization.

**Fix:** Add a typed configuration loader using an explicit `backend/.env` path independent of cwd. Precedence: CLI > process environment > `.env` > defaults, except persisted credentials have the precedence in R04. Use one loader before constructing components; eliminate import-time configuration snapshots. Add `.env.example` with safe empty placeholders, address/interface validation, HTTPS/origin settings, and queue/accounting defaults. Respect gateway/subnet overrides and require discovered/default gateway interface to match the selected interface. Preserve existing configuration on installer reruns; do not reset an existing password. Restrict `.env` permissions to the service owner. Align both service definitions with the same supported loader.

**Acceptance:** Tests cover alternate cwd, precedence, invalid values, interfaces other than eth0, explicit gateway/subnet, bootstrap password containing bcrypt dollar signs, and installer rerun preservation. A temporary `.env` must affect a constructed config without exporting shell variables. A missing password must never fall back to accept-any login.

### R06 — WebSocket telemetry is unauthenticated

**Priority:** P1. **Evidence:** Reproduced with a fake socket invoking the real standalone handler. **Sources:** `backend/api/app.py:ws_endpoint`, `backend/api/websocket.py:39,126`, `frontend/src/contexts/WebSocketContext.tsx`.

**Cause/impact:** Every connection is accepted and subscribed to all broadcasts, including device identifiers, access logs, and rule changes. REST password protection does not protect this channel; origins are unchecked.

**Fix:** Validate session and exact browser Origin before `accept()`. Associate the socket with the session so expiry, password change, and logout close it. Do not expose Basic credentials in the URL. Start browser connections only after authentication is confirmed. Bound each client's outbound queue and disconnect persistently slow clients so telemetry cannot block all users or DB logging.

**Acceptance:** Real ASGI WebSocket tests reject missing, expired, invalid, revoked, and wrong-origin sessions before any data. A valid session receives an event. Revocation closes an already-open socket. A slow/failing client does not prevent a second client receiving broadcasts.

### R07 — Packet callbacks schedule coroutines from the wrong thread

**Priority:** P1. **Evidence:** Reproduced: `RuntimeError: no running event loop`. **Sources:** `backend/main.py:140,145,157`, `backend/core/packet_analyzer.py:292`.

**Cause/impact:** Capture runs in an executor thread, while callbacks invoke `asyncio.create_task`. Access log writes never execute and coroutines may be leaked.

**Fix:** Capture the application loop during startup. Use `loop.call_soon_threadsafe` to enqueue immutable events into a bounded asyncio queue, with a loop-side nonblocking enqueue function catching QueueFull. A supervised consumer batches DB writes and broadcasts committed events. Use a default queue capacity of 10,000 events, flush at 100 records or 1 second, and expose queue overflow/write failure counters. Give each event a stable ID with a database uniqueness constraint so batch retries cannot duplicate access records. Retry transient writes with bounded backoff; on exhaustion increment a lost-event counter and expose degraded telemetry without changing enforcement verdicts. Never create a coroutine in the capture thread and abandon it. Separate observation events from R03's actual enforcement events to avoid double logging.

**Acceptance:** Invoke the real callback from a worker thread and prove exactly one expected event reaches a temporary DB. Cover queue full, failed DB write, retry/duplicate handling, loop closing, shutdown drain, and callback during shutdown. Fail tests on unawaited-coroutine warnings.

### R08 — Download shaping has no classifier

**Priority:** P1. **Evidence:** Source-confirmed; mocked command trace contained zero IFB classification filters. **Source:** `backend/core/traffic_controller.py:204-230`.

**Cause/impact:** Download classes are created but never selected by traffic. API/UI reports a download limit that is not enforced.

**Fix:** Implement directional classification described in section 2.4. Pass resolved device addresses to traffic control through the reconciler. Allocate separate upload/download classes, apply rates in Kbps consistently, and update classifiers after DHCP changes. Remove stale classes/filters when a rule is replaced/deleted. Preserve unrelated traffic. Address class-handle encoding explicitly; do not mix hexadecimal tc handles with decimal mark values unintentionally.

**Acceptance:** Run upload and download separately and concurrently using two devices and asymmetric limits. With a 60-second run and 10-second warmup excluded, measured payload throughput must stay below configured rate +15%; in an otherwise idle lab it must reach at least 70% of the configured rate. Demonstrate an unregulated control transfer exceeds the low test cap, so a broken link cannot pass. Test DHCP change, limit replacement, rule deletion, restart, and a second unaffected device.

### R09 — System command failures become false success

**Priority:** P1. **Evidence:** Reproduced with every system command returning failure: initialization and `set_bandwidth_limit` still report success. **Sources:** `backend/utils/network_utils.py:182-200`, `backend/core/traffic_controller.py`, `backend/core/device_blocker.py:initialize,unblock_device`.

**Cause/impact:** `run_command(check=True)` catches and returns failures, while callers assume exceptions indicate failure. Device unblock also discards internal state despite failed deletion. Actual kernel state and API state diverge.

**Fix:** Use a single explicit command contract: `check=True` raises a typed command error for nonzero exit, missing executable, and timeout; `check=False` returns the exit result for intentional probes. Include a bounded default timeout of 10 seconds and sanitized diagnostics. Run blocking commands outside the API event loop. Inspect all probe results. Mark initialized/applied only after required commands and verification succeed. Roll back resources created by a failed operation; retain error state if rollback fails. Never remove a tracked block until kernel removal is confirmed.

**Acceptance:** Failure injection at each setup/apply/remove step must produce error state and no success response. Test missing tc/iptables, timeout, failure after partial class creation, failed unblock, rollback failure, and repeated retry. Record kernel-state verification in Linux tests.

### R10 — Saved monitoring and bandwidth do not resume

**Priority:** P1. **Evidence:** Source-confirmed. **Sources:** `backend/main.py:197-230`, `backend/core/arp_spoofer.py:__init__`, `backend/core/device_manager.py:get_monitored_devices`, `backend/core/traffic_controller.py:initialize`.

**Cause/impact:** ARP targets start empty; scans only update targets already present. Saved bandwidth rules are never loaded after tc cleanup. Persistent flags falsely suggest protections survived restart.

**Fix:** Run reconciliation against all persisted devices and active rules after dependency initialization and initial discovery. Construct targets for every device requiring interception. Reapply content, full blocks, and bandwidth idempotently. Reconcile on address changes and device return. Unknown addresses remain pending. Do not rely on a UI toggle or manually recreating a rule to activate saved intent.

**Acceptance:** Persist a monitored device, blocked unmonitored device, content rule, and bandwidth rule. Restart twice; verify target sets and measured enforcement without UI interaction and without duplicate hooks/classes. Test offline-at-start then discovered, changed address, disabled rule, and partial restoration failure.

### R11 — Blocking does not put traffic through the firewall

**Priority:** P1. **Evidence:** Source-confirmed; topology acceptance remains required. **Sources:** `backend/api/routes/devices.py:134-163`, `backend/core/device_blocker.py`, ARP target management.

**Cause/impact:** Blocking only installs a rule on this host. An ordinary unmonitored LAN device still sends traffic directly to its gateway and avoids that rule.

**Fix:** Route all mutations through reconciliation. Compute interception requirement as monitoring OR full block OR any active enforcement rule. Turning observation off must not remove interception needed by another protection. On unblocking, retain interception if other reasons remain; restore ARP only when no reasons remain. Refuse appliance/gateway targets. Publish the IPv4/ARP coverage limitation rather than claiming an unconditional full-network block.

**Acceptance:** On a same-LAN appliance fixture, block an initially unmonitored device and prove its IPv4 internet flow fails. Toggle monitoring off while blocked and prove it remains blocked. Unblock with and without remaining rules and verify appropriate connectivity/target state. Reject gateway/appliance MACs through every mutation route.

### R12 — Cleanup destroys resources it does not own

**Priority:** P1. **Evidence:** Source-confirmed. **Source:** `backend/core/traffic_controller.py:_cleanup,_cleanup_iptables_marks`.

**Cause/impact:** Startup/shutdown deletes all shared PREROUTING MARK rules and removes root/ingress qdiscs without ownership checks. Other routing/QoS services can break.

**Fix:** Create dedicated owned chains and remove exact owned jump/rule specifications. Track allocated tc resources, mark masks, and interface handles. Do not identify ownership by substring or shared-chain line number. Refuse incompatible existing qdiscs instead of wiping them. Recovery must distinguish stale application resources from unrelated configuration.

**Acceptance:** Seed unrelated MARK/CONNMARK rules and a foreign qdisc. Attempt startup, apply, failure recovery, and shutdown. Compare foreign resource snapshots before/after and verify preservation; incompatible qdisc must yield a clear controlled error. Repeated cleanup must be safe when owned resources are already absent.

### R13 — Production dashboard assets are never served

**Priority:** P1. **Evidence:** Source-confirmed. **Sources:** `scripts/install.sh:98-99`, `backend/api/app.py:create_app`, `README.md`.

**Cause/impact:** Installer copies assets to `backend/static`, but FastAPI has no static serving or SPA fallback. Documented dashboard URL returns 404.

**Fix:** Serve built assets from an absolute path rooted in the installation. Register API, health, and WebSocket routes before a GET-only SPA fallback. Return index.html for valid client routes such as `/devices/<mac>` and `/settings`; unknown `/api/*` and missing asset files must remain 404. Prevent path traversal. Support explicit API-only development without pretending the dashboard is installed. Normal dashboard installation must build or obtain assets and verify their presence rather than silently skipping them.

**Acceptance:** Test `/`, `/login`, `/settings`, direct device deep link, a hashed JS/CSS asset, missing asset, `/api/does-not-exist`, `/health`, and a traversal attempt. Run a production preview through the backend, not only Vite's dev server.

### R14 — Frontend has strict compilation and lint setup gaps

**Priority:** P1. **Evidence:** Source-confirmed; full build not run in review. **Sources:** `frontend/src/App.tsx:2`, `frontend/src/contexts/AuthContext.tsx:2`, `frontend/tsconfig.json:15`, `frontend/package.json`, `frontend/vite.config.ts`.

**Cause/impact:** Unused `useState`, `useEffect`, and `healthCheck` imports violate `noUnusedLocals`. The lint script exists but no ESLint configuration or TypeScript parser configuration is present. These block installation/quality checks rather than proving a runtime UI defect.

**Fix:** Remove unused imports and repair all real compiler diagnostics. Keep strict and unused checks enabled. Add a working TypeScript/React ESLint configuration with required packages, or update the script and config coherently to the chosen supported tool version. Check Vite's Node typings/config too. Commit a frontend lockfile and use `npm ci` in installer/CI. Do not suppress errors wholesale or disable scripts to get a green build.

**Acceptance:** From a clean dependency installation, `npm ci`, `npm run build`, and `npm run lint` all exit zero. Generated production assets load with no browser console errors. Record the resolved Node/npm and TypeScript versions.

### R15 — WebSocket reconnect handler is overwritten

**Priority:** P2. **Evidence:** Source-confirmed. **Source:** `frontend/src/contexts/WebSocketContext.tsx:31-102`.

**Cause/impact:** `onopen` replaces `onclose` with ping cleanup only. Once connected, a later disconnect no longer clears connection state or schedules reconnect. Unmount can also schedule a reconnect after cleanup.

**Fix:** Keep one close handler responsible for timer cleanup, disconnected state, and bounded reconnect. Use refs for socket/timers/subscribers and a disposed/authenticated guard. Use exponential delays of 1, 2, 4, 8, 16, then 30 seconds with small jitter; reset after successful connection. On logout, expiry, or unmount, stop all timers and prevent reopening. Clean up failed attempts and React StrictMode effect cycles.

**Acceptance:** Fake-timer/browser tests cover successful open then close, initial failure, repeated failure, reconnect with subscriptions, logout, unmount, and StrictMode remount. There must be only one active socket and one ping timer, and no post-unmount reconnection.

### R16 — Bandwidth history has no writer

**Priority:** P2. **Evidence:** Source-confirmed. **Sources:** `backend/db/models.py:BandwidthLog`, `backend/api/routes/stats.py:127`, `backend/core/traffic_controller.py:BandwidthMonitor`, `backend/api/websocket.py:broadcast_bandwidth_stats`.

**Cause/impact:** Stats queries read a table no code populates. The unused monitor maintains in-memory zeros; charts have no actual history.

**Fix:** Add owned per-device forwarded IPv4 byte counters keyed by resolved source/destination addresses. Count upload/download once per forwarded packet, not both ingress and egress captures. Poll every 5 seconds; persist counter deltas with UTC timestamps and broadcast matching deltas. Baseline counters after startup/reset; never emit negative deltas or attribute another device's reused IP traffic to the old device. Keep capture/protection accounting definitions explicit. Prune access and bandwidth logs older than 30 days on an hourly maintenance task; retain the existing API's maximum 168-hour query window.

**Acceptance:** Controlled transfers populate both directions, DB totals, API history, and chart data. Compare totals with the chosen kernel counters and document whether IP headers are counted. Test resets, restart, DHCP reuse, no traffic, UTC hour boundaries, polling failure, retention, and no double counting.

### R17 — Live scan snapshots erase offline devices

**Priority:** P2. **Evidence:** Source-confirmed. **Sources:** `backend/core/device_manager.py:update_devices_from_scan`, `backend/main.py:on_device_scan`, `backend/api/routes/devices.py:trigger_scan`, `frontend/src/pages/Devices.tsx:43-44`.

**Cause/impact:** Scan results contain only devices seen in that scan, but `devices_list` replaces the entire UI collection. Persisted offline devices disappear and the offline filter becomes misleading.

**Fix:** Define `devices_list` as a complete persisted snapshot. After updating discovery state, query all devices for manual scan responses and broadcast snapshots. Keep `device_update` as an upsert for a single device; support newly discovered devices. Preserve the 5-minute offline threshold and distinguish scan failure from a successful empty scan. Use full persisted/address state for interception bookkeeping, not only the latest successful responders.

**Acceptance:** Start with two devices; stop one responding, run scans, advance past the threshold. Both remain listed and the absent device becomes offline. Manual scan and automatic broadcasts agree. A failed scan must not erase devices or mark the entire network offline. Test live update of a previously unseen device.

### R18 — Browser login trusts failures and stores raw passwords

**Priority:** P1. **Evidence:** Additional inspection finding, source-confirmed. **Sources:** `frontend/src/contexts/AuthContext.tsx:18-67`, `frontend/src/api/client.ts:auth helpers`, `frontend/src/App.tsx`.

**Cause/impact:** Startup trusts credentials merely because localStorage contains them. Network errors and most HTTP failures are treated as successful login. Passwords remain readable in localStorage. This grants misleading UI access even when backend authentication is unavailable; it is not by itself proof that protected REST endpoints are bypassed.

**Fix:** Implement the session APIs in section 5. Initialize from `/api/auth/session`; confirm login only on the dedicated successful login response. Treat 401 as invalid credentials and network/5xx as service errors. Remove legacy `localStorage.auth` on startup/migration and stop using browser Basic headers. Centralize 401 handling so the session, UI, and socket clear together without redirect loops. Use HTTPS as specified in section 2.2.

**Acceptance:** Invalid credentials, stale storage, offline server, 500, and 503 never set authenticated state. Valid login survives page reload through the session cookie. Logout removes access immediately. Browser storage and captured URLs contain no password/token. Error messages distinguish connection failure from wrong password.

### R19 — Mutations save intent and report it as successful enforcement

**Priority:** P1. **Evidence:** Additional inspection finding, source-confirmed. **Sources:** `backend/api/routes/devices.py:update_device,block_device,unblock_device,start_monitoring`, `backend/api/routes/rules.py:create_bandwidth_rule,delete_rule`, `frontend/src/components/RuleEditor.tsx`.

**Cause/impact:** Routes commit flags/rules before applying network changes, ignore results in several paths, and publish desired state as if applied. Rule editor callbacks are typed as synchronous and reset fields before an asynchronous operation succeeds. Concurrent changes can leave inconsistent state.

**Fix:** Implement section 2.1 for all mutation routes, including PATCH and convenience endpoints, through one service. Await asynchronous editor callbacks typed as `Promise<void>`; preserve input and show actionable errors on failure. Serialize per-device apply operations; return server-confirmed state rather than optimistic flags. For deletion, retain an error/tombstone until actual removal succeeds, or restore the desired rule and clearly report the failure; choose the tombstone approach consistently and exclude tombstones from active matching. Reconciliation must complete removal after restart.

**Acceptance:** Inject DB, iptables, tc, and ARP errors on each route; no failed operation appears applied. Exercise concurrent block/unblock, rule create/delete, duplicate retries, no known IP, and failed deletion followed by restart. Frontend inputs remain available after failure and controls prevent duplicate in-flight submission.

### R20 — Domain rule normalization and duplicate handling disagree

**Priority:** P2. **Evidence:** Additional inspection finding, source-confirmed. **Sources:** `backend/api/routes/rules.py:create_domain_block_rule,delete_rule`, `backend/core/content_blocker.py:add_domain_block,remove_domain_block,should_block`, `backend/utils/mac_utils.py:normalize_mac`.

**Cause/impact:** API creates duplicate domain DB rows while memory deduplicates by value. Deleting one row removes in-memory enforcement despite another remaining row. Wildcard matching does not lowercase the wildcard base. Invalid MACs raise unhandled ValueError. Domain input accepts arbitrary/empty patterns.

**Fix:** Canonicalize MACs and domain rules at API boundaries. Domains are lowercase IDNA ASCII without a trailing dot; allow exact names and only a leading `*.` wildcard, not schemes, paths, empty labels, whitespace, or arbitrary glob syntax. Exact rules match the exact name; `*.example.com` matches apex and descendants, not `badexample.com`. Return 422 for invalid input. Add canonical rule values and uniqueness for device/type/value, with a single bandwidth rule per device. Migration must deduplicate existing equivalent rules without losing an active restriction. Rebuild matching from authoritative active rows after changes instead of blindly removing by string.

**Acceptance:** Duplicate/concurrent requests return the existing canonical rule, not conflicting rows. Test deletion with migrated duplicates, mixed-case wildcard, apex, unrelated suffix, trailing dot, IDNA, invalid MAC/domain, and canonicalization after restart. Enforce input limits before DB writes.

### R21 — Shutdown and partial-start failure can leave workers/resources running

**Priority:** P1. **Evidence:** Additional inspection finding, source-confirmed; quiet-network hang needs runtime regression. **Sources:** `backend/core/packet_analyzer.py:stop`, `backend/main.py:run,initialize,start_services,stop_services`, `backend/core/arp_spoofer.py`.

**Cause/impact:** Capture's stop filter only runs after another packet; `stop()` sleeps and discards the future without joining the worker. Initialization occurs outside the cleanup `try/finally`; an error can leave earlier mutations in place. The custom shutdown event is set but never awaited, alongside Uvicorn signal handling. Forwarding changes are not restored.

**Fix:** Use a capture mechanism with explicit stop/wakeup and await its termination even on a silent interface. Put acquisition/startup in a lifecycle manager with reverse-order cleanup registered after each successful acquisition. Use a single signal ownership path integrated with server shutdown. Drain bounded event queues, stop accounting/enforcement workers, restore ARP, and remove owned resources in a documented order that avoids leaving poisoned peers without forwarding. Restore only owned forwarding changes. Bound application shutdown to 10 seconds, beneath systemd's 30-second stop budget, and expose incomplete cleanup in logs.

**Acceptance:** Start/stop on a quiet interface, repeated start/stop, SIGTERM, capture startup failure, failure after each initialization step, queue drain timeout, and cleanup failure all terminate predictably. No lingering capture threads, tasks, owned hooks, or accidental foreign-resource removals. Test recovery from stale owned resources after a simulated crash.

### R22 — Advertised app catalog is disconnected from runtime signatures

**Priority:** P2. **Evidence:** Additional inspection finding, source-confirmed. **Sources:** `data/app_signatures.json`, `backend/config.py:APP_SIGNATURES_FILE`, `backend/db/database.py:init_app_signatures`, `backend/core/content_blocker.py:_load_app_signatures`, `README.md:Supported Apps`.

**Cause/impact:** Runtime seeds a separate hardcoded subset, while the bundled signature file is not read. README advertises applications that are not selectable from that runtime catalog. Existing seed records are never refreshed.

**Fix:** Make the bundled JSON the canonical built-in catalog, with schema/version validation and normalized domain patterns. Import/update built-in records idempotently at startup/migration while preserving explicitly custom records. Add version tracking so updates refresh builtin domains and the live matcher. Return display names and stable identifiers from the available-apps API. Align README with shipped catalog and filtering limitations; do not claim signature coverage guarantees all app traffic is blocked.

**Acceptance:** Every advertised selectable app exists in the API and matches its shipped test domains. Repeated initialization makes no duplicates. A changed built-in signature updates while custom entries survive. Corrupt catalog produces an actionable startup error, and removed/unknown app references remain visible as unresolved rules rather than silently disappearing.

### R23 — No automated safety net or reproducible dependency installation

**Priority:** P1. **Evidence:** Additional inspection finding, source-confirmed repository inventory. **Sources:** `backend/requirements.txt`, `frontend/package.json`, absent test/CI/lock configuration.

**Cause/impact:** No automated tests or CI were found. Python dependencies have only lower bounds; frontend has no lockfile. Installation can resolve different versions, and fundamental startup errors went undetected.

**Fix:** Add pytest/pytest-asyncio with temporary SQLite and injected network adapters, frontend component tests with fake timers, and Playwright browser smoke tests. Commit reproducible Python constraints/lock input and output and `package-lock.json`; record their regeneration commands. Test Python 3.11 and 3.12 and Node 22 in CI as explicit supported targets. Add a default portable CI job plus a separate Linux integration job using only disposable networking. Add `.gitignore` entries for environments, node_modules, builds, secrets, databases, logs, coverage, and browser artifacts. Keep example configuration/catalog tracked.

**Acceptance:** A clean checkout can install from locks and run the section 8 commands. Portable tests never call real iptables/tc/ARP or write the normal data directory. CI catches R01/R02/R14 regressions. Linux job publishes packet/counter/assertion artifacts and cleans up its namespaces on failure. Document the exact tested distributions/kernel and dependency versions rather than claiming every Linux distribution was verified.

### R24 — Discovery blocks the event loop and can expose the gateway as a target

**Priority:** P1. **Evidence:** Additional inspection finding, source-confirmed. **Sources:** `backend/core/device_manager.py:scan_network,initialize`, `backend/utils/network_utils.py:get_hostname_from_ip,get_default_gateway`, `backend/api/routes/devices.py`.

**Cause/impact:** An async function calls blocking `srp` and reverse DNS sequentially. During scans the event loop cannot promptly serve HTTP, sockets, logging, or spoof refresh. A comment promises to skip the gateway but code skips only the local MAC; gateway selection also ignores the requested interface.

**Fix:** Run blocking discovery/resolution off the event loop with bounded concurrency and timeouts. Cache reverse DNS separately; a slow hostname lookup must not prevent publishing MAC/IP discovery. Resolve the gateway on the selected interface and honor explicit validated overrides. Exclude gateway/local addresses from controllable devices, and enforce that invariant again in every mutation service rather than trusting the list. Distinguish failed scans from successful empty results.

**Acceptance:** During a simulated 5-second ARP scan and stalled reverse DNS, a health/session request and a spoof timer remain responsive within 500 ms in the controlled test. Verify multiple interfaces, overrides, gateway/local filtering, direct API attempts against those addresses, failed scan handling, and bounded worker cleanup.

## 4. File responsibilities

Existing files may be split only where these responsibilities require it. Proposed new paths are concrete targets; equivalent small modules are acceptable if the results document maps the final names.

| File | Required responsibility |
| --- | --- |
| `backend/config.py` | Explicit validated runtime config loader with deterministic precedence |
| `backend/main.py` | CLI parsing and application lifecycle orchestration |
| `backend/api/app.py` | Dependency wiring, auth/session routes, CORS, readiness, static assets |
| `backend/api/auth.py` | Shared REST/WS authentication dependencies; no import-time credential snapshot |
| `backend/api/routes/auth.py` (new) | Login, session check, logout and CSRF/session responses |
| `backend/core/auth_service.py` (new) | Canonical credentials, session creation/revocation, password change |
| `backend/core/reconciler.py` (new) | Per-device desired/applied state, target requirements, retries |
| `backend/core/firewall.py` (new) | Owned resource setup/probes/removal and directional rule specs |
| `backend/core/enforcement.py` (new) | Inline queue worker, bounded flow inspection, packet verdicts |
| `backend/core/event_pipeline.py` (new) | Thread-safe telemetry ingestion, batching, overflow/error metrics |
| `backend/core/bandwidth_monitor.py` (new) | Owned counter polling, deltas, persistence and retention |
| `backend/core/content_blocker.py` | Pure normalized rule matching and catalog-backed snapshots |
| `backend/core/device_manager.py`, `arp_spoofer.py` | Bounded discovery and explicit interception target lifecycle |
| `backend/core/traffic_controller.py`, `device_blocker.py` | Verified resource application behind reconciliation |
| `backend/utils/network_utils.py` | Explicit command outcomes/timeouts and interface-bound network queries |
| `backend/db/models.py`, `database.py`, `migrations.py` (new) | Versioned schema migration, constraints, credentials, desired/applied records |
| `backend/api/routes/devices.py`, `rules.py`, `settings.py`, `stats.py` | Validated contracts invoking services and exposing truthful state |
| `backend/api/websocket.py` | Authenticated session-bound clients and bounded outbound queues |
| `frontend/src/api/client.ts`, auth/WS contexts | Cookie sessions, errors, reconnect lifecycle, typed contracts |
| `frontend/src/pages/*`, `components/RuleEditor.tsx` | Applied/pending/error UX, coverage notice, accurate histories |
| `backend/.env.example`, `scripts/install.sh`, `systemd/parental-control.service` | Repeatable installation, supported config, complete asset/service delivery |
| `backend/tests/`, `frontend/src/**/*.test.tsx`, `frontend/e2e/` (new) | Portable regression, UI, browser tests |
| `tests/integration/` (new), `.github/workflows/ci.yml` (new) | Disposable Linux enforcement tests and automated gates |
| `README.md`, `docs/remediation-results.md` | Correct setup/support claims, migration/run commands, measured evidence |

## 5. Interfaces and migration contracts

### Authentication API

- `POST /api/auth/login`: JSON `{username, password}`. On success set session cookie and return `{username, csrf_token, expires_at}`; invalid credentials return 401, unavailable auth store 503. Never return a password hash, raw session token, or password in JSON; the CSRF token is intentionally returned to the authenticated browser. Use a process-wide limit of 5 failed logins per source address per minute with a bounded expiring key store; return 429 with Retry-After. Do not trust arbitrary forwarded IP headers.
- `GET /api/auth/session`: validate session and return `{username, csrf_token, expires_at}` or 401. A service readiness failure is not a successful login response.
- `POST /api/auth/logout`: authenticated and CSRF-protected, revoke current session and close its sockets, clear cookie; repeat logout may return 204.
- `POST /api/settings/password`: authenticated and CSRF-protected for browsers, JSON `{current_password, new_password}`; after successful change invalidate all sessions and clear cookie. CLI reset follows the same credential-version invalidation path.
- Keep `/health` as minimal liveness. Add `/ready` for component initialization/reconciliation service readiness; sanitized component states belong in an authenticated diagnostics endpoint. A configured offline device with pending protection does not by itself make the whole API unready.

### Internal contracts

Implement typed equivalents of these signatures and use one definition across modules:

```python
load_config(env_file: Path | None, cli_overrides: dict[str, object]) -> AppConfig
await command_runner.run(argv: list[str], *, check: bool = True,
                         timeout: float = 10.0) -> CommandResult
await reconciler.reconcile_device(mac: str) -> EnforcementResult
await reconciler.reconcile_all() -> list[EnforcementResult]
await auth_service.authenticate(username: str, password: str) -> AdminIdentity
await auth_service.validate_session(raw_token: str) -> SessionIdentity
content_blocker.match(mac: str, domain: str) -> RuleMatch | None
event_pipeline.submit_threadsafe(event: AccessEvent) -> None
```

`CommandResult` contains `returncode`, `stdout`, and `stderr`; exceptions carry sanitized command context. `EnforcementResult` contains normalized MAC, per-component state, overall state, last error, and timestamp. `RuleMatch` contains rule ID/type/canonical value. `AccessEvent` contains an event ID, UTC timestamp, MAC, domain, protocol, action (`observed_allowed` or `blocked`), matched rule ID if applicable, and reason. Map observed allowed to the existing public `allowed` action for backward compatibility. Do not treat passive observation as proof every packet in a flow was allowed.

### Schema and compatibility

Use explicit schema-versioned migrations; `create_all` alone cannot upgrade existing installations. Back up the database before migration. Preserve device IDs, friendly names, rules, and historical logs. Migrate legacy password settings into private credential records, then remove secret keys from general settings. Deduplicate normalized rules, add the required uniqueness constraints, and enable SQLite foreign-key enforcement on every connection.

Existing device/rule URLs and basic response fields remain available. Extend their response types for enforcement status and update all frontend uses. Existing `devices_list`, `device_update`, `rule_update`, `access_log`, and `bandwidth_stats` message names remain; document stable payloads, with `devices_list` always a full snapshot. Rule removal must be represented explicitly. API validation errors use 422; missing valid MAC uses 404; auth failures 401; disallowed origins/CSRF 403; apply failures 503; accepted-but-offline work 202.

## 6. Reproduction examples and test naming

These examples demonstrate the existing defects; incorporate equivalent regression tests without retaining the bug in the fixed code.

### Syntax compilation without imports or filesystem writes

```python
from pathlib import Path

def test_backend_sources_compile():
    root = Path(__file__).resolve().parents[1]
    for path in root.rglob("*.py"):
        if "venv" not in path.parts and ".venv" not in path.parts:
            compile(path.read_text(encoding="utf-8"), str(path), "exec")
```

Place this in `backend/tests/test_startup.py`; exclude dependency/cache directories in the actual collection configuration as well.

### Failure outcome contract

```python
async def test_apply_failure_is_not_reported_applied(reconciler, failing_network):
    failing_network.fail_next("tc class add")
    result = await reconciler.reconcile_device("AA:BB:CC:DD:EE:FF")
    assert result.state == "error"
    assert result.last_error
    assert result.components["bandwidth"].state != "applied"
```

The fixtures must use temporary persisted desired state and an injected adapter that fails a real apply step. Do not fake the reconciler's return value. Create `backend/tests/conftest.py` to provide temporary config/database, a fake adapter recording owned resources, and an application factory that does not touch host networking.

### Portable test files to create

| Test file | Issue IDs / required cases |
| --- | --- |
| `backend/tests/test_startup.py` | R01, R02, R05: compile, imports, CLI, configuration precedence |
| `backend/tests/test_auth.py` | R04, R06, R18: passwords, bootstrap/migration, sessions, CSRF, WS revocation |
| `backend/tests/test_commands.py` | R09: failures, missing binary, timeout, diagnostics |
| `backend/tests/test_reconciler.py` | R10, R11, R19: target reasons, restart, pending/error, race/retry |
| `backend/tests/test_firewall_ownership.py` | R12: foreign rule preservation and idempotence |
| `backend/tests/test_content_rules.py` | R03, R20, R22: matching, canonicalization, duplicates, catalog |
| `backend/tests/test_packet_events.py` | R07: worker thread, overflow, batching, shutdown |
| `backend/tests/test_bandwidth.py` | R08, R16: directional specs, counter deltas/reset/retention |
| `backend/tests/test_discovery.py` | R17, R24: complete snapshots, failures, gateway, responsiveness |
| `backend/tests/test_lifecycle.py` | R21: partial acquisition failure and bounded shutdown |
| `backend/tests/test_static.py` | R13: assets, SPA fallback, API 404, traversal |
| `backend/tests/test_migrations.py` | R04, R19, R20, R22: real reviewed schema upgraded without lost intent |
| `frontend/src/contexts/AuthContext.test.tsx` | R18: never authenticate on failures/stale storage |
| `frontend/src/contexts/WebSocketContext.test.tsx` | R06, R15: auth gating, reconnect, timers, cleanup |
| `frontend/src/pages/Devices.test.tsx` | R17, R19: offline retention and applied/error display |
| `frontend/src/components/RuleEditor.test.tsx` | R19: await operations, retain input after rejection |
| `frontend/e2e/remediation.spec.ts` | Production login, deep links, password change, rule status, logout |

## 7. Implementation stages and dependencies

Checkboxes track implementation evidence recorded in the results document. Passing earlier stages is not completion of later issues or of the full Linux acceptance gates.

### Stage A — Bootable, repeatable application foundation

**Issues:** R01, R02, R05, R14, R23 foundation. **Depends on:** none.

- [x] Add the temporary-config/app-factory test harness and compile/import regression tests.
- [x] Repair CLI/global declarations and the invalid FastAPI dependency.
- [x] Implement explicit config loading and remove startup/import side effects.
- [x] Fix TypeScript/lint configuration without weakening checks; create dependency locks.
- [x] Add portable CI and record clean compile/import/build/lint output.

**Exit:** App factory and `--help` work without root or network mutation; clean frontend build/lint pass. Normal startup without credentials is rejected predictably.

### Stage B — Credential, session, and WebSocket security

**Issues:** R04, R06, R18 and auth parts of R05/R23. **Depends on:** A.

- [ ] Write migration/password/session/origin/CSRF tests, including existing-database fixtures.
- [ ] Add credential/session schema migrations and local password-reset command.
- [ ] Implement auth API, password rotation, exact-origin policy, and session-bound sockets.
- [ ] Replace frontend credential storage with confirmed sessions and clear legacy storage.
- [ ] Integrate HTTPS configuration in manual/service setup; run auth/browser regression checks.

**Exit:** No accept-any login path, stale credentials, unauthenticated telemetry, or browser password storage remains.

### Stage C — Owned network resources and truthful mutations

**Issues:** R09, R10, R11, R12, R19, R24 and migration parts of R20. **Depends on:** A; B for authenticated route tests.

- [ ] Add command failure, ownership, concurrency, gateway, discovery responsiveness, and reconciliation tests.
- [ ] Implement explicit command failures/timeouts and owned firewall/tc resource inventory.
- [ ] Add desired/applied state migrations and a per-device reconciler.
- [ ] Make discovery asynchronous, interface-aware, and safe for local/gateway targets.
- [ ] Route every mutation and restart/address-change recovery through reconciliation.
- [ ] Update frontend mutation contracts and pending/error display; run failure-injection checks.

**Exit:** No success is inferred from a saved flag; foreign resources survive; protections acquire interception independently of monitoring.

### Stage D — Real content enforcement and catalog consistency

**Issues:** R03, R20, R22. **Depends on:** C.

- [ ] Add canonical-rule/catalog migrations and matcher tests.
- [ ] Install/validate queue dependencies on the chosen Linux target and build the disposable network fixture.
- [ ] Implement inline DNS/TLS inspection, bounded reassembly, real verdicts, and supervised worker failure handling.
- [ ] Connect rule updates, existing-flow invalidation, and reconciler state to the engine.
- [ ] Add protocol coverage notices and run blocked/allowed Linux traffic assertions.

**Exit:** Real supported traffic is blocked/allowed correctly; only actual verdicts produce blocked events. Matching-only tests are insufficient.

### Stage E — Directional bandwidth and persistent telemetry

**Issues:** R07, R08, R16. **Depends on:** C, D for enforcement-derived access events.

- [ ] Add worker-thread event, queue overflow, directional accounting, and counter-reset tests.
- [ ] Implement direction-specific classifiers and verified class replacement/removal.
- [ ] Add bounded event ingestion, batched access writes, bandwidth delta persistence, retention, and broadcasts.
- [ ] Run measured bidirectional Linux transfer tests plus restart/DHCP/unaffected-device checks.

**Exit:** Asymmetric limits are measured, access logs survive thread boundaries, and charts display real nonduplicated traffic history.

### Stage F — Lifecycle, snapshots, dashboard, and installation

**Issues:** R13, R15, R17, R21; installer/README closure for R05/R14/R22. **Depends on:** B-E.

- [ ] Add quiet-interface shutdown, partial-start rollback, snapshot, reconnect, and static-route tests.
- [ ] Implement supervised startup/shutdown and restore only owned state.
- [ ] Repair complete snapshot broadcasts and frontend reconnect/subscription lifecycle.
- [ ] Serve production assets and update installer/service definitions, preserving existing config/data.
- [ ] Run browser smoke tests against the built backend-served dashboard and repeat install/start/restart/stop checks in a disposable Linux environment.

**Exit:** A documented installation presents the dashboard; offline devices remain manageable; shutdown terminates without waiting for traffic.

### Stage G — Full acceptance and handoff

**Issues:** All R01-R24. **Depends on:** A-F.

- [ ] Run the complete portable, browser, migration, and isolated Linux suites from locked dependencies.
- [ ] Review the full changed code against every acceptance criterion in section 3.
- [ ] Correct README feature claims, setup commands, supported protocols, and recovery instructions.
- [ ] Complete `docs/remediation-results.md` with one evidence entry per issue and explicit environment/coverage limits.
- [ ] Reconcile every checkbox and deliver a final report of fixes, tests, remaining risks, and any unverified criteria.

**Exit:** Every issue has evidence of resolution; any unmet Linux acceptance criterion prevents a claim that all repairs are complete.

## 8. Verification commands and Linux fixture

The implementing agent must create the referenced test configuration/scripts before claiming these commands work. Run commands from the stated directory. Use a disposable environment; never point the integration harness at the user's normal network interface.

### Portable/backend, from repository root

```bash
python -m pip install -r backend/requirements.txt -c backend/constraints.txt
python -m pip install -r backend/requirements-dev.txt -c backend/constraints.txt
python backend/main.py --help
python -m pytest backend/tests -q
```

Configure test import paths in `backend/pytest.ini` or repository `pyproject.toml`, use temporary databases, and make the test fixture fail if a real privileged command escapes a fake adapter. Python constraints must be generated for and tested against the supported version matrix; do not assume a lock generated on Windows proves Linux queue dependencies install.

### Frontend, from `frontend/`

```bash
npm ci
npm run lint
npm run build
npm run test -- --run
npx playwright install chromium
npm run test:e2e
```

Add `test` and `test:e2e` scripts using Vitest and Playwright. The E2E config must start a backend in an explicit test environment with a seeded temporary administrator and fake network adapters, serving the actual build. It must not require or embed a real user's password.

### Isolated Linux integration, from repository root

```bash
sudo -E backend/venv/bin/python -m pytest tests/integration -m network -v
```

The test harness creates uniquely prefixed network namespaces and veth links entirely inside a disposable Linux VM or runner. Model two clients, an Ethernet segment, the appliance on that segment, a separate gateway, and an upstream DNS/TLS/throughput server. Client default routes point to the gateway so R11 is tested using interception, not by accidentally routing clients directly through the appliance. Also provide a routed fixture to distinguish classifier errors from ARP limitations.

Use only controlled fixture domains/certificates and local traffic generators. Assert packets observed at the upstream fixture, kernel counters/classes, database records, and API state. Snapshot and compare foreign firewall/qdisc fixtures. Test clean stop, worker crash, API restart, offline device return, address reassignment, and queue overload. Fixture cleanup must run on assertion failure and remove only the uniquely named fixture resources. Store packet traces with synthetic fixture traffic only.

The harness must refuse to run if it cannot establish isolated namespaces or if its selected interface/namespace is outside the fixture. Do not compensate by running ARP spoofing or firewall cleanup on the host's default interface. If the runtime cannot supply namespaces/required kernel features, record that limitation and leave network acceptance unverified.

## 9. Completion definition and review traceability

Original numbered review findings 1-11 map to R01/R02, R03, R04, R05, R06, R07, R08, R09, R10, R11, and R12 respectively. Original additional findings (static dashboard, compilation, reconnect, history, offline devices) map to R13-R17. R18-R24 document additional concrete defects from the same inspection and handoff preparation. Security exposure of general password settings and ignored gateway/subnet overrides are included in R04/R05.

The implementation is complete only when all R01-R24 acceptance criteria pass, data upgrades preserve existing user intent, the dashboard reports applied state honestly, a fresh documented installation works, and isolated Linux measurements prove the supported enforcement contract. Claims about unsupported protocols must be corrected rather than expanded without evidence.

Specification preparation is complete:

- [x] Mapped every finding from the review to an issue ID and included additional inspection findings.
- [x] Supplied causes, repair requirements, source references, and acceptance checks for R01-R24.
- [x] Defined architecture, interfaces, migration behavior, ordered stages, and test environments.
- [x] Checked issue coverage, required fields, document structure, and contradictory requirements.

These completed preparation items do not mark any implementation stage or defect as fixed.

### Copyable agent prompt

> Implement `docs/superpowers/specs/2026-09-05-codebase-remediation-spec.md` against the current repository. Read all requirements and local instructions first. Execute stages A-G in dependency order, add meaningful regression tests, preserve existing device/rule data with migrations, and maintain `docs/remediation-results.md` with evidence for every R01-R24 issue. Do not stop after startup/build fixes or substitute simulated enforcement for real packet verdicts. Run portable and browser tests with temporary state and run privileged networking tests only in the disposable Linux fixture. If Linux verification is unavailable, finish independent work and report those criteria as unverified. Do not deploy to a live network or claim complete repair until the specified acceptance checks are satisfied.

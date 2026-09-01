# Changelog

All notable changes to Custodexa will be documented in this file.

## 1.1.2 — a cleaner look across the interface (2026-09-02)

No schema change. No migration runs.

### Interface

- Icons across the sidebar, the dashboard, and the workspace toolbar were
  redrawn from a single open-source icon set. Entries that used to share an
  icon now each carry their own, so pages are easier to tell apart at a glance.

## 1.1.1 — the upload worker starts when off-site storage is first configured (2026-09-01)

No schema change. No migration runs.

### Off-site storage

- On a deployment that started without off-site storage configured, saving the
  configuration for the first time now starts the upload worker immediately.
  Before this fix the worker only started with the backend, so recordings queued
  after the first save waited until the next restart. Confirming a storage
  switch starts it the same way.
- One follow-up is recorded: upload queue metrics registered at startup appear
  after the next restart when the worker was started this way. Queue state on
  the settings page is not affected.

### Copy

- Traditional Chinese wording pass across the interface.

## 1.1.0 — off-site evidence storage (2026-09-01)

**This release changes the database schema.** One migration runs when the backend
starts: `20260825_evidence_offsite`. It creates two tables that track off-site
storage and adds tracking columns to sessions and export jobs. It does not rewrite
existing rows, so the first start after the upgrade takes about as long as usual.

**Back up before you upgrade, and keep the images you are running now.** What to
record before you stop the old version, and what to check afterwards, is section 2
of `docs/ops/upgrade-sop.md`. Going back needs both the pre-upgrade backup and the
previous images: the migration's `Down` removes the tracking tables and has no
production entry point, so restoring the backup is the only supported way back.

**A deployment that does not configure off-site storage behaves as before.** The
feature stays off until a storage target is saved.

### Off-site evidence storage

- After a session ends, its recording uploads to object storage you configure:
  an S3-compatible service (AWS S3, MinIO, and others) or Google Cloud Storage
  through its native API. Evidence packages upload the same way once packing
  finishes. Uploads retry with backoff, and failures are visible on the settings
  page with a per-item retry.
- Retrieval verifies before it serves. When the local copy is gone, playback and
  downloads fetch the object, check its SHA-256 against the value recorded at
  upload time, and refuse to serve content that does not match. Browsers never
  receive storage URLs; the backend streams everything.
- Configuration lives in the admin UI under system settings. Credentials are
  envelope-encrypted with the platform key hierarchy and are write-only: once
  saved they do not appear in any response, log, or audit entry. A connection
  test runs against the values in the form before saving.
- Changing the storage target is a confirmed switch. The previous configuration
  is kept as a retired generation, objects uploaded under it stay readable
  through their original provider and credentials, and credentials of a retired
  generation can be revoked individually.
- Environment variables can seed the initial configuration on the first start of
  a new deployment. After that, management is in the UI.
- Immutability, versioning, and expiry of remote objects belong to the bucket
  settings of the deployment. The product never deletes remote objects; when the
  recording retention policy expires a recording, it clears the local copy and
  the database tracking only. Recommended bucket settings for both providers are
  in `docs/ops/backup-and-restore.md`.
- A local cache setting can clear local copies early once uploaded; playback then
  streams from object storage. Uploads, retention expiry, integrity mismatches,
  and configuration changes all write audit entries, and queue state is exposed
  as metrics.

## 1.0.7 — how the frontend image installs its dependencies (2026-08-27)

No schema change. No migration runs. A running deployment behaves the same as 1.0.6.

### Building from source

- Both Node stages of the frontend image install with `npm ci --ignore-scripts`. The
  install follows the committed lock file exactly, and package install scripts do not
  run during the build. Building from a tree whose lock file and `package.json`
  disagree now stops with an error instead of resolving new versions on its own.

## 1.0.6 — first sign-in password change for accounts an admin creates (2026-08-26)

No schema change. No migration runs.

### Accounts an admin creates

- An account created through user administration now asks for a new password at
  first sign-in. The person signing in with the initial password sets their own
  password and goes straight to the system. This applies to every account an admin
  creates.
- Accounts created before this version are unchanged.

## 1.0.5 — source address forensics, encrypted clipboard auditing, and a check for a second instance (2026-08-26)

**This release changes the database schema.** Two migrations run when the backend
starts: `20260824_audit_export_jobs` and `20260826_source_ip_forensics`. The second
one also backfills a per-account baseline of the source addresses already seen, so
on a long audit history the first start takes longer than usual.

**Back up before you upgrade, and keep the images you are running now.** What to
record before you stop the old version, and what to check afterwards, is section 2
of `docs/ops/upgrade-sop.md`. Going back needs both the pre-upgrade backup and the
previous images: the source address migration has a `Down` that destroys data and
no production entry point, so restoring the backup is the only supported way back.

**If you put the new version's source tree in a different directory, set
`DATA_PATH` to an absolute path**, or point it back at the original data directory,
before starting it. A relative `DATA_PATH` resolves against the directory the
compose file sits in, so a new tree beside the old one gets an empty data
directory. The backend starts on it without complaint, builds a fresh database, and
the first five checks in section 2.7 still pass. In the log, an existing deployment
should never print `執行 migration: 20260816_schema_baseline` followed by `baseline
schema 已建立`. Stop it before anyone signs in. Section 2.5 of the upgrade SOP has
two queries that settle it without reading the log.

### Source address forensics

- The auditor workbench has a third pivot: source address. Picking an address shows
  what that address did across all six event sources, with every row naming both
  the account and the asset.
- Events and session spans under the person and asset pivots carry the source
  address. Where there is none the row says so and gives the reason: the event had
  no client (`system`), the address could not be resolved (`unresolvable`), or the
  record's session is gone (`session_missing`). An address is never inferred.
- The filter row takes an exact source address, and the reserved value `unknown`
  selects the rows that have none.
- Addresses on the person and asset pivots link into the address pivot, carrying
  the current time window and category selection. Alert rows carry the source
  address of their session and link into the address pivot for the day the alert
  fired. An address is not a link to itself, and an unknown source is not a link.
- Command, alert and clipboard rows have no address of their own; theirs comes from
  the session they belong to: the address that session was opened from, not a
  per-request sample. The workbench labels which rows carry their own address and
  which inherit it from a session.

### Allowed source networks, per account

Decide how a source address is determined before turning this on. Without
`TRUSTED_PROXIES` set, only the socket peer is trusted and forwarding headers are
ignored. Behind a reverse proxy, a load balancer or a CDN, that means every
request looks like it came from the proxy, so a list of user networks locks everyone out
and a list holding the proxy address admits everyone behind it. The same address is
the one the workbench records and the one the new address alert watches.

- An account can carry a list of allowed source networks. An empty list means no
  restriction. IPv4 and IPv6 CIDR are both accepted, a bare address counts as `/32`
  or `/128`, and a list holds up to 32 entries.
- The list is enforced when a browser signs in, when MFA is completed or enrolled,
  when a forced password change completes, on the OIDC token exchange, when a
  session is refreshed, when a connection ticket is issued, and again when that
  ticket is redeemed: for the text terminal and for the graphical protocols.
  Tickets carry no address: each point reads the current source and the current
  list.
- The list also covers an account setting up, enabling or disabling its own second
  factor, and changing its own password. Three administrator actions on another
  account, resetting its password, unlocking it and clearing its enrolled second
  factor, are judged against the administrator's own list rather than the target
  account's.
- A refusal answers with a machine-readable code and nothing more. The address that
  was refused and the rule it failed go to the audit log.
- A session refresh refused this way does not consume the credential.
- Tightening a list does not cut anyone off at once. An access token already issued
  stays usable for the rest of its lifetime, at most 15 minutes, and a protocol
  session already open runs to its own end. The next refresh is refused and the
  next connection is blocked. Tell the people affected before tightening; without
  warning the symptom reads as a fault.
- If a stored list cannot be read or parsed, the request is refused rather than
  treated as an empty list, and the failure is raised on the audit failure panel.
- The user list carries a tag per account saying whether it is restricted or holds
  a list equivalent to no restriction. The user form validates entries as they are
  typed, and says when a list is equivalent to no restriction (`0.0.0.0/0`, `::/0`)
  while still storing it. When the list about to be saved does not contain the
  address the administrator is working from, the form says so before saving, and
  still lets it be saved.
  Another administrator can put the list back from the user form. When there is no
  other administrator, `docs/QUICKSTART.md` has the offline database step.
- An OIDC token exchange refused by this policy records the refusal only; no
  successful sign-in is written alongside it.

### New source address alerts

- The first connection an account opens from an address it has not been seen at
  before raises one alert, delivered through the existing alert channels. The same
  account and address does not raise it again.
- The baseline is built during the upgrade from existing session history and
  successful sign-in records, so addresses already in use do not fire on the first
  start.
- Signing in from a new address, as opposed to opening a connection, records the
  address and an audit entry, without an alert.

### Running a second instance

Custodexa runs as a single instance. The backend now checks that for itself.

- A second instance started against the same database does not come up. It stops
  before any migration runs. The log names the host and process holding the lock,
  prints a confirmation code, and gives two commands for getting out of it.
- To start it anyway, set `INSTANCE_GUARD_ACK` to that confirmation code. A code
  belongs to one holder, so a code left over in the environment from last time does
  nothing. Starting this way writes an audit event, raises a metric, and puts a
  banner in the interface that nobody can dismiss.
- The banner is up whenever this instance is not alone: it was started with
  `INSTANCE_GUARD_ACK`, it lost the lock while running, or it holds the lock and
  sees other instances of this version or later on the same database. A metric
  counts how many it sees. Nothing is refused in any of these states, and the
  banner comes down once the instance is alone again.
- An instance that loses the lock while running keeps serving and keeps trying to
  take it back, and says so in a log line and an audit event. It does not fence
  anything off.
- `GET /api/v1/seal/status` carries an `instance_guard` field for the banner, and
  `GET /api/v1/instance-guard` returns the detail for administrators. Four
  `custodexa_instance_guard_*` metrics were added. `/health` is unchanged.
- **What this does and does not do:** it makes a second instance impossible to
  start without someone noticing, and it leaves audit evidence when someone starts
  one anyway. It does not prevent a second instance from running, and it does not
  protect against the data problems two instances cause; whoever confirms the start
  carries those. The check only works when both instances are this version or later.
  On the first upgrade the old instance holds no lock, so the new one taking it
  does not mean the old one has stopped. Check that yourself.

### Clipboard content and evidence packages

- Clipboard content is stored envelope-encrypted, under the same scheme as stored
  credentials. The list view returns the facts about each entry rather than its
  content; opening one entry decrypts it and writes its own audit record. If that
  record cannot be written, the content is not delivered.
- On a graphical session that does not allow sending, returning focus to the window
  no longer pushes the local clipboard to the remote, and no clipboard event is
  written for it.
- Session detail has a clipboard card, and a clipboard event in the workbench
  timeline leads to it with the recording positioned at the same moment.
- Evidence bundles now carry clipboard content, and the manifest lists it. Event
  reports are unchanged.
- Bundle export runs in the background: it is requested, then packaged, and the
  artifact is kept for 24 hours. Only the account that requested a bundle can
  download it; another account holding the same permission gets a 403. Requests,
  packaging and downloads are all audited, and finished job records are cleared
  after 30 days. Event reports are still produced synchronously. The existing
  synchronous export endpoint now refuses a bundle request outright instead of
  producing one, so a caller that used it for bundles has to move to the job
  endpoint, and the kind of package wanted is named by a new `pack` parameter.
- Packaged bundles are written to a directory inside the backend container,
  `/var/lib/custodexa/exports` unless `EXPORT_ARTIFACT_PATH` names another one. It
  is not bind-mounted, so it does not outlive the container, and it holds decrypted
  clipboard text and recording bytes. It is deliberately not a backup target;
  `docs/ops/backup-and-restore.md` says why it should not be copied elsewhere.
- A downloads page under Audit lists the bundles an account has requested and the
  state each one is in.
- The workbench layout was reworked: the event table is the main pane with a single
  scrollbar and a filter row that stays put, the session overview groups by asset
  with a per-session layer underneath it, and the category panel folded into the
  filter row. The retention coverage notices that used to sit as a standing banner
  now hang off the category chips, with the wording unchanged, and the page's
  explanatory text moved behind a question mark button. Export is now two buttons,
  one for the event report and one for the evidence bundle, instead of one, and the
  time scale no longer stays put while the list scrolls.
- Outside the workbench, the sidebar's collapse button moved from the bottom of the
  sidebar into the header row beside the product name, where a long menu can no
  longer push it below the fold. It is in that position on every page.

### Database

- `20260824_audit_export_jobs` creates the `audit_export_jobs` table and three
  indexes, one of them a partial unique index that keeps the same filter from being
  queued twice by one requester while it is pending or running.
- `20260826_source_ip_forensics` adds `users.allowed_cidrs`, creates the
  `user_source_ips` baseline table, adds indexes on `sessions (client_ip,
  start_time)` and on `user_source_ips (client_ip, last_seen_at)`, widens the
  `command_alerts.kind` check constraint to accept `new_source_ip`, and backfills
  `user_source_ips` from session history and successful sign-in records.
- Converting existing clipboard rows to encrypted storage is not part of either
  migration: it needs the key encryption key, so it runs after unsealing. On a
  deployment that unseals through the UI it therefore happens at unseal, not at
  startup. The conversion rewrites every row and drops the plaintext column in one
  transaction; if a row fails, nothing is dropped and it is retried on the next
  start. A database created fresh by this release is already in the final shape.
- `docs/DB_SCHEMA.md` describes all of the above.

### Documentation

- `docs/ops/upgrade-sop.md`: going back needs the backup *and* the previous images,
  so those images are tagged before the new build takes over `latest`; the row
  counts to write down before backing up; the absolute-`DATA_PATH` warning; and a
  new section on confirming, after the upgrade, that you are looking at your own
  data.
- `docs/ops/backup-and-restore.md`: a deployment that unseals through the UI
  returns to sealed when the backup finishes, and the audit queue metric does not
  exist while sealed. The key inventory is four fingerprints, not three. The
  directory that holds packaged bundles is named there as a temporary location that
  is not a backup target, and as one that holds decrypted content.
- `docs/ops/deployment-topology-limits.md`: what the backend does when it finds a
  second instance, what it asks you to confirm, and what that confirmation does
  not buy you. It also covers how a source address is determined behind a proxy,
  which ways in an allowed-network list closes, and what to do before tightening
  one.
- `docs/QUICKSTART.md`: the offline database procedure for an administrator locked
  out by an allowed-network list, including the fact that those statements are not
  audited by the product. The offline SQL now states outright that `$1` and `$2` are
  placeholders to substitute by hand; `psql` will not do it for you.
- `docs/API_SPEC.md` covers the new endpoints, parameters and response fields.
- Where the operations documentation described behavior the system does not have,
  it was corrected; the entries above are the ones that change what an operator
  does.

## 1.0.4 — comment and documentation edits (2026-08-24)

No functional changes. Behavior, API surface, configuration keys and database
schema are identical to 1.0.3, and no migration runs on startup. Upgrading is a
rebuild and nothing else.

### Documentation

- Source comments across the backend and frontend were edited for readability.
  Where a comment explained a trade-off, the explanation stayed and only the
  shorthand around it changed.
- `CONTRIBUTING.md` folds the note on where behavior is authoritatively
  described into the existing checklist: `openspec/specs/` governs, and a
  comment that disagrees with a spec is the comment that is wrong.
- The column notes in `docs/DB_SCHEMA.md` now read on their own: each one
  carries its reasoning in the note itself rather than pointing at a section
  number.

## 1.0.3 — the session cookie's Secure attribute becomes a policy (2026-08-22)

Whether the session refresh cookie carries the `Secure` attribute is now a setting
on the Security Policies page, and it ships turned on. Saving it takes effect on
the next sign-in; no restart.

**If you serve Custodexa over plain HTTP**, turn this policy off. Leaving it on
means the browser will not keep the cookie, so everyone is sent back to the sign-in
page about every 15 minutes. The system will not change the setting for you: the
sign-in page tells the user what is happening, and the Security Policies page
tells an administrator how to handle it.

`AUTH_REFRESH_COOKIE_SECURE` now only seeds the policy the first time the backend
starts, the same way the `LDAP_*` variables work. Editing it afterwards does
nothing; change the policy instead.

### Changed

- The `Secure` attribute follows the `refresh_cookie_secure` policy. On a first
  start the seed value comes from `AUTH_REFRESH_COOKIE_SECURE` if set, otherwise
  from the scheme of `PUBLIC_BASE_URL`, otherwise it is on. Every fallback path,
  including an unreachable policy store, resolves to on.
- Sorting in audit log queries builds the ORDER BY clause out of column names
  taken from a fixed list rather than out of the request.
- Local user lookup parses uid and gid with an explicit bit size, so a value too
  large to represent is rejected at the parse step.

### Notes

- On `http://localhost`, Chromium and Firefox still accept a cookie marked
  `Secure`; the WebKit build behind Safari does not. Local development in Safari
  needs the policy off.

## 1.0.2 — session cookie and audit query hardening (2026-08-22)

Browsers now hold the session refresh credential in an httpOnly cookie rather than
in local storage. Sessions do not carry across the upgrade: everyone signs in once
after you deploy this.

If you serve Custodexa over HTTPS, set `PUBLIC_BASE_URL` to the public https
address, or set `AUTH_REFRESH_COOKIE_SECURE=true` when TLS terminates further out
and that variable cannot carry the public address. The startup log states which
value is in effect and where it came from.

### Security

- The session refresh credential is issued as an httpOnly, `SameSite=Strict`
  cookie scoped to `/api/v1/auth/`. It no longer appears in response bodies and
  the browser no longer stores it; the frontend clears any value left over from
  an earlier version at startup. Access tokens continue to travel in the
  `Authorization` header and are not read from cookies.
- Audit log queries check the `sort_by` and `sort_order` parameters against a
  fixed column list before building the query.
- Integer parsing in configuration, pagination cursors and local user lookup
  rejects out-of-range input at the parse step rather than after conversion.
- A malformed `SEAL_UNSEAL_COOLDOWN_THRESHOLD` refuses startup instead of falling
  back to the default.

### Changed

- The version reported by `/health` is injected at build time from the `VERSION`
  file, which a test keeps in step with this changelog.

### Documentation

- The environment template is written in English, with Traditional Chinese and
  Japanese reference translations under `docs/`. The template remains the one file
  you copy to `.env`.
- QUICKSTART covers the refresh cookie's `Secure` derivation alongside the TLS
  reverse-proxy walkthrough.

## 1.0.1 — dependency security updates (2026-08-21)

No product code changes. Rebuild your images to pick these up.

### Security

- Frontend dependencies updated to resolve all open advisories: lodash and
  lodash-es 4.18.1, axios 1.18.0, flatted 3.4.4, minimatch 3.1.5, ajv 6.15.0,
  nanoid, postcss, form-data, js-yaml, and the Vite toolchain (Vite 8,
  plugin-vue 6). `npm audit` and GitHub dependency alerts are clean after
  this release.
- Backend: `github.com/Azure/go-ntlmssp` updated to v0.1.1.
- Verified against the full backend and frontend test suites and the
  production image build.

### Documentation

- QUICKSTART now walks through a minimal TLS reverse-proxy setup step by step
  (nginx container, certificate mounts, WebSocket upgrade verification).
- Public-facing prose reworked to read naturally; commands, procedures, and
  capability claims unchanged.

## 1.0.0 — initial public release (2026-08-21)

First public release under AGPL-3.0.

### What's in 1.0.0

- Browser-based access to SSH (native web terminal), RDP / VNC, database web CLIs
  (MySQL / PostgreSQL / Redis / SQL Server), and Kubernetes exec, plus SFTP file
  management, all funneled through one gateway with one-time connect tokens:
  the frontend never touches plaintext credentials.
- Full-session recording with variable-speed playback; command-level audit via an
  in-house terminal screen parser that reconstructs commands accurately inside
  full-screen programs (vim, top, pagers); clipboard and file-transfer auditing;
  no recording quotas, and recordings are never dropped to save space.
- Tamper-evident audit chain: row-level HMAC seals plus Ed25519-signed checkpoints
  anchored off-host via syslog; offline-verifiable evidence bundle export; an
  auditor workbench; alert rules with real-time command blocking and
  webhook / Slack delivery.
- Access governance: three-tier access policies, approval flows, break-glass
  emergency access (ships disabled), user groups, asset-tree authorization,
  periodic access reviews, and daily sign-off.
- Identity: local accounts, LDAP / AD directory login, OIDC SSO (multiple
  providers side by side), and TOTP MFA; envelope encryption for stored secrets
  with pluggable KEK providers (env / in-memory UI unseal / cloud KMS);
  in-memory unseal is the default mode.
- Credential rotation for the SSH domain (account-level passwords and SSH keys);
  session watermarking, live read-only monitoring, and session sharing.
- Full UI internationalization: Traditional Chinese, English, Japanese.
- docker compose deployment with a quickstart script, hardened fail-close startup
  checks, Prometheus metrics, RFC 5424 syslog forwarding, retention policies with
  audited deletion, and four operations runbooks.

### Known limitations at release

- Single-instance deployment only.
- Text-based command audit has principled limits; session recording replay is the
  source of truth (see "Design boundaries" in the README).

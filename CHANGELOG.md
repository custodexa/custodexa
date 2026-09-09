# Changelog

All notable changes to Custodexa will be documented in this file.

## 1.9.1 — code quality follow-up (2026-09-10)

No schema change. No migration runs.

### Fixes

- Tightens the code introduced in 1.9.0 without changing behaviour: shared query fragments in the
  policy group repository and the policy group routes are named once; the schedule shape parser
  is split into smaller steps and its patterns are written as raw strings; the clause-number key
  mapping uses a pattern that cannot backtrack and reads optional fields with optional chaining.
- Makes the frequency picker's five field labels announce their controls to assistive
  technology, and marks the policy group strip as a live output region.

## 1.9.0 — policy groups and the compliance map (2026-09-10)

### Policy groups are data, not code

- Two built-in groups ship with the product and are written into the database when the backend
  starts: PCI DSS 4.0.1, and the information system standard and security control baseline that
  applies to electronic payment institutions. Each carries its clauses and the requirements those
  clauses place on individual security settings.
- An organization adds groups of its own for its internal rules, and can rename, enable, disable
  and delete them and edit the clauses inside them; that text is stored and shown in the language
  it was written in, labelled with that language and never machine translated. Several groups can
  be in effect at once, a setting can belong to none of them, and two groups can ask different
  things of the same setting.
- A clause is either a requirement on settings or a statement the organization attests to itself.
  A requirement names an exact value: at least or at most for numbers, and the value itself for
  switches and choices, with no notion of one option outranking another.
- A requirement can also state that the clause covers a setting without naming a value. That
  setting then shows its current value for an auditor to read.
- Every clause takes a note in the organization's own words. Clauses that carry a reference value
  rather than a fixed one are confirmed by an administrator, with their name, the date and one
  sentence. A version that no longer contains a clause keeps the notes and confirmations hanging on
  it and marks that clause as removed.
- Built-in clauses cannot be edited or deleted, only annotated and confirmed, and an upgrade leaves
  each group's enabled state as the organization set it.

### One compliance answer, shown in three places

- One build takes the groups in effect and the current settings, and produces for every pairing of
  setting and group one of five results: meets the requirement, deviates from it, awaiting the
  organization's confirmation, awaiting an auditor's reading, or not covered by that group. Only the
  first two count towards the compliant and deviating figures. Each result carries its reason, and
  the build carries the time the settings were read.
- The deviation counts on the settings pages, the summary and clause results on the compliance map,
  and the apply preview all read that one build, and a test pins the three to the same set of
  deviating settings.

### The security policy pages, slimmed down

- Each setting shows a label, its control, its unit and one info button. Clause numbers,
  recommended values, non-compliance text and the meaning of a zero value now live in that
  setting's drawer.
- The drawer reads in order: one plain sentence saying what the value decides, one sentence per
  group in effect giving its requirement and the result, who last changed the value and when with
  a link to the record, when a change takes effect, and a longer explanation folded away.
- Each section of a page shows how many of its settings deviate, and a deviating setting carries an
  amber dot with text beside it rather than colour alone. The count opens the compliance map. While
  a value is edited and not yet saved, the count follows the draft and is labelled as one.
- The header of each page lists the groups in effect and offers to apply their values, either for
  one group or for all of them at once.
- Applying shows a preview first, listing only the settings that will change, each with its current
  value, its new value and the group the value comes from. A value already stricter than every
  requirement is left as it is, and a setting whose groups ask for opposite values is described in
  plain words and left for the administrator to decide.

### The compliance map

- A read-only page under the audit group, open to administrators and auditors, with no way to write
  anything from it; one click switches between groups.
- The summary gives six figures in two rows, one row counting clauses and one counting settings, so
  the two units are never added together. A line below them counts the settings outside this
  group's scope.
- A clause expands into its settings: current value, requirement, result, and who last changed the
  value and when, with a link to that record. One filter shows only the deviating clauses, and a
  search finds a setting by its displayed name or by its machine key.
- An auditor reaches a setting's change history in three steps: find the setting, expand its
  clause, follow the record link. The record page opens filtered to that setting.

### Policy group management

- A page under system settings, for administrators, and the only place any policy group is written.
- Adding a requirement starts from the setting: choosing one brings its type, its comparison
  directions, its unit and its legal range into the form, and the form shows the current value
  along with the result the requirement will produce once saved.
- Clauses awaiting the organization's confirmation are confirmed here. Every write on this page
  goes to the operation log with the group, the clause and the values before and after.

### Schedules in words rather than in a schedule string

- Schedules are set with a frequency picker offering daily, weekly, monthly, quarterly, yearly and
  custom, which opens the fields each frequency needs and lists the next three run times as they are
  chosen. Those times come from the service that will run the schedule.
- Credential change plans and rotation evidence report schedules use it. Their list columns read as
  words with the next run time beside them, and the schedule string itself now lives in the custom
  field.
- An existing schedule is read back into whichever frequency it matches, and is kept as it is when
  it matches none of them.

### Upgrading

- **Upgrade note**: the security policy list endpoint no longer returns `pci_value`,
  `epayment_value`, `compliant`, `epayment_compliant` and `strictest_value` on each policy item, nor
  `deviation_count` and `epayment_deviation_count` alongside them. Each item now carries its result
  against every group in effect, and the response names those groups.
- Adds one incremental migration that runs when the backend starts. It creates four tables and one
  index and touches nothing that already exists, so its duration is independent of how much data
  you hold. The built-in groups' content is written by the startup seed, not by the migration.
- Back up before you upgrade. That backup is a complete logical backup and so contains the four new
  tables; section 4.1 of `docs/ops/upgrade-sop.md` covers the way back and what to export first if
  you have built groups of your own.
- Writes to policy groups, reads of the compliance map and schedule previews each record under
  their own audit resource, so they can be searched apart from changes to security policy values.

### Fixes

- Reads the numeric source identifier inside a role-mapping channel value at the integer width of
  the platform the backend was built for. A value that does not fit is rejected as malformed on every
  build, and the parser is covered by tests for round trips, malformed values and the upper bound.

## 1.8.0 — directory groups decide roles (2026-09-09)

### Roles that come from an external group

- Maps a group in your directory or identity provider onto a role in this system. Each rule belongs
  to one source, names the group value and the target role, and can be paused without being deleted.
- Recomputes those roles at every sign-in, from the group information that sign-in carried. An
  account added to a mapped group holds the role from its next sign-in, and an account taken out of
  the group loses it the same way.
- Leaves the roles an administrator assigned alone; mapping only adds. An administrator can also pin
  a role a group granted, after which it no longer follows the group.
- Advances the account's credential generation and ends its other open sessions when a sign-in takes
  a role away. A sign-in that only adds roles leaves open sessions as they are.
- Applies to accounts that sign in through an external source. An account that also has a local
  password keeps only the roles an administrator gave it.

### Sign-ins that carry no group data

- Keeps the roles already granted, and records a recognizable event, when a source is set up to read
  groups but this sign-in could not read them.
- Treats an account the source reports with no groups as a member of none, and withdraws its mapped
  roles.
- Records a skip event on every sign-in through a source that has enabled rules but has not been
  told where to read groups from.
- Asks the administrator to confirm a rule that targets the administrator role, or one on a source
  with no group attribute set yet. The confirmation is recorded with the rule.
- Picks up a right withdrawn at the source at the earlier of two moments: the person's next sign-in,
  or the end of their current web session under the "Web session max hours" policy.

### One page for identity sources

- Merges the identity provider and directory pages into one Identity Sources entry, with the mapping
  rules of each source as a section of its detail page. The two former addresses still resolve.
- Shows each source's address, whether it is enabled, how many rules it has, and when someone last
  signed in through it. The rule section filters by target role.
- Refuses to delete a source that still has mapping rules, and says to remove the rules first.
- States on screen that a mapping takes effect at the person's next sign-in. The user list shows
  whether a role came from an administrator or from a group, and when that account last signed in.
- Keeps the group values observed at each account's last sign-in through an external source,
  presented as reported by that source, for answering "I am in the group but did not get the role".

### Provider settings that explain themselves

- Sets which claim the username, email, and display name are read from, each one blank meaning the
  default already in use. Changing them does not re-identify existing accounts.
- Sets the group claim by name, blank meaning this provider does not let groups decide roles.
- Previews an issuer's discovery document before anything is saved, listing its endpoints and the
  claims it advertises, so key names can be confirmed against the provider.
- Shows the callback address to register at the provider, computed from the deployment's public base
  URL, and says when that base URL has not been set.
- Reports a provider's state on one panel from facts the system has already observed, without dialing
  out when the page loads; re-running discovery and testing the connection are separate actions. The
  directory connection test now also reports whether the group attribute has a value on the sampled
  entries, without returning the values themselves.

### Upgrading

- Adds one incremental migration that runs when the backend starts; it only adds structure, and
  every new setting means "not configured, behavior unchanged" while it is empty, so a deployment
  that configures no source behaves exactly as it did before. Section 2 of
  `docs/ops/upgrade-sop.md` walks through the upgrade steps.
- Back up before you upgrade, and export your mapping rules before any rollback.
- Set the group attribute name on the directory, or the group claim on the provider, before you
  create the first rule. Then add the rules and use the source's status panel and connection test to
  confirm the groups are being read.

## 1.7.1 — the standby takes over from a page (2026-09-08)

### The pages you see before the service is up

- The unseal page is now two columns: the left column holds what you need to know (seal state, the
  warning that a lost master key cannot be recovered, and any condition that applies right now), the
  right column holds the one thing to do, as numbered steps. Conditions such as a cooldown or a
  failed previous unseal appear in a fixed place and no longer push the form down the page.
- The text on these pages is written for someone handling an outage: one sentence per element, the
  action first, and reference material (key formats, generator commands) folded away until opened.
  Nothing an operator needs to decide is removed.

### Taking over on the standby without editing files

- When a second application instance starts against a database whose single-instance lock is held,
  it no longer exits. It stays up in a halted state, serves the guard page, and retries the lock
  every 15 seconds. Nothing is migrated or written while halted.
- The guard page shows who holds the lock, when that session started, and the acknowledgement code.
  To take over, an administrator confirms on the page that the other host is down, retypes the code,
  and signs in with their credentials. The code is checked against the lock holder at the moment of
  submission, so a code copied from an earlier holder is refused with the current one. Repeated wrong
  credentials are throttled.
- After a successful acknowledgement the same process continues its startup; no restart is needed.
  The audit event records the administrator's account. If the lock is released while the page is
  open, the instance starts on its own and the page says so.
- The in-app banner shown while the lock is still held elsewhere is now one line with the time and
  who acknowledged, with the details behind a control. Starting with `INSTANCE_GUARD_ACK` in the
  environment still works and is recorded as before.

### Upgrading

No schema change. The standby procedure in `docs/ops/standby-takeover.md` now describes the page;
the environment-variable path remains for scripted takeovers.

## 1.7.0 — role assignments join the checkpoint chain (2026-09-07)

### Who holds which role is now part of the evidence

- Every audit checkpoint now carries a signed snapshot of the role assignments in force at the
  moment it was sealed. A checkpoint signed by the system attests not only to the operation log
  but also to who was an administrator or an auditor at that time.
- The checkpoint verification page gains a "role assignments" line. It states whether the current
  assignments match what the signed record and the audited changes since then add up to, and when
  they do not, it names the accounts and roles that differ and links to the failure event.
- Every change to a role assignment, whether made by an administrator, at sign-up, or on a first
  single sign-on login, leaves an audit record in the same transaction as the change itself.

### Escalation shows up at the first sign-in

- When an account signs in as an administrator or an auditor, the system compares the live role
  assignments with the signed record before issuing the session. A difference that no audit
  record explains opens a failure event on the spot and, where failure alerting is enabled, sends
  the alert through the configured channel. Sign-in itself is not blocked, so an incorrect alarm
  never locks an administrator out.
- The same comparison runs at every seal and at every verification, so a change made outside the
  application is reported within one checkpoint interval even if nobody signs in.

### Verification tools

- The offline verifier accepts both the previous and the new checkpoint payload versions, so a
  chain that spans this upgrade verifies end to end with the public key alone.

### Upgrading

This release changes the database schema. One migration adds the snapshot columns to the checkpoint
table when the backend starts; existing checkpoints are untouched and keep verifying. Role
assignments are covered from the first checkpoint sealed after the upgrade; the verification page
names the checkpoint the comparison currently starts from. Back up before you upgrade; section 2 of `docs/ops/upgrade-sop.md`
walks through the steps.

## 1.6.0 — a credential library for login secrets (2026-09-07)

### Every login secret in one place

- A new Credentials page lists every login secret the system holds. A credential is either
  dedicated, so it comes and goes with the account on one asset, or shared, so it is named once
  and attached to as many assets as use it. Filter by scope, secret type, protocol, rotation state
  or account name; search by name, account name or asset.
- Each credential keeps its secret as versions, and every asset attached to it shows the version
  it is on. Selecting a credential shows the assets attached to it, which are on the current
  version, and which are marked privileged.
- Create a shared credential, attach it to an asset, detach it, rename it, record the secret a host
  already has, or convert a credential between dedicated and shared, all from the same page. The
  page says at each action whether the host itself is touched.

### Adding and editing an asset

- The asset form offers two ways to log in: a credential dedicated to this asset, or one of the
  shared credentials already in the library. The list shows only credentials that fit the asset's
  protocol and says how many hosts a shared one already covers.
- Editing an asset opens a drawer beside the list with its accounts inline, each showing the
  credential it uses and the version in place.

### Changing a shared secret on every host that uses it

- Start the change and the hosts are worked through in the background, one at a time. Each host
  moves to the new secret once a sign-in with it has succeeded, so hosts already verified use the
  new secret while the rest keep working on the one they had; any host can be retried on its own
  from the page.
- The other mode gives every host its own new password and ends the sharing, moving each host onto
  a credential of its own as it verifies. One host can also be taken out of a shared secret on its
  own, with a random or a chosen new password, verified by signing in before the switch.

### Batch rotation, reports and audit

- The batch rotation mode that gives a whole batch one password now names the resulting shared
  credential, so the hosts that succeed can be changed as a group from the library afterwards.
- The rotation evidence report takes its shared marking from the credential itself and states, for
  each account, the credential it signs in with and the version that host has in place.
- Audit records gain a credential category, so everything done to a credential is queryable as one
  kind of event.

### Upgrading

This release changes the database schema. Two migrations run when the backend starts and move
existing login secrets into the credential library, and a one-time conversion after the KEK is
unsealed merges accounts that already shared one secret into a shared credential. Back up before
you upgrade and keep your current images; section 2 of `docs/ops/upgrade-sop.md` walks through the
steps and the two log lines that confirm the conversion is complete. Creating an account by copying
another asset's credentials is replaced by attaching a shared credential.

## 1.5.0 — batch password rotation by account name, and a standby application host (2026-09-06)

**This release changes the database schema.** The migration
`20260905_account_batch_rotation` runs when the backend starts. It adds one table for
batch rotations and a batch reference to the rotation record and candidate tables. Nothing
is rewritten, so the first start after the upgrade takes about as long as usual, and the
rotation records you already have stay marked as coming from a plan.

**Back up before you upgrade and keep your current images.** Section 2 of
`docs/ops/upgrade-sop.md` lists what to record before stopping the old version and what
to check afterwards. To go back, restore that backup with the previous images. That does
not undo a batch you ran after the upgrade: the hosts keep the passwords it set, and the
record of which of them share one is gone. Export the batch list before rolling back.

### Rotate one account name across many hosts

- A new page under Assets lists every asset that has an account with the name you pick,
  grouped by rotation state. Tick the ones you want, or a whole group at once, and start
  the rotation from there. Each host is rotated and recorded on its own, so one that fails
  or cannot be verified does not hold up the rest.
- Two password modes. By default every host gets its own random password. You can instead
  give the whole batch one shared password, in which case the hosts that succeed end up in
  a single credential group and the rotation evidence report marks that credential as
  shared. The dialog states this before the batch starts.
- The rotation evidence report now shows which records came from a batch and which from a
  scheduled plan.
- A batch rotates a host the same way a scheduled plan does, verification included, on
  Linux and on Windows local accounts. Plans you already have are untouched.

### A standby application host

- A new compose overlay, `docker-compose.external-database.yml`, runs the stack against a
  PostgreSQL server you operate elsewhere. With the database off the application host, a
  second prepared host pointed at the same database can take over while the first one is
  down.
- `docs/ops/standby-takeover.md`, in English, Traditional Chinese and Japanese, covers what
  the standby needs in advance and how the takeover runs, including the way the
  single-instance guard behaves while the old host still holds its lock. It also states the
  boundary: an unplanned takeover leaves behind the recordings on the failed host's disk
  and the audit rows that had fallen back to files there.
- The quick start script leaves `DB_PASSWORD` alone when an external database is
  configured, and stops with a message when the value is missing instead of generating one.

### The audit queue is drained at shutdown

- Audit rows still waiting in the in-memory queue when the service is asked to stop are
  now written out before it exits. If the database does not answer within the shutdown
  budget, the rows go to the audit fallback file where that is enabled and are counted as
  lost where it is not, the number not confirmed written is logged, and the process exits
  with a non-zero code.
- Keep the container stop grace period at ten seconds or more, since the drain runs inside
  it. `docs/ops/upgrade-sop.md` gives the shutdown budget and the two log lines to look for
  when stopping the backend.

### The graphical protocol daemon runs with fewer privileges

- The guacd container now drops every Linux capability, refuses privilege escalation, and
  runs on a read-only root filesystem, with two writable areas in memory that RDP drive
  redirection and the RDP library need. The compose file sets this, so it applies to any
  image you put in that slot.
- The backend waits for guacd to pass its health check before starting, so the first
  graphical connection after a cold start no longer races the daemon coming up.
- `docker/guacd/Dockerfile` and `docs/ops/deployment-topology-limits.md` state the three
  things an image in that slot has to provide, so you can build or choose your own.

### Fixes

- Reloading the browser on the Assets page no longer returns the web server's own 403
  page. That address collided with a directory in the built frontend; it now falls through
  to the application like every other page.

## 1.4.1 — the approvals card follows approval rights (2026-09-04)

No schema change. No migration runs.

- The pending-approvals card on the dashboard and the badge in the sidebar now follow the
  same rule the server applies to the approval endpoints: holding the approver role, or
  belonging to an approver group. An account with neither no longer sees the card, so a
  count it could never read no longer appears as a zero.
- Members of an approver group who do not hold the approver role see the card and its
  count, matching what the approvals page already let them do.
- Gaining or losing approval rights takes effect on the page that is open: the card
  appears or disappears with it, and the sidebar stops asking for a count once the rights
  are gone.

## 1.4.0 — https out of the box (2026-09-04)

No schema change. No migration runs.

**The published ports change.** The stack now serves https on 443 and redirects plain
http on 80 to it, where it previously served http on 80 only. A host already running
something on 443 takes a different pair through `TLS_HTTPS_PORT` and `TLS_HTTP_PORT` in
`.env`, and the address then carries that port. If you started a reverse proxy container
of your own alongside a previous version, stop it before upgrading so it does not hold
the ports the built-in one now publishes.

### The production stack terminates TLS itself

- `docker compose up -d` brings up a reverse proxy in front of the frontend: 443 inside
  the network with TLS 1.2 and above, HSTS, WebSocket forwarding for terminal and
  graphical sessions, and a redirect from http. The proxy is a service like any other, so
  `ps`, `up -d`, `down` and the upgrade procedure all cover it.
- The host name comes from `TLS_DOMAIN` in `.env` and is substituted into the proxy
  configuration at startup, so the configuration file itself needs no editing. Point
  `PUBLIC_BASE_URL` at the same host over https.
- `bash scripts/quickstart.sh` fills in the host name, the addresses of the machine and
  the https base URL when they are missing, and prints the address to open along with the
  link to download the certificate authority. With `--up` it also names whatever already
  holds the http or https port, before it starts anything.
- The built-in proxy is trusted for source addresses out of the box: quickstart sets
  `TRUSTED_PROXIES` to the Docker subnet the stack runs on, so the audit log and the
  sign-in rate limit see the address of the client rather than the address of the proxy.

### Certificates: generated for you, or your own

- `TLS_MODE=selfsigned`, the default, generates a local certificate authority and a
  server certificate on the first start and keeps them in `tls/`. The certificate covers
  the host name in `TLS_DOMAIN` plus any addresses listed in `TLS_IP_SAN`. The proxy
  publishes the CA certificate at `/custodexa-ca.crt`: install it on the machines that
  connect, through group policy, MDM or by hand, and browsers show the site as trusted.
  The CA private key stays on the host and never enters the proxy container.
- `TLS_MODE=provided` takes `tls/fullchain.pem` and `tls/privkey.pem` from your own CA. A
  missing file stops the start with a message naming it, and the rest of the system is
  untouched.
- Certificates already in `tls/` are kept as they are on every later start. Replacing them
  means deleting the files and starting again.
- Need settings the shipped proxy configuration does not cover? Copy
  `docker/reverse-proxy/nginx-tls.conf.template`, edit the copy, and point
  `TLS_NGINX_TEMPLATE` at it.

### Deployments with their own ingress

- Already running a load balancer or reverse proxy in front? Start with
  `docker compose -f docker-compose.yml -f docker-compose.external-ingress.yml up -d` and
  the built-in proxy stays out of the way while the frontend publishes plain http on 80
  for your ingress. Setting `COMPOSE_FILE` in `.env` makes that the default for every
  later command. The contract for such an ingress is unchanged and is written out in
  `docs/QUICKSTART.md`.
- Two settings belong to that ingress: forward the Host header with the port people
  connect to, which is what lets the backend recognise a same-origin request, and set
  `TRUSTED_PROXIES` to the ingress address so requests are attributed to the client.

### Documentation in three languages

- The README, the quickstart, the security policy, the contribution guide, the settings
  reference and the four operations procedures now read in English at the top level, with
  Traditional Chinese under `docs/zh-TW/` and Japanese under `docs/ja/`. Each file links
  to its counterparts, and `docs/README.md` indexes all three.

## 1.3.1 — spreadsheet-safe CSV files in audit exports (2026-09-04)

No schema change. No migration runs.

### Event reports and evidence bundles

- Every CSV file inside an event report or an evidence bundle now applies the same
  formula-escaping rule as the query console export and the rotation evidence report.
  A text cell that starts with `=`, `+`, `-`, `@`, a tab or a carriage return gets a
  leading apostrophe, so a spreadsheet shows it as text instead of running it as a
  formula. Plain numbers, including negative ones, are written as they are.
- The manifest of each package records that this rule was applied, and the export
  dialog says so before you download. For the exact original text of a command, use
  the record reference in the file to look the record up in the system.

## 1.3.0 — password rotation for Windows local accounts (2026-09-03)

**This release changes the database schema.** The migration
`20260904_windows_local_account_rotation` runs when the backend starts and adds six
columns to the assets table. Existing rows are not touched.

**Back up before you upgrade and keep your current images.** Section 2 of
`docs/ops/upgrade-sop.md` lists what to record before stopping the old version and
what to check afterwards. To go back, restore that backup with the previous images.
Rotation channel settings made after the upgrade, including uploaded CA
certificates, are not in it, so note them down first.

**Nothing changes until you set it up.** SSH assets keep rotating as before. RDP
assets start rotating once an administrator gives them a rotation channel.

### Windows hosts join password rotation

- Rotation plans now cover Windows local accounts. Pick the Windows assets in a plan
  and the product rotates each account over the channel set on the asset, on the same
  schedule and with the same records as your Linux hosts.
- Two ways to reach a Windows host. WinRM, for hosts that already have remote
  management on. SSH to PowerShell, for hosts that run OpenSSH Server. Both use one
  script, so the outcome looks the same whichever you choose.
- WinRM traffic is always NTLM with message level encryption, over http and https
  alike. Https adds server certificate verification with your choice of trust: the
  operating system store, a CA certificate uploaded on the asset, or none for lab
  hosts.
- Each account rotates itself. It logs in with its own credentials, sets the new
  password, then confirms on the host that the new password works before the product
  commits it. If that confirmation fails, the script restores the old password on the
  spot, so the host is never left with a password nobody knows.
- Passwords travel on standard input only. They never appear on a command line, in
  the script text, in logs, or in records.
- Execution records show which channel was used and, when something goes wrong, a
  reason you can act on in all three languages.

### Setting it up

- Asset form: RDP assets get a rotation channel section with the WinRM transport,
  port and certificate options, or the SSH port for PowerShell. SSH assets get a
  switch that marks the host as Windows OpenSSH.
- Plan form: the asset list shows each asset's channel, so you can see at a glance
  which hosts a plan will reach.
- Transmission inventory: assets rotating over WinRM appear as their own row, and the
  asset risk badge shows when a channel runs over http or skips certificate
  verification.

### Target host requirements

- Enable the WinRM service and listener, set `LocalAccountTokenFilterPolicy` to 1,
  leave `AllowUnencrypted` at false and Basic authentication off, and provide a server
  certificate for https. For the SSH channel install OpenSSH Server; cmd or PowerShell
  as the default shell both work. Account names follow the Windows rules for local
  accounts, so a name with spaces, non-ASCII characters or `@` rotates like any other.
  The full checklist is in `docs/ops/upgrade-sop.md`.

### Login credentials stay out of browser storage

- The credential a browser uses to call the API now lives only in the memory of the
  open page. Closing the tab discards it, and nothing is left behind on disk.
- Reloading a page or opening a new tab restores the session from the session cookie,
  so the page you were on is the page you come back to.
- Logging out in one tab logs out every tab of that browser.
- Watching a live session and joining a shared session now open the same way a
  terminal does: the page asks for a single-use ticket first, so no login credential
  ever appears in a WebSocket address.
- One thing to check before you upgrade: if your deployment is reached over plain
  http, turn off the "mark the session cookie as Secure" policy on the security
  policy page. On an existing deployment the environment variable no longer changes
  it, because that value only seeds the policy on the very first start. A browser
  will not keep that cookie over http, and without it a reload sends the user back to
  the login page. The login page explains this when it happens, and
  `docs/ops/deployment-topology-limits.md` covers the two ways to resolve it.

### Dependencies

- New backend dependencies: `github.com/masterzen/winrm` for WS-Management messages
  and `github.com/bodgit/ntlmssp` for NTLM.

## 1.2.5 — evidence that credentials are being rotated (2026-09-03)

**This release changes the database schema.** One migration,
`20260903_rotation_evidence_report`, runs when the backend starts. It adds columns to
three existing tables and creates one table. Existing rows are not rewritten, so the
first start after the upgrade takes about as long as usual.

**The backend image is about 21 MB larger.** Reports are rendered as PDF with a font
that covers Traditional Chinese and Japanese, and that font is compiled into the
backend binary. Allow for it when you pull images.

**Back up before you upgrade, and keep the images you are running now.** What to
record before you stop the old version, and what to check afterwards, is section 2 of
`docs/ops/upgrade-sop.md`. Going back means restoring the pre-upgrade backup with the
previous images. Report schedules and policy values set after the upgrade are not in
that backup, so write them down before going back.

**Nothing changes until you set it up.** The new policy value ships as zero, which
means off; plans carry no override; with no schedule defined, no report is produced.

### Rotation evidence

- A rotation evidence page lists every asset account the system holds, with the
  maximum credential age that applies to it, where that number comes from, when it was
  last rotated successfully, how many days are left, and a status. Administrators and
  auditors reach it from the audit group in the sidebar.
- Each account carries one status: unverified candidate, no policy set, no rotation
  record, overdue, due within thirty days, or compliant. An account the system holds no
  successful rotation for is reported under its own count rather than as overdue.
- Two compliance rates sit side by side. One leaves accounts without a record out of
  the calculation; the other counts them as not compliant. Each carries the sentence
  that defines it, and when there is nothing to divide by, the page says the rate does
  not apply instead of showing zero percent.
- The population is the asset accounts registered in the system. The product reads its
  own records rather than scanning target hosts, and every output states that.
- A report covers the whole system, one asset node together with everything below it,
  or the accounts one rotation plan reaches.
- A report is delivered as a package: a PDF to read, two CSV files to work with, a manifest
  listing every file with its checksum, and a signature over the manifest. The manifest
  is written last, so a package without one is incomplete and is not evidence. CSV files
  open in a spreadsheet with the right encoding, and cells a spreadsheet would run as a
  formula are rewritten.
- Reports are written in Traditional Chinese, English, or Japanese. Dates carry their
  time zone offset in every language.

### Scheduling and delivery

- Administrators can define report schedules, each with its own timetable, scope,
  retention period, and language. Consecutive reports from one schedule cover
  consecutive periods that meet end to end, across restarts and missed runs alike. A
  schedule can also produce a report immediately, which counts as that period arriving
  early.
- Any account holding audit view permission can produce a report on demand for a period
  it chooses.
- The downloads page now has two tabs. My exports holds the evidence packages the
  account requested itself and behaves as before. Rotation reports lists report
  packages and is shared: any account with audit view permission can list and download
  them, because a report carries no recordings, no clipboard text and no credential
  material, and because a scheduled report has no requester to bind to. Evidence
  packages stay bound to the account that asked for them, and every download is audited
  with the file checksum.
- Report packages are written to the same directory as evidence packages and are kept
  for the retention period their schedule sets, which can be much longer than the 24
  hours an evidence package lives. That directory is still not a backup target: a
  report restates facts held in the database, and producing one again after a restore
  gives a fresh package with its own generation time and signature. Size the disk for
  the reports you schedule.
- The export directory sits inside the backend container and starts empty every time
  the container is rebuilt. Mount it as a volume, or turn on offsite storage, to hold
  report packages for the whole retention period their schedule sets.

### Credential policy

- A security policy sets the maximum age for asset account credentials, in days. It
  ships as zero, which means off, and it feeds the rotation evidence report. Platform
  user passwords keep their own separate settings. The PCI DSS figure is shown on the
  policy page as a reference value, because requirement 8.6.3 asks each organization to
  set this frequency from its own targeted risk analysis instead of naming a number.
- A rotation plan can override that figure for the accounts it covers. Where several
  plans cover one account, the report takes the strictest and names all of them.

### Shared credentials

- Creating an asset account by copying another marks both as sharing one credential,
  and the report shows the mark. A successful rotation clears it for that account, and
  once a single account is left holding the mark, it clears there too. The mark states
  what the system observed: a credential edited by hand keeps whatever mark it had, and
  accounts copied before this release carry none.

## 1.2.0 — a query console for database assets, and a sign-in notice (2026-09-02)

**This release changes the database schema.** Two migrations run when the backend
starts. `20260826_db_query_console` adds columns to three existing tables for the
query console; it does not rewrite existing rows. `20260903_security_policies_value_text`
widens the column that stores policy values so a sign-in notice fits. The first start
after the upgrade takes about as long as usual.

**Back up before you upgrade, and keep the images you are running now.** What to
record before you stop the old version, and what to check afterwards, is section 2
of `docs/ops/upgrade-sop.md`. Going back means restoring the pre-upgrade backup
with the previous images: neither migration has a production rollback path. A
sign-in notice written after the upgrade is not in that backup, so copy the text
from the security policy page before going back.

### Query console

- Database assets on MySQL, PostgreSQL, and SQL Server open in a query console, a
  workspace tab beside the terminal. The backend connects with its own database
  driver using the credentials it holds for the asset; no client program runs, and
  the browser never receives the credentials.
- Every statement is written to the audit trail before it executes. Each entry
  records the target database, the outcome (completed, error, blocked, cancelled,
  timed out, partial, or unknown effect), row counts, and the transaction state
  afterwards. If the audit entry cannot be written, the statement does not run.
  Command blocking and alert rules apply to console statements the same way they
  apply to terminal sessions.
- Console sessions are transcribed and play back in the session viewer. The
  transcript carries statements and result summaries, not result rows. Error
  messages returned by the database are kept as received and may contain data
  fragments.
- An asset can carry a list of allowed databases. The object tree then shows only
  those, and a statement aimed elsewhere is refused and recorded. Changing the
  list takes effect on the next statement.
- Result sets export as CSV when the file download policy allows it. The backend
  streams the file, records every export with its size and checksum, and rewrites
  cell values that a spreadsheet would run as formulas.
- The command audit page filters by outcome, target database, and error code.
  Session detail lists the facts recorded for each statement.
- A user can hold up to four console sessions at once, and a deployment up to
  sixty-four. Capacity notes are in `docs/ops/deployment-topology-limits.md`.

### Sign-in notice

- Administrators can set a title and a text under security policies. The sign-in
  page shows them above the credential form, as plain text, on every step of
  signing in. Leave the text empty and nothing is shown. Anyone who reaches the
  sign-in page can read the notice, so keep internal details out of it. Changes
  are audited with the full text before and after.

### Interface

- The message shown when the site is opened over plain HTTP is now two short lines.
- The sign-in page scrolls when its content is taller than the window, so small
  screens reach the form.

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

# Deployment Topology Limits

**English** | [繁體中文](../zh-TW/ops/deployment-topology-limits.md) | [日本語](../ja/ops/deployment-topology-limits.md) | [More languages →](../README.md)

> Applies to: Custodexa 1.0.

## Topologies supported in this release

**This release is a single-instance deployment: the whole system runs exactly one application instance.**

Running two or more application instances at the same time causes data problems. That topology is neither designed for nor verified, and must not be used in production.

**As of this release, a second application instance started against the same database is stopped and asked to confirm.** It halts before any write: it prints the lock holder's fingerprint and two recovery commands, and until it is acknowledged it does not open its listener, does not run migrations, and does not write to the database. An operator can start it by setting `INSTANCE_GUARD_ACK` to the confirmation code from the message, but every acknowledged start leaves an `audit_logs` event, a metric, and a persistent banner in the admin interface. **A start after acknowledgement leaves audit evidence.**

**The guard protects against acting unaware, not against the situation occurring.** Data problems caused by two instances coexisting after an acknowledgement are not prevented by the guard; they are owned by whoever acknowledged. What the guard guarantees is the halt, the notification, and the ability to prove afterwards from `audit_logs` which instance acknowledged, when, and against which lock holder. For reading the message and the recovery procedure, see [Deployment and Upgrade SOP §2.6b](./upgrade-sop.md#26b-if-the-backend-is-stopped-and-reports-that-the-single-instance-lock-is-held-by-another-database-session).

The following three architectures are specifically excluded:

- Two or more application instances behind a load balancer.
- High-availability (HA), active-active, or active-standby multi-replica deployments.
- Upgrading by rolling update; the switchover necessarily has the old and new instances coexisting.
  **A rolling update between guard-bearing releases is stopped on the new instance** (when the new instance takes the lock it sees the old instance holding it, and halts at the acknowledgement gate). The one upgrade from a release without the guard to this release is not stopped (the old release holds no lock), and depends on the checks in the upgrade SOP.

> This limit applies to the **application instance**. Running the database, guacd, and the frontend nginx as separate containers is the normal deployment shape and is not affected.

> **The guard only recognizes guard-bearing releases.** Older releases without the guard hold no lock: on the first upgrade from a release without the guard to this one, and on a rollback from this release to one without the guard, coexisting old and new instances are not stopped. Those two windows are covered by the "confirm the old instance has stopped" check in the upgrade SOP.

> **Connection pool mode.** The application must connect to postgres directly, or through a pool in session pooling mode. Transaction pooling lets the lock drift between sessions, and the guard will repeatedly report losing and retaking it. That topology is not supported.

## Keeping sign-in state when the service is exposed over plain HTTP

**A deployment still exposed over http must turn off the security policy "mark the refresh cookie Secure."** Sign-in state is kept in a single HttpOnly cookie, and while that policy key is at its default (on), the browser only stores and returns it over an https connection; over plain http it is never stored at all. Users can still sign in, but reloading the page, opening a new tab, or closing a tab and coming back all return to the sign-in page; nothing usable for restoring the session was left on the browser side (the access token exists only in the page's runtime memory and is never written to browser storage).

How to recognize it: pressing reload after signing in asks for sign-in again, and the sign-in page itself explains why. There are two responses. The correct one is to configure https on the public entry point; until then, turning that key off in the security policy restores normal sign-in persistence, at the cost of the credential for the sign-in state travelling over an unencrypted connection. That is the same order of risk as running the whole deployment over http, not an additional risk, but it should not become a long-term state either.

## Outbound connection requirements for the credential change channel

Credential changes are initiated by the backend container towards the target host; they pass through neither the frontend nginx nor the user's browser. Linux hosts use the target's SSH port; Windows hosts use whichever change channel is configured on the asset, either the target's WinRM port (http 5985 or https 5986, configurable) or its SSH port (22 by default, configurable). The WinRM transport **does not read proxy environment variables and does not follow HTTP redirects**, and speaks only HTTP/1.1; if traffic between the backend and the target must pass through a proxy or a redirect, WinRM credential changes for that host cannot connect. When the https certificate verification mode is `system`, the trust anchor is the certificate store of the backend container's operating system; for a listener certificate issued by an internal CA, use `ca` mode instead and upload that CA on the asset. For target-side prerequisites, see the Windows local account credential change section of §2.5 in the [Deployment and Upgrade SOP](./upgrade-sop.md).

## State of the base systems of components (affects vulnerability management planning)

**The base system of the guacd container used for RDP and VNC no longer receives security updates.**

This project's guacd image is built on the official Apache Guacamole image, whose base is Alpine 3.18, past its official support period. **This is not a choice made by this project**: the official `latest` and `1.6.0` are the same `alpine-minirootfs-3.18.12`, and upstream has not yet provided a newer base.

Two consequences matter for your deployment planning:

- **The operating system layer of that container will receive no further security patches** until upstream updates the base.
- **Vulnerability scan results for that image cannot be used as a security basis.** Scanning it yields "zero findings," which correctly reads as "no data": a system past its support period no longer receives vulnerability database updates, and guacd itself is a compiled binary that is not in the package list, so the scanner cannot see it.

Structural mitigations already in place (in effect with the default deployment, no extra configuration needed):

- guacd **exposes no port at all**; it exists only on the compose internal network, and the only thing that can reach it is this system's backend service.
- The recording directory is its only shared mount point. **Enabling offsite storage does not change this**: guacd still writes directly into the local recording directory, and the upload is performed separately by the backend **after the session ends**. guacd never touches object storage and holds no storage credentials. For the same reason, **recordings left behind on a crash path do not go offsite**: for a file whose session ended abnormally without a completed write confirmation, the system creates no upload tracking, and the existing local cleanup mechanism handles it. Offsite retention covers recordings that ended normally and were confirmed written. On retrieval, the staging area the file lands in is **a cache local to the backend container** (with a lifetime and a total size cap), which likewise is not shared with guacd.

**Mitigation is not the absence of risk**: if the backend is compromised, or a managed remote desktop host attacks back through the protocol, that path still exists. **If your vulnerability management policy requires every component's base system to be within its support period, put this image into an exception assessment before deployment.**

## How allowed source ranges affect the deployment

**Allowed source ranges (`allowed_cidrs`) restrict which source addresses an account may use the system from.** An empty list means no source restriction, which is the default. It restricts the **usable sources**; it does not replace the password policy, account lockout, or multi-factor.

### First decide how the "source address" is determined

This system has exactly one way of determining where a request came from, shared by every path:

- **When `TRUSTED_PROXIES` is not set, only the socket peer is trusted**, meaning the far end of the TCP connection. Forwarding headers such as `X-Forwarded-For`, `X-Real-IP`, and `Forwarded` **are never trusted**.
- Once `TRUSTED_PROXIES` is set, forwarding headers are interpreted according to the trusted proxy chain you declared. **If the value is invalid the backend refuses to start**; it does not fall back to the default and keep running.

Not trusting headers by default is deliberate: those headers are controlled by the caller. Trusting them lets anyone who can send a request set an arbitrary address on their own audit row, and lets them bypass any address-keyed restriction by using a different header each time.

**When the application sits behind a reverse proxy, load balancer, or CDN and `TRUSTED_PROXIES` is not set, the source the system sees is always that proxy's address.** Three consequences:

- Allowed source ranges are evaluated against the proxy address. Entering your users' ranges blocks **everyone**; entering the proxy address permits everyone who goes through that proxy.
- The source address pivot in the audit workbench, and the source address column on audit rows and session rows, all record the proxy address.
- The new source address alert only fires when the proxy address changes.

**The default deployment brings its own proxy, and `bash scripts/quickstart.sh` fills `TRUSTED_PROXIES` in with the Docker subnet that proxy runs on.** Run an ingress of your own and the list is yours to write: put the ingress address, or the range it connects from, there.

**To evaluate and record the real source, you must first set `TRUSTED_PROXIES` and list the proxy chain explicitly.** Make this decision **before** enabling source restrictions: setting up the list first and then changing the proxy configuration makes an already-effective list suddenly apply to a different set of addresses.

### Which entry points are blocked, and what a block looks like

When the list is non-empty and the source does not fall within it, the following actions are all denied:

- Sign-in (including multi-factor completion and the OIDC exchange), and the issuance and consumption of the restricted tickets for forced enrollment and forced password change.
- Web session refresh.
- Connection issuance, and both redemption entry points, text terminal and graphical. **Each redemption reads the current list and evaluates again**, rather than reusing the conclusion from the moment of issuance.
- Three administrator endpoints (**resetting another user's password**, **unlocking another user's account**, and **clearing another user's multi-factor**), evaluated against **the operator's own** list.

A blocked response **says only "this source is not allowed"; it does not echo the address and does not list the ranges**. The address and a snapshot of the matched list are written only to the audit record. Connection-type denials additionally carry the machine field `reason=source_not_allowed`, from which the interface shows "your current source is outside the allowed range" instead of opening a request dialog.

**When the list cannot be read or its content is corrupt the action is always denied** (it is not treated as an empty list and permitted), and the outward response is exactly the same as for a source mismatch; diverging would tell the caller "this account's policy is broken." Such a case opens a `source_policy` event in the audit failure panel of the admin interface, with the cause classified as either unreadable or a corrupt string; the system closes it out by itself once the data is fixed.

### Before tightening the list: notify the people it will block

**Tightening the list does not cut off people already online.** Specifically:

- Web access tokens already issued remain usable for their lifetime, with **a residual window of at most 15 minutes**; after that every `refresh` is denied, the user is returned to the sign-in page, and the source evaluation blocks the next sign-in.
- **Protocol connections already established are not actively cut when the list is tightened**; they run to their normal end. Only the next connection is blocked.
- Actions such as issuing a full session or a restricted ticket, and writing authentication state, are all evaluated before the action takes effect, so after tightening no new session can grow from an address outside the list.

The right way to tighten the list is therefore to **notify first**: tell the affected people the new usable sources, when the change takes effect, and who to contact if they are blocked. Tightening without notification shows up as failed refreshes and being kicked back to the sign-in page, and users cannot tell that apart from a system fault.

### How to recover when an administrator locks themselves out

**The system does not block such a save**, because an administrator may deliberately configure a range they have not yet moved to. The interface only shows a warning next to the field before saving; it does not block submission.

If you really are locked out, in order:

1. **Another administrator is available**: ask them to change the list back in the admin interface. This path leaves a field-level audit diff (the list's before and after values), and is the preferred one.
2. **No other administrator is available**: use the existing offline reset path, connecting to the database directly to clear that account's list to an empty string. For the literal steps and the SQL, see [Quick Start — Lost admin password, a startup blocked by the weak-credential scan, or an administrator locked out by source restrictions (offline reset)](../QUICKSTART.md#lost-admin-password-a-startup-blocked-by-the-weak-credential-scan-or-an-administrator-locked-out-by-source-restrictions-offline-reset). This one **only needs the list cleared; the password does not have to be touched**.

An offline reset **does not go through product audit**: it bypasses the application and writes to the database directly, so `audit_logs` has no corresponding row. **The record of that operation is owned by the deployment's own change management** (who touched the database, when, under what authorization). What the product side can show afterwards is the sign-in audit rows after recovery (including the source address), and the field-level diff left when the list is configured again through the interface. No service restart is needed after clearing. **But do not stop at the cleared state**, because that means every address can get in.

### What the new source address alert means for operations

The first time an account establishes a protocol connection from a given source address, the system produces a `new_source_ip` alert and pushes it through the existing notification channels. Each (account, address) pair fires once.

Three things to keep in mind when reading it:

- **It means "this account has not connected from here before," not "this attempt was blocked."** Whether the attempt is permitted is decided by allowed source ranges, and the two do not affect each other: with an empty list every new address fires, while a connection the list blocks never reaches the point of establishing a connection at all.
- **Signing in without connecting does not fire it**; it only adds that address to the baseline. The typical flow of signing in and then connecting still fires once at connection time.
- **Addresses already visible at the time of the upgrade do not fire**: on upgrade the system backfills a baseline from the full session history and successful sign-in records. A fresh installation has no history to backfill, so the first batch of connections each fire once, which is expected.

If your users are on floating addresses (home broadband, mobile networks, rotating VPN egress), these alerts will be quite frequent. They suit being a "worth a look" signal, not a blocking condition; use allowed source ranges to block.

### Effect on backup and restore

Nothing new to store. Allowed source ranges and the source address baseline both live in PostgreSQL and are backed up along with the database; the existing [backup and restore](./backup-and-restore.md) procedure is unchanged and needs no extra steps.

## Effect on upgrades

Upgrades must be performed with downtime; rolling updates are not permitted. For the procedure, see the [Deployment and Upgrade SOP](./upgrade-sop.md).

As of this release, **there is one more reason a new instance may fail to come up: the old instance is still running, or its database session is left over**. A leftover only happens when the lock holder's host crashes or a network partition leaves the TCP connection half open; postgres reclaims that session according to the operating system's TCP keepalive (the postgres container sets nothing of its own, so the Linux default of roughly 2 hours applies). The startup log prints the lock holder's fingerprint and the confirmation code; for the recovery procedure, see [Deployment and Upgrade SOP §2.6b](./upgrade-sop.md#26b-if-the-backend-is-stopped-and-reports-that-the-single-instance-lock-is-held-by-another-database-session). **Recovery requires no operation on the database.**

The mutual exclusion guarantee only holds between guard-bearing releases. On the first upgrade from a release without the guard, the new release acquiring the lock **does not mean** the old one has stopped; the first-upgrade check in §2.3 of the upgrade SOP is the only source of evidence.

If the lock is lost at runtime (postgres restart, the session being terminated, a network event), this instance **keeps serving** and retakes it each cycle. During that time the admin interface shows a persistent banner, the metric `custodexa_instance_guard_held` is 0, and `audit_logs` holds an `instance_guard` event; for how to read them, see [Deployment and Upgrade SOP §3.4](./upgrade-sop.md#34-losing-the-single-instance-lock-at-runtime-reading-the-log-the-banner-and-the-audit-event).

## Effect on availability planning

The single-instance shape has no automatic failover, so availability planning works on shortening the time to restore: keep backups and KEK material ready at all times, and rehearse the restore procedure in advance. See [backup and restore](./backup-and-restore.md).

**Offsite evidence storage changes whether evidence can be lost, not how fast the service comes back.** Keep the two apart when planning:

- **It shortens the exposure window for evidence; it does not remove it.** The upload happens only after the session ends: text recordings are queued within seconds, graphical recordings wait at least a minute (until the file stops changing), and if the storage endpoint is unreachable they wait until it recovers. **Within that window the local copy is still the only copy.** If the machine is destroyed then, that recording has no second copy.
- **It does not change the recovery time objective.** A remote copy means evidence already offsite can still be retrieved after the machine is destroyed, but bringing the system back into service still requires the restore procedure (database, KEK, deployment-layer configuration). **Offsite storage is not a substitute for backups**; plan for both together.
- **The first playback of an offsite recording involves a download wait.** For a recording whose local copy has been cleared, playback first retrieves it from object storage, writes it locally, and verifies the hash before streaming begins; the wait depends on file size and bandwidth. This is expected behavior, not a fault, and it happens only on that recording's first playback (the staged cache is reusable within its lifetime). If your audit work has response time requirements, count this wait in.

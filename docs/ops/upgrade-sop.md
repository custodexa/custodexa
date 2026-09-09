# Deployment and Upgrade SOP

**English** | [繁體中文](../zh-TW/ops/upgrade-sop.md) | [日本語](../ja/ops/upgrade-sop.md) | [More languages →](../README.md)

> Applies to: Custodexa 1.0.
>
> This document covers two things: **the mandatory checks for a new installation** and **the version upgrade procedure for an existing deployment**.
>
> Related documents: [Backup and Restore](./backup-and-restore.md), [Deployment Topology Limits](./deployment-topology-limits.md),
> [Rotating the Platform's Own Privileged Credentials](./privileged-credential-rotation.md).
>
> The `docker compose` commands in this document assume the production shape (`docker-compose.yml`, with the built-in TLS reverse proxy).
> For a deployment where your own ingress terminates TLS (`docker-compose.external-ingress.yml`), always pass both `-f` flags
> (`-f docker-compose.yml -f docker-compose.external-ingress.yml`), or set `COMPOSE_FILE` in `.env` so that becomes the
> default; with only one of them the stack starts in the built-in TLS proxy shape.

---

## 1. New installation delivery checklist (mandatory at delivery)

Every item below is **a step the delivery engineer must perform**, not something to consider. The consequence of skipping one is in that item's "if you skip it" note; sign each item off at delivery acceptance.

### 1.1 Apply the compliance baseline values

**The factory defaults favor ease of use, so a new installation without the compliance baseline applied is a non-compliant system.**

The factory values of the security policies exist so the system works as soon as it is installed, not so it is compliant. For example:

| Policy | Factory value | What the policy groups in effect ask for |
|---|---|---|
| Transport enforcement level (RDP, VNC, database, LDAP, syslog, notifications; six keys) | `off` (not enforced) | No level: the clause on transport encryption asks for strong encryption without naming one of the three levels (`off`, `warn`, `strict`). See the last paragraph of this item |
| Global default access policy tier | `open` | `approval` |

**How**: as an admin, open each policy page in turn (security policy, transport security, access control, key management), use that page's **Apply recommended values** menu to fill in the values, and **then press save**. The header of each policy page lists the policy groups in effect, and the menu holds one entry per group plus **Meet every policy at once**:

- **One group**: fills in that group's requirements for the policy keys on that page. A value already stricter than what that group asks for stays as it is, and a value that already meets a requirement of another group in effect is not relaxed either — applying one group never gives up what another one has secured.
- **Meet every policy at once**: for each setting, takes the strictest requirement across every group in effect (the largest value where a requirement is a minimum, the smallest where it is a maximum). Where the PCI DSS group asks for a minimum password length of 12 and the electronic payment baseline asks for 6, for instance, this fills in 12; it never lowers a setting to the more permissive of the two. Where two groups ask for opposite values on the same setting, that setting is **left as it is**: the preview names it and says which two requirements disagree, and the decision is yours.

Either way, the apply shows a preview first. It lists only the settings that would change, each with its current value, the value it would become, and the group that value comes from.

The WinRM credential change channel is **not one of those six keys**: a credential change is a system path rather than a user connection, so it has neither an enforcement level nor a consent gate. Its encryption state (message-layer encryption over http, the certificate verification mode over https) appears only in the `winrm` row of the transport inventory and on the asset risk badge; see the Windows section of §2.5.

Confirming a preview only fills in form values, and **nothing takes effect until you press save**; you can revert at any point before saving. The scope of an apply is the policy keys on the current page, so it has to be done page by page and one pass does not cover everything.

**An apply does not raise the six transport enforcement levels.** Neither built-in policy group names a level for them, so they stay at their factory value and the compliance map lists them as awaiting audit judgement, showing the current value. Choosing the level per protocol is a decision you make, and it is part of this checklist item.

> **If you skip it**: the transport enforcement and access control of the new system all sit at their most permissive, with no warning of any kind. The system does not decide for you whether they should be tightened.

### 1.2 Configure the off-box log collector (syslog forwarding), a required companion, not an option

**Where**: System Settings → Security Policy → log forwarding settings.

The audit integrity mechanism (the checkpoint chain) **covers only local integrity while no off-box collector is configured**. It can prove that the records in the database have not been altered, but it cannot counter replacing the local data together with the checkpoints (including rolling the whole database back to an older backup). For such an attack to be discovered there has to be a copy the system itself cannot reach.

While it is not configured, the verification page in the product marks a degraded state at the top and points at that setting; **but that is the product reminding you afterwards, not a check before deployment. This checklist is that check.**

> **If you skip it**: the outward claims of the integrity mechanism have to be narrowed accordingly. On a deployment without a collector configured, you **must not** claim the system can counter an insider with database access swapping records out: the defense there rests on the retention at the collector, and with no collector the defense does not exist.

The transport encryption of the forwarding itself is governed separately by the `transport_syslog_level` policy key (see 1.1).

### 1.3 Check the file permissions on `DATA_PATH`

Under a bind mount, permission settings inside the image do not apply, and the host-side directory permissions are the deployment's responsibility. Recording files contain everything the user typed on the target host. For details, see
[Backup and Restore §3.6](./backup-and-restore.md#36-file-permissions-on-data_path-the-deployments-responsibility).

> **If you skip it**: any local account on the host can read every session recording.

**If you intend to enable offsite evidence storage**, prepare a storage identity dedicated to this system, with permissions no broader than this minimum set:

- **Upload**: write objects under the prefix you specify.
- **Retrieve**: read objects and their metadata.
- **Read the bucket configuration**: so the connection test in the admin interface can report the current versioning and retention settings faithfully. If it cannot be read, that only shows as a warning (**uploads are unaffected**), so whether to grant this one is up to your permission policy.

**No write permission on retention fields is needed**, because the product never sets a retention period on an object. **No delete permission is needed either**: the normal paths never delete remotely, and the only place delete is used is the connection test clearing the probe object it left behind, where a failure is only recorded as a warning. For suggested values for the bucket's own versioning, retention, and lifecycle rules, see
[Backup and Restore §3.7](./backup-and-restore.md#37-suggested-settings-for-the-object-storage-bucket-the-deployments-responsibility).

### 1.4 Replace the factory secrets and remove the initial password

- `JWT_SECRET`: the factory value is a placeholder string; in release mode, detecting that it has not been changed means refusing to start (fail closed).
- `ENCRYPTION_KEY` (needed only for KEK mode A): the shipping default is `KEK_PROVIDER=ui` (the key is never written to disk), and in that mode this key must stay empty; a value in it is a configuration contradiction and the system refuses to start.
  **If you use mode A**, generate 32 characters of material with a CSPRNG and **declare `KEK_PROVIDER=env` explicitly**: with the explicit declaration, material in an unacceptable format means refusing to start, whereas setting only `ENCRYPTION_KEY` without the declaration takes the backward-compatible path for existing deployments, which **deliberately applies no format validation**. A new installation relying on that path gives up this check.
- `ADMIN_INITIAL_PASSWORD`: **remove it from `.env`** once the database initialization is complete.
  While a value in a valid format remains, the system warns about it in the startup log (this one warns, it does not fail closed), but leaving it there means a static credential that stays valid indefinitely.

### 1.5 Confirm the deployment topology

This release **is a single-instance deployment**. Before delivery, confirm the architecture plan assumes no multiple instances, no multiple replicas behind a load balancer, and no rolling updates. For details, see [Deployment Topology Limits](./deployment-topology-limits.md).

This release **stops a second application instance started against the same database and asks for confirmation** (for reading the message and recovering, see §2.6b). What that stop guarantees has two boundaries, and both should be conveyed to the customer at delivery:

- It only holds between guard-bearing releases. Older releases without the guard hold no lock, so a mixed-version coexistence is not stopped.
- What it stops is coexistence you are unaware of, not coexistence itself. Once an operator starts with the confirmation code, the two instances run at the same time; the data consequences are owned by whoever confirmed, and what the guard guarantees is that this is recorded (an `audit_logs` event, a metric, and a banner in the admin interface).

### 1.6 Establish the backup procedure and rehearse it once

Delivery does not end with the system installed. Complete these at the same time:

- Set up regular backups per [Backup and Restore](./backup-and-restore.md), and confirm off-machine custody of the KEK material is in place.
- **Record the four fingerprints from the key inventory** (`ENCRYPTION_KEY (KEK)`, `JWT_SECRET`, the export signing key (Ed25519), and the checkpoint signing key (Ed25519)) and keep them with the backups.
- If the KEK uses interface-entry mode, complete the **pre-deployment disclosure** to the customer: losing the material means the data is permanently undecryptable, and the product offers no way to recover it.

### 1.7 Configure the login banner

**Where**: System Settings → Security Policy → login banner.

Before a user signs in, the sign-in page shows a passage you wrote, declaring that the system is for authorized users only and that all operations are recorded. The wording of that declaration belongs to your legal and HR functions, and the product presumes no content: **it ships empty, and empty means nothing is shown**.

**How**: fill in the title (optional, up to 120 characters, single line) and the body (up to 2000 characters, line breaks allowed) and press save. Once saved, sign out and open the sign-in page to confirm the banner appears before the sign-in form and that the line breaks look right. The content is **plain text**: HTML markup and links are not interpreted and appear literally. Clearing the body stops it being shown (the title is never shown on its own). Each change leaves an audit record containing the full text before and after.

> **The content is readable by anyone before sign-in**, including people who have not signed in and people with no account. Do not put internal host names, contact extensions, system versions, or anything else meant only for insiders into it.

> **If you skip it**: the sign-in entry point carries no access declaration. When you later want to assert to an unauthorized user that they were notified, there is no identifiable point of notification; the system can prove they signed in, not what they saw before signing in.

### 1.8 Run the deployment verification

Run the five steps in the "deployment verification" section of `docs/QUICKSTART.md` (services up, backend health check, frontend reachable, sign-in path, no fatal in the startup log).

---

## 2. Version upgrade procedure

### 2.0 Decide on the rollback plan, confirm the prerequisites, and run the pre-upgrade checks

**There is exactly one rollback path when an upgrade fails: restore the backup** (procedure in section 4). The cost is losing all data produced after the last backup, so decide the backup point and the downtime window accordingly, and do not discover halfway through an upgrade that there is no way back.

**A rollback needs two things, and misses without either: the pre-upgrade backup, and the old version's images.**
The backup is §2.1; the images are the easy square to miss, because all three images are referenced as `custodexa/*:latest`, and one build or pull of the new version overwrites that tag, after which the old image has no name to reach it by.
If you build the images yourself, see the tag-aside step in §2.2; if you deploy delivered images, confirm first that you still hold the old version's image file (or that the version is still obtainable from your registry).

> **What this section applies to**: the database schema of `Custodexa 1.0` starts from a single baseline (`20260816_schema_baseline`) and evolves through **incremental migrations** (the twelve in this release are listed in §2.5 below). This section therefore applies to version changes within the 1.0 baseline generation, that is, to deployments whose database has had that baseline applied.
>
> If the database's `schema_migrations` table contains version values this release's code does not recognize while the baseline has not been applied, the backend refuses to start (see §2.6). Treat such an upgrade across baseline generations as a new installation plus a data migration project; the scope and tooling of that migration have to be agreed separately with the delivering party and are outside this SOP.
>
> Confirm your source version before planning the upgrade.

> **What the single-instance guard guarantees**: as of this release, a second application instance started against the same database is stopped and asked to confirm (§2.6b). That mutual exclusion **only holds between guard-bearing releases**: older releases without the guard hold no lock, so on the first upgrade from a release without the guard, the new release acquiring the lock **does not mean** the old one has stopped. Step 5 of §2.3 is the first-upgrade check that exists for exactly this, and it must not be skipped.

#### Pre-upgrade check: deployments serving over plain http

Whether the web session refresh cookie is stored only over https is decided by the security policy
**"keep sign-in state only over https connections"** (System Settings → Security Policy → "Connections and accounts"), whose factory value is on. This policy is not new in this release, **deployments on v1.0.4 already have it**; the table below is the seeding rule at the first startup while it **has no value yet**:

| `.env` at the first startup after the upgrade | Initial policy value |
|---|---|
| `AUTH_REFRESH_COOKIE_SECURE=true` or `false` present | Taken as is |
| Not set, `PUBLIC_BASE_URL` is `https://…` | On |
| Not set, `PUBLIC_BASE_URL` is `http://…` | Off |
| Neither present | On (the factory value) |

**If you serve over http, set `AUTH_REFRESH_COOKIE_SECURE=false` in `.env` before the upgrade.** Sign-in behavior after the upgrade then matches what it was before.

**But your deployment probably already has a value** (for an existing deployment, if it ever started with `AUTH_REFRESH_COOKIE_SECURE` or `PUBLIC_BASE_URL`, the seeding happened then), and in that case changing `.env` has no effect at all; see the note at the end of this section. **To confirm the current state, look at the actual value of that switch on the security policy page, not at `.env`.**

Not setting it does not make the system unusable: the service starts normally and connections are established normally. The cost is that the browser does not store the refresh cookie, so a user's sign-in state lasts at most 15 minutes (the lifetime of the access token), after which their next action takes them back to the sign-in page and whatever they were looking at is interrupted. The sign-in page explains the situation to the user and asks them to contact an administrator; when an administrator signs in at that same http address, a matching notice appears at the top of the security policy page.
**The system never changes this policy on its own.**

**If you only notice after the upgrade, there is no need to touch the deployment files again**: sign in as admin, turn off "keep sign-in state only over https connections" on System Settings → Security Policy and save, and the next cookie issued uses the new value with no restart needed.

Deployments serving over https do not need this item; leaving the policy on is the correct setting.

> This policy accepts seeding from `.env` only while it has no value. Once it has been seeded, or once someone has saved on the security policy page, changing `.env` has no effect at all, and adjustments always go back to the security policy page.

> **You confirmed the policy is off, yet the sign-in page still says the system keeps sign-in state only over https connections**: that notice is shown by the frontend on three **local** conditions (the page was opened over http, this tab has never refreshed successfully, and the refresh finally failed), and **it does not look at the policy's actual value**. So a brand-new browser (or a private window) opening the sign-in page for the first time sees it even with the policy off. **Always judge the current policy state by the switch on the security policy page**; if it stops appearing after a successful sign-in, this is what happened, and there is no configuration problem to chase.

#### Pre-upgrade check: the external ports and the built-in TLS proxy when upgrading to 1.4.0

The production compose of 1.4.0 has a built-in TLS-terminating reverse proxy (the `tls-init` and `tls-proxy` services), so the external entry point changes. Four things to handle before the upgrade:

- **The external ports become 443 (https) and 80 (http)**, and frontend and backend no longer publish host ports. A host already running something on those ports takes a different pair: set `TLS_HTTPS_PORT` and `TLS_HTTP_PORT` in `.env` (8443 and 8088 are the usual choice) before the upgrade, and the external address then carries the port. Firewall rules, user bookmarks, and the SSO callback URL (`PUBLIC_BASE_URL`) all have to match the new external address.
- **The http port only redirects**: anything arriving on the http port gets a 301 to the external https port, and no content is served there.
- **`TRUSTED_PROXIES` covers the built-in proxy**: with it unset, every request is attributed to the proxy's own address, which is what the audit log records and what the sign-in rate limit counts against. `bash scripts/quickstart.sh` fills it in with the Docker subnet for the built-in form; deployments with their own ingress put that ingress address here instead.
- **Stop the proxy container you started yourself first**: a reverse proxy started by hand per the older guide is not in the compose lifecycle, `docker compose down` does not stop it, and leaving it up makes it contend with the built-in proxy for ports and certificate files. Stop and remove it before the upgrade.
- **Deployments with their own ingress switch to the overlay**: add `-f docker-compose.yml -f docker-compose.external-ingress.yml` to every compose command after the upgrade (or set `COMPOSE_FILE=docker-compose.yml:docker-compose.external-ingress.yml` in `.env`); the built-in proxy does not start and frontend gets its external http port back (80 by default, changed via `HTTP_PORT` in `.env`). Two settings then belong to your ingress: forward the Host header with the port people actually connect to (the backend compares `Origin` against `Host` to recognise a same-origin request, and a `Host` without the port makes an authenticated request look cross-origin), and set `TRUSTED_PROXIES` to the ingress address.

The certificate source is decided by `TLS_MODE` in `.env`: `selfsigned` (the default) generates a local CA and a server certificate at first startup, landing in `tls/` under the project directory; `provided` requires `tls/fullchain.pem` and `tls/privkey.pem` to be in place first, and a missing file fails explicitly at the initialization step with the proxy not starting. `tls/` holds private keys and the local CA and is within backup scope (see [Backup and Restore §2.1](./backup-and-restore.md)).

### 2.1 Pre-upgrade backup (required, not skippable)

Take a **stopped backup** per [Backup and Restore §3.2](./backup-and-restore.md#32-recommended-procedure-service-stopped-best-consistency).

The pre-upgrade backup has to be a stopped backup; a no-downtime backup is not acceptable, because what you restore when an upgrade fails has to be a consistent point in time, not one where the database and the recordings are a few minutes apart.

Confirm at the same time:

- The backup files are readable, which is step 6 of [Backup and Restore §3.2](./backup-and-restore.md#32-recommended-procedure-service-stopped-best-consistency) (`pg_restore --list` and `tar -tzf` inside the container, so the machine you operate from needs no PostgreSQL client).
- The KEK material is in hand (`.env` for mode A, the unseal material for mode B, KMS access for mode C).
- The four fingerprints from the key inventory have been recorded (`ENCRYPTION_KEY (KEK)`, `JWT_SECRET`, the export signing key (Ed25519), and the checkpoint signing key (Ed25519)).
- **The row counts of a few business tables have been noted down**, for the "this is the same data" check in §2.5 after the upgrade:

  ```bash
  docker compose -f docker-compose.yml exec -T postgres \
    psql -U "${DB_USER:?}" -d "${DB_NAME:?}" -tAc \
    "SELECT 'users', count(*) FROM users
     UNION ALL SELECT 'sessions', count(*) FROM sessions
     UNION ALL SELECT 'audit_logs', count(*) FROM audit_logs"
  ```

### 2.2 Build verification (before deploying the new images)

**This applies to those who build the images themselves**: the step needs the full source tree (`docker-compose.yml` and the Dockerfiles are all in the build scope). If you deploy delivered images and have no source tree, this step does not apply; skip to §2.3.

> **When the new source tree is in a different directory, deal with the relative paths in `.env` first.**
> The three data locations of the production compose file (`postgres`, `recordings`, `audit`) are all **bind mounts** of `${DATA_PATH:-./data}`, **with no named volume at all**; and `docker compose` resolves relative paths against **the directory the compose file is in**.
> So after copying an existing deployment's `.env` verbatim into a new source tree in a different directory, `DATA_PATH=./data` (the template's factory value) means **the empty, not-yet-existing data directory under the new directory**, not the original data.
> The service comes up as usual, treats this as a new installation, and runs the baseline from scratch, **with no error message of any kind**: the system cannot tell "this is a new installation" from "you attached the wrong directory."
>
> **What to do**: before the upgrade, change `DATA_PATH` in `.env` to an **absolute path** (`DATA_PATH=/opt/custodexa/data`, for instance), or confirm it still points back at the original data directory from the new one. Check every other path setting in `.env` that starts with `./` or `../` the same way. Updating source and images in place in the original directory is unaffected.
>
> `COMPOSE_PROJECT_NAME` offers no protection: what it isolates is the naming of containers and networks, not where bind mounts land. If you do attach the wrong one, see "the first thing to do after the upgrade" in §2.5 for how to notice before any damage is done.
>
> **Carry `tls/` over to the new directory as well**: the built-in TLS proxy keeps its certificate material in `tls/` under the project directory, not under `DATA_PATH`, and a new directory without it makes `TLS_MODE=selfsigned` issue a fresh self-signed CA on startup, so every client that trusted the old CA loses that trust at the moment of the upgrade. Copy the directory across, or unpack the `tls` archive from the §2.1 backup into the new tree:
>
> ```bash
> cp -a /opt/custodexa/tls /opt/custodexa-new/
> # or, from the pre-upgrade backup:
> tar -xzf "custodexa-tls-${STAMP}.tar.gz" -C /opt/custodexa-new
> ```

> **A build overwrites the tag of the same name: save the current images aside first, or there will be nothing to roll back to.**
> All three images are referenced as `:latest` (`custodexa/backend:latest`, `custodexa/frontend:latest`, `custodexa/guacd:latest`), so as soon as the new build runs, the three currently running images have no name to reach them by. The rollback procedure (§4.2 step 2) needs exactly those. Run this **before the `build` below**:
>
> ```bash
> for img in backend frontend guacd; do
>   docker tag "custodexa/${img}:latest" "custodexa/${img}:pre-upgrade"
> done
> docker images | grep pre-upgrade    # only go on to the build with all three lines present
> ```
>
> The same applies if you deploy delivered images: **keep the old version's image file or confirm the version is still obtainable from the registry**, rather than relying on `:latest`.

From the project root, run one real build of every build target of the production compose file. If any target fails, do not deploy:

```bash
docker compose -f docker-compose.yml build
```

**Always pass `-f docker-compose.yml` explicitly**: if the local `.env` sets `COMPOSE_FILE`, without the flag you may build something other than the production targets. The production and development image names are separate (`custodexa/*:latest` versus `custodexa/*:dev`), so building the production images does not overwrite the development ones.

After a successful build, check one more property that only the production images have: **no executable shell interpreter exists inside the backend image** (which structurally closes the escape surface of the database CLI):

```bash
for sh_path in /bin/sh /bin/ash /bin/bash /usr/bin/sh; do
  docker run --rm --entrypoint "$sh_path" custodexa/backend:latest -c true 2>/dev/null \
    && echo "FAIL: ${sh_path} is still executable"
done
```

It passes only with **no `FAIL` output at all**; a FAIL means the image just built does not meet this release's runtime environment prerequisite.

**This step is mandatory after changing a Dockerfile, `.dockerignore`, or a compose build section.**

#### When you change a base image version, the license documentation has to change with it

All shipping bases are pinned to concrete versions (`alpine:3.24.1`, `nginx:1.31.3-alpine3.24`, `guacamole/guacd:1.6.0`, `postgres:16.15-alpine3.24`).
Section 3 of `THIRD-PARTY-LICENSES.md` promises publicly to provide the corresponding source for the GPL and LGPL components inside those images, and "corresponding" presumes the version can be named. Once a base floats, the promise cannot be kept.

So **changing the version on any `FROM` line requires updating the following in the same commit**:

1. The version table in `THIRD-PARTY-LICENSES.md` §3.1. All three columns have to be read again, not just one: the pinned value in the Dockerfile, the measured value of `/etc/alpine-release` inside the image, and the number of GPL and LGPL packages. The commands to measure (run once per image, replacing `<img>` with `custodexa/backend:latest` and so on):

   ```bash
   cid=$(docker create <img>)
   docker cp "$cid":/etc/alpine-release - | tar -xO
   docker cp "$cid":/lib/apk/db/installed - | tar -xO \
     | awk '/^P:/{p=substr($0,3)} /^L:/{if (substr($0,3) ~ /GPL/) print p}' | wc -l
   docker rm "$cid"
   ```

2. The aports branch name in `THIRD-PARTY-LICENSES.md` §3.2. When Alpine's major version moves, `3.24-stable` becomes a different branch, and source links pointing at the old branch stop working.
3. The release archive in §2.8 (a new version means a new listing, and the three-year period of the old version does not end because of an upgrade).

> **Redo the license inventory after changing a base.** Run your existing SBOM or license scanning tools (`syft` plus `grype`, or `trivy`, for instance) once against each of the three production images. The criterion is that every package has at least one OSI-approved license option, confirming the new base introduced no package that fails it.
>
> **Whatever tool you use, it will not check whether the documentation above is in step; that part is manual.**

### 2.3 Stopping the service

**Choose a low-traffic period.** The reason is in section 3: graceful shutdown has two residual gaps, and the lower the traffic, the fewer audit rows are affected.

The order before stopping:

1. **Stop new connections from arriving** (block them at the frontend reverse proxy layer, or announce a maintenance window).
2. **Wait for sessions in progress to end**, or terminate them deliberately as operations judgment dictates.
3. **Confirm the audit queue has drained** (see §2.4).
4. Issue the stop: `docker compose stop` (which sends SIGTERM and takes the graceful shutdown path).
5. **The check for the first upgrade to a guard-bearing release** (mandatory when the source version has no single-instance guard; doing it on every later upgrade does no harm). The guard **offers no protection in this window**: the old release holds no lock, so the new one will certainly acquire it. Both items have to hold before moving to §2.5:
   - `docker compose ps` shows no backend running. If an instance was ever started on another host, or under another compose project (production and development side by side, for instance) pointing at the same database, check every one of them.
   - The application account has 0 connections on the database (`DB_USER` and `DB_NAME` come from `.env`; for how to obtain them, see
     [Backup and Restore §2.3](./backup-and-restore.md#23-how-the-shell-commands-in-this-document-obtain-deployment-variables-read-before-you-start)):

     ```bash
     docker compose -f docker-compose.yml exec -T postgres \
       psql -U "${DB_USER:?}" -d "${DB_NAME:?}" -tAc \
       "SELECT count(*) FROM pg_stat_activity
        WHERE datname = current_database() AND usename = current_user
          AND pid <> pg_backend_pid()"
     ```

     `pid <> pg_backend_pid()` excludes this psql's own connection. **Non-zero means the old instance is still there, or its session has not been reclaimed, and you must not deploy**: go find it, stop it, and check again until it reads 0.
   - How to read it: **the new release acquiring the lock is not evidence that the old one has stopped.** The evidence for this step is only the two items above.

### 2.4 Confirm the audit queue has drained before stopping

The metric `custodexa_audit_queue_depth` exposes the current depth of the asynchronous audit write queue.

**This endpoint cannot be reached from outside** (see the first point below), so the way to read it is from inside the backend container:

```bash
# When METRICS_TOKEN is empty (the default)
docker compose exec -T backend \
  wget -qO- http://localhost:8080/metrics | grep custodexa_audit_queue_depth

# When METRICS_TOKEN has a value (a missing or wrong token always returns 401 with no metrics in the body)
docker compose exec -T backend \
  wget -qO- --header="Authorization: Bearer <token>" http://localhost:8080/metrics \
  | grep custodexa_audit_queue_depth
```

- **Endpoint**: `/metrics`, on the backend's own HTTP service (8080 inside the container).
  **It is deliberately not under `/api`**: the production edge proxies only `location /api` and `/ws`. Together with the production compose file publishing only nginx's port 80 and not the backend's 8080, this endpoint is reachable only inside the compose network in a default deployment and cannot be reached from outside.
  If you attach the backend to a directly reachable internal network of your own (for Prometheus scraping), reading it from there with `curl -s http://<backend>:8080/metrics` works too.
- **Authentication**: when the `METRICS_TOKEN` environment variable is non-empty, `Authorization: Bearer <token>` is required; when it is empty the endpoint is exposed without authentication (the security of which rests on the edge not proxying it).
- **Criterion**: prefer to stop once the value is `0`. Since this release the shutdown path drains the queue itself (see §3.1), so a non-zero value at the moment of SIGTERM no longer means those rows are lost; it means the shutdown will spend part of its budget writing them. Waiting for `0` keeps the shutdown short and avoids the fallback file.
- **This metric exists only once the system is unsealed.** In the sealed state `/metrics` still answers, but it carries only the seal state and single-instance guard groups, and `grep` finds no `custodexa_audit_queue_depth`. **That is not a broken metric; it is asynchronous audit not being up yet** (it belongs, with the other business components, to stage 2, which is assembled only after unseal).
  Deployments using `KEK_PROVIDER=ui` (mode B) hit this in particular: backend returns to the sealed state on every restart, including after the routine backup in [Backup and Restore §3.2](./backup-and-restore.md#32-recommended-procedure-service-stopped-best-consistency).
  **In the sealed state there is no audit queue to drain**; unseal first, then do this check.

> **The boundary of this metric**: it reads the length of the queue itself, meaning how many rows have not yet been taken by a worker.
> **A value of 0 does not mean every audit row has been written to the database**: a worker may still hold a batch that has not been flushed. The shutdown path flushes those batches and drains whatever is still queued (§3.1); what this check buys you is a shutdown that finishes quickly and cleanly, without touching the fallback file.
>
> Also: the queue exists only while asynchronous audit is enabled. In synchronous mode writes block until they complete, and this metric is always 0.

### 2.5 Deploy the new version

```bash
docker compose -f docker-compose.yml pull    # or load the new images however they were delivered
docker compose -f docker-compose.yml up -d
```

**Before rebuilding the containers, confirm the export directory is mounted or already offsite.** The two lines above rebuild the backend container, and if the export staging directory (`EXPORT_ARTIFACT_PATH`, default `/var/lib/custodexa/exports`) is not mounted as a volume or a bind mount, the artifacts in it disappear with the rebuild. For report artifacts still within their retention period that you want to keep, confirm before the upgrade that the directory is mounted, or that offsite storage is enabled, or download the artifacts beforehand. Evidence package artifacts have a retention period of only 24 hours and are usually unaffected; report artifacts, whose retention period comes from the schedule and can run to years, are what this step is really about.

Database migrations run automatically when the backend starts. **The startup log is the only basis for judging whether the migrations succeeded**, so do not declare the upgrade complete without reading it. The server writes these log lines in Traditional Chinese, and they are reproduced verbatim below so you can match them.

When upgrading to a version that **introduces no new migration** (the database has had the baseline and every existing increment applied), the log reads:

```
開始執行 database migrations...
  跳過已執行的 migration: 20260816_schema_baseline (schema_baseline)
所有 migrations 都已執行，無需更新
```

**When upgrading to a version that introduces new incremental migrations**, each one applied adds a line `執行 migration: <version> (<name>)`, and that increment is applied within a single transaction. A missing line means that increment **did not run** (usually because the source version already contained it), which is not an anomaly. The log lines for this release's thirteen increments read verbatim:

```
  執行 migration: 20260824_audit_export_jobs (audit_export_jobs)
  執行 migration: 20260825_evidence_offsite (evidence_offsite)
  執行 migration: 20260826_source_ip_forensics (source_ip_forensics)
  執行 migration: 20260826_db_query_console (db_query_console)
  執行 migration: 20260903_security_policies_value_text (security_policies_value_text)
  執行 migration: 20260903_rotation_evidence_report (rotation_evidence_report)
  執行 migration: 20260904_windows_local_account_rotation (windows_local_account_rotation)
  執行 migration: 20260905_account_batch_rotation (account_batch_rotation)
  執行 migration: 20260906_credential_library (credential_library)
  執行 migration: 20260906_credential_library_contract (credential_library_contract)
  執行 migration: 20260908_role_state_checkpoint (role_state_checkpoint)
  執行 migration: 20260908_group_role_mapping (group_role_mapping)
  執行 migration: 20260909_policy_groups (policy_groups)
```

`20260825_evidence_offsite` creates the two offsite storage tables (the settings generation table and the custody ledger) and adds two columns each to sessions and export jobs. **It is purely additive, with no data backfill and no codec dependency**, so its duration is independent of how much data you hold.
**Its Down is irreversible for data tracking**, and the ledger listing has to be exported before a rollback; see §4.

`20260826_source_ip_forensics` creates tables and adds columns, and additionally performs a **cold-start backfill** (working out the source addresses each account has already been seen from, out of the full session history and successful sign-in records), so that addresses already visible at the time of the upgrade do not trigger a new source address alert. The backfill's duration grows with the volume held in `sessions` and `audit_logs`, so count it into the downtime window; before the real upgrade, a trial run on a replica environment with comparable data volume is recommended, so the window can be set from a measured duration.

`20260826_db_query_console` adds columns to three existing tables (the allowed database list on assets, the console marker on sessions, and eleven result fact columns on the command audit table), plus three value range constraints and three indexes.
**It only adds columns, with no data backfill**, and every column carries a default, so its duration is independent of the volume held.
**Its `Down` is lossy**; read §4.1 before a rollback.

`20260903_security_policies_value_text` widens the value column of the security policy table from a fixed length to unlimited (the body of the login banner needs it). **It is a pure type widening, with no data conversion and no backfill**; existing policy values are untouched and its duration is independent of the volume held. It creates no table and adds no column, so **the only visible signal after the upgrade is that startup log line above**.

`20260903_rotation_evidence_report` creates the data layer for rotation evidence reports: one column added to each of three existing tables (asset accounts, credential change plans, and export jobs, plus two indexes), and one new report schedule table. **It is purely additive with no data backfill**, and the added columns are all defaulted or nullable, so its duration is independent of the volume held. **Its `Down` is lossy**; read §4.1 before a rollback.

`20260904_windows_local_account_rotation` adds six credential change channel columns to the asset table (channel, WinRM connection method, port, certificate verification mode, CA certificate, and the SSH port used for credential changes), and creates no table, index, or constraint. **It only adds columns, with no data backfill**: after the upgrade the channel column is empty (meaning derived from the protocol, so ssh assets keep their existing credential change path and the rest keep not changing credentials), and the other five are nullable, so its duration is independent of the volume held. **Its `Down` is lossy**; read §4.1 before a rollback.

`20260905_account_batch_rotation` creates the data layer for account-centric batch credential changes: one new batch table (with an index on the account name), a batch reference column on the credential change record table (with an index), and two columns on the pending credential table (the batch reference and the shared credential group the pending credential joins once it is verified). **It is purely additive with no data backfill**: every added column carries a default or is nullable, existing records and pending credentials are marked as coming from a plan (which is what they are), and its duration is independent of the volume held. The batch table stores no password. **Its `Down` is lossy**; read §4.1 before a rollback.

`20260906_credential_library` moves login secrets out of the account rows and into a credential of
their own: it creates four tables (the credential, its immutable secret versions, one rotation, and
that rotation's per-host members) with their indexes, adds two columns to asset accounts (which
credential this host logs in with, and which version it is currently using), two to credential
change plans (the target kind and the target credential), and three snapshot columns each to the
change records and the pending credentials. **In the same transaction it converts the existing
rows**: every surviving asset account gets a credential of its own, and those that held a secret
also get version 1 of it. Accounts left behind by assets removed before the upgrade are converted the
same way and then retired together with their credential in the same transaction, so they do not appear
in the credential library; their ciphertext is kept. The ciphertext is moved as it is, not decrypted and re-encrypted, so no
key is needed at this point. Its duration grows with the number of asset accounts, which in a
typical deployment is far smaller than the session and audit volume. **It is not idempotent**: if
any step fails the whole transaction is rolled back and the database is exactly as it was before,
and it can be run again once the cause is fixed — **that rollback is the migration's own
transaction, not a way back from the upgrade**; the product has no rollback entry point, and going
back means deploying the old version's images and restoring the pre-upgrade backup. **Its `Down` is
lossy**; read §4.1 before planning any way back.

`20260906_credential_library_contract` takes down what no longer has a reader: the two ciphertext
columns on asset accounts (login secrets now live in the credential's secret versions), the shared
group column on the pending credentials and on the batches (sharing is now expressed by the
credential itself), and the index on the account group column. **It is a separate version rather
than an addition to the previous one**, because the previous one has already been applied on
databases that carry it, and appending statements to an applied migration would leave the code
declaring a shape the database does not have. It drops columns only, with no data conversion, so
its duration is independent of the volume held. **Its `Down` is lossy**; read §4.1 before planning
any way back.

`20260908_role_state_checkpoint` adds four nullable columns to the audit checkpoint table, so that a
checkpoint also seals the role assignments in force at that moment (a hash of the snapshot, the
snapshot, a count, and whether it reconciled). It creates no table, index, or constraint. **It only
adds columns, with no data conversion and no backfill**, so its duration is independent of the volume
held. **Checkpoints sealed before the upgrade stay empty**, which is the honest statement that those
periods do not cover role assignments; they are not backfilled, because writing today's snapshot into
a past checkpoint would sign, on history's behalf, a claim history never made. **Its `Down` is
lossy**; read §4.1 before planning any way back.

`20260908_group_role_mapping` adds the data layer for mapping external directory or identity provider
groups onto roles in this system: a source column on the user-role association (whether a role was
assigned by an administrator, granted by a group mapping, or both), two new tables (the mapping rules
an administrator maintains, and the mapping facts each login path recomputes), a group membership
attribute name on the directory settings, three group observation snapshot columns on the account
table, and a group claim name plus three claim mapping columns on the identity provider settings,
together with six foreign keys and three indexes. **It is purely additive with no data backfill**:
every added column is nullable or carries a default, so its duration is independent of the volume
held. **Existing rows on the user-role association are all defaulted to "assigned by an
administrator"**, which is what they are — before this column existed there was no other way for a
role to be granted. **Every one of the new configuration columns means "not configured, behaviour
unchanged" while it is empty**: an empty group attribute name or group claim name means this
deployment does not let external groups decide roles, and the three claim mapping columns fall back
to the parsing already in use. A deployment that configures none of them behaves exactly as it did
before the upgrade. **Its `Down` is lossy**; read §4.1 before planning any way back.

`20260909_policy_groups` adds the data layer for policy groups and the compliance map: four new
tables (a policy group, the clauses in it, each clause's requirements on individual security
settings, and the organization's notes and manual confirmations) plus one unique index. **It creates
tables only**: it touches no existing table, adds no column, converts nothing and backfills nothing,
so its duration is independent of the volume held. The built-in groups' content is written by a seed
at startup, not by the migration, and the four tables are empty until then. A deployment that opens
none of the new pages behaves after the upgrade exactly as it did before. **Its `Down` is lossy and
part of that loss cannot be restored**; read §4.1 before planning any way back.

#### The query console (a feature new in this release, the parts that affect upgrade decisions)

This release opens one more **entry point** for existing mysql, postgres, and mssql assets: alongside the original command line connection, a query console can be opened to write statements on screen, see the result table, and export the result as CSV. Six things to know when planning the upgrade:

- **This is a new entry point, not new authorization.** The server-side authorization decision is **exactly the same** as for the command line: the same one-time connection ticket, the same gate sequence table, the same credential unsealing point. Whoever can open a console is whoever already had connection authorization for that asset.
- **The reachable database scope is the same as the command line's for the same account.** The console uses the same asset account, and what it can see and act on is decided by **the account's permissions on the target**; a command line session could always switch to any database that account can see.
- **Result exports are governed by the existing transport policy.** Exports go through the existing file download capability (`file_download_enabled`), so whoever you have downloads turned off for cannot export results; every export that succeeds, is refused, or is interrupted midway leaves an audit record.
- **Assets gain an allowed databases field, empty by default, and empty means no restriction.** The upgrade fills no value for existing assets, so behavior before and after the upgrade is the same. Once filled, it restricts **what the console can execute against** (the tree lists only databases in the list, and it is confirmed again on switching database and before each execution); it is not database-level access control, it does not parse statement content, and it **has no effect at all on command line sessions**.
- **Concurrent console sessions have a cap** (4 per person, 64 globally). At the cap a new console connection is refused and recorded, existing connections are unaffected, and command line sessions do not consume this allowance.
- **Every unit of execution leaves an audit record** (the statement as written, the target database, the final state and reason code, the row count, the duration, and the transaction state afterwards), in the same table as command line records, with the same retention period and the same export. If the record cannot be written, the execution does not run.

**This release also carries a one-time clipboard content encryption conversion** (`content` → `content_enc`): it needs a codec, so it is not part of the stage 1 migrations above but runs **after the KEK is unsealed (stage 2)**, printing on completion the log line
`[ClipboardMigration] 剪貼簿內容加密轉換完成：<N> 筆既有列已回填，明文欄已移除`.
The conversion uses "does the `content` column exist" for idempotency (a restart after the upgrade does not rerun it), and a failed backfill rolls the whole segment back and keeps the plaintext column (fail closed). **It does not run before the KEK is unsealed**, so with interface-entry mode (mode B) it is only reached once the unseal is done.

**This release also carries a one-time credential secret conversion**, and it runs **after the KEK
is unsealed (stage 2)**, not with the stage 1 migrations above. It does two things in one
transaction: it re-binds the column identity of the ciphertext that stage 1 moved into the secret
version table, and it then decides, by comparing the decrypted values, which of the existing
implicit sharing relationships are genuinely the same secret. Both need a key, which is why neither
can be in stage 1. On completion the log prints
`[CredentialSecretConversion] 完成：改綁密文 <N> 筆、合併共用 <M> 組、標記待處理 <K> 組`
followed by `[PostUnsealMigration] credential_secret_conversion 完成`.

**Confirm those two lines before declaring the upgrade complete.** A failure rolls the whole segment
back, writes no completion marker, and is retried on the next start — but **it does not stop the
service from coming up**. Each failed attempt also writes an audit row (resource `credential`, action
`migration`, status failure) naming the stage it stopped at and how much is left to convert, so a failed
upgrade is still discoverable afterwards; the error text itself stays in the startup log. Until it has succeeded, the moved ciphertext is still bound to its old
column identity, so connections to managed assets fail to obtain their credentials, loudly and
visibly. The usual cause is the key not being available; fix that and restart, and the conversion
runs again. Its idempotency is a marker row in `schema_migrations`
(`20260906_credential_secrets_converted`), not a column shape, so a restart after a successful run
does not repeat it.

Credentials whose group could not be proven identical are left as they were and marked for
attention: their note is prefixed with `[MIGRATION_GROUP_MISMATCH:<group>]`, which shows on the credential's
detail and can be cleared by an administrator, and one audit row is written per group (resource
`credential`, action `migration`) listing the credential ids and why the group was left alone, whether
the secrets themselves differ or only the credential's attributes do (account name, secret type,
authentication method, protocol family), which is how to find them: the
credential library's search box matches names and account names, not notes. Those hosts keep working; the mark says that the system could not confirm they share one
secret, not that anything is broken.

#### Rotation evidence reports (a feature new in this release, the parts that affect upgrade decisions)

This release adds a report that can be produced on a schedule: taking the asset accounts registered in the system as its population, it states each account's applicable number of days, the last successful credential change, the days remaining, and the status, for auditors to check against. Seven things to know when planning the upgrade.

- **The upgrade changes no existing behavior.** The new security policy key ships at 0 (off), the day override column on credential change plans defaults to 0 (use the global value), and with no schedule no report is produced. The "My exports" tab of the download center and the existing export behavior are untouched.
- **The backend image grows by about 21 MB.** The report PDF needs a font set that renders Traditional Chinese and Japanese correctly, and that font is compiled into the backend binary, so the image grows accordingly (about 20.6 MiB measured). Allow for it in pull times and disk quota.
- **One more menu item and one more download center tab.** The report page sits under the "Audit" group and is visible only to the admin and auditor roles; the download center gains a "Rotation reports" tab listing report artifacts. The position, name, and path of existing menu items are unchanged.
- **The download rules for reports differ from those for evidence packages, deliberately.** An evidence package is bound to its requester in person (because it contains recordings and clipboard plaintext); a report contains no recording, no clipboard content, and no credential material, its content is entirely a projection of facts already open to auditors, and a scheduled report has no natural person requester to bind to, so **anyone with audit view permission can list and download it**. The rules for evidence packages are untouched. Every download leaves an audit record as usual.
- **Report artifacts and evidence package artifacts land in the same directory** (`EXPORT_ARTIFACT_PATH`, default `/var/lib/custodexa/exports`), and **the backup scope is unchanged**: that directory is still temporary and not a backup target. The facts a report states all come from the database (accounts, credential change records, policy settings), and the backup contains those facts; producing it again gives a new report, with a new production time and a new signature, not the same document.
  What differs is the retention period: evidence packages are fixed at 24 hours, while a report's retention period comes from the schedule (1 to 3650 days), so peak usage of that directory is higher than before the upgrade. Count it into your disk planning.
- **Report artifacts live in the backend container's export staging directory, and disappear on a container rebuild while no volume is mounted.** The default compose configuration mounts neither a volume nor a bind mount for that directory, and a container rebuild (including the upgrade steps in this SOP) clears the artifacts in it. To have reports actually last for the retention period set on the schedule, mount that directory as a volume or a bind mount, or enable offsite storage; with neither, the retention period only holds while the container lives.
- **The report has two boundaries in what it states, and auditors should know them before reading it.** First, the population contains only asset accounts **registered in the system**; the system does not probe target hosts. Second, the "shared credential" marker comes from the credential library: an account is marked shared when it logs in with a shared credential, whether that credential was created by an administrator, produced by a batch change, or merged by this release's one-time conversion from accounts proven to hold the same secret; accounts whose grouping could not be proven are not marked (§2.5). Both points are written on the report's own scope note.

#### Windows local account credential change (a feature new in this release, the parts that affect upgrade decisions)

This release lets Windows hosts registered as rdp (and Windows hosts registered as ssh) be covered by credential change plans: an asset gains a "credential change channel" setting, the channel being either WinRM (NTLM authentication, message-layer encryption) or SSH to PowerShell, and the credential change command is always PowerShell's `Set-LocalUser`, acting on local accounts only. Four things to know when planning the upgrade.

- **The upgrade changes no existing behavior.** After the upgrade the channel column is "not configured": ssh assets change credentials over the existing SSH path as before, rdp assets keep not changing credentials (when a plan covers one it is recorded as skipped, with the reason being no credential change channel configured), and other protocols are unchanged. To change credentials on a Windows host, an administrator has to configure the channel on that asset's form; nothing is enabled automatically.
- **The backup scope is unchanged.** The channel settings (including an uploaded CA certificate) live in the asset table in the database and travel with the database backup in §2.1; there is no new location and no new environment variable.
- **The backend container has to be able to make outbound connections to the target host.** The WinRM channel connects to the target's 5985 (http) or 5986 (https) port (an asset can set another port), and the SSH channel connects to the target's SSH port (22 by default for an rdp asset, configurable). The credential change transport **does not read proxy environment variables and does not follow HTTP redirects**, so a network topology that requires a proxy or a redirect to reach the target cannot connect.
- **A few more fields in the frontend, with no path changes.** The rdp section of the asset form gains a "credential change channel" block (and the ssh section gains a "Windows OpenSSH" switch); the asset dropdown on a credential change plan lists only assets with a channel configured; execution records gain a "channel" column showing the credential change channel currently configured on that asset, rather than the one taken at execution time (the record itself does not store the channel, so if an administrator changes the channel afterwards, old records show the new value). No menu item and no API path is added.

##### Prerequisites on the Windows target

Below is the state the target host has to be in. Every line corresponds to a mechanism this product actually exercises; settings this product does not use are not listed.

| Item | Requirement | Why |
|---|---|---|
| WinRM service and listener (WinRM channel) | Enabled, for example `Enable-PSRemoting -Force` (add `-SkipNetworkProfileCheck` on a machine whose network profile is Public); the firewall permits 5985 (http) or 5986 (https) | The product establishes a session against that listener over WS-Management |
| `LocalAccountTokenFilterPolicy` (WinRM channel) | The DWORD under the registry key `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System` set to `1` | A credential change signs in with the credentials of the account being changed. Without this, a local administrator account other than the built-in Administrator receives a UAC-filtered restricted token on a network sign-in, and the WinRM service refuses at session creation, so the credential change command is never sent; that run is recorded as failed (the reason code follows the form of the target's refusal, either credentials rejected or the session could not be established), the candidate is cleared, and the system does not retry. This product's automated regression is always run on a host with this set to `1`, and the actual outcome without it has not been measured. Whether the SSH channel, whose token is created by the OpenSSH service, is affected by this setting has not been verified in this release; setting it on the same host is recommended either way |
| `WSMan:\localhost\Service\AllowUnencrypted` | **Leave at the default `false`**; do not turn it on for this product | The product applies NTLM message-layer encryption to every message, and the default configuration works. If a target accepts only unencrypted requests, the product refuses to connect and records "WinRM encryption unavailable"; it does not fall back to plaintext |
| `WSMan:\localhost\Service\Auth\Basic` | **Leave it off** (some versions default it on; check) | The product does not use Basic, and the transport refuses to send any request carrying a Basic header; leaving it on is only one more attack surface |
| `WSMan:\localhost\Service\Auth\Negotiate` | Leave at the default, on | The NTLM handshake goes through the Negotiate header; turning it off on the target simply means no connection, with no fallback path |
| The account whose credentials change | A local account, a member of the local Administrators group; the account name follows the Windows local account rules (length 1 to 20, none of `" / \ [ ] : ; \| = , + * ? < >`, no leading or trailing whitespace), and names containing non-ASCII characters or `@` work as usual | The account signs in with its own credentials and changes its own password; the account name is validated locally against the same rules before anything is sent, and one that fails is recorded as failed without touching the remote host. Domain accounts (`DOMAIN\user`) are not supported in this release |
| PowerShell with `Set-LocalUser` (the `Microsoft.PowerShell.LocalAccounts` module) | Available; Server 2012 R2 and earlier do not have this command and are not supported in this release | The credential change command is `Set-LocalUser`, executed by the 64-bit `powershell.exe` (the module is unavailable in a 32-bit host) |
| OpenSSH Server (SSH channel) | Enabled with the SSH port permitted; the default shell may be cmd or PowerShell | The command calls `powershell.exe -NoProfile -NonInteractive -EncodedCommand` explicitly and does not depend on the default shell. The host key is recorded through the existing trust-on-first-use mechanism |

**`TrustedHosts` does not need to be configured.** `WSMan:\localhost\Client\TrustedHosts` is a client-side setting on the initiating Windows machine, used to let a Windows client use Negotiate against a non-domain host; this product's client is not Windows and does not read that setting, so requiring it would only be one more change with no effect on the outcome.

##### The three certificate verification modes for https (5986)

When the WinRM channel uses https, a server certificate verification mode has to be chosen on the asset. There is no default, and it cannot be saved empty:

| Mode | Behavior | Inventory and badge |
|---|---|---|
| `system` | Verifies the target certificate against the trust anchors of the backend container's operating system | No risk |
| `ca` | Trusts only the CA certificate uploaded on that asset (PEM, checked as parseable on save); a listener certificate issued by an internal CA goes here | No risk |
| `insecure` | Does not verify the certificate | Marked `winrm_tls_insecure` |

http (5985) has no TLS, the payload still carries NTLM message-layer encryption, and the inventory and badge mark it `winrm_http_ntlm`. An https connection whose certificate is not trusted **is never downgraded automatically** to `insecure`: that credential change fails before the command is sent and is recorded as failed (the session could not be established, the remote host is untouched, and the candidate is cleared), changing the mode means going back to the asset form, and the system does not retry on its own.
The minimum TLS version is 1.2. You provide the target's listener certificate (which needs the Server Authentication usage); the product does not sign one for you.

##### Boundaries when reading credential change records (know these before auditing them)

- The new password and the current password are delivered only over standard input, never on a command line and never in script text; but they exist briefly in plaintext in the PowerShell process memory on the target, which follows from the `Set-LocalUser` interface.
- The semantics of the three record states match the Linux path: failed means the remote host definitely did not change, unverified means the remote state is unknowable (the candidate is kept and the system retries), and success means a separate connection with the new password verified it (a fixed retry sequence of three: immediately, after 2 seconds, then after another 5 seconds). The dividing line is whether the credential change command was sent: a failure before it is sent (cannot connect, session creation timed out (WinRM 30 seconds, SSH dial 10 seconds), certificate not trusted, credentials rejected) is always failed with the candidate cleared; only an interruption or timeout after it is sent (the command's 90 seconds, the same for both channels) is unverified.
- The credential change script verifies itself on the target: right after setting the new password it verifies locally on that host that the new password can sign in, and if it cannot, it changes the password back on the spot. When the script leaves the host, the host is on either the verified new password or the original one; the run that changed back is recorded as failed (the reason being the target's self-verification failed and it rolled back, the candidate is cleared, and the host is still on the original password), and the extreme case where changing back also failed is recorded as unverified (the reason being the target's self-verification failed and the rollback failed, the candidate is kept, and the system retries).
  When the host's local verifier is unavailable (the script calibrates it with the original password first, and does not trust it if the calibration fails), the script neither self-verifies nor rolls back, and the credential change outcome is decided by the reconnection verification in the previous point.
- The script's outcome is taken from the result marker it prints on standard output, not from the exit code the host shell reports, and the record semantics are the same for both channels (WinRM and SSH). A run where the marker is not received and the script exited non-zero, or where the marker's value is not in the contract table, is recorded as unverified (the reason being the remote state is unknowable, the candidate is kept, and the system retries); it is not recorded as failed.
- While a candidate is kept, later credential changes for the same account are skipped as "candidate awaiting verification." Once you have confirmed the host is still on the original password, an administrator can clear that candidate on the "unverified credentials" tab of the credential change plan page, after which credential changes resume; clearing is irreversible, and if the host is in fact on the new password, after clearing it can only be reset through an out-of-band route such as the host console.
- Only one WinRM request is in flight at any moment (serialized process-wide), so batch credential changes do not run in parallel; each account on each host is handled in turn.
- This product's automated regression for the Windows credential change path runs over the loopback network on a single Windows Server host (which is both client and target). Cross-host network topologies, internal CA certificate chains, and hosts on Server 2012 R2 or earlier are outside its range; before going live, trigger a plan manually against one representative host and confirm the record is success (item 10 of §2.7).

#### Startup logs related to offsite storage (new in this release)

**The line that decides whether the feature is running.** With no current storage settings generation (never configured, or offsite storage stopped in the admin interface), the log has only this line and no upload worker is created:

```
[OffsiteUploader] 目前無現行離機儲存設定世代，不啟動上傳 worker
```

Seeing this line means this deployment is not making new uploads right now. It **does not mean the feature is broken**, and it does not affect retrieval of historical objects.

**Reading the first-time configuration (seed).** The `OFFSITE_*` keys in `.env` are read once at first startup and written into the database. It needs to encrypt credentials, so it runs **after the KEK is unsealed** (with mode B it is only reached once you unseal). Four possible outcomes:

| Log | Meaning | What to do |
|---|---|---|
| `[OffsiteSeed] 已自 env seed 一列離機儲存設定（…）；其後的變更請於系統設定的離機儲存頁進行，改動 .env 不再生效` | The settings were written into the database | Make all later adjustments in the admin interface |
| `[OffsiteSeed] offsite_profiles 已有 N 列，不 seed（標記為已評估）；執行期沿用資料庫中的設定` | The database already had settings, and `.env` was skipped | Nothing |
| `[OffsiteSeed] env 的離機儲存設定有矛盾（…）：不寫入設定、不寫標記，下次啟動重試；離機設定亦可直接於管理介面完成` | The configuration in `.env` does not hold together (credentials only half filled in, for instance) | Fix `.env` and restart, or complete the configuration in the admin interface. **The service starts as usual**: the first-time configuration is a convenience, and the main service is not tied to it |
| `[OffsiteSeed] OFFSITE_GCS_CREDENTIALS_FILE 指向的檔案不存在或不可讀（…）` | The credentials file cannot be read inside the container | As above |

**The marker means "the assessment is done," not "data was created"**: an actual write, `.env` not being configured, and the table already being non-empty all write the marker; only infrastructure failures and configuration contradictions do not (leaving it to be retried at the next startup).
**Once the marker is written, `.env` takes no part in any runtime decision.**

> **The marker is restored along with the database backup**, so "marker present, settings table empty" is a genuinely possible state (after restoring to some intermediate point in time, for instance). The outcome of that state is **not configured**, and `.env` is not seeded again: **it can only be configured again through the admin interface.** Do not modify the database, and do not try to clear the marker.
> Conversely, "settings table non-empty, marker absent" only writes the marker and does not overwrite the existing settings. See
> [Backup and Restore §4.4](./backup-and-restore.md#44-disaster-recovery-prerequisites-for-object-storage-credentials).

**Reading a failed health check.** At startup the system checks that every storage generation in the custody ledger is present in the settings table. When they do not match, the backend refuses to start, with a message beginning

```
離機保管帳冊的儲存設定世代對不到設定表（資料損壞，多半是部分還原或手動改資料庫）：…
```

and naming the generations that do not match and the object count of each (**with no endpoint or credential information**).
**This is a signal of data corruption, not a configuration problem**: the correct response is **to restore a complete backup**.
**Do not patch it by inserting rows by hand**: a generation created that way will not have the right credentials, and all that does is turn "cannot retrieve" into "believed retrievable, actually holding the wrong credentials."

A brand-new empty database instead shows the baseline actually running, printing the number of DDL statements and built-in alert rules created.
**If what you see is a refusal-to-start message, stop and read §2.6.**
**If what you see is `CRITICAL：單實例鎖由另一個資料庫工作階段持有`, stop and read §2.6b**: the migration lines do not appear, because the guard decides before the migrations.

#### The first thing to do after the upgrade: confirm you got the data you had

**Upgrading an existing deployment should not show the baseline actually running in the log.** Seeing these two lines means the backend received an **empty data directory** and is building a database as if this were a new installation:

```
  執行 migration: 20260816_schema_baseline (schema_baseline)
  baseline schema 已建立：<N> 條 DDL、<M> 條內建告警規則
```

**Stop immediately**: `docker compose -f docker-compose.yml stop`, do not sign in, do not let users in, and make no writes. The cause is almost always the square described in §2.2: `DATA_PATH` in `.env` is a relative path while the new source tree is in a different directory. The original data is still in the original directory with not a bit touched; point `DATA_PATH` back at it (or make it absolute) and start over, and simply delete the empty data just created under the wrong directory. Only carrying on begins accumulating new data in the wrong directory.

**This failure has no error signal**: the backend starts normally, `/health` returns ok, and the frontend comes up too, only with nothing in the database. All five of the first items in §2.7 pass.
(Deployments using interface-entry mode (mode B) have one indirect signal: an empty database has no existing KEK, so the screen asks to **initialize** a KEK rather than to unseal. If you see that, do not initialize; go back and check `DATA_PATH` first. Modes A and C do not even have that signal.)

The equivalent check without reading the log, both lines run once each:

```bash
# 1. Are the rows that existed before the upgrade still there
docker compose -f docker-compose.yml exec -T postgres \
  psql -U "${DB_USER:?}" -d "${DB_NAME:?}" -tAc \
  "SELECT version FROM schema_migrations ORDER BY version"

# 2. Do the business row counts match the numbers noted before the backup in §2.1
docker compose -f docker-compose.yml exec -T postgres \
  psql -U "${DB_USER:?}" -d "${DB_NAME:?}" -tAc \
  "SELECT 'users', count(*) FROM users
   UNION ALL SELECT 'sessions', count(*) FROM sessions
   UNION ALL SELECT 'audit_logs', count(*) FROM audit_logs"
```

How to read it: **the second is decisive**: one user, zero sessions, and a handful of audit rows means an empty database. The first supports it: a deployment that has been unsealed at least once has, besides the migration versions, **runtime marker rows** in `schema_migrations` (three in this release: `20260804_ldap_env_seeded` and `20260825_offsite_env_seeded`, the idempotency markers for the env-to-database first-time configuration of the directory integration and of offsite storage, and `20260906_credential_secrets_converted`, the marker for the one-time credential secret conversion in §2.5, **none of them migrations**), which a brand-new database does not have before its first unseal.

> The order here cannot be reversed: **confirm you got the right data first, then do the rest of the verification in §2.7.**
> §2.7 verifies whether the new version runs correctly; it will not tell you whether what it runs on is your data.

### 2.6 If the backend refuses to start and reports unrecognized versions in `schema_migrations`

This is a deliberate fail-closed behavior of 1.0, and the database itself is not damaged.

**What the message looks like** (excerpt):

```
拒絕啟動：資料庫的 schema_migrations 內有 N 筆本版程式碼不認得的 migration 版本：…
  本版本以單一 schema baseline（20260816_schema_baseline）作為 schema 的唯一事實源，
  壓縮前的逐條 migration 已不存在，因此不提供既有資料庫的就地升級路徑。
```

**What it means**: this database was created **before** the baseline generation, and this release's code cannot read the shape of its schema.

**The decision happens before any write**: by the time you reach this point not a bit of the database has been touched. That is deliberate: letting the baseline run against an existing database would at best abort on a table conflict, and at worst write the seed data twice, silently doubling the alert rules.

**What to do**:

1. **Development environments**: rebuild an empty database.
2. **Production environments**: the workable path is a new installation on a new empty database, and migrating the existing data is project work. Stop here and confirm with the delivering party; do not try to work around it yourself.
3. **Never delete rows from `schema_migrations` by hand to get past this check.**
   The baseline's table creation statements are unconditional (no `IF NOT EXISTS`), so the first `CREATE TABLE` collides with an existing table and aborts, leaving a database that is **neither the old version nor the new one**, after you have destroyed the one table that could tell which version it is.

> **A normal situation that is easy to misread**: besides the baseline, `schema_migrations` also holds **runtime idempotency markers** written by modules (currently the only one is the LDAP env-to-database seed marker). These are **not** migrations, and the fail-closed decision already excludes them, so their presence does not trigger a refusal to start.

### 2.6b If the backend is stopped and reports that the single-instance lock is held by another database session

This is this release's single-instance guard, and the database itself is not damaged. What the guard guarantees is that a second instance will not run without your knowing, not that there will be no second instance; "what confirming means" at the end of this section says so again.

**What the message looks like** (excerpted from a real run on 2026-08-25; `pid`, the times, and `code` differ with every conflict):

```
[InstanceGuard] 等待既有實例釋放單實例鎖（第 1/5 次，2s 後重試）
…
[InstanceGuard] 等待既有實例釋放單實例鎖（第 4/5 次，2s 後重試）
CRITICAL：單實例鎖由另一個資料庫工作階段持有。本版不支援多實例部署，本實例未啟動服務。
  持鎖者：application_name=custodexa-instance-guard pid=8510 backend_start=2026-08-25T10:04:22.2442Z code=55bd875b8d97
  風險：兩個實例同時執行會造成金鑰快取、匯出工作、錄影落地與封印期留痕的資料問題（見 docs/ops/deployment-topology-limits.md）。
  處置 (a)：若確認另一實例仍在執行：先停止它，再重啟本實例（無需任何設定）。
  處置 (b)：若確認無其他實例在執行（例如持鎖者是主機當機後殘留的工作階段）：開啟本實例的守衛攔下頁 /instance-guard，以管理員帳密重打確認碼 55bd875b8d97 後確認，不需重啟；腳本化替代路徑為設定環境變數 INSTANCE_GUARD_ACK=55bd875b8d97 後重啟。兩者都會寫入審計事件並在管理介面顯示橫幅，直到鎖由本實例取得。
  澄清：這不是資料庫損毀；本次啟動未由本實例執行 migration 或任何資料寫入；INSTANCE_GUARD_ACK 綁定上列指紋，持鎖者變更後失效；確認後兩實例並存造成的資料問題由確認者承擔，守衛只保證此事被記錄。
```

**What it means**: there is another session in the database holding this system's single-instance lock. The guard cannot tell a live instance from a leftover session, so it hands the judgment to you. The waiting lines before it are deliberate: when a previous process has just exited, the database takes a few milliseconds to reclaim its session, so the guard waits 5 times at 2 seconds each (about 10 seconds), and prints this passage only if the lock is still held afterwards.

**The decision happens before any write**: this instance ran no migration and wrote nothing to the database. It does not exit; it stays in the guard's halted mode, retries the lock every 15 seconds, and opens a listener that serves only the health check, the seal status and the halt page's two endpoints. Every other path answers 503 while it is halted.

**Where to act: `https://<address>/instance-guard` on that host.** The halt page needs no sign-in and is reachable under the same source restriction as the unseal page (`SEAL_UNSEAL_ALLOWED_CIDRS`, when set). It shows the lock holder's fingerprint, the confirmation code for this conflict, and the two choices below, and it follows the guard's state on its own: when the lock is released, the instance takes it at the next retry and the page turns to "started", with no restart.

**How to read the lock holder line**:

| Field | Meaning |
|---|---|
| `application_name=custodexa-instance-guard` | The holder is the guard connection of a guard-bearing instance. An empty value or another name means the holder is not this system's guard connection, which is outside this section; hand it to the database administrator |
| `pid` | The process id of the holding session inside postgres, **not** the application process id inside the container |
| `backend_start` | When that session was created. Much earlier than now, with no live instance to be found, is the typical look of a leftover session |
| `code` | The confirmation code: the first 12 characters of the hash of the three fields above. A different holder means a different code |

If that line instead says the holder's details could not be obtained (`無法取得持鎖者細節（pg_stat_activity 查詢失敗或無權限），降級確認碼為 code=…`): the guard cannot see the holder. A degraded code is not bound to a particular session, only to the fact that it could not be seen; after starting with it, the audit event's `holder.fingerprint_source` is `unavailable`. At the same time, check whether the application account's read permission on `pg_stat_activity` has been changed.

**What to do (choose one; nothing in either requires any operation on the database)**:

1. **Another instance is still running**: stop it, then restart this one. Nothing has to be set, because the lock is released as soon as the previous instance stops. Check every host this system could have been started on and every compose project pointing at the same database (the development and production compose files are each a project, and starting both means two instances).
2. **You have confirmed no other instance is running** (you looked in all the places above, and the holder is a leftover session): confirm on the halt page. Tick the statement that you have checked on the host itself that the other instance is not running and will not restart by itself, retype the confirmation code the page shows, enter an administrator's account and password, and submit. All three are required. The code is checked against the holder at the moment you submit, so a holder that changed while you were filling the form makes the submission fail and the page offers the new code. Wrong administrator credentials are refused as well, and after five credential failures the page stops accepting submissions for five minutes; that count lives in the halted process only and nothing about it is written to the database. Once the submission is accepted the page shows "starting", the service port is briefly unresponsive while the migrations and the rest of the startup run, and the page then turns to "started" and offers the way to sign in. No restart, and nothing to edit in `.env`.

   The startup log shows
   `CRITICAL：以守衛攔下頁的確認啟動：單實例鎖仍由 … 持有；本實例將照常執行 migration 與服務；此確認已記錄（actor=… actor_source=page）`,
   followed by the normal migration and listener lines. The `overridden` audit row carries that administrator account, and the guard's `reason` is `ack_page`.

   **The scripted alternative**, for a recovery driven by a script or on a host where the page is not reachable: put the code from the message into `.env` and restart.

   ```bash
   # add one line to .env; the value comes from code= in the message and is valid for this conflict only
   INSTANCE_GUARD_ACK=55bd875b8d97
   ```

   ```bash
   docker compose -f docker-compose.yml up -d backend
   ```

   The startup log should then show
   `CRITICAL：以 INSTANCE_GUARD_ACK 啟動：單實例鎖仍由 … 持有；本實例將照常執行 migration 與服務；此確認已記錄（actor=operator via env）`,
   followed by the normal migration and listener lines, with `reason=ack_startup`. **Once the start succeeds, the line can be removed from `.env`** with no further restart: it is valid for that one conflict only, and leaving it is inert (a later conflict-free start just prints one line, `INSTANCE_GUARD_ACK 已設定但本次未偵測到衝突，未使用；建議自環境移除`).

**What confirming means (read this through before you confirm, on either path)**:

- The confirmation is bound to the holder fingerprint in that message. As soon as the holder changes (another instance came up, or the leftover was reclaimed and a new holder appeared), the code stops being valid. On the page the submission is refused and a new code is offered; with the environment variable the guard halts the start again and prints a new code, the message gains a line, `提供的 INSTANCE_GUARD_ACK 與當前持鎖者指紋不符（持鎖者已變更），請以上列 code 重新確認`, and no audit event is written. So neither path can be left set permanently to turn the guard off.
- Every confirmed start writes an `audit_logs` row: `resource=instance_guard`, `status=failure`, with details containing `event=overridden`, `ack`, the holder fingerprint (`holder.*`), this instance's `instance.hostname`, `pid`, and `started_at`, and the confirmer. With interface-entry mode (mode B) this row reaches the database only after unseal, though its timestamp is still the moment of the start.
- **Who the row names depends on the path.** A confirmation on the halt page names the administrator account that was verified, records the page as the source, and carries the number of credential failures that preceded it. `actor="operator via env"` means **the system does not know who set it**: an environment variable cannot identify a natural person, so on that path who set it and when is owned by your change management, and belongs on the change ticket.
- After a confirmation the guard **stops nothing at all**: migrations run, the service opens, background jobs run. If your judgment was wrong and the other instance really is alive, two instances write the same database at the same time, and the data problems listed on the message's risk line **will occur; the guard does not prevent them**, and they are owned by whoever confirmed.
- An instance started with a confirmation retries acquiring the lock every cycle (15 seconds). Until it succeeds, the admin interface shows every signed-in user a persistent banner, "This instance started with an acknowledgement code; another database session still holds the single-instance lock", with the confirmer on its second line (administrators additionally see the fingerprint and the confirmation code), and the metric `custodexa_instance_guard_overridden` is 1. The leftover session is reclaimed by postgres according to the operating system's TCP keepalive (the postgres container sets nothing of its own, so the Linux default of roughly 2 hours applies); after that the guard acquires the lock on its own, the banner disappears, and `audit_logs` gains an `event=regained` row carrying the same `reason` as the acknowledgement (`ack_page` from the guard page, `ack_startup` from the environment variable). **No restart is needed.**
- If another instance really is running and you chose option 2, that instance's banner shows "Detected 1 other instance connected to the same database." That is how it comes to know, and it is not an error.

**An optional diagnostic: is the holder a live instance or a leftover?** (not required for recovery; neither option above needs it)

Joining `pg_locks` and `pg_stat_activity` on the lock key is the authoritative query, and `application_name` is only supporting evidence. Run it as the application account (`DB_USER` and `DB_NAME` come from `.env`; for how to obtain them, see
[Backup and Restore §2.3](./backup-and-restore.md#23-how-the-shell-commands-in-this-document-obtain-deployment-variables-read-before-you-start)):

```bash
docker compose -f docker-compose.yml exec -T postgres \
  psql -U "${DB_USER:?}" -d "${DB_NAME:?}" -c "
SELECT a.pid, a.usename, a.application_name, a.backend_start, a.state, a.state_change
FROM pg_locks l
JOIN pg_stat_activity a ON a.pid = l.pid
WHERE l.locktype = 'advisory'
  AND l.classid = 1869900645 AND l.objid = 1795162116 AND l.objsubid = 1
  AND l.granted
  AND l.database = (SELECT oid FROM pg_database WHERE datname = current_database());"
```

- `classid` and `objid` are the guard lock key `0x6F746B656B000004` split into two 32-bit integers; `objsubid = 1` is the fixed value for a 64-bit advisory lock.
- **The `l.database = …` line must not be omitted.** `pg_locks` is a cluster-wide view while advisory locks are per database, so without that filter a session holding the same key in another database is taken for the holder (measured inside compose on 2026-08-25: querying from the maintenance database found the holder in the `custodexa` database).
- How to read it: a `backend_start` earlier than the last normal stop you know of, with no live instance to be found on any host, means a leftover, so take option 2; finding a live instance means option 1.
- Column visibility (**measured on postgres 16.15, not a documented guarantee**: the official documentation only says many columns are NULL for sessions of other roles, without listing them): when the holder and the querier are the same application account, every column is visible; when the holder belongs to another role, `application_name` is visible while `backend_start` is NULL, in which case the guard substitutes `-` for that field in the fingerprint and the confirmation code is still bound by `pid` and `application_name`. `state` and `state_change` for sessions of other roles have not been measured here and may be NULL. If your postgres version differs, go by the actual output.
- Permissions: `pg_locks` is readable by every role; `pg_stat_activity` shows every column for sessions of your own role, and only existence and general attributes for other roles. If the query is refused (`permission denied`) or the columns are all empty, run it with an operations account or hand it to the database administrator. **Do not widen permissions for this**: **`pg_signal_backend`, `pg_read_all_stats`, and superuser must not be granted to the application account.**
- This passage is a diagnostic, not a remedy. When you are done, go back to the two options above. **Do not terminate database sessions**: the guard's recovery path does not need it, and what you terminate may be a live instance on another host.

> **A normal situation that is easy to misread**: a halted container stays up, and `docker compose ps` shows the backend running while no service answers. That is the halted mode, not a half-started service: business paths answer 503 and only the halt page works. It is also why the passage is printed once instead of over and over.

### 2.7 Post-upgrade verification

Run the five steps in the "deployment verification" section of `docs/QUICKSTART.md`:

1. `docker compose ps` — all services up and postgres healthy.
2. `docker compose exec backend wget -qO- http://localhost:8080/health` — the backend health check (backend publishes no port, and `/health` is not on an nginx proxy path, so it goes from inside the container).
3. `curl -I http://localhost/` — the frontend is reachable.
4. The sign-in path works.
5. `docker compose logs backend | tail -30` — no fatal in the startup log; every release fail-closed message appears here. The single-instance guard is here too: a normal upgrade should show one line,
   `[InstanceGuard] 單實例鎖狀態=held hostname=… pid=… started_at=… db_session_pid=…`,
   and if you see `CRITICAL：單實例鎖由另一個資料庫工作階段持有`, read §2.6b.

Then three more checks specific to an upgrade:

6. **The four fingerprints in the key inventory match what they were before the upgrade** (an upgrade should change no key; a changed fingerprint means something else happened).
   The env side of the inventory has four items: `ENCRYPTION_KEY (KEK)`, `JWT_SECRET`, the export signing key (Ed25519), and the checkpoint signing key (Ed25519). **Compare all four**: comparing only the first three would not reveal the checkpoint signing key having been replaced.
7. **Audit chain verification** passes, with no unexpected break in the sequence.
8. Spot-check that a session recording that existed before the upgrade plays back. **Both a local source and an offsite source count as a pass**: a session whose local copy was cleared per the retention settings is fetched from object storage instead (with a download wait on first playback, and retrieval always verifies the hash before delivery).
   Deployments with offsite storage enabled should also glance at the "Offsite Storage" page on the admin side: the settings summary and generation state as expected, and no abnormal buildup in the failure list.
9. **Run one end-to-end audit verification for real**: create a test connection (SSH or database), run a few recognizable commands, then confirm in the audit interface that **those commands really appear for that session**.
10. **Deployments with a Windows credential change channel configured**: trigger a credential change plan manually against one representative host and confirm the record is success.
    A failed with "the session could not be established" means it could not connect before the command was sent, so check the target's WinRM or SSH reachability and certificate settings first; unverified means the remote state is unknowable after the command was sent and the candidate will be retried by the system, which is not a sign of a failed upgrade.

> **Item 9 must not be skipped.** A successful backend start **does not imply** that auditing still works; they are different mechanisms. A start only verifies that the program runs and the migrations are applied, while the existing design on an audit write failure is **not to interrupt the connection** (so that an audit fault does not become users being kicked off). So if connections work and operations work but the audit records are empty, that is a problem in the audit write layer, and **no error message will tell you**; running it for real is the only way to find it.

> When verifying the production stack on a development machine, add an explicit `-f docker-compose.yml` to every command above (overriding `COMPOSE_FILE` in `.env`).

### 2.8 Recording GPL corresponding source at release time (for those who distribute images)

**Who this applies to: anyone who hands self-built images to a third party** (this project's publisher, and anyone who builds and then redistributes). It does not apply to those who deploy only inside their own data center and deliver no images.

The images contain GPL and LGPL binaries from the base image (Alpine). `THIRD-PARTY-LICENSES.md` §3.2 fulfills the corresponding source obligation **by pointing at the upstream source** (GPLv3 §6(d) and the last part of GPLv2 §3), and that approach holds only if you can point out **which source the binaries in this version of the image correspond to**.

So recording these two things at each release is enough (a few KB each, a few seconds):

```bash
VERSION=<the tag being released>
mkdir -p "release-archive/$VERSION"

# 1. The full package listing of the three images (with versions); this listing defines which packages "corresponding source" corresponds to
for img in custodexa/backend custodexa/frontend custodexa/guacd; do
  cid=$(docker create "$img:$VERSION")
  docker cp "$cid":/lib/apk/db/installed - | tar -xO > "release-archive/$VERSION/${img##*/}-apk-installed.txt"
  docker rm "$cid"
done

# 2. The corresponding aports commit (the anchor that pins the version; branches move on, commits do not)
#    Record both branches: 3.24-stable corresponds to the Alpine base of the backend and frontend images,
#    and 3.18-stable to the upstream base of guacd (see "Deployment Topology Limits"). Miss one and
#    that image has no nameable corresponding source.
for br in 3.24-stable 3.18-stable; do
  git ls-remote https://gitlab.alpinelinux.org/alpine/aports.git "refs/heads/$br" \
    >> "release-archive/$VERSION/aports-refs.txt"
done
```

**Why those two are enough**:

Upstream source availability for Alpine is quite solid: aports keeps every `*-stable` branch from 2014 onwards (with naming unchanged for years), package indexes of EOL branches remain accessible, and distfiles only accumulate and are never pruned (sampling a branch that has been EOL for about five years, package source was still fully downloadable).
So pointing out which version corresponds to which source is enough, and you do not have to hoard the source yourself.

A known availability risk (not a compliance gap): Alpine makes no written commitment about a retention period, and `distfiles.alpinelinux.org` is currently a single host, with the official mirrors not carrying the distfiles path.
If your risk appetite requires the evidence to be self-contained, see below.

**If your risk appetite requires holding a copy yourself** (a regulated industry requiring self-contained evidence, for instance), the suggested scope is **mirroring only the distfiles tarballs of GPL and LGPL packages plus a snapshot of that version's APKBUILD**, with the retention period tied to "that image tag is still downloadable" rather than a fixed number of years.
**But it must not be described publicly as a commitment to provide the source on request for three years**; that would voluntarily upgrade a lighter obligation (which can end when distribution ends) into a heavier one (three years from the last distribution, and not ending when distribution does).

## 3. The effect of stopping on asynchronous writes in progress

**Sending SIGTERM takes the graceful shutdown path, and the audit worker flushes the batch it holds.**
That much holds; it is not an empty statement.

But there are **two residual gaps** the operator has to know about:

### 3.1 The queue is drained at shutdown, with a time limit

When the worker receives the shutdown signal it first drains **the rows still waiting in the queue**, flushing them in batches, and then flushes the batch it holds. Rows that were queued when SIGTERM arrived are written before the process exits.

The drain runs inside the shutdown budget (§3.2). If the database does not respond in time, shutdown does **not** wait indefinitely: it stops taking rows, writes whatever is still queued to the audit fallback file when file fallback is enabled (otherwise those rows are counted as lost), increments `custodexa_audit_dropped_total` by that count (label `fallback_file` or `discarded`), logs the exact number of rows that were not confirmed written, and exits with a non-zero code. Rows that a worker had already handed to the database when the limit hit are reported separately as "not confirmed"; whether the database committed them cannot be known from the outside, so treat them as unwritten unless you verify.

What to do with that log line: when file fallback is enabled, the rows are in the fallback file under the audit fallback path and can be reconciled after the upgrade; when it is disabled, the count in the log is the number of audit rows lost, and the upgrade record should say so.

The check in §2.4 remains the way to make this a non-event: a queue that reads `0` at SIGTERM has nothing to drain.

### 3.2 Shutdown budget: 5 seconds for listeners, at least 4 seconds for the rest

Shutdown runs in two stages with separate budgets. The HTTP listeners (the separate unseal listener, if any, and the main listener) get up to 5 seconds to finish in-flight requests. The stage 2 resources, including the audit drain described in §3.1, then get **whatever remains of that 5 seconds or 4 seconds, whichever is longer**. A listener that uses up its whole budget therefore cannot starve the audit drain.

The worst case is about 9 seconds in total. Keep the container stop grace period at the default 10 seconds or higher; a shorter grace period cuts into the audit drain first.

When a stage runs out of its budget the service **records a message and exits with a non-zero exit code** (the remaining resource wind-down is not skipped, and the non-zero code takes effect only at the very end).
A non-zero exit code is a fact supervisors and CI need to know, **and a fact the operator needs to see** as well:

```bash
docker compose logs backend | tail -20   # look for 「關閉過程有未完成項目」 and 「審計佇列排空逾時」
```

「關閉過程有未完成項目」 means some step did not finish within its budget; it appears for a listener that timed out as well as for the audit drain. 「審計佇列排空逾時」 is the line that concerns audit rows: it carries the counts described in §3.1 (rows not confirmed written, rows written to the fallback file, rows a worker still held, rows lost). If only the first line appears, the audit drain finished and what ran out of time was a listener.

### 3.2b The effect of stopping on offsite uploads (with offsite storage enabled)

Offsite uploads are asynchronous writes like the audit queue, but **their residual gap is milder than §3.1's**: there is no "lost permanently at the moment of the stop" square here, because the state is in the custody ledger in the database rather than in an in-memory queue.

- **Items being uploaded when the service stops**: that upload is interrupted, and once the lease held by the ledger row expires it **returns to pending** automatically and is picked up again by the new version's worker. Re-uploading means re-uploading the same key with the same content, so the overwrite is harmless.
- **Items not yet uploaded**: they stay pending, **the local copy is still there** (it is not cleared before the retention policy expires), and they upload as usual once the service is back.
- **Sessions that end during the downtime**: their recordings stay local, and the backfill scan after the next start picks up the evidence accumulated during that period in one batch.

**The cost has the same shape as §3.1's**: during the downtime the local copy is the only copy of those recordings, so the exposure window grows during the downtime. That is a fact, not a defect. The one thing that really needs attention: **when the downtime window is long, confirm first that the pending upload count on the offsite storage page is not abnormally large**, which usually means a batch of failed uploads was already accumulating before the stop.

### 3.3 Operational suggestions

- Stop during a low-traffic period.
- Block new connections first, then wait for the queue to reach zero.
- After stopping, check the exit code and the log and confirm there is no timeout message.
- Even with all of the above there may still be a very small loss; that is a known boundary of this release's shutdown path.

### 3.4 Losing the single-instance lock at runtime: reading the log, the banner, and the audit event

This section has nothing to do with stopping; it is here because, like §3.2, it concerns exit codes: **the guard has no exit code of its own, and losing the lock at runtime does not make the process exit.**
The three signals of a lost lock are the log, the banner in the admin interface, and `audit_logs`; `/health` is unchanged and no request is refused because of it.

Every 15 seconds the guard queries `pg_locks` on its own pinned connection to confirm the lock is still held by that session (with a 5-second query timeout), so **the upper bound on detection latency is about 20 seconds**. On finding it not held, or on a query error, the guard enters `lost`: it discards the old connection, pins a new one, `custodexa_instance_guard_held` goes to 0, `custodexa_instance_guard_lost_total` increments by 1, an `audit_logs` row is written (`event=lost`, `reason=…`), and then it **keeps serving**, retrying the acquisition every 15 seconds with no limit. A successful reacquisition returns it to `held`: `held` goes to 1, an `event=regained` row is written (with `unheld_for_ms`), and the banner disappears at the interface's next poll (within 60 seconds).

**The log lines** (`grep '\[InstanceGuard\]'` pulls them out; `reason=` has four values):

```
[InstanceGuard] CRITICAL：單實例鎖已失守（reason=<reason> lost_total=<n>）；本實例繼續服務、每週期重取，不阻擋任何操作
[InstanceGuard] CRITICAL：重取單實例鎖失敗（reason=contention）：鎖由另一個工作階段持有 [<持鎖者指紋>]；本實例繼續服務、下一週期再試
[InstanceGuard] 重取單實例鎖失敗（reason=db_unreachable，可重試；本行每分鐘至多一次）: <錯誤>
[InstanceGuard] CRITICAL：守衛無法驗證或重取單實例鎖（reason=<permanent|unknown>）；本實例繼續服務、下一週期再試: <錯誤>
[InstanceGuard] 已重新取得單實例鎖（自 <前一狀態：lost 或 overridden> 起未持鎖 <n> ms，reason=<失守前的 reason>）；告知解除
```

| `reason` | Meaning | Banner text | Next step |
|---|---|---|---|
| `contention` | Another session took the lock; the log and the event carry its fingerprint (`holder.*`). The most common source: another instance came up in the gap while this one had lost the lock | This instance has lost the single-instance lock: the lock is held by another session | Go find that instance across your hosts. If it should not exist, stop it and this instance reacquires the lock at the next cycle; if it is the one to keep, stop this instance. For the period while both are writing the database, the data consequences are as in "what confirming means" in §2.6b |
| `db_unreachable` | The connection to the database was lost (a postgres restart, a network event, a query timeout). Every request needing the database is failing anyway at that point, and this line is just the guard seeing it too. The reacquisition failure log is at most one line per minute; when the event cannot be written to the database it goes to the JSONL fallback file | This instance has lost the single-instance lock: the database connection was lost | Deal with the database connection itself. Once it is back the guard reacquires automatically, with no restart needed |
| `permanent` | The database returned a permission or object error (the application account's permission on `pg_locks` or `pg_stat_activity` was withdrawn, SQLSTATE `42501`, for instance). One CRITICAL line per cycle, not throttled | This instance has lost the single-instance lock: the guard cannot verify the lock (permission or object error) | Check whether the application account's permissions on the database were changed, and look at the SQLSTATE at the end of the log line. Once fixed the guard reacquires automatically |
| `unknown` | An error that cannot be classified; handled as for `permanent` | This instance has lost the single-instance lock: reason unknown | Read the error text at the end of the log line, and hand it to the database administrator or report it. The guard keeps retrying |

`reason=ack_page` and `reason=ack_startup` are not a lost lock; they are the state of option 2 in §2.6b, started with a confirmation and not yet holding the lock, on the halt page and through the environment variable respectively. The `regained` event carries the same reason.

**How to query `audit_logs`**: on the audit page, filter the resource by "Instance Guard", or query `resource = 'instance_guard'` directly. Three events:

| `details.event` | `status` | When | Fields of its own |
|---|---|---|---|
| `overridden` | `failure` | At the moment of a start with a confirmation | `ack`, `holder.*`, and the confirmer: the verified administrator account with the page as its source (plus the credential failures that preceded it), or `actor="operator via env"` on the environment-variable path |
| `lost` | `failure` | On entering `lost` at runtime | `reason`; with `contention`, also `holder.*` |
| `regained` | `success` | On returning to `held` from `lost` or `overridden` | `unheld_for_ms`, `reason` (the reason before the loss) |

Each carries `instance.hostname`, `pid`, and `started_at`, plus `db_session_pid` and `lost_total`; none carries a connection string, password, host address, or `client_addr`.
`overridden` and `lost` being recorded as `failure` means "mutual exclusion does not hold," not "the process is broken": filtering on `failure` finds every moment the lock was lost.
The events go through asynchronous audit (at most once), and when the database cannot be written they go to the JSONL fallback file; delivery is not claimed to be guaranteed. Events occurring before the stage 2 audit service is connected at startup are buffered in the process, **up to 16**, with the oldest dropped beyond that; this affects only the first few seconds of a start and is not reached under normal conditions.

**The banner**: when the state is not `held`, or when the holding instance detects other guard-bearing instances connected (`custodexa_instance_guard_peers` greater than 0, with a separate log line, `偵測到 <n> 個其他守衛版實例連線至同一資料庫`, at most once every 10 minutes), the admin interface shows every signed-in user a persistent banner with no dismiss button; the interface polls `GET /api/v1/seal/status` every 60 seconds to update it. Inside the banner an administrator sees the holder fingerprint, the confirmation code, this instance's hostname and process id, and what to do (from `GET /api/v1/instance-guard`, with each view leaving a read audit record). Once the state is back to `held` with no peer connections, the banner disappears on its own.

**What the guard will not do** (do not wait for it when reading these): it does not refuse requests, does not pause background jobs, does not exit the process, and does not terminate other database sessions. Writes between the loss and your intervention are not blocked, which is a deliberate trade-off in this release: automatic blocking on a misjudgment would leave you unable to recover.

---

## 4. Rollback path

### 4.1 The only means of rollback is restoring a backup

To go back to an older version after an upgrade, you deploy the old version's images and then restore the pre-upgrade backup; the procedure is §4.2.

This release's database has the schema baseline (`20260816_schema_baseline`) and the thirteen increments after it
(`20260824_audit_export_jobs`, `20260825_evidence_offsite`, `20260826_source_ip_forensics`,
`20260826_db_query_console`, `20260903_security_policies_value_text`,
`20260903_rotation_evidence_report`, `20260904_windows_local_account_rotation`, `20260905_account_batch_rotation`, `20260906_credential_library`,
`20260906_credential_library_contract`, `20260908_role_state_checkpoint`,
`20260908_group_role_mapping`, `20260909_policy_groups`).

**The `Down` of an incremental migration is not a production rollback method**, which is this product's consistent position and does not change as versions come and go: `Down` restores **structure**, not data. Whatever was in the columns and tables it drops has no second source afterwards; on a later upgrade those columns reappear empty, which looks like they came back while in fact it is a new, empty structure. The only option that belongs in a rollback plan is **restoring the pre-upgrade backup**. The specific cost of each is below.

The baseline's `Down` always returns a refusal error. What it creates is **the entire database schema**, so running its `Down` would drop every table, taking users, assets, authorizations, and audit evidence with it, rather than restoring some older schema shape; so that path always errors and points the way back at restoring a backup.

**`20260824_audit_export_jobs` has a `Down` and it drops that table** (which holds only the state of export jobs, with neither artifacts nor audit evidence in it, which is why `DB_SCHEMA.md` calls it discardable and reversible; that means **dropping the table loses no evidence**, not that it can serve as a rollback method). It likewise **has no production entry point**: `RollbackMigration` is called only by tests anywhere in the tree, and dropping the table restores nothing to its pre-upgrade shape.

**The `Down` of `20260825_evidence_offsite` is irreversible for data tracking.** It drops the offsite custody ledger and the settings generation table, and with them two things: which bucket and key hold the remote copy of which recording and what its hash was at upload time, and which credentials are needed to retrieve which object. **Remote objects do not disappear with a rollback** (the product never deletes remotely), so after a rollback those objects become **orphans**: the things are still there, but the system does not recognize them.

Deployments that have used offsite storage **must export the ledger listing before a rollback and keep it with the backup set**:

```bash
docker compose -f docker-compose.yml exec -T postgres \
  pg_dump --data-only -t offsite_objects -U "${DB_USER:?}" -d "${DB_NAME:?}" \
  > "custodexa-offsite-ledger-$(date +%Y%m%d-%H%M).sql"
```

Two more consequences of a rollback to know first:

- **Recordings whose local cache copy has been cleared cannot be played on the old version**: the old version has no offsite retrieval path, and the local file has already been cleared per the retention settings. Before the rollback, confirm how many are affected and tell the people concerned, either on the "Offsite Storage" page on the admin side or with a one-line count:

  ```bash
  docker compose -f docker-compose.yml exec -T postgres \
    psql -U "${DB_USER:?}" -d "${DB_NAME:?}" -tAc \
    "SELECT count(*) FROM offsite_objects WHERE state = 'local_purged'"
  ```

- **Object storage does not roll back with the restore**: restoring the database adds and removes no remote object. Cleanup of the remote copies belongs to the deployment's lifecycle rules anyway, and a rollback does not change that.

**Reconciling on a later re-upgrade** (rolling back and then upgrading again): run `Up` first to recreate the two tables, and **before starting the service** load the previously exported listing back in, and the correspondence between the ledger and the remote objects reconnects as a whole, **with zero re-uploads**. If the listing is lost there are two cases: where the local file is still there, the backfill scan queues it again and **re-uploads the same key** (same content, harmless overwrite), reconnecting it; where the local file has been cleared it cannot be reconnected, and those remote objects are orphans. Reconcile them against the custody chain events in the audit record and the object listing in the bucket, and do not try to recreate ledger rows by hand.

**The `Down` of `20260826_source_ip_forensics` restores only structure, not data, and is for development databases only.**
It drops the entire account source address baseline (`user_source_ips`), drops each user's allowed source ranges (`users.allowed_cidrs`), and deletes the existing `new_source_ip` alert rows (without which the old CHECK constraint cannot be added back).
After a later upgrade those lists are empty and the baseline is empty: **source restrictions silently disappear, and every address is judged new again.**
**The production rollback method for `20260826_source_ip_forensics` is deploying the old version's images and restoring the pre-upgrade backup** (§4.2), not running this `Down`.

**The `Down` of `20260826_db_query_console` is lossy and is for development databases only.** The two kinds of things it drops differ in nature:

- **Policy**: the allowed database list on assets. Dropping it silently lifts the restriction, and after a later upgrade every asset is back to unrestricted, with no signal on screen that such a list ever existed. The list itself is cheap to rebuild, but **nobody will know that it needs rebuilding**, which is the more dangerous part.
- **Audit evidence**: the final state, reason code, target database, row count, duration, and event identifier of every query console execution unit in the command audit table. Once dropped there is **no second source to recover them from**: the transcript recording is a reading surface derived from the same batch of events, not the source of the facts, and its content is not sufficient to reconstruct these columns either. The statement as written stays in its original column, but the answer to "did this statement actually take effect" disappears wholesale.

So **before a rollback, confirm the pre-upgrade backup contains the whole `session_commands` table**. A complete logical backup contains it anyway (the backup procedure in §2.1 is a complete backup), so all there is to do here is confirm it once before restoring:

```bash
docker compose -f docker-compose.yml exec -T postgres \
  pg_restore --list < "<the pre-upgrade backup file>" | grep 'TABLE DATA public session_commands'
```

**The production rollback method for `20260826_db_query_console` is likewise deploying the old version's images and restoring the pre-upgrade backup** (§4.2).

**The `Down` of `20260903_security_policies_value_text` narrows the value column back to a fixed length and is for development databases only.**
If any stored value already exceeds that length, the database errors outright and the whole transaction rolls back. Its production rollback method is likewise deploying the old version's images and restoring the pre-upgrade backup (§4.2).

**The `Down` of `20260903_rotation_evidence_report` is lossy and is for development databases only.** It drops four things:

- **The report schedule definitions** (the whole table): name, schedule, scope, retention days, and language, with no second source once dropped.
- **The account group column**: in this release it is transitional, read only by the one-time conversion in §2.5; the shared credential marker now comes from the credential itself (see the `Down` of `20260906_credential_library` above). Dropping it loses the record of which accounts were created by copying from another, and **it is not registered retroactively**, because that relationship was only recorded at the moment of creation.
- **The day overrides on credential change plans**: dropping them silently lifts the overrides, every plan goes back to the global value, and there is no signal on screen that those overrides ever existed.
- **The kind column on export jobs**: once dropped, the two kinds of artifact are mixed in one list with no way to tell them apart, and the kind branch of the download authorization stops working too.

**Its production rollback method is likewise deploying the old version's images and restoring the pre-upgrade backup** (§4.2).
The report artifacts themselves need no special preservation: they are derivatives that can be produced again, the facts are all in the database, and you can produce another one after the restore.

**The `Down` of `20260904_windows_local_account_rotation` is lossy and is for development databases only.** It drops the six credential change channel columns on the asset table, that is, each Windows host's credential change channel, WinRM connection method, port, certificate verification mode, uploaded CA certificate, and SSH port for credential changes.
After a later upgrade those columns reappear empty and every asset is back to "not configured" and derived from the protocol: **rdp assets stop having their credentials changed, with no signal on screen that a channel was ever configured on them.** Its production rollback method is likewise deploying the old version's images and restoring the pre-upgrade backup (§4.2).

**The `Down` of `20260905_account_batch_rotation` is lossy and is for development databases only.** It drops the batch table (every batch's summary counts and who started it, with no second source once dropped) and the batch reference columns on credential change records and pending credentials: after a later upgrade every record and pending credential is back to "from a plan," and **the shared credential group a pending credential was meant to join is gone**, so a credential verified after the restore is no longer marked as shared even though the same password is in effect on the other hosts of that batch. Its production rollback method is likewise deploying the old version's images and restoring the pre-upgrade backup (§4.2). Batches run after the upgrade are lost when the backup is restored; the credentials they set on the target hosts are not, so **export the batch list (account name, mode, per-host results) before rolling back** if you need to know which hosts share a password.

**The `Down` of `20260906_credential_library` is lossy and is for development databases only.** It
drops the four credential tables and the two columns on asset accounts. With the tables go every
shared-credential relationship and the whole history of secret versions; with the columns goes the
answer to "which credential does this host log in with, and which version is it on", and that answer
has no second source. The conversion the `Up` performed has no reverse. **The production way back is
deploying the old version's images and restoring the pre-upgrade backup** (§4.2), not running this
`Down`. Credentials created and shared-credential changes made after the upgrade are lost when the
backup is restored; **the secrets those changes set on the target hosts are not**, so if you need to
know which hosts were sharing one secret at that point, export the credential list and its bindings
before rolling back.

**The `Down` of `20260906_credential_library_contract` is lossy and is for development databases
only.** It puts the four dropped columns back as empty shells and recreates the group index, and
**restores no data**: what those columns held was gone the moment they were dropped, so after a later
upgrade they come back empty. Its production way back is likewise deploying the old version's images
and restoring the pre-upgrade backup (§4.2).

**The `Down` of `20260908_role_state_checkpoint` is lossy and is for development databases only.** It
drops the four columns, and with them the role assignment snapshot on every checkpoint; afterwards
all checkpoints are back to not covering role assignments, and a later upgrade gives you no baseline
again until the next seal. Its production way back is likewise deploying the old version's images and
restoring the pre-upgrade backup (§4.2).

**The `Down` of `20260908_group_role_mapping` is lossy and part of that loss cannot be restored, and
it is for development databases only.** Three things go with it, and they are not equivalent:

- **The mapping rules an administrator entered have no second source.** They are typed in one at a
  time on the identity source pages, and nothing else in the system holds a copy. **Export them
  before any rollback** and keep the export with the backup set:

  ```bash
  docker compose -f docker-compose.yml exec -T postgres \
    pg_dump --data-only -t group_role_mappings -U "${DB_USER:?}" -d "${DB_NAME:?}" \
    > "custodexa-group-role-mappings-$(date +%Y%m%d-%H%M).sql"
  ```

- **The source column on the user-role association is dropped**, so which roles an administrator
  assigned and which ones only an external group granted stops being recorded. All role rows go back
  to the older, source-blind meaning, and **the local administrator count starts counting accounts
  again whose administrator role came only from a group mapping** — an account whose administrator
  role disappears at its next sign-in, if the group changes.
- **The mapping facts go too**, but those are rebuildable: each account's next sign-in recomputes
  them. What Down removes is structure — the source column, the mapping facts and the rules — not
  the role rows themselves. A role an account obtained through a mapping stays with it after the
  downgrade as an ordinary assignment; it does not lapse on its own. To take such a role back, an
  administrator has to remove it by hand.

The group observation snapshot columns and the directory and provider configuration columns simply
return to "not configured", which loses nothing that matters — the snapshots are diagnostic data
rewritten at the next sign-in. Its production way back is likewise deploying the old version's images
and restoring the pre-upgrade backup (§4.2). **Mapping rules created after the upgrade are lost when
the backup is restored**, so if you have added any, export them as above before rolling back and enter
them again after a later upgrade.

**The `Down` of `20260909_policy_groups` is lossy, part of that loss cannot be restored, and it is
for development databases only.** It drops the four policy group tables outright. The built-in
groups' content comes back on the next startup, because a seed writes it; **the policy groups an
organization built itself, the clauses in them, and every note and manual confirmation have no
second source**, and a rollback loses them for good. There is no dedicated export endpoint for
them; what covers them is the pre-upgrade backup, which is a complete logical backup (§2.1) and
therefore contains all four tables. **Before rolling back to a version that predates policy groups,
export the self-built groups and the notes** and keep the export with the backup set:

```bash
docker compose -f docker-compose.yml exec -T postgres \
  pg_dump --data-only -t policy_groups -t policy_clauses -t policy_clause_controls \
    -t policy_clause_annotations -U "${DB_USER:?}" -d "${DB_NAME:?}" \
    > "custodexa-policy-groups-$(date +%Y%m%d-%H%M).sql"
```

**Groups built and notes written after the upgrade are lost when the backup is restored** as well,
for the same reason as everything else created after that point. Its production way back is likewise
deploying the old version's images and restoring the pre-upgrade backup (§4.2).

**A login banner configured after the upgrade is lost when the backup is restored**: that text was written after the upgrade, and the pre-upgrade backup does not contain it. **If you are going to roll back, copy the banner's title and body off the security policy page first** (plain text, into a ticket or a handover document), and put them back after a later upgrade.

**Report schedules created and policy values set after the upgrade are likewise lost when the backup is restored**, for the same reason: the pre-upgrade backup does not contain them. If you are going to roll back, copy off the schedules' names, schedules, scopes, retention days, and languages, along with any newly set asset account credential day policy values (into a ticket or a handover document), and set them again after a later upgrade. Copy the day overrides on credential change plans along with them.

**Credential change channels configured after the upgrade are likewise lost when the backup is restored**: copy each Windows host's channel, WinRM connection method, port, certificate verification mode, and SSH port for credential changes into a ticket, save any uploaded CA certificate as a separate PEM, and set them again after a later upgrade.

The code contains one more internal function, `RollbackMigration`. This release gives it no production-usable entry point, and no product code calls it (the only caller is a test).

A database from across a baseline generation cannot even start the new version (§2.0, §2.6), so that situation is stopped before any data is touched and never reaches a rollback.

### 4.2 The actual rollback procedure

1. Stop all services. **Confirm the guard-bearing release has stopped before the rollback**: `docker compose ps` shows no backend running, and the connection count query in step 5 of §2.3 reads 0. If the rollback target has no guard, the old release holds no lock and old and new coexisting are not stopped; the evidence for this step is only those two items.
2. **Deploy the old version's images and binaries** (do this first; the restored database structure has to be paired with the matching code).

   **If you build your own images: put the old images back on `:latest`.** compose references `custodexa/*:latest`, and the new build in §2.2 has already overwritten those three tags with the new artifacts. Without this step, `up -d` brings up **new code against an old database**, which is exactly the combination the §2.6 fail-closed check exists to stop. Use the tags saved aside in §2.2:

   ```bash
   for img in backend frontend guacd; do
     docker tag "custodexa/${img}:pre-upgrade" "custodexa/${img}:latest"
   done
   docker image inspect custodexa/backend:latest --format '{{.Id}}'   # only go on if this matches the old image ID
   ```

   If you did not save the tags in §2.2 and the old images have already been overwritten, the old version has to be rebuilt or obtained again before the rollback (pull that version from a registry, or run the build once from the old source tree); **no old image means no rollback**. If you deploy delivered images, load the old version's image file again instead and confirm compose references it.
3. **When rolling back from 1.4.0 to a release without the built-in proxy, run one `down` with the new compose file first** (`docker compose -f docker-compose.yml down`): the old compose file does not know `tls-init` and `tls-proxy`, so a `down` with it leaves those two containers up, still holding the external http and https ports. **Keep the `tls/` directory, do not delete it**: upgrading again later can then keep the original CA, with no redistribution to client machines. The external entry point returns to the old release's ports, and the firewall rules and `PUBLIC_BASE_URL` change back with it.
4. Restore the pre-upgrade backup per [Backup and Restore §5](./backup-and-restore.md#5-restore-procedure).
5. Run all ten items of the [post-restore verification checklist](./backup-and-restore.md#6-post-restore-verification-checklist) (item 10 applies only with offsite storage enabled).

### 4.3 The cost of a rollback

**Restoring a backup loses all data produced after the backup point**, including the session records, recordings, and audit records from that period. If the system served users for a while after the upgrade before you decided to roll back, the audit trail from that period does not come back.

So:

- The pre-upgrade backup point should be **as close as possible to the moment of the stop** (§2.1 requires a stopped backup for exactly this).
- The post-upgrade verification (§2.7) should be finished **before** service is restored to users. The sooner a problem is found, the smaller the cost of a rollback.

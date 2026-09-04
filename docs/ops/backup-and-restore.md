# Backup and Restore

**English** | [繁體中文](../zh-TW/ops/backup-and-restore.md) | [日本語](../ja/ops/backup-and-restore.md) | [More languages →](../README.md)

> Applies to: Custodexa 1.0.
>
> **Verification status of this procedure**: the steps below were written by deriving them from the actual data location settings and program behavior.
> **A full walk-through test of backup, restore into a clean environment, and the service coming up
> has not been run**, so this document does not claim the procedure has been verified. Before relying on it in earnest, a deployment should walk through it once in a clean environment and keep the record of that rehearsal.
>
> Related documents: [Upgrade SOP](./upgrade-sop.md), [Deployment Topology Limits](./deployment-topology-limits.md),
> [Rotating the Platform's Own Privileged Credentials](./privileged-credential-rotation.md).

---

## 1. Backups are performed by the deployment using standard tools

Backup and restore use `pg_dump`, `pg_restore`, and `tar`. This document gives the full procedure; no script ships with the product. Where backups are kept, for how long, and how they are encrypted and replicated off site all belong to the deployment's data governance.

---

## 2. Where persistent data lives

In a `docker compose` deployment, all persistent data lives under a **single data root**, `DATA_PATH`
(set in `.env`, default `./data`), bind-mounted into the containers:

| Location | Path in the container | Content | Mounted by |
|---|---|---|---|
| `${DATA_PATH}/postgres` | `/var/lib/postgresql/data` | The PostgreSQL data directory (all business data, audit records, encrypted credentials, and wrapped keys) | postgres |
| `${DATA_PATH}/recordings` | `/var/lib/custodexa/recordings` | Session recording files | backend, guacd (shared mount) |
| `${DATA_PATH}/audit` | `/var/log/custodexa/audit` | Audit fallback files, the seal-period journal | backend |
| **Object storage** (optional) | Not in a container filesystem | **Offsite evidence copies**: uploaded copies of recordings and evidence packages | Uploaded by the offsite storage feature; **lives outside the data root** |

> **The last row is not part of the data root, and the backup procedure does not cover it.** Once offsite storage is enabled, copies of recordings and evidence packages are uploaded to the deployment's own object storage bucket, and the backup, retention, and recovery of that copy **belong entirely to the deployment's storage governance**; neither `tar` nor `pg_dump` can reach it. The converse is worth remembering too: **offsite is not the same as backed up.** It is a second copy that shortens the exposure window, not a replacement for the backup procedure (see §3.3).
> The custody ledger in the database (which copy of which recording is in which bucket, under which key, with what hash at upload time) **travels with the database backup**, so whether the ledger matches the remote objects depends on whether the two points in time line up (see §3.1).

**The first three rows above are all bind mounts; there are no named volumes.** Two direct consequences:

- `docker compose down -v` **does not** clear the data (`-v` only clears named volumes).
- Conversely, deleting or overwriting the `DATA_PATH` directory itself deletes all the data, with no second copy.

An asset's credential change channel settings (including the CA certificate uploaded for a WinRM channel) live in the asset table in the database and are backed up with the first row above; there is no separate location for them.

**A temporary directory that is not a backup target**: the artifacts of asynchronous exports land in `/var/lib/custodexa/exports`
(`EXPORT_ARTIFACT_PATH`, the path inside the container), which evidence packages and rotation evidence reports share.
**It is temporary and not a backup target**, but the retention period and the way to retrieve the artifact differ between the two kinds:

- **Evidence packages**: the artifact is cleared automatically by the system after its retention period (24h), and the download stops working once it expires. Backing it up serves no purpose; its content can be retrieved by the requester starting a new export.
- **Rotation evidence reports**: the artifact's retention period comes from the schedule settings (1 to 3650 days), and it is likewise cleared on expiry with the download no longer working. A scheduled report has no natural person as its requester, so there is no "the requester starts it again" path; anyone with audit view permission can produce another one, but that is a new report, with a new production time and a new signature, not the same delivered document. The facts stated in a report come from the database (accounts, credential change records, policy settings), and the backup contains those facts.

This directory **has no bind mount by default** (it is not one of the three bind-mounted locations in the table above) and is stored for the lifetime of the container. Do not set up a separate backup for it, and do not expect it to survive a container rebuild. **This matters especially for reports**: a schedule can set a retention period of years, but while that directory is not mounted as a volume or bind mount, the retention period only holds while the container lives, and any container rebuild (including a version upgrade) empties the artifacts in it. To have reports survive their retention period, mount that directory as a volume or a bind mount, enable offsite storage, or download them within the retention period yourself.
**Mind its sensitivity**: evidence package artifacts contain **decrypted clipboard plaintext** and the recordings themselves
(see §4 and the export documentation), so files in that directory have `0700` and `0600` permissions and should not be pulled into a general backup flow that would spread plaintext copies around.

With offsite storage enabled, this section gains one more path: **copies of the artifacts are uploaded too** (both evidence packages and reports). When the local artifact is gone (cleared, or lost to a container rebuild), as long as a copy of that artifact was uploaded when it completed, it can still be retrieved from object storage **within the artifact's retention period** (the hash is verified before delivery); past the retention period the download is refused regardless, even with the remote copy still there. **The product does not delete remote copies for you**: neither clearing the local artifact nor cleaning up the job row issues a delete against object storage, and when that copy disappears depends on the lifecycle rules the deployment set on the bucket. That also means **plaintext copies of evidence packages will sit in your object storage**, and their access control and encryption have to be treated as being on par with the production database.

**The offsite retrieval staging area** (`OFFSITE_SPOOL_PATH`, the path inside the container) is **a container-local cache** where a retrieved file lands for verification. It likewise has no bind mount by default and is not a backup target; it has a lifetime and a total size cap, its content is **plaintext**, and its meaning is a cache, not a copy.

### 2.1 Locations outside the data root (the easiest square to miss in a backup)

Where audit fallback files and the seal-period journal actually land is decided by the environment variable `AUDIT_LOG_PATH`,
which **falls back to the relative path `logs/audit_fallback` when not set**. That path is relative to the process's working directory and is not under `DATA_PATH`.

- **compose deployments**: both compose files set `AUDIT_LOG_PATH=/var/log/custodexa/audit` explicitly in `environment:`, and that path is already mounted to `${DATA_PATH}/audit`, so it lands inside the data root and backing up `DATA_PATH` covers it.
- **Standalone binary deployments (not through compose)**: if you do not set `AUDIT_LOG_PATH` yourself, these two kinds of files land under `logs/audit_fallback/` in **the working directory the process was started from**. Backing up `DATA_PATH` does not cover it.

> **Do this before deployment**: for any non-compose deployment, always set `AUDIT_LOG_PATH` explicitly and confirm that path is within the backup scope.

The importance of these two kinds of files is not symmetric, and they should be understood separately:

- **Audit fallback files**: when database writes fail, or when the audit queue is saturated, audit rows are written here instead
  (**only while the file fallback switch is enabled**; when it is off, that batch of records is discarded outright and lost permanently).
  What they carry is the batch of audit records that could not be written to the database at the time, which is exactly the record you need most during an incident.
  **These files have no integrity protection of their own** and can be modified or deleted without a trace; they are a lead from the degraded period, not evidence. The point of backing them up is to recover data afterwards, not to obtain proof.
- **The seal-period journal** (see the next section).

**The second square outside the data root: object storage.** With offsite storage enabled, recordings and evidence packages have a copy in the deployment's own object storage bucket, which is likewise outside the data root and **is not inside any compose mount**, so `tar -C "$DATA_PATH"` cannot reach it. The division of responsibility should be stated once and clearly:

- **The product is responsible for**: the upload, recording the bucket, key, and the SHA-256 at upload time in the custody ledger in the database, and verifying on retrieval.
- **The deployment is responsible for**: backup or cross-region replication of the bucket itself, versioning, retention and expiry cleanup, access control, and encryption at rest. The product never deletes remote objects, and claims no protection for the remote copy; all of that protection comes from the settings on the bucket (suggested parameters in §3.7).

When planning backup scope, treat it as **a separate data location**: whether to back it up, to where, and for how long are all storage governance decisions.

**The third square outside the data root: `tls/`.** The certificates for the built-in TLS proxy land in `tls/` under the project directory, not under `DATA_PATH`: `fullchain.pem` and `privkey.pem` are the external certificate, and self-signed mode (`TLS_MODE=selfsigned`) additionally holds the local CA that issued them (`ca-private/custodexa-ca.key` and `ca-public/custodexa-ca.crt`). **Lose that CA private key and the original CA cannot be kept**; the only way on is to reissue under a new CA, and changing the CA means distributing the new CA certificate to every client machine again. So `tls/` must be inside the backup scope, and kept encrypted the same way `.env` is (it likewise contains private keys).

### 2.2 The seal-period journal

The file name is fixed as `seal_journal.bin`, it lands in the directory `AUDIT_LOG_PATH` points at, and **there is no separate environment variable key for it**. Its content is the record of unseal attempts during the seal period (while the KEK is in interface-entry mode and not yet unsealed), in a fixed-length ring that never grows.

**It can safely be included in a backup, and safely restored along with one**: after unseal the journal is replayed back into the audit record automatically, and each event's idempotency key `IdempotencyUUID` is derived deterministically from the journal UUID, the sequence number, the event kind, and the slot, with a unique index on it in `audit_logs`. **Replaying the same journal several times produces no duplicate audit rows.**

### 2.3 How the shell commands in this document obtain deployment variables (read before you start)

The commands in sections 3 and 5 need three deployment-layer variables: `DATA_PATH`, `DB_USER`, and `DB_NAME`.
**They do not appear in your shell on their own.** `docker compose` reads `.env` only to do its own `${...}` substitution, and **exports no value to the calling shell**.

Writing a form with a default value in a command, such as `"${DATA_PATH:-./data}"`, is therefore dangerous: `DATA_PATH` is almost certainly unset in your shell, so it always falls back to `./data`. **The worst such fallback happens during a restore:**
`tar -xzf ... -C "${DATA_PATH:-./data}"` extracts the backup into `./data`, and that directory usually exists, so **tar succeeds with no error message at all**; then the service comes up with the real, empty data root mounted. Recordings and audit records disappear just like that, and it happens in the middle of a disaster recovery.

The procedures in this document are therefore written to two rules:

1. **Read the values from `.env` explicitly, and read them literally, without `source .env`.**
   `.env` is in `docker compose` env_file format, not a shell script. This product's `.env` template contains `LDAP_USER_FILTER=(uid=%s)`: handing it to POSIX sh (`/bin/sh` on Debian and Ubuntu is dash) gives `Syntax error: "(" unexpected` and aborts everything, while bash treats it as an array assignment.
   The `env_get` below takes only the literal value and performs no shell evaluation on `.env`, so quotes, whitespace, `#`, and parentheses all come back as they are.
2. **Fail loudly when a value cannot be obtained.** The commands always use `"${VAR:?explanation}"` rather than `"${VAR:-default}"`.
   Backup and restore are procedures people copy under pressure, and a prerequisite of the form "remember to do something first" will certainly be skipped; so even if you skip the step that obtains the values, the command itself only aborts and prints why, rather than using a default and "succeeding" at the wrong thing. **In a disaster recovery, a command that used the wrong directory and reported success is far worse than one that simply aborted.**

The block below is the first step of both §3.2 and §5, repeated separately in each, so **you do not have to remember to come back here**:

```bash
# ---- Obtain this deployment's variable values ----
# ENV_FILE points at the .env in this deployment's docker compose project directory.
# If you are not working in that directory, use an absolute path, e.g. ENV_FILE=/opt/custodexa/.env
ENV_FILE="${ENV_FILE:-./.env}"

# Take the literal value of one key from .env; on duplicate keys take the last (matching compose, where later wins)
env_get() { sed -n "s/^[[:space:]]*$1=//p" "$ENV_FILE" | tail -n 1; }

# A value already set in the shell environment wins, matching docker compose's precedence (environment variable > .env)
DATA_PATH="${DATA_PATH:-$(env_get DATA_PATH)}"
DB_USER="${DB_USER:-$(env_get DB_USER)}"
DB_NAME="${DB_NAME:-$(env_get DB_NAME)}"

# Look at these with your own eyes: all three must be the values this deployment actually uses
printf 'ENV_FILE=%s\nDATA_PATH=%s\nDB_USER=%s\nDB_NAME=%s\n' \
  "$ENV_FILE" "$DATA_PATH" "$DB_USER" "$DB_NAME"
```

> - If `DATA_PATH` prints as a relative path (`./data`, say), **every following command has to run from the same working directory**. To be safer, convert it to an absolute path on the spot:
>   `DATA_PATH="$(cd "${DATA_PATH:?}" && pwd)"`. If the directory does not exist, `cd` prints an error and `DATA_PATH` becomes an empty string, which does not pass silently, because the `${DATA_PATH:?...}` in the later commands aborts on an empty value just the same (verified: `tar` does not run).
> - If any of the three prints empty, `ENV_FILE` points at the wrong file. **Do not continue.**
> - The `docker compose` commands in this document all assume they run in the deployment project directory (for a production deployment, `docker-compose.yml`). On a machine that also has the development compose file, always add an explicit `-f docker-compose.yml`.
> - For a deployment where your own ingress terminates TLS (`docker-compose.external-ingress.yml`): every `docker compose` command in this document needs both `-f` flags (`-f docker-compose.yml -f docker-compose.external-ingress.yml`), or set `COMPOSE_FILE` in `.env` so that becomes the default. With only one of them the stack starts in the built-in TLS proxy shape.

---

## 3. Backup procedure

### 3.1 Consistency requirement (the three locations must come from the same point in time)

The three locations reference one another, and the most important such reference is that the `recording_path` column of the `sessions` table points at a file in the recordings directory.

- **Database newer, recordings directory older** → the newer session records in the database point at recording files that do not exist, and those sessions cannot fetch a file on playback.
- **Recordings directory newer, database older** → orphaned recording files appear. Service operation is unaffected, but those files appear in no list and are not cleared by the retention policy.

So **prefer the recordings directory being newer than the database, not the other way round**. The order of the procedure below follows from that.

**Offsite storage adds one more reference chain**: a session maps through an indicator to the custody ledger in the database, and a ledger row points at a bucket and key in object storage. **The ledger travels with the database backup**, so:

- **Restoring to a backup taken before a ledger row was created** leaves the remote objects uploaded after that as **orphans**: they are still remote (the product does not delete them), but no row in the database can reach them. To reconcile, compare the custody chain events in the audit record (upload, integrity decision, local expiry) against the object listing in the bucket.
- **After the local cache is cleared, `recording_path` still being there while the file is not is the normal state**, not something the backup missed: that recording's local copy was cleared per the retention settings, and playback automatically fetches it from object storage instead. Reading that as a lost recording leads to unnecessary restore work.

### 3.2 Recommended procedure (service stopped, best consistency)

A stopped backup is the only way to get all three locations from strictly the same point in time. The downtime window depends on the amount of data.

```bash
# 0. Obtain this deployment's variable values (rationale in §2.3). Skip this and the later commands abort rather than use defaults.
ENV_FILE="${ENV_FILE:-./.env}"
env_get() { sed -n "s/^[[:space:]]*$1=//p" "$ENV_FILE" | tail -n 1; }
DATA_PATH="${DATA_PATH:-$(env_get DATA_PATH)}"
DB_USER="${DB_USER:-$(env_get DB_USER)}"
DB_NAME="${DB_NAME:-$(env_get DB_NAME)}"
printf 'ENV_FILE=%s\nDATA_PATH=%s\nDB_USER=%s\nDB_NAME=%s\n' \
  "$ENV_FILE" "$DATA_PATH" "$DB_USER" "$DB_NAME"

# The timestamp shared by this backup (every later step references it, so the steps do not each take their own time and disagree)
STAMP="$(date +%Y%m%d-%H%M)"

# 1. Stop the services that produce new data (keep postgres up for the logical backup)
docker compose stop backend guacd frontend

# 2. Logical database backup (custom format, which makes selective restore possible)
docker compose exec -T postgres \
  pg_dump -U "${DB_USER:?DB_USER not obtained, run step 0 first}" \
          -d "${DB_NAME:?DB_NAME not obtained, run step 0 first}" -Fc \
  > "custodexa-db-${STAMP}.dump"

# 3. Copy the file locations (recordings and audit)
#    **Local copies only**: with offsite storage enabled, the copy inside the object storage bucket is not included here, and backing it up belongs to the deployment's storage governance (see §2.1).
#    For a recording already cleared from the cache, there is no local file to pack.
tar -czf "custodexa-files-${STAMP}.tar.gz" \
  -C "${DATA_PATH:?DATA_PATH not obtained, run step 0 first; do not continue with a default}" recordings audit

# 4. The deployment-layer settings file (contains KEK material, see section 4; keep it encrypted) and the TLS certificate directory
cp "$ENV_FILE" "custodexa-env-${STAMP}.bak"
#    tls/ contains the private key of the external certificate and, in self-signed mode, the local CA private key (see §2.1); keep it encrypted the same way as .env
tar -czf "custodexa-tls-${STAMP}.tar.gz" tls

# 5. Bring the service back
#    KEK mode B (KEK_PROVIDER=ui): as soon as backend restarts it returns to the **sealed state**,
#    all business routes return 503 until someone enters the unseal material in the interface again.
#    This step only brings the containers up; it is not the service being back. For a scheduled backup, schedule who does the unseal along with it (see the end of this section).
docker compose start backend guacd frontend

# 6. Confirm on the spot that both backups can be read (skip this and you do not know what you backed up)
#    Uses pg_restore inside the container, so the machine you operate from needs no PostgreSQL client
docker compose exec -T postgres pg_restore --list < "custodexa-db-${STAMP}.dump" | head
tar -tzf "custodexa-files-${STAMP}.tar.gz" | head
```

> **Mode B (`KEK_PROVIDER=ui`): this backup puts the system back into the sealed state.**
> Step 1 stopped backend, and what step 5 brings back is a **sealed** instance, because KEK material is never written to disk and someone has to unseal at every start. The backup itself is unaffected (`pg_dump` goes through postgres and has nothing to do with sealing); what is affected is what comes **after** the backup: until someone unseals, sign-in and connections all return 503.
>
> Two consequences follow, and belong in the planning of a routine backup:
>
> - **Scheduling a backup means scheduling a service interruption**, lasting from step 5 until someone goes and unseals. A backup that runs in the middle of the night usually has nobody watching. Either schedule the backup for a time when someone is around, or accept that interruption and have monitoring alert on the sealed state.
> - During the seal period `/metrics` **does not carry** `custodexa_audit_queue_depth` (asynchronous audit belongs to stage 2, which is assembled only after unseal), so the "wait for the value to be 0 before stopping" step in [Upgrade SOP §2.4](./upgrade-sop.md#24-confirm-the-audit-queue-has-drained-before-stopping) has no value to read in this state. That is not a broken metric; unseal first, then do that check.
>
> Mode A (`KEK_PROVIDER=env`) and mode C (`KEK_PROVIDER=kms`) are unaffected: the material is supplied by the deployment layer or by KMS and is obtained on its own at restart, so the service comes back with step 5. To determine which one this deployment uses, see section 4.

### 3.3 Backup without downtime (when bounded inconsistency is acceptable)

Run step 0 above (obtaining the values, equally not optional) and steps 2 through 4, skipping 1 and 5 (the service keeps running), and do the readability confirmation in step 6 as written. `pg_dump` takes a consistent snapshot as of when it starts, so the database itself is fine; the inconsistency only affects sessions newly created between the database snapshot and the file copy. To keep the direction of inconsistency on the safe side (recordings newer), **do the database backup first and copy the recordings directory after**.

**Offsite storage does not change that order and does not narrow the backup scope**: the upload is asynchronous and happens afterwards. Between the end of a session and the copy landing there is a window (seconds for text recordings, at least a minute for graphical ones; until recovery if the endpoint is unreachable), and during it the local copy is the only one. The point in time a no-downtime backup captures may have a batch of recordings **not yet offsite**.

### 3.4 What not to do

- **Do not copy the `${DATA_PATH}/postgres` directory at the file layer while the service is running.**
  A running PostgreSQL data directory is not a set of files that can be copied safely, and the copy may not start. A file-layer backup requires stopping the postgres container first.
- **Do not back up only the database.** The KEK material (section 4), the recording files, and the audit fallback files are all outside the database.
- **Do not treat "already offsite" as "already backed up."** They hold independently, and each has its own gap:
  - **Exposure window**: the offsite upload happens only after a session ends, and during that time the local copy is the only one; if the machine is destroyed inside the window, that recording has no second copy. Going offsite **shortens** that window; it does not remove it.
  - **Orphaned objects**: restoring to an older database point in time leaves the remote objects uploaded after it without a ledger entry (see §3.1); they are still remote, but the system does not recognize them.
  - The reverse gap exists too: a recording that never uploaded successfully (retries exhausted) has only the local copy, and the offsite storage page and failure list in the admin interface exist precisely so that this is seen.

### 3.5 Protecting the backup files themselves

Backup content includes encrypted asset credentials, wrapped keys, and all audit records, and is no less sensitive than the production system. The `.env` backup contains the KEK material and `JWT_SECRET` in plaintext outright. Always keep backup files encrypted, and **never store them in the same place as the KEK material**; putting the two together downgrades envelope encryption to no encryption.

### 3.6 File permissions on `DATA_PATH` (the deployment's responsibility)

**Under a bind mount, directory permissions set inside the image do not apply**; the actual permissions come from the host-side directory. The deployment has to ensure that `DATA_PATH` and its three subdirectories are **not world-readable**.

Recording files contain everything the user typed on the target host, including passwords they entered on the target side. Recording files have `0600` permissions, but file permissions are only one layer, and directory permissions are the necessary second one.

Suggested: set the `DATA_PATH` directory to `0750` or stricter, owned by the user the containers run as.

**The equivalent protection on the object storage side is the deployment's to carry.** The recordings and evidence packages uploaded into the bucket are as sensitive as the originals under `DATA_PATH`, but the permission model there is not in the product's hands: bucket access control (who can list, who can read, who can delete) and encryption at rest both have to be configured by the deployment on the bucket. The product **does not encrypt object content**, so unless the bucket does encryption at rest itself, objects are plaintext on the storage side. Suggested minimum: a dedicated least-privilege identity (able to write and read, with **no need for delete permission**, which the product does not use), public access blocked, encryption at rest on, and versioning and retention rules set according to your retention requirements.

**The offsite retrieval staging directory is a container-local plaintext cache** (`OFFSITE_SPOOL_PATH`): retrieved bytes land there for verification and are only delivered once verified. It has a lifetime and a total size cap, is stored for the lifetime of the container, and is not a backup target; but while it exists its content is a plaintext recording or evidence package, so do not mount that path somewhere shared or world-readable.

### 3.7 Suggested settings for the object storage bucket (the deployment's responsibility)

> **Everything in this section is a suggestion, not a product capability.** The product does exactly three things with remote objects: upload, bookkeeping (bucket, key, the SHA-256 and size at upload time), and verify on retrieval. **It sets no retention field, tracks no version history, and deletes no remote object.**
> So "the remote copy will not be overwritten or deleted by mistake" and "the remote copy will be cleared when it expires" **can only be provided by the settings on the bucket**.
> On the connection test and the offsite storage page the product **probes and reports faithfully** what you have set, but it only reports the current state; it does not judge it good or bad, and it does not fix anything on your behalf.

Decide whether to turn these on, and for how long, according to your retention requirements. Those numbers are part of your evidence retention policy, and the product does not decide them for you.

#### S3 and MinIO

- **Versioning**: suggested on. It is the prerequisite for the old content under the same key still being there, and the only way evidence can be recovered after being overwritten. Without it, overwritten content is simply gone; all the product can do is refuse delivery on retrieval because the hash does not match, and it cannot recover the original.
- **Object Lock**: protection against deletion has to be enabled **when the bucket is created** (checked at bucket creation on AWS; `mc mb --with-lock` on MinIO). **An existing bucket cannot have it enabled afterwards.** Once on, add a default retention rule, with the mode (governance or compliance) and the number of days set according to your retention requirements. **The product sends no retention header**, so the protection comes entirely from that rule.
- **Lifecycle rules**: expiry cleanup of remote objects depends on them. Two suggestions:
  - **Align the expiry days with your recording retention policy.** The product's retention policy and this rule are **two independently running deadlines**: no rule means the remote copy stays forever; a rule shorter than the retention policy means the remote copy disappears first, and once the local copy has also been cleared from the cache there is nothing to play back. The product neither detects nor synchronizes these two deadlines.
  - **Add a `NoncurrentVersionExpiration`** to clean up the historical versions accumulated by re-uploads (a retry re-uploads the same key, and with versioning on that accumulates old versions).
  - Two inevitable exceptions to know about first: **objects within an object lock retention period cannot be cleared** (lifecycle rules skip them, which is expected behavior rather than a broken rule), and **the probe object left by a connection test** also cannot be deleted when it falls within a retention rule, in which case the product records it as a warning, stops tracking it, and leaves it to a lifecycle rule or manual cleanup.
- **Least privilege**: give the product a dedicated identity whose permissions are just writing objects under the prefix you specified and reading objects and their metadata, plus reading the bucket configuration (so the connection test can reveal the current versioning and retention state; if it cannot be read, that only shows as a warning and does not affect uploads). **No write permission on retention fields is needed, and no delete permission is needed**, because the product's normal paths never delete remotely. The only place delete is used is the connection test clearing the probe object it left behind, and a failure there is only a warning.

#### Google Cloud Storage

- **The baseline suggestion is a bucket retention policy (which can additionally be locked).** It applies automatically to **every** object in the bucket and requires nothing to be done per object, which suits a writer like this product that only uploads and sets no retention.
- **Per-object retention (`--enable-object-retention`) needs a careful look before you take it**:
  `gcloud storage buckets create --enable-object-retention` only **enables the capability** (an existing bucket can only have it enabled from the console). **This product sets no retention period on any object**, so enabling it alone **protects none of the objects this product uploads**. To take that route you have to set the retention period per object with your own external automation; otherwise you end up with a deployment where protection looks enabled but is not.
- **Where both are present, the later expiry wins.** Also, an event-based hold and a retention setting are mutually exclusive; **the product does not handle that conflict**, and you decide on the bucket which one to use.
- **Object versioning**: suggested on, for the same reason as in the S3 section.
- **Lifecycle rules**: the same two as in the S3 section (align expiry days with the retention policy, clean up noncurrent versions); on a bucket with a retention policy, objects inside the lock period likewise cannot be cleared.
- **Least-privilege service account role**: being able to create and read objects is enough (the `objectCreator` plus `objectViewer` level), plus permission to read the bucket configuration for the disclosure. **No delete permission is needed.**
- **No HMAC key is needed**: this product uses the native GCS API and connects with a service account JSON or application default credentials. Environments where organization policy restricts HMAC are unaffected.

---

## 4. Disaster recovery prerequisites for encryption keys (read before deployment)

The system protects asset credentials, the bind password for the directory integration, notification channel URLs and secrets, signing private keys, **clipboard audit content**, **object storage credentials**, and other fields with envelope encryption. **Whether they can be decrypted after a database backup is restored depends entirely on whether the KEK (key encryption key) can be recovered.**
**Losing the KEK means none of the fields above can be decrypted**, object storage credentials included: the credentials of every historical storage generation are one of that batch, and if they cannot be decrypted the offsite copies of that generation cannot be retrieved. This is not a new risk surface introduced by the offsite feature; it shares its fate with clipboard content and the directory integration password.

> **Clipboard audit content depends on the KEK just the same**: clipboard content is stored envelope encrypted
> (`clipboard_events.content_enc`), so **losing the key means clipboard audit content cannot be read**, on the same terms as every other envelope-encrypted field such as asset credentials, with no exception for being audit data. The **factual side** of a clipboard event (time, direction, content length, status) is not encrypted and remains readable after a restore, but the **full content** cannot be decrypted without the KEK. Disaster recovery planning has to put clipboard content in the "depends on the KEK" category and must not assume it can still be reviewed without the key.
>
> **Evidence package artifacts contain plaintext**: an evidence package export **decrypts** the clipboard content and packs it, together with the recordings themselves, into a ZIP that lands in the temporary export directory
> (`/var/lib/custodexa/exports`, not a backup target, see §2). This is one of the few places in the system where plaintext secrets exist, and its data exposure surface has to be treated as being on par with the production database: directory and file permissions `0700` and `0600`, downloads bound to the requester in person, and the artifact cleared automatically after 24h. **Never** pull that directory into a general backup or copy it anywhere outside key custody; doing so scatters plaintext secrets into places without equivalent protection.

The KEK has three custody modes, declared by the environment variable `KEK_PROVIDER`. **The disaster recovery prerequisites of the three modes are completely different, and the mode has to be chosen and understood before deployment.**

### 4.1 Mode A: `KEK_PROVIDER=env` (local environment variable)

- **Where the material lives**: `ENCRYPTION_KEY` in `.env`. It is a **32-byte** key and can be written three ways: 32 characters (A-Z a-z 0-9), 64 hexadecimal characters, or base64 that decodes to exactly 32 bytes. **The three forms are the same key**: material from a backup entered in a different form decrypts the same data, so on recovery you do not need to remember which form was used originally.
- **Recovery prerequisite**: `.env` itself must be backed up off the machine. **Restoring only the database, without `ENCRYPTION_KEY`, leaves every envelope-encrypted field undecryptable**, and the service also refuses to start.
- **Custody responsibility**: the deployment's.
- **Note**: this mode has exactly one KEK material key, `ENCRYPTION_KEY`; the system reads no other key name.

### 4.2 Mode B: `KEK_PROVIDER=ui` (key entered in the interface, never written to disk)

- **Where the material lives**: **in memory only, never written to disk.** After startup the system is in the sealed state, with every route apart from the health check and the seal endpoints returning 503, and a person has to enter the material on the `/unseal` page to unseal it.
- **Startup prerequisite**: when `ui` mode is declared, `ENCRYPTION_KEY` **must have no value**. Declaring that the material is not written to disk while leaving the material in the environment is a configuration contradiction, and the system refuses to start.
- **Custody responsibility: the customer's own.**

> ### Facts you must know before deployment
>
> **In this mode, once the unseal material is lost, all encrypted data is permanently undecryptable. The product offers no way to recover it: there is no backup key, no escrowed copy, and no vendor backdoor, and technical support cannot recover it either.**
>
> Choosing this mode is choosing to carry custody of the material on your own. Before submitting the initialization, save the material to a secure offline location (a password vault or physical custody, for instance) and confirm that at least one other person can obtain it.

- **The initialization trap (very important)**: if the initialization times out, the screen tells you to **retry with the key you entered the first time, not a new one**. **Do exactly that.** A timeout does not mean initialization failed: internally it **may already have completed**, and the first key is already fixed as this deployment's master key. Using a new key at that point **fails forever**, and there is no remedy.
- **An ordinary unseal** (an existing deployment, not initialization): it needs only the material, no account credentials, and it does not validate the material's format (an existing deployment's KEK may predate the current format rules). Repeated failures trigger exponential backoff, and past a threshold a time-limited cooldown; **the cooldown ends on its own and the process never has to be restarted for any reason**. Attempts during the cooldown are refused outright and do not extend it.
- **A convergence worth enabling**: with `SEAL_UNSEAL_BIND_ADDR` set, the unseal endpoint is served by a separate listener on that address, and that listener exposes only the seal-related endpoints (it does not turn into the full business interface after unseal), while the main listener refuses unseal requests outright and points them at the management port. **Failing to bind means refusing to start**, so it does not silently degrade into looking isolated while not being so.
  When trusted proxies (`TRUSTED_PROXIES`) are not configured, the source is determined from the transport-layer peer address only, and per-IP backoff conservatively degrades to global backoff.

### 4.3 Mode C: `KEK_PROVIDER=kms` (delegated to a cloud KMS)

```
KEK_PROVIDER=kms
KEK_KMS_PROVIDER=aws
KEK_KMS_REGION=<region>
KEK_KMS_KEY_ID=<alias, key-id, or ARN>
```

- **Recovery prerequisite**: the key in KMS and the AWS account must still exist, and the restored environment must have IAM permission to access that key. A key scheduled for deletion or a closed account amounts to losing the material.
- **IAM permissions needed**: `kms:Encrypt`, `kms:Decrypt`, `kms:DescribeKey`; if native re-encryption is used, also the two actions `kms:ReEncryptFrom` and `kms:ReEncryptTo`.
- **Credentials**: the AWS SDK default chain (IRSA, instance profile, `AWS_*`); the product does not manage them.
- **Trust boundary**: `KEK_KMS_KEY_ID` is also the only source of the trusted account scope, and the target key of a delegated rewrap must be in the same AWS account and partition as it, or it is refused.
- **Multi-region keys (MRK)**: the stored identifier includes the region, so **switching to a replica amounts to changing the key and requires a rewrap first**. If your disaster recovery plan covers a cross-region switch, put that rewrap into the procedure; switching straight over leaves the existing data undecryptable.
- **Endpoint overrides are always refused**: detecting a value in `AWS_ENDPOINT_URL_KMS` or `AWS_ENDPOINT_URL` means refusing to start. Those variables are parsed by the SDK directly and would direct `kms:Encrypt` requests, which contain the plaintext data key, at that address (which may be plaintext HTTP).

### 4.4 Disaster recovery prerequisites for object storage credentials

Both the connection parameters and the **credentials** for offsite storage live in the database, with the credentials envelope encrypted (one set per storage generation). The disaster recovery prerequisite is therefore simple: **restore the database and obtain the same KEK, and the ability to retrieve is back**. There is no separate object storage key to keep, and nothing to leave in `.env` for it.

> **The plaintext burden this item placed on `.env` is gone.** Object storage credentials no longer go through `.env`, so the settings file does not have to be kept as a secret for their sake. **The other keys are still secrets**: `.env` still contains `DB_PASSWORD` and `JWT_SECRET`, and in mode A also `ENCRYPTION_KEY`, so §3.5's requirement to keep the `.env` backup encrypted is unchanged.

- **Consequence of losing the KEK**: object storage credentials of every generation become undecryptable, and the offsite copies of those generations cannot be retrieved (the objects are still in the bucket, but the system cannot get the credentials to read them). This belongs to the same category as clipboard content and the directory integration password at the start of section 4; it is not an additional risk surface. There is exactly one **way around it**: the deployment reaches those objects on the storage side by other means, which is a matter of storage governance, not a product path.
- **Generation changes in the storage settings**: changing the provider, endpoint, or bucket all take effect after confirmation in the admin interface, and the old generation **becomes a historical generation**, whose credentials are **kept with the generation** so historical objects can still be retrieved. When a historical generation is no longer needed, its credentials can be **revoked for that generation alone**; afterwards the objects of that generation cannot be retrieved, the message states plainly which generation is missing what, and **there is no fallback to the cloud provider's default credential chain**.
- **Stopping offsite storage is also done in the admin interface**: after stopping there are no new uploads, but **retrieval of historical objects is unaffected**, because credentials are not revoked by stopping. Revoking has to be stated explicitly, generation by generation.
- **The execution marker for the first-time configuration is restored with the database backup.** The offsite keys in `.env` are read once at first startup and written into the database, and an execution marker is recorded at the same time. The marker lives in the database, so a restore may land on two kinds of misalignment:

  | State after the restore | Result | What to do |
  |---|---|---|
  | **Marker present, settings table empty** | The system considers the assessment done, `.env` **is not seeded again**, and this deployment counts as not configured | **It can only be configured again through the admin interface.** Do not modify the database, and do not try to delete the marker; changing `.env` and restarting has no effect at all |
  | **Settings table non-empty, marker absent** | The next startup only writes the marker, and **does not overwrite** the settings in the database | Nothing to do; the runtime uses the settings in the database |
  | A complete point-in-time restore | The two agree, and behavior is the same as before the restore | Whether the credentials can be decrypted rests on the same KEK (see above) |

---

## 5. Restore procedure

**One point where the order differs from §3.2**: `.env` is restored first, and the variables are obtained after. The reason is in the note on step 2.

Below, `STAMP` carries the timestamp of the set of backup files to restore (the file name suffix produced in §3.2). **Set it to the actual value before running anything**:

```bash
# 0. The target environment has to be prepared first: code and images of the same version as the backup, and the corresponding KEK (see section 4)
#    If the versions differ, check the compatibility statement in the upgrade SOP first.
#
#    The timestamp of the set of backup files to restore. **The value on the line below must be changed to the actual file name suffix**;
#    if you forget, the three commands after it fail because the files do not exist (they will not restore the wrong thing).
STAMP=YYYYMMDD-HHMM

# 1. Stop all services. ${DATA_PATH}/postgres in the target environment must be an empty directory
#    (the postgres container only initializes a clean database when the data directory is empty);
#    confirm this machine is the one meant for the restore, then empty that directory
docker compose down

# 2. Restore the deployment-layer settings first (required for KEK mode A; mode B contains no material, mode C contains no KMS credentials).
#    This comes before obtaining the values because it overwrites .env entirely. If you obtained the values first and overwrote afterwards,
#    the DATA_PATH, DB_USER, and DB_NAME you hold would be the old pre-overwrite values, inconsistent with what the service actually uses.
ENV_FILE="${ENV_FILE:-./.env}"
cp "custodexa-env-${STAMP}.bak" "$ENV_FILE"
#    Note: what you restored is the .env of the *source* machine. If this machine's data root differs from
#    the source machine's, change DATA_PATH in .env to this machine's actual path now, before going on.

# 3. Obtain this deployment's variable values (rationale in §2.3). **This is the most critical step of the procedure**:
#    if DATA_PATH is not obtained and falls back to a default, the next step extracts the backup into the wrong directory, and reports no error.
env_get() { sed -n "s/^[[:space:]]*$1=//p" "$ENV_FILE" | tail -n 1; }
DATA_PATH="${DATA_PATH:-$(env_get DATA_PATH)}"
DB_USER="${DB_USER:-$(env_get DB_USER)}"
DB_NAME="${DB_NAME:-$(env_get DB_NAME)}"
printf 'ENV_FILE=%s\nDATA_PATH=%s\nDB_USER=%s\nDB_NAME=%s\n' \
  "$ENV_FILE" "$DATA_PATH" "$DB_USER" "$DB_NAME"

# 4. Restore the file locations. Before extracting, print the absolute path of the extraction target and check it once
#    (if the directory does not exist, or DATA_PATH was not obtained, this line fails and tar is never reached)
( cd "${DATA_PATH:?DATA_PATH not obtained, run step 3 first; do not continue with a default}" && pwd )
tar -xzf "custodexa-files-${STAMP}.tar.gz" \
  -C "${DATA_PATH:?DATA_PATH not obtained, run step 3 first; do not continue with a default}"
#    Restore the TLS certificate directory into the project directory (without it, self-signed mode generates a new CA and certificate at startup,
#    and the CA has to be distributed to every client machine again)
tar -xzf "custodexa-tls-${STAMP}.tar.gz"

# 5. Start postgres only, and load the logical backup **after it can really accept connections**.
#    `up -d` only guarantees the container started, not that postgres is ready; and on first startup (empty data directory),
#    the postgres image first runs a temporary server that listens on the unix socket only, to do the initialization.
#    During that period `pg_isready` over the socket reports ready, but the target database **does not exist yet**,
#    and loading the backup then gives `database "..." does not exist`, so the whole restore comes to nothing.
#    So the criterion here is both **TCP** (`-h 127.0.0.1`, not listened on during initialization) and **actually connecting to the target database** holding at the same time.
docker compose up -d postgres
for _ in $(seq 1 60); do
  docker compose exec -T postgres \
    pg_isready -h 127.0.0.1 -U "${DB_USER:?DB_USER not obtained, run step 3 first}" >/dev/null 2>&1 \
  && docker compose exec -T postgres \
    psql -U "${DB_USER:?}" -d "${DB_NAME:?DB_NAME not obtained, run step 3 first}" -c 'select 1' >/dev/null 2>&1 \
  && break
  sleep 2
done
# Confirm explicitly one more time; if this line is non-zero do not go on (loading into a half-ready server only produces an incomplete database)
docker compose exec -T postgres psql -U "${DB_USER:?}" -d "${DB_NAME:?}" -c 'select 1'

docker compose exec -T postgres \
  pg_restore -U "${DB_USER:?DB_USER not obtained, run step 3 first}" \
             -d "${DB_NAME:?DB_NAME not obtained, run step 3 first}" --clean --if-exists \
  < "custodexa-db-${STAMP}.dump"

# 6. Start the remaining services
docker compose up -d
```

A KEK mode B deployment is still sealed after step 6, and only starts serving once the material is entered at `/unseal`.

---

## 6. Post-restore verification checklist

**Confirm every item; if any of them fails, do not hand the system back into service.**

| # | Check | How | Pass criterion |
|---|---|---|---|
| 1 | All services are up | `docker compose ps` | Each service is running, postgres is healthy |
| 2 | Backend health check | `docker compose exec backend wget -qO- http://localhost:8080/health` | A normal response (backend publishes no port, so it has to be called from inside the container) |
| 3 | No fatal in the startup log | `docker compose logs backend \| tail -50` | No refusal-to-start message. **A KEK mismatch says so plainly here** |
| 4 | The frontend is reachable | `curl -I http://localhost/` | Responds 200 |
| 5 | The sign-in path works | Sign in with an existing administrator account | A token is obtained; the console can be entered |
| 6 | **Compare the fingerprints in the key inventory** | The "Key Management" page on the admin side | The fingerprints of the four env-side items, `ENCRYPTION_KEY (KEK)`, `JWT_SECRET`, the export signing key (Ed25519), and the checkpoint signing key (Ed25519), **are the same as the values recorded before the backup** |
| 7 | Encrypted fields decrypt | Open any asset that has credentials, or trigger one LDAP sign-in | No decryption failure appears |
| 8 | Recordings play back | Open a session recording that existed before the backup | It plays. **Both a local source and an offsite source count as a pass**: where the local file has been cleared from the cache it is fetched from object storage instead (with a download wait on first playback), and that path likewise verifies the hash before delivery |
| 9 | Audit chain verification | The integrity verification page on the audit side | The verification result matches the one before the backup |
| 10 | **The ledger and the objects in the bucket agree** (only with offsite storage enabled) | The "Offsite Storage" page on the admin side: confirm the settings summary and generation state are as expected and that the failure list has no abnormal buildup; spot-check that a recording already offsite plays back | The ledger state matches the remote reality. **The two directions of disagreement read differently**: a ledger row with nothing in the bucket means a restore to a newer database point in time (or the remote copy was cleared by a lifecycle rule); something in the bucket with no ledger row is an orphaned object, usually a restore to an older point in time (see §3.1), to be reconciled against the custody chain events in the audit record |

> Item 6 is the most valuable one: **a fingerprint is a one-way digest, and matching fingerprints confirm that the same key is in use after the restore**, without touching any key material. Record these **four** fingerprints with every backup and keep them with it.
> Record only three at backup time and one of them has nothing to compare against after the restore; the one usually missed is the checkpoint signing key.
>
> The Key Management page can only be entered **after unseal** (mode B), so this item comes after the service is back.

---

## 7. Manual handling of exceptional cases

### 7.1 Both headers of the seal-period journal are invalid

**Symptom**: the service refuses to open its listener, and **does not rewrite that journal file**.

The system deliberately does not rebuild this file automatically. Automatically "repairing" a file that records the number of unseal attempts would amount to providing a legitimate way to zero out that history.

**Handling (four steps, done in order)**:

1. Copy the file (`seal_journal.bin`) offline and keep it. **Do not modify it in place.**
2. Inspect it with external tools to see whether it can still be read, and judge whether this is damaged storage media or human modification.
3. Have a person decide whether to start over with a new file, **and record that decision**: who decided, when, and why. That record is the only basis for later explaining why this trail starts from zero.
4. Remove the damaged file and restart the service.

### 7.2 Booting with a retired KEK whose material has not been cleared

**Symptom**: the service fails closed and refuses to start, and the error message states plainly that this is a retired KEK, with different guidance depending on the retirement reason:

- **Reason "switched over"**: the message directs you to recover its retirement row manually per the runbook and restart if you really intend to roll back to this KEK, or to change `ENCRYPTION_KEY` back to the current KEK if it was set by mistake.
- **Reason "abandoned"** (that KEK was never in service): the message directs you to change back to the current KEK, or to start with the current KEK and run the rewrap again.

The system **does not reverse retirement automatically**. Setting an old KEK after the switchover has completed is almost always an operator mistake, and reversing it automatically would silently undo a deliberate key ceremony.

**Whether "recovering the retirement row manually" is possible**: KEK retirement is a soft retirement that changes only the status column, and **the wrapping material is kept until it is cleared explicitly**. So until "clear retired data" is run, rolling back to an old KEK at the data layer is always possible. Once the explicit clear has run, that material is emptied and unrecoverable, and booting with the old KEK then gives only a generic mismatch error. For details, see the KEK sections of [Rotating the Platform's Own Privileged Credentials](./privileged-credential-rotation.md).

### 7.3 Recovering audit fallback files after a restore

If there are fallback files under the restored `${DATA_PATH}/audit`, audit writes failed at some point before the backup. Those records are **not** loaded into the database by the restore; the handling is to keep the files as a basis for later investigation.

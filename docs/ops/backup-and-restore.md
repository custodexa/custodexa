# Backup and Restore

**English** | [繁體中文](../zh-TW/ops/backup-and-restore.md) | [日本語](../ja/ops/backup-and-restore.md) | [More languages →](../README.md)

> Applies to: Custodexa 1.0. §3.8 and §5.1 describe the management script of package deployments, from 1.13.0; the single backup file of §3.8, §5.2 and §5.3, the backup file an upgrade takes, the backup of a deployment with an external database, `rollback` in §5.1 and `restore` in §5 are from 1.16.0.
>
> **Verification status of this procedure**: the steps below were written by deriving them from the actual data location settings and program behavior.
> **A full walk-through test of backup, restore into a clean environment, and the service coming up
> has not been run**, so this document does not claim the procedure has been verified. Before relying on it in earnest, a deployment should walk through it once in a clean environment and keep the record of that rehearsal.
>
> Related documents: [Upgrade SOP](./upgrade-sop.md), [Deployment Topology Limits](./deployment-topology-limits.md),
> [Rotating the Platform's Own Privileged Credentials](./privileged-credential-rotation.md).

---

## 1. Backups are performed by the deployment using standard tools

Backup and restore use `pg_dump`, `pg_restore`, and `tar`. This document gives the full procedure. In a deployment installed from the release package, the management script `custodexa.sh` runs the stopped backup of §3.2 for you (§3.8); a restore is always done by hand, with section 5. Where backups are kept, for how long, and how they are encrypted and replicated off site all belong to the deployment's data governance.

---

## 2. Where persistent data lives

In a `docker compose` deployment, all persistent data lives under a **single data root**, `DATA_PATH`
(set in `.env`, default `./data`), bind-mounted into the containers:

| Location | Path in the container | Content | Mounted by |
|---|---|---|---|
| `${DATA_PATH}/postgres` | `/var/lib/postgresql/data` | The PostgreSQL data directory (all business data, audit records, encrypted credentials, and wrapped keys) | postgres |
| `${DATA_PATH}/recordings` | `/var/lib/custodexa/recordings` | Session recording files | backend, guacd (shared mount) |
| `${DATA_PATH}/audit` | `/var/log/custodexa/audit` | Audit fallback files, the seal-period journal | backend |
| `${DATA_PATH}/exports` | `/var/lib/custodexa/exports` | Artifacts of asynchronous exports (evidence packages, rotation evidence reports, compliance reports). **Kept across container rebuilds, but not covered by the backup commands** (see below) | backend |
| **Object storage** (optional) | Not in a container filesystem | **Offsite evidence copies**: uploaded copies of recordings and evidence packages | Uploaded by the offsite storage feature; **lives outside the data root** |

> **The last row is not part of the data root, and the backup procedure does not cover it.** Once offsite storage is enabled, copies of recordings and evidence packages are uploaded to the deployment's own object storage bucket, and the backup, retention, and recovery of that copy **belong entirely to the deployment's storage governance**; neither `tar` nor `pg_dump` can reach it. The converse is worth remembering too: **offsite is not the same as backed up.** It is a second copy that shortens the exposure window, not a replacement for the backup procedure (see §3.3).
> The custody ledger in the database (which copy of which recording is in which bucket, under which key, with what hash at upload time) **travels with the database backup**, so whether the ledger matches the remote objects depends on whether the two points in time line up (see §3.1).

**The first four rows above are all bind mounts; there are no named volumes.** Two direct consequences:

- `docker compose down -v` **does not** clear the data (`-v` only clears named volumes).
- Conversely, deleting or overwriting the `DATA_PATH` directory itself deletes all the data, with no second copy.

An asset's credential change channel settings (including the CA certificate uploaded for a WinRM channel) live in the asset table in the database and are backed up with the first row above; there is no separate location for them.

**A directory that is kept but is not a backup target**: the artifacts of asynchronous exports land in `/var/lib/custodexa/exports`
(`EXPORT_ARTIFACT_PATH`, the path inside the container), which evidence packages, rotation evidence reports and compliance reports share.
The production compose file mounts it at `${DATA_PATH}/exports`. **It is not a backup target**, and the retention period and the way to retrieve the artifact differ between the kinds:

- **Evidence packages**: the artifact is cleared automatically by the system after its retention period (24h), and the download stops working once it expires. Backing it up serves no purpose; its content can be retrieved by the requester starting a new export.
- **Rotation evidence reports**: the artifact's retention period comes from the schedule settings (1 to 3650 days), and it is likewise cleared on expiry with the download no longer working. A scheduled report has no natural person as its requester, so there is no "the requester starts it again" path; anyone with audit view permission can produce another one, but that is a new report, with a new production time and a new signature, not the same delivered document. The facts stated in a report come from the database (accounts, credential change records, policy settings), and the backup contains those facts.
- **Compliance reports**: produced by hand from the compliance mapping page. The requester sets the retention period (1 to 3650 days, 90 by default), and the artifact is cleared on expiry with the download no longer working. The report states the settings as they were when it was packaged; producing it again gives a new report with a new data time, not the same document. The settings, clauses and confirmation records it draws on are in the database and in the backup.

Because the directory is a bind mount, artifacts survive a container rebuild, a version upgrade included, and stay downloadable until their retention period ends. **The backup commands in §3 deliberately leave it out**: the `tar` there names `recordings` and `audit` only, for the sensitivity reason below. A backup that copies the whole of `DATA_PATH` (a filesystem snapshot, for instance) takes this directory along; exclude `exports` from it. The consequence after a restore: the job rows come back with the database, but their artifacts do not. Downloading such a job answers 410 (`RULE_EXPORT_ARTIFACT_UNAVAILABLE`), while the job list still shows it as done. **This matters especially for reports**, whose retention period can run to years: to have them outlive the loss of the host, enable offsite storage, or download them within the retention period yourself.
A deployment that runs its own compose file instead of the shipped one has to mount this path itself. Without a mount, the directory lives only as long as the container, and any container rebuild empties it.
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
> - In a package deployment (§3.8), run them in the deployment folder. Its `.env` names the compose files under `current/` in `COMPOSE_FILE`, so no `-f` is needed, but `up` and `down` need `--project-directory .`, as written in section 5; §5.1 says what else to set first.
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
> Mode A (`KEK_PROVIDER=env`) is unaffected: the material is supplied by the deployment layer and is obtained on its own at restart, so the service comes back with step 5. Mode C (`KEK_PROVIDER=kms`) comes back sealed like mode B, because its custodian credentials are held only in memory and are supplied again on the unseal page (§4.3); the two consequences above apply to it too. To determine which one this deployment uses, see section 4.

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

A backup file written by the management script (§3.8) holds all of this in one file, `.env` included as `env.bak`:

- **Mode A (`KEK_PROVIDER=env`, §4.1): the backup file contains the master key.** `env.bak` carries `ENCRYPTION_KEY`, so the KEK material and the data it protects travel together, and whoever has an unencrypted copy can decrypt every stored credential. The completion screen marks `.env` as including the master key. Encrypt the file with a passphrase when it is made (§3.8), or encrypt it by other means before it leaves the host, and keep the passphrase or key apart from the file.
- **Modes B and C (§4.2, §4.3): the external material is not in the file.** The unseal material of mode B and the custodian credentials of mode C live in no file and no table, and the script collects none of them; the file records only the master key fingerprint or key ID, for comparison after a restore. In these modes `ENCRYPTION_KEY` has to be empty, and the backup refuses to start when it has a value.
- **`.env` is copied byte for byte, so whatever else is written in it travels with the backup.** Do not put cloud credentials into `.env`, such as the access keys, service account key file or Vault secret of a mode C custodian, whether as a value or in a comment. The product never reads custodian credentials from `.env` (§4.3), and the script cannot tell them apart from other text.

### 3.6 File permissions on `DATA_PATH` (the deployment's responsibility)

**Under a bind mount, directory permissions set inside the image do not apply**; the actual permissions come from the host-side directory. The deployment has to ensure that `DATA_PATH` and its four subdirectories are **not world-readable**.

Recording files contain everything the user typed on the target host, including passwords they entered on the target side. Text (SSH) recordings are `0600` files owned by root, inside per-day directories that the backend creates and keeps at `0700`. Graphical (RDP and VNC) recordings are `0640` files owned by `1000:0` in the top level of the recordings directory, written by guacd running as uid 1000. The recordings directory itself is `1000:0` with mode `2770` ([Deployment and Upgrade SOP §1.3](./upgrade-sop.md#13-check-the-file-permissions-on-data_path)): guacd writes into it as its owner, and the backend, which runs as root without the capabilities that bypass file permissions, reads, renames and expires graphical recordings through group 0. Do not change that owner, group or mode. It follows that a host account with uid 1000 can read graphical recordings, and rename or move anything in the top level of the recordings directory, without going through the product; keep that uid for the people who administer this system. File permissions are only one layer, and directory permissions are the necessary second one.

The export directory needs no preparation: the backend sets `${DATA_PATH}/exports` to `0700` each time it starts and writes every artifact as a `0600` file, both owned by root as the container sees them. Evidence package artifacts in it hold decrypted plaintext (§4).

Suggested: keep the `DATA_PATH` directory itself owned by root with mode `0750` or stricter. The containers mount only its subdirectories, so a root-owned data root does not stand in their way.

**After a restore, set the recordings directory again.** Extraction keeps owners and modes only when it runs as root, and a backup taken on a host deployed with 1.12.2 or earlier may carry the owner Docker gave the directory there (`root:root 0755`), with which RDP and VNC sessions leave no recording. Step 4 of the restore procedure (§5) therefore runs the preparation command from SOP §1.3 right after extracting the data. For a package deployment, use the preparation step in this procedure; `scripts/quickstart.sh` belongs to the source-tree evaluation path and must not be run against a package deployment.

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

### 3.8 Backups taken by the management script (package deployments)

In a deployment installed from the release package, `custodexa.sh` runs the stopped backup of §3.2. It does so when asked, from the menu (**Back up to a single file**) or with `sudo ./custodexa.sh backup` in the deployment folder, and on its own at step 7 of every upgrade ([Upgrade SOP](./upgrade-sop.md#upgrading-with-the-management-script)). Both write a single backup file in the same format, which can be copied to another host; the backup an upgrade takes differs only in what it holds (end of this section). A deployment with an external database is backed up the same way, with the release's PostgreSQL client in place of the bundled database (below).

#### The backup file written by `backup`

- **What it runs**: seven steps, numbered as on the screen. (1) Stop backend, guacd and frontend; the database keeps running. (2) Dump the database with `pg_dump -Fc` and take `snapshot.txt`. (3) Pack `audit`, and `recordings` when chosen. (4) Copy `.env`, pack `tls/` when the deployment has one, copy the proxy template that `TLS_NGINX_TEMPLATE` names when it is set, and copy the two release manifests. (5) Start the services and wait up to 180 seconds for the backend to be ready. (6) Confirm that the dump lists with `pg_restore --list` and each archive with `tar -tzf`. (7) Build the single file, encrypting it when chosen, and read it back. The services are paused for steps 1 to 5 only; the preview gives both durations.
- **Checked before anything stops**: free space (the size of the file, room for its largest part while the file is built, and 1 GB spare); the master key settings (§4: in mode A `ENCRYPTION_KEY` has a value, in modes B and C it is empty, and `KEK_PROVIDER` is a value the backend accepts; the refusal names the keys and never prints their values); that the version recorded in `state.json` is the one in `current/MANIFEST.json`; when `TLS_NGINX_TEMPLATE` in `.env` is set, that it names a regular file that can be read, and that its path has no character the manifest cannot record: a double quote, a backslash, a tab or other control character, or a character outside ASCII (a restore puts the template back at that path); and, when encrypting, the passphrase file and the openssl image. A refusal stops nothing.
- **After step 5**: in mode A the final screen says the services are back. In modes B and C the system comes back sealed (the mode B note in §3.2, and §4.3): the preview warns about it and the final screen gives the unseal page. If the backend is not ready within 180 seconds, step 5 is marked WARN and the backup still finishes; the final screen prints the `status` and `start` commands.
- **Questions and flags**: run in a terminal without `--yes`, the script asks two questions, both answered no by default: whether to put the recordings in the file, and whether to encrypt the file with a passphrase. `--with-recordings` puts the recordings in without asking; `--passphrase-file <file>` encrypts without asking (below). With `--yes` and neither flag, the file holds no recordings and is not encrypted, and the preview names the flag for each. Without a terminal, `--yes` is required. Only `backup` accepts these two flags.
- **Where**: `backups/custodexa-backup-<version>-<STAMP>.tar` in the deployment folder (`.tar.enc` when encrypted), with a checksum file of the same name plus `.sha256` next to it. `<version>` is the installed version and `<STAMP>` is `YYYYMMDD-HHMMSS` (seconds included, unlike §3.2). `backups/` is mode `0700`, and the backup file and its checksum file are `0600`. The script never overwrites a backup: when the name is taken it moves to the next second, at most twice, and when all three names are taken it refuses before anything stops. `status` shows the latest backup with its size, and says when it is encrypted.

The checksum file is in `sha256sum` format and names the file without a path, so after copying both files to another folder or host, `sha256sum -c <name>.sha256` in that folder checks the copy.

The backup file is an uncompressed tar. Its members are plain files at the top level, each present at most once:

| Member | Content |
|---|---|
| `backup-manifest.json` | What the backup is (below). It holds no secret values |
| `release-MANIFEST.json` | The release manifest of the installed version, as it was (`current/MANIFEST.json`) |
| `tool-MANIFEST.json` | The release manifest of the script that wrote the file |
| `snapshot.txt` | What the database held once the services had stopped (below) |
| `db.dump` | The database, `pg_dump -Fc` (§3.2 step 2) |
| `audit.tar.gz` | `audit` under `DATA_PATH` |
| `recordings.tar.gz` | `recordings` under `DATA_PATH`; only when chosen |
| `env.bak` | `.env` as it was, secrets included; in mode A that includes the master key (§3.5) |
| `tls.tar.gz` | `tls/`; only when the deployment has one (behind your own ingress it has none) |
| `nginx-tls.conf.template` | The proxy template that `TLS_NGINX_TEMPLATE` in `.env` names, as it was; only when that is set |
| `db-ca.pem` | With an external database: the CA file that `PGSSLROOTCERT` in `.env` names, as it was; only when that names a file |
| `state.json` | Only in the backup an upgrade takes: the script's record as it was when that upgrade began (§5.1) |
| `SHA256SUMS` | The checksums of every other member |

`exports` is never included (§2). The recordings are left out unless chosen, because they are usually most of the size; the final screen then names the recordings folder. If you keep the recordings another way, copy them after the backup has finished, so that the recordings are the newer side (§3.1).

**`backup-manifest.json`** holds one `"key": "value"` per line. The keys to read when restoring by hand: `product.version` (the version the data belongs to; the target of a restore runs this version, §5 step 0), `created_at` (when the services stopped), `kek.provider` (the master key mode the backend actually uses: `env` for mode A, `ui` for mode B, `kms` for mode C), `kek.material_included` (`true` only in mode A), `kek.fingerprint` (the master key fingerprint or key ID, equal to `fp.kek` in `snapshot.txt`), `encryption.enabled` with `encryption.scheme`, `contents.recordings`, `contents.tls` (`false` when the deployment had no `tls/`: the file then has no `tls.tar.gz`, and nothing is missing), `contents.nginx_template` with `source.tls_nginx_template` (whether the proxy template is in the file, and the path `.env` gave for it), `trigger` (`manual` for `backup`, `upgrade` for the backup an upgrade takes, which alone has `contents.state` `true`), and `db.location` (`bundled`, or `external` with the keys in "Deployments with an external database" below). It also records the PostgreSQL server and `pg_dump` versions, the database encoding, the overlays in use, and the source host's name, deployment folder, `DATA_PATH`, `TLS_DOMAIN`, `TLS_IP_SAN` and `PUBLIC_BASE_URL`.

**When a backup file counts as made**: the script builds it in `backups/.partial-<STAMP>/` (mode `0700`), reads it back and compares every member with `SHA256SUMS`, puts the checksum file in `backups/`, and only then gives the backup file its final name. A backup file under its final name has therefore been read back once in full. After that the script records it in `state.json` and removes `.partial-<STAMP>/`. What a failure or an interruption (Ctrl-C, a closed terminal, a TERM signal) leaves depends on how far the backup got:

- **Before `.partial-<STAMP>/` exists** (while the checks run, before anything stops): the backup is cancelled. Nothing was stopped or written, there is nothing to delete, and nothing later is held up by it.
- **After `.partial-<STAMP>/` exists, before the backup file has its final name**: there is no backup file, and `state.json` still points at the previous backup. `.partial-<STAMP>/` stays: it cannot be restored from and holds sensitive plaintext, so delete it once you know the cause. A `.sha256` whose backup file is missing comes from the same situation and can be deleted. The screen prints the command to start the services when they may still be stopped.
- **After the backup file has its final name, before `state.json` records it**: the screen says the file is valid and that `state.json` was not updated, so `status` still shows the previous backup; delete `.partial-<STAMP>/` by hand.
- **After `state.json` records it**: only removing `.partial-<STAMP>/` is left. The screen says the file is valid; delete the folder by hand. The backup counts as finished.

When a backup was interrupted in the second or third case, `state.json` still holds it as unfinished: `start`, `stop` and `backup` run as usual and first warn about it, and `upgrade` refuses until a backup has finished; `start` alone does not lift that. The same applies after a power loss or a killed process, which the script cannot catch; `.partial-<STAMP>/` may then be missing, and the warning says only that the last backup did not finish.

#### Deployments with an external database

In the external database shape (`compose.external-database.yml`), `backup` and the backup at step 7 of an upgrade dump the database from the server that `.env` names (`EXTERNAL_DB_HOST`, `EXTERNAL_DB_PORT`, `DB_NAME`, `DB_USER`, `DB_SSLMODE`). The steps, the file, its members and the questions are those above; step 1 stops backend, guacd and frontend and does not touch the database.

- **The export tool.** The release ships PostgreSQL 16, 17 and 18 clients as images pinned in its manifest. In this shape `install`, `upgrade` and `load` obtain them and check them against the manifest; they are tools the script runs, not services, so `status` does not list them as containers. Before anything stops, the script asks the server for its version and then uses only the client of the server's own major version, for the dump and for `snapshot.txt`. A server of any other major version, such as 15 or 19, is refused, even where another client could read it. The manifest records the client in `tool.dump_image` (`pgclient16`, `pgclient17` or `pgclient18`) and its digest, as listed in `tool-MANIFEST.json`.
- **Checked before anything stops**, besides the checks above, each with its own message: that the client images are on this host (if not, load the release's offline image bundle with `load`), that the server can be reached and accepts the sign-in (the reason for a failure is in the log file), that the release has a client of the server's major version, and the settings the items below describe. A refusal stops nothing.
- **What a dump does not carry.** `pg_dump` writes neither roles nor tablespaces, so a database that would need them on a new server is refused, with what was found: a custom tablespace, objects owned by a role other than `DB_USER`, or an extension other than `plpgsql`. The `public` schema owned by the built-in role `pg_database_owner`, as PostgreSQL creates it, is not another owner; the objects in it still have to be owned by `DB_USER`.
- **Privileges granted to other roles** are not refused. When objects grant privileges to roles other than `DB_USER`, `PUBLIC` and the built-in `pg_` roles, a monitoring account for instance, the backup finishes, its final screen warns and names those roles, and the manifest lists them in `db.extra_grant_roles_hex`: each name as the lower-case hex of its UTF-8 bytes, separated by spaces (§5.3 prints them as names). A new database server needs those roles before the restore, or the restored privileges differ.
- **TLS.** The client checks the server exactly as much as the backend does with the same `.env`, never less and never more, and the preview shows the mode and how the server is checked. `DB_SSLMODE` unset or empty means `disable`, as it does for the backend.

  | `DB_SSLMODE` | `PGSSLROOTCERT` | How the server is checked, by the backend and the backup alike |
  |---|---|---|
  | `disable`, `allow`, `prefer`, `require` | not set | Not checked |
  | `verify-ca` | not set | Against the system's trusted certificate authorities, host name not checked; on the backup's side these are the CA file of the client image, and without one the backup is refused |
  | `verify-full` | not set | Against the system's trusted certificate authorities |
  | any | `system` | Against the system's trusted certificate authorities, as `verify-full` |
  | `disable`, `allow`, `prefer` | a file | Not checked; the CA file still goes into the backup |
  | `require`, `verify-ca` | a file | Against the CA file, host name not checked |
  | `verify-full` | a file | Against the CA file |

  The backend and the client image each have their own list of trusted authorities. When the client's list lacks the authority that signed the server's certificate, the connection fails before anything stops; the backup does not fall back to checking less.
- **TLS files.** `PGSSLROOTCERT`, `PGSSLCERT` and `PGSSLKEY` hold paths inside the backend container. The script reads these files on the host through the backend's mounts, so they have to be under `/var/log/custodexa/audit`, `/var/lib/custodexa/recordings` or `/var/lib/custodexa/exports` (`audit`, `recordings` and `exports` under `DATA_PATH`); a file anywhere else is refused. The CA file, which is public, goes into the backup as `db-ca.pem` (`contents.db_ca`). A client certificate is used for the connection and recorded as `db.tls_client_cert` `true`, but **its private key never goes into the backup file**: keep it with the deployment's other secrets, because a restore needs it again. A private key inside the audit or recordings folder, which the backup packs, is refused.
- **The database password** reaches the client in a file of mode `0600` inside a private folder (mode `0700`) under `backups/`: `backups/.partial-<STAMP>/` while the backup's steps run, and `backups/.db-client-<PID>/` for the database checks outside them (before anything stops, and at steps 6 and 12 of an upgrade). The file is removed after each call and on an interruption, and `.db-client-<PID>/` with it. It is on no command line and in no environment variable.
- **No other writer during the backup.** Stopping this host's services does not stop another host from writing to the same database. Do not let a standby host take over the database while the backup runs ([Application Host Standby Takeover](./standby-takeover.md)), or the database and the file locations come from different points in time (§3.1); the preview says so as well.

#### Encrypting the backup file with a passphrase

Choose it at the question, or pass `--passphrase-file <file>`. The passphrase has 12 to 256 characters: letters, digits, spaces and the symbols of a US keyboard (printable ASCII), and spaces count as part of it. At the question it is typed twice and not shown. With `--passphrase-file` it is the first line of the file, and the file has to be a regular file (not a symbolic link) owned by you or root, with no read or write permission for group or others and no extended ACL; otherwise the backup refuses before anything stops and prints the `chown`, `chmod` and `setfacl` commands that fix it. To create such a file without the passphrase reaching the shell history:

```bash
sudo install -m 600 -o root /dev/null /root/cx-pass
sudo bash -c 'IFS= read -r -s p && printf "%s\n" "$p" > /root/cx-pass'
```

The encryption runs in the openssl image that the release manifest pins, checked against it, not with tools on the host. The script obtains that image at install and upgrade in every deployment shape; if it is missing, the backup refuses before anything stops and points at loading the release's offline image bundle. The passphrase reaches openssl on its standard input: it is on no command line, in no environment variable, in no log and not in `state.json`, and the script writes no file that holds it. The unencrypted tar is never written to disk, as it streams straight into openssl; the parts in `backups/.partial-<STAMP>/` are plaintext until the file is made and they are removed.

The scheme is named `cx-enc-1` (`encryption.scheme` in the manifest), and its parameters are fixed:

| Item | Value |
|---|---|
| Cipher | AES-256-CBC, PKCS#7 padding |
| Key and IV | PBKDF2-HMAC-SHA256, 600,000 iterations, giving a 32-byte key and a 16-byte IV |
| Salt | 8 random bytes |
| File layout | ASCII `Salted__` (8 bytes), then the salt (8 bytes), then the ciphertext: the `openssl enc` format |
| Passphrase | The bytes as typed, or as on the first line of the file, without the line ending |

An encrypted backup file has a name ending in `.tar.enc` and starts with `Salted__`. Opening it needs only OpenSSL 1.1.1 or later and tar, with the commands below.

> **If the passphrase is lost, the encrypted backup cannot be restored.** The file holds nothing derived from the passphrase, the script keeps no copy of it, and neither the script nor its developers can recover it. Keep the passphrase apart from the file, and make sure that someone besides you can obtain it.

The encryption keeps the content from whoever gets hold of the file. It does not show who made the file: AES-256-CBC carries no authentication tag, and the checksums detect damage, not a change made by someone who also recomputes them. Keep backup files where only the people who administer the system can write.

**Checking a file and its passphrase.** Do this once soon after a backup, so that a recovery is not the first time the passphrase is used. Read the passphrase without echo; it then reaches openssl on its standard input and appears on no command line.

```bash
FILE=backups/custodexa-backup-1.16.0-YYYYMMDD-HHMMSS.tar.enc   # change to the actual name
IFS= read -r -s -p 'Passphrase: ' CX_PASS; echo
```

Then run the one command that fits the openssl you have; each lists the members. `enc` has `-saltlen` from OpenSSL 3.2 on; 1.1.1, 3.0 and 3.1 do not have it. What `openssl enc -help` lists decides, whatever the version number says. With an OpenSSL whose `openssl enc -help` lists `-saltlen` (3.2 and later):

```bash
printf '%s\n' "$CX_PASS" | openssl enc -d -aes-256-cbc -saltlen 8 -pbkdf2 -md sha256 -iter 600000 -pass stdin -in "${FILE:?}" | tar -tvf -
```

With OpenSSL 1.1.1, 3.0 or 3.1, or any version whose `openssl enc -help` does not list `-saltlen` (the salt is always 8 bytes there):

```bash
printf '%s\n' "$CX_PASS" | openssl enc -d -aes-256-cbc -pbkdf2 -md sha256 -iter 600000 -pass stdin -in "${FILE:?}" | tar -tvf -
```

With the release's openssl image instead of an openssl on the host, from the deployment folder:

```bash
printf '%s\n' "$CX_PASS" | docker run --rm -i --network none \
  --mount "type=bind,src=$(realpath "${FILE:?}"),dst=/backup.tar.enc,readonly" \
  "${CUSTODEXA_IMAGE_OPENSSL:-alpine/openssl:3.5.4}" \
  enc -d -aes-256-cbc -saltlen 8 -pbkdf2 -md sha256 -iter 600000 -pass stdin -in /backup.tar.enc | tar -tvf -
```

Afterwards run `unset CX_PASS`. A wrong passphrase ends with openssl reporting `bad decrypt`, or tar reporting that the input does not look like a tar archive. Do not try other parameters: the ones above are the only ones the scheme uses.

#### The backup an upgrade takes

At step 7 of an upgrade the script writes a backup file like the one `backup` writes: `backups/custodexa-backup-<version>-<STAMP>.tar` with its `.sha256`, where `<version>` is the version before the upgrade. The services are already stopped and are not started again, because the next step changes the version, so of the seven steps above it runs 2, 3, 4, 6 and 7. It asks nothing, and what it holds is fixed:

- The recordings are always in it.
- It is never encrypted (`encryption.enabled` is `false`). Encrypt it, or a copy, before it leaves the host (§3.5).
- It holds `state.json` as it was when the upgrade began (`trigger` is `upgrade`, `contents.state` is `true`); §5.1 puts that record back.
- `.env`, `tls/` when the deployment has one, and the proxy template that `TLS_NGINX_TEMPLATE` names, as in any backup file. When that template cannot be read, or its path has a character the manifest cannot record, the upgrade refuses before anything stops. This check is left out when the upgrade can only take your own backup: `--backup-ref` was given, or the external database cannot be backed up by the script this time.
- With an external database it is made with the release's client, as described above. When that is not possible this time, the upgrade offers your own backup only ([Upgrade SOP](./upgrade-sop.md#upgrading-with-the-management-script)).

`snapshot.txt` is taken first. Besides the member in the file, the script keeps a copy next to the upgrade's log, `logs/upgrade-<STAMP>.before.txt`, and the checks at step 12 compare against that copy. Once the file is made it is the latest backup in `status`, and the upgrade's record names it; the upgrade screens print its full path. A backup that fails leaves no backup file, only `backups/.partial-<STAMP>/` as described above, and the screen prints the command that starts the old version again. Free space is checked at step 1 for this file, recordings included, and the preview's downtime estimate includes building and reading back the file.

An upgrade to a release before 1.16.0 took this backup as a folder, `backups/<STAMP>/` (mode `0700`), with `<STAMP>` also the suffix of the files inside; §5.1 still restores from such a folder:

| File | Content |
|---|---|
| `custodexa-db-<STAMP>.dump` | The database (§3.2 step 2) |
| `custodexa-files-<STAMP>.tar.gz` | `recordings` and `audit` under `DATA_PATH` (step 3); not `exports` (§2) |
| `custodexa-env-<STAMP>.bak` | `.env`, secrets included (step 4) |
| `custodexa-tls-<STAMP>.tar.gz` | `tls/` (step 4); not there when the deployment has no `tls/` (behind your own ingress) |
| `snapshot.txt` | What the database held once the services had stopped (below) |
| `state.json` | The script's record as it was when that upgrade began (§5.1 F) |
| `SHA256SUMS` | Checksums of the files above: in the folder, `sha256sum -c SHA256SUMS` |
| `INCOMPLETE` | Present only when the backup failed. A folder with this file is not a backup to restore from |

Such a folder does not hold the proxy template that `TLS_NGINX_TEMPLATE` names; going back with §5.1 leaves that file where it is.

When you choose your own backup at step 7, the script records it in a folder `backups/<STAMP>/` too: that folder holds `state.json` as it was when the upgrade began and, when the script could take it, `snapshot.txt`, but no data.

**`snapshot.txt`** holds one `key=value` per line: the row counts of `users`, `sessions` and `audit_logs`; one `migration=` line per applied row of `schema_migrations`; the four fingerprints of §6 item 6 (`fp.jwt`, `fp.kek`, `fp.export_signing`, `fp.checkpoint_signing`), computed with the algorithm of the Key Management page; and `usable=true` or `usable=false`. It is `false`, with the reason on the `unusable=` line, when a fingerprint could not be computed or its source is not unique; the checks after an upgrade then leave the keys to a manual comparison on the Key Management page. Taking it needs neither an unseal nor a sign-in. Keep it with the backup: it is the "values recorded before the backup" that §6 compares against.

**Keeping it**: a backup file or folder holds everything §3.5 describes, `.env` in plaintext included unless the file is encrypted, and it sits on the same host as the running `.env`. Copy it elsewhere, encrypted. In modes B and C keep it apart from the KEK material; in mode A the KEK material is inside it, so keep it apart from the passphrase or key that encrypts it. The script never deletes a backup: remove the ones you no longer need yourself, and count `backups/` in the disk planning.

**Not covered by the script**: the no-downtime backup of §3.3.

---

## 4. Disaster recovery prerequisites for encryption keys (read before deployment)

The system protects asset credentials, the bind password for the directory integration, notification channel URLs and secrets, signing private keys, **clipboard audit content**, **object storage credentials**, and other fields with envelope encryption. **Whether they can be decrypted after a database backup is restored depends entirely on whether the KEK (key encryption key) can be recovered.**
**Losing the KEK means none of the fields above can be decrypted**, object storage credentials included: the credentials of every historical storage generation are one of that batch, and if they cannot be decrypted the offsite copies of that generation cannot be retrieved. This is not a new risk surface introduced by the offsite feature; it shares its fate with clipboard content and the directory integration password.

> **Clipboard audit content depends on the KEK just the same**: clipboard content is stored envelope encrypted
> (`clipboard_events.content_enc`), so **losing the key means clipboard audit content cannot be read**, on the same terms as every other envelope-encrypted field such as asset credentials, with no exception for being audit data. The **factual side** of a clipboard event (time, direction, content length, status) is not encrypted and remains readable after a restore, but the **full content** cannot be decrypted without the KEK. Disaster recovery planning has to put clipboard content in the "depends on the KEK" category and must not assume it can still be reviewed without the key.
>
> **Evidence package artifacts contain plaintext**: an evidence package export **decrypts** the clipboard content and packs it, together with the recordings themselves, into a ZIP that lands in the export directory
> (`/var/lib/custodexa/exports` in the container, `${DATA_PATH}/exports` on the host; not a backup target, see §2). This is one of the few places in the system where plaintext secrets exist, and its data exposure surface has to be treated as being on par with the production database: directory and file permissions `0700` and `0600`, downloads bound to the requester in person, and the artifact cleared automatically after 24h. **Never** pull that directory into a general backup or copy it anywhere outside key custody; doing so scatters plaintext secrets into places without equivalent protection.

The KEK has three custody modes, declared by the environment variable `KEK_PROVIDER`. **The disaster recovery prerequisites of the three modes are completely different, and the mode has to be chosen and understood before deployment.**

### 4.1 Mode A: `KEK_PROVIDER=env` (local environment variable)

- **Where the material lives**: `ENCRYPTION_KEY` in `.env`. It is a **32-byte** key and can be written three ways: 32 characters (A-Z a-z 0-9), 64 hexadecimal characters, or base64 that decodes to exactly 32 bytes. **The three forms are the same key**: material from a backup entered in a different form decrypts the same data, so on recovery you do not need to remember which form was used originally.
- **Recovery prerequisite**: `.env` itself must be backed up off the machine. **Restoring only the database, without `ENCRYPTION_KEY`, leaves every envelope-encrypted field undecryptable**, and the service also refuses to start.
- **Custody responsibility**: the deployment's.
- **Note**: this mode has exactly one KEK material key, `ENCRYPTION_KEY`; the system reads no other key name.
- **When `KEK_PROVIDER` is not set or empty**: with `ENCRYPTION_KEY` holding a value, the backend runs in this mode, and everything in this section applies.
- **In a backup file written by `backup` (§3.8)**: `env.bak` is `.env` as it was, `ENCRYPTION_KEY` included, and the manifest records `kek.material_included=true`. An unencrypted file, or an encrypted one once decrypted with its passphrase, therefore brings the key back in a restore; an unencrypted copy that leaks is enough to decrypt every stored credential. Encrypt it with a passphrase or by other means (§3.5). A `.tar.enc` file still needs its original passphrase.

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
- **An ordinary unseal** (an existing deployment, not initialization): the page first checks a local administrator's username and password, and then takes the material. **The one-time code is not checked while the system is sealed**, because its seed is protected by the data key; that step is therefore not two-factor and should not be recorded as one. The material itself is not validated for format (an existing deployment's KEK may predate the current format rules). Repeated failures trigger exponential backoff, and past a threshold a time-limited cooldown; **the cooldown ends on its own and the process never has to be restarted for any reason**. Attempts during the cooldown are refused outright and do not extend it.
- **A convergence worth enabling**: with `SEAL_UNSEAL_BIND_ADDR` set, the unseal endpoint is served by a separate listener on that address, and that listener exposes only the seal-related endpoints (it does not turn into the full business interface after unseal), while the main listener refuses unseal requests outright and points them at the management port. **Failing to bind means refusing to start**, so it does not silently degrade into looking isolated while not being so.
  When trusted proxies (`TRUSTED_PROXIES`) are not configured, the source is determined from the transport-layer peer address only, and per-IP backoff conservatively degrades to global backoff.

### 4.3 Mode C: `KEK_PROVIDER=kms` (delegated to a key custodian)

```
KEK_PROVIDER=kms
KEK_KMS_PROVIDER=aws
```

**Two keys, and no more.** `KEK_KMS_REGION`, `KEK_KMS_KEY_ID`, `KEK_VAULT_ADDR`, `KEK_VAULT_ROLE_ID` and `KEK_VAULT_SECRET_ID` no longer take effect. What used to be in them is now in two different places:

- **The non-secret topology** — the service region, the custodian address, the Transit key name, the role identifier — is set on the key management page and stored in the database, in the `kek_topologies` table. **It is backed up with the database** and needs nothing kept for it separately. The key reference itself is not stored there; it follows the `kek_id` on the key rows, which are in the database too.
- **The credentials** — the AWS access key pair, the contents of the GCP service account key file, the Vault role secret or a directly supplied token — are entered on the unseal page at every unseal, are held only in the memory of that unseal generation, and are erased when the system is sealed. **They are in no backup**, because they are in no file and in no table. Their custody is the deployment's, on the same footing as mode B's material.

**What this changes for recovery.** After a restore, the restored system knows where its custodian is, because that travelled with the database, and does not know how to reach it, because that did not. **The first start after a restore therefore comes up sealed and waits for a person**, who signs in on the unseal page with a local administrator's username and password, checks the custodian shown there against the deployment record, and supplies that provider's credentials. The process does not exit while it waits. Put both the person and the credentials into the recovery plan; a restore rehearsal that stops at "the containers are up" has not rehearsed this mode.

- **Recovery prerequisite**: the key still exists at the custodian and is still usable, the account or project that holds it is still open, and credentials with permission to use it can still be obtained. A key scheduled for deletion, a closed account, or credentials that can never be obtained again amounts to losing the material. Revoked credentials are recoverable in a way a deleted key is not: the issuer can issue another set.
- **Permissions needed on the AWS path**: `kms:Encrypt`, `kms:Decrypt`, `kms:DescribeKey`; if native re-encryption is used, also the two actions `kms:ReEncryptFrom` and `kms:ReEncryptTo`. Construction runs one throwaway encrypt and decrypt round trip besides `DescribeKey`, so a missing permission surfaces while unsealing rather than at first use.
- **Credentials are injected explicitly and are never discovered from the environment.** The AWS SDK default chain (IRSA, instance profile, `AWS_*`, SSO) and GCP Application Default Credentials are no longer used, and construction is refused when no credentials were supplied. A restored environment that relies on an instance role will not come up; supply the credentials on the unseal page.
- **A directly supplied Vault token** is accepted instead of an AppRole login, with the same lifecycle: it is erased on seal and fails closed when it expires. A long-lived token is not a recommended practice, because its exposure window equals its lifetime and this product cannot rotate it.
- **Trust boundary**: the `kek_id` on the key rows is also the only source of the trusted account scope, and the target key of a delegated rewrap must be in the same AWS account and partition as it, or it is refused.
- **Changing the topology is a security change.** The address decides where the wrapped data keys are sent to be unwrapped, and where the plaintext key material goes during a rewrap. Only the authenticated key management page can change it; every change, accepted or refused, is written to the audit log with its before and after values, and an accepted one raises a security alert through the configured notification channels (with none configured, the audit row is the only record). **This does not stop anyone who can write to the database directly**, and the check on the unseal page is a step for a person to perform, not a guarantee the system enforces; the defence on that path is database access control and the off-box copy of the audit log.
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

From 1.16.0, a package deployment restores a single backup file (§3.8) with the management script: `sudo ./custodexa.sh restore <backup file>` in the deployment folder, or **Restore from a backup file** in the menu (**Restore a backup file onto this new host** on a host not yet installed). It checks the file, installs the backup's version when needed, keeps the data it replaces, and counts the restore as finished only once the data, the version and the master key have been checked. "Restoring with `restore`" below describes it for a deployment with the bundled database, and "Restoring a deployment with an external database" after it gives what differs when the database is on a server outside the deployment.

Restore by hand, with "Restoring by hand" below, in the cases the script refuses. It refuses them before it stops a service or downloads anything, and the screen names the case:

- **A backup that is not a single backup file**: the files of §3.2, or a folder `backups/<STAMP>/` from an upgrade to a release before 1.16.0 (§3.8). Such a backup has no `backup-manifest.json`. Restore it by hand on the host that made it, or upgrade that host to 1.16.0 or later and back up again.
- **A backup file whose data belongs to a version before 1.16.0** (`product.version`): the backup an upgrade takes of a deployment of 1.13 to 1.15. Those versions do not report the master key ID after unsealing, so the script cannot confirm the master key after a restore. Take its files out with §5.2, then go on with §5.1 to go back to that version on this host, or with the steps below to restore onto another host.
- **A backup file without a master key fingerprint** (`kek.fingerprint_status` is not `ok`, because a single value could not be read when it was made). Restore it by hand and compare the key inventory as §6 item 6 describes.
- **A backup file whose master key mode is `hsm`**: this release has no working HSM implementation.
- **A bundled database that grants privileges to roles other than `DB_USER`**, `PUBLIC` and the built-in `pg_` roles: the new database has only `DB_USER`. The refusal names the roles.

A deployment that was not installed from the release package has no management script and restores by hand as well.

#### Restoring with `restore`

**Which restore it is** depends on the host, not on the file:

| Host | What `restore` does |
|---|---|
| Installed (`status` shows a version) | Replaces the data on this host. It backs up the current data first (the safety backup, below). A backup made on another host is restored the same way, and the preview warns that it comes from another host |
| Not yet installed | Installs the backup's version, then restores into it. The host has to be empty: no `postgres` or `audit` under the chosen `DATA_PATH`, or only empty folders. Files already in `recordings` are allowed and left as they are |

Without a terminal, give `--same-host` (installed host) or `--new-host` (host not yet installed), matching the host, and `--yes`; on an installed host also `--confirm-data-loss`. A deployment older than 1.16.0 has no `restore`: upgrade it to 1.16.0 or later first.

**On a new host**, first put a release package there with `get-custodexa.sh`, of the backup's version or any later one, and run `restore` with the `custodexa.sh` it placed. The script has to be no older than the backup's version. When it is newer, the script puts the backup's version under `releases/<version>/`, and the deployment runs that version after the restore. Offline, also bring the package of the backup's version with its `SHA256SUMS` (`--package`) and the offline image bundle of that version (`--images`); for an encrypted backup file, the offline image bundle of the script's own release as well, since the decryption runs in its openssl image. When the two versions are the same, one package and one image bundle are enough. The preview lists what is missing.

**What is checked before anything stops.** A refusal at this point changes nothing.

- The copy is whole: the `.sha256` file next to it has to report OK. Without one, the script asks for a confirmation at the terminal, or needs `--no-checksum-file`; the checksums inside the file are checked either way.
- An encrypted file (`.tar.enc`): the passphrase is asked once, with three tries in all, or read from `--passphrase-file`, which follows the rules of `backup` (§3.8).
- The members, their checksums and the manifest, as §3.8 describes them.
- The data version and the master key, as listed above. In mode A, the master key in the backup's `.env` has to have the fingerprint `kek.fingerprint`. When `snapshot.txt` holds `fp.jwt`, the sign-in token key `JWT_SECRET` in the backup's `.env` has to match it. The backup's `.env` has to hold real values for `JWT_SECRET` and `DB_PASSWORD`, and in mode A for `ENCRYPTION_KEY`; the script does not make up new ones.
- The data has no data structure change that the backup's version does not know. One that it does not know means a newer version changed the data, and the script does not put newer data into an older version.
- The backup's version: when it is already on this host, its release manifest has to be identical to `release-MANIFEST.json` in the backup. Otherwise the package comes from `--package` (with `SHA256SUMS` in the same folder) or is downloaded. Its checksum has to match, and the publisher signature is checked as in an upgrade: a missing `cosign`, a missing signature or a signature that does not match gives a warning. A version without release files is refused; the script never installs another version in its place.
- The images of that version, from this host, `--images` or the registry, and the free space for the working folder, the safety backup and the restored data.

Then the preview says what is restored, what is replaced and kept, the downtime and the space, and what the master key needs. On an installed host, confirm by typing the version after the restore; on a new host, answer `y`.

**Host values.** `DATA_PATH`, `TLS_DOMAIN`, `TLS_IP_SAN` and `PUBLIC_BASE_URL` describe the host; every other value in `.env` comes from the backup, secrets included.

- On an installed host, the four keep this host's current values, and the preview lists those that differ from the backup.
- On a new host, the script asks for each, showing the backup's value and a value for this host: Enter takes the value for this host, `-` keeps the backup's. Without a terminal, `--data-path`, `--tls-domain`, `--tls-ip-san` and `--public-base-url` give them, and those not given take the value for this host. Behind your own ingress (no `tls/` in the backup), `TLS_DOMAIN` and `TLS_IP_SAN` are not asked.
- With a self-signed certificate and a different name or address, the restored certificate authority is kept and a server certificate for the new values is issued at startup; the previous server certificate is moved aside inside `tls/`. Clients that trust that certificate authority keep trusting it. A certificate you provided is not changed: the preview and the final screen warn when it does not cover the new name or address.
- When `PUBLIC_BASE_URL` changes, the final screen reminds you to update the callback address at the identity provider of an external sign-in (OIDC).
- The proxy template that `TLS_NGINX_TEMPLATE` names (when the backup holds one) goes back to its path. On a new host, when that path cannot be used there (its parent folder is missing, it is a symbolic link, or it is under `releases/` or `current/`), the script asks for another absolute path, or takes `--nginx-template <path>`, and points `.env` at it. A different file already at the destination is renamed `<name>.before-restore-<STAMP>` and kept.

**The safety backup** (installed host). Before anything is overwritten, the script backs up the current data into `backups/custodexa-backup-<version>-<STAMP>.tar`: database, audit files, settings and certificates, without recordings and not encrypted. The services are stopped for it and not started again, and the database keeps running. The script then reads the file back and checks it as it would check a backup to restore, and goes on only when it passes. It also copies `state.json` and `.env` as they were into the working folder.

Instead, you can use your own backup taken after the services stop, a storage snapshot for example: choose it at the question, or give `--backup-ref`, `--backup-time` and `--backup-restore` (as for an upgrade, [Upgrade SOP](./upgrade-sop.md#upgrading-with-the-management-script)); `--backup-time` cannot be earlier than the moment the services stopped. When a safety backup made by the script could not later be restored by `restore --revert`, only your own backup is offered, and the screen says why: for example when a single master key ID cannot be read from the current database, or the images of the current version are no longer on this host.

**What is replaced and what is kept.**

- The current `postgres` and `audit` under `DATA_PATH`, and `tls/` in the deployment folder, are renamed `*.before-restore-<STAMP>` and kept. They are not deleted: remove them yourself once section 6 has passed.
- Recordings: when the backup has none, the `recordings` folder is not touched. On an installed host the recordings may then not match the backup's point in time: recordings made after the backup stay on disk but are no longer listed, and recordings cleared after the backup do not come back. On a new host, the final screen gives the number of recordings the restored database knows about whose file is not on this host, and the list is in `missing-recordings.txt` in the working folder; copy them over from `recordings` under the source host's `DATA_PATH`. A recording already uploaded to offsite storage is fetched from there when played. When the backup has recordings, they are put back, and a file already there with the same name is kept, not overwritten.
- The version goes back with the data: on an installed host the version after the restore is the backup's, even when the host runs a newer one.

**The steps.** On an installed host there are ten: put the backup's version and its images in place; stop the services (the database keeps running); the safety backup; check that it can be restored; stop the database and rename the current data; import the database; check the database; put back the audit files, certificates and settings; start the services and wait until ready; check the master key. On a new host there are eight, without the safety backup and with the settings file written from the backup. The database check compares the imported migrations, the row counts of `users`, `sessions` and `audit_logs`, and the master key ID with what the backup recorded. After startup, the script checks that the running images are the recorded ones and that the backend reports the backup's version; it waits up to 180 seconds for the backend to be ready.

**The master key and when the restore counts as finished.**

- **Mode A**: the backend unseals itself with the key in `.env`. The script reads the master key ID the backend reports after unsealing and compares it with `kek.fingerprint`. When they match, the restore is finished.
- **Modes B and C**: the script starts the services and ends with exit code 4: the data is imported and the system waits for the unseal. Someone signs in on the unseal page with an administrator account from the backup and enters the master key (mode B), or checks the custodian shown there, which came back with the database, and supplies the custodian credentials again (mode C; this host's address has to be among the sources the custodian accepts). Then run `restore --resume`: it reads the master key ID and finishes. While the system is still sealed it says so, changes nothing, and ends with exit code 4 again.
- Until the master key has been checked, the restore is not finished: `upgrade` and `backup` refuse to run.
- **When the ID does not match**, the script stops the services and the restore is not finished. Check the key inventory as §6 item 6 describes, then either carry on (in mode A the key in `.env` is checked again first, and the services are not started while it still does not match; in modes B and C the services start again and the check runs once someone unseals with the right key), or go back or give up as described below.

**When it has finished**, the final screen gives the backup it came from, the folders kept and the safety backup, the address, the master key check, the recordings and any warning, and points to section 6, which is still to be done (below). The working folder under `restore/` in the deployment folder (mode `0700`) loses its plaintext copies of the database, `.env` and the archives; it keeps the list of missing recordings and the copies of `state.json` and `.env` from before the restore (`state-before.json`, `env-before-restore`, mode `0600`, secrets included). At a terminal the script then looks up the latest version as the menu does and asks whether to upgrade, no by default; without a terminal it prints the commands only. When the backup was the one an upgrade took (`trigger` is `upgrade`), it neither looks up nor asks: it says the deployment is back on the version from before the upgrade and prints the upgrade command.

#### When `restore` stops partway

A failure or an interruption (Ctrl-C, a closed terminal, a TERM signal) stops the restore where it is, and nothing is undone automatically. The services stay stopped, the data that was renamed stays kept, and the working folder and the record of the restore remain. The screen prints two commands, with the full path of the script that started the restore; on a new host whose script is newer than the backup's version that is `releases/<script version>/custodexa.sh`, so use the path as printed.

- `restore --resume` carries on from the step that did not finish.
- On an installed host, `restore --revert` goes back. When nothing has been overwritten yet, it clears the record of the restore and starts the original services, and counts as done once they are ready. Once overwriting has begun, it restores the safety backup with the same steps, without taking another safety backup; the data this restore had put in place is renamed `*.partial-restore-<STAMP>` and kept. With your own backup instead of the safety backup, it prints the restore procedure you registered.
- On a new host, `restore --abandon` gives up. It stops the services the restore started, renames what it put in place (`postgres`, `audit`, `tls/` and `.env`) to `*.abandoned-<STAMP>`, points `current` back to the script's version and keeps `releases/<version>/`, and deletes the plaintext in the working folder. It does not touch the `recordings` folder, which may hold files you copied there yourself. The host is then not installed again.

When the safety backup did not finish, nothing has been overwritten: carry on to take it again, carry on with your own backup (choose it at the terminal, or add `--backup-ref`, `--backup-time` and `--backup-restore` to `restore --resume`; the time cannot be earlier than the moment this restore stopped the services), or go back. A going back or giving up that is itself interrupted continues when the same command is run again.

`--revert` handles only an unfinished restore. To get the data from before a finished restore back, restore its safety backup file with `restore`: that is a new restore, and it takes a safety backup of the current data first.

When the script cannot tell whether one of its own changes to the deployment took place (a folder rename, a file it put in place), it names that change and the paths involved, changes nothing, and stops. Look at those paths before changing anything: the data kept as `*.before-restore-<STAMP>` and the safety backup are not affected. When you cannot tell which copy is which, restore by hand from the backup file with "Restoring by hand" below. When the working folder has been lost after overwriting began, `restore --resume` refuses, and `restore --revert` or `restore --abandon` remain.

While a restore has not finished, `status` shows it in a Restore section with the command to carry on, and the menu offers only carrying on, going back or giving up, the status, starting and stopping the services, and help. `status`, `load` and `stop` run as usual. `start` runs only once the restore has started the services itself (waiting for the unseal, or not ready in time). `backup`, `upgrade`, `install` and another `restore` refuse and print the commands to carry on, go back or give up.

#### Restoring a deployment with an external database

When the backup's manifest has `db.location` `external` (§3.8), `restore` empties the database on that server and imports the backup into it, with the steps above and the differences below.

**Before you start.**

- On a new host, stop the services on the original host first, and make sure no standby host has taken the database over ([Application Host Standby Takeover](./standby-takeover.md)). Keep it that way until the restore has finished: the script checks for other connections at the points below, and nobody else may start the original host or a standby host in between.
- The database server needs free space for about twice the size of the database, because the old and the new data are both on it until the import is committed. The preview gives the figure with a warning; the script cannot see the server's disk, so check it first.
- While the import runs, the working folder also holds the SQL text of the import, about the size of the database uncompressed. On a new host whose database already holds data, it also holds the safety export (below). Plan the free space of the deployment folder for both.
- The connection is the backup's: `EXTERNAL_DB_HOST`, `EXTERNAL_DB_PORT`, `DB_NAME`, `DB_USER`, `DB_PASSWORD`, `DB_SSLMODE` and the paths in `PGSSLROOTCERT`, `PGSSLCERT` and `PGSSLKEY` come from the backup's `.env` on either kind of host. A new host asks only for the four host values. To move to another database server or another database, restore by hand with §5.3, where the connection in `.env` is set to fit the new server.

**What is checked before anything stops**, with the backup's connection and the release's PostgreSQL client of the server's major version. A refusal gives every reason found, ends with exit code 3, and changes nothing.

- The server runs PostgreSQL 16, 17 or 18, the major versions this release carries a client for, and the client image of that version is on this host (if not, load the release's offline image bundle with `load`). The server's major version is not lower than that of the server the backup was taken from, and the client's is not lower than that of the tool that made the dump.
- The client connects and signs in, and the server certificate is checked exactly as much as when the backup was taken (the TLS table in §3.8), never less.
- `DB_USER` owns the database `DB_NAME`, because rebuilding the `public` schema needs the owner of the database, and owns every object in its schemas other than the system ones. The `public` schema itself may keep the owner PostgreSQL gives it, `pg_database_owner`. The refusal lists the objects with their owners.
- The database has no extension other than `plpgsql`.
- Its encoding, collation and character type are the backup's (`db.encoding`, `db.collate`, `db.ctype`). Otherwise the screen prints the settings, and the database administrator creates the database with them: the script creates neither databases nor roles.
- No other connection uses the database. On a new host this is strict: the refusal lists the source addresses, the application names and the number of connections. On an installed host its own backend is still connected at this point, so the preview only lists the connections; the strict check comes once the services have stopped (below).
- The roles the backup grants privileges to exist on the server (below).
- Whether the database is empty: no object in a schema other than the system ones.

**Roles the server lacks.** The roles come from `db.extra_grant_roles_hex` and from the grants in the dump, apart from `DB_USER`, `PUBLIC` and the built-in `pg_` roles. At a terminal the script names the missing roles and offers two choices: `[1]` create these roles first (the default; the restore ends and nothing has been changed), or `[2]` skip the grants to these roles and go on, which leaves out only those grants and restores everything else. Without a terminal it refuses unless `--accept-grant-loss` is given. Skipping needs each grant statement to concern either missing roles only or none of them; when a statement cannot be told apart that way, the script asks for the roles to be created first and changes nothing. The preview says which grants are skipped, and the final screen gives their number and the list, `skipped-grants.txt` in the working folder.

**The CA file and the client certificate.** The CA file from the backup (`db-ca.pem`) is put at the path `PGSSLROOTCERT` names, under `DATA_PATH` (the TLS files in §3.8); a file with other content already there is refused. When the backup's connection used a client certificate (`db.tls_client_cert` is `true`), give the certificate and its private key with `--db-client-cert` and `--db-client-key`, or type the two paths when the terminal asks for them; files already at the paths `PGSSLCERT` and `PGSSLKEY` name on this host are used as they are, and a file with other content there is refused. The private key is not in the backup file (§3.8), so keep it with the deployment's other secrets. After the confirmation the files are copied to those paths with mode `0600`; the private key goes there directly, never through the working folder or into the log.

**What is emptied.** Every object in the schemas of `DB_NAME` other than the system ones (`pg_catalog`, `information_schema` and PostgreSQL's toast and temporary schemas). The `public` schema is dropped and created again as PostgreSQL 15 and later create it: owned by `pg_database_owner`, with `USAGE` for `PUBLIC`. Other databases, roles and tablespaces are not touched. The preview gives the server, the database and its PostgreSQL version, the client used, how the server is checked, and the number of objects in each schema that is emptied. An empty database needs no emptying, and the preview says so.

**One transaction.** The script first writes the SQL of the import to files in the working folder and checks that each one is complete. Only then does it send the emptying and the import to the server as a single transaction. When the transaction fails, all of it is rolled back and the database stays as it was.

**Confirmation.** When the database is not empty, the confirmation is to type its name, in place of the version on an installed host or `y` on a new host. Without a terminal, give `--yes` and `--confirm-data-loss` on either kind of host.

**On an installed host** the safety backup holds the external database as well: the script exports it with the client of the server's major version into the same backup file. There is no `postgres` folder to rename: the database is emptied and imported in place, and what it held before is in the safety backup. Other connections are checked strictly at three points: once the services have stopped (step 2, "Stop the services (the external database is not affected)"), before anything here is renamed (step 5, "Make sure no other connection is open"), and right before the transaction (step 6, "Empty and import the database (one transaction)"). When one is found, the step fails with its source and application name, the services stay stopped, and the external database has not been changed. Find and end that connection, making sure it is not a standby host taking over, then run `restore --resume`, or go back with `restore --revert`. Once overwriting has begun, `restore --revert` restores the safety backup as described above, and its database goes back in one transaction as well.

**On a new host** the safety backup depends on the database:

- **Empty**: the preview says no safety backup is needed, and none is made. Eight steps, as above.
- **Not empty**: its content is the only copy of that data. After the settings are written, step 3 checks again that no other connection is open and exports the database with the client of the server's major version to `safety-db.dump` in the working folder. The export is read back in full, and the database is measured before and after it; when the two measurements differ, something wrote to the database during the export, and the export is not used. Only a complete, unchanged export lets the restore go on. Nine steps.

**When the import stops partway.** When the server reported an error, the transaction was rolled back and the external database is as it was. When the result cannot be known (the import was killed, or the connection was lost), `restore --resume` measures the database first: unchanged means nothing was committed, and the import runs again; the checks of the database step all passing means it was committed, and the restore goes on. When it is neither, the script stops, shows both measurements, and does not import again. Then follow the commands on the screen: go back with the safety backup or the safety export, or, on a new host whose database was empty, have the database administrator look at the database.

**Going back or giving up on a new host.**

- **The database was not empty**: `restore --revert` asks for a confirmation (or takes `--yes`), stops the services, puts the safety export back into the external database in one transaction, and finishes only once the database measures as it did at the export; the host then returns to not installed, as `--abandon` leaves it. When putting the export back fails, `safety-db.dump` is kept and the same command can be run again. Once the emptying and import have been sent to the server, `restore --abandon` is refused with exit code 3 and prints `restore --revert`. Before that point the external database has not been touched and giving up is allowed; `safety-db.dump` is kept and the screen gives its path, for you to delete once it is not needed.
- **The database was empty**: `restore --abandon` does not empty it. The data this restore imported stays in the database, and the screen says so; have the database administrator empty it if needed. A later restore treats that database as not empty and exports it first.

The script deletes `safety-db.dump` only when `restore --revert` has finished. In every other case it stays in the working folder, including after a restore that finished, and holds the database in plaintext: delete it yourself once section 6 has passed.

#### Restoring by hand

**Going back after an upgrade by the management script** (its screens point here): read §5.1 first. It says what to do before and after the steps below, and how to fill them in from a folder under `backups/`.

**Restoring from a single backup file** (`custodexa-backup-<version>-<STAMP>.tar` or `.tar.enc`, written by `backup` or by an upgrade, §3.8): take its files out with §5.2 first. §5.2 sets `STAMP` and `BACKUP_DIR` for the steps below. When its database was external (`db.location` is `external`), §5.3 takes the place of step 5.

**One point where the order differs from §3.2**: `.env` is restored first, and the variables are obtained after. The reason is in the note on step 2.

Below, `STAMP` carries the timestamp of the set of backup files to restore (the file name suffix produced in §3.2). **Set it to the actual value before running anything**:

```bash
# 0. The target environment has to be prepared first: code and images of the same version as the backup, and the corresponding KEK (see section 4)
#    If the versions differ, check the compatibility statement in the upgrade SOP first.
#
#    The timestamp of the set of backup files to restore. **The value on the line below must be changed to the actual file name suffix**;
#    if you forget, the three commands after it fail because the files do not exist (they will not restore the wrong thing).
#    A backup folder of the management script uses YYYYMMDD-HHMMSS, the name of the folder under backups/ (§3.8).
#    For a single backup file, §5.2 has already set STAMP and BACKUP_DIR: skip the two assignments below.
STAMP=YYYYMMDD-HHMM
#    The folder that holds the backup files: . when they are in this directory, backups/<STAMP> for a script backup folder
BACKUP_DIR=.

# 1. Stop all services. ${DATA_PATH}/postgres in the target environment must be an empty directory
#    (the postgres container only initializes a clean database when the data directory is empty).
#    Left as it is, postgres keeps the database it holds and skips the initialization. On another host that database
#    has the password (and user) of that host's install, which the restored .env does not match, so the backend
#    cannot sign in to the database; on the same host, objects the backup does not hold stay in the database.
#    Confirm this machine is the one meant for the restore. The lines below move the current database aside
#    instead of deleting it; delete postgres.before-restore-<STAMP> once section 6 has passed.
docker compose --project-directory . down
DATA_NOW="$(sed -n 's/^[[:space:]]*DATA_PATH=//p' "${ENV_FILE:-./.env}" | tail -n 1)"
( cd "${DATA_NOW:?DATA_PATH not found in .env; do not go on}" && pwd )
[ ! -d "${DATA_NOW:?}/postgres" ] || mv "${DATA_NOW:?}/postgres" "${DATA_NOW:?}/postgres.before-restore-${STAMP:?}"
mkdir -m 700 "${DATA_NOW:?}/postgres"

# 2. Restore the deployment-layer settings first (required for KEK mode A; mode B contains no material, mode C contains no KMS credentials).
#    This comes before obtaining the values because it overwrites .env entirely. If you obtained the values first and overwrote afterwards,
#    the DATA_PATH, DB_USER, and DB_NAME you hold would be the old pre-overwrite values, inconsistent with what the service actually uses.
ENV_FILE="${ENV_FILE:-./.env}"
cp "${BACKUP_DIR:?}/custodexa-env-${STAMP}.bak" "$ENV_FILE"
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
#    Extract as root (sudo). Extracted by any other account, the per-day recording directories, the text recordings
#    and the audit files end up owned by that account, and the preparation command below does not change them back.
#    A backup folder has one archive for recordings and audit. A single backup file (§5.2) has audit.tar.gz,
#    and recordings.tar.gz only when the recordings were put in it.
if [ -e "${BACKUP_DIR:?}/custodexa-files-${STAMP}.tar.gz" ]; then
  tar -xzf "${BACKUP_DIR:?}/custodexa-files-${STAMP}.tar.gz" \
    -C "${DATA_PATH:?DATA_PATH not obtained, run step 3 first; do not continue with a default}"
else
  tar -xzf "${BACKUP_DIR:?}/audit.tar.gz" \
    -C "${DATA_PATH:?DATA_PATH not obtained, run step 3 first; do not continue with a default}"
  if [ -e "${BACKUP_DIR:?}/recordings.tar.gz" ]; then
    tar -xzf "${BACKUP_DIR:?}/recordings.tar.gz" -C "${DATA_PATH:?}"
  fi
fi
#    Set the recordings directory back to 1000:0 2770 (§3.6); safe to run even when extraction already kept it
docker run --rm --network none -v "$(cd "${DATA_PATH:?}" && pwd)/recordings:/r" --entrypoint /bin/sh "${CUSTODEXA_IMAGE_OPENSSL:-alpine/openssl:3.5.4}" -c \
  'chown 1000:0 /r && chmod 2770 /r && find /r -mindepth 1 -maxdepth 1 -type f -group 1000 -exec chgrp 0 {} +'
#    Restore the TLS certificate directory into the project directory (without it, self-signed mode generates a new CA and certificate at startup,
#    and the CA has to be distributed to every client machine again). A backup of a deployment behind your own ingress
#    has no tls archive (contents.tls is false in its manifest), and there is nothing to restore.
if [ -e "${BACKUP_DIR:?}/custodexa-tls-${STAMP}.tar.gz" ]; then
  tar -xzf "${BACKUP_DIR:?}/custodexa-tls-${STAMP}.tar.gz"
fi
#    The proxy template that TLS_NGINX_TEMPLATE in .env names, when the backup file holds one (§3.8): back to that path
if [ -e "${BACKUP_DIR:?}/nginx-tls.conf.template" ]; then
  CX_TPL="$(env_get TLS_NGINX_TEMPLATE)"
  install -D -m 644 "${BACKUP_DIR:?}/nginx-tls.conf.template" "${CX_TPL:?TLS_NGINX_TEMPLATE is not set in .env}"
fi

# 5. Start postgres only, and load the logical backup **after it can really accept connections**.
#    `up -d` only guarantees the container started, not that postgres is ready; and on first startup (empty data directory),
#    the postgres image first runs a temporary server that listens on the unix socket only, to do the initialization.
#    During that period `pg_isready` over the socket reports ready, but the target database **does not exist yet**,
#    and loading the backup then gives `database "..." does not exist`, so the whole restore comes to nothing.
#    So the criterion here is both **TCP** (`-h 127.0.0.1`, not listened on during initialization) and **actually connecting to the target database** holding at the same time.
docker compose --project-directory . up -d postgres
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
  < "${BACKUP_DIR:?}/custodexa-db-${STAMP}.dump"

# 6. Start the remaining services
docker compose --project-directory . up -d
```

A KEK mode B deployment is still sealed after step 6, and only starts serving once the material is entered at `/unseal`. **A mode C deployment is sealed after step 6 as well**: its custodian settings came back with the database, but the credentials were in no backup, so someone signs in at `/unseal`, checks the custodian on screen, and supplies them again (§4.3). Until then every business route answers 503, which is expected rather than a failed restore.

### 5.1 Going back to the previous version after an upgrade by the management script

From 1.16.0, start with the `rollback` command. Before it stops anything, it decides whether it can go straight back to the version before the upgrade. When it can, it switches back only the version and keeps the data. When it cannot, it changes nothing and prints the next step. It never restores a backup by itself.

A failure before the version switch does not require going back. At steps 1 to 7 the screen prints the command for restarting the old version; step 8 is reserved and performs no conversion. Run in that state, `rollback` says the upgrade stopped before the switch and prints the same commands.

#### When `rollback` can go straight back

All four of these have to hold:

- The last version change of this package deployment was an upgrade by the script that reached the switch to the new version (step 9 or later). The upgrade may have finished, failed, or been interrupted after that point.
- The version before the upgrade is 1.16.0 or later.
- The new version has not changed the database. One of three grounds is enough: the new version never started; the database holds the same migrations as the record taken before the upgrade; or the manifest of the new release lists the previous version as one it can go straight back to. A database that cannot be read counts as changed.
- Every image of the previous version is still on this host, with the image ID recorded before the upgrade. The script checks this host only; the table below says how to load a missing image.

When the first two hold, the upgrade screens print the command, for example `Back to 1.16.1   sudo /opt/custodexa/custodexa.sh rollback`. Whether the other two hold is decided by `rollback` itself.

#### Going back with `rollback`

```bash
sudo /opt/custodexa/custodexa.sh rollback
```

It first shows a preview: the installed version, the version it goes back to, why the database counts as unchanged, and the old images it found. Nothing has been changed at that point, and it asks `Start? [y/N]`. Add `--yes` to skip the question in automation. Then it runs four steps:

1. **Stop the services.** As `stop` does, it first waits until the audit records are in the database, then stops every service except the bundled database. When that wait cannot be confirmed, it stops nothing: a new run ends with nothing changed, and a resumed one stays unfinished.
2. **Check the database again and switch back.** With the application services stopped, it decides again whether the new version has changed the database, because the new version could still change it while the preview waited. If the database is still unchanged, it stops the database, points `current` to `releases/<previous version>`, and swaps the script's records of the two versions.
3. **Start the services** with the images of the previous version.
4. **Check** that the backend reports the previous version and that the running images are the ones recorded before the upgrade.

The data, `.env` and the certificates are not touched and no backup is restored, so everything recorded since the upgrade is kept. When the deployment comes up sealed (KEK mode B or C, §4.2 and §4.3), the closing line gives the `/unseal` address. From then on the `custodexa.sh` in the deployment folder is the script of the previous version, and `status` shows that the last upgrade was rolled back. Each run writes its own log file, `logs/rollback-<time>.log`.

#### When `rollback` stops partway

When a step fails or the run is interrupted, the rollback stays unfinished. The screen describes the current state, prints the command for reading the backend log, and then the commands to continue:

```bash
sudo /opt/custodexa/custodexa.sh rollback --resume   # once the cause is fixed, finish going back
sudo /opt/custodexa/custodexa.sh rollback --revert   # or return to the version after the upgrade
```

- `--resume` carries on from the step where the run stopped. Steps whose result is already in place are passed over.
- `--revert` abandons the rollback and returns to the version after the upgrade with the same four steps, without the database check. When the run stopped at step 1, nothing has been switched yet and the screen prints only `--resume`.
- Once a `--revert` has started, the unfinished run is a return to the version after the upgrade. Its screens print only `rollback --resume`, which finishes that return. To go back to the previous version after it completes, run `rollback` again.
- While a rollback is unfinished, `upgrade`, `backup` and `restore` refuse to run and print the same commands. `start`, `stop` and `status` still work.

#### One version back only

`rollback` goes back one version. After a finished rollback, a second `rollback` is refused with "There is no previous version to go back to" and nothing changes. To return to the version after the upgrade, upgrade to it again as usual ([Upgrade SOP](./upgrade-sop.md#upgrading-with-the-management-script)).

#### When `rollback` cannot go straight back

When one of the conditions does not hold, `rollback` ends with exit code 3 before it stops any service, and nothing is changed. The one exception is the second check in step 2: when the new version changed the database while the preview waited, the version is not switched, the application services stay stopped, the bundled database keeps running, and the exit code is 1. That screen also prints `sudo /opt/custodexa/custodexa.sh start` for keeping the new version in service, unless the upgrade itself is still unfinished.

The next step follows what the screen says:

| The screen says | Next step |
|---|---|
| The new version has changed the database, or it could not be read, and it prints a `restore` command | Run that command as printed. It names the backup file the upgrade took, for example `sudo /opt/custodexa/custodexa.sh restore /opt/custodexa/backups/custodexa-backup-1.16.1-<STAMP>.tar`. Everything recorded after that backup is replaced. Once the restore finishes, the failed upgrade no longer stands in the way: `upgrade` runs again as usual. Restoring is described in section 5. |
| The script can only go back to 1.16.0 or later, or it points to the manual restore in section 5 | Go back by hand as below. The screen shows where the backup is. This is the case when the version before the upgrade is older than 1.16.0, or when you chose your own backup at step 7. |
| Images of the previous version are not on this host, or differ from the record | Load the offline image bundle of the previous version with the `load` command it prints, then run `rollback` again. |
| There is no previous version to go back to | There is nothing to go back from: the deployment was not upgraded by the script, the last change was already a rollback, the version record has changed since the upgrade, or the running version does not match the record. Check the state with `status`. |

#### Going back by hand

This procedure restores the backup the upgrade took at its step 7. The upgrade screens name it: a backup file, `backups/custodexa-backup-<version>-<STAMP>.tar`, when the script took it; a folder `backups/<STAMP>/` when the upgrade was to a release before 1.16.0 (§3.8). **Everything recorded after that backup is lost**, which is why the backup was taken with the services stopped.

When you chose your own backup at step 7, restore it with the procedure you recorded for it, in place of A and E below; B, D and F still apply, with `BACKUP_DIR` the folder the script recorded for it.

Work as root in the deployment folder, and fill in the values from the screen:

```bash
sudo -s
cd /opt/custodexa                      # the deployment folder
OLD=1.13.0                             # the version before the upgrade
STAMP=YYYYMMDD-HHMMSS                  # the timestamp in the name of the backup file or folder
BACKUP_DIR="backups/${STAMP}"          # a backup folder; for a backup file, §5.2 sets it in E

# A. A backup folder has to be complete: no INCOMPLETE file, and every checksum OK.
#    A backup file is checked by §5.2 in E; skip this line for it.
test ! -e "${BACKUP_DIR}/INCOMPLETE" && ( cd "${BACKUP_DIR}" && sha256sum -c SHA256SUMS )

# B. Stop and remove the new version's containers (the data in DATA_PATH is not touched)
docker compose --project-directory . down

# C. Keep the database the new version used, instead of emptying it (section 5, step 1).
#    With an external database there is no postgres folder: skip the four lines below, and
#    keep the new version's database on the server as §5.3 says.
DATA_NOW="$(sed -n 's/^[[:space:]]*DATA_PATH=//p' .env | tail -n 1)"
( cd "${DATA_NOW:?}" && pwd )           # look at it: this deployment's data root
mv "${DATA_NOW:?}/postgres" "${DATA_NOW:?}/postgres.before-restore-${STAMP}"
mkdir -m 700 "${DATA_NOW:?}/postgres"
```

**D. Put the previous version's files back in place.** Which commands depends on what ran before the upgrade.

When it was a package deployment, point `current` back to the previous release and load that release's image references into this shell (the script loads them before every compose call; section 5's commands need them too):

```bash
ln -sfn "releases/${OLD}" current.new && mv -Tf current.new current
set -a; . ./current/images.env; set +a
```

**E. For a backup file, take its files out with §5.2** in this shell (leave out its `sudo -s`). Its step G checks that the release `current` now points at is the backup's version, and it sets `STAMP` and `BACKUP_DIR`. **Then, for either kind, run section 5 from step 2 to step 6** in this shell, with `STAMP` and `BACKUP_DIR` as set; not from step 1, because B and C did its work. With an external database, §5.3 takes the place of step 5. `docker compose` then starts the previous package release through `current`. Then go through section 6. Compare item 6 with the fingerprints in `${BACKUP_DIR}/snapshot.txt`, and the counts of `users` and `sessions` with that file too.

**F. Afterwards.** Delete `postgres.before-restore-${STAMP}` (with an external database, the database kept aside on the server) once section 6 has passed and you are sure you will not need the new version's data. The previous version's images have to be on the host, because the script does not delete images; the upgrade preview warned when some were missing.

In a package deployment the script's own record, `state.json`, still describes the newer version and the upgrade: `status` shows that version, and `upgrade` refuses to run and prints the same instructions again. Put back the record as it was before the upgrade, which the upgrade kept in its backup (the `state.json` member that §5.2 took out, or the file in the backup folder): `cp -p "${BACKUP_DIR}/state.json" state.json`. This release has no command that corrects the record otherwise. After that, delete the folder §5.2 made, as §5.2 says: it holds the database, `.env` and the private keys in plaintext.

### 5.2 Taking the files out of a single backup file

From 1.16.0, `restore` takes the files out by itself (§5). The steps below are for restoring by hand, in the cases §5 lists.

A backup file written by `backup` or by an upgrade (§3.8) is unpacked into a folder before section 5. The steps below check it, take its members out, give them the names section 5 uses, load the image references of the installed release, and set `STAMP` and `BACKUP_DIR` for section 5. After them, run section 5 from step 1 in the same shell; step 0 still applies, apart from its two assignments.

| Member | Where it is used |
|---|---|
| `backup-manifest.json` | Step E below: the version for §5 step 0, and the master key mode (section 4) |
| `env.bak` | §5 step 2, renamed to `custodexa-env-<STAMP>.bak` in step F |
| `audit.tar.gz`, `recordings.tar.gz` | §5 step 4, which extracts both when there is no `custodexa-files-<STAMP>.tar.gz` |
| `tls.tar.gz` | §5 step 4, renamed to `custodexa-tls-<STAMP>.tar.gz` in step F; not in the file when the deployment had no `tls/` (`contents.tls` is `false`) |
| `nginx-tls.conf.template` | §5 step 4, put back at the path that `TLS_NGINX_TEMPLATE` in `.env` names; only when that was set (`contents.nginx_template`) |
| `db.dump` | §5 step 5, renamed to `custodexa-db-<STAMP>.dump` in step F |
| `db-ca.pem` | §5.3, with an external database: the CA file `PGSSLROOTCERT` names (`contents.db_ca`) |
| `state.json` | §5.1 F, in the backup an upgrade takes (`contents.state`) |
| `snapshot.txt` | Section 6: the fingerprints for item 6, and the row counts of `users` and `sessions` |
| `release-MANIFEST.json`, `tool-MANIFEST.json`, `SHA256SUMS` | Checking only |

The target is a package deployment of the version in `product.version`; on another host, install that version there first. Work as root **in the deployment folder of the target**, because section 5 runs `docker compose`, writes `.env` and extracts `tls/` there. The backup file and its `.sha256` can be anywhere: give `FILE` as an absolute path.

Each block below runs only when the one before it succeeded, and ends by printing how far it got. **Go on to section 5 only when the last block prints `5.2: ready`.** Anything else means a check, the decryption or a rename failed: stop there, read the error above that line, delete `BACKUP_DIR` (`rm -rf "${BACKUP_DIR:?}"`) and start again from the first block.

```bash
sudo -s
cd /opt/custodexa                                     # the deployment folder of the target
FILE=/path/to/custodexa-backup-1.16.0-YYYYMMDD-HHMMSS.tar   # absolute path; it ends in .tar.enc when encrypted
STAMP=YYYYMMDD-HHMMSS                                 # the timestamp in that name
BACKUP_DIR="$(pwd)/backups/restore-${STAMP}"          # a new folder for the members, as an absolute path
CX_52=start

# A. The copy is whole: the checksum file next to it has to report OK
# B. A new folder that only root can open (mkdir fails if it exists already)
( cd "$(dirname "${FILE:?}")" && sha256sum -c "$(basename "${FILE:?}").sha256" ) \
  && { [ -d backups ] || mkdir -m 700 backups; } \
  && mkdir -m 700 "${BACKUP_DIR:?}" \
  && CX_52=B
echo "5.2: ${CX_52}"
```

C. Take the members out. For an unencrypted file (`.tar`):

```bash
[ "${CX_52}" = B ] && tar -xf "${FILE:?}" -C "${BACKUP_DIR:?}" && CX_52=C
echo "5.2: ${CX_52}"
```

For an encrypted file (`.tar.enc`), use the openssl command from "Checking a file and its passphrase" in §3.8 that fits your openssl, with `tar -xf - -C "${BACKUP_DIR:?}"` in place of `tar -tvf -`. The exit codes of the whole pipeline are kept before the passphrase is cleared, and only all three at 0 count. With an OpenSSL whose `openssl enc -help` lists `-saltlen` (3.2 and later):

```bash
if [ "${CX_52}" = B ]; then
  IFS= read -r -s -p 'Passphrase: ' CX_PASS; echo
  printf '%s\n' "$CX_PASS" | openssl enc -d -aes-256-cbc -saltlen 8 -pbkdf2 -md sha256 -iter 600000 -pass stdin -in "${FILE:?}" | tar -xf - -C "${BACKUP_DIR:?}"
  CX_RC="${PIPESTATUS[*]}"
  unset CX_PASS
  echo "exit codes (printf openssl tar): ${CX_RC}"
  [ "${CX_RC}" = "0 0 0" ] && CX_52=C
fi
echo "5.2: ${CX_52}"
```

Then, for either kind:

```bash
# D. Every member matches the checksums written when the file was made
# E. What the backup is: the version to restore onto, the master key mode and fingerprint, whether recordings, tls/ and a proxy template are in it, where the database was
# F. The names section 5 uses
# G. The installed release is the backup's version; load its image references for docker compose
[ "${CX_52}" = C ] \
  && ( cd "${BACKUP_DIR:?}" && sha256sum -c SHA256SUMS ) \
  && grep -E '"(product\.version|created_at|kek\.provider|kek\.material_included|kek\.fingerprint|contents\.recordings|contents\.tls|contents\.nginx_template|source\.tls_nginx_template|db\.location)"' \
       "${BACKUP_DIR:?}/backup-manifest.json" \
  && ( cd "${BACKUP_DIR:?}" && mv db.dump "custodexa-db-${STAMP}.dump" \
       && mv env.bak "custodexa-env-${STAMP}.bak" \
       && { [ ! -e tls.tar.gz ] || mv tls.tar.gz "custodexa-tls-${STAMP}.tar.gz"; } ) \
  && CX_VER="$(sed -n 's/^ *"product\.version": "\([^"]*\)".*/\1/p' "${BACKUP_DIR:?}/backup-manifest.json")" \
  && echo "backup ${CX_VER}, installed $(tr -d '[:space:]' < current/VERSION)" \
  && [ "$(tr -d '[:space:]' < current/VERSION)" = "${CX_VER:?}" ] \
  && set -a && . ./current/images.env && set +a \
  && CX_52=ready
echo "5.2: ${CX_52}"
```

Step G loads `current/images.env`, the image references the installed release recorded at install, into this shell, as the script does before every `docker compose` call; section 5 runs `docker compose` itself, so without them it may not find the images that are on the host. When the two versions printed differ, install the backup's version first.

Before going on to section 5:

- **Master key**: with `kek.provider` `env`, the key comes back with `.env` in §5 step 2. With `ui` or `kms`, the backup file does not contain it: have the unseal material or the custodian credentials ready. Either way, section 6 item 6 compares the master key after the restore with `kek.fingerprint`, which is the same value as `fp.kek` in `snapshot.txt`.
- **Another host**: `.env` from the backup describes the host that made it. Right after §5 step 2, before going on, set the four values that describe a host to this host's: `DATA_PATH` (the note in step 2), `TLS_DOMAIN`, `TLS_IP_SAN` and `PUBLIC_BASE_URL`. The manifest's `source.data_path`, `source.tls_domain`, `source.tls_ip_san` and `source.public_base_url` hold the source host's values for comparison. When the backup holds a proxy template, `TLS_NGINX_TEMPLATE` names where §5 step 4 puts it: change it as well if that path does not suit this host (`source.tls_nginx_template` holds the source host's value).
- **Certificates for a new name or address**: changing those values does not change the certificate restored in §5 step 4. The built-in TLS proxy keeps using `tls/fullchain.pem` and `tls/privkey.pem` as long as both exist. When the name or address differs, prepare a matching certificate after step 4 and before step 6. With `TLS_MODE=selfsigned`, delete those two files and keep `tls/ca-private/` and `tls/ca-public/`: at step 6 a new server certificate is issued from the restored CA for the values now in `.env`, and clients that already trust that CA keep trusting it. With `TLS_MODE=provided`, put a certificate chain and key that match the new name and address in those two files. Behind your own ingress, the certificate is the ingress's.
- **External database**: when step E printed `"db.location": "external"`, section 5 step 5 does not apply; §5.3 loads the database in its place.
- **Afterwards**: `BACKUP_DIR` holds the database, `.env` and the private keys in plaintext. Delete it once section 6 has passed.

### 5.3 Loading the database of a deployment with an external database

From 1.16.0, `restore` loads such a database by itself ("Restoring a deployment with an external database" in section 5). The load below is for restoring by hand, in the cases section 5 lists, and for moving to another database server or another database.

A backup file whose manifest has `db.location` `external` holds a dump of a database on a server outside the deployment (§3.8). For it, section 5 step 5, which starts and loads the bundled database, is replaced by the load below; then go on with step 6. In this shape step 1 only stops the services: the `postgres` folder it prepares is not used.

Before the load, whoever runs the database server prepares it:

- **The version**: PostgreSQL of the major version in `db.server_major`. The dump is loaded with `pg_restore` of that same major version, which the release's client image of that version has (the second block below uses it).
- **The database**: an empty database named `DB_NAME`, owned by `DB_USER` with the password in `.env`, created with the encoding, collation and character type in `db.encoding`, `db.collate` and `db.ctype`. To keep the database it replaces (the new version's, when going back after an upgrade), rename that one instead of dropping it, and drop it once section 6 has passed.
- **The roles** the first block below lists from `db.extra_grant_roles_hex`, created before the load. Without them `pg_restore` reports an error for their grants and ends with exit code 1, and those privileges are missing; the backend itself connects only as `DB_USER`. The dump needs no other role, tablespace or extension: the backup refused those before it ran (§3.8).

On the deployment side, after section 5 step 4:

- **Another server**: `.env` from the backup names the source's server. When the database goes to another one, set `EXTERNAL_DB_HOST`, `EXTERNAL_DB_PORT`, `DB_SSLMODE` and `PGSSLROOTCERT` in `.env` to fit it, right after section 5 step 2. The manifest's `db.external_host`, `db.external_port` and `db.sslmode` hold the source's values.
- **The CA file**: when `PGSSLROOTCERT` in `.env` names a file, the backend reads it at that path. A path under `/var/log/custodexa/audit` or `/var/lib/custodexa/recordings` came back with section 5 step 4 when those were in the backup; a path under `/var/lib/custodexa/exports` did not, since no backup holds `exports` (§2). Put `db-ca.pem` from `BACKUP_DIR` there, under `DATA_PATH`, when the file is missing.
- **A client certificate** (`db.tls_client_cert` is `true`): its private key is not in the backup file. Put the certificate and the key back where `PGSSLCERT` and `PGSSLKEY` name, and to load with them, mount both into the container below and add `sslcert=` and `sslkey=` to `CX_CONN`.

First, what the database in the backup needs:

```bash
# What the database in this backup needs (BACKUP_DIR as §5.2 set it)
grep -E '"(db\.location|db\.server_version|db\.server_major|db\.name|db\.user|db\.encoding|db\.collate|db\.ctype|db\.external_host|db\.external_port|db\.sslmode|db\.tls_trust|db\.tls_verify|db\.tls_client_cert|contents\.db_ca|tool\.dump_image)"' \
  "${BACKUP_DIR:?}/backup-manifest.json"
# The other roles that hold privileges, one name per line (none printed when there are none)
for h in $(sed -n 's/^ *"db\.extra_grant_roles_hex": "\([0-9a-f ]*\)".*/\1/p' "${BACKUP_DIR:?}/backup-manifest.json"); do
  printf '%b\n' "$(printf '%s' "$h" | sed 's/../\\x&/g')"
done
```

Then the load, from the deployment folder, in the shell of section 5 (`env_get`, `DB_USER`, `DB_NAME`, `STAMP` and `BACKUP_DIR` as set there). It runs the release's client of the server's major version, which the install of this shape obtained, and connects from `.env` the way the backup did: the table in §3.8, with `db-ca.pem` from the backup as the CA file. Only exit code 0 counts; anything else means the database is not complete, so do not go on to step 6.

```bash
# The release's client of the server's major version, by the image ID recorded at install or upgrade
CX_MAJOR="$(sed -n 's/^ *"db\.server_major": "\([0-9]*\)".*/\1/p' "${BACKUP_DIR:?}/backup-manifest.json")"
CX_PGIMG="$(sed -n 's/^ *"current\.tool_image_ids": "\([^"]*\)".*/\1/p' state.json | tr ' ' '\n' | sed -n "s/^pgclient${CX_MAJOR:?}=//p")"
echo "PostgreSQL ${CX_MAJOR} client: ${CX_PGIMG:?no such client recorded in state.json}"

# The connection from .env, checking the server as the backend does (the table in §3.8)
CX_PORT="$(env_get EXTERNAL_DB_PORT)"
CX_MODE="$(env_get DB_SSLMODE)"; CX_MODE="${CX_MODE:-disable}"
CX_ROOT="$(env_get PGSSLROOTCERT)"
CX_TLS=""
case "${CX_ROOT}" in
  "")
    case "${CX_MODE}" in
      verify-full) CX_TLS="sslrootcert=system" ;;
      verify-ca) CX_TLS="sslrootcert=/etc/ssl/certs/ca-certificates.crt" ;;
    esac ;;
  system) CX_MODE=verify-full CX_TLS="sslrootcert=system" ;;
  *)
    case "${CX_MODE}" in
      require | verify-ca | verify-full) CX_TLS="sslrootcert=/backup/db-ca.pem" ;;
    esac ;;
esac
CX_CONN="host=$(env_get EXTERNAL_DB_HOST) port=${CX_PORT:-5432} dbname=${DB_NAME:?} user=${DB_USER:?} sslmode=${CX_MODE} ${CX_TLS}"
echo "${CX_CONN}"

# Load the dump; pg_restore asks for the password of DB_USER
docker run --rm -it --network host \
  --mount "type=bind,src=$(cd "${BACKUP_DIR:?}" && pwd),dst=/backup,readonly" \
  "${CX_PGIMG:?}" pg_restore --dbname="${CX_CONN}" "/backup/custodexa-db-${STAMP:?}.dump"
echo "pg_restore exit code: $?"
```

---

## 6. Post-restore verification checklist

**Confirm every item; if any of them fails, do not hand the system back into service.**

**After `restore`** (§5), part of this list has already been checked by the script: every service running with the recorded images (item 1), and the backend ready and reporting the backup's version (item 2). For item 6 it compared the master key ID with `kek.fingerprint`, and the fingerprint of `JWT_SECRET` with `fp.jwt` in `snapshot.txt` when that holds one. It also compared the imported database with the backup: the migrations, the row counts of `users`, `sessions` and `audit_logs`, and the master key ID. Still to be done by hand: items 3 to 5, item 6 for the export signing key and the checkpoint signing key, and items 7 to 10.

| # | Check | How | Pass criterion |
|---|---|---|---|
| 1 | All services are up | `docker compose ps` | Each service is running, postgres is healthy (with an external database there is no postgres service) |
| 2 | Backend health check | `docker compose exec backend wget -qO- http://localhost:8080/health` | A normal response (backend publishes no port, so it has to be called from inside the container) |
| 3 | No fatal in the startup log | `docker compose logs backend \| tail -50` | No refusal-to-start message. **A KEK mismatch says so plainly here** |
| 4 | The frontend is reachable | With the built-in TLS proxy: `curl -skI https://localhost/`. Behind your own ingress: `curl -I http://localhost:${HTTP_PORT:-80}/` on this host, then the address people use through the ingress | Responds 200. With the built-in proxy, `http://` answers 301 and points to HTTPS; that is expected, not a failure |
| 5 | The sign-in path works | Sign in with an existing administrator account | A token is obtained; the console can be entered |
| 6 | **Compare the fingerprints in the key inventory** | The "Key Management" page on the admin side | The fingerprints of the four env-side items, `ENCRYPTION_KEY (KEK)`, `JWT_SECRET`, the export signing key (Ed25519), and the checkpoint signing key (Ed25519), **are the same as the values recorded before the backup** |
| 7 | Encrypted fields decrypt | Open any asset that has credentials, or trigger one LDAP sign-in | No decryption failure appears |
| 8 | Recordings play back | Open a session recording that existed before the backup | It plays. **Both a local source and an offsite source count as a pass**: where the local file has been cleared from the cache it is fetched from object storage instead (with a download wait on first playback), and that path likewise verifies the hash before delivery |
| 9 | Audit chain verification | The integrity verification page on the audit side | The verification result matches the one before the backup |
| 10 | **The ledger and the objects in the bucket agree** (only with offsite storage enabled) | The "Offsite storage" page on the admin side: confirm the settings summary and generation state are as expected and that the failure list has no abnormal buildup; spot-check that a recording already offsite plays back | The ledger state matches the remote reality. **The two directions of disagreement read differently**: a ledger row with nothing in the bucket means a restore to a newer database point in time (or the remote copy was cleared by a lifecycle rule); something in the bucket with no ledger row is an orphaned object, usually a restore to an older point in time (see §3.1), to be reconciled against the custody chain events in the audit record |

> Item 6 is the most valuable one: **a fingerprint is a one-way digest, and matching fingerprints confirm that the same key is in use after the restore**, without touching any key material. Record these **four** fingerprints with every backup and keep them with it.
> Record only three at backup time and one of them has nothing to compare against after the restore; the one usually missed is the checkpoint signing key.
>
> The Key Management page can only be entered **after unseal** (modes B and C), so this item comes after the service is back.
>
> **In mode C, check the custodian settings on that same page while you are there**: the address, region, Transit key name and role identifier came back from the backup, so they are as of the backup point in time. If the topology was changed after that point, what you are looking at is the older destination, and the change has to be made again on this page; the alert and the audit rows for that change are in the system that was backed up, not in this one.
>
> After a restore, the role assignment comparison on the checkpoint verification page runs against the newest checkpoint in the backup whose notarization-time comparison matched (a checkpoint notarized while a mismatch was open is never used as the starting point), and the first notarization on the restored system whose comparison matches becomes the new starting point.

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

## Sensitive output detection: scope and operational checks

Detection scans only parsed text output from SSH, K8s and database consoles. RDP/VNC graphics, encrypted, compressed or encoded content (including Base64) are outside its coverage. Terminal control sequences are not rendered or removed. Encoding can bypass matching; a match means the output **may contain** sensitive data, and no match does not establish absence. This mechanism raises alerts and does not block or alter delivered bytes.

Output rule additions, disabling and edits take effect for **new sessions**. Sessions already in progress retain the rule set captured at startup. After an upgrade, restore or takeover, check rule direction, enabled state and protocols, then open a new text session to verify the applicable rule set. The installed seed set has 16 rules: 12 original input rules, two agent input/block rules, plus card-number and private-key-header output rules. The builtin card pattern additionally uses Luhn validation; editing that pattern makes it an ordinary regular expression without card validation.

Hits for the same rule and session are aggregated over five seconds; session close flushes the remaining window. Alert records and forwarding retain identifiers, rule, count and time, with an empty command and no matching text or byte offsets. The count is encoded as `o1:<base36 count>` in `reason_code`; webhook payloads also expose `possible_sensitive_output.count`. These are indications of possible sensitive output, not evidence that all output was scanned.

A bounded queue overflow disables scanning for that session without interrupting output. Query the existing audit records for action `output_scan_disabled`, resource `session` and the session's resource ID; `details` contains `session_id` and `reason=queue_overflow`, with no output text. A server log alone is not the audit record. Treat that session's subsequent output as unscanned; inspect the existing evidence under the usual permissions and open a new session after checking load. Scanner failures also leave server logs; absence of alerts is not a successful-scan guarantee.

The shared redaction primitive returns fully replaced text and a replacement count; it is **not connected to a product response path in this release**. Recordings, command records and other evidence are not redacted. Existing retention, access controls and backup/restore procedures continue to apply to their original contents.


### Principal and credential integrity coverage

The verification page reports role assignments, principal kind/owner, and agent credential state separately. After upgrade, the two new rows remain “Not covered” until the first checkpoint containing their snapshots. Detection is not immediate: reconciliation runs during verification, checkpoint sealing, and before token issuance. A mismatch raises one `principal_state_integrity` / `principal_state_mismatch` event per projection, with identifier-only differences and a notification. Issuance continues on mismatch or reconciliation error; errors are logged as unknown and do not change business state. Service-layer projection state rows record actor `system`; the existing HTTP audit rows identify the operator.

Compatibility is one-way: this release verifies old checkpoints, but old releases cannot fully verify the new snapshot keys. Do not remove snapshot keys, re-sign checkpoints, or restore the old single-mechanism failure index. Rollback requires a consistent pre-upgrade backup and the documented restore procedure. The payload version remains the current latest version (v3).

## Agent MCP operations

Create an agent principal with an active human owner. As that owner or an administrator, create a named, expiring agent token; save the one-time plaintext in the operator's secret store. The agent has only the user role and explicitly scoped asset/account grants. Install the `custodexa-mcp` stdio client on the agent's machine from https://github.com/custodexa/custodexa-mcp, either with `go install github.com/custodexa/custodexa-mcp@latest` or as a release binary verified against the `checksums.txt` published with that release. Supply `CUSTODEXA_AGENT_TOKEN` to `custodexa-mcp` through its environment and set `CUSTODEXA_MCP_URL` to the HTTPS `/api/v1/mcp` endpoint. Human JWTs and cookies cannot authenticate this endpoint. The stdio client forwards tool calls; all decisions and evidence writes happen in the service. Never put the token in command arguments or reports.

Whether a task the agent submits waits for a person is decided by the access policy segment of each requested asset, taken from the asset's own `access_policy` when set and otherwise from the `access_policy_default` security policy. An item in the `approval` segment stays pending until an approver whose scope covers that asset decides it. Items in the `open` and `reason` segments are approved at submission, are recorded with `auto_approved: true` and a policy snapshot, and carry no approval votes. Under the shipped defaults most assets fall outside `approval`, so a deployment that changes nothing will see agent tasks approve themselves. To require a human decision, set `access_policy` to `approval` on the assets concerned, or set `access_policy_default` to `approval` for the whole deployment; `access_request_min_approvals` then sets how many approvals such a request needs. Decide this before granting an agent its first asset, and state the choice in the runbook: automatic approval is still fully recorded, but it is not a human control.

Rotate by issuing a new named token, updating the operator's secret, starting a new MCP connection and verifying asset visibility, then revoking the old token. There is no in-place token secret rotation or automatic token recovery from backup. Revocation closes sessions created with the old token; a session handle cannot move to a new token or MCP connection. After restore or standby takeover, create new MCP connections and tasks as needed; old in-memory handles and the 60-second idempotency cache do not survive restart. Inspect retained token state and task state before resuming work.

To contain an incident, revoke or suspend the affected token, disable the agent if necessary, and inspect its task, tool-call and HTTP request records. A probe breaker suspends tokens and records an incident. An owner or administrator releases it with a reason; release does not reactivate suspended tokens, so issue a new token afterward. Its count covers one class of reference only: assets that exist and have never been exposed to that agent. A reference to an asset id that does not exist, or to a deleted one, is classified as retired, and a reference to an asset previously exposed to that agent is classified as revoked; both are recorded as events but neither counts toward the trip threshold. Enumerating identifiers at random therefore mostly produces uncounted events, and the breaker should not be presented as general scanning detection. It is a control against repeated reach for real assets outside the agent's scope; cover broader enumeration with alert rules and request rate policy, and read the `class` field on the breaker event list before judging how much a denied reference means. Existing webhook/Slack notifications include `owner_id`; they are not a private inbox or proof of delivery. Visibility exposure history begins at its migration and cannot reconstruct older visibility; verify that boundary before attributing a denied reference to abuse.

Token expiry, the bound task item's expiry and task closure terminate existing sessions and in-flight tools without waiting for the current command to finish. Expiry checks sample current state every 250 ms; that interval is not a completion SLA. Revocation uses the existing termination path (target at most three seconds, with late termination evidence). Termination controls only sessions created by this system, not detached processes or changes already made on the target. During an in-flight request, cancellation closes its session. Between POST requests, client departure cannot be detected immediately: the server closes abandoned handles when its five-minute idle lease expires. Do not describe this as immediate disconnect detection.

`completed` means a prompt was observed again; it guarantees neither command termination nor success. Prompts can be forged and background output can interleave. `timed_out` means the outcome is unknown: inspect subsequent output before retrying. Same-handle idempotency keys suppress repeat writes for 60 seconds; calls without a key can execute again. `needs_input` requires an explicit `send_keys` reset; the service never sends an interrupt automatically. `read_screen` is a line buffer, not a virtual screen. Agent-visible text is masked while recordings and command records retain the original. Masking is rule-driven and enumerated, not a general sensitive-data filter: it applies the enabled alert rules with `direction=output` whose subject kind covers agents and whose protocol list covers the session, and replaces each matched span with a placeholder. Anything no enabled rule matches reaches the agent in full, and the shipped rule set covers two categories, a card-number pattern and a private-key header pattern. Treat the rule list as the definition of what this deployment considers sensitive on the agent channel, review it against the data actually reachable on the granted assets, and add rules for the categories that matter there. Masking never applies to human terminals, recordings or command records.

For evidence, preserve the database, recordings, checkpoints and matching versioned integrity keys. A pending tool row proves recorded intent, not delivery or completion. An unattributable task/handle is rejected before the tool ledger and recorded in that MCP HTTP request's audit row with principal, tool, reason code and time. Command integrity coverage is available only through the Investigation Workbench and batch export; a single-session export has no coverage axis. Zero degraded rows does not prove that no commands were lost. Keep report versions and closed-task timestamps; do not manufacture results for pending calls.

After restore, reconcile retained evidence before resuming agent work.

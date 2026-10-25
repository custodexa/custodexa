# Rotating the Platform's Own Privileged Credentials

**English** | [繁體中文](../zh-TW/ops/privileged-credential-rotation.md) | [日本語](../ja/ops/privileged-credential-rotation.md) | [More languages →](../README.md)

> Applies to: Custodexa 1.0.
>
> **The scope of this page is the credentials the system itself holds**: the service account passwords, encryption keys, and signing keys the platform must hold in order to operate. Rotating account credentials on managed assets (credential change) is a product feature rather than an operational procedure, and the day-to-day use of it is not covered here. **One part of it is operational and is covered, in §13**: what to do when one set of credentials is shared by several hosts and a rotation of that set does not finish on every host. For Windows target prerequisites, see the Windows local account credential change section of §2.5 in the [Deployment and Upgrade SOP](./upgrade-sop.md).
>
> Related documents: [Backup and Restore](./backup-and-restore.md), [Deployment and Upgrade SOP](./upgrade-sop.md).

---

## 1. Summary table

| Credential | Stored in | Rotation entry point | When it takes effect | Interrupts existing connections or sign-ins | External coordination needed |
|---|---|---|---|---|---|
| LDAP bind password | Database (envelope encrypted) | Identity & Access → Identity sources (UI) | Immediately | No | Must be changed on the directory server first |
| Notification channel secret | Database (envelope encrypted) | Notification Channels (UI) | Immediately (same process) | Not applicable | The receiving end must be updated in step |
| Notification channel URL | Database (envelope encrypted) | Notification Channels (UI) | Immediately (same process) | Not applicable | — |
| Offsite storage credentials (offsite evidence storage) | Database (envelope encrypted, one set per settings generation) | System Settings → Offsite storage (UI) | As soon as the save succeeds | No | The storage side must create the new credentials first and revoke the old ones afterwards |
| KEK (key encryption key) | Depends on mode: env / memory / KMS | Key Management → KEK rewrap wizard | After the rewrap completes | No | Mode C needs a key on the KMS side |
| DEK (data key) | Database (wrapped by the KEK) | Key Management (`POST /keys/rotate`) | Immediately | No | — |
| Audit stamping key | Database (wrapped by the KEK) | Key Management (`POST /keys/rotate`) | Immediately | No | — |
| `ENCRYPTION_KEY` (KEK material, mode A) | `.env` | Through the KEK rewrap wizard, not by editing env directly | After the rewrap and a restart | Yes (restart) | — |
| KEK material (mode B, `KEK_PROVIDER=ui`) | Memory only (entered at unseal) | Through the KEK rewrap wizard | After the rewrap, a restart, and an unseal | Yes (restart, and service resumes only once someone unseals) | — |
| `JWT_SECRET` | `.env` | Edit env, then restart | After the restart | Restart ends active protocol connections; browser sign-ins may continue through refresh cookies | — |
| Ed25519 export signing key | Database (envelope encrypted private key) | System-managed; through the data layer if required (see §8) | — | — | **Yes, the public key must be redistributed** |
| Ed25519 checkpoint signing key | Database (envelope encrypted private key) | System-managed; the related endpoints are read-only (see §9) | — | — | **Yes, the public key must be redistributed** |
| `METRICS_TOKEN` | `.env` | Edit env, then restart | After the restart | No (the collector must be updated in step) | The collector must be updated in step |

Where the "external coordination needed" column is not empty, **if that coordination is not completed after the rotation the failure is silent**. Pay particular attention to §8, §9, and §3.

---

## 2. LDAP bind password

**Stored in**: the `bind_password_enc` column of the `ldap_directories` table (envelope encrypted). That table is a single-row settings table; a deployment has exactly one LDAP directory configuration. The column is write-only: no API response returns it, and the edit form cannot prefill it.

**Rotation procedure**:

1. Change the service account's password on the directory server (AD or LDAP) first.
2. Admin side → Identity & Access → Identity sources → enter the new password.
3. Press "Test Connection" to confirm the bind succeeds. **That test runs against the current form values, including unsaved changes**, so you can verify the new password before saving. It takes up to about 15 seconds.
4. Save.

**When it takes effect: immediately.** The bind password is **not cached**: each LDAP sign-in reads the configuration and decrypts once, and the plaintext lives only in the call stack of that sign-in. Therefore:

- **No service restart is needed.**
- **Existing sign-ins are not interrupted**: signed-in users hold a token issued by this system, which has nothing to do with the LDAP bind.
- During the gap between steps 1 and 2, **new LDAP sign-ins fail** (local account sign-ins are unaffected). Keep the gap as short as possible, or do this during a low-traffic period.

**Failure behavior**: when decryption of the bind password fails the system fails closed. Outwardly it converges on a credential error and **does not pretend LDAP is disabled and let the request through**; the internal log states plainly that this was a key incident rather than a wrong password.

**The `LDAP_*` variables in `.env`**: they are used **only on first startup**, to seed the configuration into the database. Changing them after seeding **has no effect**. Rotation always goes through the UI.

---

## 3. Notification channel secret and URL

**Stored in**: the `secret` and `url` columns of the `notification_channels` table (both envelope encrypted).

**What the secret is for**: computing an HMAC signature over the body of the webhook delivery request, carried in the `X-OT-Signature` header so the receiving end can verify the origin. **An empty secret means no signature.**

- **Slack-type channels never hold a secret**: Slack does not verify custom headers, and attaching one would only mislead. When a channel is converted from webhook type to slack type, any leftover secret is cleared.
- **Webhook type**: leaving the field empty on edit means keep the existing value (the secret is not returned, so that no edit silently clears it); you have to choose "clear" explicitly for it to be emptied.

**Rotation procedure**:

1. Notification Channels UI → edit the channel → enter the new secret → save.
2. **Update the verification key on the receiving end in step.**
3. Use "Test send" to confirm the receiving end got it and the signature verified.

**When it takes effect: immediately** (the channel cache is refreshed in-process; no restart needed).

**What else a change sets off.** Saving a changed URL or secret is recorded in the audit log and raises a `notification_channel_changed` system security alert, which is sent to the other enabled channels and also to this channel's destination before and after the change; expect that notice at the receiving end during the rotation. System security alerts already queued before the save keep the URL and secret the channel had when they were queued. If the receiving end stops accepting the old secret first, those deliveries fail and are retried until they are marked abandoned 72 hours after they were queued ([Deployment Topology Limits](./deployment-topology-limits.md#system-security-alerts-and-notification-channels)), so let the receiving end accept both secrets until the queue has drained, or accept that those deliveries are lost.

> ### A silent degradation path you have to know about
>
> When the channel cache is refreshed, the URL and secret are decrypted into the plaintext used for delivery. **If either fails to decrypt, that channel is skipped outright with no delivery, and only a single log line is written; no alert is produced, and the channel still looks normal in the UI.**
>
> This is a deliberate trade-off (better nothing than sending ciphertext as a URL), but the price is that **"looks fine in the interface" does not mean "is delivering."**
>
> System security alerts take a different path. For a channel whose settings cannot be decrypted, the alert is still recorded and still sent to every other enabled channel, and that channel's entry in the alert's delivery list is marked abandoned at once with zero attempts, so the gap shows in the alert detail; the operation that raised the alert is not blocked by it. Such a channel can still be edited or deleted; to repair it, enter the URL again and set or clear the secret.
>
> When you can hit it: after a KEK change or a change to encryption settings, when the old encrypted columns no longer decrypt.
>
> **How to confirm**: after changing anything related to encryption, press "Test send" once for each enabled channel and confirm the receiving end **actually received** it. Do not rely on whether the channel shows as enabled in the UI.
>
> A related path: if the cache refresh itself fails, the old cache is kept and only a log entry is written, with the next refresh catching up. So when you change settings and do not see the behavior you expected, the log is the only clue.

---

## 3b. Offsite storage credentials (offsite evidence storage)

**Stored in**: the offsite storage settings table in the database, envelope encrypted, **with one set held by each settings generation** (a deployment that has changed storage locations holds several, each matching the objects uploaded at the time). The column is write-only: no API response, admin interface, or audit record returns it, and **not even a masked value appears**; the edit form cannot prefill it either, so changing it means entering it again.

**Rotation procedure**:

1. Create the new credentials on the storage side (S3, MinIO, or GCS) first.
2. Admin side → System Settings → Offsite storage → enter the new credentials.
3. Press "Test Connection". **That test runs against the current form values, including unsaved changes**, so you can confirm the new credentials before saving.
4. Save.
5. Go back to the storage side and revoke the old credentials.

**When it takes effect: as soon as the save succeeds. No service restart is needed, and `.env` does not have to change.**

- **It does not trigger a generation change and does not change the settings fingerprint**: credentials are not part of the connection location. Changing only the credentials updates the current generation in place, and neither the ownership nor the retrieval path of historical objects is affected.
- **Conversely, changing the location requires entering the credentials again**: when the provider, endpoint, or bucket changes, the system refuses to reuse the existing credentials (credentials are not carried along with the settings to somewhere else). That path is also a generation change, and the admin interface asks for confirmation.

**Failure behavior: not silent.** When new credentials are invalid on the storage side, uploads move to a failed state, which is visible on the offsite storage page and the failure list in the admin interface and is reflected in the metrics. **Failure to decrypt the credentials (a key incident) is a separate state of its own** and is not treated as "the feature is not configured" and quietly stalled.

**Revoking credentials of historical generations**: after a location change, the old generation's credentials are **kept with that generation**, because retrieving historical objects needs them. When you are sure a historical generation no longer needs to be retrieved from, you can revoke the credentials on that generation alone: afterwards the objects of that generation cannot be retrieved, both the screen and the API state plainly which generation is missing what, **and there is no fallback to the cloud provider's default credential chain**, so "revoked yet still able to connect" does not happen. Revocation is irreversible: the current generation can be restored by entering credentials again on the settings page, but **a historical (retired) generation has no way back after revocation**, because the settings page can only write credentials for the current generation, and that generation's remote objects can never again be retrieved by the system. Before revoking a historical generation, confirm its objects are no longer needed.

**Turning offsite storage off does not revoke credentials**: "stop offsite" in the admin interface only stops new uploads from being produced; retrieval of historical objects continues as before, and the credentials remain. Revoking has to be stated explicitly, generation by generation.

**The `OFFSITE_*` variables in `.env`**: they are used **only on first startup**, to seed the configuration into the database. Changing them after seeding **has no effect**, and rotation always goes through the UI. Credentials therefore do not need to stay in the deployment-layer settings file, and their disaster recovery prerequisite becomes "restore the database and obtain the same KEK." See [Backup and Restore §4.4](./backup-and-restore.md#44-disaster-recovery-prerequisites-for-object-storage-credentials).

---

## 4. KEK (key encryption key)

For GCP, first read [§13b](#gcp-kms): production wiring and complete migration/recovery acceptance are not yet available. The generic KEK procedures do not establish GCP deployment readiness.

For Vault, first read [§14](#vault-transit): the current evidence covers an isolated full-service test assembly, not deployment-specific TLS or storage recovery. The generic KEK steps below are not evidence of Vault support.

The KEK is the root of the whole envelope encryption scheme. Rotating it is called a **rewrap** in this product: the existing data keys are wrapped again with a new KEK, and the data itself is not re-encrypted.

**Entry point**: the Key Management page → KEK rewrap wizard (requires the `key:manage` permission, held by the super administrator and the system security administrator templates). The related APIs all require `key:manage`:

| Endpoint | Purpose |
|---|---|
| `POST /api/v1/keys/rewrap` | Perform a rewrap |
| `DELETE /api/v1/keys/rewrap` | Abandon a rewrap that has not switched over |
| `DELETE /api/v1/keys/retired-material` | Clear the material of retired KEKs, **the only place material is destroyed** |

**An important property: material is kept after retirement until it is cleared explicitly.**
KEK retirement is a soft retirement: only the status column changes, and the wrapping material is not cleared. So **until "clear retired data" is run, rolling back to an old KEK at the data layer is always possible** (a last resort, handled manually per §10.4). After the clear runs the material is emptied and unrecoverable; the retirement trail (source, target, timestamps) and the fingerprints are kept permanently.

**Abandoning a rewrap**: the abandoned target is marked retired (with the reason recorded as abandoned) rather than deleted. On a later rewrap the system refuses to reuse any key reference that has appeared before (including retired records), so a brand-new key must be used.

**The topology after a rewrap.** In a delegated key deployment, a rewrap that changes the non-secret topology writes the new topology only after the rewrap itself has succeeded, in one transaction with its audit entry and the `key_topology_changed` system alert. If that write fails, the topology stays as it was, the rewrap is still reported as done (it is not rolled back, and running it again is not the remedy), and an audit entry records that the rewrap succeeded while the topology was not synchronized. To find it, look in the audit log for a `key_management` entry with action `update` and status `failure`, whose request body carries `rewrap_topology_not_synced` in `note`; the backend log carries a line that starts with `[KEKTopology]`. That entry is an ordinary audit entry, so it is not written when the audit log master switch is off, and the rewrap response does not carry this signal. Set the topology yourself in the topology section of the key management page; that save is audited and raises the alert like any other topology change. The alert is always created and left on record; whether anyone receives it depends on the notification channels.

**The steps that complete the switchover differ by KEK mode.** The rewrap itself and the switchover mechanism are the same in every mode, and the switchover is always completed by the **boot sequence** (once the system has verified that the new KEK can unwrap every key, it marks the old wrapped rows retired). What differs is where the new KEK enters the process, and **when that boot sequence can run at all**: in modes A and C at the moment of the restart, while in mode B the system stops in the sealed state after startup and only runs it once someone submits the material on the unseal page, so its switchover completes at unseal:

| Mode | What to do after the rewrap completes |
|---|---|
| `env` (mode A) | Write the new KEK into `ENCRYPTION_KEY` in `.env` (or the compose file) → restart the backend service → the switchover completes at boot |
| `ui` (mode B) | Restart the backend service (it comes back sealed) → **enter the new KEK on the unseal page** → the switchover completes at unseal. **Do not write the new KEK into `.env` or any environment variable**: in mode B the material exists only in memory, and writing it to disk gives up the only protection this mode offers |
| `kms` (mode C) | See "Cross-mode migration" below. The switchover requires changing the `KEK_PROVIDER` declaration and the corresponding configuration and then restarting, which is a deployment-layer change |

The full path for mode B is: rewrap → restart → enter the new-generation KEK on the unseal page → unseal succeeds and sign-in works normally.

The on-screen instructions on the Key Management page and in the key change wizard show the version matching the **runtime provider**; when the provider cannot be read they list the approach for each mode and ask the operator to identify their own, and **do not default to showing the `env` version**.

**Cross-mode migration (local → cloud KMS)**:

1. Fill in the KMS configuration keys first (`KEK_KMS_PROVIDER`, `KEK_KMS_REGION`, `KEK_KMS_KEY_ID`) and restart (still running on the local KEK at this point).
2. Key Management page → KEK rewrap wizard → choose the delegation target → enter the target key ARN. The preflight actually calls KMS to verify connectivity, key availability, and permissions.
3. After the rewrap completes, change `KEK_PROVIDER` to `kms`, remove the local `ENCRYPTION_KEY`, and restart.
4. Confirm the key inventory shows `provider=kms` and a canonical ARN for `key_ref`.

**Migrating back (cloud → local)** also goes through the rewrap wizard; just choose a local target.

---

### Runtime seal and unseal

Verification scope (2026-09-13): HTTP operation of the development build in env, ui and delegated modes; delegation used the delivered AWS driver with an isolated target. Complete three-mode page operation and a release-wide memory-dump conclusion remain unverified limitations.

1. Before sealing, arrange a service interruption and retain the current key source and existing administrator session. Seal stops new material use and releases the service graph, including work and connections; do not promise uninterrupted sessions or completion of every external job.
2. An administrator requests `POST /api/v1/seal/seal` with the existing Bearer token. Read `GET /api/v1/seal/status`; wait for `state=sealed` and `cleanup_pending=false`. A sealed label alone does not prove cleanup succeeded. Status queries do not restore service.
3. Restore through `POST /api/v1/seal/unseal`. In `ui`, explicitly enter the same effective KEK again; ordinary unseal does not require login. In `env`, submit an empty object with the existing administrator token: the backend rereads `ENCRYPTION_KEY`. Editing a deployment file does not change a running process environment. In delegated mode, the same authorized request uses deployment credentials to unwrap again; do not enter a local KEK. Retain `KEK_KMS_PROVIDER`, `KEK_KMS_REGION` and `KEK_KMS_KEY_ID` and access to the configured key service.
4. Wait for `unsealing` to finish and confirm `unsealed`; verify access to the original encrypted data. Wrong material or an unavailable delegated source must not be treated as success. `409` during cleanup or a concurrent unseal means inspect status before retrying; do not send parallel retries. Seal and unseal are not key rotation.
5. For an expired, revoked or otherwise invalid administrator token in env or delegated mode, restart the backend with the configured source. There is no separate rescue login or newly issued rescue token. For `sealed-faulted` or persistent `cleanup_pending`, preserve the result, resolve the reported cause and stop the old process before restarting. Do not delete the journal or treat restart as proof that earlier cleanup succeeded.
6. Account plaintext is not retained beyond the SSH handshake; DEKs and signing keys remain resident in process memory protected by the configured process safeguards and can be cleared with the seal action; memory snapshots may still contain keys and plaintext. In env mode, the key can remain in process environment, configuration strings and deployment files. In unsealed mode DEKs are cached; protocol strings, library copies and session traffic are outside an all-memory erasure promise. Owned buffers becoming zero does not establish the absence of all plaintext. Source credentials can permit subsequent unwrapping; seal does not revoke them.

## 5. DEK and the audit stamping key

**Entry point**: the Key Management page, or `POST /api/v1/keys/rotate` (requires `key:manage`), with `purpose` naming what to rotate:

- The data key (which protects encrypted columns such as asset credentials).
- The audit integrity stamping key.

**When it takes effect: immediately, no restart, no interruption to existing connections.** Once the new version is active, new writes use it; existing ciphertext is still opened by its own version, and the version chain is kept.

**Responses that may refuse the request** (all normal gatekeeping, not errors):

- A key operation is in progress (another key operation holds the lock) → 409.
- A rewrap is in flight and has not switched over → 409; complete or abandon that rewrap first.
- The in-process key cache has expired → 409.

**Rotation frequency**: the Key Management page carries the `key_cryptoperiod_reminder_days` policy key. When set greater than 0, keys past that age show a reminder in the inventory. The reminder appears only in the inventory; the rotation itself has to be performed by a person.

---

## 6. `ENCRYPTION_KEY` (the material for KEK mode A)

**Do not rotate this key by editing the value in `.env` and restarting.** That is not a rotation; that turns the system into one that will not start: if at startup the KEK does not match the wrapping in the database, it fails closed and refuses to start.

The correct approach is the **rewrap wizard** in §4: rewrap with the new material, and update `.env` only after the system has completed the switchover.

The key inventory shows this key's **fingerprint** (the first 8 bytes of the SHA-256 of the material). Environment variables carry no rotation record, so the inventory has only a fingerprint, without an age or a last-rotated time; if you need a record of rotation times, maintain it in your own operational documentation.

For the error guidance when a retired KEK is set by mistake, see [Backup and Restore §7.2](./backup-and-restore.md#72-booting-with-a-retired-kek-whose-material-has-not-been-cleared).

**Mode B (`KEK_PROVIDER=ui`) has no such env key**; the material is entered at unseal and never written to disk. For the rewrap switchover steps in that mode, see the mode table in §4: after the restart, enter the new KEK on the unseal page, and **do not** write it into `.env`.

---

## 7. `JWT_SECRET`

**Stored in**: `.env`. This is the HS256 signing trust root for sign-in tokens, and must be at least 32 bytes long.

**Rotation procedure**: change the value in `.env` → restart the service.

**When it takes effect: after the restart.**

> Restart ends active protocol connections. Existing JWT access tokens signed with the old key stop verifying after the restart. Refresh tokens stored in the database remain valid and can issue access tokens signed with the new key, so existing browser sign-ins may continue without another login. Changing `JWT_SECRET` alone does not force every user to sign in again.
> Schedule a maintenance window and notify users in advance.

In release mode the system detects whether `JWT_SECRET` is still the factory placeholder value and refuses to start if it has not been changed.

**`JWT_SECRET` and the restore generation** (from 1.18.0). The key that signs sign-in tokens is derived from `JWT_SECRET` and the restore generation kept in the database. Until the first restore the generation is empty, and the key is `JWT_SECRET` itself. The two change separately:

- A restore by the management script of a backup of 1.18.0 or later sets a new generation and puts `.env` back as the backup holds it. `JWT_SECRET` and its fingerprint on the Key Management page stay the same, every token signed before the restore stops verifying, and the refresh tokens and agent tokens in the backup are refused ([Backup and Restore §5](./backup-and-restore.md#restoring-with-restore)).
- Replacing `JWT_SECRET` as above does not change the generation.
- A restart, or another host taking over the same database, keeps the generation.

### Revoking long-lived sign-ins (going back to an older version)

An older version does not know the restore generation of the permission model, so changing `JWT_SECRET` alone leaves refresh tokens, agent tokens and approved temporary grants valid. When you return to an older version by hand, do both at the stop point of the restore commands ([Backup and Restore §5](./backup-and-restore.md#restoring-by-hand), step 5a): after the database is loaded and before any service starts, with every application service on every application host stopped. Do not do them before the load, because the load replaces both the `.env` and the data they act on. If either step fails, do not start the services.

1. Put a new random value in `JWT_SECRET` in the `.env` that the restore put back (at least 32 bytes). With two application hosts, give both the same value before either starts.
2. With the database stopped from receiving other writes, run the statements below in one session of the deployment's database client (for the bundled database: `docker compose exec -T postgres psql -U <database user> -d <database name>`), then check that each statement reports the rows it changed.

```sql
UPDATE refresh_tokens SET revoked_at = now(), revoked_reason = 'restore' WHERE revoked_at IS NULL;
UPDATE agent_tokens SET revoked_at = now(), revoke_note = 'restore' WHERE revoked_at IS NULL;
UPDATE asset_authorizations SET date_expired = now()
 WHERE source = 'ticket' AND deleted_at IS NULL AND (date_expired IS NULL OR date_expired > now());
```

Everyone signs in again afterwards; agent tokens must be issued anew and temporary grants requested again. Standing authorizations are not changed. When you restore a backup taken before the upgrade with the scripts of the new version, the restore does both steps itself before the older version starts, and records only the fingerprint of the new secret ([Backup and Restore §5.1](./backup-and-restore.md#from-1180-or-later-to-a-version-before-it)). The same two steps, at the same stop point, close the sign-ins of any backup restored by hand, which does not set a new restore generation. The new `JWT_SECRET` stays: the fingerprint check of [Backup and Restore §6](./backup-and-restore.md#6-post-restore-verification-checklist) then compares against it, not against the backup. This does not protect against someone who controls the host.

---

## 8. Ed25519 export signing key (audit evidence export)

**Purpose**: signing the manifest of an audit evidence export. The verifiers (external auditors, a QSA) are outside the organization and verify **offline with the public key**. This is exactly why Ed25519 was chosen over HMAC: a shared secret is not workable for verifiers outside the organization.

**Stored in**: a **single row** of the `export_signing_keys` table (private key envelope encrypted, public key stored in plaintext for download). It is generated automatically on first startup. **This table has no version column.**

**Getting the public key**: `GET /api/v1/audit-export/public-key` (requires the `audit:view` permission), or copy/download the public key on the Key Management page (the inventory shows the **public key fingerprint**, not a material fingerprint). This key is marked system-managed in the inventory and **has no rotate button**.

### If it has to be replaced: the data-layer procedure

Replacing this key is a data-layer operation: delete that row of `export_signing_keys` and restart, and the service generates a new one at the next startup. This path **has not been verified by the product**; back up before running it, and understand the following consequences:

> ### After a key change the public key must be redistributed, or external verification fails silently
>
> - **Every external verifier's old public key becomes invalid immediately.** Verifying newly exported evidence with the old public key gives "signature does not verify," and that outcome looks **exactly the same** as "the evidence was tampered with."
> - **Existing evidence exports that have already been delivered cannot be verified with the new public key.** The old signatures correspond to the old private key, which no longer exists, so that evidence can never be verified again.
>
> **So before changing the key, confirm**: has the verification window closed for all evidence already delivered? After the change you must actively redistribute the new public key to every external verifier and tell them in writing when the change took place, so they know which evidence to verify with which public key.
>
> No mechanism does this for you, and no error message will remind you that you skipped it.

---

## 9. Ed25519 checkpoint signing key (the audit checkpoint chain)

**Purpose**: signing the checkpoints of the audit checkpoint chain, for offline re-verification. It is **deliberately separate** from the export signing key and is not shared with it. It is generated automatically on first startup, and its table (`checkpoint_signing_keys`) has had a version column from the beginning.

**Getting the public key**: `GET /api/v1/audit-checkpoints/public-key` (returns the public key, the version, and the fingerprint).

### The lifecycle of this key

Once generated, this key stays the same one, and the three endpoints under `/api/v1/audit-checkpoints` (list, public key, verify) are all read-only. The version column on the table, and the verification logic accepting a version to verify against, are room reserved for several versions coexisting.

If rotation is opened up later, the external coordination requirement in §8 applies just the same: **the new public key has to be redistributed to offline re-verifiers**, and checkpoints of the old version still have to be verified with the old public key.

---

## 10. Exception handling around the KEK

The four items below are operations where a mistake leaves data undecryptable. Work through them step by step and do not skip steps.

### 10.1 Row-by-row handling when `kek_id` is not in canonical form

**Symptom**: at startup the system detects rows in delegated mode (`wk:2:kms:`) whose `kek_id` does not match KMS key ARN syntax, and fails closed, refusing to start.

> **Handling must be done row by row; a single table-wide `UPDATE` is strictly forbidden.**

1. Export `purpose`, `version`, `kek_id`, and `wrapped_key` for those rows.
2. For **each row**, try to unwrap with an explicit KeyId and the correct AAD, confirming that the material really does belong to that key.
3. **Only rows that unwrap successfully** may be relabeled with a canonical ARN.
4. Rows that fail to unwrap **must not be relabeled**. A failed unwrap means the correspondence between the label and the material is itself in question, and a bare `UPDATE` only turns a diagnosable error into irreversible label contamination.

### 10.2 Recomputing the AAD (for cloud KMS audit comparison)

In delegated mode, the `EncryptionContext` sent to KMS is a single-key opaque mapping, `{"aad": base64(aadBytes)}`.

**This changes the audit power of CloudTrail from directly readable to comparable**: the base64 value seen in CloudTrail records cannot be read directly and has to be recomputed locally and compared.

How to recompute: the AAD at the data key layer is the base64 of the length-prefixed canonical encoding of that key's `purpose` and `version`. When the recomputed result matches the CloudTrail record, you have confirmed which key purpose and version that KMS operation corresponds to.

### 10.3 Order for reverting

The reverse rewrap (delegated → local) is itself performed through the rewrap wizard; see §4.

> **Reverting is only that one reverse rewrap.** The legal value of the wrapping prefix is always a single form, with no fallback branch, so the rewrap completing is the end of it. There is no second step.

### 10.4 Manually recovering a retired KEK row (last resort)

For Vault, use [§14.7](#vault-recovery). Do not apply this manual row-revival procedure to Vault; use a consistent whole-backup recovery instead.

Use this only when you must roll back to a KEK that has been retired, and **it is only possible while that KEK's material has not been cleared explicitly** (see §4).

Prerequisites and cautions:

- This is a data-layer operation; the product offers no UI or API entry point for it.
- Take a full database backup before running it.
- The system **does not reverse retirement automatically**: setting an old KEK after the switchover has completed is almost always an operator mistake, and reversing it automatically would silently undo a deliberate key ceremony.
- If the reason for retirement was that the KEK was abandoned (it was never in service), recovering it amounts to silently undoing a deliberate decision to abandon. The right approach in that case is to **start with the current KEK and run the rewrap again**, not to recover the retired row.

When the system boots with a retired KEK set by mistake, it gives guidance matching the retirement reason; see [Backup and Restore §7.2](./backup-and-restore.md#72-booting-with-a-retired-kek-whose-material-has-not-been-cleared).

---

## 11. Email (SMTP) credentials

Audits and procurement assessments often ask who rotates your email service account. **This product contains no email sending component**: there is no SMTP client, no sending account, and no mail server configuration, so there are no SMTP credentials to rotate.

Alerts go out over webhooks and Slack (see §3). Both are HTTP POST, the credentials take the form of a channel URL and an HMAC secret, and the rotation procedure is the one in §3.

If you need to receive alerts by email, do it by forwarding from your own webhook receiver; the email credentials on that leg are managed by you and are outside the scope of this product.

---

## 12. Checks common to every rotation

Whatever you rotated, confirm the following afterwards:

1. **The fingerprints in the key inventory changed as expected** (what should have changed did, and what should not have did not), and update the fingerprint record kept with your backups.
2. **Press "Test send" once for each enabled notification channel**, and confirm the receiving end actually received it (the silent degradation path in §3).
3. **The audit record contains a record of this rotation.** Key operations all require `key:manage` and are audited; clearing material additionally records the number of rows cleared and the fingerprint of each key version.
4. If you touched a key on the env side, confirm the startup log after the restart has no fail-closed message.

---

## 13. Shared credentials on managed assets

**Applies to**: one set of login credentials used by several managed hosts. In the credential library
such a set is one named credential with several bindings, and the binding list is the answer to
"which hosts use this secret". This section is the recovery procedure for the case where changing
that secret does not finish on every host.

### 13.1 Changing the whole group

Starting a group change returns straight away; the hosts are worked through in the background,
one at a time. **A host only moves to the new secret once the system has logged in with that new
secret and the login succeeded.** Until then that host keeps using the version it already had.

**So a partial result is a normal state, not a fault.** Each binding records the version it is
actually using, and connections keep going through with whichever version that is: hosts that
verified use the new secret, hosts that did not keep using the old one. Nothing on either side is
left without a usable secret.

The credential's state is one of five values, and the page shows it:

| State | What it means |
|---|---|
| `idle` | No change in progress and no version waiting to take effect |
| `queued` | A change has started and every host is still waiting its turn |
| `changing` | Hosts are being worked through |
| `partial` | Some hosts are on the new secret and some are not |
| `out_of_sync` | The round has ended with hosts still not on the new secret |

`partial` is shown ahead of `changing` on purpose: once "some done, some not" is true, that is the
thing you need to see.

**What advances by itself, and what does not.** Within a round that is still running, the retry
schedule picks up a host that hit a retryable failure once its own retry time comes, and sends the
change again; a host whose remote result is not yet known is only logged in to with the new secret,
and the change is not sent again. Both follow the same backoff as the credential change retries,
until 24 hours after the round started. Hosts that ended in a final failure, hosts closed out with
the round, and **every host in a round you abandoned** are never advanced automatically, and the
schedule never sends the change to them again. Those need you to retry them one at a time: nobody
has checked which secret such a host is taking now, and a host that certainly cannot be changed
should not be hammered indefinitely.

**A host that was being changed when the service stopped.** The remote result of that change is
unknown. At the next start, before any schedule runs, each such host is marked Changed, unverified
with the reason that the service restarted: its pending secret is kept, nothing is sent to it, an
audit entry is written in the same step and an alert is raised for it. From then on it is handled
like any host whose remote result is not known: in a running round the retry schedule logs in to it
with the new secret, and Retry does the same; neither sends the change again. If it still cannot be
verified 24 hours after the round started it becomes Failed, and after that only Retry moves it,
sending the change again. If the audit entry cannot be written, the host is left as it was, the
alert says so, and the next start tries again.

**Retrying one host** acts on that host only and answers synchronously; it can take tens of seconds,
because it opens a real connection and verifies the login.

### 13.2 Abandoning a round

Abandoning **stops the automation; it does not roll anything back**. Hosts already on the new secret
are not put back, pending secrets that have already been sent to a host are not deleted, and nothing
further is sent to any host.
Rolling back would mean logging in to those machines again, and "abandon" is precisely the decision
not to touch them any more.

There are two outcomes:

- **No host had been touched** (every one still queued or waiting to retry, with nothing delivered):
  the round is discarded and the credential returns to `idle`.
- **Otherwise**: the credential goes to `out_of_sync` and stays there. **The only way out is to
  retry the remaining hosts one at a time until every host is on the same version.** While the
  credential is `out_of_sync` the system refuses to start a new round on it — starting one would
  make "which secret is actually on which host" unanswerable. The abandoned round stays on the
  credential's page: every host not yet on the new secret that is still bound has the Retry action
  there, including hosts that were closed out when you abandoned, and when the last one is on the new
  secret the credential returns to `idle`.

**Do not clear a pending secret to tidy the state up.** That record may be the only copy of a secret
that is already live on the host; once it is gone, the way back is the host's own console.

### 13.3 Giving each host its own secret

The other mode gives every host a different new secret and ends the sharing: as each host verifies,
it is moved onto a credential of its own. When the original credential is left with one host it
becomes that host's own credential; left with none and with nothing pending, it is removed.
If you abandon this kind of round after hosts were changed, it stays on the credential's page, and
every host whose new secret is still kept and that is not yet on a credential of its own has the Retry
action there, including a host that was stopped after it had been worked on (for example by a Retry
pressed while the person who started the round had lost the permission). Hosts the new secret had
certainly not reached when you abandoned had it discarded; they keep the shared credential and have
nothing to retry.

**There is no undo.** The system does not offer a way to put those hosts back on one shared set —
the secrets are now genuinely different on each machine. Sharing them again means creating a new
shared credential, binding the hosts to it, and then starting a whole-group change on that
credential: binding by itself changes nothing on any host, and it is that change that sets one new
secret on every host.

### 13.4 Taking one host out of the group

Detaching one host logs in with the secret that host is currently using, applies the new one, and
verifies it by logging in again. **Only if that verification succeeds** does the host move onto a
credential of its own. If it fails, or if the remote result cannot be determined, the host stays on
the shared credential and the response says which of the two it was — the difference matters,
because a plain failure can simply be retried, while an unknown result means you first have to
find out which secret that machine is now taking.

**Detaching is not the same as removing a binding.** Removing a binding takes the host off the
credential and **does not touch the password on the host**; detaching changes the password on the host.
The screen says which is which at the point of the action.

### 13.5 A scheduled plan that covers a shared host

A credential change plan whose target is accounts **will not save** if its selection covers a host
that uses a shared credential, and any such host reached at run time is recorded as skipped.
Neither alternative is acceptable: changing one member alone leaves the other hosts of that set
without a usable secret, and quietly extending the change to the rest means changing machines the
operator did not select.

Two ways forward, both supported:

- **Point the plan at the credential instead of at accounts.** The plan then changes that credential
  as a group, on the same schedule, with the same password policy.
- **Take that host out of the group first** (§13.4), after which an account-targeted plan covers it
  like any other host.

### 13.6 What to confirm afterwards

1. **The credential's state is `idle`** and every binding shows the same version. A credential left
   at `partial` or `out_of_sync` is a change that has not finished.
2. **The audit record contains this change.** Every change to the credential library needs the
   matching credential permission and is audited; binding and unbinding additionally record which host was affected, so the change is
   findable from the host as well as from the credential.
3. **The rotation evidence report marks the hosts as expected.** A host that has been detached is no
   longer marked as sharing; the report reads the credential's scope.

### 13.7 Who may do this, and what happens when permission is lost

- **Managing credentials and connecting are separate permissions.** Viewing, creating, editing,
  declaring a new secret, changing the secret on hosts, converting the scope, detaching, deleting and
  binding each need their own credential permission, and changing a managed account's secret needs
  the account-rotation permission. Holding a connection permission does not allow managing, and
  holding a management permission does not allow connecting. The super administrator role holds all
  of them.
- **A plan, batch or rotation runs as the person who started it, and the person's current permissions
  are checked again before each target starts, before each rotation member step and before each
  candidate retry.** For a scheduled plan that person is the one who last saved the plan, or
  whoever later took it over with the banner on the credential-change plan page; right after an upgrade it is the user
  the upgrade found in the audit trail, until the plan is saved or taken over. A rotation taken over
  with the Retry action on one of its members runs as the person who took it over. A manual
  "run now" applies to that run only. The check covers the permission itself and, for a person who holds it
  only through assignments limited to some nodes, whether the target is still within that scope (§13.8). If the person has lost the permission, that
  piece of work stops, no new change is sent to that host, and an alert and an audit entry are
  attempted (alerts are de-duplicated, so their count is not an exact tally). On each host the check is
  made after the new secret has been prepared and before the first write to the host; a key change is
  checked again before the old key is removed. Verifying the new secret, and for a key change restoring
  the previous keys when that verification fails, belong to the step already allowed and are not
  checked again. Each check is completed before the step it allows sends anything to the host, and it
  does not overlap with a change to where assets, nodes or credentials belong. A move out of scope or a
  removed permission that takes effect only after a host's check has completed affects the next host or
  the next checked step. A role removed, directly or through a group, while a host's check is in
  progress may still let that host be changed once; the next host is checked with the role already
  removed. The step already allowed is not cut off midway and finishes its normal safety steps. For roles that come from
  an external identity source, "current permissions" means what the platform last computed for that
  person; see [Deployment Topology Limits](./deployment-topology-limits.md#roles-granted-from-an-external-identity-source-when-a-change-there-takes-effect).
- **If the stop came after a change had already been sent to the host,** the candidate or rotation
  member is kept, not discarded. Within 24 hours of the candidate or rotation being created the
  platform may still verify it and record the result, as described in
  [Upgrade SOP §2.5b](./upgrade-sop.md#25b-scheduled-credential-change-plans-after-the-upgrade);
  after that, or when the target has changed, an authorized person has to decide which secret the
  host is taking. Candidates and members that are still waiting for a retry are looked at again on
  their normal schedule, so if the permission is restored they may continue on their own. Work whose host identity has changed is not covered by this: if the host key record was replaced, adopted again, reset or deleted after the job first exchanged host keys with the target, or the job recorded no identity, it stays stopped until a person confirms it, as described in [Upgrade SOP §2.5b](./upgrade-sop.md#25b-scheduled-credential-change-plans-after-the-upgrade). For work from before the upgrade, the first confirmation fixes the target as it is when the confirm button is pressed (a candidate credential from before the upgrade first needs one ordinary Retry, and the target is fixed as it is when that Retry runs); if the target had already been changed before then, this cannot be detected.
- **Declaring or choosing a secret yourself is a recorded, alerted action, not a blocked one.**
  Declaring a new secret and detaching a host with a custom secret leave an audit entry and raise an
  alert. A person who may do this can set a host's
  password to a value only they know and then connect to that host directly, without passing through
  this platform. The platform records and alerts; it does not prevent it.

### 13.8 Credential changes by an administrator limited to some nodes

This section describes what happens when a person holds the account-rotation or the credential-rotation permission through an assignment limited to some nodes. Each action is judged by the one permission it needs: a person who holds that permission through any assignment covering the whole system is not limited for that action, even when other permissions of theirs are. For a person who holds it only through assignments limited to some nodes, batches and plans act only on targets within that scope.

- **Batch credential change.** Account names, targets and host counts include only hosts within the scope. The batch list shows a batch when at least one host it selected is within the scope, and the batch's detail counts only those hosts. If any account selected for a new batch is outside the scope or no longer exists, the whole batch is refused and nothing is changed on any host; the response gives only the number of such accounts. In single-password mode the owner of the new shared credential is judged separately, by the credential creation permission: a person who holds that permission through an assignment covering the whole system can make the credential global, and a person who holds it only through assignments limited to some nodes has to give it to a node within that permission's scope. Before each host is changed, the new credential is also checked against the person's credential attach permission; if its owner is outside that permission's scope, the host is not touched and keeps its current credential.
- **A plan that targets accounts.** Every asset in the plan has to be within the scope, or the plan is not saved. A plan whose assets are not all within the scope is not shown to that person, and running, editing or deleting it behaves as for a plan that does not exist.
- **A plan that targets a credential.** The credential's owner has to be within the scope. Changing the credential changes every host it is attached to, including hosts outside the scope. If any attached host is outside the scope at the moment of saving, the person is shown how many (a count only, the hosts are not named) and has to confirm before the plan is saved, as when rotating the credential from the credential library. On the plan page, when such a plan is edited and saved and hosts outside the scope are affected, the page asks for this confirmation before the plan is saved; with no host outside the scope affected, the plan is saved directly. When the plan is saved, the platform stores every attachment the credential has at that moment as the bound of that version of the plan.

**When the attachments grow after the plan was saved.** Each run, before anything is sent to any host, splits the credential's current attachments into those on hosts within the scope of the person the run acts for, and the rest. That person is the plan's initiator for a scheduled run and the person who pressed "run now" for a manual one. If that person holds credential rotation only for some nodes and the rest includes an attachment that is not in the bound, the whole run stops and no host is touched. A version saved by a person without a scope limit has no bound, which counts as empty here. For a scheduled run, and for a manual run when the plan's initiator does not hold credential rotation through an assignment covering the whole system, the plan is then marked as needing re-confirmation (`needs_reconfirmation`, reason `CHANGE_SECRET_SCOPE_BOUND_EXCEEDED`). The alert and the audit entry are written once, when the plan enters that state, and the schedule does not run the plan while it is marked. If the plan has been saved again after the run compared its attachments with the bound, the run still stops and the newly saved version is not marked. When the plan's initiator holds credential rotation through an assignment covering the whole system, a manual run by a person limited to some nodes is only refused that once: it leaves a stop audit entry and an alert with the same reason, the plan is not marked and its schedule keeps running. A manual run is also only refused that once when the platform cannot determine the initiator's permission at that moment.

- A new attachment on a host within the scope does not stop the run. It is changed with the other hosts and appears in the run's records.
- A second account on a host outside the scope is an attachment outside the bound, so it stops the run.
- A host that was within the scope when the plan was saved and has since been moved out is already in the bound and does not stop the run.

**Getting a paused plan running again.**

- A person limited to some nodes saves the plan again, with the Reconfirm action on the plan's row or by editing and saving it. If hosts outside the scope are still attached, that person confirms their number again before the save. That saves a new version with a new bound and clears the mark. Neither the takeover banner nor "run now" lets such a person skip this save: the banner lists the plan as skipped and leaves it paused, and "run now" stops before anything is sent.
- A person who holds credential rotation through an assignment covering the whole system can take the plan over with the banner. That person becomes its initiator, the schedule resumes, and from then on each run changes every current attachment without a bound. Or that person can press "run now" once: that run covers every current attachment, the plan stays paused and the schedule still does not run it. Both leave the same audit entries as any takeover or manual run.

**Checks while the work runs.** The checks described in §13.7 also look at whether the target is still within the scope of the person the work runs as: for an account, the host it is on; for a plan that targets a credential, the credential's owner. A target that has left the scope stops with the reason that the authorization was revoked (`CHANGE_SECRET_AUTHZ_REVOKED`), and the other targets continue: in a plan or batch that changes hosts one at a time, only that host stops and each later host is checked on its own. If the person has lost the permission itself, the platform cannot determine it at that moment, or the owner of a batch's new shared credential is outside the scope of the person's credential attach permission, the plan or batch stops at that host and no later host is touched.

**A person without a scope limit** sees no change. A credential-target plan saved by such a person needs no confirmation, stores no bound and changes every current attachment on each run, as before.

**Work from before the upgrade.** Plans, batches, rotations and candidates that exist at the upgrade are not rewritten. Before this version no assignment could be limited to some nodes, so their initiators have no scope limit; that work keeps running and settling as before and is never paused for a bound. Plans already paused for re-authorization stay paused until they are saved or taken over.

**Limits that remain.**

- **Confirming proves that the person was told; it does not stop the change.** A person limited to some nodes who confirms and saves a credential-target plan changes the password on the hosts outside their scope as well. The confirmation only makes sure the number of those hosts was shown before saving. The bound only stops a run from reaching attachments added outside the scope after the save without a new confirmation; it does not limit what was confirmed when the plan was saved. Grant credential rotation with the same care as the right to log in to every host the credential is attached to; see [Deployment Topology Limits](./deployment-topology-limits.md#shared-credentials-within-a-limited-scope-what-the-impact-confirmation-stops-and-what-it-does-not).
- **Choosing a secret yourself is still recorded, not prevented.** As described in §13.7, a person who may declare a secret or detach a host with a custom secret can do so on hosts within their scope, set the password to a value only they know, and then connect to that host directly without passing through this platform. The platform records and alerts; it does not prevent it.


---

<a id="gcp-kms"></a>
## 13b. GCP Cloud KMS KEK operations

<a id="gcp-availability"></a>
### 13b.1 Availability and release prerequisites

GCP Cloud KMS is selectable. It has been exercised against the contract test suite and an in-process fake; a run against a live GCP project has not yet been performed by the project. The current build includes the GCP driver, five-provider common contract tests, service-object tests using a fake client, and the production startup and client ownership wiring; the complete migration wizard is not yet available. Against a live project, ADC/IAM, PostgreSQL transaction rollback, process restart, live sessions, audit delivery and complete backup recovery remain unverified. Take that into account before making GCP the custodian of an operating deployment.

The procedures below apply only to a release with the required production wiring and successful isolated full-service acceptance. Stop if any prerequisite is missing; do not substitute manual database edits or handcrafted requests. For GCP, this gate also qualifies the generic procedures in §§4 and 10. Local retirement checks must not be bypassed to recover the current database.

<a id="gcp-configuration"></a>
### 13b.2 Resource identity, configuration and TLS

Use the full CryptoKey resource name `projects/<p>/locations/<l>/keyRings/<r>/cryptoKeys/<k>` as `kek_id`. Do not use a bare key name, URL, or a cryptoKeyVersions child resource. The deployment reference defines the trusted project; a wizard target supplies only a key reference in that project, not a new project trust setting or credentials. The driver does not guess equivalence between project IDs and project numbers. The complete reference must fit the 255-byte storage limit. See the [Cloud KMS resource reference](https://cloud.google.com/kms/docs/reference/rest).

This is the target configuration, not an instruction to enable an unwired release:

```dotenv
KEK_PROVIDER=kms
KEK_KMS_PROVIDER=gcp
KEK_KMS_KEY_ID=projects/example-project/locations/global/keyRings/platform/cryptoKeys/platform-kek
KEK_KMS_REGION=
ENCRYPTION_KEY=
```

GCP does not require `KEK_KMS_REGION`; leave it unset or empty. A retained value is ignored and is not passed to the SDK; location comes from the resource name. Delegated mode rejects nonempty `ENCRYPTION_KEY`. Before switching, keep the active local mode and its recovery material until §13b.5 explicitly calls for the target configuration.

The KMS data transport uses only https://cloudkms.googleapis.com, TLS 1.2 or later with certificate verification, and no redirects or environment proxy. Custom endpoints, HTTP, disabled TLS verification and nondefault SDK universe/mTLS settings are rejected. Credential token/metadata traffic follows the separate official ADC flow; its legitimate destinations are not restricted to the KMS host. No product endpoint or GCP credential configuration keys are added.

<a id="gcp-authentication"></a>
### 13b.3 ADC, permissions and credential replacement

Authentication uses the official SDK's Application Default Credentials (ADC); token refresh belongs to that library. Supply the deployment's approved workload identity or service-account credential source. `GOOGLE_APPLICATION_CREDENTIALS` is a standard SDK input, not a product secret store. There is no anonymous or static test-credential fallback and no product API for live credential replacement. Do not assume changing a credential file updates an already constructed client.

Grant the runtime identity only the metadata read and encrypt/decrypt access needed for the selected CryptoKeys. Use a separate administrator identity for creating versions, changing primary, disabling or destroying versions, and changing access policy. Metadata access alone is insufficient: preflight must complete encrypt and decrypt as well. Actual project IAM and credential refresh still require isolated real-project acceptance.

1. Record the approved identity, nonsecret resource references, credential custody, maintenance window and recovery access. Do not record private keys or bearer tokens.
2. Provision replacement access through the deployment's secret mechanism. Preserve authorized recovery access until adoption is confirmed; never place credential contents in shell arguments, tickets or tracked files.
3. Once §13b.1 is satisfied, rebuild the client through that release's supported deployment/restart procedure. Require real-project metadata, encrypt/decrypt and credential refresh checks before switching production access.
4. Revoke superseded access after successful adoption. If adoption fails, stop and restore authorized access through the deployment procedure. If compromise is suspected, revoke affected access promptly and accept that operations requiring KMS may be unavailable; credentials alone cannot replace missing KEK versions.

<a id="gcp-actions"></a>
### 13b.4 API operations, AAD and distinct rotations

In the paths below, `<cryptoKey>` means the complete resource name from §13b.2.

| Operation | Request | Effect and boundary |
| --- | --- | --- |
| Wrap a DEK | `POST /v1/<cryptoKey>:encrypt` | Uses the CryptoKey's primary; sends plaintext and original AAD, and receives ciphertext plus the actual version name and integrity fields. |
| Unwrap a DEK | `POST /v1/<cryptoKey>:decrypt` | Sends ciphertext and the original AAD; returns the DEK to the backend. The service selects the ciphertext's version. |
| Create a remote version | `POST /v1/<cryptoKey>/cryptoKeyVersions` | Administrator action. A create response alone is not proof that primary changed or that stored database wraps changed. |
| Select primary | `POST /v1/<cryptoKey>:updatePrimaryVersion` | Administrator supplies `cryptoKeyVersionId`; require the returned/read-back CryptoKey primary to match. The CryptoKey reference stays the same; existing database wraps are not rewritten. |
| Replace a product KEK reference | Source decrypt, then target encrypt | No native ReEncrypt endpoint is used. For GCP-related service rewraps, both operations and clone-row writes occur inside the existing locked database transaction. Failure or failed commit returns no success and does not publish pending state in memory. Remote requests themselves cannot be rolled back by the database. |

Official schemas: [encrypt](https://cloud.google.com/kms/docs/reference/rest/v1/projects.locations.keyRings.cryptoKeys/encrypt), [decrypt](https://cloud.google.com/kms/docs/reference/rest/v1/projects.locations.keyRings.cryptoKeys/decrypt), [create version](https://cloud.google.com/kms/docs/reference/rest/v1/projects.locations.keyRings.cryptoKeys.cryptoKeyVersions/create), and [update primary](https://cloud.google.com/kms/docs/reference/rest/v1/projects.locations.keyRings.cryptoKeys/updatePrimaryVersion).

The driver supplies the existing purpose/version canonical DEKAAD bytes directly as `additionalAuthenticatedData`; REST JSON applies one base64 encoding. Do not pre-encode the logical AAD or change it between operations. The driver supplies request CRC32C checksums and checks response integrity; encrypt's version parent must exactly match the expected CryptoKey. Empty or malformed results are rejected. These checks do not replace IAM. Stored wraps use `wk:2:gcp:<base64(raw-ciphertext)>`.

Creating a version, selecting primary, and replacing database wraps are separate events. Do not report a database version upgrade after only remote administration. The same-KeyRef wizard guard prevents using the wizard as an in-place version updater; no such product endpoint is provided. Product DEK rotation is also separate. Do not disable or destroy any remote version needed by live rows or retained backups. The system rejects locally retired KEK rows even when KMS could still decrypt their ciphertext.

<a id="gcp-migration"></a>
### 13b.5 local→gcp procedure

These are acceptance steps for a suitably integrated release, not evidence that the current build has completed a production migration.

1. Satisfy §13b.1, pause competing key operations and take a consistent backup of the database, associated files and configuration. Record the recovery timestamp, application image digest/version, schema version, local KEK recovery method and target CryptoKey. Use [backup and restore](./backup-and-restore.md) with the additional key requirements in §13b.7.
2. Keep the active local mode and material. Prepare the GCP target configuration and ADC source, and prove target metadata plus encrypt/decrypt permissions in an isolated real project. Do not remove local recovery material at this stage.
3. In the release's supported admin wizard, select GCP and submit only the full target reference. Require scope validation and canary preflight. If the option or production client ownership wiring is absent, stop without switching the KEK.
4. Require all pending target wraps to coexist with source wraps after a successful transaction. Confirm the source still reads existing data and that failed operations leave no new pending rows. PostgreSQL rollback acceptance must be completed before relying on it in deployment.
5. Apply §13b.2's target configuration, remove the active local `ENCRYPTION_KEY`, and use the release's supported restart procedure. Require every current row to unwrap, old data to remain readable with unchanged ciphertext, correct inventory mode/reference, and soft retirement of source wraps. A matching key name is insufficient.
6. Record observed startup and audit results, and complete outage and recovery acceptance under §§13b.6–13b.7 before depending on continuity. Retain required key versions and recovery materials for the approved backup retention period.

<a id="gcp-continuity"></a>
### 13b.6 Availability evidence and outage acceptance

Service-object fake tests show cached data encryption/decryption and cached audit-key access continuing while the fake KMS is unavailable; operations that require KMS and a new service-object load fail. These tests do not prove that live sessions, audit delivery or a real process restart behave the same way. Do not promise uninterrupted service from this evidence.

After the release gate is satisfied, rehearse KMS unreachability and ADC rejection in an isolated full-service environment. Require observed existing-data reads, new connections, audit delivery, remote-operation refusal and cold-start refusal before accepting the deployment. Stop or recover according to the observed failure; do not change endpoint settings, bypass integrity checks or replace ciphertext with cached plaintext to force success. These full-service exercises remain outstanding.

<a id="gcp-recovery"></a>
### 13b.7 Abandonment and backup recovery

**Before switching:** preserve the current local KEK and configuration. For an unswitched pending target, use the release's supported admin abandonment operation (`DELETE /api/v1/keys/rewrap`), then check pending state, target retirement, current data reads and the audit result. Do not restore an older database just to abandon pending work. Local pending/abandon behavior has service-object fake evidence; the complete handler/wizard procedure remains unverified. Any later attempt must pass the release's target-reference guards; do not revive retired rows manually.

**After switching:** do not merely downgrade the binary, reset retired-row flags, or point the current database at a retired source KEK. Stop writes in the approved recovery environment and preserve the current evidence. Restore a consistent backup set with its compatible application image, schema, associated files and deployment configuration, following [backup and restore](./backup-and-restore.md). A pre-switch backup requires its original recoverable local KEK material. A GCP-backed backup requires the same full CryptoKey, all remote versions needed by its wrapped rows, and working authorized ADC access. A database backup does not contain the KMS KEK; credentials alone cannot recover data after required key material is lost.

Require actual unwrap of the recovered rows, old-data readback, inventory and audit consistency before reopening writes. Record the chosen recovery point, binary/image and schema compatibility, key-version dependencies and observed results. Writes after that backup point may be lost; reconcile files and external storage to the same point. A matching resource name or a newer binary proves neither compatibility nor decryptability. This is whole-backup recovery, not revival of retired rows in the current database. The complete GCP restore procedure remains unverified.

<a id="gcp-protection"></a>
### 13b.8 Protection claims and operating records

At the driver boundary, **the KEK does not enter the backend process, but DEKs and authentication credentials remain in the backend**. Password plaintext and session traffic may also exist in memory. Do not claim that the backend contains no secrets or plaintext, that all memory copies are erased, or that the product provides HSM-level protection. A deployment's choice of a Cloud KMS HSM protection level does not establish such a product-wide claim.

Record timestamps, nonsecret references, version identifiers, status codes and readback outcomes. Do not collect private keys, bearer tokens, DEKs, plaintext, or secret-bearing request/response bodies. Keep fake evidence separate from real-project evidence; real-project results remain pending credentials and acceptance, not completed because a contract test is green.

---

<a id="vault-transit"></a>
## 14. Vault Transit KEK operations

<a id="vault-availability"></a>
### 14.1 Availability and prerequisites

Production startup and delegated wizard factories now have Vault client ownership wiring. The isolated full-service test assembly exercises the formal handlers and database with real dev Vault AppRole/Transit; only its HTTP client is injected through test-only code. It verifies local→vault migration and generation restart. Production transport still requires verified HTTPS; this rehearsal does not validate a production TLS deployment.

Before applying §§14.4, 14.6 or 14.7 to a live deployment, rehearse with that deployment's compatible image/schema, durable Vault key versions, storage and TLS. Missing prerequisites require stopping. The general procedures in §§4 and 10 do not establish Vault availability; this section governs Vault, including recovery.

<a id="vault-configuration"></a>
### 14.2 TLS and deployment configuration

Provision a symmetric derived key at the fixed `transit` mount and AppRole at `auth/approle`. Use a dedicated key with export and plaintext backup disabled. Custom mounts and namespaces are not supported by this adapter. The following is a target configuration example, not a substitute for deployment rehearsal; credential values must come from the deployment's secret injection mechanism.

```dotenv
KEK_PROVIDER=kms
KEK_KMS_PROVIDER=vault
KEK_KMS_KEY_ID=custodexa-kek
KEK_VAULT_ADDR=https://vault.example.com
KEK_VAULT_ROLE_ID=
KEK_VAULT_SECRET_ID=
KEK_KMS_REGION=
ENCRYPTION_KEY=
```

Set nonempty role_id and secret_id at deployment time. Vault does not require `KEK_KMS_REGION`; leave it unset or empty. The AWS branch still requires its region. Delegated mode rejects a nonempty `ENCRYPTION_KEY`. Before a local-to-Vault switchover, keep the existing `KEK_PROVIDER` and local material until the procedure explicitly says to change them.

`KEK_KMS_KEY_ID` accepts the key name or the canonical reference `vault:<base64url-without-padding(HTTPS-origin)>:transit:<key-name>`. Key names contain only ASCII letters, digits, `_` and `-`; the entire reference is at most 255 bytes. The origin is canonical HTTPS scheme/host/port, without a path, query, credentials or fragment. The reference has no key version or credential. A target reference must resolve to the deployment origin; a wizard request cannot supply a different address or credential.

Production transport requires HTTPS with certificate verification and TLS 1.2 or newer, and refuses redirects. Ensure the backend runtime trusts the server certificate through its system trust store. Do not use `VAULT_ADDR`, `VAULT_TOKEN`, `VAULT_CACERT`, `VAULT_SKIP_VERIFY` or other Vault SDK environment overrides: the adapter rejects them, and it has no custom CA-file or client-certificate setting. Environment proxy settings are not used by this transport. The loopback HTTP dev fixture is accessible only through private test injection; dev mode is not a production TLS or persistence solution.

<a id="vault-authentication"></a>
### 14.3 AppRole permissions and token renewal

Give the product identity only metadata read and encrypt/decrypt/rewrap on its named key, plus token self-renewal. For a key named `custodexa-kek`, the policy shape is:

```hcl
path "transit/keys/custodexa-kek" { capabilities = ["read"] }
path "transit/encrypt/custodexa-kek" { capabilities = ["update"] }
path "transit/decrypt/custodexa-kek" { capabilities = ["update"] }
path "transit/rewrap/custodexa-kek" { capabilities = ["update"] }
path "auth/token/renew-self" { capabilities = ["update"] }
```

Replace the key name consistently. Do not attach other policies that grant wildcard key access, rotate, export or global administration. Provision mounts, keys, policies and AppRole separately with an administrator identity. The product does not accept a root token as an authentication fallback. See the [AppRole API](https://developer.hashicorp.com/vault/api-docs/auth/approle) and [token API](https://developer.hashicorp.com/vault/api-docs/auth/token).

The client validates the auth token and a positive lease, renews at half the returned lease, and reschedules using the new lease. A nonrenewable token is not forcibly renewed. Retryable renewal faults have at most two retries; at expiry or an observed rejection, one login flow may reuse the configured SecretID if it is still valid. Failed login terminates that client; it does not switch provider. A revoked token can be detected only when Vault rejects an operation or renewal, or its local lease ends. Token renewal does not rotate a KEK or a DEK.

<a id="vault-secretid"></a>
### 14.4 Replacing a SecretID

This deployment procedure requires the availability gate in §14.1. The client retains the credentials supplied at construction; editing an environment source does not hot-reload an existing client. There is no product endpoint for rotating or injecting AppRole credentials into a running client.

1. Record the role, policy, token/SecretID TTL and use limits, and the maintenance/recovery window without recording credential values. Ensure the replacement SecretID can be used for the planned login and any permitted recovery login. A one-use SecretID consumed by a test login cannot also be used by the backend; issue a separate SecretID for the test.
2. Have the Vault administrator issue a replacement SecretID. Deliver it through the approved deployment secret channel, not a ticket, command-line argument, log or tracked file. Keep role_id and secret_id out of collected response bodies and shell tracing.
3. In the isolated full-service environment, reconstruct the client through the release's supported restart procedure with the replacement injected as `KEK_VAULT_SECRET_ID` (and `KEK_VAULT_ROLE_ID` if the role changed). Require successful login, named-key metadata/canary and renewal before repeating the procedure in production. Fresh AppRole clients and service generations have been exercised in the test assembly; this does not establish deployment-specific SecretID replacement and renewal readiness.
4. After successful adoption, have the administrator invalidate the old SecretID by its accessor and separately retire the old client token as appropriate. Destroying a SecretID prevents later logins with it; it does not by itself revoke tokens already issued from it. If credentials are suspected compromised, revoke them promptly and accept the resulting unavailability of Vault-dependent operations; do not retain access solely to avoid downtime.
5. If adoption fails, stop the switchover and restore an authorized deployment configuration or issue fresh credentials. Do not assume an old SecretID still has remaining uses or that a revoked token can be renewed.

<a id="vault-actions"></a>
### 14.5 Four operations and two different rotations

| Operation | Vault request | Effect and boundary |
| --- | --- | --- |
| Wrap a DEK | `POST /v1/transit/encrypt/<key>` | Sends base64 DEK plus context; reads `data.ciphertext`. The KEK stays in Vault. |
| Unwrap a DEK | `POST /v1/transit/decrypt/<key>` | Sends the complete ciphertext and original context; decodes `data.plaintext` into the backend DEK. |
| Rotate the remote KEK version | `POST /v1/transit/keys/<key>/rotate` | Administrator operation; creates a new version of the same named key. It does not change the key reference or rewrite database wrapped rows. The product AppRole cannot rotate. |
| Rewrap an old ciphertext under the same named key | `POST /v1/transit/rewrap/<key>` | Returns a new `data.ciphertext` without plaintext in the response. The provider returns that value; it does not persist it to the database. |

See the [Transit API](https://developer.hashicorp.com/vault/api-docs/secret/transit). The driver sends the existing purpose/version canonical AAD bytes as `context=base64(aad)` exactly once. `context` derives the key; it is not AEAD `associated_data`, which this driver does not use. Keep the original context on decrypt and rewrap. The complete `vault:v<n>:` ciphertext retains the remote version; storage uses `wk:2:vault:<base64(complete-transit-ciphertext)>`.

Remote version rotation and product KEK-reference replacement are different procedures. Remote rotate alone never means that database wraps have moved to the new version. The product's same-KeyRef guard prevents using the wizard as an in-place database version upgrader; no such upgrade endpoint is provided. Do not manually rewrite wrapped rows. Product DEK rotation is a third, separate operation and is not a substitute for Vault rotate.

At provider level, conversion from another key or provider uses source unwrap followed by target encrypt; native Transit rewrap is only for the same named key and origin. The service rewrap path uses already cached DEKs and target Wrap within its existing database transaction. The full-service handler evidence and its limits are described in §14.1. Do not raise `min_decryption_version` or delete old remote versions while any live or retained-backup wrap needs them. Local KEK-row retirement remains enforced by the system even when Vault can decrypt the old version.

<a id="vault-migration"></a>
### 14.6 local→vault procedure

Execute only after §14.1 is satisfied, first in an isolated full-service environment. These are required steps and acceptance checks, not a claim of a completed production migration.

1. Freeze competing key operations. Capture a consistent database and required file/configuration backup, record its timestamp, application image digest/version, schema version, source KEK recovery method, and target Vault origin/key and retained versions. Protect secret material separately. Use [backup and restore](./backup-and-restore.md) for the base backup procedure; the Vault qualifications in §§14.2 and 14.7 also apply.
2. Provision TLS, the derived target key and restricted AppRole. Inject the Vault settings while keeping the active local mode/material. Check login, metadata, encrypt/decrypt and renewal using a separate test SecretID; keep the deployment SecretID usable.
3. In the release's supported admin rewrap wizard, choose Vault and submit only its canonical reference. Require successful target preflight. If the Vault option or client ownership wiring is unavailable, stop without changing the active KEK.
4. Require the pending target wraps and source wraps to coexist, and confirm the source still reads the data. Do not remove source recovery material or clear retired material before the recovery window is resolved.
5. Change to the target configuration in §14.2, remove the local `ENCRYPTION_KEY`, and use the supported restart procedure. Require actual unwrap of every current representative row, readable pre-existing data with unchanged ciphertext, correct inventory mode/reference and soft retirement of source wraps. A matching reference alone is insufficient.
6. Record the observed startup, login, renewal and audit results. Rehearse unavailable Vault and cold-start failure behavior in the isolated environment before depending on service continuity. The test assembly has observed cached data crypto, a reused HTTP connection and new audit writes continuing when its route to real Vault is disconnected; Vault-required operations and cold unseal fail. This does not establish SSH/RDP session continuity or deployment-wide availability.

<a id="vault-recovery"></a>
### 14.7 Abandonment and backup recovery

Both procedures require the full-service gate in §14.1. An isolated Vault alone cannot exercise the product database, wizard abandonment or restore. Do not use the dev fixture as a durable key backup.

**Before switching:** keep the current local KEK and configuration. Use the supported admin abandonment operation (`DELETE /api/v1/keys/rewrap`) only for an unswitched pending target. Check that pending converges, the current data remains readable, and the abandoned target is recorded as retired. Do not revive retired rows. An abandoned delegated reference may be submitted again through the wizard, subject to fresh preflight and the existing same-current-reference, live-row and pending guards; abandonment does not permanently burn that remote key. Capture the operation time and audit result. Do not restore an older database merely to abandon an unswitched operation. The real-Vault handler rehearsal observed HTTP 200 for abandonment, zero pending, retained wrapped material with retirement reason `abandoned`, local readback and an audit record; it loses no business writes.

**After switching:** do not simply revert the binary, reset flags on retired rows, or reconfigure a retired source KEK against the current database. In the approved recovery environment, stop writes and preserve the current evidence, then restore a consistent backup set using the compatible application image and schema, associated files and deployment configuration. Follow [backup and restore](./backup-and-restore.md); its AWS credential assumptions do not apply to Vault AppRole secrets. Obtain the KEK required by that backup: source local material for a pre-switch backup, or the same Vault origin/named key with every required remote version plus working AppRole credentials for a Vault-backed backup. This is whole-backup recovery, not resurrection of retired rows in the current database. Test actual row unwrap and old data reads, inventory and audit consistency before allowing writes.

Record the chosen recovery timestamp, binary/image and schema compatibility, configuration/credential custody, required remote key versions and observed readback results. Writes after the recovered database point are outside that backup and may be lost; reconcile associated files and external storage against the same point. A newer application or a matching key label is not proof of compatibility or decryptability. If the necessary KEK versions or recoverable local material are lost, credentials alone cannot recover the data. The rehearsal scope below is narrower than a deployment backup/restore.

**Completed isolated rehearsal and limits:** Rollback against Vault has been rehearsed in an isolated environment. The rehearsal first performs the unswitched abandonment above, then switches a separate full-service fixture to Vault and selects a **post-switch Vault-backed** recovery point. After sealing and draining cleanup, it closes the journal and snapshots the whole SQLite database (all tables), seal journal and protected configuration. It records the exact test binary hash, schema hash, toolchain, timestamp, canonical reference and required remote versions. It resumes service, commits one later data row, freezes writes again and preserves the current database/journal before restoring the backup into fresh paths and a new service machine with fresh AppRole credentials. It verifies backup row/audit/file consistency before unseal, then actual unwrap of every live row, unchanged old ciphertext, readable data and kms/vault inventory. The later row is absent, making the recovery-point loss explicit; retired source rows stay retired.

This uses the same test binary and schema, with no recordings or external storage configured. It is **not** a `pg_dump`/`pg_restore`/`tar` rehearsal of the deployment described in [backup and restore](./backup-and-restore.md), nor proof of cross-version compatibility, restoration of Vault storage, or restoration of a pre-switch local backup. Those require separate deployment evidence; do not infer them from the SQLite result. Keep recoverable source material for a pre-switch backup and durable remote versions for a Vault-backed backup, regardless of the successful lab result.

<a id="vault-protection"></a>
### 14.8 Protection claims and operational records

At the driver boundary, **the KEK does not enter the backend process, but DEKs and authentication credentials remain in the backend**. Password plaintext and session traffic can also exist in memory. Do not claim that memory contains no plaintext, that all copies are erased, or that the product provides HSM-level protection. Deployment choices for Vault storage or seal protection do not establish such a product claim.

Keep operating records to timestamps, nonsecret references, versions, status codes and readback outcomes. Do not collect tokens, role_id, secret_id, DEKs, plaintext or secret-bearing request/response bodies. The full-service test observes an existing HTTP connection, new audit writes and cached data crypto during a disconnected real-Vault route. It does not prove SSH/RDP continuity, production TLS, PostgreSQL restore or external-storage recovery; deployments must rehearse those dependencies.

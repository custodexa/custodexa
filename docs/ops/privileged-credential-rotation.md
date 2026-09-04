# Rotating the Platform's Own Privileged Credentials

**English** | [繁體中文](../zh-TW/ops/privileged-credential-rotation.md) | [日本語](../ja/ops/privileged-credential-rotation.md) | [More languages →](../README.md)

> Applies to: Custodexa 1.0.
>
> **The scope of this page is the credentials the system itself holds**: the service account passwords, encryption keys, and signing keys the platform must hold in order to operate. Rotating account credentials on managed assets (credential change) is not covered here; that is a product feature rather than an operational procedure. For Windows target prerequisites, see the Windows local account credential change section of §2.5 in the [Deployment and Upgrade SOP](./upgrade-sop.md).
>
> Related documents: [Backup and Restore](./backup-and-restore.md), [Deployment and Upgrade SOP](./upgrade-sop.md).

---

## 1. Summary table

| Credential | Stored in | Rotation entry point | When it takes effect | Interrupts existing connections or sign-ins | External coordination needed |
|---|---|---|---|---|---|
| LDAP bind password | Database (envelope encrypted) | Identity & Access → LDAP Directory (UI) | Immediately | No | Must be changed on the directory server first |
| Notification channel secret | Database (envelope encrypted) | Notification Channels (UI) | Immediately (same process) | Not applicable | The receiving end must be updated in step |
| Notification channel URL | Database (envelope encrypted) | Notification Channels (UI) | Immediately (same process) | Not applicable | — |
| Offsite storage credentials (offsite evidence storage) | Database (envelope encrypted, one set per settings generation) | System Settings → Offsite Storage (UI) | As soon as the save succeeds | No | The storage side must create the new credentials first and revoke the old ones afterwards |
| KEK (key encryption key) | Depends on mode: env / memory / KMS | Key Management → KEK rewrap wizard | After the rewrap completes | No | Mode C needs a key on the KMS side |
| DEK (data key) | Database (wrapped by the KEK) | Key Management (`POST /keys/rotate`) | Immediately | No | — |
| Audit stamping key | Database (wrapped by the KEK) | Key Management (`POST /keys/rotate`) | Immediately | No | — |
| `ENCRYPTION_KEY` (KEK material, mode A) | `.env` | Through the KEK rewrap wizard, not by editing env directly | After the rewrap and a restart | Yes (restart) | — |
| KEK material (mode B, `KEK_PROVIDER=ui`) | Memory only (entered at unseal) | Through the KEK rewrap wizard | After the rewrap, a restart, and an unseal | Yes (restart, and service resumes only once someone unseals) | — |
| `JWT_SECRET` | `.env` | Edit env, then restart | After the restart | **Yes, everyone is signed out** | — |
| Ed25519 export signing key | Database (envelope encrypted private key) | System-managed; through the data layer if required (see §8) | — | — | **Yes, the public key must be redistributed** |
| Ed25519 checkpoint signing key | Database (envelope encrypted private key) | System-managed; the related endpoints are read-only (see §9) | — | — | **Yes, the public key must be redistributed** |
| `METRICS_TOKEN` | `.env` | Edit env, then restart | After the restart | No (the collector must be updated in step) | The collector must be updated in step |

Where the "external coordination needed" column is not empty, **if that coordination is not completed after the rotation the failure is silent**. Pay particular attention to §8, §9, and §3.

---

## 2. LDAP bind password

**Stored in**: the `bind_password_enc` column of the `ldap_directories` table (envelope encrypted). That table is a single-row settings table; a deployment has exactly one LDAP directory configuration. The column is write-only: no API response returns it, and the edit form cannot prefill it.

**Rotation procedure**:

1. Change the service account's password on the directory server (AD or LDAP) first.
2. Admin side → Identity & Access → LDAP Directory → enter the new password.
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

> ### A silent degradation path you have to know about
>
> When the channel cache is refreshed, the URL and secret are decrypted into the plaintext used for delivery. **If either fails to decrypt, that channel is skipped outright with no delivery, and only a single log line is written; no alert is produced, and the channel still looks normal in the UI.**
>
> This is a deliberate trade-off (better nothing than sending ciphertext as a URL), but the price is that **"looks fine in the interface" does not mean "is delivering."**
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
2. Admin side → System Settings → Offsite Storage → enter the new credentials.
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

The KEK is the root of the whole envelope encryption scheme. Rotating it is called a **rewrap** in this product: the existing data keys are wrapped again with a new KEK, and the data itself is not re-encrypted.

**Entry point**: the Key Management page → KEK rewrap wizard (admin only). The related APIs are all admin only:

| Endpoint | Purpose |
|---|---|
| `POST /api/v1/keys/rewrap` | Perform a rewrap |
| `DELETE /api/v1/keys/rewrap` | Abandon a rewrap that has not switched over |
| `DELETE /api/v1/keys/retired-material` | Clear the material of retired KEKs, **the only place material is destroyed** |

**An important property: material is kept after retirement until it is cleared explicitly.**
KEK retirement is a soft retirement: only the status column changes, and the wrapping material is not cleared. So **until "clear retired data" is run, rolling back to an old KEK at the data layer is always possible** (a last resort, handled manually per §10.4). After the clear runs the material is emptied and unrecoverable; the retirement trail (source, target, timestamps) and the fingerprints are kept permanently.

**Abandoning a rewrap**: the abandoned target is marked retired (with the reason recorded as abandoned) rather than deleted. On a later rewrap the system refuses to reuse any key reference that has appeared before (including retired records), so a brand-new key must be used.

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

## 5. DEK and the audit stamping key

**Entry point**: the Key Management page, or `POST /api/v1/keys/rotate` (admin only), with `purpose` naming what to rotate:

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

> **It interrupts every user: all existing tokens become invalid immediately and everyone has to sign in again.**
> Old tokens were signed with the old key and no longer verify after the change, which is inherent to rotating a signing key.
> Schedule a maintenance window and notify users in advance.

In release mode the system detects whether `JWT_SECRET` is still the factory placeholder value and refuses to start if it has not been changed.

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
3. **The audit record contains a record of this rotation.** Key operations are all admin only and are audited; clearing material additionally records the number of rows cleared and the fingerprint of each key version.
4. If you touched a key on the env side, confirm the startup log after the restart has no fail-closed message.

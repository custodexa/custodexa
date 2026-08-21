# sftp-files

## Purpose

SSH 資產的 SFTP 檔案管理與全操作審計。
## Requirements
### Requirement: Asset-gated SFTP file operations

The system SHALL provide file management (list, upload, download, mkdir, delete) for SSH assets over SFTP, gated by the same asset reference and connect authorization as terminal sessions. Credentials MUST be resolved backend-side; clients send only token and asset_id. Unauthorized access SHALL be rejected with 404 (asset not found semantics, consistent with per-asset visibility gating; MUST NOT reveal asset existence).

The gate order is: authorization check first (rejecting with 404 on failure), then the existence/disabled gate, then the access-policy gate, **then the data-transfer gate**. Within the existence/disabled gate the system SHALL distinguish "asset does not exist" from "asset exists but is disabled": a request naming an asset that does not exist SHALL be rejected with 404 (asset not found semantics) and MUST NOT be reported as disabled; only an existing asset with `active = false` SHALL be rejected with 403 and `reason = asset_disabled`.

This distinction MUST hold for every caller that reaches the gate, which includes both callers whose authorization check short-circuits (admin) and callers holding an authorization grant that outlives its asset (asset deletion is a soft delete and does not revoke grants, and the permission query does not join `assets`).

**Data-transfer gate**: connect authorization alone SHALL NO LONGER imply permission to perform every file operation. Upload and mkdir SHALL additionally require the effective `file_upload_enabled` capability, download SHALL require `file_download_enabled`, and delete SHALL require `file_delete_enabled`, where "effective" is resolved per `data-transfer-control` (currently the global policy key alone). Listing a directory SHALL NOT be gated by this capability set. The data-transfer gate SHALL run after the access-policy gate and SHALL apply to every caller including admin (no role exemption). A rejection SHALL return a registered machine-readable error code distinct from the authorization rejection (the asset exists and the caller may connect — hiding that behind 404 would mislead), and SHALL be recorded in the audit log with status `denied`.

The system SHALL additionally expose a read-only effective-capability endpoint for the UI, gated by the **same** asset-level checks as the file endpoints (role recheck, connect authorization, asset enabled, access-policy tier; unauthorized callers receive 404). It SHALL NOT be relaxed on the grounds of "only reading capabilities" — a laxer gate would turn it into an asset-existence probe. Its resolution failures SHALL be presented as all-denied rather than returned as a server error, so the UI never falls back to showing everything as available.

#### Scenario: List a remote directory

- **WHEN** an authorized user lists path /tmp on an SSH asset
- **THEN** the response contains entries with name, size, modification time and directory flag

#### Scenario: Upload and download round-trip

- **WHEN** the user uploads a file to the asset and downloads the same remote path
- **THEN** the downloaded content is byte-identical to the uploaded file

#### Scenario: Unauthorized user blocked

- **WHEN** a user without connect permission on the asset calls any file endpoint
- **THEN** the request is rejected with 404 (indistinguishable from a nonexistent asset) before any SFTP connection is made

#### Scenario: Nonexistent asset is not reported as disabled

- **WHEN** an admin (whose permission check short-circuits) calls any file endpoint with an asset_id that does not exist
- **THEN** the request is rejected with 404 (asset not found semantics), not 403 `asset_disabled`

#### Scenario: Soft-deleted asset with a surviving grant is not reported as disabled

- **WHEN** a non-admin user holding a connect grant on an asset that was subsequently deleted (soft delete, grant not revoked) calls any file endpoint for it
- **THEN** the request is rejected with 404 (asset not found semantics), not 403 `asset_disabled`

#### Scenario: Disabled asset blocked

- **WHEN** a caller that passes the authorization check, including an admin, calls a file endpoint on an existing asset with `active = false`
- **THEN** the request is rejected with 403 and `reason = asset_disabled`

#### Scenario: Path traversal rejected

- **WHEN** a request path contains ".." segments or is not absolute
- **THEN** the request is rejected with a validation error

#### Scenario: Transfer capability denied

- **WHEN** a user with connect permission calls the download endpoint while the effective `file_download_enabled` capability is false
- **THEN** the request is rejected with a registered machine-readable code distinct from the authorization rejection, no SFTP read occurs, and an audit entry with action `file_download` and status `denied` is written

#### Scenario: Admin not exempt from the transfer gate

- **WHEN** an admin calls the delete endpoint while the effective `file_delete_enabled` capability is false
- **THEN** the request is rejected identically to a non-admin caller

#### Scenario: Listing survives a full transfer lockdown

- **WHEN** all five data-transfer capabilities are false and an authorized user lists a directory
- **THEN** the listing succeeds

#### Scenario: Capability endpoint is gated like the file endpoints

- **WHEN** a user without connect permission calls the effective-capability endpoint for an asset
- **THEN** the request is rejected with 404 (indistinguishable from a nonexistent asset)

### Requirement: File operation audit
Every successful file operation SHALL be recorded in the audit log with the acting user, asset, operation type and remote path. **Every file operation rejected by the data-transfer gate SHALL likewise be recorded, with the same action value as its successful counterpart (mkdir stays `file_mkdir` even though the gating key is `file_upload_enabled`) and status `denied`, plus the rejection source.** Audit SHALL NOT be written only on the success path.

#### Scenario: Upload is audited
- **WHEN** a user uploads a file to an asset
- **THEN** an audit log entry exists with action file_upload, the asset reference and the remote path

#### Scenario: Denied upload is audited
- **WHEN** a user's upload is rejected by the data-transfer gate
- **THEN** an audit log entry exists with action file_upload, status denied, the asset reference, the remote path and the rejection source

#### Scenario: Denied mkdir keeps its own action value
- **WHEN** a user's mkdir is rejected by the data-transfer gate (gated by the upload capability)
- **THEN** the audit entry records action file_mkdir with status denied, not file_upload

### Requirement: File manager UI
The SSH terminal page SHALL offer a file manager panel supporting directory browsing, upload, download, mkdir and delete. **Actions whose effective capability is false SHALL be presented as unavailable with a reason, rather than failing only on click**; the panel SHALL nonetheless remain usable for browsing. The UI state SHALL be derived from a server-provided capability set, SHALL NOT be inferred client-side from role or policy values, and SHALL NOT be treated as the enforcement point (the server gate remains authoritative).

#### Scenario: Browse and download from terminal page
- **WHEN** the user opens the file panel during an SSH session and clicks a file's download action
- **THEN** the browser downloads the file content

#### Scenario: Unavailable actions are shown as unavailable
- **WHEN** the user opens the file panel while the effective upload and delete capabilities are false
- **THEN** the upload and delete controls are shown as unavailable with a reason, browsing and download still work

#### Scenario: Client-side state is not the gate
- **WHEN** a client bypasses the disabled control and calls the upload endpoint directly
- **THEN** the server rejects the request


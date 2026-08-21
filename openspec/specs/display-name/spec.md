# display-name Specification

## Purpose
規範使用者自助設定的顯示名稱：本地顯示名稱欄位與其更新端點、顯示名稱解析的單一事實來源，以及顯示名稱的作用範圍限制。
## Requirements
### Requirement: Self-service local display name field
The system SHALL provide a nullable `local_display_name` field on the user account, editable by the account owner via self-service. It SHALL default to NULL on account creation and MUST NOT be initialized from `username`, `full_name`, or any IdP-supplied value. A trimmed empty (or whitespace-only) submission SHALL be stored as NULL, clearing the override. The field SHALL NOT carry a uniqueness constraint (display names may repeat).

#### Scenario: New account has null display name
- **WHEN** a user account is created (local, or a future IdP-provisioned shadow account)
- **THEN** `local_display_name` is NULL and the resolved display name is produced by the resolver fallback

#### Scenario: Clearing reverts to fallback
- **WHEN** the owner submits a blank or whitespace-only display name
- **THEN** `local_display_name` is stored as NULL and the resolved display name falls back to `full_name` or `username`

### Requirement: Self-service display name update endpoint
The system SHALL expose a self-service endpoint `PATCH /api/v1/auth/me` that updates only `local_display_name` for the authenticated user. The target user SHALL be derived solely from the session token claims and MUST NOT accept a user ID from path or body. The endpoint MUST re-check account active status and reject disabled or deleted accounts. It SHALL validate input (length cap, reject control characters and newlines, treat whitespace-only as clear) and SHALL reject any attempt to set other fields (`full_name`, `email`, `username`, `role`, `active`, `is_ldap`). On success it SHALL return the canonical `UserInfo` including the resolved `display_name`. The action SHALL be audited as `resource=user`, `resource_id`= the authenticated user's ID.

#### Scenario: Successful self update
- **WHEN** the authenticated owner submits a valid `local_display_name`
- **THEN** the value is stored and the response returns the canonical `UserInfo` with the updated resolved `display_name`

#### Scenario: Other fields rejected
- **WHEN** the request body includes `full_name`, `email`, `role`, `active`, `username`, or `is_ldap`
- **THEN** the endpoint does not modify those fields (rejects the attempt), only `local_display_name` is ever writable here

#### Scenario: Identity bound to token
- **WHEN** the request carries a path or body user ID different from the token subject
- **THEN** the update applies only to the token's own user, never to the specified other user

#### Scenario: Disabled account rejected
- **WHEN** a token belongs to an account that has since been disabled or deleted
- **THEN** the endpoint rejects the update after re-checking active status

#### Scenario: Input validation
- **WHEN** the submitted display name exceeds the length cap or contains control characters/newlines
- **THEN** the endpoint rejects it with a validation error

#### Scenario: Audit classification correct
- **WHEN** the self update succeeds
- **THEN** the audit entry is classified as `resource=user`, `resource_id`= the authenticated user's ID (not `resource=auth` without an id)

### Requirement: Display name resolution single source of truth
The system SHALL compute the resolved display name as `local_display_name || full_name || username` in a single shared resolver, returned by `GET /api/v1/auth/me` as a computed `display_name`. Consumers MUST NOT each implement their own fallback chain.

#### Scenario: Override wins
- **WHEN** `local_display_name` is set
- **THEN** the resolved `display_name` equals `local_display_name`

#### Scenario: Falls back to full name
- **WHEN** `local_display_name` is NULL and `full_name` is present
- **THEN** the resolved `display_name` equals `full_name`

#### Scenario: Falls back to username
- **WHEN** both `local_display_name` and `full_name` are NULL or empty
- **THEN** the resolved `display_name` equals `username`

### Requirement: Display name scope restriction
The resolved display name SHALL be used only on decorative or self-view surfaces (login greeting, sidebar own-name, Profile page). Identity-sensitive surfaces — audit log actor, authorization subject, approver display, admin user management lists, session owner, and live session monitoring — SHALL display `username` (optionally with authoritative `full_name`) and MUST NOT use `local_display_name` or the resolved `display_name`, because a self-editable, non-unique display name could otherwise be used to impersonate another identity.

#### Scenario: Greeting uses display name
- **WHEN** the login greeting or the sidebar renders the current user's own name
- **THEN** it uses the resolved `display_name`

#### Scenario: Audit and authorization use username
- **WHEN** an audit log actor, an authorization subject, an approver, an admin user list, a session owner, or live monitoring renders a user identity
- **THEN** it uses `username` and never `local_display_name` or the resolved `display_name`


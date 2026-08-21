# user-profile

## Purpose

個人自助頁：帳號資訊、自助改密與 MFA 管理的單一入口。
## Requirements
### Requirement: Self-service profile page
The system SHALL provide a `/profile` page available to all authenticated roles, containing: read-only identity information (username, `full_name`, email, roles, MFA status from `GET /auth/me`); a self-service display name (`local_display_name`) that the owner can edit and clear via `PATCH /api/v1/auth/me`, with the effective name reflected through the resolved `display_name`; self-service password change (via the existing `POST /auth/change-password` endpoint with the current session token, with inline validation and near-field error display); and MFA management (status display, secret generation with a scannable QR code of the otpauth URL as the primary binding path plus manual-entry secret as fallback, enable with 6-digit code, disable with password) migrated from the layout header dialog. The page SHALL make clear the distinct roles of `username` (login identity), `full_name` (authoritative identity, read-only), and the self-editable display name. The header dropdown SHALL offer a single 個人資料 entry navigating to this page, replacing the previous placeholder and the separate 安全設定 dialog entry. For LDAP-provisioned accounts (`is_ldap` from `GET /auth/me`), the password-change card SHALL be replaced by a notice that the password is managed by the directory service, and the identity fields (`full_name`, `email`) SHALL remain read-only as managed by the directory service while `local_display_name` remains self-editable.

#### Scenario: Profile page renders account info
- **WHEN** any authenticated user opens /profile
- **THEN** username, full_name, email, role chips, and MFA status are displayed read-only, and the current display name is shown

#### Scenario: Self display name edit
- **WHEN** the owner edits and submits a valid display name on /profile
- **THEN** it is saved via `PATCH /auth/me`, the resolved `display_name` updates, and the cached user (e.g. sidebar name) reflects the new value without requiring re-login

#### Scenario: Self display name cleared
- **WHEN** the owner clears the display name field and submits
- **THEN** `local_display_name` is set to NULL and the shown name falls back to full_name or username

#### Scenario: Self password change
- **WHEN** the user submits current and new passwords passing policy validation
- **THEN** the password is changed via the existing endpoint and a success message is shown; policy violations are shown inline without a global toast

#### Scenario: MFA management migrated
- **WHEN** the user manages MFA (enroll or disable) from /profile
- **THEN** the flows behave as the former header dialog did, and the header dropdown no longer offers a separate 安全設定 dialog

#### Scenario: MFA setup shows QR code
- **WHEN** the user starts MFA setup on /profile
- **THEN** a QR code of the otpauth URL is rendered for scanning, with the manual-entry secret still available

#### Scenario: Placeholder removed
- **WHEN** the user opens the header dropdown and selects 個人資料
- **THEN** the app navigates to /profile instead of showing a「開發中」message

#### Scenario: LDAP account identity fields and password
- **WHEN** an LDAP shadow account opens /profile
- **THEN** the password-change form is not offered (a notice explains the password is managed by the directory service), full_name and email are read-only as directory-managed, and the display name remains self-editable


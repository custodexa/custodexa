# mfa-totp

## Purpose

TOTP 雙因素認證的綁定、驗證與恢復流程，涵蓋自願啟用與依安全政策強制註冊（PCI 8.4.2）的閘門，以及防止已消耗驗證碼被重放的 time-step 防護（PCI 8.5.1）。

## Requirements
### Requirement: TOTP enrollment
An authenticated user SHALL be able to generate a TOTP secret (otpauth URL + base32 secret) and enable MFA by proving possession with a valid code. The secret MUST be stored encrypted; enabling MUST be rejected for an invalid code. Both enrollment surfaces (the profile self-service panel and the forced-enrollment login step) SHALL render the otpauth URL as a scannable QR code (locally generated in the browser — the secret SHALL NOT be sent to any third-party or additional endpoint for rendering), with the base32 secret retained as the manual-entry fallback; if QR rendering is unavailable the manual path SHALL remain fully functional.

#### Scenario: Successful enrollment
- **WHEN** the user requests MFA setup and submits a valid TOTP code from the generated secret
- **THEN** MFA is enabled for the account and the event is audit-logged

#### Scenario: Invalid code rejected
- **WHEN** the user submits an incorrect code during enable
- **THEN** MFA remains disabled and an error is returned

#### Scenario: QR code shown on both enrollment surfaces
- **WHEN** the user opens MFA setup from /profile, or a policy-forced user reaches the login enrollment step
- **THEN** a QR code encoding the otpauth URL is displayed for authenticator-app scanning, alongside the manual-entry secret

### Requirement: Two-phase login for MFA users
For users with MFA enabled, password authentication SHALL NOT issue a session JWT directly; it returns `mfa_required` with a short-lived pending token (5 minutes) valid only for the TOTP verification endpoint. A valid TOTP code exchanges the pending token for a session JWT.

#### Scenario: MFA login success
- **WHEN** an MFA-enabled user submits correct credentials then a valid TOTP code
- **THEN** a session JWT is issued and login success is audit-logged

#### Scenario: Wrong TOTP code
- **WHEN** the user submits an invalid TOTP code with a valid pending token
- **THEN** no JWT is issued and the failure is audit-logged

#### Scenario: Pending token cannot access APIs
- **WHEN** a pending token is presented to any API other than MFA verification
- **THEN** the request is rejected as unauthenticated

#### Scenario: Non-MFA user unaffected
- **WHEN** a user without MFA submits correct credentials
- **THEN** a session JWT is issued in one step exactly as before

### Requirement: MFA disable paths
The account owner SHALL be able to disable own MFA by re-authenticating with password; an admin SHALL be able to disable MFA for a locked-out user. Both events MUST be audit-logged.

#### Scenario: Self disable
- **WHEN** an MFA-enabled user requests disable with the correct password
- **THEN** MFA is disabled and audit-logged

#### Scenario: Admin rescue
- **WHEN** an admin disables MFA for another user
- **THEN** that user can log in with password only and the action is audit-logged with the admin identity

### Requirement: MFA 強制註冊
安全政策 `mfa_required` SHALL 為三態：未啟用/僅管理員/所有用戶（出廠預設未啟用——易用取向；PCI 8.4.2 建議值為所有用戶，隨一鍵套用開啟）。對受強制範圍內的使用者，未註冊 TOTP 者通過密碼驗證後 SHALL NOT 取得正式會話，改回 `mfa_enrollment_required` 與 enrollment scoped token；該 token SHALL 僅可存取 TOTP 綁定端點（setup/confirm）。完成綁定前 SHALL NOT 可存取任何一般 API。LDAP 影子用戶 SHALL 同樣適用。政策未啟用時 SHALL 維持既有 opt-in 行為。強制註冊流程 SHALL 僅適用於尚未註冊 TOTP 的使用者：setup 與 confirm 端點在動作前 SHALL 重新查核 `totp_enabled`，已註冊者一律拒絕——防洩漏的 enrollment token（TTL 內）被重放以重置並改綁已註冊帳號的第二因子。綁定確認的驗證碼失敗 SHALL 計入與登入共用的帳號鎖定計數。

#### Scenario: 僅管理員檔位
- **WHEN** 政策設為「僅管理員」且未註冊 TOTP 的 admin 與一般 user 分別登入
- **THEN** admin 被導向綁定流程，一般 user 直接取得正式會話

#### Scenario: 未註冊者被導向綁定
- **WHEN** 政策已開啟且未註冊 TOTP 的使用者以正確密碼登入
- **THEN** 回 mfa_enrollment_required 與 enrollment token，不發正式會話

#### Scenario: enrollment token 不可越權
- **WHEN** enrollment token 被用於 TOTP 綁定以外的 API
- **THEN** 請求被拒為未認證

#### Scenario: 綁定完成後直接換發會話
- **WHEN** 使用者以 enrollment token 完成 TOTP 綁定確認
- **THEN** 直接換發正式會話（不重走登入、不需再輸密碼或再驗一次 TOTP）

#### Scenario: 已註冊帳號不可經 enrollment token 改綁
- **WHEN** 使用者已完成 TOTP 綁定後，同一枚（TTL 未過的）enrollment token 再次用於 setup 或 confirm
- **THEN** 請求被拒（帳號已註冊），既有第二因子不被重置或改綁，事件入審計

#### Scenario: 綁定確認碼失敗計入鎖定
- **WHEN** 使用者於綁定確認連續提交錯誤 TOTP 碼達鎖定門檻
- **THEN** 帳號被鎖定（與登入驗證共用計數），後續嘗試一律拒絕

#### Scenario: 政策關閉維持 opt-in
- **WHEN** 政策關閉且未註冊 TOTP 的使用者以正確密碼登入
- **THEN** 直接取得正式會話（與現行行為相同）

### Requirement: TOTP 防重放
系統 SHALL 記錄每個使用者最後成功消耗的 TOTP time-step 索引（⌊unix/30⌋），並拒絕 step 索引小於或等於該值的驗證（PCI 8.5.1：MFA 系統不得受重放攻擊影響）。此防護 SHALL 以 step 索引為單位而非時間窗——因驗證容忍 skew（同一碼在相鄰 step 皆有效），僅比對「同窗」無法擋跨窗重放。並發驗證 SHALL 以原子更新（CAS）避免競態。此防護 SHALL 涵蓋登入驗證與綁定確認兩條路徑。

#### Scenario: 已消耗 step 的碼重放被拒
- **WHEN** 一個剛驗證成功的 TOTP 碼（step N）再次提交，即使落在相鄰 skew 窗
- **THEN** 驗證被拒（step ≤ 已消耗索引）且事件入審計

#### Scenario: 下一 step 新碼正常
- **WHEN** time-step 前進後使用者提交新產生的碼（step > 已消耗索引）
- **THEN** 驗證正常通過


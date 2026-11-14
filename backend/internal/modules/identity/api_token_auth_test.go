package identity

import (
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/policy"
	"github.com/custodexa/backend/internal/sourceip"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// API token 的認證（每次請求現查）。

const tokenTestIP = "192.0.2.10"

func newAuthTokenEnv(t *testing.T) *tokenEnv {
	t.Helper()
	e := newTokenEnv(t)
	e.auth.SetRestoreGenerationSource(func(*gorm.DB) (string, error) { return *e.gen, nil })
	return e
}

// issue 以服務建立一把永不到期的 token，回傳明文與識別。
func (e *tokenEnv) issue(t *testing.T, owner uint, name string, roles ...uint) (string, uint) {
	t.Helper()
	got := e.mustCreate(t, owner, name, roles...)
	return got.Token, got.View.ID
}

// seedRawToken 直接寫入一列 token（服務層不允許建立的形狀，例如非人類帳號）。
func (e *tokenEnv) seedRawToken(t *testing.T, owner uint, roles ...uint) string {
	t.Helper()
	plain, digest, err := GenerateAPIToken()
	require.NoError(t, err)
	row := model.APIToken{UserID: owner, Name: "raw", TokenHash: digest, RestoreGeneration: *e.gen, CreatedAt: time.Now()}
	require.NoError(t, e.db.Create(&row).Error)
	for _, r := range roles {
		require.NoError(t, e.db.Create(&model.APITokenRole{APITokenID: row.ID, RoleID: r}).Error)
	}
	return plain
}

func (e *tokenEnv) assertRejected(t *testing.T, plain, wantReason string) {
	t.Helper()
	id, reason := e.auth.ValidateAPIToken(plain, tokenTestIP)
	assert.Nil(t, id, "應拒絕")
	assert.Equal(t, wantReason, reason)
}

func (e *tokenEnv) assertAccepted(t *testing.T, plain string, owner uint) *APITokenIdentity {
	t.Helper()
	id, reason := e.auth.ValidateAPIToken(plain, tokenTestIP)
	require.NotNil(t, id, "應通過，實際原因 %q", reason)
	assert.Empty(t, reason)
	assert.Equal(t, owner, id.UserID)
	return id
}

func TestAPITokenValidateAcceptsAndCarriesGrantedRoles(t *testing.T) {
	e := newAuthTokenEnv(t)
	owner := e.mkUser(t, "owner", "identity_admin", "security_admin")
	plain, tokenID := e.issue(t, owner, "terraform", e.roles["security_admin"])
	id := e.assertAccepted(t, plain, owner)
	assert.Equal(t, tokenID, id.TokenID)
	assert.Equal(t, "terraform", id.TokenName)
	assert.Equal(t, "owner", id.Username)
	assert.Equal(t, []uint{e.roles["security_admin"]}, id.GrantedRoleIDs)
}

func TestAPITokenValidateNotFound(t *testing.T) {
	e := newAuthTokenEnv(t)
	e.assertRejected(t, APITokenPrefix+"does-not-exist", APITokenReasonNotFound)
}

func TestAPITokenValidateRevoked(t *testing.T) {
	e := newAuthTokenEnv(t)
	owner := e.mkUser(t, "owner", "identity_admin")
	plain, id := e.issue(t, owner, "n", e.roles["identity_admin"])
	require.NoError(t, e.tokens.RevokeOwn(e.op(owner), id, ""))
	e.assertRejected(t, plain, APITokenReasonRevoked)
}

func TestAPITokenValidateExpired(t *testing.T) {
	e := newAuthTokenEnv(t)
	owner := e.mkUser(t, "owner", "identity_admin")
	plain, id := e.issue(t, owner, "n", e.roles["identity_admin"])
	past := time.Now().Add(-time.Second)
	require.NoError(t, e.db.Model(&model.APIToken{}).Where("id = ?", id).Update("expires_at", past).Error)
	e.assertRejected(t, plain, APITokenReasonExpired)
}

// TestAPITokenValidateNeverExpiresPasses expires_at 為空即永不到期。
func TestAPITokenValidateNeverExpiresPasses(t *testing.T) {
	e := newAuthTokenEnv(t)
	owner := e.mkUser(t, "owner", "identity_admin")
	plain, id := e.issue(t, owner, "n", e.roles["identity_admin"])
	var row model.APIToken
	require.NoError(t, e.db.First(&row, id).Error)
	require.Nil(t, row.ExpiresAt)
	e.assertAccepted(t, plain, owner)
	future := time.Now().Add(time.Hour)
	require.NoError(t, e.db.Model(&model.APIToken{}).Where("id = ?", id).Update("expires_at", future).Error)
	e.assertAccepted(t, plain, owner)
}

func TestAPITokenValidateRestoreGenerationMismatch(t *testing.T) {
	e := newAuthTokenEnv(t)
	owner := e.mkUser(t, "owner", "identity_admin")
	plain, _ := e.issue(t, owner, "n", e.roles["identity_admin"])
	*e.gen = "gen-restored"
	e.assertRejected(t, plain, APITokenReasonRestoreInvalidated)
}

func TestAPITokenValidateAccountDisabled(t *testing.T) {
	e := newAuthTokenEnv(t)
	owner := e.mkUser(t, "owner", "identity_admin")
	plain, _ := e.issue(t, owner, "n", e.roles["identity_admin"])
	require.NoError(t, e.db.Model(&model.User{}).Where("id = ?", owner).Update("active", false).Error)
	e.assertRejected(t, plain, APITokenReasonAccountDisabled)
	require.NoError(t, e.db.Model(&model.User{}).Where("id = ?", owner).Update("active", true).Error)
	e.assertAccepted(t, plain, owner) // 重新啟用後恢復
}

func TestAPITokenValidateAccountDeleted(t *testing.T) {
	e := newAuthTokenEnv(t)
	owner := e.mkUser(t, "owner", "identity_admin")
	plain, id := e.issue(t, owner, "n", e.roles["identity_admin"])
	// 只軟刪帳號、不經刪除流程（未標記 token）：認證入口仍以帳號已刪除拒絕
	require.NoError(t, e.db.Delete(&model.User{}, owner).Error)
	e.assertRejected(t, plain, APITokenReasonAccountDeleted)
	var row model.APIToken
	require.NoError(t, e.db.First(&row, id).Error)
	assert.Nil(t, row.RevokedAt)
}

func TestAPITokenValidateNonHumanAccount(t *testing.T) {
	e := newAuthTokenEnv(t)
	agent := e.agent(t, "bot")
	plain := e.seedRawToken(t, agent, e.roles["user"])
	e.assertRejected(t, plain, APITokenReasonAccountNotHuman)
}

func TestAPITokenValidateSourceMismatch(t *testing.T) {
	e := newAuthTokenEnv(t)
	owner := e.mkUser(t, "owner", "identity_admin")
	plain, _ := e.issue(t, owner, "n", e.roles["identity_admin"])
	require.NoError(t, e.db.Model(&model.User{}).Where("id = ?", owner).Update("allowed_cidrs", "10.0.0.0/8").Error)
	e.assertRejected(t, plain, sourceip.ReasonSourceNotAllowed)
	id, reason := e.auth.ValidateAPIToken(plain, "10.1.2.3")
	require.NotNil(t, id, reason)
}

// TestAPITokenValidateRecordsLastUse 最近使用時間與來源在通過認證時寫入。
func TestAPITokenValidateRecordsLastUse(t *testing.T) {
	e := newAuthTokenEnv(t)
	owner := e.mkUser(t, "owner", "identity_admin")
	plain, id := e.issue(t, owner, "n", e.roles["identity_admin"])
	e.assertAccepted(t, plain, owner)
	var row model.APIToken
	require.NoError(t, e.db.First(&row, id).Error)
	require.NotNil(t, row.LastUsedAt)
	assert.Equal(t, tokenTestIP, row.LastUsedIP)
	// 來源改變即更新，即使仍在間隔內
	_, reason := e.auth.ValidateAPIToken(plain, "192.0.2.99")
	require.Empty(t, reason)
	require.NoError(t, e.db.First(&row, id).Error)
	assert.Equal(t, "192.0.2.99", row.LastUsedIP)
	// 失敗的請求不寫
	require.NoError(t, e.db.Model(&model.User{}).Where("id = ?", owner).Update("active", false).Error)
	_, reason = e.auth.ValidateAPIToken(plain, "192.0.2.77")
	require.NotEmpty(t, reason)
	require.NoError(t, e.db.First(&row, id).Error)
	assert.Equal(t, "192.0.2.99", row.LastUsedIP)
}

// TestAPITokenValidateSucceedsWhenLastUseWriteFails 最近使用的寫入失敗不影響認證結果。
func TestAPITokenValidateSucceedsWhenLastUseWriteFails(t *testing.T) {
	e := newAuthTokenEnv(t)
	owner := e.mkUser(t, "owner", "identity_admin")
	plain, id := e.issue(t, owner, "n", e.roles["identity_admin"])
	require.NoError(t, e.db.Exec(`CREATE TRIGGER block_api_token_touch BEFORE UPDATE ON api_tokens BEGIN SELECT RAISE(ABORT, 'blocked'); END`).Error)
	e.assertAccepted(t, plain, owner)
	var row model.APIToken
	require.NoError(t, e.db.First(&row, id).Error)
	assert.Nil(t, row.LastUsedAt, "寫入確實失敗")
}

// ── 不影響 token 的帳號事件：每一種各一個測試 ──────────────

func TestAPITokenUnaffectedByPasswordChange(t *testing.T) {
	e := newAuthTokenEnv(t)
	owner := e.mkUser(t, "owner", "identity_admin")
	e.withPassword(t, owner)
	plain, _ := e.issue(t, owner, "n", e.roles["identity_admin"])
	require.NoError(t, e.users.ChangePasswordBy(e.op(e.admin), owner, "An0ther-Passw0rd!xyz"))
	assert.Greater(t, reloadUserInternal(t, e.db, owner).CredentialEpoch, 0, "改密推進了憑證世代")
	e.assertAccepted(t, plain, owner)
}

func TestAPITokenUnaffectedByAccountLockout(t *testing.T) {
	e := newAuthTokenEnv(t)
	owner := e.mkUser(t, "owner", "identity_admin")
	plain, _ := e.issue(t, owner, "n", e.roles["identity_admin"])
	until := time.Now().Add(time.Hour)
	require.NoError(t, e.db.Model(&model.User{}).Where("id = ?", owner).Updates(map[string]any{"failed_login_attempts": 10, "locked_until": until}).Error)
	e.assertAccepted(t, plain, owner)
}

func TestAPITokenUnaffectedByForcedPasswordChange(t *testing.T) {
	e := newAuthTokenEnv(t)
	owner := e.mkUser(t, "owner", "identity_admin")
	plain, _ := e.issue(t, owner, "n", e.roles["identity_admin"])
	require.NoError(t, e.db.Model(&model.User{}).Where("id = ?", owner).Update("must_change_password", true).Error)
	e.assertAccepted(t, plain, owner)
}

func TestAPITokenUnaffectedByMFAEnrollmentRequirement(t *testing.T) {
	e := newAuthTokenEnv(t)
	owner := e.mkUser(t, "owner", "identity_admin")
	plain, _ := e.issue(t, owner, "n", e.roles["identity_admin"])
	require.NoError(t, e.db.Create(&model.SecurityPolicy{Key: policy.PolicyMFARequired, Value: policy.MFARequiredAll}).Error)
	require.False(t, reloadUserInternal(t, e.db, owner).TOTPEnabled, "帳號尚未註冊兩步驟驗證")
	e.assertAccepted(t, plain, owner)
}

func TestAPITokenUnaffectedBySessionRevocation(t *testing.T) {
	e := newAuthTokenEnv(t)
	owner := e.mkUser(t, "owner", "identity_admin")
	plain, _ := e.issue(t, owner, "n", e.roles["identity_admin"])
	require.NoError(t, e.db.Transaction(func(tx *gorm.DB) error { return e.users.invalidateCredentialsLocked(tx, owner, "sessions_revoked") }))
	assert.Greater(t, reloadUserInternal(t, e.db, owner).CredentialEpoch, 0)
	e.assertAccepted(t, plain, owner)
}

func TestAPITokenUnaffectedByExternalOnlyLogin(t *testing.T) {
	e := newAuthTokenEnv(t)
	owner := e.mkUser(t, "owner", "identity_admin")
	plain, _ := e.issue(t, owner, "n", e.roles["identity_admin"])
	require.NoError(t, e.db.Create(&model.UserExternalIdentity{UserID: owner, ProviderID: e.provider, Subject: "sub-owner", Issuer: "https://idp.example", ClientID: "cid"}).Error)
	require.NoError(t, e.db.Model(&model.User{}).Where("id = ?", owner).Updates(map[string]any{"external_credential": true, "credential_epoch": gorm.Expr("credential_epoch + 1")}).Error)
	e.assertAccepted(t, plain, owner)
	// 解除外部身分綁定同樣不影響
	require.NoError(t, e.db.Where("user_id = ?", owner).Delete(&model.UserExternalIdentity{}).Error)
	e.assertAccepted(t, plain, owner)
}

func reloadUserInternal(t *testing.T, db *gorm.DB, id uint) model.User {
	t.Helper()
	var u model.User
	require.NoError(t, db.First(&u, id).Error)
	return u
}

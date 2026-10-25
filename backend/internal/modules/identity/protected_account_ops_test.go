package identity

import (
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/audit/port"
)

type acctEnv struct {
	*guardEnv
	auth     *AuthService
	provider uint
}

type failingAlerts struct{}

func (failingAlerts) RaiseInTx(*gorm.DB, port.SystemAlertEvent) (port.SystemAlertReceipt, error) {
	return port.SystemAlertReceipt{}, errors.New("alert sink down")
}

func newAcctEnv(t *testing.T, alerts port.SystemAlertSink) *acctEnv {
	t.Helper()
	g := newGuardEnv(t, true)
	require.NoError(t, g.db.Exec(`CREATE TABLE IF NOT EXISTS command_alerts (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		rule_id INTEGER, rule_name TEXT NOT NULL,
		session_id INTEGER, user_id INTEGER NOT NULL, asset_id INTEGER,
		command TEXT NOT NULL, severity TEXT NOT NULL, triggered_at DATETIME NOT NULL,
		reviewed_by INTEGER, reviewed_at DATETIME,
		disposition TEXT NOT NULL DEFAULT 'pending', note TEXT NOT NULL DEFAULT '',
		blocked BOOLEAN NOT NULL DEFAULT 0,
		kind TEXT NOT NULL DEFAULT 'rule', reason_code TEXT NOT NULL DEFAULT ''
	)`).Error)
	require.NoError(t, g.db.AutoMigrate(&model.SystemAlertDetail{}, &model.SystemAlertOutbox{},
		&model.SystemAlertSeverityOverride{}, &model.NotificationChannel{},
		&model.OIDCProvider{}, &model.RoleBindingNode{}, &model.UserExternalIdentity{}, &model.AssetAuthorization{}))
	if alerts == nil {
		alerts = audit.NewSystemAlertSink(nil)
	}
	ops := NewProtectedAccountOps(audit.NewTxSink(), alerts)
	g.users.SetProtectedAccountOps(ops)
	auth := &AuthService{}
	auth.SetEpochGateDB(g.db)
	auth.SetProtectedAccountOps(ops)
	p := model.OIDCProvider{Name: "idp", Issuer: "https://idp.example", ClientID: "cid", Enabled: true}
	require.NoError(t, g.db.Create(&p).Error)
	return &acctEnv{guardEnv: g, auth: auth, provider: p.ID}
}

func (e *acctEnv) alerts(t *testing.T) int64 {
	t.Helper()
	var n int64
	require.NoError(t, e.db.Model(&model.SystemAlertDetail{}).Where("alert_type = ?", "security_admin_account_operated").Count(&n).Error)
	return n
}

func (e *acctEnv) acctAudits(t *testing.T) int64 {
	t.Helper()
	var n int64
	require.NoError(t, e.db.Model(&model.AuditLog{}).Where("details LIKE ?", "%security_admin_account_operated%").Count(&n).Error)
	return n
}

func (e *acctEnv) password(t *testing.T, uid uint) string {
	t.Helper()
	var u model.User
	require.NoError(t, e.db.First(&u, uid).Error)
	return u.Password
}

func (e *acctEnv) totp(t *testing.T, uid uint, on bool) {
	t.Helper()
	require.NoError(t, e.db.Model(&model.User{}).Where("id = ?", uid).
		Updates(map[string]any{"totp_enabled": on, "totp_secret_enc": map[bool]string{true: "enc:x", false: ""}[on]}).Error)
}

func (e *acctEnv) totpOn(t *testing.T, uid uint) bool {
	t.Helper()
	var u model.User
	require.NoError(t, e.db.First(&u, uid).Error)
	return u.TOTPEnabled
}

func (e *acctEnv) bindings(t *testing.T, uid uint) int64 {
	t.Helper()
	var n int64
	require.NoError(t, e.db.Model(&model.UserExternalIdentity{}).Where("user_id = ?", uid).Count(&n).Error)
	return n
}

// credentialEpoch 帳號目前的憑證世代。
func (e *acctEnv) credentialEpoch(t *testing.T, uid uint) int64 {
	t.Helper()
	var ep int64
	require.NoError(t, e.db.Model(&model.User{}).Where("id = ?", uid).Pluck("credential_epoch", &ep).Error)
	return ep
}

// 本地帳號有密碼，才有「解綁後仍有登入途徑」。
func (e *acctEnv) withPassword(t *testing.T, uid uint) {
	t.Helper()
	require.NoError(t, e.db.Model(&model.User{}).Where("id = ?", uid).Update("password", "hash-old").Error)
}

// TestProtectedAccountOperations 擋：非超管對超管帳號（三種來源）的改密、停 MFA、綁定、追加角色；
// 放行：身分管理員對一般帳號；對系統安全管理員帳號四項各一審計一事件（解綁並停用屬停用，限超管）；
// 超管不產生事件；事件寫入失敗回滾。
func TestProtectedAccountOperations(t *testing.T) {
	const newPw = "N3w-Passw0rd!xyz"

	t.Run("非超管對超管帳號（直接、群組、映射）全部拒絕且帳號不變", func(t *testing.T) {
		e := newAcctEnv(t, nil)
		ida := e.mkUser(t, "ida", "identity_admin")
		direct := e.mkUser(t, "sa-direct", "admin")
		viaGroup := e.mkUser(t, "sa-group")
		g := model.UserGroup{Name: "sg"}
		require.NoError(t, e.db.Create(&g).Error)
		require.NoError(t, e.db.Create(&model.UserGroupMember{UserGroupID: g.ID, UserID: viaGroup, Manual: true}).Error)
		require.NoError(t, e.db.Create(&model.UserGroupRole{UserGroupID: g.ID, RoleID: e.roles["admin"], ScopeKind: model.ScopeKindGlobal}).Error)
		mapped := e.mkUser(t, "sa-mapped")
		require.NoError(t, e.db.Create(&model.UserRole{UserID: mapped, RoleID: e.roles["admin"], Source: model.RoleSourceMapped, ScopeKind: model.ScopeKindGlobal}).Error)

		for name, uid := range map[string]uint{"direct": direct, "group": viaGroup, "mapped": mapped} {
			e.withPassword(t, uid)
			e.totp(t, uid, true)
			before := e.password(t, uid)
			epochBefore := e.credentialEpoch(t, uid)
			assertCode(t, e.users.ChangePasswordBy(e.op(ida), uid, newPw), apierror.CodeAuthProtectedAccountOperation)
			assertCode(t, e.auth.AdminDisableMFABy(e.op(ida), uid), apierror.CodeAuthProtectedAccountOperation)
			_, err := e.users.BindExternalIdentityBy(e.op(ida), uid, e.provider, "subj-"+name)
			assertCode(t, err, apierror.CodeAuthProtectedAccountOperation)
			assertCode(t, e.users.AddRoleBy(e.op(ida), uid, "auditor"), apierror.CodeAuthProtectedAccountOperation)
			assert.Equal(t, before, e.password(t, uid), name)
			assert.Equal(t, epochBefore, e.credentialEpoch(t, uid), "被拒時憑證世代不變："+name)
			assert.True(t, e.totpOn(t, uid), name)
			assert.Zero(t, e.bindings(t, uid), name)
			assert.False(t, hasRoleName(e.manual(t, uid), "auditor"), name)
		}
		assert.Zero(t, e.alerts(t), "被拒不產生事件")
	})

	t.Run("身分管理員對一般帳號改密、停 MFA、綁定成功且不產生事件", func(t *testing.T) {
		e := newAcctEnv(t, nil)
		ida := e.mkUser(t, "ida", "identity_admin")
		plain := e.mkUser(t, "plain")
		e.withPassword(t, plain)
		e.totp(t, plain, true)
		require.NoError(t, e.users.ChangePasswordBy(e.op(ida), plain, newPw))
		assert.NotEqual(t, "hash-old", e.password(t, plain))
		require.NoError(t, e.auth.AdminDisableMFABy(e.op(ida), plain))
		assert.False(t, e.totpOn(t, plain))
		_, err := e.users.BindExternalIdentityBy(e.op(ida), plain, e.provider, "subj-plain")
		require.NoError(t, err)
		assert.EqualValues(t, 1, e.bindings(t, plain))
		assert.Zero(t, e.alerts(t))
		assert.Zero(t, e.acctAudits(t))
	})

	t.Run("身分管理員對系統安全管理員帳號四項各成功並各一審計一事件，解綁並停用被拒，內容無秘密", func(t *testing.T) {
		e := newAcctEnv(t, nil)
		ida := e.mkUser(t, "ida", "identity_admin")
		sec := e.mkUser(t, "sec", "security_admin")
		e.withPassword(t, sec)
		e.totp(t, sec, true)

		require.NoError(t, e.users.ChangePasswordBy(e.op(ida), sec, newPw))
		require.NoError(t, e.auth.AdminDisableMFABy(e.op(ida), sec))
		dto, err := e.users.BindExternalIdentityBy(e.op(ida), sec, e.provider, "secret-subject-1")
		require.NoError(t, err)
		require.NoError(t, e.users.UnbindExternalIdentityBy(e.op(ida), sec, dto.ID))
		dto2, err := e.users.BindExternalIdentityBy(e.op(ida), sec, e.provider, "secret-subject-2")
		require.NoError(t, err)
		// 解綁並停用會停用帳號：持保護角色的帳號只有超管能停用，整筆拒絕、不留事件
		assertCode(t, e.users.UnbindExternalIdentityAndDisableBy(e.op(ida), sec, dto2.ID), apierror.CodeAuthProtectedAccountOperation)

		// 綁定兩次、解綁一次、改密、停 MFA：共 5 次受控操作，每次一審計一事件
		assert.EqualValues(t, 5, e.alerts(t))
		assert.EqualValues(t, 5, e.acctAudits(t))
		var params []string
		require.NoError(t, e.db.Model(&model.SystemAlertDetail{}).Pluck("params", &params).Error)
		joined := strings.Join(params, "|")
		for _, action := range []string{"password_change", "mfa_disabled", "external_bound", "external_unbound"} {
			assert.Contains(t, joined, action)
		}
		var details []string
		require.NoError(t, e.db.Model(&model.AuditLog{}).Where("details LIKE ?", "%security_admin_account_operated%").Pluck("details", &details).Error)
		all := joined + "|" + strings.Join(details, "|")
		for _, leak := range []string{newPw, "secret-subject", "enc:x", "hash-old"} {
			assert.NotContains(t, all, leak)
		}
	})

	t.Run("超管執行同五項不產生事件", func(t *testing.T) {
		e := newAcctEnv(t, nil)
		sec := e.mkUser(t, "sec", "security_admin")
		e.withPassword(t, sec)
		e.totp(t, sec, true)
		require.NoError(t, e.users.ChangePasswordBy(e.op(e.admin), sec, newPw))
		require.NoError(t, e.auth.AdminDisableMFABy(e.op(e.admin), sec))
		dto, err := e.users.BindExternalIdentityBy(e.op(e.admin), sec, e.provider, "s1")
		require.NoError(t, err)
		require.NoError(t, e.users.UnbindExternalIdentityBy(e.op(e.admin), sec, dto.ID))
		dto2, err := e.users.BindExternalIdentityBy(e.op(e.admin), sec, e.provider, "s2")
		require.NoError(t, err)
		require.NoError(t, e.users.UnbindExternalIdentityAndDisableBy(e.op(e.admin), sec, dto2.ID))
		assert.Zero(t, e.alerts(t))
		assert.Zero(t, e.acctAudits(t))
	})

	t.Run("事件寫入失敗時操作回滾", func(t *testing.T) {
		e := newAcctEnv(t, failingAlerts{})
		ida := e.mkUser(t, "ida", "identity_admin")
		sec := e.mkUser(t, "sec", "security_admin")
		e.withPassword(t, sec)
		e.totp(t, sec, true)
		require.Error(t, e.users.ChangePasswordBy(e.op(ida), sec, newPw))
		assert.Equal(t, "hash-old", e.password(t, sec))
		require.Error(t, e.auth.AdminDisableMFABy(e.op(ida), sec))
		assert.True(t, e.totpOn(t, sec))
		_, err := e.users.BindExternalIdentityBy(e.op(ida), sec, e.provider, "s1")
		require.Error(t, err)
		assert.Zero(t, e.bindings(t, sec))
		assert.Zero(t, e.acctAudits(t), "審計與事件同交易，事件失敗審計也不留")
		// 已有綁定時解綁同樣回滾
		require.NoError(t, e.db.Create(&model.UserExternalIdentity{UserID: sec, ProviderID: e.provider, Issuer: "https://idp.example", ClientID: "cid", Subject: "pre"}).Error)
		var id model.UserExternalIdentity
		require.NoError(t, e.db.Where("user_id = ?", sec).First(&id).Error)
		require.Error(t, e.users.UnbindExternalIdentityBy(e.op(ida), sec, id.ID))
		assert.EqualValues(t, 1, e.bindings(t, sec))
	})
}

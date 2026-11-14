package identity

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/notifycat"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// 建立與撤銷 API token 的交易內留痕：稽核列（不受稽核開關控制）與高權限告警。

func newRecordedTokenEnv(t *testing.T) *tokenEnv {
	t.Helper()
	e := newTokenEnv(t)
	e.tokens = NewAPITokenService(e.db, NewAPITokenEventRecorder(audit.NewTxSink(), audit.NewSystemAlertSink(nil)))
	e.tokens.now = func() time.Time { return e.clock }
	e.tokens.SetRestoreGenerationSource(func(*gorm.DB) (string, error) { return *e.gen, nil })
	require.NoError(t, e.db.Create(&model.NotificationChannel{Name: "ops", Type: "webhook", URL: "https://hook.example.test/a",
		Enabled: true, Language: "zh-TW", MinSeverity: "low"}).Error)
	return e
}

func (e *tokenEnv) tokenAlerts(t *testing.T) []model.SystemAlertDetail {
	t.Helper()
	var rows []model.SystemAlertDetail
	require.NoError(t, e.db.Where("alert_type = ?", "privileged_api_token_created").Order("alert_id").Find(&rows).Error)
	return rows
}

func (e *tokenEnv) tokenAudits(t *testing.T, action model.AuditAction) []model.AuditLog {
	t.Helper()
	var rows []model.AuditLog
	require.NoError(t, e.db.Where("resource = ? AND action = ?", model.ResourceAPIToken, action).Order("id").Find(&rows).Error)
	return rows
}

func (e *tokenEnv) outboxFor(t *testing.T, alertID uint) int64 {
	t.Helper()
	var n int64
	require.NoError(t, e.db.Model(&model.SystemAlertOutbox{}).Where("alert_id = ?", alertID).Count(&n).Error)
	return n
}

func (e *tokenEnv) severityOf(t *testing.T, alertID uint) string {
	t.Helper()
	var sev string
	require.NoError(t, e.db.Raw("SELECT severity FROM command_alerts WHERE id = ?", alertID).Scan(&sev).Error)
	return sev
}

func TestAPITokenPrivilegedAlertSuperAdminRole(t *testing.T) {
	e := newRecordedTokenEnv(t)
	got, err := e.tokens.Create(e.op(e.admin), CreateAPITokenInput{Name: "root-automation", RoleIDs: []uint{e.roles["admin"]}, NeverExpires: true})
	require.NoError(t, err)
	alerts := e.tokenAlerts(t)
	require.Len(t, alerts, 1)
	a := alerts[0]
	assert.Equal(t, "user", a.TargetKind)
	assert.Equal(t, jsonUint(e.admin), a.TargetID, "告警對象是建立者本人")
	var params map[string]any
	require.NoError(t, json.Unmarshal([]byte(a.Params), &params))
	assert.Equal(t, model.BuiltinSuperAdmin, params["privileged_roles"])
	assert.Equal(t, "root-automation", params["token_name"])
	assert.Equal(t, "op", params["actor"], "建立者的使用者名稱")
	assert.Equal(t, "never", params["expiry"], "永不到期明寫為 never，與資料缺漏分得開")
	_, hasExpiry := params["expires_at"]
	assert.False(t, hasExpiry, "永不到期不帶到期時刻")
	for _, c := range []struct{ lang, want string }{{"zh-TW", "永不到期"}, {"en-US", "never expires"}, {"ja-JP", "有効期限なし"}} {
		strParams := map[string]string{"severity": model.AlertSeverityHigh}
		for k, v := range params {
			strParams[k] = fmt.Sprint(v)
		}
		_, text := notifycat.Render(c.lang, notifycat.EventSystemAlertPrivilegedAPITokenCreated, strParams)
		assert.Contains(t, text, c.want, "%s 通知文案寫出永不到期", c.lang)
	}
	assert.Equal(t, model.AlertSeverityHigh, e.severityOf(t, a.AlertID), "預設分級 high")
	assert.Equal(t, int64(1), e.outboxFor(t, a.AlertID), "通知佇列有對應待送項")
	assert.NotContains(t, a.Params, got.Token)
	assert.NotContains(t, a.Params, apiTokenDigest(got.Token))
	rows := e.tokenAudits(t, model.ActionCreate)
	require.Len(t, rows, 1)
	assert.Contains(t, rows[0].Details, a.CorrelationID, "稽核細節與告警以關聯識別對應")
}

func TestAPITokenPrivilegedAlertSecurityAdminRole(t *testing.T) {
	e := newRecordedTokenEnv(t)
	owner := e.mkUser(t, "sec", "security_admin", "identity_admin")
	exp := e.future(30 * 24 * time.Hour)
	_, err := e.tokens.Create(e.op(owner), CreateAPITokenInput{Name: "sec-tf", RoleIDs: []uint{e.roles["security_admin"], e.roles["identity_admin"]}, ExpiresAt: exp})
	require.NoError(t, err)
	alerts := e.tokenAlerts(t)
	require.Len(t, alerts, 1)
	var params map[string]string
	require.NoError(t, json.Unmarshal([]byte(alerts[0].Params), &params))
	assert.Equal(t, model.BuiltinSecurityAdmin, params["privileged_roles"])
	assert.Contains(t, params["granted_roles"], model.BuiltinIdentityAdmin)
	assert.Contains(t, params["granted_roles"], model.BuiltinSecurityAdmin)
	assert.Equal(t, exp.UTC().Format(time.RFC3339), params["expires_at"])
	assert.Equal(t, "at", params["expiry"])
	params["severity"] = model.AlertSeverityHigh
	_, text := notifycat.Render("zh-TW", notifycat.EventSystemAlertPrivilegedAPITokenCreated, params)
	assert.Contains(t, text, "到期時刻："+params["expires_at"], "通知文案帶到期時刻")
}

func TestAPITokenPrivilegedAlertNotRaisedForOtherRoles(t *testing.T) {
	e := newRecordedTokenEnv(t)
	owner := e.mkUser(t, "ida", "identity_admin", "security_admin")
	_, err := e.tokens.Create(e.op(owner), CreateAPITokenInput{Name: "plain", RoleIDs: []uint{e.roles["identity_admin"]}, NeverExpires: true})
	require.NoError(t, err)
	assert.Empty(t, e.tokenAlerts(t), "授權角色不含超級管理者與系統安全管理員時不告警（即使本人持有）")
	require.Len(t, e.tokenAudits(t, model.ActionCreate), 1, "建立仍有稽核")
}

func TestAPITokenPrivilegedAlertSeverityOverride(t *testing.T) {
	e := newRecordedTokenEnv(t)
	require.NoError(t, e.db.Create(&model.SystemAlertSeverityOverride{AlertType: "privileged_api_token_created", Severity: model.AlertSeverityLow, UpdatedBy: e.admin}).Error)
	_, err := e.tokens.Create(e.op(e.admin), CreateAPITokenInput{Name: "x", RoleIDs: []uint{e.roles["admin"]}, NeverExpires: true})
	require.NoError(t, err)
	alerts := e.tokenAlerts(t)
	require.Len(t, alerts, 1)
	assert.Equal(t, model.AlertSeverityLow, e.severityOf(t, alerts[0].AlertID), "分級取覆寫值")
}

func TestAPITokenPrivilegedAlertRolledBackWithCreate(t *testing.T) {
	e := newRecordedTokenEnv(t)
	// 告警落地失敗：token、稽核與告警整筆回滾
	e.tokens = NewAPITokenService(e.db, NewAPITokenEventRecorder(audit.NewTxSink(), failingAlerts{}))
	e.tokens.now = func() time.Time { return e.clock }
	_, err := e.tokens.Create(e.op(e.admin), CreateAPITokenInput{Name: "x", RoleIDs: []uint{e.roles["admin"]}, NeverExpires: true})
	require.Error(t, err)
	assert.Empty(t, e.tokenRows(t, e.admin), "token 列一併回滾")
	assert.Empty(t, e.tokenAudits(t, model.ActionCreate), "稽核列一併回滾")
	assert.Empty(t, e.tokenAlerts(t), "不留告警")
	var outbox int64
	require.NoError(t, e.db.Model(&model.SystemAlertOutbox{}).Count(&outbox).Error)
	assert.Zero(t, outbox, "不留通知佇列項目")
	// 告警寫入途中失敗（告警列已寫、明細寫入被拒）：已寫的告警列隨交易回滾
	e2 := newRecordedTokenEnv(t)
	require.NoError(t, e2.db.Exec("CREATE TRIGGER fail_token_role AFTER INSERT ON system_alert_details BEGIN SELECT RAISE(ABORT, 'forced'); END").Error)
	_, err = e2.tokens.Create(e2.op(e2.admin), CreateAPITokenInput{Name: "y", RoleIDs: []uint{e2.roles["admin"]}, NeverExpires: true})
	require.Error(t, err)
	assert.Empty(t, e2.tokenRows(t, e2.admin))
	assert.Empty(t, e2.tokenAudits(t, model.ActionCreate))
	var commandAlerts int64
	require.NoError(t, e2.db.Raw("SELECT count(*) FROM command_alerts").Scan(&commandAlerts).Error)
	assert.Zero(t, commandAlerts, "告警列一併回滾")
}

func TestAPITokenCreateAndRevokeAuditDetails(t *testing.T) {
	e := newRecordedTokenEnv(t)
	owner := e.mkUser(t, "owner", "identity_admin")
	got, err := e.tokens.Create(e.op(owner), CreateAPITokenInput{Name: "tf", RoleIDs: []uint{e.roles["identity_admin"]}, NeverExpires: true})
	require.NoError(t, err)
	require.NoError(t, e.tokens.RevokeOwn(e.op(owner), got.View.ID, "rotated"))
	require.NoError(t, e.tokens.RevokeOwn(e.op(owner), got.View.ID, "again"))
	created := e.tokenAudits(t, model.ActionCreate)
	revoked := e.tokenAudits(t, model.ActionAPITokenRevoked)
	require.Len(t, created, 1)
	require.Len(t, revoked, 1, "重複撤銷不另寫稽核")
	for _, row := range append(created, revoked...) {
		require.NotNil(t, row.ResourceID)
		assert.Equal(t, got.View.ID, *row.ResourceID)
		assert.Equal(t, owner, row.UserID)
		assert.NotContains(t, row.Details, got.Token, "稽核細節不含明文")
		assert.NotContains(t, row.Details, apiTokenDigest(got.Token), "稽核細節不含雜湊")
		assert.Nil(t, row.APITokenID, "親自操作的列不帶 token 標示")
	}
	var detail map[string]any
	require.NoError(t, json.Unmarshal([]byte(created[0].Details), &detail))
	assert.Equal(t, "tf", detail["token_name"])
	assert.Equal(t, "owner", detail["owner_username"])
	assert.Equal(t, true, detail["never_expires"])
	require.NoError(t, json.Unmarshal([]byte(revoked[0].Details), &detail))
	assert.Equal(t, "rotated", detail["revoke_note"])
}

func jsonUint(v uint) string {
	b, _ := json.Marshal(v)
	return string(b)
}

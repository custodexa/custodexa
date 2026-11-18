package identity

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/notifycat"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// 授權角色的層級：建立的兩種寫法與驗證、投影的層級與彙總、建立稽核與高權限告警帶層級。

func (e *tokenEnv) createLeveled(t *testing.T, owner uint, name string, roles ...APITokenRoleGrant) *CreatedAPIToken {
	t.Helper()
	got, err := e.tokens.Create(e.op(owner), CreateAPITokenInput{Name: name, Roles: roles, NeverExpires: true})
	require.NoError(t, err)
	return got
}

func storedLevels(t *testing.T, e *tokenEnv, tokenID uint) map[uint]string {
	t.Helper()
	var links []model.APITokenRole
	require.NoError(t, e.db.Where("api_token_id = ?", tokenID).Find(&links).Error)
	out := map[uint]string{}
	for _, l := range links {
		out[l.RoleID] = l.Level
	}
	return out
}

// TestAPITokenCreateLevelRules 服務層的建立驗證：兩種寫法皆非空即拒絕；roles 寫法同一角色重複即拒絕（不論層級）；
// 層級須為認得的值；role_ids 寫法去重並等同讀寫；拒絕時不留任何列。
func TestAPITokenCreateLevelRules(t *testing.T) {
	e := newTokenEnv(t)
	owner := e.mkUser(t, "owner", "identity_admin", "security_admin")
	ida, sec := e.roles["identity_admin"], e.roles["security_admin"]
	reject := []struct {
		name string
		in   CreateAPITokenInput
		want *APITokenError
	}{
		{"both", CreateAPITokenInput{RoleIDs: []uint{ida}, Roles: []APITokenRoleGrant{{sec, model.APITokenLevelRead}}}, ErrAPITokenRolesConflict},
		{"duplicate same level", CreateAPITokenInput{Roles: []APITokenRoleGrant{{ida, model.APITokenLevelRead}, {ida, model.APITokenLevelRead}}}, ErrAPITokenRoleDuplicate},
		{"duplicate different level", CreateAPITokenInput{Roles: []APITokenRoleGrant{{ida, model.APITokenLevelRead}, {ida, model.APITokenLevelReadWrite}}}, ErrAPITokenRoleDuplicate},
		{"unknown level", CreateAPITokenInput{Roles: []APITokenRoleGrant{{ida, "admin"}}}, ErrAPITokenLevelInvalid},
		{"empty level", CreateAPITokenInput{Roles: []APITokenRoleGrant{{ida, ""}}}, ErrAPITokenLevelInvalid},
		{"one bad level among good", CreateAPITokenInput{Roles: []APITokenRoleGrant{{ida, model.APITokenLevelRead}, {sec, "Read"}}}, ErrAPITokenLevelInvalid},
		{"role zero", CreateAPITokenInput{Roles: []APITokenRoleGrant{{0, model.APITokenLevelRead}}}, ErrAPITokenRoleNotGrantable},
		{"role not held", CreateAPITokenInput{Roles: []APITokenRoleGrant{{e.roles["admin"], model.APITokenLevelRead}}}, ErrAPITokenRoleNotGrantable},
		{"none", CreateAPITokenInput{}, ErrAPITokenRoleRequired},
	}
	for _, c := range reject {
		t.Run(c.name, func(t *testing.T) {
			in := c.in
			in.Name, in.NeverExpires = "n-"+c.name, true
			_, err := e.tokens.Create(e.op(owner), in)
			assertTokenErr(t, err, c.want)
		})
	}
	assert.Empty(t, e.tokenRows(t, owner), "拒絕的請求不留任何列")
	assert.Empty(t, e.events.created, "拒絕的請求不留痕")

	leveled := e.createLeveled(t, owner, "leveled", APITokenRoleGrant{sec, model.APITokenLevelRead}, APITokenRoleGrant{ida, model.APITokenLevelReadWrite})
	assert.Equal(t, map[uint]string{ida: model.APITokenLevelReadWrite, sec: model.APITokenLevelRead}, storedLevels(t, e, leveled.View.ID))
	legacy, err := e.tokens.Create(e.op(owner), CreateAPITokenInput{Name: "legacy", RoleIDs: []uint{sec, ida, sec, 0}, NeverExpires: true})
	require.NoError(t, err)
	assert.Equal(t, map[uint]string{ida: model.APITokenLevelReadWrite, sec: model.APITokenLevelReadWrite}, storedLevels(t, e, legacy.View.ID),
		"role_ids 寫法去重、略過 0，各角色為讀寫")
}

// TestAPITokenProjectionLevelsAndAccess 投影的每個授權角色帶層級，token 帶彙總；三種彙總、不認得的保存值視為唯讀、
// 本欄出現前的列（由資料庫預設值補上）為讀寫；目前不生效的角色也計入彙總。
func TestAPITokenProjectionLevelsAndAccess(t *testing.T) {
	e := newTokenEnv(t)
	owner := e.mkUser(t, "owner", "identity_admin", "security_admin")
	ida, sec := e.roles["identity_admin"], e.roles["security_admin"]
	ro := e.createLeveled(t, owner, "ro", APITokenRoleGrant{ida, model.APITokenLevelRead}, APITokenRoleGrant{sec, model.APITokenLevelRead})
	rw := e.createLeveled(t, owner, "rw", APITokenRoleGrant{ida, model.APITokenLevelReadWrite}, APITokenRoleGrant{sec, model.APITokenLevelReadWrite})
	mixed := e.createLeveled(t, owner, "mixed", APITokenRoleGrant{ida, model.APITokenLevelReadWrite}, APITokenRoleGrant{sec, model.APITokenLevelRead})
	assert.Equal(t, model.APITokenAccessRead, ro.View.Access, "建立回應")
	assert.Equal(t, model.APITokenAccessReadWrite, rw.View.Access)
	assert.Equal(t, model.APITokenAccessMixed, mixed.View.Access)
	for _, r := range mixed.View.GrantedRoles {
		want := model.APITokenLevelRead
		if r.RoleID == ida {
			want = model.APITokenLevelReadWrite
		}
		assert.Equal(t, want, r.Level, "建立回應的角色 %d", r.RoleID)
	}
	for id, want := range map[uint]string{ro.View.ID: model.APITokenAccessRead, rw.View.ID: model.APITokenAccessReadWrite, mixed.View.ID: model.APITokenAccessMixed} {
		assert.Equal(t, want, e.viewOf(t, owner, id).Access, "清單的彙總")
	}

	// 不認得的保存值視為唯讀：讀寫的 token 其中一個角色的值被改壞，彙總成為混合
	require.NoError(t, e.db.Model(&model.APITokenRole{}).Where("api_token_id = ? AND role_id = ?", rw.View.ID, sec).Update("level", "owner").Error)
	v := e.viewOf(t, owner, rw.View.ID)
	assert.Equal(t, model.APITokenAccessMixed, v.Access)
	for _, r := range v.GrantedRoles {
		if r.RoleID == sec {
			assert.Equal(t, model.APITokenLevelRead, r.Level, "不認得的值呈現為唯讀")
		}
	}

	// 本欄出現前的列：以不帶層級的方式寫入，資料庫預設值補上讀寫
	legacy := e.mustCreate(t, owner, "legacy-shape", ida)
	require.NoError(t, e.db.Where("api_token_id = ?", legacy.View.ID).Delete(&model.APITokenRole{}).Error)
	require.NoError(t, e.db.Exec("INSERT INTO api_token_roles (api_token_id, role_id) VALUES (?, ?)", legacy.View.ID, ida).Error)
	assert.Equal(t, model.APITokenAccessReadWrite, e.viewOf(t, owner, legacy.View.ID).Access, "升級前的 token 視為讀寫")

	// 角色收回後仍計入彙總（回退前要撤銷的範圍包含暫不生效的唯讀角色）
	require.NoError(t, e.db.Where("user_id = ? AND role_id = ?", owner, sec).Delete(&model.UserRole{}).Error)
	assert.Equal(t, model.APITokenAccessMixed, e.viewOf(t, owner, mixed.View.ID).Access)
}

// TestAPITokenAccessOf 彙總的邊界：空集合歸到唯讀（需要注意的一側），不認得的值視為唯讀。
func TestAPITokenAccessOf(t *testing.T) {
	cases := []struct {
		levels []string
		want   string
	}{
		{nil, model.APITokenAccessRead},
		{[]string{"read"}, model.APITokenAccessRead},
		{[]string{"read_write"}, model.APITokenAccessReadWrite},
		{[]string{"read_write", "read"}, model.APITokenAccessMixed},
		{[]string{"read_write", "bogus"}, model.APITokenAccessMixed},
		{[]string{""}, model.APITokenAccessRead},
	}
	for _, c := range cases {
		assert.Equal(t, c.want, model.APITokenAccessOf(c.levels), "%v", c.levels)
	}
	assert.True(t, model.IsAPITokenLevel("read") && model.IsAPITokenLevel("read_write"))
	assert.False(t, model.IsAPITokenLevel("") || model.IsAPITokenLevel("READ") || model.IsAPITokenLevel("write"))
}

// TestAPITokenIdentityRoleSelection 認證身分依路由性質選角色：計入全部或只計入讀寫；不認得的層級不算讀寫。
func TestAPITokenIdentityRoleSelection(t *testing.T) {
	id := &APITokenIdentity{GrantedRoles: []APITokenGrantedRole{{1, model.APITokenLevelReadWrite}, {2, model.APITokenLevelRead}, {3, "bogus"}}}
	assert.Equal(t, []uint{1, 2, 3}, id.RoleIDsCounted(true))
	assert.Equal(t, []uint{1}, id.RoleIDsCounted(false))
	assert.True(t, id.HasReadWriteRole())
	ro := &APITokenIdentity{GrantedRoles: []APITokenGrantedRole{{2, model.APITokenLevelRead}, {3, "READ_WRITE"}}}
	assert.False(t, ro.HasReadWriteRole())
	assert.NotNil(t, ro.RoleIDsCounted(false), "沒有讀寫角色時回非 nil 的空集合")
	assert.Empty(t, ro.RoleIDsCounted(false))
	empty := &APITokenIdentity{}
	assert.NotNil(t, empty.RoleIDsCounted(true))
}

// TestAPITokenValidateCarriesLevels 認證讀出授權角色的層級（不認得的值正規化為唯讀）。
func TestAPITokenValidateCarriesLevels(t *testing.T) {
	e := newAuthTokenEnv(t)
	owner := e.mkUser(t, "owner", "identity_admin", "security_admin")
	ida, sec := e.roles["identity_admin"], e.roles["security_admin"]
	got := e.createLeveled(t, owner, "mixed", APITokenRoleGrant{ida, model.APITokenLevelReadWrite}, APITokenRoleGrant{sec, model.APITokenLevelRead})
	auth := e.auth
	id, reason := auth.ValidateAPIToken(got.Token, "192.0.2.1")
	require.NotNil(t, id, reason)
	assert.ElementsMatch(t, []APITokenGrantedRole{{ida, model.APITokenLevelReadWrite}, {sec, model.APITokenLevelRead}}, id.GrantedRoles)
	require.NoError(t, e.db.Model(&model.APITokenRole{}).Where("api_token_id = ? AND role_id = ?", got.View.ID, ida).Update("level", "superuser").Error)
	id, _ = auth.ValidateAPIToken(got.Token, "192.0.2.1")
	require.NotNil(t, id)
	assert.False(t, id.HasReadWriteRole(), "不認得的保存值不提供寫入能力")
}

// TestAPITokenCreateAuditAndAlertCarryLevels 建立的稽核細節每個授權角色帶層級並帶彙總；只授權唯讀超級管理者角色的
// token 仍發高權限告警、分級不變，參數帶同序的層級；撤銷的稽核不帶授權角色。
func TestAPITokenCreateAuditAndAlertCarryLevels(t *testing.T) {
	e := newRecordedTokenEnv(t)
	got, err := e.tokens.Create(e.op(e.admin), CreateAPITokenInput{Name: "ro-root", Roles: []APITokenRoleGrant{{e.roles["admin"], model.APITokenLevelRead}}, NeverExpires: true})
	require.NoError(t, err)

	alerts := e.tokenAlerts(t)
	require.Len(t, alerts, 1, "唯讀的高權限角色仍發告警")
	assert.Equal(t, model.AlertSeverityHigh, e.severityOf(t, alerts[0].AlertID), "分級不因唯讀而降低")
	var params map[string]string
	require.NoError(t, json.Unmarshal([]byte(alerts[0].Params), &params))
	assert.Equal(t, model.BuiltinSuperAdmin, params["privileged_roles"])
	assert.Equal(t, model.APITokenLevelRead, params["granted_role_levels"])
	assert.NotContains(t, alerts[0].Params, got.Token)
	strParams := map[string]string{"severity": model.AlertSeverityHigh}
	for k, v := range params {
		strParams[k] = fmt.Sprint(v)
	}
	assert.Equal(t, model.APITokenLevelRead, params["privileged_role_levels"])
	assert.Equal(t, model.APITokenAccessRead, params["access"])
	_, text := notifycat.Render("zh-TW", notifycat.EventSystemAlertPrivilegedAPITokenCreated, strParams)
	assert.Contains(t, text, "高權限角色："+model.BuiltinSuperAdmin+"（唯讀）", "通知文案逐角色附層級")
	assert.Contains(t, text, "全部授權角色："+model.BuiltinSuperAdmin+"（唯讀）")
	assert.NotContains(t, text, "read", "通知文案不露出層級機器值")

	rows := e.tokenAudits(t, model.ActionCreate)
	require.Len(t, rows, 1)
	var detail struct {
		Access       string           `json:"access"`
		GrantedRoles []map[string]any `json:"granted_roles"`
	}
	require.NoError(t, json.Unmarshal([]byte(rows[0].Details), &detail))
	assert.Equal(t, model.APITokenAccessRead, detail.Access)
	require.Len(t, detail.GrantedRoles, 1)
	assert.Equal(t, model.APITokenLevelRead, detail.GrantedRoles[0]["level"])

	// 混合層級：告警參數的層級與角色同序
	owner := e.mkUser(t, "sec", "security_admin", "identity_admin")
	_, err = e.tokens.Create(e.op(owner), CreateAPITokenInput{Name: "mixed", Roles: []APITokenRoleGrant{
		{e.roles["security_admin"], model.APITokenLevelRead}, {e.roles["identity_admin"], model.APITokenLevelReadWrite}}, NeverExpires: true})
	require.NoError(t, err)
	alerts = e.tokenAlerts(t)
	require.Len(t, alerts, 2)
	require.NoError(t, json.Unmarshal([]byte(alerts[1].Params), &params))
	labels, levels := splitComma(params["granted_roles"]), splitComma(params["granted_role_levels"])
	require.Len(t, levels, len(labels))
	for i, l := range labels {
		want := model.APITokenLevelRead
		if l == model.BuiltinIdentityAdmin {
			want = model.APITokenLevelReadWrite
		}
		assert.Equal(t, want, levels[i], "角色 %s 的層級", l)
	}
	assert.Equal(t, model.BuiltinSecurityAdmin, params["privileged_roles"])
	assert.Equal(t, model.APITokenLevelRead, params["privileged_role_levels"], "高權限角色的層級取自同一個授權角色")
	assert.Equal(t, model.APITokenAccessMixed, params["access"])

	require.NoError(t, e.tokens.RevokeOwn(e.op(e.admin), got.View.ID, ""))
	revoked := e.tokenAudits(t, model.ActionAPITokenRevoked)
	require.Len(t, revoked, 1)
	assert.NotContains(t, revoked[0].Details, "granted_roles", "撤銷的稽核不帶授權角色（層級由建立事件查得）")
}

func splitComma(s string) []string {
	if s == "" {
		return nil
	}
	out := []string{}
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == ',' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return out
}

// TestAPITokenCreatedBeforeLevelsMarker 升級前建立的標記：本版起建立的 token（不論 roles 或 role_ids 寫法）不是升級前建立；
// 欄位出現前的列（由資料庫預設值補上否）投影為升級前建立。標記只供呈現：同一把 token 的彙總與層級不受影響。
func TestAPITokenCreatedBeforeLevelsMarker(t *testing.T) {
	e := newTokenEnv(t)
	owner := e.mkUser(t, "owner", "identity_admin")
	ida := e.roles["identity_admin"]
	leveled := e.createLeveled(t, owner, "leveled", APITokenRoleGrant{ida, model.APITokenLevelRead})
	legacyShape := e.mustCreate(t, owner, "role-ids", ida)
	assert.False(t, leveled.View.CreatedBeforeLevels, "建立回應：roles 寫法")
	assert.False(t, legacyShape.View.CreatedBeforeLevels, "建立回應：role_ids 寫法")
	assert.False(t, e.viewOf(t, owner, leveled.View.ID).CreatedBeforeLevels, "清單")

	// 欄位出現前的列：以不帶此欄的方式寫入，資料庫預設值補上否
	pre := model.APIToken{UserID: owner, Name: "pre-upgrade", TokenHash: "pre-upgrade-digest"}
	require.NoError(t, e.db.Omit("levels_recorded").Create(&pre).Error)
	require.NoError(t, e.db.Exec("INSERT INTO api_token_roles (api_token_id, role_id) VALUES (?, ?)", pre.ID, ida).Error)
	var stored model.APIToken
	require.NoError(t, e.db.First(&stored, pre.ID).Error)
	assert.False(t, stored.LevelsRecorded, "資料庫預設為否")
	v := e.viewOf(t, owner, pre.ID)
	assert.True(t, v.CreatedBeforeLevels, "升級前建立")
	assert.Equal(t, model.APITokenAccessReadWrite, v.Access, "升級前的 token 各角色為讀寫")
}

// TestAPITokenAuditRefCarriesAccessAndLevels 操作日誌詳情的「經由」資料：每個授權角色帶層級、token 帶彙總；
// 彙總依建立時的選擇，角色收回後不變；不認得的保存值視為唯讀。
func TestAPITokenAuditRefCarriesAccessAndLevels(t *testing.T) {
	e := newTokenEnv(t)
	owner := e.mkUser(t, "owner", "identity_admin", "security_admin")
	ida, sec := e.roles["identity_admin"], e.roles["security_admin"]
	mixed := e.createLeveled(t, owner, "mixed", APITokenRoleGrant{ida, model.APITokenLevelReadWrite}, APITokenRoleGrant{sec, model.APITokenLevelRead})
	ro := e.createLeveled(t, owner, "ro", APITokenRoleGrant{ida, model.APITokenLevelRead})

	ref, err := e.tokens.AuditRef(mixed.View.ID)
	require.NoError(t, err)
	require.True(t, ref.Found)
	assert.Equal(t, model.APITokenAccessMixed, ref.Access)
	got := map[uint]string{}
	for _, r := range ref.GrantedRoles {
		got[r.RoleID] = r.Level
	}
	assert.Equal(t, map[uint]string{ida: model.APITokenLevelReadWrite, sec: model.APITokenLevelRead}, got)

	ref, err = e.tokens.AuditRef(ro.View.ID)
	require.NoError(t, err)
	assert.Equal(t, model.APITokenAccessRead, ref.Access)

	// 角色收回後彙總不變
	require.NoError(t, e.db.Where("user_id = ? AND role_id = ?", owner, sec).Delete(&model.UserRole{}).Error)
	ref, err = e.tokens.AuditRef(mixed.View.ID)
	require.NoError(t, err)
	assert.Equal(t, model.APITokenAccessMixed, ref.Access, "角色收回後彙總不變")

	// 不認得的保存值視為唯讀
	require.NoError(t, e.db.Model(&model.APITokenRole{}).Where("api_token_id = ? AND role_id = ?", mixed.View.ID, ida).Update("level", "owner").Error)
	ref, err = e.tokens.AuditRef(mixed.View.ID)
	require.NoError(t, err)
	assert.Equal(t, model.APITokenAccessRead, ref.Access)

	// token 列不存在
	ref, err = e.tokens.AuditRef(999999)
	require.NoError(t, err)
	assert.False(t, ref.Found)
	assert.Empty(t, ref.Access)
}

// TestAPITokenRoleLabelsKeepItemCount 自訂角色名稱含半形逗號時，告警的角色清單項數仍與層級清單一致。
func TestAPITokenRoleLabelsKeepItemCount(t *testing.T) {
	roles := []APITokenRoleRef{
		{Name: "Ops,Review", Level: model.APITokenLevelRead},
		{BuiltinKey: model.BuiltinIdentityAdmin, Level: model.APITokenLevelReadWrite},
	}
	labels := strings.Split(strings.Join(apiTokenRoleLabels(roles), ","), ",")
	levels := strings.Split(strings.Join(apiTokenRoleLevels(roles), ","), ",")
	require.Len(t, labels, 2)
	require.Len(t, levels, len(labels))
	assert.Equal(t, "Ops，Review", labels[0])
}

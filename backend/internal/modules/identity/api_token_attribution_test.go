package identity

import (
	"testing"

	"github.com/custodexa/backend/config"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// 稽核歸因：以 API token 進行的操作，該次操作落地的每一筆稽核列都帶 token 識別與名稱快照；
// 親自操作的列兩欄為空。

func lastAuditID(t *testing.T, e *tokenEnv) uint {
	t.Helper()
	var id uint
	require.NoError(t, e.db.Raw("SELECT COALESCE(MAX(id), 0) FROM audit_logs").Scan(&id).Error)
	return id
}

func auditRowsAfter(t *testing.T, e *tokenEnv, after uint) []model.AuditLog {
	t.Helper()
	var rows []model.AuditLog
	require.NoError(t, e.db.Where("id > ?", after).Order("id").Find(&rows).Error)
	return rows
}

func assertAllAttributed(t *testing.T, rows []model.AuditLog, tokenID uint, name string) {
	t.Helper()
	require.NotEmpty(t, rows, "該次操作應有落地的稽核列")
	for _, r := range rows {
		if assert.NotNil(t, r.APITokenID, "列 %d（%s %s）應帶 token 識別", r.ID, r.Action, r.Resource) {
			assert.Equal(t, tokenID, *r.APITokenID)
		}
		if assert.NotNil(t, r.APITokenName, "列 %d 應帶 token 名稱", r.ID) {
			assert.Equal(t, name, *r.APITokenName)
		}
	}
}

func assertNoneAttributed(t *testing.T, rows []model.AuditLog) {
	t.Helper()
	require.NotEmpty(t, rows)
	for _, r := range rows {
		assert.Nil(t, r.APITokenID, "親自操作的列 %d（%s %s）不帶 token 識別", r.ID, r.Action, r.Resource)
		assert.Nil(t, r.APITokenName, "親自操作的列 %d 不帶 token 名稱", r.ID)
	}
}

// TestAPITokenRoleAssignmentTxRowsAttributed 以 token 變更角色指派：交易內寫入的角色列（資料層依操作者組出的稽核脈絡）帶標示；
// 同一 token 改動受保護帳號時，交易內寫入面的留痕列同樣帶標示；同一操作改以人類工作階段進行時兩欄為空。
func TestAPITokenRoleAssignmentTxRowsAttributed(t *testing.T) {
	e := newTokenEnv(t)
	root := e.mkUser(t, "root-a", "admin", "identity_admin")
	target := e.mkUser(t, "sec-t", "security_admin")
	tok := e.tokenOp(t, root, e.roles["identity_admin"])
	tok.APIToken = model.APITokenRef{ID: 77, Name: "terraform-ci"}

	before := lastAuditID(t, e)
	_, err := e.users.AssignRolesBy(tok, target, []string{"security_admin", "auditor"})
	require.NoError(t, err)
	e.withPassword(t, target)
	require.NoError(t, e.users.ChangePasswordBy(tok, target, "N3w-Passw0rd!xyz"))
	rows := auditRowsAfter(t, e, before)
	var roleRows, protectedRows int
	for _, r := range rows {
		switch r.Resource {
		case model.ResourceUserRole:
			roleRows++
		case model.ResourceUser:
			protectedRows++
		}
	}
	assert.Positive(t, roleRows, "交易內的角色指派列")
	assert.Positive(t, protectedRows, "受保護帳號的交易內留痕列")
	assertAllAttributed(t, rows, 77, "terraform-ci")

	// 人類工作階段：同一類操作，列不帶標示
	before = lastAuditID(t, e)
	_, err = e.users.AssignRolesBy(e.op(root), target, []string{"security_admin"})
	require.NoError(t, err)
	assertNoneAttributed(t, auditRowsAfter(t, e, before))
}

// TestAPITokenCreateRevokeByTokenAttributed 以 token 建立與撤銷 token：兩筆交易內稽核帶操作所經由的 token。
func TestAPITokenCreateRevokeByTokenAttributed(t *testing.T) {
	e := newRecordedTokenEnv(t)
	owner := e.mkUser(t, "owner", "identity_admin")
	op := e.op(owner)
	op.APIToken = model.APITokenRef{ID: 91, Name: "rotator"}
	before := lastAuditID(t, e)
	got, err := e.tokens.Create(op, CreateAPITokenInput{Name: "next", RoleIDs: []uint{e.roles["identity_admin"]}, NeverExpires: true})
	require.NoError(t, err)
	require.NoError(t, e.tokens.RevokeOwn(op, got.View.ID, ""))
	rows := auditRowsAfter(t, e, before)
	require.Len(t, rows, 2)
	assertAllAttributed(t, rows, 91, "rotator")
	for _, r := range rows {
		assert.NotContains(t, r.Details, got.Token, "稽核細節不含明文")
		assert.NotContains(t, r.Details, apiTokenDigest(got.Token), "稽核細節不含雜湊")
	}
}

// TestAPITokenCreateRevokeAuditedWithAuditSwitchOff 稽核開關關閉時，一般條目不落地，
// 建立與撤銷的稽核仍隨交易寫入。
func TestAPITokenCreateRevokeAuditedWithAuditSwitchOff(t *testing.T) {
	e := newRecordedTokenEnv(t)
	off := audit.NewAuditLogService(&config.FeatureFlags{AuditLogEnabled: false})
	owner := e.mkUser(t, "owner", "identity_admin")
	before := lastAuditID(t, e)
	off.Log(&audit.AuditLogEntry{UserID: owner, Username: "owner", Action: model.ActionUpdate, Resource: model.ResourceUser, Status: model.StatusSuccess})
	assert.Empty(t, auditRowsAfter(t, e, before), "開關關閉時一般條目不落地")

	got, err := e.tokens.Create(e.op(owner), CreateAPITokenInput{Name: "tf", RoleIDs: []uint{e.roles["identity_admin"]}, NeverExpires: true})
	require.NoError(t, err)
	require.NoError(t, e.tokens.RevokeOwn(e.op(owner), got.View.ID, "done"))
	assert.Len(t, e.tokenAudits(t, model.ActionCreate), 1, "建立仍有稽核")
	assert.Len(t, e.tokenAudits(t, model.ActionAPITokenRevoked), 1, "撤銷仍有稽核")
}

func selfAuditRowsAfter(t *testing.T, e *selfEnv, after uint) []model.AuditLog {
	t.Helper()
	var rows []model.AuditLog
	require.NoError(t, e.db.Where("id > ?", after).Order("id").Find(&rows).Error)
	return rows
}

func selfLastAuditID(t *testing.T, e *selfEnv) uint {
	t.Helper()
	var id uint
	require.NoError(t, e.db.Raw("SELECT COALESCE(MAX(id), 0) FROM audit_logs").Scan(&id).Error)
	return id
}

// TestAPITokenActorStructRowsAttributed 操作者結構帶進服務層的途徑：映射規則（映射操作者結構）與群組成員異動
// （操作者與來源位址）的交易內留痕皆帶標示；人類工作階段兩欄為空。
func TestAPITokenActorStructRowsAttributed(t *testing.T) {
	e := newSelfEnv(t)
	owner := e.mkUser(t, "owner", "identity_admin")
	other := e.mkUser(t, "other")
	tok := e.tokenOp(t, owner, e.roles["identity_admin"])
	tok.APIToken = model.APITokenRef{ID: 55, Name: "idp-sync"}
	actor := e.actorOf(tok)
	actor.APIToken = tok.APIToken
	g := e.group(t, "plain", nil)

	before := selfLastAuditID(t, e)
	_, err := e.src.CreateMapping(model.RoleMappingChannelKindProvider, e.provider, GroupRoleMappingInput{MatchValue: "ops", Role: "auditor",
		RiskAcknowledged: true, Actor: actor})
	require.NoError(t, err)
	ids := []uint{other}
	_, err = e.groups.ReplaceMembersBy(tok, g, &ids, nil)
	require.NoError(t, err)
	rows := selfAuditRowsAfter(t, e, before)
	var mapping, group int
	for _, r := range rows {
		if r.Resource == model.ResourceUserGroup {
			group++
		} else {
			mapping++
		}
	}
	assert.Positive(t, mapping, "映射規則的留痕列")
	assert.Positive(t, group, "群組成員異動的留痕列")
	for _, r := range rows {
		if assert.NotNil(t, r.APITokenID, "列 %d（%s %s）應帶標示", r.ID, r.Action, r.Resource) {
			assert.Equal(t, uint(55), *r.APITokenID)
		}
		if assert.NotNil(t, r.APITokenName) {
			assert.Equal(t, "idp-sync", *r.APITokenName)
		}
	}

	before = selfLastAuditID(t, e)
	_, err = e.src.CreateMapping(model.RoleMappingChannelKindProvider, e.provider, GroupRoleMappingInput{MatchValue: "ops2", Role: "auditor",
		RiskAcknowledged: true, Actor: e.actorOf(e.op(owner))})
	require.NoError(t, err)
	none := []uint{}
	_, err = e.groups.ReplaceMembersBy(e.op(owner), g, &none, nil)
	require.NoError(t, err)
	human := selfAuditRowsAfter(t, e, before)
	require.NotEmpty(t, human)
	for _, r := range human {
		assert.Nil(t, r.APITokenID, "親自操作的列 %d 不帶標示", r.ID)
		assert.Nil(t, r.APITokenName)
	}
}

// TestAPITokenAuditRefForAuditDetail 稽核詳情所需的 token 資訊：授權角色與到期取 token 列，所屬帳號刪除後標示已刪除，
// token 不存在時回未找到。
func TestAPITokenAuditRefForAuditDetail(t *testing.T) {
	e := newTokenEnv(t)
	owner := e.mkUser(t, "owner", "identity_admin")
	exp := e.future(48 * 3600 * 1e9)
	got, err := e.tokens.Create(e.op(owner), CreateAPITokenInput{Name: "tf", RoleIDs: []uint{e.roles["identity_admin"]}, ExpiresAt: exp})
	require.NoError(t, err)
	ref, err := e.tokens.AuditRef(got.View.ID)
	require.NoError(t, err)
	require.True(t, ref.Found)
	require.Len(t, ref.GrantedRoles, 1)
	assert.Equal(t, e.roles["identity_admin"], ref.GrantedRoles[0].RoleID)
	assert.NotEmpty(t, ref.GrantedRoles[0].Name)
	require.NotNil(t, ref.ExpiresAt)
	assert.True(t, exp.Equal(*ref.ExpiresAt))
	assert.False(t, ref.OwnerDeleted)
	require.NoError(t, e.db.Delete(&model.User{}, owner).Error)
	ref, err = e.tokens.AuditRef(got.View.ID)
	require.NoError(t, err)
	assert.True(t, ref.OwnerDeleted, "所屬帳號軟刪後標示已刪除")
	missing, err := e.tokens.AuditRef(999999)
	require.NoError(t, err)
	assert.False(t, missing.Found)
}

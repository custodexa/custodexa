package identity

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/pkg/gatewayapi"
)

// TestUserLockSQLiteUnchanged 固定 SQLite 單機部署的鎖行為：五個入口都在期限內完成，
// 且各自取得 per-user mutex 的次數與修正前相同（數字取自修正前的樹在同一 fixture 實測）。
// SQLite 沒有列鎖與 advisory 鎖，鎖序修正不得讓這些入口多取或少取行程內的 per-user mutex。
func TestUserLockSQLiteUnchanged(t *testing.T) {
	const deadline = 10 * time.Second
	var mu sync.Mutex
	counts := map[uint]int{}
	restoreMutexHook := SetUserMutexAcquireHookForTest(func(id uint) { mu.Lock(); counts[id]++; mu.Unlock() })
	defer restoreMutexHook()
	reset := func() { mu.Lock(); counts = map[uint]int{}; mu.Unlock() }
	// check 比對總次數與各使用者次數，並清空計數；expect 未列出的使用者次數必須為 0（含在總數內）。
	check := func(name string, total int, expect map[uint]int) {
		t.Helper()
		mu.Lock()
		defer mu.Unlock()
		sum := 0
		for _, c := range counts {
			sum += c
		}
		require.Equal(t, total, sum, "%s 的 per-user mutex 取得總次數", name)
		for id, want := range expect {
			require.Equal(t, want, counts[id], "%s 使用者 %d 的取得次數", name, id)
		}
		counts = map[uint]int{}
	}
	within := func(name string, fn func() error) {
		t.Helper()
		done := make(chan error, 1)
		go func() { done <- fn() }()
		select {
		case err := <-done:
			require.NoError(t, err, name)
		case <-time.After(deadline):
			t.Fatalf("%s 逾時", name)
		}
	}

	e := newGroupBindEnv(t)
	a := e.mkUser(t, "a")
	b := e.mkUser(t, "b", "auditor")
	c := e.mkUser(t, "c")
	gid := e.group(t, "g", a, b, c)
	other := e.group(t, "other", c)
	require.NoError(t, e.db.Create(&model.UserGroupRole{UserGroupID: gid, RoleID: e.roles["auditor"], ScopeKind: model.ScopeKindGlobal}).Error)
	require.NoError(t, e.db.Create(&model.UserGroupRole{UserGroupID: other, RoleID: e.roles["auditor"], ScopeKind: model.ScopeKindGlobal}).Error)

	// 1 群組角色替換（含 losers）：只有失去角色的 a 取一次
	reset()
	within("group_role_replace_with_losers", func() error {
		_, err := e.svc.ReplaceRoleBindings(e.op(e.admin), gid, GroupRoleBindingsRequest{RoleIDs: nil})
		return err
	})
	check("group_role_replace_with_losers", 1, map[uint]int{a: 1, b: 0, c: 0})

	// 2 成員替換：移除 a、新增 d，b、c 保留
	d := e.mkUser(t, "d")
	reset()
	within("group_member_replace", func() error {
		_, err := e.svc.ReplaceMembersBy(e.op(e.admin), gid, &[]uint{b, c, d}, nil)
		return err
	})
	check("group_member_replace", 4, map[uint]int{a: 1, b: 1, c: 1, d: 1})

	// 3 群組刪除：此時成員為 b、c、d
	require.NoError(t, e.db.AutoMigrate(&model.UserRoleMapping{}, &model.Asset{}, &model.AssetNode{}, &model.AssetAuthorization{}, &model.ApproverScope{}, &model.AccessRequest{}, &model.AccessRequestItem{}, &model.AccessRequestApproval{}))
	delSvc := NewUserGroupService(e.db, audit.NewTxSink(), authz.NewAssetAuthorizationService(e.db))
	delSvc.SetAssignmentGuard(NewAssignmentGuard(FullCatalog()))
	reset()
	within("group_delete", func() error {
		_, err := delSvc.DeleteBy(e.op(e.admin), gid)
		return err
	})
	check("group_delete", 3, map[uint]int{a: 0, b: 1, c: 1, d: 1})

	// 4 映射撤銷（a、c 兩名使用者）：要走到撤權分支（角色收回、世代推進、refresh token 撤銷）
	channel := model.RoleMappingChannel(model.RoleMappingChannelKindProvider, 1)
	var rule model.GroupRoleMapping
	require.NoError(t, e.db.Transaction(func(tx *gorm.DB) error {
		extGroup, err := ensureExternalGroupWithNote(tx, model.RoleMappingChannelKindProvider, 1, "unchanged-group", "")
		if err != nil {
			return err
		}
		p := uint(1)
		rule = model.GroupRoleMapping{OIDCProviderID: &p, ExternalGroupID: extGroup, MatchValue: "unchanged-group", RoleID: e.roles["auditor"], Enabled: true, CreatedBy: e.admin}
		return tx.Create(&rule).Error
	}))
	require.NoError(t, e.db.AutoMigrate(&model.RefreshToken{}, &model.AgentToken{}))
	for _, uid := range []uint{a, c} {
		require.NoError(t, e.db.Create(&model.UserRoleMappingRuleSupport{UserID: uid, RoleID: e.roles["auditor"], Channel: channel, RuleID: rule.ID}).Error)
		require.NoError(t, e.db.Create(&model.UserRoleMapping{UserID: uid, RoleID: e.roles["auditor"], Channel: channel, MatchedAt: time.Now()}).Error)
		require.NoError(t, e.db.Create(&model.UserRole{UserID: uid, RoleID: e.roles["auditor"], Source: model.RoleSourceMapped, ScopeKind: model.ScopeKindGlobal}).Error)
		require.NoError(t, e.db.Create(&model.RefreshToken{UserID: uid, TokenHash: fmt.Sprintf("unchanged-%d", uid), SessionStartedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour), LastUsedAt: time.Now()}).Error)
	}
	epochOf := func(uid uint) int {
		var u model.User
		require.NoError(t, e.db.First(&u, uid).Error)
		return u.CredentialEpoch
	}
	epochA, epochC := epochOf(a), epochOf(c)
	reset()
	within("mapping_revoke_two_users", func() error {
		return e.db.Transaction(func(tx *gorm.DB) error {
			return revokeMappingSupportsLocked(tx, audit.NewTxSink(), model.RoleMappingChannelKindProvider, 1, "role", rule.ID)
		})
	})
	for _, uid := range []uint{a, c} {
		var roleRows, liveTokens int64
		require.NoError(t, e.db.Model(&model.UserRole{}).Where("user_id = ?", uid).Count(&roleRows).Error)
		require.NoError(t, e.db.Model(&model.RefreshToken{}).Where("user_id = ? AND revoked_at IS NULL", uid).Count(&liveTokens).Error)
		require.Zero(t, roleRows)
		require.Zero(t, liveTokens)
	}
	require.Equal(t, epochA+1, epochOf(a))
	require.Equal(t, epochC+1, epochOf(c))
	check("mapping_revoke_two_users", 2, map[uint]int{a: 1, c: 1})

	// 5 簽 agent 憑證：只取擁有者的 per-user mutex
	agent := e.agent(t, "ag")
	svc := NewAgentTokenService(e.db, audit.NewTxSink())
	reset()
	within("agent_token_create", func() error {
		_, err := svc.Create(agent, CreateAgentTokenRequest{Name: "t", ExpiresAt: time.Now().Add(time.Hour)}, gatewayapi.Actor{UserID: e.admin, Username: "root"})
		return err
	})
	check("agent_token_create", 1, map[uint]int{agent: 0, e.admin: 1})
}

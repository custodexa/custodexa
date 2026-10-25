package identity

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
)

// chainHeadMatchesState 回報事件鏈最後一筆的事後摘要是否等於現況摘要。
func chainHeadMatchesState(t *testing.T, db *gorm.DB) (head, current string) {
	t.Helper()
	var ev model.PermissionStateEvent
	require.NoError(t, db.Order("seq DESC").First(&ev).Error)
	require.NoError(t, db.Transaction(func(tx *gorm.DB) error {
		st, err := audit.ReadPermissionState(context.Background(), tx)
		if err != nil {
			return err
		}
		current, err = st.Digest()
		return err
	}))
	return ev.AfterDigest, current
}

// TestScopedAssignmentEventChain 擋：直接指派新增帶節點範圍的角色時，範圍與節點在版本推進之後才寫入，
// 交易結尾沒有補記，事件鏈的事後摘要少了範圍與節點，下一筆權限寫入就多出一筆無來源變動。
func TestScopedAssignmentEventChain(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name        string
		seedExisted bool // 先以全域列備妥既有的 assetmgr
		seedScoped  bool // 先備妥既有的節點範圍 assetmgr
		names       []string
		scoped      []string // 本次要帶節點的角色名
		wantBumps   int64
	}{
		{name: "U1 新增一個帶節點的角色", names: []string{"assetmgr"}, scoped: []string{"assetmgr"}, wantBumps: 1},
		{name: "U7 一次新增兩個都帶節點的角色", names: []string{"assetmgr", "assetmgr-b"}, scoped: []string{"assetmgr", "assetmgr-b"}, wantBumps: 2},
		{name: "U9 帶節點的角色加一個全域角色", names: []string{"assetmgr", "plain-view"}, scoped: []string{"assetmgr"}, wantBumps: 2},
		{name: "U10 新增帶節點的角色而既有節點角色不動", seedScoped: true, names: []string{"assetmgr", "assetmgr-b"}, scoped: []string{"assetmgr-b"}, wantBumps: 1},
		{name: "對照 既有全域角色只改為節點範圍", seedExisted: true, names: []string{"assetmgr"}, scoped: []string{"assetmgr"}, wantBumps: 1},
		{name: "對照 只新增全域角色", names: []string{"plain-view"}, wantBumps: 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newNodeRaceEnv(t)
			e.create(t, "assetmgr-b", permStrings(authz.ScopedTemplateAssetAdminPermissions())...)
			e.create(t, "plain-view", "asset:view")
			e.create(t, "followup-view", "session:view")
			node := e.node(t, "chain-node")
			u := e.mkUser(t, "chain-holder")
			if tc.seedExisted {
				require.NoError(t, e.db.Create(&model.UserRole{UserID: u, RoleID: e.rid(t, "assetmgr"), Source: model.RoleSourceManual, ScopeKind: model.ScopeKindGlobal}).Error)
			}
			if tc.seedScoped {
				_, err := e.assign(u, []string{"assetmgr"}, map[string]RoleNodesValue{"assetmgr": nodesOf(node)})
				require.NoError(t, err)
			}
			audit.SetPermissionSources(authz.PermissionStateAuthzPart, PermissionStateIdentityPart)
			t.Cleanup(func() { audit.SetPermissionSources(nil, nil) })
			require.NoError(t, e.db.Transaction(func(tx *gorm.DB) error {
				st, err := audit.ReadPermissionState(ctx, tx)
				if err != nil {
					return err
				}
				_, err = audit.EnsurePermissionActivation(ctx, tx, st, 1)
				return err
			}))

			v0, err := authz.CurrentVersion(e.db)
			require.NoError(t, err)
			nodes := map[string]RoleNodesValue{}
			for _, n := range tc.scoped {
				nodes[n] = nodesOf(node)
			}
			_, err = e.assign(u, tc.names, nodes)
			require.NoError(t, err)

			head, current := chainHeadMatchesState(t, e.db)
			assert.Equal(t, current, head, "提交後鏈頭的事後摘要等於現況")
			v1, err := authz.CurrentVersion(e.db)
			require.NoError(t, err)
			assert.Equal(t, tc.wantBumps, v1-v0, "版本推進次數等於新增或改範圍的角色數")

			// 再做一筆合法寫入：殘差若存在，會在這一步的開頭被記成無來源變動。
			require.NoError(t, e.users.AddRoleBy(e.op(e.idAdmin), u, "followup-view"))
			assert.Zero(t, eventKinds(t, e.db)[model.PermEventUntraced], "後續寫入前後都沒有無來源變動")
		})
	}
}

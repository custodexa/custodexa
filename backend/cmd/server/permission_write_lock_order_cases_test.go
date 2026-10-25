package main

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/pkg/crypto"
)

// TestPermissionWriteLockOrder 子案例 (a)–(d) 的組裝：同一組裝根同時組裝 identity 與 asset 的真服務，
// 每個參與者一個連線池；共用列由正式的級聯撤銷或映射撤銷寫到。

const pwloClientIP = "127.0.0.1"

func (e *pwloEnv) op() identity.Operator {
	return identity.Operator{UserID: e.root, Username: "pwlo-root", ClientIP: pwloClientIP}
}

func (e *pwloEnv) userDeleteParty() pwloParty {
	svc := identity.NewUserService(e.actor("user").db, e.revoker("user"))
	svc.SetAssignmentGuard(identity.NewAssignmentGuard(identity.FullCatalog()))
	return pwloParty{name: "user_delete", actor: "user", stopSite: "revoke_by_user", run: func(fx *pwloFixture) error {
		_, err := svc.DeleteWithSummaryBy(e.op(), fx.user)
		return err
	}}
}

func (e *pwloEnv) nodeDeleteParty() pwloParty {
	svc := newWiredAssetGroupService(e.actor("node").db, e.revoker("node"))
	return pwloParty{name: "node_delete", actor: "node", stopSite: "revoke_by_asset_group", topology: true, run: func(fx *pwloFixture) error {
		_, err := svc.Delete(e.nodeCtx(), fx.node, e.root, "pwlo-root", pwloClientIP)
		return err
	}}
}

func (e *pwloEnv) groupDeleteParty() pwloParty {
	svc := identity.NewUserGroupService(e.actor("group").db, audit.NewTxSink(), e.revoker("group"))
	return pwloParty{name: "group_delete", actor: "group", stopSite: "revoke_by_user_group", run: func(fx *pwloFixture) error {
		_, err := svc.Delete(fx.group, e.root, "pwlo-root", pwloClientIP)
		return err
	}}
}

// assetDeleteParty 資產刪除走正式的範圍化刪除流程：操作者 op 不是系統呼叫者，服務在交易內取拓撲鎖後
// 以正式目錄與拓撲重讀主體與歸屬判定範圍，再級聯撤銷授權與審核範圍。
func (e *pwloEnv) assetDeleteParty(t *testing.T, op uint) pwloParty {
	t.Helper()
	aes, err := crypto.NewAESCrypto(make([]byte, 32))
	require.NoError(t, err)
	svc, err := asset.NewAssetService(fieldCapTestCodec{c: aes}, "localhost", 4822, audit.NewTxSink())
	require.NoError(t, err)
	svc.SetAuthorizationRevoker(e.revoker("asset"))
	svc.SetTopologyPermissionPort(authz.TopologyPermissionAdapter{})
	svc.SetSecurityChangeAlertSink(noopAlertSink{})
	svc.SetAssetWriteScopePort(authz.NewAssetWriteScope(authz.NewScopeEvaluator(authz.ProductCatalogue(), asset.NewScopeTopologyReader())))
	// AssetService 經 database.DB 開交易：本子案例把它指向資產參與者的連線池
	database.DB = e.actor("asset").db
	ctx := context.WithValue(context.Background(), "userID", op) //nolint:staticcheck // 沿用審計 context 慣例
	ctx = authz.ContextWithPrincipal(ctx, &authz.Principal{UserID: op})
	return pwloParty{name: "asset_delete", actor: "asset", stopSite: "revoke_by_asset", topology: true, run: func(fx *pwloFixture) error {
		return svc.Delete(ctx, fx.asset)
	}}
}

// scopedAssetOperator 只持節點範圍資產刪除能力的操作者：自訂角色（檢視、刪除）以節點範圍指派在 node 上。
func (e *pwloEnv) scopedAssetOperator(t *testing.T, node uint) uint {
	t.Helper()
	for _, k := range []authz.Permission{authz.PermAssetDelete} {
		d, ok := authz.LookupPermission(k)
		require.True(t, ok)
		require.Equal(t, authz.ScopeEnforced, d.Scope, "前提：%s 在正式目錄已啟用範圍判定", k)
	}
	op := e.human(t, "pwlo-c-op")
	r := model.Role{Name: "pwlo-c-asset-deleter", DefinitionVersion: 1}
	require.NoError(t, e.fix.Create(&r).Error)
	for _, k := range []authz.Permission{authz.PermAssetView, authz.PermAssetDelete} {
		require.NoError(t, e.fix.Create(&model.RolePermission{RoleID: r.ID, PermissionKey: string(k)}).Error)
	}
	require.NoError(t, e.fix.Create(&model.UserRole{UserID: op, RoleID: r.ID, Source: model.RoleSourceManual, ScopeKind: model.ScopeKindNodes}).Error)
	require.NoError(t, e.fix.Create(&model.RoleBindingNode{SubjectKind: model.BindingSubjectUser, SubjectID: op, RoleID: r.ID, NodeID: node}).Error)
	return op
}

// probeScopedDelete 範圍判定確實走到的自檢：同一操作者刪除另掛範圍外節點的資產，須回範圍外歸屬拒絕且資產仍在
// （若刪除經系統呼叫者略過判定，或節點範圍來源未生效，這裡就會成功或回能力拒絕）。
func (e *pwloEnv) probeScopedDelete(t *testing.T, party pwloParty, inScope uint) {
	t.Helper()
	outside := e.newNode(t, "c-probe-out")
	a := model.Asset{Name: "pwlo-asset-probe", Host: "10.9.0.2", Port: 5901, Protocol: model.ProtocolVNC, Active: true}
	require.NoError(t, e.fix.Create(&a).Error)
	for _, n := range []uint{inScope, outside} {
		require.NoError(t, e.fix.Create(&model.AssetNode{AssetID: a.ID, NodeID: n}).Error)
	}
	err := party.run(&pwloFixture{asset: a.ID})
	var oos *asset.AssetOutOfScopeNodesError
	require.True(t, errors.As(err, &oos), "掛範圍外節點的資產刪除應回範圍外歸屬拒絕，實得 %v", err)
	require.Equal(t, 1, oos.Count)
	require.Zero(t, e.deleted(t, "assets", a.ID), "被拒的刪除不得刪到資產")
	fmt.Printf("EVIDENCE scoped-delete-probe subcase=%s out_of_scope_nodes=%d\n", e.subcase, oos.Count)
}

func (e *pwloEnv) mappingDeleteParty(t *testing.T) pwloParty {
	t.Helper()
	svc := identity.NewIdentitySourceService(e.actor("mapping").db, audit.NewTxSink())
	svc.SetAssignmentGuard(identity.NewAssignmentGuard(identity.FullCatalog()))
	// 先行停點：映射撤銷寫完該使用者的支持記錄、仍持其使用者憑證鎖、尚未提交
	restore := identity.SetLockOrderHookForTest(func(point string, tx *gorm.DB, ids ...uint) {
		if point == "mapping_revoke_after_user" && len(ids) > 0 {
			e.stops.hit("mapping_revoke_after_user", tx)
		}
	})
	t.Cleanup(restore)
	actor := identity.GroupRoleMappingActor{ID: e.root, Name: "pwlo-root", IP: pwloClientIP}
	return pwloParty{name: "mapping_rule_delete", actor: "mapping", stopSite: "mapping_revoke_after_user", run: func(fx *pwloFixture) error {
		return svc.DeleteMapping(model.RoleMappingChannelKindProvider, fx.provider, fx.rule, actor)
	}}
}

func (e *pwloEnv) newNode(t *testing.T, tag string) uint {
	t.Helper()
	n := model.AssetGroup{Name: "pwlo-node-" + tag}
	require.NoError(t, e.fix.Create(&n).Error)
	return n.ID
}

func (e *pwloEnv) newGroup(t *testing.T, tag string) uint {
	t.Helper()
	g := model.UserGroup{Name: "pwlo-group-" + tag}
	require.NoError(t, e.fix.Create(&g).Error)
	return g.ID
}

func (e *pwloEnv) userScope(t *testing.T, user uint, assetID, nodeID *uint) uint {
	t.Helper()
	u := user
	s := model.ApproverScope{ApproverID: &u, AssetID: assetID, AssetGroupID: nodeID, GrantedBy: e.root}
	require.NoError(t, e.fix.Create(&s).Error)
	return s.ID
}

func (e *pwloEnv) deleted(t *testing.T, table string, id uint) int64 {
	t.Helper()
	return e.scalar(t, "SELECT count(*) FROM "+table+" WHERE id = ? AND deleted_at IS NOT NULL", id)
}

// pwloBuildCase 依子案例名組出環境與參與者。
func pwloBuildCase(t *testing.T, name string) (*pwloEnv, pwloCase) {
	t.Helper()
	switch name {
	case "user_delete_vs_node_delete":
		// (a) U 是 N 上一筆審核範圍的審核方：RevokeByUser／RevokeByAssetGroup 軟刪同一列 approver_scopes
		e := newPWLOEnv(t, name, true, "user", "node")
		return e, pwloCase{
			parties: [2]pwloParty{e.userDeleteParty(), e.nodeDeleteParty()},
			target:  func(*pwloFixture) pwloTarget { return pwloRowLock() },
			setup: func(t *testing.T, tag string) *pwloFixture {
				fx := &pwloFixture{user: e.human(t, "pwlo-a-u-"+tag), node: e.newNode(t, "a-"+tag)}
				n := fx.node
				fx.scope = e.userScope(t, fx.user, nil, &n)
				fx.version = e.version(t)
				return fx
			},
			snap: func(t *testing.T, fx *pwloFixture) map[string]int64 {
				return map[string]int64{
					"user_deleted":  e.deleted(t, "users", fx.user),
					"node_deleted":  e.deleted(t, "asset_groups", fx.node),
					"scope_deleted": e.deleted(t, "approver_scopes", fx.scope),
					"scopes_live":   e.scalar(t, "SELECT count(*) FROM approver_scopes WHERE (approver_id = ? OR asset_group_id = ?) AND deleted_at IS NULL", fx.user, fx.node),
					"node_audit":    e.scalar(t, "SELECT count(*) FROM audit_logs WHERE resource = ? AND resource_id = ? AND action = ?", string(model.ResourceAsset), fx.node, string(model.ActionDelete)),
					"version_delta": e.version(t) - fx.version,
				}
			},
		}
	case "group_delete_vs_node_delete":
		// (b) G 在 N 上有節點授權：RevokeByUserGroup／RevokeByAssetGroup 軟刪同一列 asset_authorizations
		e := newPWLOEnv(t, name, true, "group", "node")
		return e, pwloCase{
			parties: [2]pwloParty{e.groupDeleteParty(), e.nodeDeleteParty()},
			target:  func(*pwloFixture) pwloTarget { return pwloRowLock() },
			setup: func(t *testing.T, tag string) *pwloFixture {
				fx := &pwloFixture{group: e.newGroup(t, "b-"+tag), node: e.newNode(t, "b-"+tag)}
				g, n := fx.group, fx.node
				a := model.AssetAuthorization{UserGroupID: &g, AssetGroupID: &n, Permission: model.PermissionConnect, Source: "manual", GrantedBy: e.root}
				require.NoError(t, e.fix.Create(&a).Error)
				fx.authz = a.ID
				fx.version = e.version(t)
				return fx
			},
			snap: func(t *testing.T, fx *pwloFixture) map[string]int64 {
				return map[string]int64{
					"group_deleted": e.deleted(t, "user_groups", fx.group),
					"node_deleted":  e.deleted(t, "asset_groups", fx.node),
					"authz_deleted": e.deleted(t, "asset_authorizations", fx.authz),
					"authz_live":    e.scalar(t, "SELECT count(*) FROM asset_authorizations WHERE (user_group_id = ? OR asset_group_id = ?) AND deleted_at IS NULL", fx.group, fx.node),
					"node_audit":    e.scalar(t, "SELECT count(*) FROM audit_logs WHERE resource = ? AND resource_id = ? AND action = ?", string(model.ResourceAsset), fx.node, string(model.ActionDelete)),
					"group_audit":   e.scalar(t, "SELECT count(*) FROM audit_logs WHERE resource = ? AND resource_id = ? AND action = ?", string(model.ResourceUserGroup), fx.group, string(model.ActionDelete)),
					"version_delta": e.version(t) - fx.version,
				}
			},
		}
	case "asset_delete_vs_user_delete":
		// (c) U 是 A 上一筆資產型審核範圍的審核方：RevokeByAsset／RevokeByUser 軟刪同一列 approver_scopes。
		// 資產刪除由只持節點範圍刪除能力的操作者經正式範圍化流程執行（A 只掛其範圍內節點）
		e := newPWLOEnv(t, name, true, "asset", "user")
		scopeNode := e.newNode(t, "c-scope")
		assetParty := e.assetDeleteParty(t, e.scopedAssetOperator(t, scopeNode))
		e.probeScopedDelete(t, assetParty, scopeNode)
		return e, pwloCase{
			parties: [2]pwloParty{assetParty, e.userDeleteParty()},
			target:  func(*pwloFixture) pwloTarget { return pwloRowLock() },
			setup: func(t *testing.T, tag string) *pwloFixture {
				fx := &pwloFixture{user: e.human(t, "pwlo-c-u-"+tag), node: scopeNode}
				a := model.Asset{Name: "pwlo-asset-" + tag, Host: "10.9.0.1", Port: 5901, Protocol: model.ProtocolVNC, Active: true}
				require.NoError(t, e.fix.Create(&a).Error)
				fx.asset = a.ID
				require.NoError(t, e.fix.Create(&model.AssetNode{AssetID: a.ID, NodeID: fx.node}).Error)
				id := a.ID
				fx.scope = e.userScope(t, fx.user, &id, nil)
				fx.version = e.version(t)
				return fx
			},
			snap: func(t *testing.T, fx *pwloFixture) map[string]int64 {
				return map[string]int64{
					"asset_deleted": e.deleted(t, "assets", fx.asset),
					"user_deleted":  e.deleted(t, "users", fx.user),
					"scope_deleted": e.deleted(t, "approver_scopes", fx.scope),
					"scopes_live":   e.scalar(t, "SELECT count(*) FROM approver_scopes WHERE (approver_id = ? OR asset_id = ?) AND deleted_at IS NULL", fx.user, fx.asset),
					"asset_nodes":   e.scalar(t, "SELECT count(*) FROM asset_nodes WHERE asset_id = ?", fx.asset),
					"version_delta": e.version(t) - fx.version,
				}
			},
		}
	case "mapping_rule_delete_vs_user_delete":
		// (d) 刪除映射規則（受影響使用者含 U）× 刪除 U：兩邊都取 U 的使用者憑證鎖、都寫到 U 的同一筆支持記錄
		e := newPWLOEnv(t, name, true, "mapping", "user")
		var userRole model.Role
		require.NoError(t, e.fix.Where("name = ?", model.RoleUser).First(&userRole).Error)
		return e, pwloCase{
			parties: [2]pwloParty{e.mappingDeleteParty(t), e.userDeleteParty()},
			target:  func(fx *pwloFixture) pwloTarget { return pwloUserLock(fx.user) },
			setup: func(t *testing.T, tag string) *pwloFixture {
				fx := &pwloFixture{user: e.human(t, "pwlo-d-u-"+tag), role: userRole.ID}
				p := model.OIDCProvider{Name: "pwlo-d-" + tag, Issuer: "https://id.example.test/pwlo-" + tag, ClientID: "client",
					Scopes: "openid groups", GroupsClaim: "groups", Enabled: true, AdmissionMode: model.AdmissionPreboundOnly, AdmissionRules: "{}"}
				require.NoError(t, e.fix.Create(&p).Error)
				fx.provider = p.ID
				fx.channel = model.RoleMappingChannel(model.RoleMappingChannelKindProvider, p.ID)
				ext := model.ExternalGroup{OIDCProviderID: &p.ID, MatchValue: "ops"}
				require.NoError(t, e.fix.Create(&ext).Error)
				rule := model.GroupRoleMapping{OIDCProviderID: &p.ID, ExternalGroupID: ext.ID, MatchValue: "ops", RoleID: userRole.ID, Enabled: true, CreatedBy: e.root}
				require.NoError(t, e.fix.Create(&rule).Error)
				fx.rule = rule.ID
				require.NoError(t, e.fix.Create(&model.UserRoleMappingRuleSupport{UserID: fx.user, RoleID: userRole.ID, Channel: fx.channel, RuleID: rule.ID}).Error)
				require.NoError(t, e.fix.Create(&model.UserRole{UserID: fx.user, RoleID: userRole.ID, Source: model.RoleSourceMapped, ScopeKind: model.ScopeKindGlobal}).Error)
				require.NoError(t, e.fix.Create(&model.UserRoleMapping{UserID: fx.user, RoleID: userRole.ID, Channel: fx.channel, MatchedAt: time.Now()}).Error)
				fx.version = e.version(t)
				return fx
			},
			snap: func(t *testing.T, fx *pwloFixture) map[string]int64 {
				return map[string]int64{
					"user_deleted":  e.deleted(t, "users", fx.user),
					"rule_deleted":  e.deleted(t, "group_role_mappings", fx.rule),
					"supports":      e.scalar(t, "SELECT count(*) FROM user_role_mapping_rule_supports WHERE user_id = ? OR rule_id = ?", fx.user, fx.rule),
					"facts":         e.scalar(t, "SELECT count(*) FROM user_role_mappings WHERE user_id = ?", fx.user),
					"mapped_roles":  e.scalar(t, "SELECT count(*) FROM user_roles WHERE user_id = ? AND role_id = ?", fx.user, fx.role),
					"rule_audit":    e.scalar(t, "SELECT count(*) FROM audit_logs WHERE resource = ? AND resource_id = ? AND action = ?", string(model.ResourceAuth), fx.rule, string(model.ActionDelete)),
					"revoke_audit":  e.scalar(t, "SELECT count(*) FROM audit_logs WHERE resource = ? AND resource_id = ? AND error_msg = ?", string(model.ResourceUser), fx.user, identity.MappingRuleRevokedEvent),
					"version_delta": e.version(t) - fx.version,
				}
			},
		}
	case "asset_create_vs_credential_rotate":
		// (f) 建立資產並掛共用憑證 C × 先取拓撲鎖再以 FOR UPDATE 鎖 C 的寫入（最小替身寫法，不經完整的授權寫入流程）
		return pwloBuildCreateVsRotate(t, name)
	default:
		t.Fatalf("未知子案例 %s", name)
		return nil, pwloCase{}
	}
}

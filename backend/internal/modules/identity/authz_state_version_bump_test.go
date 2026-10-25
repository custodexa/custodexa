package identity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
	"gorm.io/gorm"
)

// TestAuthzStateVersionBump 權限版本推進。
//
// 擋三件事：
//   - 撤權相關寫入沒有推進版本（漏推進＝之後的 token 失效與快取撤權不生效）；
//   - 交易回滾仍推進版本（寫入沒生效，版本卻動了）；
//   - 唯讀路徑推進版本。
//
// 結構：
//   - 「路徑01」…「路徑23」各一個子測試，對應權限版本推進清單的 23 個寫入路徑，
//     每條路徑自備起始狀態並斷言執行後版本確實前進；
//   - `rollback_no_advance`：在 `authz_state` 上掛一個遇更新即中止的觸發器，逼每條路徑的
//     推進呼叫失敗，斷言路徑回錯、版本不動、且該路徑碰過的全部表原封不動——
//     推進若沒有與寫入同交易（或根本沒被呼叫到），這裡必紅；
//   - `readonly_no_advance`：一組唯讀入口跑完版本與資料皆不動；
//   - `noop_no_advance`：沒有實際改變授權狀態的寫入呼叫（冪等重送、只更新命中時間）不推進。

// bumpPathCount 權限版本推進清單的路徑數；清單增減時同步調整。
const bumpPathCount = 23

type bumpEnv struct {
	t       *testing.T
	db      *gorm.DB
	users   *UserService
	groups  *UserGroupService
	mapping *IdentitySourceService
	login   *OIDCLoginService // 僅路徑08 設置（該路徑需要自己的 OIDC 夾具）

	alice, bob *model.User
	role       *model.Role
	group      *model.UserGroup
	provider   *model.OIDCProvider
	channel    string

	// beginInTx 由 permission_event_replay 設定：tx 級函式依契約由呼叫端在交易開頭呼叫
	// authz.BeginPermissionChange（生產的外層入口皆已呼叫），inTx 代為扮演該外層。
	beginInTx bool
}

var bumpActor = GroupRoleMappingActor{ID: 1, Name: "admin", IP: "10.0.0.1"}

func newBumpEnv(t *testing.T) *bumpEnv {
	t.Helper()
	db := extIdentityDB(t)
	if err := migrateWithAuthz(db, &model.UserGroup{}, &model.PasswordHistory{}, &model.SecurityPolicy{},
		&model.LDAPDirectory{}, &model.GroupRoleMapping{}, &model.ExternalGroup{},
		&model.GroupUserGroupMapping{}, &model.UserRoleMapping{},
		&model.UserRoleMappingRuleSupport{}, &model.UserGroupMappingRuleSupport{}, &model.UserChannelObservation{},
		&model.UserGroupRole{}, &model.Asset{}, &model.AssetGroup{}, &model.AssetNode{},
		&model.AssetAuthorization{}, &model.ApproverScope{},
		&model.AccessRequest{}, &model.AccessRequestItem{}, &model.AccessRequestApproval{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	// 關聯 model 必須排在 many2many 宣稱者（User／UserGroup）之後另跑一次：
	// 與 UserRole 同理，同批遷移會被自動建出的兩欄關聯表蓋掉，少一欄卻編譯得過
	if err := db.AutoMigrate(&model.UserGroupMember{}); err != nil {
		t.Fatalf("migrate user_group_members: %v", err)
	}
	env := newExtIdentityEnv(t, db)
	e := &bumpEnv{t: t, db: db, users: env.svc}
	e.groups = NewUserGroupService(db, audit.NewTxSink(), authz.NewAssetAuthorizationService(db))
	e.mapping = NewIdentitySourceService(db, audit.NewTxSink())
	e.alice = seedAccount(t, db, adminSpec{username: "alice", active: true})
	e.bob = seedAccount(t, db, adminSpec{username: "bob", active: true})
	// 角色規則的目標只認內建範本（自訂角色改走使用者群組）；以稽核員範本取代原本的自訂角色
	e.role = &model.Role{Name: "auditor"}
	if err := db.Create(e.role).Error; err != nil {
		t.Fatalf("seed role: %v", err)
	}
	ensureFixtureSuperAdmin(t, db, bumpActor.ID)
	// 再備一位超級管理者，使操作者不是最後一位（部分路徑會刪除或停用操作者帳號本身）
	spare := seedAccount(t, db, adminSpec{username: "spare-admin", active: true})
	ensureFixtureSuperAdmin(t, db, spare.ID)
	e.group = &model.UserGroup{Name: "ops-group"}
	if err := db.Create(e.group).Error; err != nil {
		t.Fatalf("seed group: %v", err)
	}
	e.provider = seedExtProvider(t, db, "corp", "https://idp.example.com", "cid-1")
	if err := db.Model(e.provider).Update("groups_claim", "groups").Error; err != nil {
		t.Fatalf("provider groups claim: %v", err)
	}
	e.channel = model.RoleMappingChannel(model.RoleMappingChannelKindProvider, e.provider.ID)
	return e
}

func (e *bumpEnv) version() int64 {
	e.t.Helper()
	v, err := authz.CurrentVersion(e.db)
	if err != nil {
		e.t.Fatalf("CurrentVersion: %v", err)
	}
	return v
}

// inTx 以交易包住 tx 級函式（與生產呼叫端相同的形狀）。
func (e *bumpEnv) inTx(fn func(tx *gorm.DB) error) func() error {
	return func() error {
		return e.db.Transaction(func(tx *gorm.DB) error {
			if e.beginInTx {
				if err := authz.BeginPermissionChange(tx); err != nil {
					return err
				}
			}
			return fn(tx)
		})
	}
}

// digest 相關表的完整內容快照；任何寫入（含未回滾的殘留）都會讓它改變。
func (e *bumpEnv) digest() string {
	e.t.Helper()
	tables := []string{"users", "user_roles", "user_group_members", "user_groups",
		"group_role_mappings", "group_user_group_mappings", "external_groups",
		"user_role_mappings", "user_role_mapping_rule_supports", "user_group_mapping_rule_supports",
		"user_group_roles", "user_external_identities", "refresh_tokens", "audit_logs"}
	var b strings.Builder
	for _, tbl := range tables {
		if !e.db.Migrator().HasTable(tbl) {
			continue
		}
		var rows []map[string]any
		if err := e.db.Table(tbl).Find(&rows).Error; err != nil {
			e.t.Fatalf("digest %s: %v", tbl, err)
		}
		lines := make([]string, 0, len(rows))
		for _, r := range rows {
			lines = append(lines, fmt.Sprint(r))
		}
		sort.Strings(lines)
		fmt.Fprintf(&b, "%s:%d\n%s\n", tbl, len(rows), strings.Join(lines, "\n"))
	}
	return b.String()
}

func (e *bumpEnv) putRole(user *model.User, source string) {
	e.t.Helper()
	if err := e.db.Create(&model.UserRole{UserID: user.ID, RoleID: e.role.ID, Source: source}).Error; err != nil {
		e.t.Fatalf("seed user_role(%s): %v", source, err)
	}
	if source == model.RoleSourceMapped || source == model.RoleSourceBoth {
		if err := upsertRoleMappingFact(e.db, user.ID, e.role.ID, e.channel, time.Now()); err != nil {
			e.t.Fatalf("seed mapping fact: %v", err)
		}
	}
}

func (e *bumpEnv) roleRule(value string) uint {
	e.t.Helper()
	v, err := e.mapping.CreateMapping(model.RoleMappingChannelKindProvider, e.provider.ID,
		GroupRoleMappingInput{MatchValue: value, Role: e.role.Name, RiskAcknowledged: true, Actor: bumpActor})
	if err != nil {
		e.t.Fatalf("seed role rule: %v", err)
	}
	return v.ID
}

func (e *bumpEnv) groupRule(value string) uint {
	e.t.Helper()
	r, err := e.mapping.CreateUserGroupMapping(model.RoleMappingChannelKindProvider, e.provider.ID,
		UserGroupMappingInput{MatchValue: value, UserGroupID: e.group.ID, RiskAcknowledged: true,
			SourceConfigAcknowledged: true, Actor: bumpActor})
	if err != nil {
		e.t.Fatalf("seed group rule: %v", err)
	}
	return r.ID
}

func (e *bumpEnv) addSupport() {
	e.t.Helper()
	if err := e.db.Exec(`INSERT INTO user_group_mapping_rule_supports (user_id, user_group_id, channel, rule_id)
		VALUES (?, ?, ?, 1)`, e.alice.ID, e.group.ID, e.channel).Error; err != nil {
		e.t.Fatalf("seed support: %v", err)
	}
}

// bumpPath 一條 1.3 寫入路徑：setup 擺好起始狀態並回傳要執行的動作。
type bumpPath struct {
	id    string
	name  string
	setup func(e *bumpEnv) func() error
}

func bumpPaths() []bumpPath {
	kind := model.RoleMappingChannelKindProvider
	return []bumpPath{
		{"路徑01", "AddManualRole", func(e *bumpEnv) func() error {
			return e.inTx(func(tx *gorm.DB) error { _, err := AddManualRole(tx, e.alice.ID, e.role.ID); return err })
		}},
		{"路徑02", "RemoveManualRole", func(e *bumpEnv) func() error {
			e.putRole(e.alice, model.RoleSourceManual)
			return e.inTx(func(tx *gorm.DB) error { _, err := RemoveManualRole(tx, e.alice.ID, e.role.ID); return err })
		}},
		{"路徑03", "GrantMappedRole", func(e *bumpEnv) func() error {
			return e.inTx(func(tx *gorm.DB) error {
				_, err := GrantMappedRole(tx, e.alice.ID, e.role.ID, e.channel, time.Now())
				return err
			})
		}},
		{"路徑04", "RevokeMappedRolesForChannel", func(e *bumpEnv) func() error {
			e.putRole(e.alice, model.RoleSourceMapped)
			return e.inTx(func(tx *gorm.DB) error {
				_, err := RevokeMappedRolesForChannel(tx, e.alice.ID, e.channel, nil)
				return err
			})
		}},
		{"路徑05", "PinMappedRole", func(e *bumpEnv) func() error {
			e.putRole(e.alice, model.RoleSourceMapped)
			return func() error { _, err := e.users.PinMappedRole(e.alice.ID, e.role.Name); return err }
		}},
		{"路徑06", "UserService.Create", func(e *bumpEnv) func() error {
			return func() error {
				_, err := e.users.Create(&CreateUserRequest{Username: "newcomer", Password: "Password12345",
					Email: "newcomer@example.test", Roles: []string{model.RoleUser}})
				return err
			}
		}},
		{"路徑07", "provisionShadowUser", func(e *bumpEnv) func() error {
			return func() error {
				_, err := (&AuthService{}).provisionShadowUser(&LDAPUserInfo{
					Username: "ldap-shadow", Email: "ldap-shadow@example.test", FullName: "L"})
				return err
			}
		}},
		{"路徑08", "provisionFromClaims", func(e *bumpEnv) func() error {
			login, _, db := setupOIDCEnv(e.t)
			p := jitProvider(e.t, db)
			e.db, e.login = db, login
			return func() error {
				_, err := e.login.resolveOrProvision(p, oidcClaims("sub-1", map[string]any{
					"hd": "corp.example", "preferred_username": "carol",
					"email": "carol@corp.example", "email_verified": true, "name": "Carol",
				}), &oidcAuditTrail{})
				return err
			}
		}},
		{"路徑09", "reconcileGroupMembers", func(e *bumpEnv) func() error {
			e.addSupport()
			return e.inTx(func(tx *gorm.DB) error {
				_, err := reconcileGroupMembers(tx, e.alice.ID, []uint{e.group.ID})
				return err
			})
		}},
		{"路徑10", "ReplaceMembersDetailed", func(e *bumpEnv) func() error {
			return func() error {
				_, err := e.groups.ReplaceMembersDetailed(e.group.ID, &[]uint{e.alice.ID}, nil, 1, "admin", "10.0.0.1")
				return err
			}
		}},
		{"路徑11", "UserGroupService.Delete", func(e *bumpEnv) func() error {
			if err := e.db.Exec("INSERT INTO user_group_members (user_group_id, user_id, manual) VALUES (?, ?, true)",
				e.group.ID, e.alice.ID).Error; err != nil {
				e.t.Fatalf("seed member: %v", err)
			}
			return func() error { _, err := e.groups.Delete(e.group.ID, 1, "admin", "10.0.0.1"); return err }
		}},
		{"路徑12", "CreateMapping", func(e *bumpEnv) func() error {
			return func() error {
				_, err := e.mapping.CreateMapping(kind, e.provider.ID,
					GroupRoleMappingInput{MatchValue: "ops", Role: e.role.Name, RiskAcknowledged: true, Actor: bumpActor})
				return err
			}
		}},
		{"路徑13", "UpdateMapping", func(e *bumpEnv) func() error {
			id := e.roleRule("ops")
			return func() error {
				_, err := e.mapping.UpdateMapping(kind, e.provider.ID, id,
					GroupRoleMappingInput{MatchValue: "ops-renamed", Role: e.role.Name, RiskAcknowledged: true, Actor: bumpActor})
				return err
			}
		}},
		{"路徑14", "DeleteMapping", func(e *bumpEnv) func() error {
			id := e.roleRule("ops")
			return func() error { return e.mapping.DeleteMapping(kind, e.provider.ID, id, bumpActor) }
		}},
		{"路徑15", "CreateUserGroupMapping", func(e *bumpEnv) func() error {
			return func() error {
				_, err := e.mapping.CreateUserGroupMapping(kind, e.provider.ID,
					UserGroupMappingInput{MatchValue: "g1", UserGroupID: e.group.ID, RiskAcknowledged: true,
						SourceConfigAcknowledged: true, Actor: bumpActor})
				return err
			}
		}},
		{"路徑16", "UpdateUserGroupMapping", func(e *bumpEnv) func() error {
			id := e.groupRule("g1")
			return func() error {
				_, err := e.mapping.UpdateUserGroupMapping(kind, e.provider.ID, id,
					UserGroupMappingInput{MatchValue: "g1-renamed", UserGroupID: e.group.ID, RiskAcknowledged: true,
						SourceConfigAcknowledged: true, Actor: bumpActor})
				return err
			}
		}},
		{"路徑17", "DeleteUserGroupMapping", func(e *bumpEnv) func() error {
			id := e.groupRule("g1")
			return func() error { return e.mapping.DeleteUserGroupMapping(kind, e.provider.ID, id, bumpActor) }
		}},
		{"路徑18", "cleanupMappingHistoryForSourceLocked", func(e *bumpEnv) func() error {
			// 已軟刪的歷史規則才會被來源刪除的清理帶走（仍有活躍規則時整筆拒絕）
			id := e.roleRule("ops")
			if err := e.mapping.DeleteMapping(kind, e.provider.ID, id, bumpActor); err != nil {
				e.t.Fatalf("soft-delete rule: %v", err)
			}
			return e.inTx(func(tx *gorm.DB) error {
				return cleanupMappingHistoryForSourceLocked(tx, audit.NewTxSink(), kind, e.provider.ID)
			})
		}},
		{"路徑19", "UpdateStatus", func(e *bumpEnv) func() error {
			return func() error { return e.users.UpdateStatus(e.alice.ID, false) }
		}},
		{"路徑20", "UnbindExternalIdentityAndDisable", func(e *bumpEnv) func() error {
			if err := e.db.Model(e.alice).Updates(map[string]any{"external_credential": true,
				"provisioning_origin": model.AuthSourceOIDC}).Error; err != nil {
				e.t.Fatalf("mark external: %v", err)
			}
			dto, err := e.users.BindExternalIdentity(e.alice.ID, e.provider.ID, "sub-alice", testActor)
			if err != nil {
				e.t.Fatalf("bind: %v", err)
			}
			return func() error { return e.users.UnbindExternalIdentityAndDisable(e.alice.ID, dto.ID, testActor) }
		}},
		{"路徑21", "DeleteWithSummary", func(e *bumpEnv) func() error {
			e.putRole(e.bob, model.RoleSourceManual)
			return func() error { _, err := e.users.DeleteWithSummary(e.bob.ID); return err }
		}},
		{"路徑22", "UserService.Update(owner)", func(e *bumpEnv) func() error {
			agent := &model.User{Username: "agent-1", Password: "!", Kind: model.KindAgent, OwnerUserID: &e.alice.ID, Active: true}
			if err := e.db.Create(agent).Error; err != nil {
				e.t.Fatalf("seed agent: %v", err)
			}
			return func() error {
				_, _, err := e.users.Update(agent.ID, &UpdateUserRequest{OwnerUserID: &e.bob.ID})
				return err
			}
		}},
		{"路徑23", "authz.SetUserGroupRoles", func(e *bumpEnv) func() error {
			return e.inTx(func(tx *gorm.DB) error {
				return authz.SetUserGroupRoles(tx, e.group.ID, []uint{e.role.ID}, 1)
			})
		}},
	}
}

func TestAuthzStateVersionBump(t *testing.T) {
	paths := bumpPaths()
	if len(paths) != bumpPathCount {
		t.Fatalf("路徑數 = %d，want %d（與權限版本推進清單的路徑數同步）", len(paths), bumpPathCount)
	}
	for i, p := range paths {
		if want := fmt.Sprintf("路徑%02d", i+1); p.id != want {
			t.Fatalf("第 %d 條路徑編號 = %s，want %s", i+1, p.id, want)
		}
	}

	// 每條路徑：版本確實前進
	for _, p := range paths {
		p := p
		t.Run(p.id+"_"+p.name, func(t *testing.T) {
			e := newBumpEnv(t)
			act := p.setup(e)
			before := e.version()
			if err := act(); err != nil {
				t.Fatalf("路徑執行失敗: %v", err)
			}
			if after := e.version(); after <= before {
				t.Fatalf("版本 %d -> %d：%s 寫入了授權相關狀態卻沒有推進權限版本", before, after, p.id)
			}
		})
	}

	// 多使用者撤權迴圈的鎖序（PG-gated；未設 TEST_PG_DSN 時跳過）
	t.Run("pg_lock_order", bumpLockOrderPG)
	t.Run("untraced_vs_user_lock_deadlock", untracedVsUserLockDeadlockPG)

	// 推進呼叫失敗＝同交易的寫入一併回滾，版本不動
	t.Run("rollback_no_advance", func(t *testing.T) {
		for _, p := range paths {
			p := p
			t.Run(p.id+"_"+p.name, func(t *testing.T) {
				e := newBumpEnv(t)
				act := p.setup(e)
				beforeVersion, beforeDigest := e.version(), e.digest()
				if err := e.db.Exec(`CREATE TRIGGER inject_advance_failure BEFORE UPDATE ON authz_state
					BEGIN SELECT RAISE(ABORT, 'injected advance failure'); END`).Error; err != nil {
					t.Fatalf("install trigger: %v", err)
				}
				err := act()
				if err == nil {
					t.Fatalf("推進被注入失敗，但路徑沒有回錯：%s 要嘛沒有呼叫 AdvanceVersion，要嘛吞掉了它的錯誤", p.id)
				}
				if got := e.version(); got != beforeVersion {
					t.Fatalf("版本 %d -> %d：失敗後不得推進", beforeVersion, got)
				}
				if got := e.digest(); got != beforeDigest {
					t.Fatalf("推進失敗後仍有寫入殘留（寫入沒有與推進同交易）；err=%v", err)
				}
			})
		}
	})

	// 每條路徑在權限狀態事件鏈啟用後，
	//   - 交易開頭先把既有直寫隔離成 untraced 事件（BeginPermissionChange），合法事件差集不含直寫；
	//   - 路徑結束時目前狀態等於鏈頭事後狀態（推進之後沒有未入事件的權限寫入），對帳可重放為相符。
	t.Run("permission_event_replay", func(t *testing.T) {
		for _, p := range paths {
			p := p
			t.Run(p.id+"_"+p.name, func(t *testing.T) {
				e := newBumpEnv(t)
				e.beginInTx = true
				act := p.setup(e)
				drift := activatePermissionEvents(t, e.db)
				if err := act(); err != nil {
					t.Fatalf("路徑執行失敗: %v", err)
				}
				var events []model.PermissionStateEvent
				if err := e.db.Order("seq ASC").Find(&events).Error; err != nil {
					t.Fatalf("讀事件: %v", err)
				}
				firstUntraced, firstChange := int64(0), int64(0)
				for _, ev := range events {
					switch ev.Kind {
					case model.PermEventUntraced:
						if firstUntraced == 0 {
							firstUntraced = ev.Seq
						}
					case model.PermEventChange:
						if firstChange == 0 {
							firstChange = ev.Seq
						}
						var d audit.PermissionDelta
						if err := json.Unmarshal([]byte(ev.Delta), &d); err != nil {
							t.Fatalf("事件 seq=%d 差集無法解析: %v", ev.Seq, err)
						}
						if containsRow(d.Add[audit.PermSetGroups], drift) {
							t.Fatalf("%s 的合法事件 seq=%d 差集含直寫列 %s（交易開頭未呼叫 BeginPermissionChange）", p.id, ev.Seq, drift)
						}
					}
				}
				if firstChange == 0 {
					t.Fatalf("%s 推進了版本卻沒有 change 事件", p.id)
				}
				if firstUntraced == 0 || firstUntraced > firstChange {
					t.Fatalf("%s：直寫未在合法事件之前隔離成 untraced（untraced=%d change=%d）", p.id, firstUntraced, firstChange)
				}
				var residual bool
				if err := e.db.Transaction(func(tx *gorm.DB) error {
					var err error
					residual, err = audit.RecordUntracedPermissionDrift(context.Background(), tx)
					return err
				}); err != nil {
					t.Fatalf("殘餘漂移檢查: %v", err)
				}
				if residual {
					t.Fatalf("%s 結束後目前狀態不等於鏈頭事後狀態：推進之後仍有未入事件的權限寫入", p.id)
				}
			})
		}
	})

	// tx 級函式在呼叫端交易回滾時，版本一併回滾
	t.Run("rollback_outer_tx", func(t *testing.T) {
		e := newBumpEnv(t)
		e.putRole(e.alice, model.RoleSourceManual)
		before := e.version()
		injected := errors.New("injected")
		err := e.db.Transaction(func(tx *gorm.DB) error {
			if _, err := RemoveManualRole(tx, e.alice.ID, e.role.ID); err != nil {
				return err
			}
			var inTx int64
			if err := tx.Raw("SELECT version FROM authz_state WHERE id = 1").Scan(&inTx).Error; err != nil {
				return err
			}
			if inTx <= before {
				t.Errorf("交易內版本 %d 未前進（before=%d）", inTx, before)
			}
			return injected
		})
		if !errors.Is(err, injected) {
			t.Fatalf("交易應以注入錯誤回滾: %v", err)
		}
		if got := e.version(); got != before {
			t.Fatalf("回滾後版本 %d，want %d", got, before)
		}
	})

	t.Run("readonly_no_advance", func(t *testing.T) {
		e := newBumpEnv(t)
		e.putRole(e.alice, model.RoleSourceBoth)
		e.roleRule("ops")
		e.groupRule("g1")
		beforeVersion, beforeDigest := e.version(), e.digest()
		kind := model.RoleMappingChannelKindProvider
		reads := map[string]func() error{
			"GetByID":          func() error { _, err := e.users.GetByID(e.alice.ID); return err },
			"List":             func() error { _, err := e.users.List(&ListUsersRequest{}); return err },
			"ListRoles":        func() error { _, _, err := e.users.ListRoles(); return err },
			"CountLocalAdmins": func() error { _, err := e.users.CountLocalAdmins(); return err },
			"RoleSetsOf":       func() error { _, err := e.users.RoleSetsOf(e.alice.ID); return err },
			"groups.List":      func() error { _, err := e.groups.List(); return err },
			"AuthorizationCount": func() error {
				_, err := e.groups.AuthorizationCount(e.group.ID)
				return err
			},
			"ListMappings": func() error { _, err := e.mapping.ListMappings(kind, e.provider.ID); return err },
			"CurrentVersion": func() error {
				_, err := authz.CurrentVersion(e.db)
				return err
			},
			"UserRoleSourceOf": func() error {
				_, _, err := model.UserRoleSourceOf(e.db, e.alice.ID, e.role.ID)
				return err
			},
		}
		for name, read := range reads {
			if err := read(); err != nil {
				t.Fatalf("%s: %v", name, err)
			}
		}
		if got := e.version(); got != beforeVersion {
			t.Fatalf("唯讀呼叫推進了版本：%d -> %d", beforeVersion, got)
		}
		if e.digest() != beforeDigest {
			t.Fatal("唯讀呼叫改變了資料")
		}
	})

	// 沒有實際改變授權狀態的寫入呼叫不推進（冪等重送、只更新映射命中時間）
	t.Run("noop_no_advance", func(t *testing.T) {
		kind := model.RoleMappingChannelKindProvider
		cases := []struct {
			name  string
			setup func(e *bumpEnv) func() error
		}{
			{"AddManualRole_已是manual", func(e *bumpEnv) func() error {
				e.putRole(e.alice, model.RoleSourceManual)
				return e.inTx(func(tx *gorm.DB) error { _, err := AddManualRole(tx, e.alice.ID, e.role.ID); return err })
			}},
			{"AddManualRole_已是both", func(e *bumpEnv) func() error {
				e.putRole(e.alice, model.RoleSourceBoth)
				return e.inTx(func(tx *gorm.DB) error { _, err := AddManualRole(tx, e.alice.ID, e.role.ID); return err })
			}},
			{"RemoveManualRole_列不存在", func(e *bumpEnv) func() error {
				return e.inTx(func(tx *gorm.DB) error { _, err := RemoveManualRole(tx, e.alice.ID, e.role.ID); return err })
			}},
			{"RemoveManualRole_僅mapped", func(e *bumpEnv) func() error {
				e.putRole(e.alice, model.RoleSourceMapped)
				return e.inTx(func(tx *gorm.DB) error { _, err := RemoveManualRole(tx, e.alice.ID, e.role.ID); return err })
			}},
			{"GrantMappedRole_只更新命中時間", func(e *bumpEnv) func() error {
				e.putRole(e.alice, model.RoleSourceMapped)
				return e.inTx(func(tx *gorm.DB) error {
					_, err := GrantMappedRole(tx, e.alice.ID, e.role.ID, e.channel, time.Now().Add(time.Hour))
					return err
				})
			}},
			{"RevokeMappedRolesForChannel_無失效映射", func(e *bumpEnv) func() error {
				e.putRole(e.alice, model.RoleSourceMapped)
				return e.inTx(func(tx *gorm.DB) error {
					_, err := RevokeMappedRolesForChannel(tx, e.alice.ID, e.channel, []uint{e.role.ID})
					return err
				})
			}},
			{"PinMappedRole_已是both", func(e *bumpEnv) func() error {
				e.putRole(e.alice, model.RoleSourceBoth)
				return func() error { _, err := e.users.PinMappedRole(e.alice.ID, e.role.Name); return err }
			}},
			{"reconcileGroupMembers_無差異", func(e *bumpEnv) func() error {
				return e.inTx(func(tx *gorm.DB) error {
					_, err := reconcileGroupMembers(tx, e.alice.ID, []uint{e.group.ID})
					return err
				})
			}},
			{"ReplaceMembersDetailed_成員集不變", func(e *bumpEnv) func() error {
				if err := e.db.Exec("INSERT INTO user_group_members (user_group_id, user_id, manual) VALUES (?, ?, true)",
					e.group.ID, e.alice.ID).Error; err != nil {
					e.t.Fatalf("seed member: %v", err)
				}
				return func() error {
					_, err := e.groups.ReplaceMembersDetailed(e.group.ID, &[]uint{e.alice.ID}, nil, 1, "admin", "10.0.0.1")
					return err
				}
			}},
			{"UpdateMapping_內容未變", func(e *bumpEnv) func() error {
				id := e.roleRule("ops")
				return func() error {
					_, err := e.mapping.UpdateMapping(kind, e.provider.ID, id,
						GroupRoleMappingInput{MatchValue: "ops", Role: e.role.Name, RiskAcknowledged: true, Actor: bumpActor})
					return err
				}
			}},
			{"UpdateUserGroupMapping_內容未變", func(e *bumpEnv) func() error {
				id := e.groupRule("g1")
				return func() error {
					_, err := e.mapping.UpdateUserGroupMapping(kind, e.provider.ID, id,
						UserGroupMappingInput{MatchValue: "g1", UserGroupID: e.group.ID, RiskAcknowledged: true,
							SourceConfigAcknowledged: true, Actor: bumpActor})
					return err
				}
			}},
			{"UserService.Update_非擁有者欄位", func(e *bumpEnv) func() error {
				return func() error {
					_, _, err := e.users.Update(e.alice.ID, &UpdateUserRequest{FullName: "Alice Renamed"})
					return err
				}
			}},
			{"RemoveUserGroupRole_指派不存在", func(e *bumpEnv) func() error {
				return e.inTx(func(tx *gorm.DB) error { return authz.RemoveUserGroupRole(tx, e.group.ID, e.role.ID) })
			}},
		}
		for _, c := range cases {
			c := c
			t.Run(c.name, func(t *testing.T) {
				e := newBumpEnv(t)
				act := c.setup(e)
				before := e.version()
				if err := act(); err != nil {
					t.Fatalf("呼叫失敗: %v", err)
				}
				if after := e.version(); after != before {
					t.Fatalf("版本 %d -> %d：沒有實際改變授權狀態的呼叫不應推進", before, after)
				}
			})
		}
	})
}

// activatePermissionEvents 於 db 注入權限狀態來源並以目前狀態啟用事件鏈，
// 再以直寫新增一個使用者群組作為「兩次合法事件之間的直接改庫」；回傳該列在差集中的字串。
func activatePermissionEvents(t *testing.T, db *gorm.DB) string {
	t.Helper()
	if err := migrateWithAuthz(db, &model.User{}, &model.Role{}, &model.UserGroup{}, &model.AssetGroup{},
		&model.GroupRoleMapping{}, &model.GroupUserGroupMapping{}, &model.ExternalGroup{},
		&model.UserGroupMappingRuleSupport{}, &model.UserChannelObservation{}, &model.PermissionStateEvent{}, &model.RolePermission{},
		&model.UserRole{}, &model.UserGroupRole{}, &model.RoleBindingNode{}); err != nil {
		t.Fatalf("migrate permission tables: %v", err)
	}
	if err := db.AutoMigrate(&model.UserGroupMember{}); err != nil {
		t.Fatalf("migrate user_group_members: %v", err)
	}
	audit.SetPermissionSources(authz.PermissionStateAuthzPart, PermissionStateIdentityPart)
	t.Cleanup(func() { audit.SetPermissionSources(nil, nil) })
	if err := db.Transaction(func(tx *gorm.DB) error {
		st, err := audit.ReadPermissionState(context.Background(), tx)
		if err != nil {
			return err
		}
		_, err = audit.EnsurePermissionActivation(context.Background(), tx, st, 0)
		return err
	}); err != nil {
		t.Fatalf("activate: %v", err)
	}
	g := &model.UserGroup{Name: "drift-direct-write"}
	if err := db.Create(g).Error; err != nil {
		t.Fatalf("direct write: %v", err)
	}
	return audit.PermissionRow(g.ID, audit.PermBool(false))
}

func containsRow(rows []string, want string) bool {
	for _, r := range rows {
		if r == want {
			return true
		}
	}
	return false
}

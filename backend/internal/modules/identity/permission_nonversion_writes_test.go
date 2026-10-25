package identity

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
	"gorm.io/gorm"
)

// TestPermissionNonVersionWrites 權限狀態事件鏈與「不推進權限版本」的合法寫入。
//
// 快照涵蓋的欄位中，有些合法寫入依既有語義不推進版本（空群組、不帶角色的帳號、
// 轉為僅外部登入、本地帳號密碼由空變非空）。這些路徑必須在外層交易開頭 Begin、結尾 Settle，
// 否則下一次對帳會把它們判成無來源變動。每個子測試：啟用事件鏈 → 走合法路徑 →
// 斷言鏈上沒有 untraced 事件、鏈頭事後狀態等於目前狀態（即對帳重放相符）。
// 反例：不經服務層直接以 SQL 寫同一欄位，必須仍被偵測。
func TestPermissionNonVersionWrites(t *testing.T) {
	// 與 activatePermissionEvents 相同的啟用步驟，但不植入直寫列（本測試要乾淨的基準）。
	activate := func(t *testing.T, db *gorm.DB) {
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
	}

	// chainStatus 回傳：untraced 事件數、change 事件數、鏈頭事後狀態是否等於目前狀態。
	chainStatus := func(t *testing.T, db *gorm.DB) (untraced, changes int64, headMatches bool) {
		t.Helper()
		if err := db.Model(&model.PermissionStateEvent{}).Where("kind = ?", model.PermEventUntraced).Count(&untraced).Error; err != nil {
			t.Fatalf("count untraced: %v", err)
		}
		if err := db.Model(&model.PermissionStateEvent{}).Where("kind = ?", model.PermEventChange).Count(&changes).Error; err != nil {
			t.Fatalf("count change: %v", err)
		}
		var head model.PermissionStateEvent
		if err := db.Order("seq DESC").Limit(1).Find(&head).Error; err != nil || head.ID == 0 {
			t.Fatalf("read head: %v", err)
		}
		var nowDigest string
		if err := db.Transaction(func(tx *gorm.DB) error {
			st, err := audit.ReadPermissionState(context.Background(), tx)
			if err != nil {
				return err
			}
			nowDigest, err = st.Digest()
			return err
		}); err != nil {
			t.Fatalf("read state: %v", err)
		}
		return untraced, changes, head.AfterDigest == nowDigest
	}

	settled := func(t *testing.T, db *gorm.DB) {
		t.Helper()
		untraced, changes, ok := chainStatus(t, db)
		if untraced != 0 {
			t.Fatalf("合法寫入後鏈上出現 %d 筆 untraced 事件（無來源變動）", untraced)
		}
		if !ok {
			t.Fatal("鏈頭事後狀態不等於目前狀態：合法寫入沒有入事件鏈（對帳會判不符）")
		}
		if changes == 0 {
			t.Fatal("沒有任何 change 事件：Begin／Settle 沒有生效")
		}
	}

	type pathCase struct {
		name  string
		setup func(t *testing.T, e *bumpEnv) // 啟用事件鏈之前的起始狀態
		act   func(t *testing.T, e *bumpEnv) // 合法寫入（不得推進權限版本）
	}
	cases := []pathCase{
		{"create_group", nil, func(t *testing.T, e *bumpEnv) {
			if _, err := e.groups.Create(&UserGroupRequest{Name: "fresh-group"}); err != nil {
				t.Fatalf("建群組: %v", err)
			}
		}},
		{"create_human_without_role", nil, func(t *testing.T, e *bumpEnv) {
			if _, err := e.users.Create(&CreateUserRequest{Username: "norole", Password: "Password12345",
				Email: "norole@example.test"}); err != nil {
				t.Fatalf("建無角色帳號: %v", err)
			}
		}},
		{"create_agent_without_role", nil, func(t *testing.T, e *bumpEnv) {
			owner := e.alice.ID
			if _, err := e.users.Create(&CreateUserRequest{Username: "agent-x", Kind: model.KindAgent,
				OwnerUserID: &owner}); err != nil {
				t.Fatalf("建 agent: %v", err)
			}
		}},
		{"convert_to_external_only", func(t *testing.T, e *bumpEnv) {
			seedAccount(t, e.db, adminSpec{username: "keeper", admin: true, active: true}) // 保住最後本地超管
			p := seedExtProvider(t, e.db, "corp2", "https://idp2.example.com", "cid-2")
			mustBind(t, &extIdentityEnv{svc: e.users, db: e.db}, e.alice.ID, p, "sub-alice")
		}, func(t *testing.T, e *bumpEnv) {
			if err := e.users.ConvertToExternalOnly(e.alice.ID, testActor); err != nil {
				t.Fatalf("轉為僅外部登入: %v", err)
			}
		}},
		{"set_password_on_blank_local_account", func(t *testing.T, e *bumpEnv) {
			// 漂移列：本地帳號、密碼空白（可本地登入=0）；設密碼後變 1
			if err := e.db.Model(&model.User{}).Where("id = ?", e.bob.ID).Update("password", "").Error; err != nil {
				t.Fatalf("seed blank password: %v", err)
			}
		}, func(t *testing.T, e *bumpEnv) {
			if err := e.users.ChangePassword(e.bob.ID, "Password12345!"); err != nil {
				t.Fatalf("管理員設密碼: %v", err)
			}
		}},
	}
	for _, c := range cases {
		c := c
		// 乾淨基準：合法寫入入鏈、不留 untraced（拿掉 Settle 即紅）
		t.Run(c.name, func(t *testing.T) {
			e := newBumpEnv(t)
			if c.setup != nil {
				c.setup(t, e)
			}
			activate(t, e.db)
			before := e.version()
			c.act(t, e)
			if e.version() != before {
				t.Fatal("此路徑不應推進權限版本（既有語義不變）")
			}
			settled(t, e.db)
		})
		// 事前有直寫：必須先被隔離成 untraced（拿掉 Begin 即紅），合法事件差集不含直寫列
		t.Run(c.name+"/prior_direct_write_isolated", func(t *testing.T) {
			e := newBumpEnv(t)
			if c.setup != nil {
				c.setup(t, e)
			}
			activate(t, e.db)
			g := &model.UserGroup{Name: "drift-direct-write"}
			if err := e.db.Create(g).Error; err != nil {
				t.Fatalf("direct write: %v", err)
			}
			driftRow := audit.PermissionRow(g.ID, audit.PermBool(false))
			c.act(t, e)
			var events []model.PermissionStateEvent
			if err := e.db.Order("seq ASC").Find(&events).Error; err != nil {
				t.Fatalf("讀事件: %v", err)
			}
			firstUntraced, firstChange := int64(0), int64(0)
			for _, ev := range events {
				var d audit.PermissionDelta
				if ev.Kind == model.PermEventUntraced || ev.Kind == model.PermEventChange {
					if err := json.Unmarshal([]byte(ev.Delta), &d); err != nil {
						t.Fatalf("事件 seq=%d 差集無法解析: %v", ev.Seq, err)
					}
				}
				switch ev.Kind {
				case model.PermEventUntraced:
					if firstUntraced == 0 {
						firstUntraced = ev.Seq
					}
					if !containsRow(d.Add[audit.PermSetGroups], driftRow) {
						t.Fatalf("untraced 事件 seq=%d 的差集沒有直寫列 %s", ev.Seq, driftRow)
					}
				case model.PermEventChange:
					if firstChange == 0 {
						firstChange = ev.Seq
					}
					if containsRow(d.Add[audit.PermSetGroups], driftRow) {
						t.Fatalf("合法事件 seq=%d 的差集含直寫列（交易開頭未 Begin）", ev.Seq)
					}
				}
			}
			if firstUntraced == 0 || firstChange == 0 || firstUntraced > firstChange {
				t.Fatalf("直寫須先被隔離成 untraced 再接合法事件（untraced=%d change=%d）", firstUntraced, firstChange)
			}
			if _, _, ok := chainStatus(t, e.db); !ok {
				t.Fatal("結束後鏈頭事後狀態不等於目前狀態")
			}
		})
	}

	// 反例：不經服務層直接以 SQL 寫快照涵蓋的欄位，仍須被偵測（Begin／Settle 不是萬用橡皮擦）。
	t.Run("direct_sql_still_detected", func(t *testing.T) {
		e := newBumpEnv(t)
		activate(t, e.db)
		if err := e.db.Exec("INSERT INTO user_groups (name, description) VALUES ('sneaky', '')").Error; err != nil {
			t.Fatalf("direct sql: %v", err)
		}
		if _, _, ok := chainStatus(t, e.db); ok {
			t.Fatal("直接 SQL 寫入後，鏈頭事後狀態不應等於目前狀態")
		}
		// 之後第一個走服務層的合法寫入會把直寫隔離成 untraced 事件，對帳因此回報無來源變動
		if _, err := e.groups.Create(&UserGroupRequest{Name: "legit-after-sneaky"}); err != nil {
			t.Fatalf("建群組: %v", err)
		}
		untraced, _, ok := chainStatus(t, e.db)
		if untraced != 1 {
			t.Fatalf("untraced 事件數 %d，want 1（直寫必須被偵測）", untraced)
		}
		if !ok {
			t.Fatal("隔離直寫後，合法事件仍應使鏈頭等於目前狀態")
		}
	})
}

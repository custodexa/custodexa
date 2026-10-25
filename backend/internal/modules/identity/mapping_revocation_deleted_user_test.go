package identity

import (
	"testing"

	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
)

// TestMappingRuleDeleteSkipsUserDeletedBeforeLock 固定「支持者集合讀出之後、取到該帳號的鎖之前，
// 帳號已被刪除」的交錯：映射規則刪除必須成功；已刪帳號不得被撤角色、調群組成員、推進世代或寫入
// 以它為主體的稽核；本規則指向該帳號的支持列仍須清除。
//
// 交錯以既有的逐人停點固定：支持者依編號升冪處理，處理完編號較小的帳號後、取下一位的鎖之前，
// 在同一交易內把下一位軟刪。這裡只設 deleted_at、刻意不清它的支持列與角色列，
// 才看得出撤銷流程是否自己清掉本規則的支持列、以及是否誤動已刪帳號的權限列。
// 本測試設定包級停點，不得呼叫 t.Parallel。
func TestMappingRuleDeleteSkipsUserDeletedBeforeLock(t *testing.T) {
	for _, tc := range []struct {
		name         string
		supportTable string
		createRule   func(f *mappingSegmentFixture, t *testing.T) uint
		deleteRule   func(f *mappingSegmentFixture, ruleID uint) error
	}{
		{
			name:         "role_rule",
			supportTable: "user_role_mapping_rule_supports",
			createRule:   func(f *mappingSegmentFixture, t *testing.T) uint { return f.roleRule(t, "a") },
			deleteRule: func(f *mappingSegmentFixture, ruleID uint) error {
				return f.service.DeleteMapping(model.RoleMappingChannelKindProvider, f.provider.ID, ruleID, f.act())
			},
		},
		{
			name:         "group_rule",
			supportTable: "user_group_mapping_rule_supports",
			createRule:   func(f *mappingSegmentFixture, t *testing.T) uint { return f.groupRule(t, "a") },
			deleteRule: func(f *mappingSegmentFixture, ruleID uint) error {
				return f.service.DeleteUserGroupMapping(model.RoleMappingChannelKindProvider, f.provider.ID, ruleID, f.act())
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newMappingSegmentFixture(t)
			ruleID := tc.createRule(f, t)
			victim := model.User{Username: "victim", Password: "x", Active: true, IsLDAP: true}
			if err := f.db.Create(&victim).Error; err != nil {
				t.Fatal(err)
			}
			if victim.ID <= f.user.ID {
				t.Fatalf("前提不成立：被刪帳號編號 %d 須大於先處理的帳號 %d", victim.ID, f.user.ID)
			}
			obs := GroupObservation{Kind: model.RoleMappingChannelKindProvider, SourceID: f.provider.ID, State: GroupObservationKnown, Groups: []string{"a"}}
			for _, u := range []*model.User{&f.user, &victim} {
				if _, err := RecomputeMappedRoles(f.db, audit.NewTxSink(), u, obs); err != nil {
					t.Fatal(err)
				}
			}
			supportsOf := func(uid uint) int64 {
				t.Helper()
				var n int64
				if err := f.db.Table(tc.supportTable).Where("user_id=? AND rule_id=?", uid, ruleID).Count(&n).Error; err != nil {
					t.Fatal(err)
				}
				return n
			}
			rowsOf := func(table string, uid uint) int64 {
				t.Helper()
				var n int64
				if err := f.db.Table(table).Where("user_id=?", uid).Count(&n).Error; err != nil {
					t.Fatal(err)
				}
				return n
			}
			auditsOf := func(uid uint) int64 {
				t.Helper()
				var n int64
				if err := f.db.Model(&model.AuditLog{}).Where("resource=? AND resource_id=?", string(model.ResourceUser), uid).Count(&n).Error; err != nil {
					t.Fatal(err)
				}
				return n
			}
			epochOf := func(uid uint) int {
				t.Helper()
				var u model.User
				if err := f.db.Unscoped().First(&u, uid).Error; err != nil {
					t.Fatal(err)
				}
				return u.CredentialEpoch
			}
			if supportsOf(f.user.ID) != 1 || supportsOf(victim.ID) != 1 {
				t.Fatalf("前提不成立：兩個帳號都須由本規則支持（%d, %d）", supportsOf(f.user.ID), supportsOf(victim.ID))
			}
			victimTables := []string{"user_roles", "user_role_mappings", "user_group_members"}
			victimBefore := map[string]int64{}
			for _, table := range victimTables {
				victimBefore[table] = rowsOf(table, victim.ID)
			}
			victimAuditsBefore, victimEpochBefore := auditsOf(victim.ID), epochOf(victim.ID)
			liveAuditsBefore := auditsOf(f.user.ID)

			deletedAt := 0
			restore := SetLockOrderHookForTest(func(point string, tx *gorm.DB, ids ...uint) {
				if point != "mapping_revoke_after_user" || len(ids) == 0 || ids[0] != f.user.ID || deletedAt != 0 {
					return
				}
				deletedAt = 1
				if err := tx.Delete(&model.User{}, victim.ID).Error; err != nil {
					t.Errorf("停點內軟刪帳號失敗: %v", err)
				}
			})
			err := tc.deleteRule(f, ruleID)
			restore()
			if deletedAt != 1 {
				t.Fatal("停點未觸發：交錯沒有發生")
			}
			if err != nil {
				t.Fatalf("帳號在取鎖前被刪除時，映射規則刪除應成功: %v", err)
			}

			var gone int64
			if err := f.db.Model(&model.User{}).Where("id=?", victim.ID).Count(&gone).Error; err != nil {
				t.Fatal(err)
			}
			if gone != 0 {
				t.Fatal("前提不成立：被刪帳號仍可見")
			}
			for _, table := range victimTables {
				if got := rowsOf(table, victim.ID); got != victimBefore[table] {
					t.Fatalf("已刪帳號的 %s 被變動：%d → %d", table, victimBefore[table], got)
				}
			}
			if got := auditsOf(victim.ID); got != victimAuditsBefore {
				t.Fatalf("已刪帳號被寫入以它為主體的稽核：%d → %d", victimAuditsBefore, got)
			}
			if got := epochOf(victim.ID); got != victimEpochBefore {
				t.Fatalf("已刪帳號的憑證世代被推進：%d → %d", victimEpochBefore, got)
			}
			if supportsOf(victim.ID) != 0 || supportsOf(f.user.ID) != 0 {
				t.Fatalf("本規則的支持列未清除（已刪帳號 %d、存活帳號 %d）", supportsOf(victim.ID), supportsOf(f.user.ID))
			}
			if auditsOf(f.user.ID) <= liveAuditsBefore {
				t.Fatal("存活帳號的撤銷稽核未寫入")
			}
		})
	}
}

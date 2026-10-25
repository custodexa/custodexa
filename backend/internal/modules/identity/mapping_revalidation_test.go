package identity

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
)

// 有界重新驗證的夾具輔助：以現成的映射夾具建立「已知登入一次、有角色與群組支持」的帳號，
// 再把該通道的最近已知觀測時間撥回指定小時數，餵未知觀測看保留或收回。

func (f *mappingSegmentFixture) providerObs(state GroupObservationState, hours *int, groups ...string) GroupObservation {
	return GroupObservation{Kind: model.RoleMappingChannelKindProvider, SourceID: f.provider.ID, State: state,
		Groups: groups, HasActiveRules: true, RevalidationHours: hours}
}

func intp(v int) *int { return &v }

// age 把該通道的最近已知觀測時間設為 h 小時前；h < 0 代表刪除該列（從未有已知觀測）。
func (f *mappingSegmentFixture) age(t *testing.T, channel string, h float64) {
	t.Helper()
	if h < 0 {
		require.NoError(t, f.db.Where("user_id = ? AND channel = ?", f.user.ID, channel).Delete(&model.UserChannelObservation{}).Error)
		return
	}
	require.NoError(t, f.db.Model(&model.UserChannelObservation{}).Where("user_id = ? AND channel = ?", f.user.ID, channel).
		Update("last_known_at", time.Now().Add(-time.Duration(h*float64(time.Hour)))).Error)
}

func (f *mappingSegmentFixture) lastKnown(t *testing.T, channel string) (time.Time, bool) {
	t.Helper()
	var rows []model.UserChannelObservation
	require.NoError(t, f.db.Where("user_id = ? AND channel = ?", f.user.ID, channel).Find(&rows).Error)
	if len(rows) == 0 {
		return time.Time{}, false
	}
	return rows[0].LastKnownAt, true
}

func (f *mappingSegmentFixture) auditCount(t *testing.T, code string) int64 {
	t.Helper()
	var n int64
	require.NoError(t, f.db.Model(&model.AuditLog{}).Where("error_msg = ?", code).Count(&n).Error)
	return n
}

func (f *mappingSegmentFixture) recompute(t *testing.T, obs GroupObservation) RoleMappingOutcome {
	t.Helper()
	out, err := RecomputeMappedRoles(f.db, audit.NewTxSink(), &f.user, obs)
	require.NoError(t, err)
	return out
}

// TestMappingStaleUnknownObservation 未知觀測的上界：時限內保留並留跳過事件，超時或從未有已知觀測則收回
// 該通道的角色與群組支持；時限為 0 不因時間收回；另一條通道不受影響；已知觀測推進時間、未知不推進。
func TestMappingStaleUnknownObservation(t *testing.T) {
	chProvider := func(f *mappingSegmentFixture) string {
		return model.RoleMappingChannel(model.RoleMappingChannelKindProvider, f.provider.ID)
	}

	t.Run("時限內的未知觀測保留支持並留跳過事件，世代不變", func(t *testing.T) {
		f := newMappingSegmentFixture(t)
		f.roleRule(t, "a")
		f.groupRule(t, "a")
		f.login(t, "a")
		f.age(t, chProvider(f), 11)
		epoch := f.epoch(t)
		out := f.recompute(t, f.providerObs(GroupObservationUnknown, intp(12)))
		assert.Equal(t, RoleMappingSkipGroupsUnknown, out.Skipped)
		assert.False(t, out.Expired)
		assert.EqualValues(t, 1, f.count(t, "user_role_mapping_rule_supports"))
		assert.EqualValues(t, 1, f.count(t, "user_group_mapping_rule_supports"))
		assert.Equal(t, epoch, f.epoch(t))
		assert.EqualValues(t, 1, f.auditCount(t, RoleMappingSkipGroupsUnknown))
		assert.EqualValues(t, 0, f.auditCount(t, MembershipRevalidationExpired))
	})

	t.Run("超過時限的未知觀測收回角色與群組支持，推進世代並撤銷更新憑證，寫時限收回事件", func(t *testing.T) {
		f := newMappingSegmentFixture(t)
		f.roleRule(t, "a")
		f.groupRule(t, "a")
		f.login(t, "a")
		require.NoError(t, f.db.Create(&model.RefreshToken{UserID: f.user.ID, TokenHash: "h1", ExpiresAt: time.Now().Add(time.Hour)}).Error)
		f.age(t, chProvider(f), 13)
		before, _ := f.lastKnown(t, chProvider(f))
		epoch := f.epoch(t)
		out := f.recompute(t, f.providerObs(GroupObservationUnknown, intp(12)))
		assert.True(t, out.Expired)
		assert.True(t, out.EpochBumped)
		assert.Equal(t, []string{"auditor"}, out.Removed)
		for _, table := range []string{"user_role_mapping_rule_supports", "user_group_mapping_rule_supports", "user_role_mappings", "user_roles", "user_group_members"} {
			assert.EqualValues(t, 0, f.count(t, table), table)
		}
		assert.Greater(t, f.epoch(t), epoch)
		var live int64
		require.NoError(t, f.db.Model(&model.RefreshToken{}).Where("user_id = ? AND revoked_at IS NULL", f.user.ID).Count(&live).Error)
		assert.EqualValues(t, 0, live, "更新憑證已撤銷")
		assert.EqualValues(t, 1, f.auditCount(t, MembershipRevalidationExpired))
		assert.EqualValues(t, 0, f.auditCount(t, RoleMappingSkipGroupsUnknown))
		after, _ := f.lastKnown(t, chProvider(f))
		assert.True(t, before.Equal(after), "未知觀測不更新最近已知觀測時間")
	})

	t.Run("從未有已知觀測且持有支持即收回", func(t *testing.T) {
		f := newMappingSegmentFixture(t)
		f.roleRule(t, "a")
		f.login(t, "a")
		f.age(t, chProvider(f), -1)
		out := f.recompute(t, f.providerObs(GroupObservationUnknown, intp(12)))
		assert.True(t, out.Expired)
		assert.EqualValues(t, 0, f.count(t, "user_role_mapping_rule_supports"))
		assert.EqualValues(t, 1, f.auditCount(t, MembershipRevalidationExpired))
	})

	t.Run("時限為 0 不因時間收回，仍留跳過事件", func(t *testing.T) {
		f := newMappingSegmentFixture(t)
		f.roleRule(t, "a")
		f.login(t, "a")
		f.age(t, chProvider(f), 13)
		out := f.recompute(t, f.providerObs(GroupObservationUnknown, intp(0)))
		assert.Equal(t, RoleMappingSkipGroupsUnknown, out.Skipped)
		assert.EqualValues(t, 1, f.count(t, "user_role_mapping_rule_supports"))
		assert.EqualValues(t, 1, f.auditCount(t, RoleMappingSkipGroupsUnknown))
		// 時限未帶入（單元建構路徑）同樣不收回
		out = f.recompute(t, f.providerObs(GroupObservationUnknown, nil))
		assert.Equal(t, RoleMappingSkipGroupsUnknown, out.Skipped)
		assert.EqualValues(t, 1, f.count(t, "user_role_mapping_rule_supports"))
	})

	t.Run("有規則未設定群組屬性名與未知觀測同樣受時限約束", func(t *testing.T) {
		f := newMappingSegmentFixture(t)
		f.roleRule(t, "a")
		f.login(t, "a")
		f.age(t, chProvider(f), 11)
		out := f.recompute(t, f.providerObs(GroupObservationUnconfigured, intp(12)))
		assert.Equal(t, RoleMappingSkipSourceAttrUnset, out.Skipped)
		assert.EqualValues(t, 1, f.count(t, "user_role_mapping_rule_supports"))
		f.age(t, chProvider(f), 13)
		out = f.recompute(t, f.providerObs(GroupObservationUnconfigured, intp(12)))
		assert.True(t, out.Expired)
		assert.EqualValues(t, 0, f.count(t, "user_role_mapping_rule_supports"))
	})

	t.Run("另一條通道的支持與觀測時間不受影響", func(t *testing.T) {
		f := newMappingSegmentFixture(t)
		f.roleRule(t, "a")
		f.login(t, "a")
		// 另一條通道（目錄）上的支持與觀測由夾具直接寫入
		dir := model.LDAPDirectory{Enabled: true}
		require.NoError(t, f.db.Create(&dir).Error)
		other := model.RoleMappingChannel(model.RoleMappingChannelKindDirectory, dir.ID)
		require.NoError(t, f.db.Create(&model.UserRoleMapping{UserID: f.user.ID, RoleID: f.role.ID, Channel: other}).Error)
		require.NoError(t, f.db.Create(&model.UserChannelObservation{UserID: f.user.ID, Channel: other, LastKnownAt: time.Now().Add(-2 * time.Hour)}).Error)
		f.age(t, chProvider(f), 13)
		out := f.recompute(t, f.providerObs(GroupObservationUnknown, intp(12)))
		assert.True(t, out.Expired)
		var facts int64
		require.NoError(t, f.db.Model(&model.UserRoleMapping{}).Where("user_id = ? AND channel = ?", f.user.ID, other).Count(&facts).Error)
		assert.EqualValues(t, 1, facts, "另一通道的映射事實保留")
		_, ok := f.lastKnown(t, other)
		assert.True(t, ok)
	})

	t.Run("已知觀測推進最近已知觀測時間，未知觀測不推進", func(t *testing.T) {
		f := newMappingSegmentFixture(t)
		f.roleRule(t, "a")
		f.login(t, "a")
		f.age(t, chProvider(f), 5)
		f.login(t, "a")
		t1, ok := f.lastKnown(t, chProvider(f))
		require.True(t, ok)
		assert.WithinDuration(t, time.Now(), t1, time.Minute, "已知觀測把時間推到現在")
		f.age(t, chProvider(f), 5)
		t2, _ := f.lastKnown(t, chProvider(f))
		f.recompute(t, f.providerObs(GroupObservationUnknown, intp(12)))
		t3, _ := f.lastKnown(t, chProvider(f))
		assert.True(t, t2.Equal(t3), "未知觀測不改時間")
	})

	t.Run("該通道沒有任何映射支持時超時不製造收回事件", func(t *testing.T) {
		f := newMappingSegmentFixture(t)
		f.roleRule(t, "a")
		out := f.recompute(t, f.providerObs(GroupObservationUnknown, intp(12)))
		assert.False(t, out.Expired)
		assert.Equal(t, RoleMappingSkipGroupsUnknown, out.Skipped)
		assert.EqualValues(t, 0, f.auditCount(t, MembershipRevalidationExpired))
	})

	t.Run("手動指派的角色不屬於映射支持，超時收回不動它", func(t *testing.T) {
		f := newMappingSegmentFixture(t)
		f.roleRule(t, "a")
		require.NoError(t, f.db.Create(&model.UserRole{UserID: f.user.ID, RoleID: f.role.ID, Source: model.RoleSourceManual, ScopeKind: model.ScopeKindGlobal}).Error)
		f.login(t, "a")
		f.age(t, chProvider(f), 13)
		f.recompute(t, f.providerObs(GroupObservationUnknown, intp(12)))
		var n int64
		require.NoError(t, f.db.Model(&model.UserRole{}).Where("user_id = ? AND role_id = ?", f.user.ID, f.role.ID).Count(&n).Error)
		assert.EqualValues(t, 1, n, "manual 來源保留（只移除映射成分）")
	})
}

// TestMappingObservationBackfillNoUpgradeRevocation 升級回填之後的第一次未知觀測：
// 持有支持卻沒有觀測列的帳號（升級前的狀態）經回填後，時限從升級時刻起算，不會被立即收回。
func TestMappingObservationBackfillNoUpgradeRevocation(t *testing.T) {
	f := newMappingSegmentFixture(t)
	ch := model.RoleMappingChannel(model.RoleMappingChannelKindProvider, f.provider.ID)
	f.roleRule(t, "a")
	f.groupRule(t, "a")
	f.login(t, "a")
	// 還原升級前狀態：有支持、沒有觀測列、快照為很久以前
	f.age(t, ch, -1)
	require.NoError(t, f.db.Model(&model.User{}).Where("id = ?", f.user.ID).
		Updates(map[string]any{"group_snapshot_channel": ch, "group_snapshot_at": time.Now().Add(-72 * time.Hour)}).Error)

	_, err := database.BackfillChannelObservations(f.db, time.Now().UTC())
	require.NoError(t, err)

	epoch := f.epoch(t)
	out := f.recompute(t, f.providerObs(GroupObservationUnknown, intp(12)))
	assert.Equal(t, RoleMappingSkipGroupsUnknown, out.Skipped)
	assert.False(t, out.Expired)
	assert.EqualValues(t, 1, f.count(t, "user_role_mapping_rule_supports"))
	assert.EqualValues(t, 1, f.count(t, "user_group_mapping_rule_supports"))
	assert.Equal(t, epoch, f.epoch(t))
	assert.EqualValues(t, 0, f.auditCount(t, MembershipRevalidationExpired))
}

package identity

import (
	"fmt"
	"time"

	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit/port"
)

// 有界重新驗證：未知觀測的上界。
//
// 外部來源這次沒給出群組（讀不到、型別不符、有規則卻沒設群組屬性名／宣告名）時，
// 既有映射支持照舊保留，這是為了不讓目錄暫時故障把全員的權限收光。但「保留」沒有期限，
// 就等於一次最後的已知觀測可以讓權限無限期留著。本檔給這個保留一個上界：
//
//	時限 T 為 0（不設限）           保留，寫跳過事件
//	最近已知觀測在 T 內             保留，寫跳過事件
//	最近已知觀測超過 T，或從未有過  收回該通道全部映射支持，寫 membership_revalidation_expired
//
// 只動本通道：另一條通道的支持與觀測時間不受影響。手動指派的角色與成員身分不屬於映射支持，不動。
// 「讀不到觀測時間」不當成沒有觀測：讀取失敗就回錯，登入沿用映射重算失敗即拒絕的既有方向。

// unobservedMapping 處理未知或未設定的觀測。
func unobservedMapping(db *gorm.DB, auditSink port.TxSink, user *model.User,
	obs GroupObservation, skipCode string) (RoleMappingOutcome, error) {
	if obs.RevalidationHours == nil || *obs.RevalidationHours <= 0 {
		return skipRoleMapping(db, auditSink, user, obs, skipCode)
	}
	// 先看這條通道上有沒有任何映射支持（只讀支持表，不開交易、不取鎖）：沒有就沒有東西可收回，
	// 走原本的純留痕跳過，既有部署「規則有、屬性名沒設」的登入不多取任何鎖。
	// 這個預檢在鎖外，與並行的已知登入競爭時可能漏看剛寫入的支持，下一次未知觀測會再判一次。
	has, err := channelHasSupports(db, user.ID, obs.Channel())
	if err != nil {
		return RoleMappingOutcome{}, err
	}
	if !has {
		return skipRoleMapping(db, auditSink, user, obs, skipCode)
	}
	bound := time.Duration(*obs.RevalidationHours) * time.Hour
	return recomputeUnderLocks(db, user, obs, func(locked *gorm.DB) (RoleMappingOutcome, error) {
		return applyUnobservedLocked(locked, auditSink, user, obs, skipCode, bound)
	})
}

// channelHasSupports 該帳號在該通道是否持有任何角色或使用者群組映射支持。讀不到即回錯。
// 表名以字面量逐一寫出（依序查、先命中先回），讓模組資料邊界守衛能靜態解析。
func channelHasSupports(db *gorm.DB, userID uint, channel string) (bool, error) {
	has := func(q *gorm.DB) (bool, error) {
		var n int64
		if err := q.Where("user_id = ? AND channel = ?", userID, channel).Limit(1).Count(&n).Error; err != nil {
			return false, fmt.Errorf("讀取映射支持失敗: %w", err)
		}
		return n > 0, nil
	}
	if ok, err := has(db.Table("user_role_mapping_rule_supports")); err != nil || ok {
		return ok, err
	}
	return has(db.Table("user_group_mapping_rule_supports"))
}

// lastKnownObservation 該帳號在該通道最近一次已知觀測時間。
func lastKnownObservation(tx *gorm.DB, userID uint, channel string) (time.Time, bool, error) {
	var rows []model.UserChannelObservation
	if err := tx.Where("user_id = ? AND channel = ?", userID, channel).Limit(1).Find(&rows).Error; err != nil {
		return time.Time{}, false, fmt.Errorf("讀取通道觀測時間失敗: %w", err)
	}
	if len(rows) == 0 {
		return time.Time{}, false, nil
	}
	return rows[0].LastKnownAt, true, nil
}

// applyUnobservedLocked 鎖內判定：在時限內保留並留跳過事件，超時則收回本通道映射支持。
func applyUnobservedLocked(tx *gorm.DB, auditSink port.TxSink, user *model.User, obs GroupObservation,
	skipCode string, bound time.Duration) (RoleMappingOutcome, error) {
	skip := func() (RoleMappingOutcome, error) {
		if err := writeRoleMappingAudit(tx, auditSink, user, obs, skipCode, map[string]any{
			"channel": obs.Channel(),
		}); err != nil {
			return RoleMappingOutcome{}, err
		}
		return RoleMappingOutcome{Skipped: skipCode}, nil
	}
	last, found, err := lastKnownObservation(tx, user.ID, obs.Channel())
	if err != nil {
		return RoleMappingOutcome{}, err
	}
	now := time.Now()
	if found && now.Sub(last) <= bound {
		return skip()
	}

	// 超時或從未有已知觀測：以「沒有命中任何規則」的狀態收回本通道全部映射支持與事實
	empty := obs
	empty.Groups = nil
	roleChanges, err := syncRoleRuleSupports(tx, user.ID, obs.Channel(), nil)
	if err != nil {
		return RoleMappingOutcome{}, err
	}
	groupChanges, removedGroupIDs, err := syncGroupRuleSupports(tx, user.ID, empty)
	if err != nil {
		return RoleMappingOutcome{}, err
	}
	removedIDs, err := RevokeMappedRolesForChannel(tx, user.ID, obs.Channel(), nil)
	if err != nil {
		return RoleMappingOutcome{}, err
	}
	if len(roleChanges) == 0 && len(groupChanges) == 0 && len(removedIDs) == 0 && len(removedGroupIDs) == 0 {
		// 這條通道上本來就沒有映射支持：沒有東西可收回，不製造「已收回」的訊號
		return skip()
	}
	outcome := RoleMappingOutcome{Expired: true}
	if outcome.Removed, err = roleNamesOf(tx, removedIDs, nil); err != nil {
		return RoleMappingOutcome{}, err
	}
	if len(removedIDs) > 0 || len(removedGroupIDs) > 0 {
		if err := BumpCredentialEpoch(tx, user.ID, "membership_revalidation_expired"); err != nil {
			return RoleMappingOutcome{}, err
		}
		if _, err := RevokeAllRefreshTokens(tx, user.ID, model.RefreshRevokeCredentialEpoch); err != nil {
			return RoleMappingOutcome{}, fmt.Errorf("撤銷更新憑證失敗: %w", err)
		}
		outcome.EpochBumped = true
	}
	details := map[string]any{
		"channel":         obs.Channel(),
		"reason":          skipCode,
		"limit_hours":     int(bound / time.Hour),
		"roles_removed":   outcome.Removed,
		"groups_removed":  removedGroupIDs,
		"epoch_bumped":    outcome.EpochBumped,
		"support_changes": append(roleChanges, groupChanges...),
	}
	if found {
		details["last_known_at"] = last.UTC().Format(time.RFC3339)
	} else {
		details["last_known_at"] = nil
	}
	if err := writeRoleMappingAudit(tx, auditSink, user, obs, MembershipRevalidationExpired, details); err != nil {
		return RoleMappingOutcome{}, err
	}
	return outcome, nil
}

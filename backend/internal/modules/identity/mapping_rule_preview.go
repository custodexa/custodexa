package identity

import (
	"fmt"
	"sort"

	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/authz"
)

// 映射規則變更的預覽（唯讀）：以規則識別重讀舊值，組出與寫入相同的 mappingWrite，
// 分級用同一組規劃與分類函式；收回後的狀態由唯讀模擬依寫入的保留規則求得。
// 本檔不呼叫任何寫入函式，也不以先寫再回滾代替模擬。

// previewInvalid 把輸入驗證失敗包成預覽無效（對外一律 400，不洩漏是哪個物件不存在）。
func previewInvalid(err error) error {
	return fmt.Errorf("%w: %v", authz.ErrPreviewInvalid, err)
}

// mappingWriteFromChange 依規則識別重讀舊值，與新值合成一次寫入的描述。
// 修改時省略的欄位沿用舊值；規則須屬於該來源，否則視為無效輸入。
func mappingWriteFromChange(tx *gorm.DB, operatorID uint, c authz.MappingRuleChange) (mappingWrite, uint, error) {
	var w mappingWrite
	kind, err := MappingSourceKind(c.SourceType)
	if err != nil {
		return w, 0, previewInvalid(err)
	}
	if _, err := resolveSource(tx, kind, c.SourceID); err != nil {
		if err == ErrMappingSourceNotFound {
			return w, 0, previewInvalid(err)
		}
		return w, 0, err
	}
	w.Kind, w.SourceID, w.Op = kind, c.SourceID, Operator{UserID: operatorID}
	switch c.RuleType {
	case mappingRuleRole:
		if c.GroupID != 0 {
			return w, 0, previewInvalid(fmt.Errorf("角色規則不接受使用者群組目標"))
		}
	case mappingRuleUserGroup:
		if c.RoleID != 0 {
			return w, 0, previewInvalid(fmt.Errorf("使用者群組規則不接受角色目標"))
		}
	default:
		return w, 0, previewInvalid(fmt.Errorf("規則類別不明: %q", c.RuleType))
	}
	w.RuleType = c.RuleType

	// 舊值：既有規則以規則識別重讀。
	var oldTargetID uint
	if c.RuleID != 0 {
		oldMatch, oldTarget, oldEnabled, err := mappingRuleOldValues(tx, w, c.RuleID)
		if err != nil {
			return w, 0, err
		}
		w.OldMatch, w.OldEnabled, oldTargetID = oldMatch, oldEnabled, oldTarget
		if w.Old, err = mappingTargetOf(tx, w.RuleType, oldTarget); err != nil {
			return w, 0, err
		}
	} else if c.Delete {
		return w, 0, previewInvalid(fmt.Errorf("刪除須指定規則"))
	}

	if c.Delete {
		w.Deleted = true
		return w, c.RuleID, nil
	}

	// 新值：新增須齊全，修改沿用舊值。
	newMatch := w.OldMatch
	if c.MatchValue != nil || c.RuleID == 0 {
		raw := ""
		if c.MatchValue != nil {
			raw = *c.MatchValue
		}
		if newMatch, err = validateMatchValue(kind, raw); err != nil {
			return w, 0, previewInvalid(err)
		}
	}
	newTarget := oldTargetID
	if c.RoleID != 0 {
		newTarget = c.RoleID
	}
	if c.GroupID != 0 {
		newTarget = c.GroupID
	}
	if newTarget == 0 {
		return w, 0, previewInvalid(fmt.Errorf("缺少規則目標"))
	}
	if newTarget != oldTargetID || c.RuleID == 0 {
		if err := requireMappingTarget(tx, w.RuleType, newTarget); err != nil {
			return w, 0, err
		}
	}
	newEnabled := true
	if c.RuleID != 0 {
		newEnabled = w.OldEnabled
	}
	if c.Enabled != nil {
		newEnabled = *c.Enabled
	}
	w.NewMatch, w.NewEnabled = newMatch, newEnabled
	if w.New, err = mappingTargetOf(tx, w.RuleType, newTarget); err != nil {
		return w, 0, err
	}
	if c.RuleID == 0 {
		w.Created = true
		w.OldMatch = newMatch
	}
	return w, c.RuleID, nil
}

// mappingRuleOldValues 既有規則的比對值、目標編號與啟用旗標；規則須屬於該來源。
func mappingRuleOldValues(tx *gorm.DB, w mappingWrite, ruleID uint) (match string, target uint, enabled bool, err error) {
	if w.RuleType == mappingRuleRole {
		row, err := mappingRowOf(tx, w.Kind, w.SourceID, ruleID)
		if err != nil {
			if err == ErrMappingRuleNotFound {
				return "", 0, false, previewInvalid(err)
			}
			return "", 0, false, err
		}
		return row.MatchValue, row.RoleID, row.Enabled, nil
	}
	row, err := userGroupMappingRow(tx, w.Kind, w.SourceID, ruleID)
	if err != nil {
		return "", 0, false, previewInvalid(err)
	}
	var dictionary model.ExternalGroup
	if err := tx.First(&dictionary, row.ExternalGroupID).Error; err != nil {
		return "", 0, false, fmt.Errorf("讀取外部群組失敗: %w", err)
	}
	return dictionary.MatchValue, row.UserGroupID, row.Enabled, nil
}

// requireMappingTarget 新目標須存在（角色未刪除、使用者群組存在）。
func requireMappingTarget(tx *gorm.DB, ruleType string, id uint) error {
	if ruleType == mappingRuleRole {
		_, found, err := authz.RoleGrantEntry(tx, id)
		if err != nil {
			return err
		}
		if !found {
			return previewInvalid(ErrMappingRoleUnknown)
		}
		return nil
	}
	if err := validateMappingTargetGroup(tx, id); err != nil {
		if err == ErrUserGroupNotFound {
			return previewInvalid(err)
		}
		return err
	}
	return nil
}

func mappingTargetOf(tx *gorm.DB, ruleType string, id uint) (*mappingTarget, error) {
	if ruleType == mappingRuleRole {
		return roleMappingTarget(tx, id)
	}
	return groupMappingTarget(tx, id)
}

// mappingSupporters 目前受某條規則支持的帳號（升冪、不重複）。
func mappingSupporters(tx *gorm.DB, kind string, sourceID uint, ruleType string, ruleID uint) ([]uint, error) {
	var ids []uint
	q := tx.Table("user_group_mapping_rule_supports")
	if ruleType == mappingRuleRole {
		q = tx.Table("user_role_mapping_rule_supports")
	}
	if err := q.Where("channel = ? AND rule_id = ?", model.RoleMappingChannel(kind, sourceID), ruleID).
		Distinct().Order("user_id").Pluck("user_id", &ids).Error; err != nil {
		return nil, fmt.Errorf("讀取規則支持失敗: %w", err)
	}
	return ids, nil
}

// simulateMappingRevocation 唯讀模擬：這次寫入收回舊規則的支持之後，指定帳號的假設狀態。
// 保留規則與 revokeMappingSupportsLocked 相同：同一通道仍有其他規則支持的角色、經其他通道仍映射的角色、
// 手動或兩者兼有來源的角色都保留；仍有其他規則支持或本身是手動成員的群組成員身分也保留。
// 不受收回影響的帳號（寫入不會重算的）原樣回傳。
func simulateMappingRevocation(tx *gorm.DB, w mappingWrite, ruleID uint, users []uint) (map[uint]authz.SubjectState, error) {
	out := make(map[uint]authz.SubjectState, len(users))
	supporting := map[uint]bool{}
	if w.revokesOldSupports() {
		ids, err := mappingSupporters(tx, w.Kind, w.SourceID, w.RuleType, ruleID)
		if err != nil {
			return nil, err
		}
		for _, id := range ids {
			supporting[id] = true
		}
	}
	for _, uid := range users {
		st, err := authz.LoadSubjectState(tx, uid)
		if err != nil {
			return nil, err
		}
		if supporting[uid] {
			if st, err = revokedState(tx, w, ruleID, uid, st); err != nil {
				return nil, err
			}
		}
		out[uid] = st
	}
	return out, nil
}

// revokedState 單一帳號收回該規則支持後的假設狀態。
func revokedState(tx *gorm.DB, w mappingWrite, ruleID, userID uint, st authz.SubjectState) (authz.SubjectState, error) {
	channel := model.RoleMappingChannel(w.Kind, w.SourceID)
	isRole := w.RuleType == mappingRuleRole

	// 角色：本通道仍被其他規則支持的角色保留；其餘本通道映射事實失效。
	var roleRows []model.UserRoleMappingRuleSupport
	if err := tx.Where("user_id = ? AND channel = ?", userID, channel).Find(&roleRows).Error; err != nil {
		return st, fmt.Errorf("讀取角色支持失敗: %w", err)
	}
	keep := map[uint]bool{}
	for _, r := range roleRows {
		if !(isRole && r.RuleID == ruleID) {
			keep[r.RoleID] = true
		}
	}
	var facts []uint
	if err := tx.Table("user_role_mappings").Where("user_id = ? AND channel = ?", userID, channel).
		Pluck("role_id", &facts).Error; err != nil {
		return st, fmt.Errorf("讀取本通道映射事實失敗: %w", err)
	}
	assignments := append([]authz.Assignment(nil), st.Assignments...)
	for _, roleID := range facts {
		if keep[roleID] {
			continue
		}
		var other int64
		if err := tx.Model(&model.UserRoleMapping{}).
			Where("user_id = ? AND role_id = ? AND channel <> ?", userID, roleID, channel).Count(&other).Error; err != nil {
			return st, fmt.Errorf("查詢角色的映射成分失敗: %w", err)
		}
		if other > 0 {
			continue
		}
		for i := 0; i < len(assignments); i++ {
			a := assignments[i]
			if a.Via != authz.ViaDirect || a.RoleID != roleID {
				continue
			}
			switch a.RoleSource {
			case model.RoleSourceMapped:
				assignments = append(assignments[:i:i], assignments[i+1:]...)
				i--
			case model.RoleSourceBoth:
				assignments[i].RoleSource = model.RoleSourceManual
			}
		}
	}

	// 使用者群組：只重算這條規則支持過的群組，仍有其他支持或本身是手動成員者保留。
	groupIDs := append([]uint(nil), st.GroupIDs...)
	if !isRole {
		var grpRows []model.UserGroupMappingRuleSupport
		if err := tx.Where("user_id = ? AND channel = ? AND rule_id = ?", userID, channel, ruleID).Find(&grpRows).Error; err != nil {
			return st, fmt.Errorf("讀取群組支持失敗: %w", err)
		}
		seen := map[uint]bool{}
		var touched []uint
		for _, r := range grpRows {
			if !seen[r.UserGroupID] {
				seen[r.UserGroupID] = true
				touched = append(touched, r.UserGroupID)
			}
		}
		sort.Slice(touched, func(i, j int) bool { return touched[i] < touched[j] })
		for _, gid := range touched {
			var remaining int64
			if err := tx.Table("user_group_mapping_rule_supports").
				Where("user_id = ? AND user_group_id = ?", userID, gid).
				Where("NOT (channel = ? AND rule_id = ?)", channel, ruleID).Count(&remaining).Error; err != nil {
				return st, fmt.Errorf("查詢群組支持失敗: %w", err)
			}
			var members []model.UserGroupMember
			if err := tx.Where("user_id = ? AND user_group_id = ?", userID, gid).Find(&members).Error; err != nil {
				return st, fmt.Errorf("讀取群組成員失敗: %w", err)
			}
			switch {
			case remaining > 0 && len(members) == 0:
				var live int64
				if err := tx.Model(&model.UserGroup{}).Where("id = ?", gid).Count(&live).Error; err != nil {
					return st, fmt.Errorf("讀取使用者群組失敗: %w", err)
				}
				if live == 0 {
					continue
				}
				add, err := authz.GroupStateAssignments(tx, gid)
				if err != nil {
					return st, err
				}
				groupIDs = append(groupIDs, gid)
				assignments = append(assignments, add...)
			case remaining == 0 && len(members) > 0 && !members[0].Manual:
				kept := groupIDs[:0:0]
				for _, g := range groupIDs {
					if g != gid {
						kept = append(kept, g)
					}
				}
				groupIDs = kept
				left := assignments[:0:0]
				for _, a := range assignments {
					if !(a.Via == authz.ViaGroup && a.GroupID == gid) {
						left = append(left, a)
					}
				}
				assignments = left
			}
		}
	}
	return authz.SubjectState{Assignments: assignments, GroupIDs: groupIDs}, nil
}

// PlanMappingRuleChange 映射規則變更預覽的轉接：求受影響者、收回後的假設狀態與規則層的分類。
// 分級與寫入共用 planMappingGrade、classifyMappingGrade；唯讀，不取鎖、不寫入。
func PlanMappingRuleChange(tx *gorm.DB, operatorID uint, c authz.MappingRuleChange) (authz.MappingRulePlan, error) {
	w, ruleID, err := mappingWriteFromChange(tx, operatorID, c)
	if err != nil {
		return authz.MappingRulePlan{}, err
	}
	plan, err := planMappingGrade(tx, w, true)
	if err != nil {
		return authz.MappingRulePlan{}, err
	}
	var supporters []uint
	if w.revokesOldSupports() {
		if supporters, err = mappingSupporters(tx, w.Kind, w.SourceID, w.RuleType, ruleID); err != nil {
			return authz.MappingRulePlan{}, err
		}
	}
	seen := map[uint]bool{}
	var affected []uint
	for _, list := range [][]uint{plan.hitters, supporters} {
		for _, id := range list {
			if !seen[id] {
				seen[id] = true
				affected = append(affected, id)
			}
		}
	}

	simulate := func(tx *gorm.DB, ids []uint) (map[uint]authz.SubjectState, error) {
		return simulateMappingRevocation(tx, w, ruleID, ids)
	}
	after := plan.before
	if plan.hasOp && seen[w.Op.UserID] && w.revokesOldSupports() {
		sim, err := simulate(tx, []uint{w.Op.UserID})
		if err != nil {
			return authz.MappingRulePlan{}, err
		}
		if after, err = authz.SummarizeState(tx, sim[w.Op.UserID]); err != nil {
			return authz.MappingRulePlan{}, err
		}
	}
	grade := classifyMappingGrade(plan, after)

	out := authz.MappingRulePlan{
		Affected: affected, EvaluateCap: mappingPreviewSubjectCap,
		After: simulate,
		Marks: []string{}, SelfDirection: authz.GrantNone,
	}
	if grade.Self != nil {
		out.SelfDirection = grade.Self.Class.SelfDirection
		out.Marks = append(out.Marks, grade.Self.Class.Marks...)
	}
	if len(grade.Management) > 0 {
		out.ManagementGranted = true
		out.Marks = append(out.Marks, authz.GrantMarkManagementGrant)
	}
	if w.becomesActive() {
		out.GrantHitters = make(map[uint]bool, len(plan.hitters))
		for _, id := range plan.hitters {
			out.GrantHitters[id] = true
		}
		if w.RuleType == mappingRuleRole {
			out.GrantRoleID = w.New.id
		} else {
			out.GrantGroupID = w.New.id
		}
	}
	return out, nil
}

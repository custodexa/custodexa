package authz

import (
	"errors"
	"fmt"
	"sort"

	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
)

// 映射規則變更的預覽（唯讀）。
//
// 規則本身的告警分類、受影響者與收回後的假設狀態屬於身分模組（映射支持、通道與寫入的保留規則在那裡），
// 由組裝端注入的 MappingRulePlanner 求得；本檔只負責把它們餵進與其他種類相同的逐人求值。

// PreviewMappingRuleChange 外部群組映射規則變更：新增、修改、停用、啟用、刪除（對外輸入種類）。
const PreviewMappingRuleChange = "mapping_rule_change"

// ErrPreviewMappingPlannerMissing 映射規則變更需要的求值器未注入。
var ErrPreviewMappingPlannerMissing = errors.New("映射規則求值器未注入")

// MappingRuleChange 一筆規則變更的描述。RuleID 為 0 表示新增；修改時省略的欄位沿用舊值。
type MappingRuleChange struct {
	RuleType   string // role | user_group
	SourceType string // ldap | oidc
	SourceID   uint
	RuleID     uint
	MatchValue *string
	// RoleID／GroupID 目標：RuleType 為 role 時用 RoleID，user_group 時用 GroupID。
	RoleID  uint
	GroupID uint
	Enabled *bool
	Delete  bool
}

// SubjectState 一位主體在某個時點的假設狀態（有效指派與所屬群組）。
type SubjectState struct {
	Assignments []Assignment
	GroupIDs    []uint
}

// MappingRulePlan 身分模組對一筆規則變更求出的事實。
type MappingRulePlan struct {
	// Affected 授出側命中與收回側支持的聯集（不重複）。
	Affected []uint
	// EvaluateCap 逐人求值上限；操作者本人在受影響者內時一律先求值。
	EvaluateCap int
	// After 受影響者在寫入收回支持之後的假設狀態（唯讀模擬）；不在結果內的帳號視為不受收回影響。
	After func(tx *gorm.DB, userIDs []uint) (map[uint]SubjectState, error)
	// GrantHitters 授出側命中者（規則生效後各自多出目標）；GrantRoleID／GrantGroupID 二擇一，皆為 0 表示沒有授出。
	GrantHitters              map[uint]bool
	GrantRoleID, GrantGroupID uint
	// 規則層的分類，與寫入同一組函式求得，不受求值上限影響。
	Marks             []string
	SelfDirection     GrantDirection
	ManagementGranted bool
}

// MappingRulePlanner 依規則識別重讀舊值並求出規劃。唯讀；輸入無效時回 ErrPreviewInvalid。
type MappingRulePlanner func(tx *gorm.DB, operatorID uint, change MappingRuleChange) (MappingRulePlan, error)

// LoadSubjectState 帳號目前的假設狀態起點（與逐人求值的變更前狀態同一來源）。
func LoadSubjectState(tx *gorm.DB, userID uint) (SubjectState, error) {
	var kind string
	if err := tx.Model(&model.User{}).Where("id = ?", userID).Limit(1).Pluck("kind", &kind).Error; err != nil {
		return SubjectState{}, fmt.Errorf("查詢主體種類失敗: %w", err)
	}
	p, err := ResolveUserOn(tx, userID, TokenFacts{SubjectKind: kind})
	if err != nil {
		return SubjectState{}, err
	}
	groups, err := userGroupIDs(tx, userID)
	if err != nil {
		return SubjectState{}, err
	}
	return SubjectState{Assignments: p.Assignments, GroupIDs: groups}, nil
}

// SummarizeState 假設狀態的授權摘要（與 SummarizeGrants 同義，來源是假設狀態）。
func SummarizeState(tx *gorm.DB, st SubjectState) (GrantSummary, error) {
	return summaryOf(tx, subjectState{assignments: st.Assignments, groupIDs: st.GroupIDs})
}

// GroupStateAssignments 使用者群組帶給成員的指派（假設成員身分加入時用）。
func GroupStateAssignments(tx *gorm.DB, groupID uint) ([]Assignment, error) {
	roleIDs, err := UserGroupRoleIDs(tx, groupID)
	if err != nil {
		return nil, err
	}
	return currentGroupAssignments(tx, roleIDs, groupID)
}

// previewMappingRuleChange 規則變更種類的整體求值：總數取全部受影響者，逐人求值取到上限。
func previewMappingRuleChange(tx *gorm.DB, req PreviewRequest, limit int) (PreviewResult, error) {
	if req.MappingRule == nil {
		return PreviewResult{}, fmt.Errorf("%w: 缺少映射規則變更", ErrPreviewInvalid)
	}
	if req.MappingRulePlanner == nil {
		return PreviewResult{}, ErrPreviewMappingPlannerMissing
	}
	plan, err := req.MappingRulePlanner(tx, req.OperatorID, *req.MappingRule)
	if err != nil {
		return PreviewResult{}, err
	}
	kinds, err := userKinds(tx, plan.Affected)
	if err != nil {
		return PreviewResult{}, err
	}
	live := make([]uint, 0, len(plan.Affected))
	for _, id := range dedupeIDs(plan.Affected) {
		if _, ok := kinds[id]; ok {
			live = append(live, id)
		}
	}
	sort.Slice(live, func(i, j int) bool { return live[i] < live[j] })

	// 求值對象：操作者本人優先，其餘依帳號編號升冪取到上限。
	evalCap := plan.EvaluateCap
	if evalCap <= 0 || evalCap > len(live) {
		evalCap = len(live)
	}
	eval := make([]uint, 0, evalCap)
	for _, id := range live {
		if id == req.OperatorID && req.OperatorID != 0 {
			eval = append(eval, id)
		}
	}
	for _, id := range live {
		if len(eval) >= evalCap {
			break
		}
		if id != req.OperatorID || req.OperatorID == 0 {
			eval = append(eval, id)
		}
	}
	sort.Slice(eval, func(i, j int) bool { return eval[i] < eval[j] })

	var afters map[uint]SubjectState
	if plan.After != nil {
		if afters, err = plan.After(tx, eval); err != nil {
			return PreviewResult{}, err
		}
	}
	var grant stateMutator
	if plan.GrantRoleID != 0 || plan.GrantGroupID != 0 {
		_, grant, err = previewMappingGrantPlan(tx, PreviewRequest{RoleID: plan.GrantRoleID, GroupID: plan.GrantGroupID})
		if err != nil {
			return PreviewResult{}, err
		}
	}
	mutate := func(tx *gorm.DB, uid uint, before subjectState) (subjectState, error) {
		st := before
		if a, ok := afters[uid]; ok {
			st = subjectState{assignments: a.Assignments, groupIDs: a.GroupIDs}
		}
		if grant != nil && plan.GrantHitters[uid] {
			return grant(tx, uid, st)
		}
		return st, nil
	}

	res := PreviewResult{Total: len(live), Subjects: []PreviewSubject{}}
	all := make([]PreviewSubject, 0, len(eval))
	var listed []PreviewSubject
	for _, id := range eval {
		subj, err := previewSubject(tx, id, kinds[id], req.OperatorID, req.Scope, mutate)
		if err != nil {
			return PreviewResult{}, err
		}
		all = append(all, subj)
		if subj.Self || len(subj.NewCombos) > 0 {
			listed = append(listed, subj)
		}
	}
	sort.SliceStable(listed, func(i, j int) bool {
		if listed[i].Self != listed[j].Self {
			return listed[i].Self
		}
		return listed[i].UserID < listed[j].UserID
	})
	res.Matched = len(listed)
	if len(listed) > limit {
		listed, res.Truncated = listed[:limit], true
	}
	if len(eval) < len(live) {
		res.Truncated = true
	}
	if listed != nil {
		res.Subjects = listed
	}
	op := aggregateOperation(PreviewOperation{
		Marks: plan.Marks, SelfDirection: plan.SelfDirection, ManagementGranted: plan.ManagementGranted,
	}, all)
	res.Operation = &op
	return res, nil
}

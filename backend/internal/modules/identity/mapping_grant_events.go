package identity

import (
	"encoding/json"
	"fmt"
	"sort"

	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit/port"
	"github.com/custodexa/backend/internal/modules/authz"
)

// 外部群組映射寫入的授權變更事件。
//
// 規則寫入本身不立刻給任何人新權限（建立與啟用在對象下次登入才生效），但停用與刪除會即時收回，
// 且規則一旦生效，外部群組成員就會取得目標角色或使用者群組。所以分兩種事件：
//
//   - 對操作者本人（自我授權）：建立、啟用、修改新值「會命中操作者」為增加（高）；
//     停用、刪除、修改舊值使操作者實際失去授權為純減少（低）。增加以操作者最近一次已知群組
//     觀測快照判定，快照不存在即判定未命中；快照只用於事件分級，不用於任何授權判定。
//     減少以寫入前後的授權摘要比較，不另設判定。
//   - 對他人的管理類發放：規則生效後的目標是管理類角色，或帶管理類角色的使用者群組，
//     每次寫入一筆（中），判定基準是規則目標，不依當下命中人數。
//
// 兩者可同時成立，各自產生一筆。登入時的重算沒有本系統的操作者，不走這裡。
// 審計列、事件、規則寫入、支持收回、世代推進在同一個交易內，任一步失敗整筆回滾。

// 事件 path 欄的代碼：映射規則的兩類目標各一個，釘住沿用既有的 PathPin。
const (
	// PathMappingUserGroup 外部群組到使用者群組的規則寫入。
	PathMappingUserGroup AssignmentPath = "mapping_user_group"
)

// 規則目標類別。
const (
	mappingRuleRole      = "role"
	mappingRuleUserGroup = "user_group"
)

// MappingImpact 規則寫入前求出的可能受影響主體，交給危險組合預覽。
type MappingImpact struct {
	Path       AssignmentPath
	RuleType   string // role | user_group
	SourceKind string
	SourceID   uint
	RuleID     uint
	TargetName string
	// TargetID 規則目標：RuleType 為 role 時是角色編號，user_group 時是使用者群組編號。
	TargetID uint
	// Subjects 最近一次已知群組觀測快照命中新規則的帳號（升冪、不重複）。
	Subjects []uint
}

// MappingImpactPreview 危險組合預覽的消費端窄介面（確認不阻擋，畫面由後續變更接）。
// 實作的錯誤逸出交易使整筆回滾，所以實作應是只讀或與寫入同交易。
type MappingImpactPreview interface {
	ObserveMappingImpact(tx *gorm.DB, in MappingImpact) error
}

// SetMappingImpactPreview 注入危險組合預覽；nil 表示不餵（預覽是建議性輸入，不是留痕）。
func (g *GrantGrader) SetMappingImpactPreview(p MappingImpactPreview) {
	if g != nil {
		g.preview = p
	}
}

// mappingTarget 規則目標換算成的授權項。
type mappingTarget struct {
	id      uint // 角色或使用者群組識別
	name    string
	entries []authz.GrantEntry
	ruleIDs []uint
}

// withoutBaseline 去掉基礎使用者範本的授權項：它是所有帳號的基準身分，
// 規則指向它不構成值得告警的授權變更（一般角色零事件）。
func (t *mappingTarget) withoutBaseline() *mappingTarget {
	kept := t.entries[:0:0]
	for _, e := range t.entries {
		if e.BuiltinKey != model.BuiltinUser {
			kept = append(kept, e)
		}
	}
	t.entries = kept
	return t
}

func (t *mappingTarget) grants() bool {
	return t != nil && (len(t.entries) > 0 || len(t.ruleIDs) > 0)
}

func (t *mappingTarget) sameAs(o *mappingTarget) bool {
	if t == nil || o == nil {
		return t == o
	}
	return t.id == o.id
}

// roleMappingTarget 直接映射的角色目標。
func roleMappingTarget(tx *gorm.DB, roleID uint) (*mappingTarget, error) {
	e, found, err := authz.RoleGrantEntry(tx, roleID)
	if err != nil {
		return nil, err
	}
	if !found {
		return &mappingTarget{id: roleID}, nil
	}
	return (&mappingTarget{id: roleID, name: e.RoleName, entries: []authz.GrantEntry{e}}).withoutBaseline(), nil
}

// groupMappingTarget 使用者群組目標：群組目前的角色指派與資產授權規則。
func groupMappingTarget(tx *gorm.DB, groupID uint) (*mappingTarget, error) {
	ents, err := authz.GroupGrantEntries(tx, groupID)
	if err != nil {
		return nil, err
	}
	rules, err := authz.GroupAuthorizationRuleIDs(tx, groupID)
	if err != nil {
		return nil, err
	}
	var name string
	if err := tx.Model(&model.UserGroup{}).Where("id = ?", groupID).Pluck("name", &name).Error; err != nil {
		return nil, fmt.Errorf("查詢使用者群組名稱失敗: %w", err)
	}
	return (&mappingTarget{id: groupID, name: name, entries: ents, ruleIDs: rules}).withoutBaseline(), nil
}

// mappingWrite 一次規則寫入的描述。
type mappingWrite struct {
	RuleType   string
	Kind       string
	SourceID   uint
	Op         Operator
	OldMatch   string
	NewMatch   string
	OldEnabled bool
	NewEnabled bool
	Created    bool
	Deleted    bool
	Old, New   *mappingTarget
}

func (w mappingWrite) path() AssignmentPath {
	if w.RuleType == mappingRuleUserGroup {
		return PathMappingUserGroup
	}
	return PathMapping
}

// becomesActive 這次寫入使一條「會授出目標」的規則開始生效（或改指新目標、新比對值）。
func (w mappingWrite) becomesActive() bool {
	if w.Deleted || !w.NewEnabled || !w.New.grants() {
		return false
	}
	return w.Created || !w.OldEnabled || w.OldMatch != w.NewMatch || !w.Old.sameAs(w.New)
}

// revokesOldSupports 這次寫入會收回舊規則的支持：刪除、修改比對值或目標、由啟用改為停用。
// 新增與停用改啟用不收回任何東西。
func (w mappingWrite) revokesOldSupports() bool {
	switch {
	case w.Created:
		return false
	case w.Deleted:
		return true
	case w.OldMatch != w.NewMatch || !w.Old.sameAs(w.New):
		return true
	}
	return w.OldEnabled && !w.NewEnabled
}

// mappingPlan 寫入前求出的分級事實。預覽與寫入共用：寫入在取得來源鎖、規則尚未寫入時求，
// 預覽在唯讀交易內求；兩邊之後都只把操作者的變更後摘要交給 classifyMappingGrade。
type mappingPlan struct {
	w      mappingWrite
	hasOp  bool
	before authz.GrantSummary
	// opHits 操作者最近一次已知群組觀測是否命中新值（只在規則會生效時求）。
	opHits bool
	// hitters 授出側：最近一次已知群組觀測命中新值的帳號（升冪），只在規則會生效且要求時求。
	hitters []uint
}

// planMappingGrade 唯讀規劃：操作者的變更前摘要、操作者是否命中新值、授出側的快照命中帳號。
// 不寫庫、不發事件、不取鎖。
func planMappingGrade(tx *gorm.DB, w mappingWrite, withHitters bool) (*mappingPlan, error) {
	p := &mappingPlan{w: w, hasOp: w.Op.UserID != 0}
	if p.hasOp {
		sum, err := authz.SummarizeGrants(tx, w.Op.UserID)
		if err != nil {
			return nil, err
		}
		p.before = sum
		if w.becomesActive() {
			if p.opHits, err = operatorHitsRule(tx, w.Op.UserID, w.Kind, w.SourceID, w.NewMatch); err != nil {
				return nil, err
			}
		}
	}
	if withHitters && w.becomesActive() {
		hitters, err := snapshotHitters(tx, w.Kind, w.SourceID, w.NewMatch)
		if err != nil {
			return nil, err
		}
		p.hitters = hitters
	}
	return p, nil
}

// mappingSelfGrade 對操作者本人要留的事件：前後摘要與分類。
type mappingSelfGrade struct {
	Before, After authz.GrantSummary
	Class         authz.GrantClassification
}

// mappingGrade 一次規則寫入的分級結果。
type mappingGrade struct {
	// Self 對操作者本人的事件；nil 表示不留。
	Self *mappingSelfGrade
	// Management 規則生效後授出的管理類授權項（判定基準是規則目標，不依命中人數）。
	Management []authz.GrantEntry
}

// classifyMappingGrade 純分類：輸入規劃與操作者的變更後摘要。
// 增加以規劃中的命中與模擬授出判定，優先於減少（修改使命中目標改變算增加或範圍互換，不另記一筆減少）；
// 減少只看變更前後摘要，不看支持列有沒有被刪。
func classifyMappingGrade(p *mappingPlan, after authz.GrantSummary) mappingGrade {
	var out mappingGrade
	w := p.w
	if p.hasOp {
		if w.becomesActive() && p.opHits {
			synth := p.before.WithGranted(w.New.entries, w.New.ruleIDs)
			cls := authz.ClassifyGrantChange(p.before, synth, true)
			if cls.SelfDirection == authz.GrantIncrease {
				out.Self = &mappingSelfGrade{Before: p.before, After: synth, Class: cls}
			}
		}
		if out.Self == nil {
			cls := authz.ClassifyGrantChange(p.before, after, true)
			if cls.SelfDirection == authz.GrantDecrease {
				out.Self = &mappingSelfGrade{Before: p.before, After: after, Class: cls}
			}
		}
	}
	if w.becomesActive() {
		for _, e := range w.New.entries {
			if e.Management {
				out.Management = append(out.Management, e)
			}
		}
	}
	return out
}

// mappingTracker 一次規則寫入的前後比對。以 nil 接收者呼叫皆為無操作。
type mappingTracker struct {
	t    *grantTracker
	plan *mappingPlan
}

// beginMapping 在規則寫入前（已取得來源鎖）求分級規劃。grader 為 nil 時不分級。
func (g *GrantGrader) beginMapping(tx *gorm.DB, w mappingWrite) (*mappingTracker, error) {
	if g == nil {
		return nil, nil
	}
	plan, err := planMappingGrade(tx, w, g.preview != nil)
	if err != nil {
		return nil, err
	}
	return &mappingTracker{t: &grantTracker{g: g, op: w.Op, path: w.path()}, plan: plan}, nil
}

// finish 規則與支持收回都寫完後呼叫：判定事件、寫標記審計與事件、餵預覽。ruleID 為寫入後的規則識別。
// 變更後摘要取交易內的真實結果。
func (mt *mappingTracker) finish(tx *gorm.DB, ruleID uint) error {
	if mt == nil {
		return nil
	}
	plan := mt.plan
	w := plan.w
	var after authz.GrantSummary
	if plan.hasOp {
		var err error
		if after, err = authz.SummarizeGrants(tx, w.Op.UserID); err != nil {
			return err
		}
	}
	grade := classifyMappingGrade(plan, after)
	if grade.Self != nil {
		if err := mt.t.emitUser(tx, w.Op.UserID, grade.Self.Before, grade.Self.After, grade.Self.Class); err != nil {
			return err
		}
	}
	if len(grade.Management) > 0 {
		if err := mt.t.emitManagement(tx, port.SystemAlertTargetRoleMapping, ruleID, w.New.name, grade.Management,
			string(model.ResourceAuth), ruleID); err != nil {
			return err
		}
	}
	if w.becomesActive() && mt.t.g.preview != nil {
		if err := mt.t.g.preview.ObserveMappingImpact(tx, MappingImpact{
			Path: w.path(), RuleType: w.RuleType, SourceKind: w.Kind, SourceID: w.SourceID,
			RuleID: ruleID, TargetName: w.New.name, TargetID: w.New.id, Subjects: plan.hitters,
		}); err != nil {
			return fmt.Errorf("危險組合預覽輸入失敗: %w", err)
		}
	}
	return nil
}

// groupSnapshot 帳號最近一次已知群組觀測快照。
type groupSnapshot struct {
	Channel string
	Groups  []string
}

func loadGroupSnapshot(tx *gorm.DB, userID uint) (groupSnapshot, error) {
	var row struct {
		Channel string `gorm:"column:group_snapshot_channel"`
		Groups  string `gorm:"column:group_snapshot_groups"`
	}
	if err := tx.Model(&model.User{}).Select("group_snapshot_channel, group_snapshot_groups").
		Where("id = ?", userID).Take(&row).Error; err != nil {
		return groupSnapshot{}, fmt.Errorf("讀取群組觀測快照失敗: %w", err)
	}
	return parseGroupSnapshot(row.Channel, row.Groups), nil
}

func parseGroupSnapshot(channel, raw string) groupSnapshot {
	snap := groupSnapshot{Channel: channel}
	if raw != "" {
		// 解析失敗當作沒有快照（未命中），快照只用於事件分級
		_ = json.Unmarshal([]byte(raw), &snap.Groups)
	}
	return snap
}

func (s groupSnapshot) matches(kind string, sourceID uint, matchValue string) bool {
	if s.Channel == "" || s.Channel != model.RoleMappingChannel(kind, sourceID) {
		return false
	}
	hits, bad := groupMatcherFor(kind)(s.Groups, matchValue)
	return !bad && len(hits) > 0
}

// operatorHitsRule 操作者最近一次已知觀測是否命中這條規則的比對值。快照不存在即未命中。
func operatorHitsRule(tx *gorm.DB, userID uint, kind string, sourceID uint, matchValue string) (bool, error) {
	snap, err := loadGroupSnapshot(tx, userID)
	if err != nil {
		return false, err
	}
	return snap.matches(kind, sourceID, matchValue), nil
}

// snapshotHitters 該通道上最近一次已知觀測命中比對值的帳號（升冪）。
func snapshotHitters(tx *gorm.DB, kind string, sourceID uint, matchValue string) ([]uint, error) {
	channel := model.RoleMappingChannel(kind, sourceID)
	var rows []struct {
		ID     uint
		Groups string `gorm:"column:group_snapshot_groups"`
	}
	if err := tx.Model(&model.User{}).Select("id, group_snapshot_groups").
		Where("group_snapshot_channel = ?", channel).Order("id").Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("讀取群組觀測快照失敗: %w", err)
	}
	var out []uint
	for _, r := range rows {
		if parseGroupSnapshot(channel, r.Groups).matches(kind, sourceID, matchValue) {
			out = append(out, r.ID)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out, nil
}

// beginRoleMappingWrite 角色規則寫入的分級起點。oldRoleID／newRoleID 為 0 表示該側沒有目標。
// grader 未注入時回 nil（不分級）。
func (s *IdentitySourceService) beginRoleMappingWrite(tx *gorm.DB, actor GroupRoleMappingActor, kind string,
	sourceID uint, w mappingWrite, oldRoleID, newRoleID uint) (*mappingTracker, error) {
	if s.grader == nil {
		return nil, nil
	}
	w.RuleType, w.Kind, w.SourceID, w.Op = mappingRuleRole, kind, sourceID, mappingOperator(actor)
	var err error
	if oldRoleID != 0 {
		if w.Old, err = roleMappingTarget(tx, oldRoleID); err != nil {
			return nil, err
		}
	}
	if newRoleID != 0 {
		if w.New, err = roleMappingTarget(tx, newRoleID); err != nil {
			return nil, err
		}
	}
	return s.grader.beginMapping(tx, w)
}

// beginUserGroupMappingWrite 使用者群組規則寫入的分級起點。
func (s *IdentitySourceService) beginUserGroupMappingWrite(tx *gorm.DB, actor GroupRoleMappingActor, kind string,
	sourceID uint, w mappingWrite, oldGroupID, newGroupID uint) (*mappingTracker, error) {
	if s.grader == nil {
		return nil, nil
	}
	w.RuleType, w.Kind, w.SourceID, w.Op = mappingRuleUserGroup, kind, sourceID, mappingOperator(actor)
	var err error
	if oldGroupID != 0 {
		if w.Old, err = groupMappingTarget(tx, oldGroupID); err != nil {
			return nil, err
		}
	}
	if newGroupID != 0 {
		if w.New, err = groupMappingTarget(tx, newGroupID); err != nil {
			return nil, err
		}
	}
	return s.grader.beginMapping(tx, w)
}

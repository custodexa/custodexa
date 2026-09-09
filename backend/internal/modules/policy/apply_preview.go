package policy

import "github.com/custodexa/backend/internal/model"

// 套用政策建議值的計算。**預覽與套用是同一支計算**：畫面上看到的那張表就是
// 按下確認後會被填進表單的內容，兩者各算一次的話，管理者核可的與實際填入的
// 可以不同，而審計只看得到後者。
//
// 計算不寫入任何東西：確認套用只是把變動填進表單，仍走既有的儲存流程與審計。

// 套用模式。
const (
	// ApplyModeGroup 只依指定的一個生效政策組套用
	ApplyModeGroup = "group"
	// ApplyModeStrictest 一次滿足所有生效政策組
	ApplyModeStrictest = "strictest"
)

// ErrCodeApplyPreviewMode 套用預覽的參數不合法
const ErrCodeApplyPreviewMode = "VALIDATION_APPLY_PREVIEW_MODE"

// ApplyChange 預覽表的一列變動。
type ApplyChange struct {
	Key      string `json:"key"`
	Current  string `json:"current"`
	Proposed string `json:"proposed"`
	// SourceGroup 這個值的依據來自哪一個政策組
	SourceGroup string `json:"source_group"`
}

// ApplyConflictReason 造成衝突的其中一條規則。
type ApplyConflictReason struct {
	Group      string `json:"group"`
	Expected   string `json:"expected"`
	Comparator string `json:"comparator"`
}

// ApplyConflict 一個鍵上互相對立的要求。衝突的鍵不自動改。
type ApplyConflict struct {
	Key     string                `json:"key"`
	Reasons []ApplyConflictReason `json:"reasons"`
}

// ApplyPreview 套用預覽的完整結果。
type ApplyPreview struct {
	Mode      string `json:"mode"`
	GroupCode string `json:"group_code,omitempty"`
	// Changes 只列會變動的鍵
	Changes []ApplyChange `json:"changes"`
	// Conflicts 要求互相對立、不自動改的鍵
	Conflicts []ApplyConflict `json:"conflicts"`
	// UnchangedCount 範圍內已符合或無須變動的鍵數
	UnchangedCount int `json:"unchanged_count"`
	// UnmappedCount 範圍內不屬於任何生效政策組的鍵數
	UnmappedCount int `json:"unmapped_count"`
}

// keyExpectation 單一鍵上的一條要求。
type keyExpectation struct {
	GroupCode  string
	Comparator string
	Value      string
}

// expectationBound 收斂後的一端界線（以序數表示，整數即數值本身）。
type expectationBound struct {
	rank  int
	value string
	group string
	set   bool
}

// expectationBounds 一個鍵上全部要求收斂成的可接受區間。
//
// 三種比較方式都落在同一個區間模型上：「至少」抬高下界、「至多」壓低上界、
// 明確值同時是上下界。**開關與枚舉的兩組要求值不同即成為空區間**，衝突判定
// 因此只有一條規則，不必為每種型別各寫一套。
type expectationBounds struct {
	lower expectationBound
	upper expectationBound
	// excludeZero 零值代表停用的鍵上有非零要求，故 0 不在可接受集合內。
	//
	// **這是區間之外的第三個約束**：0 在數值上小於任何上界，只看區間的話
	// 「機制沒開」會被讀成「設得比要求更嚴」，而那正是判定會判偏離的那個值
	excludeZero bool
	conflict    bool
}

// strictest 最嚴的那一端（單一方向的要求集合只會有一端）。
func (b expectationBounds) strictest() (expectationBound, bool) {
	if b.lower.set {
		return b.lower, true
	}
	if b.upper.set {
		return b.upper, true
	}
	return expectationBound{}, false
}

// nonZeroBound 非零的界線（零值代表停用的鍵用來跳離「關著」的狀態）。
func (b expectationBounds) nonZeroBound() (expectationBound, bool) {
	if b.lower.set && b.lower.rank != 0 {
		return b.lower, true
	}
	if b.upper.set && b.upper.rank != 0 {
		return b.upper, true
	}
	return expectationBound{}, false
}

// keyPlan 單一鍵的套用結論。
type keyPlan struct {
	Change   bool
	Conflict bool
	Target   expectationBound
}

// resolveBounds 把一個鍵上的全部要求收斂成區間；ok=false 表示要求值無法比較。
func resolveBounds(def *PolicyDef, exps []keyExpectation) (expectationBounds, bool) {
	var bounds expectationBounds
	for _, e := range exps {
		rank, ok := policyValueRank(def, e.Value)
		if !ok {
			return expectationBounds{}, false
		}
		end := expectationBound{rank: rank, value: e.Value, group: e.GroupCode, set: true}
		switch e.Comparator {
		case model.PolicyControlComparatorMin:
			raiseLower(&bounds, end)
		case model.PolicyControlComparatorMax:
			pressUpper(&bounds, end)
		case model.PolicyControlComparatorEquals:
			raiseLower(&bounds, end)
			pressUpper(&bounds, end)
		default:
			return expectationBounds{}, false
		}
		if def.ZeroDisables && def.Type == PolicyTypeInt && rank != 0 {
			bounds.excludeZero = true
		}
	}
	if bounds.lower.set && bounds.upper.set && bounds.lower.rank > bounds.upper.rank {
		bounds.conflict = true
	}
	// 上界壓到零而 0 又被排除：可接受集合為空，兩條要求同時滿足不了
	if bounds.excludeZero && bounds.upper.set && bounds.upper.rank <= 0 {
		bounds.conflict = true
	}
	return bounds, true
}

func raiseLower(bounds *expectationBounds, end expectationBound) {
	if !bounds.lower.set || end.rank > bounds.lower.rank {
		bounds.lower = end
	}
}

func pressUpper(bounds *expectationBounds, end expectationBound) {
	if !bounds.upper.set || end.rank < bounds.upper.rank {
		bounds.upper = end
	}
}

// planKeyChange 單一鍵：不動、改成某個值、或衝突。
//
// **不放寬**：現值只在不滿足某條要求時才被移動，而移動的終點是被違反的那一端。
// 已經比要求更嚴的現值因此不會被拉回要求值——「套用合規基準」這個動作不該
// 降低系統的安全性。
//
// **候選值出爐後仍要逐條驗過**：區間收斂會把要求壓成上下兩端，而零值語義這類
// 不是區間的約束在收斂過程中沒有位置。以判定用的同一支比較器複驗全部要求，
// 提出的值就不可能違反其中任何一條——不驗的話，預覽會提出一個判定當場就判偏離
// 的值，而管理者按下套用之後才看得到。
func planKeyChange(def *PolicyDef, current string, exps []keyExpectation) keyPlan {
	if len(exps) == 0 {
		return keyPlan{}
	}
	bounds, ok := resolveBounds(def, exps)
	if !ok {
		// 要求值無法比較：不臆測該填什麼（寫入端已驗值域，走到這裡是資料異常）
		return keyPlan{}
	}
	if bounds.conflict {
		return keyPlan{Conflict: true}
	}
	if satisfiesAll(def, current, exps) {
		return keyPlan{}
	}
	// 有要求沒被滿足，就必須給出一個同時滿足全部要求的值；給不出來即為衝突
	// （靜默留在「不變動」會讓一個偏離的鍵在預覽上完全不出現）
	target, has := candidateFor(def, current, bounds)
	if !has || !satisfiesAll(def, target.value, exps) {
		return keyPlan{Conflict: true}
	}
	return keyPlan{Change: true, Target: target}
}

// satisfiesAll 一個值是否同時達到全部要求（用的是判定契約的那支比較器）。
func satisfiesAll(def *PolicyDef, value string, exps []keyExpectation) bool {
	for _, e := range exps {
		if ok, _ := compareExpectation(def, value, e.Comparator, e.Value); !ok {
			return false
		}
	}
	return true
}

// candidateFor 現值不滿足要求時該移到哪一端；has=false 表示區間內找不到落點。
func candidateFor(def *PolicyDef, current string,
	bounds expectationBounds) (expectationBound, bool) {

	rank, ok := policyValueRank(def, current)
	if !ok {
		// 現值無法比較（草稿還在半途）：提出一個滿足要求的值
		return bounds.strictest()
	}
	// 零值代表停用的鍵：要求非零時，0 不是「更嚴的數」而是「機制沒開」
	if bounds.excludeZero && rank == 0 {
		return bounds.nonZeroBound()
	}
	if bounds.lower.set && rank < bounds.lower.rank {
		return bounds.lower, true
	}
	if bounds.upper.set && rank > bounds.upper.rank {
		return bounds.upper, true
	}
	return expectationBound{}, false
}

// buildApplyPreview 由一份判定結果算出套用預覽。
//
// 判定與套用讀同一份輸入，故預覽會變動的鍵集合恆等於偏離的鍵集合
// （扣掉互相對立而不自動改的那些）。
func buildApplyPreview(defs []PolicyDef, values map[string]string, snap ComplianceSnapshot,
	scope []string, mode, groupCode string) ApplyPreview {

	preview := ApplyPreview{Mode: mode, GroupCode: groupCode}
	inScope := keySet(scope)
	if inScope == nil {
		return preview
	}
	unmapped := keySet(snap.UnmappedKeys)
	expectations := expectationsByKey(snap, mode, groupCode)

	for i := range defs {
		def := &defs[i]
		if !inScope[def.Key] {
			continue
		}
		if unmapped[def.Key] {
			preview.UnmappedCount++
			continue
		}
		current, ok := values[def.Key]
		if !ok {
			current = def.Default
		}
		exps := expectations[def.Key]
		switch plan := planKeyChange(def, current, exps); {
		case plan.Conflict:
			preview.Conflicts = append(preview.Conflicts,
				ApplyConflict{Key: def.Key, Reasons: conflictReasons(exps)})
		case plan.Change:
			preview.Changes = append(preview.Changes, ApplyChange{
				Key: def.Key, Current: current,
				Proposed: plan.Target.value, SourceGroup: plan.Target.group,
			})
		default:
			preview.UnchangedCount++
		}
	}
	return preview
}

// expectationsByKey 取出可自動套用的要求。
//
// 待人工確認（參考值）與待稽核判讀（條文未定值）的控制**不進來**：前者的數字
// 沒有條文出處、後者根本沒有值，兩者都由人決定，一鍵套用不得代為決定。這些鍵
// 因此落在「不變動」而不是衝突——它們沒有與任何要求對立。
//
// 指定單組時，其他生效組的要求只在現值已經符合它們時才納入——那是「不放寬已
// 符合其他生效組的值」這條規則的約束來源，不是要套用的目標。
func expectationsByKey(snap ComplianceSnapshot, mode, groupCode string) map[string][]keyExpectation {
	out := map[string][]keyExpectation{}
	for _, v := range snap.Verdicts {
		if v.GroupCode == "" || v.Expected == "" {
			continue
		}
		if v.Result != ComplianceResultCompliant && v.Result != ComplianceResultDeviating {
			continue
		}
		if mode == ApplyModeGroup && v.GroupCode != groupCode &&
			v.Result != ComplianceResultCompliant {
			continue
		}
		out[v.Key] = append(out[v.Key], keyExpectation{
			GroupCode: v.GroupCode, Comparator: v.Comparator, Value: v.Expected,
		})
	}
	return out
}

// conflictReasons 衝突鍵上每一條規則的來源與要求（畫面據此說出是哪兩條規則對立）。
func conflictReasons(exps []keyExpectation) []ApplyConflictReason {
	out := make([]ApplyConflictReason, 0, len(exps))
	for _, e := range exps {
		out = append(out, ApplyConflictReason{
			Group: e.GroupCode, Expected: e.Value, Comparator: e.Comparator,
		})
	}
	return out
}

// PreviewApply 算出一份套用預覽。
//
// scope 是本頁的鍵集合（範圍外的鍵一律不動）；mode 為 ApplyModeGroup 時
// groupCode 須指名一個生效中的政策組。draft 是尚未儲存的表單值。
func (s *ComplianceService) PreviewApply(scope []string, mode, groupCode string,
	draft map[string]string) (ApplyPreview, error) {

	if err := s.assertApplyTarget(mode, groupCode); err != nil {
		return ApplyPreview{}, err
	}
	// 現值讀不到就不出預覽：以出廠預設頂替會算出一張與實況無關的變動表，
	// 而管理者按下確認之後那張表就會被填進表單
	views, err := s.policies.ListWithError()
	if err != nil {
		return ApplyPreview{}, err
	}
	current, _ := policyStateFromViews(views)
	values := applyDraftValues(current, draft)
	// 一律以全部生效組建構：指定單組時仍要看得見其他組，才判得出「這個改動會
	// 放寬另一組已經符合的值」
	// 套用預覽只讀判定結果本身，不呈現最後變更，故不帶
	snap, err := s.snapshotWith(values, nil, "", nil)
	if err != nil {
		return ApplyPreview{}, err
	}
	return buildApplyPreview(policyDefs, values, snap, scope, mode, groupCode), nil
}

// assertApplyTarget 套用模式與目標組的檢查。
//
// 模式打錯字時回錯誤而不是回一份空預覽：後者在畫面上與「沒有任何要變動的鍵」
// 長得一樣。
func (s *ComplianceService) assertApplyTarget(mode, groupCode string) error {
	switch mode {
	case ApplyModeStrictest:
		return nil
	case ApplyModeGroup:
		if groupCode == "" {
			return groupErr(ErrCodeApplyPreviewMode, "指定單組套用須指名政策組")
		}
		group, err := s.groups.GetGroup(groupCode)
		if err != nil {
			return err
		}
		if !group.Enabled {
			return groupErr(ErrCodeApplyPreviewMode, "政策組 %s 未生效，不得作為套用依據", groupCode)
		}
		return nil
	}
	return groupErr(ErrCodeApplyPreviewMode, "未知的套用模式 %q", mode)
}

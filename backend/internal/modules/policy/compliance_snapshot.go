package policy

import (
	"time"

	"github.com/custodexa/backend/internal/model"
)

// 合規判定契約：一支純函式把「生效政策組」與「安全設定現值」算成一份判定結果，
// 設定頁的分區偏離數、合規對照頁與套用預覽三處都只投影它。
//
// **為什麼三處不能各算各的**：三個畫面回答的是同一個問題，而它們的分歧不會有
// 任何一處報錯。同一時點看到不同的答案，管理者無從得知哪一個是真的。
//
// 建構程序不碰資料庫：輸入全部由呼叫端備齊，判定本身才可以被逐案釘住，
// 也才可以在草稿值上重跑一次而不寫入任何東西。

// Verdict 單一（設定鍵，政策組）配對的判定。
type Verdict struct {
	Key string `json:"key"`
	// GroupCode 判定所依據的政策組；未對照的鍵沒有依據的組，為空字串
	GroupCode string `json:"group_code"`
	// ClauseNo 該要求所屬的條號（合規對照頁以條文分組呈現）
	ClauseNo string `json:"clause_no,omitempty"`
	// Result 判定結果（見 ComplianceResult* 常數）
	Result string `json:"result"`
	// Reason 理由碼（機器碼，人話由呈現層依語系組出）
	Reason string `json:"reason"`
	// Current 判定當下的設定值。**每一種結果都帶**：待稽核判讀要靠它才判讀得出
	// 設定是否合理，其餘結果也要它才說得出「要求 12、目前 8」
	Current string `json:"current"`
	// Expected 該組對該鍵的要求值；未對照與未定值時為空
	Expected string `json:"expected,omitempty"`
	// Comparator 要求的比較方式（min／max／equals）
	Comparator string `json:"comparator,omitempty"`
	// UnitKey 該鍵的語義單位鍵（`count`／`days`…）；無單位的鍵為空。
	//
	// **判定帶著它出去**：合規對照頁上「至少 10」少了單位就判讀不了是十天、
	// 十分鐘還是十個字元，而該頁與設定抽屜若各自查一份單位表，同一個鍵會在
	// 兩處印出不同的字。呈現層據此走與設定頁同一支格式化
	UnitKey string `json:"unit_key,omitempty"`
	// ZeroDisables 該鍵的 0 代表機制停用（而不是「數字零」）。
	//
	// 呈現層據此把 0 說成停用或永久保留；少了它，一個關掉的機制在畫面上
	// 只是一個看起來很嚴的小數字
	ZeroDisables bool `json:"zero_disables,omitempty"`
	// ConfirmedBy 待人工確認的條文最近一次由誰確認；未確認為空
	ConfirmedBy string `json:"confirmed_by,omitempty"`
	// ConfirmedAt 最近一次確認的時刻；未確認為 nil
	ConfirmedAt *time.Time `json:"confirmed_at,omitempty"`
	// UpdatedBy 該鍵最後一次由誰改的；從未改過（值即出廠預設）時為空
	UpdatedBy string `json:"updated_by,omitempty"`
	// UpdatedAt 該鍵最後一次變更的時刻；從未改過時為 nil。
	//
	// **判定帶著它出去**：稽核人員追證的第二步問的是「這個設定何時被誰改的」，
	// 而另一個答得出來的地方是管理端的設定列表——稽核角色讀不到那一支。
	// 判定不帶，稽核視角就只知道偏離、不知道誰改的
	UpdatedAt *time.Time `json:"updated_at,omitempty"`
}

// PolicyKeyChange 單一設定鍵最後一次變更的操作者與時刻（無政策列時兩者皆空）。
type PolicyKeyChange struct {
	UpdatedBy string
	UpdatedAt *time.Time
}

// GroupRef 判定所涵蓋的政策組識別與版本（報告要能說出「這份結果對的是哪一版」）。
type GroupRef struct {
	Code    string `json:"code"`
	Version string `json:"version"`
	Enabled bool   `json:"enabled"`
}

// GroupSummary 某一政策組的摘要格（合規對照頁的五格）。
type GroupSummary struct {
	GroupCode   string `json:"group_code"`
	Compliant   int    `json:"compliant"`
	Deviating   int    `json:"deviating"`
	NeedsReview int    `json:"needs_review"`
	// AuditReview 條文涉及但未定值、待稽核判讀的鍵數。與待人工確認一樣另計，
	// 不併入符合或偏離
	AuditReview int `json:"audit_review"`
	// Unmapped 不在本組對照範圍的鍵數。**不得併入符合數**——沒有人對照過的
	// 設定與「有人對照且達到要求」是兩件事
	Unmapped int `json:"unmapped"`
	// BuiltinProtection 本組由產品無條件承擔、沒有可調設定值的條文條數。
	//
	// **單位是條文而不是設定鍵**，故不進上面五格的合計：那五格數的是設定鍵，
	// 把條文數加進去會讓分母憑空長大
	BuiltinProtection int `json:"builtin_protection"`
}

// ComplianceSnapshot 一次建構的完整判定結果。
type ComplianceSnapshot struct {
	BuiltAt time.Time `json:"built_at"`
	// Draft 這份結果建立在尚未儲存的草稿值上。**必須帶出去**：草稿與已儲存的
	// 結果長得一樣，不標示的話畫面上的數字無從分辨是現況還是預期
	Draft bool `json:"draft"`
	// Groups 建構時看到的全部政策組（含未生效者，供畫面標示）
	Groups []GroupRef `json:"groups"`
	// Verdicts 每一（鍵，組）配對的判定；未被任何生效組對照的鍵各有一列未對照
	Verdicts []Verdict `json:"verdicts"`
	// UnmappedKeys 未被任何生效組對照的鍵。偏離數的分母不含它們
	UnmappedKeys []string `json:"unmapped_keys"`
	// KeyCount 本次判定涵蓋的設定鍵數（逐組摘要以它為分母）
	KeyCount int `json:"key_count"`
	// BuiltinProtectionClauses 各組系統內建保護型條文的條數（依組代號）。
	//
	// 判定本身用不到它——那些條文沒有可比較的設定值——但合規頁要說得出
	// 「這一組還有幾條是產品直接承擔的」，否則畫面上那些條文會像是漏判
	BuiltinProtectionClauses map[string]int `json:"builtin_protection_clauses,omitempty"`
}

// BuildSnapshot 由生效政策組與設定現值建構判定結果。
//
// 只吃**生效**的組與**未標記移除**的條文：停用的組與已自規範消失的條文仍留在
// 資料庫裡（前者由機構決定、後者掛著機構的備註），但它們不參與判定。
// 「由機構自行確認」型的條文不產生鍵層判定，也不計入符合或偏離。
//
// values 缺少的鍵以該鍵的出廠預設判定（無政策列即出廠預設生效）。
// changes 是各鍵的最後變更，缺席的鍵表示從未被改過；傳 nil 即全部沒有變更記錄。
func BuildSnapshot(defs []PolicyDef, values map[string]string,
	changes map[string]PolicyKeyChange,
	groups []model.PolicyGroup, clauses []model.PolicyClause,
	controls []model.PolicyClauseControl,
	annotations []model.PolicyClauseAnnotation) ComplianceSnapshot {

	snap := ComplianceSnapshot{BuiltAt: time.Now().UTC(), KeyCount: len(defs)}
	snap.Groups = make([]GroupRef, 0, len(groups))
	enabled := make([]model.PolicyGroup, 0, len(groups))
	for _, g := range groups {
		snap.Groups = append(snap.Groups, GroupRef{Code: g.Code, Version: g.Version, Enabled: g.Enabled})
		if g.Enabled {
			enabled = append(enabled, g)
		}
	}

	live := liveSettingClauses(clauses)
	byGroupKey := indexControls(controls, live)
	annotationBy := indexAnnotations(annotations)
	snap.BuiltinProtectionClauses = countBuiltinProtectionClauses(clauses)

	snap.Verdicts = make([]Verdict, 0, len(defs))
	for i := range defs {
		def := &defs[i]
		value, ok := values[def.Key]
		if !ok {
			value = def.Default
		}
		change := changes[def.Key]
		matched := false
		for _, g := range enabled {
			control, has := byGroupKey[clauseIndexKey(g.Code, def.Key)]
			if !has {
				continue
			}
			matched = true
			verdict := buildVerdict(def, value, control,
				annotationBy[clauseIndexKey(g.Code, control.ClauseNo)])
			stampKeyMeta(&verdict, def)
			stampLastChange(&verdict, change)
			snap.Verdicts = append(snap.Verdicts, verdict)
		}
		if !matched {
			verdict := Verdict{
				Key:     def.Key,
				Current: value,
				Result:  ComplianceResultUnmapped,
				Reason:  ComplianceReasonNoControl,
			}
			stampKeyMeta(&verdict, def)
			stampLastChange(&verdict, change)
			snap.Verdicts = append(snap.Verdicts, verdict)
			snap.UnmappedKeys = append(snap.UnmappedKeys, def.Key)
		}
	}
	return snap
}

// stampKeyMeta 把呈現需要的鍵中繼資料蓋在判定上（每一種結果都蓋）。
//
// 單位與零值語義是**鍵的性質**，與判定結果無關：只在偏離時附上，符合的那幾列
// 就會少掉單位，而同一張表上有的數字有單位、有的沒有。
func stampKeyMeta(verdict *Verdict, def *PolicyDef) {
	if def == nil {
		return
	}
	verdict.UnitKey = def.UnitKey
	verdict.ZeroDisables = def.ZeroDisables
}

// stampLastChange 把該鍵的最後變更蓋在判定上。
//
// **每一種結果都蓋，包含未對照的鍵**：追證問的是「這個設定何時被誰改的」，
// 那與判定結果是符合還是偏離無關；只在偏離時附上，符合的鍵就追不下去了。
func stampLastChange(verdict *Verdict, change PolicyKeyChange) {
	verdict.UpdatedBy = change.UpdatedBy
	verdict.UpdatedAt = change.UpdatedAt
}

// buildVerdict 單一要求的判定。
func buildVerdict(def *PolicyDef, value string, control model.PolicyClauseControl,
	annotation *model.PolicyClauseAnnotation) Verdict {

	verdict := Verdict{
		Key: def.Key, GroupCode: control.GroupCode, ClauseNo: control.ClauseNo,
		Current: value, Expected: control.ExpectedValue, Comparator: control.Comparator,
	}
	// 條文未定值：沒有要求可比，連同目前值交給稽核人員判讀。**先於參考值判斷**
	// ——沒有值的東西不可能是參考值
	if control.Comparator == model.PolicyControlComparatorReview {
		verdict.Result = ComplianceResultAuditReview
		verdict.Reason = ComplianceReasonExpectationUnspecified
		verdict.Expected = ""
		return verdict
	}
	// 參考值不判符合或偏離：那個數字沒有條文出處，由機構自己決定要不要採用。
	// 把它判成偏離會讓一個沒有違反任何規範的設定被記成缺失
	if control.ReferenceOnly {
		verdict.Result = ComplianceResultNeedsReview
		verdict.Reason = ComplianceReasonReferenceUnconfirmed
		if annotation != nil {
			verdict.ConfirmedBy = annotation.ConfirmedBy
			verdict.ConfirmedAt = annotation.ConfirmedAt
			if annotation.ConfirmedBy != "" {
				verdict.Reason = ComplianceReasonReferenceConfirmed
			}
		}
		return verdict
	}
	ok, reason := compareExpectation(def, value, control.Comparator, control.ExpectedValue)
	verdict.Reason = reason
	verdict.Result = ComplianceResultDeviating
	if ok {
		verdict.Result = ComplianceResultCompliant
	}
	return verdict
}

// DeviatingKeys 偏離的鍵（去重，依判定順序）；scope 為空表示不限範圍。
func (s ComplianceSnapshot) DeviatingKeys(scope []string) []string {
	inScope := keySet(scope)
	seen := map[string]bool{}
	var out []string
	for _, v := range s.Verdicts {
		if v.Result != ComplianceResultDeviating || seen[v.Key] {
			continue
		}
		if inScope != nil && !inScope[v.Key] {
			continue
		}
		seen[v.Key] = true
		out = append(out, v.Key)
	}
	return out
}

// DeviationCount 偏離鍵數（設定頁分區摘要用；同一個鍵偏離多組只算一次）。
func (s ComplianceSnapshot) DeviationCount(scope []string) int {
	return len(s.DeviatingKeys(scope))
}

// GroupDeviationCount 某一組的偏離鍵數。
func (s ComplianceSnapshot) GroupDeviationCount(groupCode string) int {
	count := 0
	for _, v := range s.Verdicts {
		if v.GroupCode == groupCode && v.Result == ComplianceResultDeviating {
			count++
		}
	}
	return count
}

// GroupSummary 某一組的摘要格。**鍵層五格**合計恆等於涵蓋鍵數；
// 系統內建保護是第六格，單位是條文，不參與該合計。
func (s ComplianceSnapshot) GroupSummary(groupCode string) GroupSummary {
	summary := GroupSummary{
		GroupCode:         groupCode,
		BuiltinProtection: s.BuiltinProtectionClauses[groupCode],
	}
	mapped := 0
	for _, v := range s.Verdicts {
		if v.GroupCode != groupCode {
			continue
		}
		mapped++
		switch v.Result {
		case ComplianceResultCompliant:
			summary.Compliant++
		case ComplianceResultDeviating:
			summary.Deviating++
		case ComplianceResultNeedsReview:
			summary.NeedsReview++
		case ComplianceResultAuditReview:
			summary.AuditReview++
		}
	}
	summary.Unmapped = s.KeyCount - mapped
	return summary
}

// VerdictsForKey 某個鍵的全部判定（設定頁抽屜逐組呈現用）。
func (s ComplianceSnapshot) VerdictsForKey(key string) []Verdict {
	var out []Verdict
	for _, v := range s.Verdicts {
		if v.Key == key {
			out = append(out, v)
		}
	}
	return out
}

// ---- 索引助手 ----

// clauseIndexKey 組合鍵；分隔字元取代號與條號都不允許出現的位元組。
func clauseIndexKey(a, b string) string { return a + "\x00" + b }

// liveSettingClauses 仍在規範內且屬設定要求型的條文。
//
// 由機構自行確認與系統內建保護兩型都不在內：前者的責任在機構、後者在產品本身，
// 兩者都沒有可比較的設定值，替它們產一筆鍵層判定等於憑空多出一條要求。
func liveSettingClauses(clauses []model.PolicyClause) map[string]bool {
	live := make(map[string]bool, len(clauses))
	for _, c := range clauses {
		if c.RemovedInVersion != "" {
			continue
		}
		if c.Kind == model.PolicyClauseKindSelfAttested ||
			c.Kind == model.PolicyClauseKindBuiltinProtection {
			continue
		}
		live[clauseIndexKey(c.GroupCode, c.ClauseNo)] = true
	}
	return live
}

// countBuiltinProtectionClauses 各組仍在規範內的系統內建保護條文條數。
//
// **這是條文層的數字，不是鍵層的**：它數的是條文，而五格摘要數的是設定鍵，
// 兩者不可相加。分開存放正是為了讓相加這件事在型別上就做不出來。
func countBuiltinProtectionClauses(clauses []model.PolicyClause) map[string]int {
	out := map[string]int{}
	for _, c := range clauses {
		if c.RemovedInVersion != "" || c.Kind != model.PolicyClauseKindBuiltinProtection {
			continue
		}
		out[c.GroupCode]++
	}
	return out
}

// indexControls 以（組代號，設定鍵）索引可判定的控制。
//
// 條文清單裡查無對應條文的控制一律略過：那是資料異常（條文被刪而控制殘留），
// 而拿殘留的要求去判定會讓合規頁出現一條指不到任何條文的結果。
func indexControls(controls []model.PolicyClauseControl,
	live map[string]bool) map[string]model.PolicyClauseControl {

	out := make(map[string]model.PolicyClauseControl, len(controls))
	for _, c := range controls {
		if !live[clauseIndexKey(c.GroupCode, c.ClauseNo)] {
			continue
		}
		out[clauseIndexKey(c.GroupCode, c.PolicyKey)] = c
	}
	return out
}

func indexAnnotations(annotations []model.PolicyClauseAnnotation) map[string]*model.PolicyClauseAnnotation {
	out := make(map[string]*model.PolicyClauseAnnotation, len(annotations))
	for i := range annotations {
		a := annotations[i]
		out[clauseIndexKey(a.GroupCode, a.ClauseNo)] = &a
	}
	return out
}

// keySet 範圍集合；空範圍回 nil（表示不限）。
func keySet(keys []string) map[string]bool {
	if len(keys) == 0 {
		return nil
	}
	out := make(map[string]bool, len(keys))
	for _, k := range keys {
		out[k] = true
	}
	return out
}

// ---- 服務層 ----

// ComplianceService 判定契約的讀取端：備齊輸入、呼叫建構程序。
//
// 本身不含任何比較邏輯——那全部在建構程序裡，這一層只負責讀。
type ComplianceService struct {
	policies *SecurityPolicyService
	groups   *PolicyGroupRepository
}

// NewComplianceService 建立合規判定服務。
func NewComplianceService(policies *SecurityPolicyService,
	groups *PolicyGroupRepository) *ComplianceService {
	return &ComplianceService{policies: policies, groups: groups}
}

// TempControl 一次性的條文要求。
//
// 條文編輯器要在按下儲存之前答出「這一條存下去會判成什麼」，而那個答案必須由
// 判定契約本身給——編輯器自己算一份，畫面上的預告與儲存後的結果就會分歧，
// 且沒有任何一處會報錯。**只影響本次回應**，不寫入任何東西。
type TempControl struct {
	GroupCode     string `json:"group_code"`
	ClauseNo      string `json:"clause_no"`
	PolicyKey     string `json:"policy_key"`
	Comparator    string `json:"comparator"`
	ExpectedValue string `json:"expected_value"`
	ReferenceOnly bool   `json:"reference_only"`
}

// Snapshot 建構一份判定結果。
//
// groupFilter 為空＝全部生效組；指定不存在的組回 ErrCodePolicyGroupNotFound。
// draft 是尚未儲存的表單值，覆蓋現值後建構，結果標示為草稿；draft 不寫入任何東西。
func (s *ComplianceService) Snapshot(groupFilter string,
	draft map[string]string) (ComplianceSnapshot, error) {
	return s.SnapshotWithTemp(groupFilter, draft, nil)
}

// SnapshotWithTemp 帶一次性條文要求的判定（條文編輯器的儲存前預覽）。
func (s *ComplianceService) SnapshotWithTemp(groupFilter string, draft map[string]string,
	temps []TempControl) (ComplianceSnapshot, error) {

	views, err := s.policies.ListWithError()
	if err != nil {
		return ComplianceSnapshot{}, err
	}
	return s.SnapshotWithValues(views, groupFilter, draft, temps)
}

// SnapshotWithValues 以呼叫端手上的那一份政策視圖建構判定。
//
// **現值與判定出自同一次讀取**：呈現層要在同一份回應裡同時給出現值與它的判定，
// 兩者各讀一次的話，其間的一次寫入會讓同一列顯示新的要求配舊值算出的結果，
// 而畫面上看不出那兩個數字出自不同時點。
func (s *ComplianceService) SnapshotWithValues(views []PolicyView, groupFilter string,
	draft map[string]string, temps []TempControl) (ComplianceSnapshot, error) {

	values, changes := policyStateFromViews(views)
	snap, err := s.snapshotWith(applyDraftValues(values, draft), changes, groupFilter, temps)
	if err != nil {
		return ComplianceSnapshot{}, err
	}
	// 尚未儲存的要求與尚未儲存的值同樣使結果成為預期而非現況，故一併標示
	snap.Draft = len(draft) > 0 || len(temps) > 0
	return snap, nil
}

// snapshotWith 以指定的一組現值建構判定（套用預覽與判定共用，避免重讀現值）。
func (s *ComplianceService) snapshotWith(values map[string]string,
	changes map[string]PolicyKeyChange,
	groupFilter string, temps []TempControl) (ComplianceSnapshot, error) {

	groups, err := s.selectGroups(groupFilter)
	if err != nil {
		return ComplianceSnapshot{}, err
	}
	clauses, err := s.groups.ListClauses(groupFilter)
	if err != nil {
		return ComplianceSnapshot{}, err
	}
	controls, err := s.groups.ListControls(groupFilter)
	if err != nil {
		return ComplianceSnapshot{}, err
	}
	annotations, err := s.groups.ListAnnotations(groupFilter)
	if err != nil {
		return ComplianceSnapshot{}, err
	}
	clauses, controls, err = applyTempControls(groups, clauses, controls, temps)
	if err != nil {
		return ComplianceSnapshot{}, err
	}
	return BuildSnapshot(policyDefs, values, changes, groups, clauses, controls, annotations), nil
}

// applyTempControls 把一次性要求併進條文與控制清單，回一份新的（不就地改動輸入）。
//
// 覆蓋的粒度是（組代號，設定鍵）：同一組內一個鍵只能有一條要求，故換掉那一條
// 就是編輯器正在做的事。要求所屬的條文若尚未存在（正在新增），一併補上一條
// 設定要求型的條文——不補的話這條要求會在建構時被當成「指不到條文的殘留」
// 靜默丟掉，而畫面上會看到一份沒有任何結果的預覽，與「這條沒有偏離」無從分辨。
func applyTempControls(groups []model.PolicyGroup, clauses []model.PolicyClause,
	controls []model.PolicyClauseControl, temps []TempControl) (
	[]model.PolicyClause, []model.PolicyClauseControl, error) {

	if len(temps) == 0 {
		return clauses, controls, nil
	}
	known := make(map[string]bool, len(groups))
	for _, g := range groups {
		known[g.Code] = true
	}

	outClauses := append([]model.PolicyClause(nil), clauses...)
	outControls := append([]model.PolicyClauseControl(nil), controls...)
	for _, temp := range temps {
		normalized, err := normalizeTempControl(known, temp)
		if err != nil {
			return nil, nil, err
		}
		outControls = replaceControl(outControls, normalized)
		outClauses = ensureSettingClause(outClauses, normalized.GroupCode, normalized.ClauseNo)
	}
	return outClauses, outControls, nil
}

// normalizeTempControl 一次性要求的驗證與正規化（與寫入端同一組規則）。
//
// 驗證沿用寫入端的那幾支：預覽若比寫入寬鬆，編輯器會預告一個儲存時會被拒絕的
// 結果；比寫入嚴格則會擋掉存得下去的條文。
func normalizeTempControl(knownGroups map[string]bool, temp TempControl) (
	model.PolicyClauseControl, error) {

	if !knownGroups[temp.GroupCode] {
		return model.PolicyClauseControl{}, groupErr(ErrCodePolicyGroupNotFound,
			"政策組 %s 不存在", temp.GroupCode)
	}
	if temp.ClauseNo == "" || len(temp.ClauseNo) > policyClauseNoMaxLen {
		return model.PolicyClauseControl{}, groupErr(ErrCodePolicyGroupClauseNo,
			"條號長度須介於 1 與 %d 之間", policyClauseNoMaxLen)
	}
	def := findDef(temp.PolicyKey)
	if def == nil {
		return model.PolicyClauseControl{}, groupErr(ErrCodePolicyGroupUnknownKey,
			"設定鍵 %s 未定義", temp.PolicyKey)
	}
	control := model.PolicyClauseControl{
		GroupCode: temp.GroupCode, ClauseNo: temp.ClauseNo,
		PolicyKey: temp.PolicyKey, Comparator: temp.Comparator,
		ExpectedValue: temp.ExpectedValue, ReferenceOnly: temp.ReferenceOnly,
	}
	if err := assertComparatorFitsType(def, control.Comparator); err != nil {
		return model.PolicyClauseControl{}, err
	}
	if err := assertExpectedValueFitsComparator(def, control); err != nil {
		return model.PolicyClauseControl{}, err
	}
	if control.Comparator == model.PolicyControlComparatorReview {
		control.ExpectedValue = ""
	}
	return control, nil
}

// replaceControl 同組同鍵的既有要求換成這一條（沒有既有的就新增）。
func replaceControl(controls []model.PolicyClauseControl,
	control model.PolicyClauseControl) []model.PolicyClauseControl {

	out := make([]model.PolicyClauseControl, 0, len(controls)+1)
	for _, c := range controls {
		if c.GroupCode == control.GroupCode && c.PolicyKey == control.PolicyKey {
			continue
		}
		out = append(out, c)
	}
	return append(out, control)
}

// ensureSettingClause 確保該條要求指得到一條仍在規範內的設定要求型條文。
func ensureSettingClause(clauses []model.PolicyClause,
	groupCode, clauseNo string) []model.PolicyClause {

	for i := range clauses {
		if clauses[i].GroupCode != groupCode || clauses[i].ClauseNo != clauseNo {
			continue
		}
		// 編輯中的條文正掛著設定要求，故本次以設定要求型判定
		clauses[i].Kind = model.PolicyClauseKindSetting
		clauses[i].RemovedInVersion = ""
		return clauses
	}
	return append(clauses, model.PolicyClause{
		GroupCode: groupCode, ClauseNo: clauseNo,
		Kind: model.PolicyClauseKindSetting,
	})
}

// selectGroups 取判定要用的政策組；指定組時先確認它存在（否則呼叫端會拿到
// 一份「每個鍵都未對照」的結果，而那與「組打錯字」無從分辨）。
func (s *ComplianceService) selectGroups(groupFilter string) ([]model.PolicyGroup, error) {
	if groupFilter != "" {
		g, err := s.groups.GetGroup(groupFilter)
		if err != nil {
			return nil, err
		}
		return []model.PolicyGroup{*g}, nil
	}
	return s.groups.ListGroups()
}

// policyStateFromViews 由一份政策視圖攤出現值與最後變更。
//
// 兩者出自同一次讀取：判定用的值與「誰在什麼時候把它改成這樣」若分兩次讀，
// 會跨在同一次寫入的兩側，畫面上就會出現一個值配另一次變更的時戳。
func policyStateFromViews(views []PolicyView) (map[string]string, map[string]PolicyKeyChange) {
	values := make(map[string]string, len(views))
	changes := make(map[string]PolicyKeyChange, len(views))
	for _, v := range views {
		values[v.Key] = v.Value
		if v.UpdatedAt == nil && v.UpdatedBy == "" {
			continue
		}
		changes[v.Key] = PolicyKeyChange{UpdatedBy: v.UpdatedBy, UpdatedAt: v.UpdatedAt}
	}
	return values, changes
}

// applyDraftValues 以草稿覆蓋現值，回新的一份（不就地改動輸入）。
//
// 未定義的鍵略過（表單可能夾帶非政策欄位）；草稿值不合法時原樣採用，
// 由判定據實回報偏離——在管理者還沒打完字的中途回錯誤，畫面只會空掉。
func applyDraftValues(values, draft map[string]string) map[string]string {
	out := make(map[string]string, len(values))
	for k, v := range values {
		out[k] = v
	}
	for key, raw := range draft {
		def := findDef(key)
		if def == nil {
			continue
		}
		if normalized, err := normalizePolicyValue(def, raw); err == nil {
			out[key] = normalized
			continue
		}
		out[key] = raw
	}
	return out
}

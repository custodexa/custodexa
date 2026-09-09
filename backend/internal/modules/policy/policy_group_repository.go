package policy

import (
	"errors"
	"fmt"
	"time"

	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

// 政策組的資料存取。
//
// **拒寫判定放在這一層而不是只放在 API 層**：內建列的可寫範圍是資料的不變式
// （內容隨產品版本發布，機構只決定生效與備註），而不是某一支端點的授權規則。
// 放在 API 層的話，任何新增的寫入路徑都要各自記得再擋一次；漏擋的症狀是機構的
// 編輯在下一次啟動被種子悄悄蓋掉，中間沒有任何訊號。

// 政策組寫入被拒的錯誤碼。
//
// 沿既有錯誤碼的命名慣例（值域類以 VALIDATION_ 前綴、狀態類以資源名開頭），
// 使 API 層可 1:1 對應到出口碼而不必再發明一套。
const (
	// ErrCodePolicyGroupBuiltinReadOnly 內建組的內容不接受管理面寫入
	ErrCodePolicyGroupBuiltinReadOnly = "POLICY_GROUP_BUILTIN_READONLY"
	// ErrCodePolicyGroupNotFound 指定的政策組不存在
	ErrCodePolicyGroupNotFound = "POLICY_GROUP_NOT_FOUND"
	// ErrCodePolicyGroupDuplicateCode 組代號已被使用
	ErrCodePolicyGroupDuplicateCode = "POLICY_GROUP_DUPLICATE_CODE"
	// ErrCodePolicyGroupCode 組代號不合法（空值或超長）
	ErrCodePolicyGroupCode = "VALIDATION_POLICY_GROUP_CODE"
	// ErrCodePolicyGroupClauseNo 條號不合法（空值或超長）
	ErrCodePolicyGroupClauseNo = "VALIDATION_POLICY_GROUP_CLAUSE_NO"
	// ErrCodePolicyGroupClauseKind 條文型別與其控制數不相容
	ErrCodePolicyGroupClauseKind = "VALIDATION_POLICY_GROUP_CLAUSE_KIND"
	// ErrCodePolicyGroupUnknownKey 控制指向未定義的設定鍵
	ErrCodePolicyGroupUnknownKey = "VALIDATION_POLICY_GROUP_UNKNOWN_KEY"
	// ErrCodePolicyGroupKeyType 該型別的設定鍵不可作為設定要求的對象
	ErrCodePolicyGroupKeyType = "VALIDATION_POLICY_GROUP_KEY_TYPE"
	// ErrCodePolicyGroupComparator 比較方式與設定鍵的型別不符
	ErrCodePolicyGroupComparator = "VALIDATION_POLICY_GROUP_COMPARATOR"
	// ErrCodePolicyGroupExpectedValue 要求值未通過該設定鍵既有的值域驗證
	ErrCodePolicyGroupExpectedValue = "VALIDATION_POLICY_GROUP_EXPECTED_VALUE"
	// ErrCodePolicyGroupDuplicateKey 同一組內同一個設定鍵已有另一條要求
	ErrCodePolicyGroupDuplicateKey = "VALIDATION_POLICY_GROUP_DUPLICATE_KEY"
)

// 代號與條號的長度上限，與資料庫欄寬一致。超長在資料庫層是截斷或報錯，
// 兩者都不會告訴管理者哪裡不對，故在寫入前先擋。
const (
	policyGroupCodeMaxLen = 64
	policyClauseNoMaxLen  = 64
)

// 本檔反覆用到的查詢條件。條件字串逐字不變，抽成常數只是讓欄名有單一改點：
// 散落的字面值改漏一處時，症狀是某一條路徑靜默地查到別的列。
const (
	condGroupByCode   = "code = ?"
	condClauseByGroup = "group_code = ?"
	condClauseByKey   = "group_code = ? AND clause_no = ?"
)

// ErrPolicyGroup 政策組寫入被拒的 sentinel（errors.Is 的比對錨點）
var ErrPolicyGroup = errors.New("政策組寫入被拒")

// PolicyGroupError 帶碼的政策組錯誤。
//
// Code 是閉集（見上方常數），供上層對應到使用者看得懂的訊息；Detail 是人話
// 補充，只供伺服器端日誌與開發期診斷。
type PolicyGroupError struct {
	Code   string
	Detail string
}

func (e *PolicyGroupError) Error() string {
	return fmt.Sprintf("%s: %s（%s）", ErrPolicyGroup.Error(), e.Code, e.Detail)
}

// Unwrap 讓 errors.Is 可比對底層 sentinel
func (e *PolicyGroupError) Unwrap() error { return ErrPolicyGroup }

func groupErr(code, format string, args ...interface{}) *PolicyGroupError {
	return &PolicyGroupError{Code: code, Detail: fmt.Sprintf(format, args...)}
}

// PolicyGroupRepository 政策組四張表的讀寫。
type PolicyGroupRepository struct {
	db *gorm.DB
}

// NewPolicyGroupRepository 建立政策組資料存取。
func NewPolicyGroupRepository(db *gorm.DB) *PolicyGroupRepository {
	return &PolicyGroupRepository{db: db}
}

// ---- 讀 ----

// ListGroups 取全部政策組（依代號排序，使呈現順序穩定）。
func (r *PolicyGroupRepository) ListGroups() ([]model.PolicyGroup, error) {
	var out []model.PolicyGroup
	if err := r.db.Order("code").Find(&out).Error; err != nil {
		return nil, fmt.Errorf("讀取政策組失敗: %w", err)
	}
	return out, nil
}

// GetGroup 取單一政策組；不存在回 ErrCodePolicyGroupNotFound。
func (r *PolicyGroupRepository) GetGroup(code string) (*model.PolicyGroup, error) {
	var g model.PolicyGroup
	if err := r.db.Where(condGroupByCode, code).First(&g).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, groupErr(ErrCodePolicyGroupNotFound, "組代號 %s", code)
		}
		return nil, fmt.Errorf("讀取政策組 %s 失敗: %w", code, err)
	}
	return &g, nil
}

// ListClauses 取某組的條文（含已標記移除者；篩選交給呼叫端，因為管理頁要看得到
// 已移除的條文，而判定不計入它們）。
func (r *PolicyGroupRepository) ListClauses(groupCode string) ([]model.PolicyClause, error) {
	var out []model.PolicyClause
	q := r.db.Order("group_code, clause_no")
	if groupCode != "" {
		q = q.Where(condClauseByGroup, groupCode)
	}
	if err := q.Find(&out).Error; err != nil {
		return nil, fmt.Errorf("讀取條文失敗: %w", err)
	}
	return out, nil
}

// ListControls 取某組的全部控制；groupCode 空字串＝全部組。
func (r *PolicyGroupRepository) ListControls(groupCode string) ([]model.PolicyClauseControl, error) {
	var out []model.PolicyClauseControl
	q := r.db.Order("group_code, clause_no, policy_key")
	if groupCode != "" {
		q = q.Where(condClauseByGroup, groupCode)
	}
	if err := q.Find(&out).Error; err != nil {
		return nil, fmt.Errorf("讀取條文要求失敗: %w", err)
	}
	return out, nil
}

// ListAnnotations 取某組的備註與確認記錄；groupCode 空字串＝全部組。
func (r *PolicyGroupRepository) ListAnnotations(groupCode string) ([]model.PolicyClauseAnnotation, error) {
	var out []model.PolicyClauseAnnotation
	q := r.db.Order("group_code, clause_no")
	if groupCode != "" {
		q = q.Where(condClauseByGroup, groupCode)
	}
	if err := q.Find(&out).Error; err != nil {
		return nil, fmt.Errorf("讀取機構備註失敗: %w", err)
	}
	return out, nil
}

// ---- 組層寫入 ----

// CreateCustomGroup 建立機構自建組。
func (r *PolicyGroupRepository) CreateCustomGroup(code, name, locale string) error {
	if code == "" || len(code) > policyGroupCodeMaxLen {
		return groupErr(ErrCodePolicyGroupCode, "組代號長度須介於 1 與 %d 之間", policyGroupCodeMaxLen)
	}
	if name == "" {
		return groupErr(ErrCodePolicyGroupCode, "組名稱不得為空")
	}
	var n int64
	if err := r.db.Model(&model.PolicyGroup{}).Where(condGroupByCode, code).Count(&n).Error; err != nil {
		return fmt.Errorf("檢查組代號失敗: %w", err)
	}
	if n > 0 {
		return groupErr(ErrCodePolicyGroupDuplicateCode, "組代號 %s 已存在", code)
	}
	g := model.PolicyGroup{
		Code: code, Name: name, Locale: locale,
		Source: model.PolicyGroupSourceCustom, Enabled: true,
	}
	if err := r.db.Create(&g).Error; err != nil {
		return fmt.Errorf("建立政策組失敗: %w", err)
	}
	return nil
}

// RenameCustomGroup 更名自建組。內建組的名稱隨產品版本發布，故拒寫。
func (r *PolicyGroupRepository) RenameCustomGroup(code, name string) error {
	if err := r.requireCustomGroup(code); err != nil {
		return err
	}
	if name == "" {
		return groupErr(ErrCodePolicyGroupCode, "組名稱不得為空")
	}
	if err := r.db.Model(&model.PolicyGroup{}).Where(condGroupByCode, code).
		Update("name", name).Error; err != nil {
		return fmt.Errorf("更名政策組失敗: %w", err)
	}
	return nil
}

// SetGroupEnabled 切換生效開關。
//
// **內建組也放行**：生效與否由機構決定，產品升級不得改動它。
func (r *PolicyGroupRepository) SetGroupEnabled(code string, enabled bool) error {
	if _, err := r.GetGroup(code); err != nil {
		return err
	}
	if err := r.db.Model(&model.PolicyGroup{}).Where(condGroupByCode, code).
		Update("enabled", enabled).Error; err != nil {
		return fmt.Errorf("更新政策組生效狀態失敗: %w", err)
	}
	return nil
}

// DeleteCustomGroup 刪除自建組，連帶清除其條文、控制與備註。
//
// 四張表之間沒有資料庫層的外鍵串聯（見 migration 檔頭），連帶清除只由這裡的
// 單一交易保證。漏刪的殘留列會在下一次建立同代號的組時，以「莫名冒出來的舊條文」
// 現形。
func (r *PolicyGroupRepository) DeleteCustomGroup(code string) error {
	if err := r.requireCustomGroup(code); err != nil {
		return err
	}
	return r.db.Transaction(func(tx *gorm.DB) error {
		for _, m := range []interface{}{
			&model.PolicyClauseControl{}, &model.PolicyClauseAnnotation{}, &model.PolicyClause{},
		} {
			if err := tx.Where(condClauseByGroup, code).Delete(m).Error; err != nil {
				return fmt.Errorf("清除政策組 %s 的附屬資料失敗: %w", code, err)
			}
		}
		if err := tx.Where(condGroupByCode, code).Delete(&model.PolicyGroup{}).Error; err != nil {
			return fmt.Errorf("刪除政策組 %s 失敗: %w", code, err)
		}
		return nil
	})
}

// ---- 條文與控制 ----

// UpsertCustomClause 新增或覆寫自建組的一條條文與其全部控制。
//
// 控制是**整批取代**而非逐筆合併：一條條文的要求集合是一個整體，逐筆合併會讓
// 「刪掉其中一個鍵」這個動作沒有表達方式。
//
// **回傳實際寫入的條文與要求**：呼叫端要據以留下「改成什麼」的審計，而寫入端
// 對輸入做過正規化（未定值的要求值被清空等）。回傳的若不是落庫的那一份，
// 審計記的就是送進來的意圖而非結果；提交後再讀一次則讓那次讀取的失敗可以
// 吃掉整列審計。
func (r *PolicyGroupRepository) UpsertCustomClause(clause model.PolicyClause,
	controls []model.PolicyClauseControl) (model.PolicyClause, []model.PolicyClauseControl, error) {
	if err := r.requireCustomGroup(clause.GroupCode); err != nil {
		return model.PolicyClause{}, nil, err
	}
	if clause.ClauseNo == "" || len(clause.ClauseNo) > policyClauseNoMaxLen {
		return model.PolicyClause{}, nil, groupErr(ErrCodePolicyGroupClauseNo,
			"條號長度須介於 1 與 %d 之間", policyClauseNoMaxLen)
	}
	normalized, err := normalizeClauseControls(clause, controls)
	if err != nil {
		return model.PolicyClause{}, nil, err
	}
	if err := r.assertControlKeysFree(clause.GroupCode, clause.ClauseNo, normalized); err != nil {
		return model.PolicyClause{}, nil, err
	}
	row := model.PolicyClause{
		GroupCode: clause.GroupCode, ClauseNo: clause.ClauseNo,
		Title: clause.Title, Summary: clause.Summary, Kind: clause.Kind,
	}
	err = r.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where(condClauseByKey,
			clause.GroupCode, clause.ClauseNo).Delete(&model.PolicyClauseControl{}).Error; err != nil {
			return fmt.Errorf("清除舊要求失敗: %w", err)
		}
		if err := upsertClauseRow(tx, row); err != nil {
			return err
		}
		if len(normalized) == 0 {
			return nil
		}
		if err := tx.Create(&normalized).Error; err != nil {
			return fmt.Errorf("寫入條文要求失敗: %w", err)
		}
		return nil
	})
	if err != nil {
		return model.PolicyClause{}, nil, err
	}
	return row, normalized, nil
}

// DeleteCustomClause 刪除自建組的一條條文與其控制。
//
// **備註不刪**：那是機構寫的資料，與條文的生滅無關（同一條號日後再出現時，
// 備註仍掛在原處）。
func (r *PolicyGroupRepository) DeleteCustomClause(groupCode, clauseNo string) error {
	if err := r.requireCustomGroup(groupCode); err != nil {
		return err
	}
	return r.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where(condClauseByKey, groupCode, clauseNo).
			Delete(&model.PolicyClauseControl{}).Error; err != nil {
			return fmt.Errorf("刪除條文要求失敗: %w", err)
		}
		if err := tx.Where(condClauseByKey, groupCode, clauseNo).
			Delete(&model.PolicyClause{}).Error; err != nil {
			return fmt.Errorf("刪除條文失敗: %w", err)
		}
		return nil
	})
}

// ---- 機構備註與人工確認（任何來源的組都可寫）----

// UpsertAnnotation 寫入或更新機構備註。備註不影響判定。
func (r *PolicyGroupRepository) UpsertAnnotation(groupCode, clauseNo, note string) error {
	if _, err := r.GetGroup(groupCode); err != nil {
		return err
	}
	return r.upsertAnnotation(groupCode, clauseNo, map[string]interface{}{"note": note},
		model.PolicyClauseAnnotation{GroupCode: groupCode, ClauseNo: clauseNo, Note: note})
}

// ConfirmClause 記錄一次人工確認。再次確認覆蓋前次（歷史留在操作日誌）。
func (r *PolicyGroupRepository) ConfirmClause(groupCode, clauseNo, confirmedBy,
	confirmationNote string, at time.Time) error {
	if _, err := r.GetGroup(groupCode); err != nil {
		return err
	}
	return r.upsertAnnotation(groupCode, clauseNo, map[string]interface{}{
		"confirmed_by":      confirmedBy,
		"confirmed_at":      at,
		"confirmation_note": confirmationNote,
	}, model.PolicyClauseAnnotation{
		GroupCode: groupCode, ClauseNo: clauseNo,
		ConfirmedBy: confirmedBy, ConfirmedAt: &at, ConfirmationNote: confirmationNote,
	})
}

// upsertAnnotation 備註列的「有就更指定欄、沒有就建列」。
//
// 逐欄更新而非整列覆寫：備註與確認記錄住在同一列但由兩個動作分別寫入，
// 整列覆寫會讓其中一個動作把另一個的內容清成空值。
func (r *PolicyGroupRepository) upsertAnnotation(groupCode, clauseNo string,
	updates map[string]interface{}, fresh model.PolicyClauseAnnotation) error {
	return r.db.Transaction(func(tx *gorm.DB) error {
		res := tx.Model(&model.PolicyClauseAnnotation{}).
			Where(condClauseByKey, groupCode, clauseNo).
			Updates(updates)
		if res.Error != nil {
			return fmt.Errorf("更新機構備註失敗: %w", res.Error)
		}
		if res.RowsAffected > 0 {
			return nil
		}
		if err := tx.Create(&fresh).Error; err != nil {
			return fmt.Errorf("建立機構備註失敗: %w", err)
		}
		return nil
	})
}

// ---- 內部 ----

// requireCustomGroup 該組存在且為機構自建。
func (r *PolicyGroupRepository) requireCustomGroup(code string) error {
	g, err := r.GetGroup(code)
	if err != nil {
		return err
	}
	if g.Source == model.PolicyGroupSourceBuiltin {
		return groupErr(ErrCodePolicyGroupBuiltinReadOnly,
			"組 %s 的內容隨產品版本發布，只有生效開關與機構備註可改", code)
	}
	return nil
}

// assertControlKeysFree 同一組內同一個設定鍵不得有第二條要求。
//
// 資料庫的唯一索引已經擋得住，但那時回的是驅動層的約束訊息，管理者看不出
// 「那個鍵已經被哪一條條文佔用」。先查一次是為了回得出這件事。
func (r *PolicyGroupRepository) assertControlKeysFree(groupCode, clauseNo string,
	controls []model.PolicyClauseControl) error {
	if len(controls) == 0 {
		return nil
	}
	keys := make([]string, 0, len(controls))
	for _, c := range controls {
		keys = append(keys, c.PolicyKey)
	}
	var taken []model.PolicyClauseControl
	if err := r.db.Where("group_code = ? AND clause_no <> ? AND policy_key IN ?",
		groupCode, clauseNo, keys).Find(&taken).Error; err != nil {
		return fmt.Errorf("檢查重複設定鍵失敗: %w", err)
	}
	if len(taken) > 0 {
		return groupErr(ErrCodePolicyGroupDuplicateKey,
			"設定鍵 %s 已由本組的條文 %s 要求", taken[0].PolicyKey, taken[0].ClauseNo)
	}
	return nil
}

// upsertClauseRow 條文列的「有就更、沒有就建」（複合主鍵，不能靠 Save 判斷）。
func upsertClauseRow(tx *gorm.DB, row model.PolicyClause) error {
	res := tx.Model(&model.PolicyClause{}).
		Where(condClauseByKey, row.GroupCode, row.ClauseNo).
		Updates(map[string]interface{}{
			"title": row.Title, "summary": row.Summary, "kind": row.Kind,
			"removed_in_version": row.RemovedInVersion,
		})
	if res.Error != nil {
		return fmt.Errorf("更新條文失敗: %w", res.Error)
	}
	if res.RowsAffected > 0 {
		return nil
	}
	if err := tx.Create(&row).Error; err != nil {
		return fmt.Errorf("建立條文失敗: %w", err)
	}
	return nil
}

// normalizeClauseControls 依條文型別與設定鍵型別驗證控制，回可直接寫入的列。
func normalizeClauseControls(clause model.PolicyClause,
	controls []model.PolicyClauseControl) ([]model.PolicyClauseControl, error) {
	switch clause.Kind {
	case model.PolicyClauseKindSelfAttested:
		if len(controls) > 0 {
			return nil, groupErr(ErrCodePolicyGroupClauseKind,
				"由機構自行確認的條文不得帶設定要求（系統只呈現不判定）")
		}
		return nil, nil
	case model.PolicyClauseKindBuiltinProtection:
		if len(controls) > 0 {
			return nil, groupErr(ErrCodePolicyGroupClauseKind,
				"系統內建保護的條文不得帶設定要求（掛得上設定鍵就表示它是可調的）")
		}
		return nil, nil
	case model.PolicyClauseKindSetting:
		if len(controls) == 0 {
			return nil, groupErr(ErrCodePolicyGroupClauseKind,
				"設定要求型條文至少要指向一個設定鍵")
		}
	default:
		return nil, groupErr(ErrCodePolicyGroupClauseKind, "未知的條文型別 %q", clause.Kind)
	}

	seen := map[string]bool{}
	out := make([]model.PolicyClauseControl, 0, len(controls))
	for _, c := range controls {
		def := findDef(c.PolicyKey)
		if def == nil {
			return nil, groupErr(ErrCodePolicyGroupUnknownKey, "設定鍵 %s 未定義", c.PolicyKey)
		}
		if err := assertComparatorFitsType(def, c.Comparator); err != nil {
			return nil, err
		}
		if err := assertExpectedValueFitsComparator(def, c); err != nil {
			return nil, err
		}
		if seen[c.PolicyKey] {
			return nil, groupErr(ErrCodePolicyGroupDuplicateKey,
				"同一條條文對設定鍵 %s 給了兩個要求", c.PolicyKey)
		}
		seen[c.PolicyKey] = true
		expected := c.ExpectedValue
		if c.Comparator == model.PolicyControlComparatorReview {
			expected = ""
		}
		out = append(out, model.PolicyClauseControl{
			GroupCode: clause.GroupCode, ClauseNo: clause.ClauseNo,
			PolicyKey: c.PolicyKey, Comparator: c.Comparator,
			ExpectedValue: expected, ReferenceOnly: c.ReferenceOnly,
		})
	}
	return out, nil
}

// assertExpectedValueFitsComparator 要求值與比較方式的相容性。
//
// 未定值的控制**必須**留空要求值：留著一個值卻宣告未定值，會讓那個值在日後
// 某條路徑上被當成要求讀出來，而畫面上從來沒有顯示過它。其餘比較方式反過來
// 必須有值——空值在判定時是「不可比較」，那與「條文沒有給值」是兩件事，
// 而使用者只會看到同一個結果。
func assertExpectedValueFitsComparator(def *PolicyDef, control model.PolicyClauseControl) error {
	if control.Comparator == model.PolicyControlComparatorReview {
		if control.ExpectedValue != "" {
			return groupErr(ErrCodePolicyGroupExpectedValue,
				"設定鍵 %s 標為未定值，不得同時帶要求值 %q", control.PolicyKey, control.ExpectedValue)
		}
		return nil
	}
	if control.ExpectedValue == "" {
		return groupErr(ErrCodePolicyGroupExpectedValue,
			"設定鍵 %s 的要求值不得為空（條文未定值時請改用未定值的比較方式）", control.PolicyKey)
	}
	if err := validatePolicyValue(def, control.ExpectedValue); err != nil {
		return groupErr(ErrCodePolicyGroupExpectedValue,
			"設定鍵 %s 的要求值 %q 不在合法值域: %v", control.PolicyKey, control.ExpectedValue, err)
	}
	return nil
}

// assertComparatorFitsType 比較方式與設定鍵型別的相容性。
//
// 整數型只有 min／max，開關與枚舉只有 equals。文字型鍵不能作為設定要求的對象
// ——它承載的是自由文字（如登入告示），沒有任何一種比較方式對它是有意義的。
func assertComparatorFitsType(def *PolicyDef, comparator string) error {
	// 未定值適用於任何可比較型別的鍵：它表達的是「條文涉及這個鍵但沒有給值」，
	// 與鍵的型別無關
	if comparator == model.PolicyControlComparatorReview {
		switch def.Type {
		case PolicyTypeInt, PolicyTypeBool, PolicyTypeEnum:
			return nil
		}
		return groupErr(ErrCodePolicyGroupKeyType,
			"型別為 %s 的設定鍵 %s 不能作為設定要求的對象", def.Type, def.Key)
	}
	switch def.Type {
	case PolicyTypeInt:
		if comparator != model.PolicyControlComparatorMin && comparator != model.PolicyControlComparatorMax {
			return groupErr(ErrCodePolicyGroupComparator,
				"整數型設定鍵 %s 的比較方式只能是 %s 或 %s，收到 %q",
				def.Key, model.PolicyControlComparatorMin, model.PolicyControlComparatorMax, comparator)
		}
		return nil
	case PolicyTypeBool, PolicyTypeEnum:
		if comparator != model.PolicyControlComparatorEquals {
			return groupErr(ErrCodePolicyGroupComparator,
				"設定鍵 %s 的取值之間沒有強弱序，要求只能是明確值（%s），收到 %q",
				def.Key, model.PolicyControlComparatorEquals, comparator)
		}
		return nil
	default:
		return groupErr(ErrCodePolicyGroupKeyType,
			"型別為 %s 的設定鍵 %s 不能作為設定要求的對象", def.Type, def.Key)
	}
}

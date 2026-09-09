package policy

import (
	"fmt"

	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

// 內建政策組的種子：內容住在程式碼，資料庫裡的內建列只是它的投影。
//
// **為什麼不把內建內容整個放進資料庫**：內建內容要隨產品版本更新，而且要能被
// 測試釘住；程式碼是唯一有版本的地方。放進資料庫之後，「這一版的內建組長什麼樣」
// 就沒有任何一份可讀、可 diff、可測試的事實源。
//
// 種子每次啟動以（組代號，條號）upsert，重複啟動冪等。**升級時只標記不刪除**：
// 這一版的種子裡沒有的既有內建條文，標上內容版本表示「已於該版移除」，機構掛在
// 那條上的備註與人工確認一個字都不動。
//
// **種子自帶內容**：條號、標題、依據關鍵語、條文型別與每一筆要求值都寫在種子檔
// 裡。設定鍵的定義只被用來校驗（鍵存在、型別與比較方式相容、值在合法值域），
// 不再是要求值的來源——同一份要求由兩個地方各說一次時，兩邊漂開了沒有人會發現。

// policyGroupSeed 一個內建組的種子內容。
type policyGroupSeed struct {
	// Code 組代號，同時是條文、控制與備註的掛靠鍵
	Code string
	// Name 顯示名稱（規範文本的正式名稱）
	Name string
	// Version 規範文本自身的版本標示，同時是條文被移除時標記的版本
	Version string
	Clauses []policyClauseSeed
}

// policyClauseSeed 一條內建條文。
type policyClauseSeed struct {
	ClauseNo string
	Title    string
	// Summary 條文依據的關鍵語（不轉述、不擴張，只截取條文自己說的話）
	Summary string
	// Kind 空字串視為設定要求型
	Kind string
	// Controls 本條文對設定鍵的要求；設定要求型至少一筆，其餘型別必須為空
	Controls []policyControlSeed
}

// policyControlSeed 條文對單一設定鍵的一筆要求。
type policyControlSeed struct {
	Key           string
	Comparator    string
	ExpectedValue string
	ReferenceOnly bool
}

// ---- 要求的建構子：讓種子表逐列讀得出「這一格是什麼要求」 ----

// atLeast 現值須不小於這個數（整數型）。
func atLeast(key, value string) policyControlSeed {
	return policyControlSeed{Key: key, Comparator: model.PolicyControlComparatorMin, ExpectedValue: value}
}

// atMost 現值須不大於這個數（整數型）。
func atMost(key, value string) policyControlSeed {
	return policyControlSeed{Key: key, Comparator: model.PolicyControlComparatorMax, ExpectedValue: value}
}

// mustBe 現值須等於這個值（開關與枚舉型）。
func mustBe(key, value string) policyControlSeed {
	return policyControlSeed{Key: key, Comparator: model.PolicyControlComparatorEquals, ExpectedValue: value}
}

// asReference 把一筆要求標成參考值：條文只給建議或原則，這個值沒有明文出處。
//
// 判定結果是待機構人工確認，不是符合或偏離——把建議印成硬要求，會讓一個
// 「宜」字在合規報告上長成一條必須達到的門檻。
func asReference(control policyControlSeed) policyControlSeed {
	control.ReferenceOnly = true
	return control
}

// unspecified 條文涉及這個鍵但沒有給值，附目前值待稽核判讀。
func unspecified(key string) policyControlSeed {
	return policyControlSeed{Key: key, Comparator: model.PolicyControlComparatorReview}
}

// SeedBuiltinPolicyGroups 於啟動時把內建組 upsert 進資料庫。
//
// 冪等：重複執行不改變結果。**不動生效開關**——那由機構決定，升級不得改它。
func SeedBuiltinPolicyGroups(db *gorm.DB) error {
	return applyPolicyGroupSeeds(db, builtinPolicyGroupSeeds())
}

// builtinPolicyGroupSeeds 本版隨產品發布的全部內建組。
func builtinPolicyGroupSeeds() []policyGroupSeed {
	return []policyGroupSeed{pciPolicyGroupSeed(), ePaymentPolicyGroupSeed()}
}

// seedControl 由種子推導出的一筆控制（尚未落庫）。
type seedControl struct {
	ClauseNo      string
	PolicyKey     string
	Comparator    string
	ExpectedValue string
	ReferenceOnly bool
}

// buildSeedControls 把種子的要求展開成控制列，並就地校驗。
//
// 校驗失敗一律回錯誤而不是靜默略過：一筆對不上設定鍵定義的要求，症狀是
// 「合規頁少了一條或多了一條，沒有人知道為什麼」。
//
// 校驗四件事：鍵存在、比較方式與鍵的型別和方向相符、要求值在合法值域、
// 同一組內同一個鍵只掛一次。最後一件由資料庫的唯一索引兜底，但在這裡擋下
// 才說得出是哪兩條條文搶同一個鍵。
func buildSeedControls(seed policyGroupSeed) ([]seedControl, error) {
	var out []seedControl
	seen := map[string]string{}
	for _, clause := range seed.Clauses {
		kind := clause.Kind
		if kind == "" {
			kind = model.PolicyClauseKindSetting
		}
		if kind != model.PolicyClauseKindSetting {
			if len(clause.Controls) > 0 {
				return nil, fmt.Errorf("內建組 %s 的條文 %s 型別為 %s，不得帶設定要求",
					seed.Code, clause.ClauseNo, kind)
			}
			continue
		}
		if len(clause.Controls) == 0 {
			return nil, fmt.Errorf("內建組 %s 的設定要求型條文 %s 沒有指向任何設定鍵",
				seed.Code, clause.ClauseNo)
		}
		for _, c := range clause.Controls {
			control, err := normalizeSeedControl(seed, clause, c)
			if err != nil {
				return nil, err
			}
			if prev, dup := seen[c.Key]; dup {
				return nil, fmt.Errorf("內建組 %s 的條文 %s 與 %s 對設定鍵 %s 各給了一個要求",
					seed.Code, prev, clause.ClauseNo, c.Key)
			}
			seen[c.Key] = clause.ClauseNo
			out = append(out, control)
		}
	}
	return out, nil
}

// normalizeSeedControl 單筆要求的校驗與正規化。
//
// 校驗走的是資料存取層那兩支同款檢查：內建組與機構自建組對「什麼樣的要求寫得
// 出來」必須是同一套規則，各寫一份的話會出現管理介面拒收、種子卻寫得進去的形態。
func normalizeSeedControl(seed policyGroupSeed, clause policyClauseSeed,
	c policyControlSeed) (seedControl, error) {

	def := findDef(c.Key)
	if def == nil {
		return seedControl{}, fmt.Errorf("內建組 %s 的條文 %s 指向未定義的設定鍵 %s",
			seed.Code, clause.ClauseNo, c.Key)
	}
	row := model.PolicyClauseControl{
		PolicyKey: c.Key, Comparator: c.Comparator,
		ExpectedValue: c.ExpectedValue, ReferenceOnly: c.ReferenceOnly,
	}
	if err := assertComparatorFitsType(def, c.Comparator); err != nil {
		return seedControl{}, fmt.Errorf("內建組 %s 的條文 %s: %w", seed.Code, clause.ClauseNo, err)
	}
	if err := assertExpectedValueFitsComparator(def, row); err != nil {
		return seedControl{}, fmt.Errorf("內建組 %s 的條文 %s: %w", seed.Code, clause.ClauseNo, err)
	}
	if c.Comparator != model.PolicyControlComparatorReview {
		// 方向是鍵的語義而不是條文的選擇：對「至少」型的鍵寫成「至多」，
		// 判定會整個反過來而畫面上看不出異狀
		want, err := comparatorForDef(def)
		if err != nil {
			return seedControl{}, fmt.Errorf("內建組 %s 的條文 %s: %w", seed.Code, clause.ClauseNo, err)
		}
		if want != c.Comparator {
			return seedControl{}, fmt.Errorf("內建組 %s 的條文 %s 對設定鍵 %s 用了比較方式 %s，該鍵的方向是 %s",
				seed.Code, clause.ClauseNo, c.Key, c.Comparator, want)
		}
	}
	value := c.ExpectedValue
	if c.Comparator == model.PolicyControlComparatorReview {
		value = ""
	}
	return seedControl{
		ClauseNo: clause.ClauseNo, PolicyKey: c.Key,
		Comparator: c.Comparator, ExpectedValue: value, ReferenceOnly: c.ReferenceOnly,
	}, nil
}

// comparatorForDef 依設定鍵的型別與比較方向決定比較方式。
//
// 整數型的方向就是比較方式本身；開關與枚舉的取值之間沒有強弱序，一律明確值。
func comparatorForDef(def *PolicyDef) (string, error) {
	switch def.Type {
	case PolicyTypeInt:
		switch def.Direction {
		case DirectionMin:
			return model.PolicyControlComparatorMin, nil
		case DirectionMax:
			return model.PolicyControlComparatorMax, nil
		default:
			return "", fmt.Errorf("整數型設定鍵 %s 沒有比較方向，推不出比較方式", def.Key)
		}
	case PolicyTypeBool, PolicyTypeEnum:
		return model.PolicyControlComparatorEquals, nil
	default:
		return "", fmt.Errorf("型別為 %s 的設定鍵 %s 不能作為設定要求的對象", def.Type, def.Key)
	}
}

// applyPolicyGroupSeeds 逐組 upsert。一組一個交易：某一組的內容有問題時，
// 另一組不該跟著回不去。
func applyPolicyGroupSeeds(db *gorm.DB, seeds []policyGroupSeed) error {
	for _, seed := range seeds {
		controls, err := buildSeedControls(seed)
		if err != nil {
			return err
		}
		if err := db.Transaction(func(tx *gorm.DB) error {
			return applyOnePolicyGroupSeed(tx, seed, controls)
		}); err != nil {
			return fmt.Errorf("寫入內建政策組 %s 失敗: %w", seed.Code, err)
		}
	}
	return nil
}

func applyOnePolicyGroupSeed(tx *gorm.DB, seed policyGroupSeed, controls []seedControl) error {
	if err := upsertBuiltinGroupRow(tx, seed); err != nil {
		return err
	}
	seedClauseNos := make(map[string]bool, len(seed.Clauses))
	for _, clause := range seed.Clauses {
		kind := clause.Kind
		if kind == "" {
			kind = model.PolicyClauseKindSetting
		}
		if err := upsertClauseRow(tx, model.PolicyClause{
			GroupCode: seed.Code, ClauseNo: clause.ClauseNo,
			Title: clause.Title, Summary: clause.Summary, Kind: kind,
		}); err != nil {
			return err
		}
		seedClauseNos[clause.ClauseNo] = true
	}
	if err := markClausesRemoved(tx, seed, seedClauseNos); err != nil {
		return err
	}
	return syncBuiltinControls(tx, seed.Code, controls)
}

// upsertBuiltinGroupRow 建組或更新其名稱與版本。**不碰生效開關**。
func upsertBuiltinGroupRow(tx *gorm.DB, seed policyGroupSeed) error {
	res := tx.Model(&model.PolicyGroup{}).Where("code = ?", seed.Code).
		Updates(map[string]interface{}{
			"name":    seed.Name,
			"version": seed.Version,
			"source":  model.PolicyGroupSourceBuiltin,
		})
	if res.Error != nil {
		return fmt.Errorf("更新政策組列失敗: %w", res.Error)
	}
	if res.RowsAffected > 0 {
		return nil
	}
	row := model.PolicyGroup{
		Code: seed.Code, Name: seed.Name, Version: seed.Version,
		Source: model.PolicyGroupSourceBuiltin, Enabled: true,
	}
	if err := tx.Create(&row).Error; err != nil {
		return fmt.Errorf("建立政策組列失敗: %w", err)
	}
	return nil
}

// markClausesRemoved 這一版的種子裡沒有的既有內建條文，標上內容版本。
//
// 標記而不刪除，因為機構的備註與人工確認掛在（組代號，條號）上；同一條號在
// 後續版本重新出現時，upsert 會把標記清回空字串，備註自然重新生效。
func markClausesRemoved(tx *gorm.DB, seed policyGroupSeed, present map[string]bool) error {
	var existing []model.PolicyClause
	if err := tx.Where("group_code = ?", seed.Code).Find(&existing).Error; err != nil {
		return fmt.Errorf("讀取既有條文失敗: %w", err)
	}
	for _, clause := range existing {
		if present[clause.ClauseNo] || clause.RemovedInVersion != "" {
			continue
		}
		if err := tx.Model(&model.PolicyClause{}).
			Where("group_code = ? AND clause_no = ?", seed.Code, clause.ClauseNo).
			Update("removed_in_version", seed.Version).Error; err != nil {
			return fmt.Errorf("標記已移除條文失敗: %w", err)
		}
	}
	return nil
}

// syncBuiltinControls 以（組代號，設定鍵）為鍵 upsert，並清掉種子已不再要求的鍵。
//
// 逐鍵 upsert 而非整組刪光重建：後者每次啟動都會換一輪主鍵，讓「這筆要求是什麼
// 時候進來的」在資料庫層失去意義。
func syncBuiltinControls(tx *gorm.DB, groupCode string, controls []seedControl) error {
	keep := make(map[string]bool, len(controls))
	for _, c := range controls {
		keep[c.PolicyKey] = true
		res := tx.Model(&model.PolicyClauseControl{}).
			Where("group_code = ? AND policy_key = ?", groupCode, c.PolicyKey).
			Updates(map[string]interface{}{
				"clause_no":      c.ClauseNo,
				"comparator":     c.Comparator,
				"expected_value": c.ExpectedValue,
				"reference_only": c.ReferenceOnly,
			})
		if res.Error != nil {
			return fmt.Errorf("更新條文要求失敗: %w", res.Error)
		}
		if res.RowsAffected > 0 {
			continue
		}
		row := model.PolicyClauseControl{
			GroupCode: groupCode, ClauseNo: c.ClauseNo, PolicyKey: c.PolicyKey,
			Comparator: c.Comparator, ExpectedValue: c.ExpectedValue,
			ReferenceOnly: c.ReferenceOnly,
		}
		if err := tx.Create(&row).Error; err != nil {
			return fmt.Errorf("建立條文要求失敗: %w", err)
		}
	}
	var existing []model.PolicyClauseControl
	if err := tx.Where("group_code = ?", groupCode).Find(&existing).Error; err != nil {
		return fmt.Errorf("讀取既有條文要求失敗: %w", err)
	}
	for _, c := range existing {
		if keep[c.PolicyKey] {
			continue
		}
		if err := tx.Where("id = ?", c.ID).Delete(&model.PolicyClauseControl{}).Error; err != nil {
			return fmt.Errorf("清除已不再要求的設定鍵失敗: %w", err)
		}
	}
	return nil
}

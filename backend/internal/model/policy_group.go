package model

import "time"

// 政策組資料模型：四張表承載「安全設定與外部規範條文的對照」。
//
// 分成四張表而不是一張寬表，理由是三種資料的**生命週期不同**：
// 組與條文隨產品版本或管理者編輯而變、控制是條文對設定鍵的展開（一條對多鍵）、
// 備註與人工確認是機構寫入的資料且必須活得比條文久（升級移除條文時不得一併消失）。

// 政策組來源。
const (
	// PolicyGroupSourceBuiltin 內建組：內容隨產品版本發布，啟動時由種子 upsert。
	// 這類列的條文與控制不接受管理介面寫入，只有生效開關與備註由機構決定
	PolicyGroupSourceBuiltin = "builtin"
	// PolicyGroupSourceCustom 機構自建組：內容全部由管理者維護
	PolicyGroupSourceCustom = "custom"
)

// 條文型別。
const (
	// PolicyClauseKindSetting 設定要求：條文指向一到多個設定鍵並帶要求值，系統據以判定
	PolicyClauseKindSetting = "setting"
	// PolicyClauseKindSelfAttested 由機構自行確認：不指向任何設定鍵，系統只呈現不判定
	PolicyClauseKindSelfAttested = "self_attested"
	// PolicyClauseKindBuiltinProtection 系統內建保護：產品無條件提供，沒有可調的設定值。
	//
	// **與「由機構自行確認」是兩件事**：後者的責任在機構，前者的責任在產品本身。
	// 兩者都不產生鍵層判定，但把它們混為一談，會讓閱讀者以為機構還得為產品已經
	// 承擔的事再做一次確認。本型別不得掛設定要求——掛得上就表示它是可調的，
	// 那該寫成設定要求型
	PolicyClauseKindBuiltinProtection = "builtin_protection"
)

// 控制的比較方式。
//
// **開關與枚舉一律 equals**：這兩類的取值之間沒有強弱序（「允許剪貼簿送出」
// 的開與關哪個比較嚴，取決於條文要求哪一個），以序位比較會讓要求值被靜默
// 解讀成「至少這麼嚴」而判錯。
const (
	// PolicyControlComparatorMin 現值須不小於要求值（僅整數型鍵）
	PolicyControlComparatorMin = "min"
	// PolicyControlComparatorMax 現值須不大於要求值（僅整數型鍵）
	PolicyControlComparatorMax = "max"
	// PolicyControlComparatorEquals 現值須等於要求值（開關與枚舉型鍵）
	PolicyControlComparatorEquals = "equals"
	// PolicyControlComparatorReview 條文涉及這個鍵但未定值，要求值留空。
	//
	// **不是漏填**：條文寫的是「使用足夠強度之加密」這類語境式要求，沒有一個
	// 數字或開關值可以代表它。系統不替條文發明一個值（那會讓稽核以為那個門檻
	// 有出處），改為連同目前值列出，由稽核人員判讀設定是否合理
	PolicyControlComparatorReview = "review"
)

// PolicyGroup 政策組：一組對照條文的容器。
//
// **主鍵是組代號而不是流水號**：條文、控制與備註三張表都以組代號掛靠，而組代號
// 同時是對外引用的識別（報告與稽核記錄都引它）。換成流水號會讓同一個內建組在
// 重建資料庫後拿到不同的識別，既有引用即失效。
type PolicyGroup struct {
	Code string `gorm:"primaryKey;size:64" json:"code"`
	Name string `gorm:"size:200;not null" json:"name"`
	// Source 來源（builtin／custom）：決定可寫範圍
	Source string `gorm:"size:16;not null" json:"source"`
	// Enabled 生效開關。**內建組的開關也由機構決定**，產品升級不得改動它
	Enabled bool `gorm:"not null;default:true" json:"enabled"`
	// Version 內建組的內容版本（規範文本自身的版本標示）；自建組留空
	Version string `gorm:"size:32;not null;default:''" json:"version"`
	// Locale 自建組的原文語言標示；內建組留空
	Locale    string    `gorm:"size:16;not null;default:''" json:"locale"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// TableName 指定表名
func (PolicyGroup) TableName() string {
	return "policy_groups"
}

// PolicyClause 政策組內的一條條文。
//
// 主鍵是（組代號，條號）而非流水號：條號是條文在該組內的自然識別，內建組的
// 升級 upsert 與機構備註的掛靠都以它為鍵。
type PolicyClause struct {
	GroupCode string `gorm:"primaryKey;size:64" json:"group_code"`
	ClauseNo  string `gorm:"primaryKey;size:64" json:"clause_no"`
	Title     string `gorm:"size:300;not null" json:"title"`
	Summary   string `gorm:"type:text;not null;default:''" json:"summary"`
	// Kind 條文型別（見 PolicyClauseKind* 常數）。
	//
	// 欄寬 32 而非 16：型別值是可讀的識別字，最長的一個已經 18 個字元，
	// 而寫不下時 postgres 是整筆寫入失敗，不是截斷
	Kind string `gorm:"size:32;not null" json:"kind"`
	// RemovedInVersion 該條文已於哪一個內容版本自規範中消失；空字串＝仍存在。
	//
	// **升級只標記不刪列**：機構可能已在這條上寫了備註或做過人工確認，刪列會讓
	// 那些記錄失去掛靠對象。標記後判定與對照不再計入本條，但管理頁仍看得到它
	RemovedInVersion string    `gorm:"size:32;not null;default:''" json:"removed_in_version"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
}

// TableName 指定表名
func (PolicyClause) TableName() string {
	return "policy_clauses"
}

// PolicyClauseControl 一條條文對單一設定鍵的要求。
//
// 一條條文可對多個鍵（多列），但**同一組內同一個鍵只能出現一次**（唯一索引
// group_code＋policy_key）：同組內對同一個鍵給出兩個要求時，該組對自己自相矛盾，
// 而判定結果會取決於列的讀取順序。
type PolicyClauseControl struct {
	ID        uint   `gorm:"primarykey" json:"id"`
	GroupCode string `gorm:"size:64;not null;uniqueIndex:idx_policy_clause_controls_group_key,priority:1" json:"group_code"`
	ClauseNo  string `gorm:"size:64;not null" json:"clause_no"`
	PolicyKey string `gorm:"size:64;not null;uniqueIndex:idx_policy_clause_controls_group_key,priority:2" json:"policy_key"`
	// Comparator 比較方式（min／max／equals），依鍵型別受限
	Comparator string `gorm:"size:16;not null" json:"comparator"`
	// ExpectedValue 要求值，以字串存放（型別語義由設定鍵的定義決定，與設定值本身同一套）
	ExpectedValue string `gorm:"type:text;not null" json:"expected_value"`
	// ReferenceOnly 要求值是參考值而非規範明定值。
	//
	// 為真時該控制產生「待人工確認」而不是符合或偏離——把參考值印成明定要求，
	// 會讓閱讀者以為那個數字有出處，而它沒有
	ReferenceOnly bool      `gorm:"not null;default:false" json:"reference_only"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// TableName 指定表名
func (PolicyClauseControl) TableName() string {
	return "policy_clause_controls"
}

// PolicyClauseAnnotation 機構掛在某條條文上的備註與人工確認記錄。
//
// **刻意不設外鍵到條文列**：條文列會因產品升級而被標記移除，備註必須在那之後
// 仍然存在且可讀。外鍵會把兩者的生命週期綁在一起，而它們本來就不同。
//
// 備註不影響判定；人工確認只作用於待確認的條文。
type PolicyClauseAnnotation struct {
	GroupCode string `gorm:"primaryKey;size:64" json:"group_code"`
	ClauseNo  string `gorm:"primaryKey;size:64" json:"clause_no"`
	// Note 機構備註（純文字）
	Note string `gorm:"type:text;not null;default:''" json:"note"`
	// ConfirmedBy 最近一次人工確認的操作者；空字串＝尚未確認
	ConfirmedBy string `gorm:"size:100;not null;default:''" json:"confirmed_by"`
	// ConfirmedAt 最近一次人工確認的時刻；未確認時為 NULL。
	// **確認不設到期**：由機構決定何時重新確認，再次確認覆蓋前次
	ConfirmedAt *time.Time `json:"confirmed_at"`
	// ConfirmationNote 確認時附的一句說明
	ConfirmationNote string    `gorm:"type:text;not null;default:''" json:"confirmation_note"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
}

// TableName 指定表名
func (PolicyClauseAnnotation) TableName() string {
	return "policy_clause_annotations"
}

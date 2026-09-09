package database

import (
	"fmt"

	"gorm.io/gorm"
)

// 政策組的資料層增量 migration：四張新表。
// 沿既有增量的紀律：DDL 無條件、不用 IF NOT EXISTS——在已套用的庫上重跑
// 必須大聲失敗，而非靜默 no-op。
//
// # Up 做什麼
//
//  1. `policy_groups`：政策組本體。主鍵是組代號（人可讀的字串）而非流水號
//     ——條文、控制與備註三張表都以組代號掛靠，且組代號是對外引用的識別。
//     `enabled` 預設 true：全新安裝時內建組即生效，與升級前「兩套建議值都顯示」
//     的現況一致。`version` 存內建組的內容版本，`locale` 存自建組的原文語言，
//     兩者各自只對一種來源有意義，故皆可為空字串而非 NULL——空字串在此的語義是
//     「這一類的組不帶這個欄位」，與 NULL 的「未知」不同，兩態並存只會多出一個
//     沒有意義的第三態。
//  2. `policy_clauses`：條文。主鍵（組代號，條號）。`removed_in_version` 空字串
//     ＝條文仍存在；非空＝該條在標示的內容版本中已自規範消失。**升級只標記不刪列**
//     ——機構備註掛在（組代號，條號）上，刪列會讓那些記錄失去掛靠對象。
//  3. `policy_clause_controls`：條文對單一設定鍵的要求，一條條文可有多列。
//     `comparator` 三值（min／max／equals）由設定鍵的型別決定合法範圍，
//     於寫入端驗證而非以 CHECK 表達——合法值域取決於鍵的定義（在程式碼裡），
//     資料庫看不到那份定義，寫成 CHECK 只擋得住三值以外的字面量，擋不住
//     「對開關型鍵用 min」這種真正會判錯的組合。
//  4. `policy_clause_annotations`：機構備註與人工確認記錄。主鍵（組代號，條號）。
//
// # 索引
//
//   - `policy_clause_controls (group_code, policy_key)` UNIQUE：同一組內同一個鍵
//     只能有一個要求。缺了它，同組出現兩個彼此矛盾的要求時，判定結果取決於列的
//     讀取順序——那是一個沒有訊號的錯誤。前綴同時服務「取某組全部控制」這個
//     最主要的讀法，故不另建索引。
//
// # 為什麼四張表之間沒有外鍵
//
// 備註表**刻意**不指向條文列：條文會因升級而被標記移除，備註必須在那之後仍然
// 存在且可讀，外鍵會把兩者的生命週期綁在一起。條文與控制指向組的外鍵則是另一
// 種取捨——刪除自建組時連帶清除其條文、控制與備註，這件事在寫入端以單一交易
// 完成並有測試釘住；交給資料庫的 ON DELETE CASCADE 會讓「刪了什麼」不出現在
// 任何一段可讀的程式碼裡，而那正是稽核要問的事。
//
// # Down 契約（讀完再用）
//
// **本 Down 有損，且損失不可還原**：四張表整個消失。內建組的內容可由下一次
// 啟動的種子重建，但**機構自建的政策組、自建條文、全部備註與人工確認記錄
// 沒有第二個地方存著**，回退即永久遺失。回退前須自行匯出。
//
// 生產沒有回滾入口（RollbackMigration 無產品碼呼叫者，回退手段是部署回舊版
// 映像並還原升級前備份，docs/ops/upgrade-sop.md §4）。
func policyGroupsDDL() []string {
	return []string{
		`CREATE TABLE policy_groups (
			code character varying(64) NOT NULL,
			name character varying(200) NOT NULL,
			source character varying(16) NOT NULL,
			enabled boolean DEFAULT true NOT NULL,
			version character varying(32) DEFAULT ''::character varying NOT NULL,
			locale character varying(16) DEFAULT ''::character varying NOT NULL,
			created_at timestamp with time zone,
			updated_at timestamp with time zone,
			CONSTRAINT policy_groups_pkey PRIMARY KEY (code)
		)`,
		`CREATE TABLE policy_clauses (
			group_code character varying(64) NOT NULL,
			clause_no character varying(64) NOT NULL,
			title character varying(300) NOT NULL,
			summary text DEFAULT ''::text NOT NULL,
			kind character varying(32) NOT NULL,
			removed_in_version character varying(32) DEFAULT ''::character varying NOT NULL,
			created_at timestamp with time zone,
			updated_at timestamp with time zone,
			CONSTRAINT policy_clauses_pkey PRIMARY KEY (group_code, clause_no)
		)`,
		`CREATE TABLE policy_clause_controls (
			id bigserial,
			group_code character varying(64) NOT NULL,
			clause_no character varying(64) NOT NULL,
			policy_key character varying(64) NOT NULL,
			comparator character varying(16) NOT NULL,
			expected_value text NOT NULL,
			reference_only boolean DEFAULT false NOT NULL,
			created_at timestamp with time zone,
			updated_at timestamp with time zone,
			CONSTRAINT policy_clause_controls_pkey PRIMARY KEY (id)
		)`,
		`CREATE TABLE policy_clause_annotations (
			group_code character varying(64) NOT NULL,
			clause_no character varying(64) NOT NULL,
			note text DEFAULT ''::text NOT NULL,
			confirmed_by character varying(100) DEFAULT ''::character varying NOT NULL,
			confirmed_at timestamp with time zone,
			confirmation_note text DEFAULT ''::text NOT NULL,
			created_at timestamp with time zone,
			updated_at timestamp with time zone,
			CONSTRAINT policy_clause_annotations_pkey PRIMARY KEY (group_code, clause_no)
		)`,
		`CREATE UNIQUE INDEX idx_policy_clause_controls_group_key ON policy_clause_controls USING btree (group_code, policy_key)`,
	}
}

func applyPolicyGroups(db *gorm.DB) error {
	for _, stmt := range policyGroupsDDL() {
		if err := db.Exec(stmt).Error; err != nil {
			return fmt.Errorf("執行 policy_groups DDL 失敗（%.80s…）: %w", stmt, err)
		}
	}
	return nil
}

// policyGroupsRollbackDDL 反序卸下的語句。
//
// 具名而非內嵌在 rollback 函式裡：Up 與 Down 的對稱性（建了什麼就要卸什麼）
// 是本增量唯一會被靜默破壞的性質——殘留物只在下一次 Up 才以「物件已存在」
// 現形，而那時人已經在別的分支上了。具名後測試讀得到兩份清單並逐項對照。
func policyGroupsRollbackDDL() []string {
	return []string{
		`DROP INDEX idx_policy_clause_controls_group_key`,
		`DROP TABLE policy_clause_annotations`,
		`DROP TABLE policy_clause_controls`,
		`DROP TABLE policy_clauses`,
		`DROP TABLE policy_groups`,
	}
}

// rollbackPolicyGroups 反序卸下。見本檔檔頭的 Down 契約——**有損**。
func rollbackPolicyGroups(db *gorm.DB) error {
	for _, stmt := range policyGroupsRollbackDDL() {
		if err := db.Exec(stmt).Error; err != nil {
			return fmt.Errorf("回滾 policy_groups 失敗（%.80s…）: %w", stmt, err)
		}
	}
	return nil
}

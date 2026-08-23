package keyvault

import (
	"fmt"
	"log"
	"sort"

	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

// AADResidue 單一登記欄位的非終態格式殘值計數
type AADResidue struct {
	Table  string `json:"table"`
	Column string `json:"column"`
	Count  int64  `json:"count"`
}

// aadResidueSQLPattern SQL 側「已為終態格式」的前綴樣式
const aadResidueSQLPattern = "enc:a1:%"

// AADResidueLowerBound 殘值的 **SQL 側前綴計數**，語義為「Go 嚴格判定的下界」。
//
// `ParseEnvelopeFull` 的嚴格解析與 `LIKE` 前綴在型別上不可能等價——`enc:a1:` 開頭
// 但格式損毀者 Go 記殘值、SQL 不記，故 SQL ≤ Go 恆成立而相等不成立。母體口徑與
// Go 掃描一致（`db.Table()` 含軟刪列、`<> ”`），否則「下界」連方向性都不保。
//
// **兩個共用點（口徑必須同一）**：啟動哨兵的提示層掃描，以及退役 DEK 銷毀前
// 引用掃描的「不可歸屬殘值」偵測（key_manager_cleanup）——後者若不沿本口徑，
// 非 `enc:a1` 的殘值會被算成零引用而放行銷毀。
func AADResidueLowerBound(db *gorm.DB) ([]AADResidue, int64, error) {
	var out []AADResidue
	var total int64
	for _, target := range envelopeMigrationTargets {
		var n int64
		err := db.Table(target.table).
			Where(fmt.Sprintf("%s <> '' AND %s NOT LIKE ?", target.column, target.column),
				aadResidueSQLPattern).
			Count(&n).Error
		if err != nil {
			return nil, 0, fmt.Errorf("SQL 下界計數 %s.%s 失敗: %w", target.table, target.column, err)
		}
		if n > 0 {
			out = append(out, AADResidue{Table: target.table, Column: target.column, Count: n})
			total += n
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Table != out[j].Table {
			return out[i].Table < out[j].Table
		}
		return out[i].Column < out[j].Column
	})
	return out, total, nil
}

// 啟動哨兵：非終態密文的「不可能態」偵測。
//
// 過渡機制拆除後，AAD 綁定恆為強制：寫入端在建構上只產 `enc:a1`，
// 系統不具備 permissive 讀取、模式切換或存量遷移能力。故啟動掃描發現任何
// 非 `enc:a1` 的登記欄位值，語義**不再是「遷移未執行」**，而是
// 「程式缺陷或繞過 API 的資料庫直寫」——一個依設計不可能發生的狀態。
//
// **分工**：本哨兵屬**資料層 fail-visible**——warn log ＋失效事件告警，
// SHALL NOT 阻塞啟動、SHALL NOT 附遷移指引、SHALL NOT 自動改寫任何值。
// 「過渡格式資料庫擋啟動」由**金鑰層 fail-close** 承擔（無前綴／`wk:1` 的
// wrapped_key、v0 金鑰列於載入時拒絕啟動）。

// ReportAADResidueOnStartup 啟動時掃描全部登記欄位的非終態格式殘值。
//
// 計數用廉價的 SQL 前綴下界（`AADResidueLowerBound`）：其語義為 Go 嚴格判定的
// **下界**，`enc:a1:` 開頭但格式損毀者不在此視野內——哨兵是提示層，權威判定在
// 解密路徑本身（非 `enc:a1` 一律 fail-close）。
//
// **計數失敗記「狀態未知」，SHALL NOT 以零頂替**（未知狀態顯示為安全是最糟的謊）。
//
// af 為 keyvault 自宣告的窄介面（4.10 拆環）：本函式是該環的**第二實例**
// ——原先只列了 `key_manager_degraded.go` 的 monitor，本實例由參照圖
// 守衛掃出（處置形態同 C↔E 環的第二實例）。呼叫端傳入型別化的 nil 指標時，
// 下方 `af == nil` 擋不住（介面不為 nil），故契約是 SHALL 傳入非 nil 實作
func ReportAADResidueOnStartup(db *gorm.DB, af AuditFailureReporter) {
	if db == nil || af == nil {
		return
	}
	residues, lowerBound, err := AADResidueLowerBound(db)
	if err != nil {
		log.Printf("[AADResidue] 啟動殘值掃描：SQL 下界計數失敗（狀態未知，不以零頂替）: %v", err)
		return
	}
	if lowerBound > 0 {
		log.Printf("[警告][AADResidue] 偵測到非終態格式密文殘值（下界 %d 筆，逐欄 %s）："+
			"寫入端在建構上只產 enc:a1，此為不可能態——請查程式缺陷或繞過 API 的資料庫直寫。"+
			"系統不提供遷移入口，該些值於讀取時一律 fail-close",
			lowerBound, formatAADResidues(residues))
		af.Report(model.MechanismAADResidue, model.CauseAADResidueImpossibleState, map[string]string{
			"residue_lower_bound": fmt.Sprintf("%d", lowerBound),
			"columns":             formatAADResidues(residues),
		})
		return
	}
	if af.AdoptOpenEvent(model.MechanismAADResidue) {
		af.Resolve(model.MechanismAADResidue)
	}
}

// formatAADResidues 逐欄殘值的單行摘要（`表.欄=筆數`，以「、」相接）。
// 只落位置與筆數，不落值本身——殘值可能是敏感密文。
func formatAADResidues(residues []AADResidue) string {
	if len(residues) == 0 {
		return "(無)"
	}
	out := ""
	for i, r := range residues {
		if i > 0 {
			out += "、"
		}
		out += fmt.Sprintf("%s.%s=%d", r.Table, r.Column, r.Count)
	}
	return out
}

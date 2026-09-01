package offsite

import (
	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

// 保管鏈事件（custody journal）。
//
// **帳冊是「現在的狀態」，審計列是「發生過什麼」**，兩者分工不重疊：
// `offsite_objects` 可變（重傳更新同列），`audit_logs` 追加式且在檢查點鏈的覆蓋內。
// 稽核員要回答「某會話的錄影在哪個 bucket、何時上傳、本機何時到期清除、結果如何」
// 全部查審計列。
//
// 本包**不直寫 `audit_logs`**（包內守衛 table_ownership_guard_test.go 擋 `AuditLog{}`
// 直寫）：宣告消費者側的窄介面，由組裝根以 audit 模組的落地面注入。

// 保管鏈事件的 Action（`AuditLog.Action` 為 varchar(20)，以下皆在長度內）。
const (
	// CustodyActionUpload 上傳成功；達重試上限失敗；租約回收 ≥2 次（result=stalled）
	CustodyActionUpload = string(model.ActionOffsiteUpload)
	// CustodyActionRetention 保留政策到期、本機副本清除。
	// **短碼**：原擬 `offsite_retention_expired` 為 25 字元、超出 varchar(20)；
	// 為一個機器碼加寬檢查點鏈覆蓋的熱表不划算，語義損失可忽略
	// （本 Action 只在保留到期路徑寫入，Details 帶 key 與前態）
	CustodyActionRetention = string(model.ActionOffsiteRetention)
	// CustodyActionIntegrity 取回驗證不符、拒絕交付
	CustodyActionIntegrity = string(model.ActionOffsiteIntegrity)
	// CustodyActionProfile 世代切換確認生效、或停止離機（舊世代物件轉 foreign）
	CustodyActionProfile = string(model.ActionOffsiteProfile)
	// CustodyActionCredRevoke 管理員撤銷某世代的憑證
	CustodyActionCredRevoke = string(model.ActionOffsiteCredRevoke)
)

// CustodyEvent 一筆保管鏈事件。
//
// **主體恆為系統**（UserID=0／Username="system"，沿 recording_failure_report.go 的
// 退路慣例）——管理員的重試與測試連線另有中介層審計（admin 主體），兩列不合併。
//
// Details **不含端點、不含憑證與其遮罩**：bucket 與 key 是
// 對帳所需的最小集合，端點只在設定面顯示為 origin。
type CustodyEvent struct {
	// Action 見本檔 CustodyAction* 常數
	Action string
	// Resource／ResourceID 擁有者（session／audit_export），非帳冊列本身
	Resource   string
	ResourceID *uint
	// Status success／failure
	Status string
	// Details JSON 負載
	Details map[string]any
}

// CustodyJournal 保管鏈事件的落地面（消費者側窄介面）。
//
// 兩個方法對應兩種呼叫脈絡，**不可互相替代**：
//
//	Record      worker 與取回路徑：沒有呼叫方交易，走 audit 的非同步佇列。
//	            回 error 只供記 log——上傳已經發生，審計寫不進去不該把它回捲成
//	            「沒上傳」（那會使下一輪重傳同 key 而狀態更亂）。
//	RecordInTx  設定寫入路徑（世代切換、停止離機、撤銷憑證）：與資料變更同交易，
//	            **回 error 即整筆回滾**——設定世代被改寫卻無審計紀錄不是可接受的終局。
type CustodyJournal interface {
	Record(ev CustodyEvent) error
	RecordInTx(tx *gorm.DB, ev CustodyEvent) error
}

// noopCustodyJournal 未注入時的退路（僅單元測試建構路徑；生產組裝一律注入，
// 沿 NotificationChannelService 的 nil codec 取捨）。
type noopCustodyJournal struct{}

func (noopCustodyJournal) Record(CustodyEvent) error               { return nil }
func (noopCustodyJournal) RecordInTx(*gorm.DB, CustodyEvent) error { return nil }

package keyvault

import (
	"fmt"
	"log"
	"strconv"
	"sync"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/notifycat"
	"gorm.io/gorm"
)

// KEK 退役收斂 degraded 偵測與持續告警（kek-rewrap-hygiene-hardening D5）。
//
// degraded ＝ retire backlog > 0（前次切換收尾未成功退役的舊 KEK 包裹列殘留）。
// 服務不降：連線、審計、既有密文加解密全部正常，僅新重包維持既有 409 拒絕。
// 收斂的唯一路徑是重啟（finalizeSwitch 僅由 load 呼叫，key-inventory-transparency
// 語義本 change 不改），故提醒文案一律指向「重啟後端收斂」。
//
// 謂詞刻意不聯集 finalize_pending：後者是「重包完成、待換 env 重啟」的正常
// 工作流狀態（有自己的待切換 banner）。推理前提「promote 未完成的殘缺態不可
// 帶病開機」由 TestFinalizePendingResidueUnbootable 釘住。

// countRetireBacklog 退役 backlog 謂詞的**唯一定義**（清冊端點與 degraded 偵測共用）。
// db 可為 *gorm.DB 或鎖內交易——鎖內判定一律傳 tx（D3：判定以鎖內重讀為準）
func countRetireBacklog(db *gorm.DB, env string) (int64, error) {
	var n int64
	err := db.Model(&model.DataKey{}).
		Where("kek_id <> ? AND kek_pending = ? AND kek_retired_at IS NULL", env, false).
		Count(&n).Error
	if err != nil {
		return 0, fmt.Errorf("檢查退役 backlog 失敗: %w", err)
	}
	return n, nil
}

// RetireBacklogCount 退役 backlog 筆數（>0 即 degraded）。清冊端點與週期評估共用
func (s *KeyManagerService) RetireBacklogCount() (int64, error) {
	return countRetireBacklog(s.db, s.kekKeyID())
}

// LastFinalizeErr 本次啟動收尾失敗原因（nil＝成功或無收尾／取鎖跳過）。
// KeyManager 初始化早於告警服務，失敗僅記錄於此，由 main 於告警就緒後讀取上報
func (s *KeyManagerService) LastFinalizeErr() error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lastFinalizeErr
}

// AuditFailureReporter 失效事件上報面（**keyvault 自宣告的窄介面**，audit 側實作）。
//
// **存在理由是 4.10 環拆解**（Phase B W1 1.11／R3.1 §3.1）：KEKRetirementMonitor 原本
// 直接持有 `*AuditFailureService`，使 keyvault→audit 成為真出向邊，而 audit→keyvault
// 又因蓋章需要 KeyManager 而必然存在（`audit_integrity_service.go` 的
// `InitAuditIntegrityVersioned(db, km)`），兩者合成環。介面由消費方（keyvault）宣告、
// 實作留在 audit、注入在 `cmd/server/stage2.go`，方向即翻轉為 audit→keyvault 單向。
//
// 方法集刻意只涵蓋 monitor 實際使用的六個，不是 `*AuditFailureService` 的全表面：
// 窄介面的價值在於「keyvault 能對 audit 做什麼」是可窮舉的，寬介面等於沒反轉。
type AuditFailureReporter interface {
	// AlertEnabled 告警政策是否允許投遞（節流狀態只在允許投遞時推進）
	AlertEnabled() bool
	// Report 開列失效事件（自帶首次通知）
	Report(mechanism, causeCode string, params map[string]string)
	// Resolve 結案並發恢復通知
	Resolve(mechanism string)
	// AdoptOpenEvent 認領重啟前遺留的 open 事件；true＝確有既有事件
	AdoptOpenEvent(mechanism string) bool
	// EnsureEventRow 進行中事件的 best-effort 補列（Report 當時拒寫的殘態修復）
	EnsureEventRow(mechanism, causeCode string, params map[string]string)
	// NotifyOngoing 進行中事件的週期重發
	NotifyOngoing(event notifycat.Event, params map[string]string)
}

// KEKRetirementMonitor 退役收斂 degraded 評估器（D5）。
// 啟動評估由 main 於 InitAuditFailure＋InitAlertNotifier 就緒後呼叫（沿
// LastKEKSwitch 補記前例——KeyManager 初始化期間發告警必然被丟棄）；
// 週期評估由 scheduler 每日呼叫（thin cron wrapper，沿 DailyReview 前例）
type KEKRetirementMonitor struct {
	km *KeyManagerService
	// af 失效上報面：型別是 keyvault 自宣告的窄介面，非 audit 的具體型別（4.10 拆環）
	af AuditFailureReporter

	mu sync.Mutex
	// lastReminded 行程內「上次**實際投遞**的提醒日」：同日不重複投遞。
	// 重啟即失為設計內行為——重啟正是收斂手段，未收斂再提醒一次合理。
	//
	// 語義是「已提醒」而非「已評估」（codex 批 2 M5）：政策關閉時 sendNotify
	// 靜默丟棄，若那次評估仍推進本欄，當日稍後才開啟政策的維運者整日收不到
	// 提醒。故推進條件一律是 af.AlertEnabled()
	lastReminded time.Time
}

// NewKEKRetirementMonitor 建立評估器。lastReminded 起始為零值（尚未提醒過）：
// 本次啟動的首次提醒由 ReportOnStartup 於**確實投遞時**登記；以建構時刻預先
// 佔位等於假設啟動評估必然投遞，而它可能因政策關閉或 backlog 查詢失敗而沒有
//
// af 為窄介面（4.10 拆環）：呼叫端 SHALL 傳入非 nil 實作——型別化的 nil 指標
// 包進介面後不等於 nil，會在首次上報時 panic 而非靜默不報
func NewKEKRetirementMonitor(km *KeyManagerService, af AuditFailureReporter) *KEKRetirementMonitor {
	return &KEKRetirementMonitor{km: km, af: af}
}

// ReportOnStartup 啟動評估：backlog > 0 → 經失效事件族上報（開列＋政策開時通知）；
// backlog 已收斂 → 認領重啟前遺留的 open 事件並結案（恢復以謂詞重評估為準，
// 不靠 ReconcileOnStartup 的無條件回填）
func (m *KEKRetirementMonitor) ReportOnStartup(now time.Time) {
	count, err := m.km.RetireBacklogCount()
	if err != nil {
		log.Printf("[KeyManager] 退役 backlog 啟動評估失敗（degraded 狀態未知）: %v", err)
		return
	}
	if count > 0 {
		// 本地無條件訊號：不受告警政策與通道配置影響
		log.Printf("[KeyManager] degraded：退役 backlog %d 筆未收斂（服務不受影響，重啟後端以重試收尾）", count)
		// 只有政策允許投遞時才算「今天提醒過」（M5）；政策關則保持零值，
		// 同日稍後開啟政策的週期評估仍會補上提醒
		if m.af.AlertEnabled() {
			m.mu.Lock()
			m.lastReminded = now
			m.mu.Unlock()
		}
		m.af.Report(model.MechanismKEKRetirement, model.CauseKEKRetirementBacklog, m.causeParams(count))
		return
	}
	if m.af.AdoptOpenEvent(model.MechanismKEKRetirement) {
		m.af.Resolve(model.MechanismKEKRetirement)
	}
}

// Evaluate 週期評估（每日）：
//   - backlog 持續 → 直投提醒（不走 Report 的進行中去重路徑），每日至多一次
//   - backlog 由 >0 轉 0 → 結束 open 事件並發恢復通知，之後不再重發
//   - 無 backlog 且無 open 事件 → 無動作
func (m *KEKRetirementMonitor) Evaluate(now time.Time) {
	count, err := m.km.RetireBacklogCount()
	if err != nil {
		log.Printf("[KeyManager] 退役 backlog 週期評估失敗（degraded 狀態未知）: %v", err)
		return
	}
	if count > 0 {
		log.Printf("[KeyManager] degraded：退役 backlog %d 筆仍未收斂", count)
		// 事件列保障（codex 第一輪審 #5）：啟動評估失敗（如 DB 暫時不可用）時
		// open 事件可能從未開列——每輪先認領既有事件，沒有才經 Report 開列
		// （Report 自帶首次通知，視同本日提醒）；已有事件才走週期重發
		hadEvent := m.af.AdoptOpenEvent(model.MechanismKEKRetirement)
		// 節流狀態只在政策允許投遞時推進（M5）：政策當時關閉、同日稍後開啟，
		// 下一輪評估仍須提醒，而非整日被一次「其實沒送出去」的評估吞掉
		alertOn := m.af.AlertEnabled()
		m.mu.Lock()
		remind := !sameDay(m.lastReminded, now)
		if remind && alertOn {
			m.lastReminded = now
		}
		m.mu.Unlock()
		if !hadEvent {
			m.af.Report(model.MechanismKEKRetirement, model.CauseKEKRetirementBacklog, m.causeParams(count))
			return
		}
		// 進行中仍補列（codex 第二輪審 H1）：Report 當時事件表拒寫會留下
		// 「in-memory failing、DB 無列」的殘態且 Report 永不重試——每輪 best-effort 補列
		m.af.EnsureEventRow(model.MechanismKEKRetirement, model.CauseKEKRetirementBacklog,
			m.causeParams(count))
		if remind {
			// 出站帶碼、時刻與積壓筆數：筆數是收件人判斷嚴重度的唯一量化訊號
			// （遷移前文案即為「N 筆舊 KEK 包裹列仍未退役」，V2 對抗驗收 L1 補回）。
			// 收尾錯誤原文等 forensic 明細仍只留 cause_params，不進出站 payload（D8）
			m.af.NotifyOngoing(notifycat.EventAuditFailureOngoing, map[string]string{
				"mechanism":   model.MechanismKEKRetirement,
				"cause_code":  model.CauseKEKRetirementBacklog,
				"reported_at": now.Format(time.RFC3339),
				"backlog":     strconv.FormatInt(count, 10),
			})
		}
		return
	}
	m.mu.Lock()
	m.lastReminded = time.Time{}
	m.mu.Unlock()
	if m.af.AdoptOpenEvent(model.MechanismKEKRetirement) {
		m.af.Resolve(model.MechanismKEKRetirement)
	}
}

// causeParams 失效原因參數（PCI 10.7.3 要求記錄 cause；原因碼＝
// model.CauseKEKRetirementBacklog）：帶未退役筆數與本次啟動收尾失敗原文。
// 收尾錯誤訊息僅含 slot/列數等中繼資訊，不含任何金鑰材料；
// detail 屬 forensic，落 cause_params 與本地 log，不進出站 payload（D8）
func (m *KEKRetirementMonitor) causeParams(count int64) map[string]string {
	params := map[string]string{"backlog": strconv.FormatInt(count, 10)}
	if err := m.km.LastFinalizeErr(); err != nil {
		params[model.CauseParamDetail] = fmt.Sprintf("本次啟動收尾失敗：%v", err)
	}
	return params
}

// sameDay 兩時刻是否同一日曆日（同時區）；零值視為不同日（尚未提醒過）
func sameDay(a, b time.Time) bool {
	if a.IsZero() {
		return false
	}
	ay, am, ad := a.Date()
	by, bm, bd := b.Date()
	return ay == by && am == bm && ad == bd
}

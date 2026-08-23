package audit

import (
	"encoding/json"
	"errors"
	"github.com/custodexa/backend/internal/modules/policy"
	"log"
	"strconv"
	"sync"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/keyvault"
	"github.com/custodexa/backend/internal/notifycat"
	"gorm.io/gorm"
)

// AuditFailureService 審計機制失效事件（PCI 10.7.2/10.7.3）。
// 事件記錄恆開；通知受政策 failure_alert_enabled 控制。
// 進行中去重：狀態機以 in-memory map 為第一層（mu 內原子轉換——呼叫端
// 自帶 CAS 旗標曾與本服務交錯出懸掛事件，審查發現後收攏於此），
// DB 未結束事件查詢為第二層（防重啟後重複開列）。
// 呼叫端對每次成敗直接呼叫 Report/Resolve，狀態未變時為廉價 no-op
type AuditFailureService struct {
	db     *gorm.DB
	policy *policy.SecurityPolicyService

	// mu 保護狀態轉換與 DB 查改序列（事件頻率低，粗鎖足矣）
	mu sync.Mutex
	// failing 各機制進行中失效狀態（惰性初始化——測試直接建構 struct）
	failing map[string]bool
	// pendingClose 結案 UPDATE 失敗的機制 → 應記的結束時刻。
	// 失敗當下若只清 in-memory failing 旗標就放行，後續 Resolve 會因「非失效中」
	// 而 no-op，open event 永不結案——PCI 失效區間的結束端證據永久破損。
	// 補結案在下一次 Report/Resolve 開頭 best-effort 進行；跨行程仍由
	// ReconcileOnStartup 兜底（其語義不變）
	pendingClose map[string]time.Time
	// notify 通知出口（測試注入；nil 走 AlertNotifier）。
	// 型別與 NotifyEvent 一致——散文自簽名消失，編譯期擋回潮
	notify func(event notifycat.Event, params map[string]string)
}

// keyvault.AuditFailureReporter 的實作在 audit 側（環相依拆解）：介面由 keyvault
// 宣告、由本型別滿足，方向 audit→keyvault 單向合法。編譯期斷言在此而非 keyvault 側，
// 正是為了讓「誰依賴誰」與斷言的位置一致——斷言寫在 keyvault 會把出向邊加回來。
var _ keyvault.AuditFailureReporter = (*AuditFailureService)(nil)

// 套件級單例：上報點在 audit fallback 與 syslog loop 深處，getter 取用、main 注入
var (
	auditFailureMu       sync.RWMutex
	auditFailureInstance *AuditFailureService
)

// InitAuditFailure 建立並註冊單例
func InitAuditFailure(db *gorm.DB, policy *policy.SecurityPolicyService) *AuditFailureService {
	svc := &AuditFailureService{db: db, policy: policy}
	auditFailureMu.Lock()
	auditFailureInstance = svc
	auditFailureMu.Unlock()
	return svc
}

// GetAuditFailure 取得單例；未初始化（單測）回 nil，呼叫端需 nil 檢查
func GetAuditFailure() *AuditFailureService {
	auditFailureMu.RLock()
	defer auditFailureMu.RUnlock()
	return auditFailureInstance
}

// sendNotify 政策開啟時經通知通道發送（測試注入 notify；預設 AlertNotifier）
func (s *AuditFailureService) sendNotify(event notifycat.Event, params map[string]string) {
	if !s.policy.GetBool(policy.PolicyFailureAlertEnabled) {
		return
	}
	if s.notify != nil {
		s.notify(event, params)
		return
	}
	if notifier := GetAlertNotifier(); notifier != nil {
		notifier.NotifyEvent(event, params)
	}
}

// AlertEnabled 失效告警政策是否允許投遞。
//
// 供提醒節流器（keyvault.KEKRetirementMonitor.lastReminded 這類「同日只提醒一次」的
// 狀態）判斷：政策關閉時 sendNotify 靜默丟棄，此時仍推進節流狀態會讓
// 「政策當天稍後才開啟」的那一整日完全收不到提醒
func (s *AuditFailureService) AlertEnabled() bool {
	return s.policy.GetBool(policy.PolicyFailureAlertEnabled)
}

// markPendingClose 記下待補結案（呼叫端須持 s.mu）
func (s *AuditFailureService) markPendingClose(mechanism string, endedAt time.Time) {
	if s.pendingClose == nil {
		s.pendingClose = make(map[string]time.Time)
	}
	s.pendingClose[mechanism] = endedAt
}

// flushPendingClose best-effort 補上先前失敗的結案（呼叫端須持 s.mu）。
//
// 補的是**原始恢復時刻**而非此刻：失效區間的結束端是既成事實，重試不該把
// 區間拉長。成功、或 open 列已不在（ReconcileOnStartup／他實例已結案）即
// 清除標記；仍失敗則保留待下輪
func (s *AuditFailureService) flushPendingClose(mechanism string) {
	endedAt, ok := s.pendingClose[mechanism]
	if !ok {
		return
	}
	var existing model.AuditFailureEvent
	switch err := s.db.Where("mechanism = ? AND ended_at IS NULL", mechanism).
		First(&existing).Error; {
	case err == nil:
		if err := s.db.Model(&existing).Update("ended_at", endedAt).Error; err != nil {
			log.Printf("[AuditFailure] 待補結案仍失敗，保留標記待下輪 (mechanism=%s, id=%d): %v",
				mechanism, existing.ID, err)
			return
		}
		log.Printf("[AuditFailure] 待補結案已補上 (mechanism=%s, id=%d, ended_at=%s)",
			mechanism, existing.ID, endedAt.Format(time.RFC3339))
	case errors.Is(err, gorm.ErrRecordNotFound):
		// 已無 open 列：標記使命已達成
	default:
		log.Printf("[AuditFailure] 待補結案查詢失敗，保留標記待下輪 (mechanism=%s): %v", mechanism, err)
		return
	}
	delete(s.pendingClose, mechanism)
}

// CauseText 失效原因的 zh-TW 顯示用散文（短語＋forensic detail）。
//
// 權威表述是 CauseCode；本函式的產物只落 DB 的 cause 欄與本地 log，
// 讓尚未改查譯的讀取點不白屏。**不供出站**——detail 含底層 err 原文
// （路徑/位址），出站 payload 只帶碼（去識別紅線）
//
// **匯出理由（export budget）**：唯一包外消費者是 session 模組的
// internal/service/recording_failure_report.go:49（錄影失敗審計列的 Details 欄）。
// 它與本模組同用一份 cause 詞彙表，複製一份到 session 側等於製造第二個會漂移的
// 顯示規則；改由 audit 提供是唯一不製造第二事實來源的形式。
func CauseText(causeCode string, params map[string]string) string {
	phrase := notifycat.Phrase(notifycat.DefaultLang, notifycat.LexiconCause, causeCode)
	if detail := params[model.CauseParamDetail]; detail != "" {
		return phrase + "：" + detail
	}
	return phrase
}

// encodeCauseParams 序列化 cause 參數落庫；空 map 存空字串（非 "null"），
// 序列化失敗不阻斷失效記錄——原因碼本身已是主要證據
func encodeCauseParams(causeCode string, params map[string]string) string {
	if len(params) == 0 {
		return ""
	}
	raw, err := json.Marshal(params)
	if err != nil {
		log.Printf("[AuditFailure] cause 參數序列化失敗 (cause_code=%s): %v", causeCode, err)
		return ""
	}
	return string(raw)
}

// Report 上報失效：狀態未變（進行中）即 no-op；轉換時建列＋（政策開時）通知。
// 通知不依賴 DB 寫入成功——DB 全掛正是最需要告警的時刻（
// 原寫法 Create 失敗直接 return，失效區間零紀錄零告警）。
// 失效記錄本身失敗僅 log——失效服務不能反向拖垮上報端
// causeCode 為 model.Cause* 常數；params 承載結構化細節（含 forensic
// detail），落 cause_params 供稽核，出站只帶碼
func (s *AuditFailureService) Report(mechanism, causeCode string, params map[string]string) {
	s.ReportWithCounts(mechanism, causeCode, params, nil)
}

// failureOutboundCountAllowed 允許進入出站 payload 的計數參數鍵（閉集合）。
//
// **白名單而非黑名單**：出站只帶碼與受控整數計數，受影響的序號清單、紀錄編號
// 區間與任何自由字串一律不出站（去識別紅線）。以閉集合承載使「新增一個看似
// 無害的參數」無法從這條路徑溜出去——不在表內的鍵會被丟棄並留下 log。
// 寫成函式而非包級 map：後者是具時序語義的包級全域，須另行登記於 lifecycle manifest
func failureOutboundCountAllowed(key string) bool {
	switch key {
	case model.FailureParamFailedPoints, model.FailureParamFailedIntervals:
		return true
	}
	return false
}

// ReportWithCounts 上報失效，並於出站 payload 附帶受控整數計數。
//
// counts 的值只可能是整數（型別即證明），且鍵須經 failureOutboundCountAllowed；
// forensic 明細仍只走 params → cause_params（DB），不出站
func (s *AuditFailureService) ReportWithCounts(mechanism, causeCode string,
	params map[string]string, counts map[string]int) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// 先補上前次失敗的結案：否則舊 open 列會被下方第二層去重當成「本輪的
	// 進行中事件」沿用，兩段失效被併成一段（且新列撞 single-open 唯一索引）
	s.flushPendingClose(mechanism)

	if s.failing == nil {
		s.failing = make(map[string]bool)
	}
	if s.failing[mechanism] {
		return // 進行中，去重（in-memory 第一層：DB 掛掉時仍有效）
	}
	s.failing[mechanism] = true

	startedAt := time.Now()
	// DB 建列 best-effort。第二層去重：DB 已有未結束事件（重啟遺留且
	// Reconcile 未及回填）時不重複開列
	var existing model.AuditFailureEvent
	switch err := s.db.Where("mechanism = ? AND ended_at IS NULL", mechanism).
		First(&existing).Error; {
	case err == nil:
		// DB 已有進行中事件，沿用；仍屬新一輪 in-memory 轉換，通知照發。
		// 出站 started_at 取該事件的真實起點而非此刻：
		// 沿用的前提就是失效自那時起未曾中斷，報 time.Now() 會把已持續數小時的
		// 失效講成剛剛才發生，收件人與後續 Resolve 的區間對不上
		startedAt = existing.StartedAt
	case errors.Is(err, gorm.ErrRecordNotFound):
		event := model.AuditFailureEvent{
			Mechanism: mechanism, StartedAt: startedAt,
			Cause:       CauseText(causeCode, params),
			CauseCode:   causeCode,
			CauseParams: encodeCauseParams(causeCode, params),
		}
		if err := s.db.Create(&event).Error; err != nil {
			log.Printf("[AuditFailure] 失效事件寫入失敗 (mechanism=%s): %v", mechanism, err)
		}
	default:
		log.Printf("[AuditFailure] 查詢進行中事件失敗 (mechanism=%s): %v", mechanism, err)
	}
	log.Printf("[AuditFailure] 機制 %s 失效: %s", mechanism, CauseText(causeCode, params))

	// 出站只帶碼：detail 不進 params（去識別紅線）
	outbound := map[string]string{
		"mechanism":  mechanism,
		"started_at": startedAt.Format(time.RFC3339),
		"cause_code": causeCode,
	}
	for key, n := range counts {
		if !failureOutboundCountAllowed(key) {
			log.Printf("[AuditFailure] 計數參數 %q 不在出站白名單，已丟棄 (mechanism=%s)", key, mechanism)
			continue
		}
		outbound[key] = strconv.Itoa(n)
	}
	s.sendNotify(notifycat.EventAuditFailure, outbound)
}

// Resolve 機制恢復：狀態未變（非失效中）即 no-op；轉換時回填進行中事件的
// EndedAt＋（政策開時）恢復通知。呼叫端可對每次成功安全呼叫。
//
// 回填 UPDATE 失敗時通知照發（恢復是既成事實，優先出站），但會留下
// pendingClose 標記，由下一次 Report/Resolve/AdoptOpenEvent 補結案——
// 不可讓 open event 因一次寫庫抖動而永久懸掛
func (s *AuditFailureService) Resolve(mechanism string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// 先補上前次失敗的結案。此步驟刻意在 failing 檢查**之前**：前次失敗時
	// failing 已被清為 false，之後每次 Resolve 都會走下面的 no-op 早退，
	// 補結案若放在早退之後就永遠到不了（病灶正是這個順序）
	s.flushPendingClose(mechanism)

	if !s.failing[mechanism] {
		return // 非失效中（map 未初始化亦落此路徑）
	}
	s.failing[mechanism] = false

	now := time.Now()
	// interval variant：known＝起訖皆可考；unknown＝DB 掛掉期間無列可回填
	params := map[string]string{
		"mechanism": mechanism,
		"interval":  notifycat.IntervalUnknown,
	}
	var existing model.AuditFailureEvent
	switch err := s.db.Where("mechanism = ? AND ended_at IS NULL", mechanism).
		First(&existing).Error; {
	case err == nil:
		if err := s.db.Model(&existing).Update("ended_at", now).Error; err != nil {
			log.Printf("[AuditFailure] 失效事件回填結束時間失敗，標記待補結案 (id=%d): %v",
				existing.ID, err)
			// 通知照發（恢復事實優先出站），但結案責任不隨 failing 旗標一起丟掉
			s.markPendingClose(mechanism, now)
		}
		params["interval"] = notifycat.IntervalKnown
		params["started_at"] = existing.StartedAt.Format(time.RFC3339)
		params["ended_at"] = now.Format(time.RFC3339)
	case errors.Is(err, gorm.ErrRecordNotFound):
		// DB 掛掉期間 Create 失敗的失效：無列可回填，通知仍照發（對稱）
	default:
		log.Printf("[AuditFailure] 查詢進行中事件失敗 (mechanism=%s): %v", mechanism, err)
	}
	log.Printf("[AuditFailure] 機制 %s 已恢復（interval=%s %s~%s）",
		mechanism, params["interval"], params["started_at"], params["ended_at"])

	s.sendNotify(notifycat.EventAuditFailureResolved, params)
}

// AdoptOpenEvent 認領 DB 中該機制未結束的事件為「進行中」in-memory 狀態，
// 使後續 Resolve 得以與之配對。
// 用於狀態可由 DB 謂詞導出、且不被 ReconcileOnStartup 無條件關閉的機制：
// 重啟後 in-memory 狀態歸零，不認領則遺留事件永無人回填。
// 回傳是否處於失效中（true 時呼叫 Resolve 才會實際結案）
func (s *AuditFailureService) AdoptOpenEvent(mechanism string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	// 同 Report/Resolve：待補結案的列不是「進行中事件」，先補結案再判定，
	// 否則會把已恢復的舊事件認領成本輪失效（invariant：任何路徑都不得把
	// pendingClose 的列當成 open）
	s.flushPendingClose(mechanism)

	if s.failing[mechanism] {
		return true
	}
	var existing model.AuditFailureEvent
	if err := s.db.Where("mechanism = ? AND ended_at IS NULL", mechanism).
		First(&existing).Error; err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			log.Printf("[AuditFailure] 查詢進行中事件失敗 (mechanism=%s): %v", mechanism, err)
		}
		return false
	}
	if s.failing == nil {
		s.failing = make(map[string]bool)
	}
	s.failing[mechanism] = true
	return true
}

// NotifyOngoing 對「仍在進行中」的失效狀態直接投遞提醒（週期重發入口）：
// 不經 Report——Report 的進行中去重語義
// 就是不重發。本方法不動狀態機也不動事件列，只走通知出口，
// 投遞仍受 failure_alert_enabled 政策與通道配置節制（無通道即無外送）
func (s *AuditFailureService) NotifyOngoing(event notifycat.Event, params map[string]string) {
	s.sendNotify(event, params)
}

// EnsureEventRow 確保進行中失效有事件列：Report 當時
// 事件表暫時拒寫會使 in-memory failing=true 但 DB 無列，且 Report 的
// in-memory 去重讓它永不重試——週期評估經此 best-effort 補列（PCI 證據
// 完整性）。不投遞通知、不動 in-memory 狀態；失敗僅 log 待下輪再試
// 起點誠實註記：補列的 StartedAt 為補列時刻而非真實失效起點（真實起點在
// Report 寫庫失敗時已無從取得）——Details 明載，避免稽核把 T0–T1 失效期
// 誤讀為未發生
const failureEventBackfillDetails = "補列事件：原始上報時寫入失敗，起始時間為補列時刻而非實際失效起點"

func (s *AuditFailureService) EnsureEventRow(mechanism, causeCode string, params map[string]string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var existing model.AuditFailureEvent
	switch err := s.db.Where("mechanism = ? AND ended_at IS NULL", mechanism).
		First(&existing).Error; {
	case err == nil:
		return // 列已在
	case errors.Is(err, gorm.ErrRecordNotFound):
		event := model.AuditFailureEvent{Mechanism: mechanism, StartedAt: time.Now(),
			Cause:       CauseText(causeCode, params),
			CauseCode:   causeCode,
			CauseParams: encodeCauseParams(causeCode, params),
			Details:     failureEventBackfillDetails}
		// 跨實例競態由 partial unique index（migration 20260801_failure_event_single_open）
		// 攔下：另一實例同輪補列成功時本次 Create 撞唯一鍵而失敗——已有列即目的達成
		if err := s.db.Create(&event).Error; err != nil {
			log.Printf("[AuditFailure] 失效事件補列失敗（可能為另一實例已補列）(mechanism=%s): %v", mechanism, err)
		}
	default:
		log.Printf("[AuditFailure] 失效事件補列查詢失敗 (mechanism=%s): %v", mechanism, err)
	}
}

// ReconcileOnStartup 啟動時回填重啟遺留的進行中事件（失效
// 狀態為 in-memory，重啟歸零後 open 事件永無人回填）。結束時間取重啟時刻
// 並於 Details 誠實註明非精確；條件仍在時新事件會重新開列。
//
// 例外：狀態可由 DB 謂詞導出的機制
// （kek_retirement）排除在無條件回填之外——以「重評估」取代「盲目關閉」。
// 否則 backlog 跨重啟仍在卻被記為已恢復，PCI 退役證據反成假證據
func (s *AuditFailureService) ReconcileOnStartup() {
	s.mu.Lock()
	defer s.mu.Unlock()

	res := s.db.Model(&model.AuditFailureEvent{}).
		Where("ended_at IS NULL AND mechanism <> ?", model.MechanismKEKRetirement).
		Updates(map[string]any{
			"ended_at": time.Now(),
			"details":  "進程重啟時回填；實際恢復時間不精確（重啟前的失效狀態不跨進程保存）",
		})
	if res.Error != nil {
		log.Printf("[AuditFailure] 啟動回填遺留事件失敗: %v", res.Error)
		return
	}
	if res.RowsAffected > 0 {
		log.Printf("[AuditFailure] 啟動回填 %d 筆重啟遺留的進行中失效事件", res.RowsAffected)
	}
}

// List 失效事件（新到舊，前端失效事件列表）
func (s *AuditFailureService) List(page, pageSize int) ([]model.AuditFailureEvent, int64, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}
	var total int64
	if err := s.db.Model(&model.AuditFailureEvent{}).Count(&total).Error; err != nil {
		return nil, 0, err
	}
	var rows []model.AuditFailureEvent
	err := s.db.Order("started_at DESC").
		Offset((page - 1) * pageSize).Limit(pageSize).Find(&rows).Error
	return rows, total, err
}

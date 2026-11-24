package audit

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/keyvault"
	"github.com/custodexa/backend/internal/notifycat"
	"github.com/custodexa/backend/pkg/crypto"
	"gorm.io/gorm"
)

// 通知的持久投遞程序（所有類別共用；型別名稱沿用系統安全告警時期）。
//
// 單一背景 goroutine，每一輪（RunOnce）依序：
//  0. 讀取全部啟用通道並解密，換新稽核失效退路的通道清單（讀不到就沿用舊清單）。
//  1. syslog 轉發（teePending）。
//  2. 掃描：分派或嘗試次數已達上限、租約已過、仍在進行中的列標為終態；因限流延後超過時窗的紀錄標放棄。
//  3. 分派：取待分派的通知內容（系統事件先於指令告警），認領後在一個交易內解析名稱、決定連結、選通道、
//     為每個通道建立一筆不帶快照的待投遞紀錄，最後以條件更新標為已分派（notification_dispatch.go）。
//  4. 取消：來源通道已停用或已刪除的不帶快照紀錄標為已取消。
//  5. 投遞：依目的地輪流取到期紀錄，認領前判斷不計次的終態，認領時計次，送出並判讀（notification_delivery.go）。
//  6. 回報檢查點：依排入計數與本輪分派結果回報或結束稽核失效（不在交易內、不持鎖）。
//
// 投遞語義是至少一次：payload 帶紀錄上的投遞識別，收端可據此去重。每筆紀錄最多嘗試 notifyMaxAttempts 次，
// 間隔以指數退避到上限；帶快照的紀錄（系統安全告警）用產生當下的目的地，不帶快照的紀錄用通道當下的設定。
// 分級只影響處理順序與顯示，不決定系統安全告警是否送出。
const (
	// systemAlertWebhookEvent webhook 收端契約的事件識別字（不可改）。
	systemAlertWebhookEvent = "system_security_alert"

	systemAlertPollInterval = 2 * time.Second
	systemAlertLease        = 60 * time.Second
	systemAlertBackoffBase  = 1 * time.Second
	systemAlertBackoffMax   = 2 * time.Hour
	systemAlertBatch        = 100
	systemAlertStopWait     = 15 * time.Second
	// systemAlertErrMax 落庫的最後錯誤長度上限（已脫敏）。
	systemAlertErrMax = 500

	// notifyMaxAttempts 每筆待投遞紀錄的嘗試次數上限（含第一次）。
	notifyMaxAttempts = 48
	// notifyDispatchMaxAttempts 每則通知內容的分派次數上限。
	notifyDispatchMaxAttempts = 10
	// notifyPerDestBatch 每個目的地每輪至多取的紀錄數。
	notifyPerDestBatch = 10
	// notifyThrottleWindow 自第一次因限流被延後起的放棄時窗。
	notifyThrottleWindow = 72 * time.Hour
	// notifyPauseMax 限流暫停的上限。
	notifyPauseMax = 2 * time.Hour
)

// outboxWorkerHooks 測試與後續功能的掛點；全部可為 nil。
type outboxWorkerHooks struct {
	// afterCancel 每輪的取消步驟之後、投遞步驟之前。
	afterCancel func()
	// afterPreRead 投遞步驟對一筆紀錄做完認領前的讀取與判斷之後、認領之前。
	afterPreRead func(id uint)
	// afterClaim 認領成功之後；回傳 true 時不再處理這一筆（模擬行程在送出途中結束）。
	afterClaim func(id uint) bool
	// beforeSend 送出前（在逐筆 recover 之內）。
	beforeSend func(id uint)
	// dispatchAfterClaim 分派認領成功之後；回傳 true 時不再處理這一則（模擬行程在分派途中結束）。
	dispatchAfterClaim func(id uint) bool
	// dispatchRead 分派交易讀到內容列之後（在逐列 recover 之內；可回錯讓分派交易失敗）。
	dispatchRead func(msg *model.NotificationMessage) error
	// beforeDispatchFinalize 分派交易建立紀錄之後、收尾的條件更新之前。
	beforeDispatchFinalize func(tx *gorm.DB, id uint)
	// dispatchExtension 分派交易內建立頻道紀錄之後的擴充點（以 savepoint 包住；回錯只回到 savepoint）。
	dispatchExtension func(tx *gorm.DB, msg *model.NotificationMessage) error
	// beforeAbandon 掃描把紀錄標為放棄之前；回傳 cancel 時改標已取消並以 reason 為結束原因。
	beforeAbandon func(row model.NotificationDelivery) (cancel bool, reason string)
	// onAbandonInTx 紀錄在放棄交易內轉為放棄之後（同一交易）。
	onAbandonInTx func(tx *gorm.DB, row model.NotificationDelivery, reason string)
	// beforeAbandonNotice 投遞放棄通知寫入內容列之前呼叫；回錯即當成寫入失敗（故障注入用）
	beforeAbandonNotice func() error
	// beforeAbandonThrottle 投遞放棄通知的節流條件更新之前呼叫（並行測試的會合點）
	beforeAbandonThrottle func()
	// afterLookup 個人訊息的外部查詢回應之後、第二次送出前檢查之前（模擬查詢期間單被處理）
	afterLookup func(id uint)
	// beforeTargetedRows 分派交易寫入個人訊息紀錄之前（在 savepoint 內；回錯即當成寫入失敗）
	beforeTargetedRows func(tx *gorm.DB) error
	// beforeTargetedThrottle 未能送達事件的節流條件更新之前（並行測試的會合點）
	beforeTargetedThrottle func()
	// beforeTargetedNotice 未能送達事件寫入內容列之前；回錯即當成寫入失敗
	beforeTargetedNotice func() error
}

// SystemAlertOutboxWorker 通知持久投遞程序。
type SystemAlertOutboxWorker struct {
	db    *gorm.DB
	codec crypto.ColumnCodec

	// 以下欄位可由測試覆寫。
	now          func() time.Time
	tee          func(model.CommandAlert)
	interval     time.Duration
	lease        time.Duration
	backoffBase  time.Duration
	backoffMax   time.Duration
	httpTimeout  time.Duration
	transport    http.RoundTripper
	risks        notifyRiskEvaluator
	maxAttempts  int
	dispatchMax  int
	batch        int
	perDestBatch int
	throttleFor  time.Duration
	reporter     AuditFailureAlerter
	// sleep 限速目的地送出間隔的等待（測試以可控時鐘覆寫）。
	sleep func(time.Duration)
	hooks outboxWorkerHooks

	// stats 排入成敗計數（與排入介面共用）。
	stats *EnqueueStats
	// fallback 稽核失效退路的通道清單（與排入介面共用；每輪開頭換新）。
	fallback *AuditFallbackList

	// 定向通知的收件人判定（UseTargetedJudge 登錄）與求得逾時（0＝targetedResolveTimeout；測試可縮短）。
	targetedMu      sync.RWMutex
	targeted        map[notifycat.Event]TargetedJudge
	targetedTimeout time.Duration

	// 目的地的記憶體狀態（限流暫停、上次送出時刻）。
	destMu sync.Mutex
	dests  map[deliveryDestKey]*destRuntime

	// 回報檢查點的狀態（只由執行 RunOnce 的 goroutine 讀寫）。
	roundMu         sync.Mutex
	enqFailChecked  uint64
	enqOpen         bool
	dispOpen        bool
	roundDispFailed int
	roundRegularOK  bool

	wake      chan struct{}
	stopCh    chan struct{}
	doneCh    chan struct{}
	startOnce sync.Once
	stopOnce  sync.Once
}

// NewSystemAlertOutboxWorker 建立投遞程序（不啟動）。codec 為通道網址與秘密的信封解密器，nil＝明文直通（單測）。
func NewSystemAlertOutboxWorker(db *gorm.DB, codec crypto.ColumnCodec) *SystemAlertOutboxWorker {
	return &SystemAlertOutboxWorker{
		db:           db,
		codec:        codec,
		now:          func() time.Time { return time.Now().UTC() },
		tee:          defaultSystemAlertTee,
		interval:     systemAlertPollInterval,
		lease:        systemAlertLease,
		backoffBase:  systemAlertBackoffBase,
		backoffMax:   systemAlertBackoffMax,
		httpTimeout:  notifyHTTPTimeout,
		maxAttempts:  notifyMaxAttempts,
		dispatchMax:  notifyDispatchMaxAttempts,
		batch:        systemAlertBatch,
		perDestBatch: notifyPerDestBatch,
		throttleFor:  notifyThrottleWindow,
		sleep:        time.Sleep,
		dests:        map[deliveryDestKey]*destRuntime{},
		wake:         make(chan struct{}, 1),
		stopCh:       make(chan struct{}),
		doneCh:       make(chan struct{}),
	}
}

// SetPollInterval 調整輪詢週期（須在 Start 之前呼叫；跨套件的整合測試用來縮短等待）。
func (w *SystemAlertOutboxWorker) SetPollInterval(d time.Duration) {
	if d > 0 {
		w.interval = d
	}
}

// UseAuditFallback 指定稽核失效退路的通道清單（組裝根以排入介面的清單呼叫一次）。
func (w *SystemAlertOutboxWorker) UseAuditFallback(l *AuditFallbackList) {
	w.fallback = l
}

// refreshAuditFallback 讀取全部啟用通道並解密，成功就整份換掉退路清單；讀不到就沿用舊清單。
func (w *SystemAlertOutboxWorker) refreshAuditFallback() {
	if w.fallback == nil {
		return
	}
	channels, err := loadEnabledChannelsPlain(w.db, w.codec)
	if err != nil {
		log.Printf("[NotificationOutbox] 讀取啟用通道失敗，稽核失效退路沿用上一份清單: %v", err)
		return
	}
	w.fallback.replace(channels)
}

// UseEnqueueStats 指定排入成敗計數的來源（組裝根以排入介面的計數呼叫一次）。
func (w *SystemAlertOutboxWorker) UseEnqueueStats(s *EnqueueStats) {
	w.stats = s
}

func defaultSystemAlertTee(row model.CommandAlert) {
	if f := GetSyslogForwarder(); f != nil {
		f.EnqueueAlert(&row)
	}
}

// Start 啟動背景迴圈（冪等）。
func (w *SystemAlertOutboxWorker) Start() {
	w.startOnce.Do(func() { go w.loop() })
}

// Stop 停止並排空：不再開始新的投遞，等進行中的那一筆結束（受 HTTP 逾時約束）後返回。
// 未處理的列保持原狀，重啟後依資料庫狀態續送。未曾 Start 時直接返回。
func (w *SystemAlertOutboxWorker) Stop() {
	w.stopOnce.Do(func() { close(w.stopCh) })
	w.startOnce.Do(func() { close(w.doneCh) }) // 未啟動：直接標記已完成
	select {
	case <-w.doneCh:
	case <-time.After(systemAlertStopWait):
		log.Printf("[NotificationOutbox] 關機排空逾時，未完成的列保留於資料庫待重啟續送")
	}
}

// Wake 縮短下一輪的等待；不是正確性條件，輪詢本身就會處理所有到期的列。
func (w *SystemAlertOutboxWorker) Wake() {
	select {
	case w.wake <- struct{}{}:
	default:
	}
}

func (w *SystemAlertOutboxWorker) stopped() bool {
	select {
	case <-w.stopCh:
		return true
	default:
		return false
	}
}

func (w *SystemAlertOutboxWorker) loop() {
	defer close(w.doneCh)
	t := time.NewTicker(w.interval)
	defer t.Stop()
	for {
		w.RunOnce()
		select {
		case <-w.stopCh:
			return
		case <-t.C:
		case <-w.wake:
		}
	}
}

// RunOnce 執行一輪（見檔頭的步驟）。回傳本輪送達的紀錄數。迴圈與測試共用；各步失敗只記 log，下一輪重試。
func (w *SystemAlertOutboxWorker) RunOnce() int {
	if w == nil || w.db == nil {
		return 0
	}
	w.roundMu.Lock()
	w.roundDispFailed = 0
	w.roundRegularOK = false
	w.roundMu.Unlock()

	w.refreshAuditFallback()
	w.teePending()
	w.scan()
	w.dispatchPending()
	w.cancelChannelGone()
	if w.hooks.afterCancel != nil {
		w.hooks.afterCancel()
	}
	delivered := w.deliverDue()
	w.reportCheckpoint()
	return delivered
}

// teePending 把尚未離機轉發的明細各轉發一次並標記。
func (w *SystemAlertOutboxWorker) teePending() {
	var details []model.SystemAlertDetail
	if err := w.db.Where("published_at IS NULL").Order("alert_id").Limit(systemAlertBatch).Find(&details).Error; err != nil {
		log.Printf("[NotificationOutbox] 讀取待轉發明細失敗: %v", err)
		return
	}
	for _, d := range details {
		if w.stopped() {
			return
		}
		var rows []model.CommandAlert
		if err := w.db.Where("id = ?", d.AlertID).Limit(1).Find(&rows).Error; err != nil {
			log.Printf("[NotificationOutbox] 讀取告警列失敗 (alert_id=%d): %v", d.AlertID, err)
			continue
		}
		if len(rows) == 1 && w.tee != nil {
			w.tee(rows[0])
		}
		now := w.now()
		if err := w.db.Model(&model.SystemAlertDetail{}).
			Where("alert_id = ? AND published_at IS NULL", d.AlertID).
			Update("published_at", now).Error; err != nil {
			log.Printf("[NotificationOutbox] 標記離機轉發完成失敗 (alert_id=%d): %v", d.AlertID, err)
		}
	}
}

func activeOutboxStates() []string {
	return []string{model.NotificationDeliveryPending, model.NotificationDeliveryRetrying}
}

// scan 掃描：分派次數達上限的內容列標失敗；嘗試次數達上限或因限流延後超過時窗的紀錄標放棄。
// 只處理租約已過的列（認領後當掉的列，租約到期才由這裡收尾）。
func (w *SystemAlertOutboxWorker) scan() {
	now := w.now()
	var msgs []struct {
		ID       uint
		EventKey string
	}
	if err := w.db.Model(&model.NotificationMessage{}).Select("id, event_key").
		Where("state = ? AND dispatch_attempts >= ? AND (lease_until IS NULL OR lease_until < ?)",
			model.NotificationMessagePending, w.dispatchMax, now).
		Order("id").Limit(w.batch).Find(&msgs).Error; err != nil {
		log.Printf("[NotificationOutbox] 讀取分派逾限的內容列失敗: %v", err)
	}
	for _, m := range msgs {
		res := w.db.Model(&model.NotificationMessage{}).
			Where("id = ? AND state = ? AND (lease_until IS NULL OR lease_until < ?)", m.ID, model.NotificationMessagePending, now).
			Updates(map[string]any{"state": model.NotificationMessageFailed,
				"fail_reason": model.NotificationMessageFailDispatchError, "lease_until": nil})
		if res.Error != nil || res.RowsAffected != 1 {
			continue
		}
		w.noteDispatchFailed(m.ID, m.EventKey, model.NotificationMessageFailDispatchError)
	}

	var rows []model.NotificationDelivery
	if err := w.db.Where("state IN ? AND (lease_until IS NULL OR lease_until < ?) AND (attempts >= ? OR (throttled_since IS NOT NULL AND throttled_since <= ?))",
		activeOutboxStates(), now, w.maxAttempts, now.Add(-w.throttleFor)).
		Order("id").Limit(w.batch).Find(&rows).Error; err != nil {
		log.Printf("[NotificationOutbox] 讀取應放棄的紀錄失敗: %v", err)
		return
	}
	for _, row := range rows {
		reason := model.NotificationEndRateLimited
		if row.Attempts >= w.maxAttempts {
			reason = model.NotificationEndMaxAttempts
		}
		if w.hooks.beforeAbandon != nil {
			if cancel, why := w.hooks.beforeAbandon(row); cancel {
				if why == "" {
					why = model.NotificationEndPrecheckCanceled
				}
				w.terminate(row, model.NotificationDeliveryCanceled, why, now, true)
				continue
			}
		}
		// 個人訊息放棄前先重驗：已了結或已不具資格者改標已取消，不產生未能送達事件
		if cancel, why := w.targetedBeforeAbandon(row); cancel {
			w.terminate(row, model.NotificationDeliveryCanceled, why, now, true)
			continue
		}
		w.abandon(row, reason, now, true)
	}
}

// terminate 把紀錄轉為終態（取消或放棄），不改嘗試次數。requireUnleased 為真時只處理租約已過的列
// （認領前與掃描）；為假時是持有租約者自己收尾。放棄經 abandon 進行。
func (w *SystemAlertOutboxWorker) terminate(row model.NotificationDelivery, state, reason string, now time.Time, requireUnleased bool) bool {
	if state == model.NotificationDeliveryAbandoned {
		return w.abandon(row, reason, now, requireUnleased)
	}
	q := w.db.Model(&model.NotificationDelivery{}).Where("id = ? AND state IN ?", row.ID, activeOutboxStates())
	if requireUnleased {
		q = q.Where("(lease_until IS NULL OR lease_until < ?)", now)
	}
	res := q.Updates(map[string]any{"state": state, "end_reason": reason, "lease_until": nil, "ended_at": now})
	if res.Error != nil {
		log.Printf("[NotificationOutbox] 紀錄轉為終態失敗 (id=%d): %v", row.ID, res.Error)
		return false
	}
	return res.RowsAffected == 1
}

// abandon 在一個交易內把紀錄標為放棄並呼叫放棄掛點（同一交易）。
func (w *SystemAlertOutboxWorker) abandon(row model.NotificationDelivery, reason string, now time.Time, requireUnleased bool) bool {
	done := false
	err := w.db.Transaction(func(tx *gorm.DB) error {
		q := tx.Model(&model.NotificationDelivery{}).Where("id = ? AND state IN ?", row.ID, activeOutboxStates())
		if requireUnleased {
			q = q.Where("(lease_until IS NULL OR lease_until < ?)", now)
		}
		res := q.Updates(map[string]any{"state": model.NotificationDeliveryAbandoned, "end_reason": reason, "lease_until": nil, "ended_at": now})
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected != 1 {
			return nil
		}
		done = true
		w.abandonNoticeInTx(tx, row, reason, now)
		w.targetedAbandonNoticeInTx(tx, row, reason, now)
		if w.hooks.onAbandonInTx != nil {
			w.hooks.onAbandonInTx(tx, row, reason)
		}
		return nil
	})
	if err != nil {
		log.Printf("[NotificationOutbox] 標記放棄失敗 (id=%d): %v", row.ID, err)
		return false
	}
	if done {
		log.Printf("[NotificationOutbox] 投遞放棄 (outbox_id=%d, category=%s, 嘗試 %d 次, 原因 %s)", row.ID, row.Category, row.Attempts, reason)
	}
	return done
}

// cancelChannelGone 把來源通道已停用或已刪除的不帶快照紀錄標為已取消（帶快照的紀錄照送）。
func (w *SystemAlertOutboxWorker) cancelChannelGone() {
	now := w.now()
	base := func() *gorm.DB {
		return w.db.Model(&model.NotificationDelivery{}).
			Where("category <> ? AND state IN ? AND (lease_until IS NULL OR lease_until < ?)",
				model.NotificationCategorySystemSecurityAlert, activeOutboxStates(), now)
	}
	if err := base().
		Where("source_channel_id IN (?)", w.db.Model(&model.NotificationChannel{}).Select("id").Where("enabled = ?", false)).
		Updates(map[string]any{"state": model.NotificationDeliveryCanceled, "end_reason": model.NotificationEndChannelDisabled, "lease_until": nil, "ended_at": now}).Error; err != nil {
		log.Printf("[NotificationOutbox] 取消停用通道的紀錄失敗: %v", err)
	}
	if err := base().
		Where("(source_channel_id IS NULL OR source_channel_id NOT IN (?))", w.db.Model(&model.NotificationChannel{}).Select("id")).
		Updates(map[string]any{"state": model.NotificationDeliveryCanceled, "end_reason": model.NotificationEndChannelDeleted, "lease_until": nil, "ended_at": now}).Error; err != nil {
		log.Printf("[NotificationOutbox] 取消已刪除通道的紀錄失敗: %v", err)
	}
}

// noteDispatchFailed 記下一則內容轉為分派失敗；稽核失效一族只記 log（避免自我循環）。
func (w *SystemAlertOutboxWorker) noteDispatchFailed(id uint, eventKey, reason string) {
	log.Printf("[NotificationOutbox] 通知內容分派失敗 (message_id=%d, event=%s, 原因 %s)", id, eventKey, reason)
	if isAuditFailureFamily(eventKey) {
		return
	}
	w.roundMu.Lock()
	w.roundDispFailed++
	w.roundMu.Unlock()
}

func (w *SystemAlertOutboxWorker) noteRegularDispatched() {
	w.roundMu.Lock()
	w.roundRegularOK = true
	w.roundMu.Unlock()
}

func isAuditFailureFamily(eventKey string) bool {
	spec, ok := notifycat.Spec(notifycat.Event(eventKey))
	return ok && spec.AuditFailureFamily
}

func (w *SystemAlertOutboxWorker) failureAlerter() AuditFailureAlerter {
	if w.reporter != nil {
		return w.reporter
	}
	if s := GetAuditFailure(); s != nil {
		return s
	}
	return nil
}

// reportCheckpoint 每輪結束時依排入計數與本輪分派結果回報或結束稽核失效。
// 由執行 RunOnce 的 goroutine 呼叫，不在任何交易內、不持任何鎖。
func (w *SystemAlertOutboxWorker) reportCheckpoint() {
	rep := w.failureAlerter()
	failSeq, okSeq, event, errText := w.stats.snapshot()
	w.roundMu.Lock()
	dispFailed, regularOK := w.roundDispFailed, w.roundRegularOK
	reportEnq := failSeq > w.enqFailChecked
	if reportEnq {
		w.enqFailChecked = failSeq
		w.enqOpen = true
	}
	resolveEnq := !reportEnq && w.enqOpen && okSeq > failSeq
	if resolveEnq {
		w.enqOpen = false
	}
	reportDisp := dispFailed > 0
	if reportDisp {
		w.dispOpen = true
	}
	resolveDisp := !reportDisp && regularOK && w.dispOpen
	if resolveDisp {
		w.dispOpen = false
	}
	w.roundMu.Unlock()
	if rep == nil {
		return
	}
	if reportEnq {
		rep.ReportWithCounts(model.MechanismNotificationDelivery, model.CauseNotificationEnqueueFailed,
			map[string]string{"event": event, "error": errText}, nil)
	}
	if resolveEnq {
		rep.Resolve(model.MechanismNotificationDelivery)
	}
	if reportDisp {
		rep.ReportWithCounts(model.MechanismNotificationDispatch, model.CauseNotificationDispatchFailed,
			map[string]string{"failed_messages": strconv.Itoa(dispFailed)}, nil)
	}
	if resolveDisp {
		rep.Resolve(model.MechanismNotificationDispatch)
	}
}

// 投遞給 webhook 的機器 payload：散文不入，收端以 delivery_id 去重。
// delivery_id 是佇列列上排入當下隨機產生的識別（不是列編號）：同一列重送不變，
// 還原備份後新建的列必為新值，不會與還原前發出的識別重複。
type systemAlertWebhookPayload struct {
	Event      string                  `json:"event"`
	Alert      systemAlertWebhookAlert `json:"alert"`
	DeliveryID string                  `json:"delivery_id"`
	SentAt     string                  `json:"sent_at"`
	// Notification 三種形狀共用的新物件（純加法；既有欄位不動）。
	Notification *notificationObject `json:"notification,omitempty"`
}

type systemAlertWebhookAlert struct {
	ID         uint                   `json:"id"`
	Type       string                 `json:"type"`
	Severity   string                 `json:"severity"`
	OccurredAt string                 `json:"occurred_at"`
	Actor      systemAlertWebhookUser `json:"actor"`
	Target     systemAlertWebhookTgt  `json:"target"`
	Params     map[string]any         `json:"params"`
}

type systemAlertWebhookUser struct {
	UserID   uint   `json:"user_id"`
	Username string `json:"username"`
}

type systemAlertWebhookTgt struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
}

// snapshotDestination 解開帶快照紀錄的目的地；解不開時回錯（不可能成功，由呼叫端放棄）。
func (w *SystemAlertOutboxWorker) snapshotDestination(out model.NotificationDelivery) (ChannelDestination, error) {
	plainURL, err := readChannelValue(w.codec, keyvault.RefSystemAlertOutboxURL, out.URLEnc)
	if err != nil || plainURL == "" {
		return ChannelDestination{}, errors.New("無法解開投遞目的地")
	}
	secret, err := readChannelValue(w.codec, keyvault.RefSystemAlertOutboxSecret, out.SecretEnc)
	if err != nil {
		return ChannelDestination{}, errors.New("無法解開投遞目的地")
	}
	return ChannelDestination{Type: out.DestType, URL: plainURL, Secret: secret, Target: out.DestTarget, Language: out.DestLanguage}, nil
}

// renderSnapshot 組出系統安全告警紀錄送往 dest 的本文。
//
// 類型未登錄、明細不存在或參數無法解析時降級而不失敗：webhook 照送完整形狀、alert.params 為空物件、
// 新物件標 degraded；文字型別走降級模板。告警列本身讀不到時才回錯。
func (w *SystemAlertOutboxWorker) renderSnapshot(out model.NotificationDelivery, dest ChannelDestination) (body []byte, err error) {
	var alert model.CommandAlert
	if err = w.db.First(&alert, derefUint(out.AlertID)).Error; err != nil {
		return nil, fmt.Errorf("讀取告警列失敗: %w", err)
	}
	degraded := false
	var detail model.SystemAlertDetail
	if derr := w.db.First(&detail, derefUint(out.AlertID)).Error; derr != nil {
		log.Printf("[NotificationOutbox] 系統安全告警明細讀不到，降級送出 (alert_id=%d): %v", alert.ID, derr)
		detail = model.SystemAlertDetail{AlertID: alert.ID}
		degraded = true
	}
	params := map[string]string{}
	if detail.Params != "" {
		if perr := json.Unmarshal([]byte(detail.Params), &params); perr != nil {
			log.Printf("[NotificationOutbox] 系統安全告警明細無法解析，降級送出 (alert_id=%d)", alert.ID)
			params = map[string]string{}
			degraded = true
		}
	}
	actor := params["actor"]
	delete(params, "actor")
	event, ok := notifycat.SystemAlertEvent(detail.AlertType)
	if !ok {
		event = notifycat.Event(detail.AlertType)
		degraded = true
	}

	if channelRendersText(dest.Type) {
		in := map[string]string{"actor": actor, "severity": alert.Severity}
		for k, v := range params {
			in[k] = v
		}
		var title, text, link string
		if !degraded {
			link = composeNotificationLink(notifycat.LinkPath(event, in))
		}
		if clean, verr := notifycat.Validate(event, in); verr == nil && !degraded {
			title, text = notifycat.RenderLinked(out.DestLanguage, event, clean, link != "")
		} else {
			kept, _ := notifycat.FilterDeclared(event, in)
			title, text = notifycat.RenderDegraded(out.DestLanguage, event, kept)
		}
		slackText := notifycat.ComposeSlack(out.DestLanguage, notifycat.SlackMessage{
			Prefix: notifycat.SeveritySymbol(alert.Severity), Title: title, Severity: alert.Severity, Body: text,
			Extra:    notifycat.Phrase(out.DestLanguage, notifycat.LexiconAlertKindText, model.AlertKindSystemSecurity),
			Occurred: alert.TriggeredAt, Link: link, LinkLabel: notifycat.LinkLabelOf(event),
		})
		return buildRenderedBody(dest.Type, dest, OutboundMessage{Text: slackText})
	}

	wire := map[string]any{}
	if !degraded {
		wire = notifycat.WireParams(event, params)
	}
	now := w.now()
	payload := systemAlertWebhookPayload{
		Event: systemAlertWebhookEvent,
		Alert: systemAlertWebhookAlert{
			ID:         alert.ID,
			Type:       detail.AlertType,
			Severity:   alert.Severity,
			OccurredAt: alert.TriggeredAt.UTC().Format(time.RFC3339),
			Actor:      systemAlertWebhookUser{UserID: alert.UserID, Username: actor},
			Target:     systemAlertWebhookTgt{Kind: detail.TargetKind, ID: detail.TargetID},
			Params:     wire,
		},
		DeliveryID:   out.DeliveryKey,
		SentAt:       now.Format(time.RFC3339),
		Notification: systemAlertObject(alert, detail, actor, params, event, degraded, out.DeliveryKey, now),
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	return buildRenderedBody(dest.Type, dest, OutboundMessage{JSON: raw})
}

// derefUint 可空識別碼的值；nil 為 0（不存在的主鍵，查詢結果為找不到）。
func derefUint(p *uint) uint {
	if p == nil {
		return 0
	}
	return *p
}

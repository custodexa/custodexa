package audit

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/keyvault"
	"github.com/custodexa/backend/internal/notifycat"
	"github.com/custodexa/backend/pkg/crypto"
	"gorm.io/gorm"
)

// 系統告警持久投遞程序。
//
// 單一背景 goroutine：每個輪詢週期（或被 Wake 喚醒）先把尚未離機轉發的明細各 tee 一次，
// 再以租約認領到期的佇列列逐筆投遞。投遞語義是**至少一次**：payload 帶佇列列上的隨機投遞識別，
// 收端可據此去重；失敗以指數退避續送、重啟後依資料庫狀態接續，自建立起超過時窗仍未成功即標記放棄。
// 重送一律使用佇列列上的目的地快照，通道之後改址或刪除都不影響。
//
// 分級只影響處理順序與顯示，**不決定是否送出**：每一列都會被處理，不看任何通道門檻。
const (
	// systemAlertWebhookEvent webhook 收端契約的事件識別字（不可改）。
	systemAlertWebhookEvent = "system_security_alert"

	systemAlertPollInterval = 2 * time.Second
	systemAlertLease        = 60 * time.Second
	systemAlertBackoffBase  = 1 * time.Second
	systemAlertBackoffMax   = 10 * time.Minute
	systemAlertAbandonAfter = 72 * time.Hour
	systemAlertBatch        = 100
	systemAlertStopWait     = 15 * time.Second
	// systemAlertErrMax 落庫的最後錯誤長度上限（已脫敏）。
	systemAlertErrMax = 500
)

// SystemAlertOutboxWorker 系統告警持久投遞程序。
type SystemAlertOutboxWorker struct {
	db     *gorm.DB
	codec  crypto.ColumnCodec
	client *http.Client

	// 以下欄位可由測試覆寫。
	now          func() time.Time
	tee          func(model.CommandAlert)
	interval     time.Duration
	lease        time.Duration
	backoffBase  time.Duration
	backoffMax   time.Duration
	abandonAfter time.Duration

	wake      chan struct{}
	stopCh    chan struct{}
	doneCh    chan struct{}
	startOnce sync.Once
	stopOnce  sync.Once
}

// NewSystemAlertOutboxWorker 建立投遞程序（不啟動）。codec 為通道網址與簽章密鑰的信封解密器，nil＝明文直通（單測）。
func NewSystemAlertOutboxWorker(db *gorm.DB, codec crypto.ColumnCodec) *SystemAlertOutboxWorker {
	return &SystemAlertOutboxWorker{
		db:           db,
		codec:        codec,
		client:       &http.Client{Timeout: notifyHTTPTimeout},
		now:          func() time.Time { return time.Now().UTC() },
		tee:          defaultSystemAlertTee,
		interval:     systemAlertPollInterval,
		lease:        systemAlertLease,
		backoffBase:  systemAlertBackoffBase,
		backoffMax:   systemAlertBackoffMax,
		abandonAfter: systemAlertAbandonAfter,
		wake:         make(chan struct{}, 1),
		stopCh:       make(chan struct{}),
		doneCh:       make(chan struct{}),
	}
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
		log.Printf("[SystemAlertOutbox] 關機排空逾時，未完成的列保留於資料庫待重啟續送")
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

// RunOnce 執行一輪：離機轉發、放棄過期列、依分級認領並投遞到期列。回傳本輪投遞成功的列數。
// 迴圈與測試共用；各步失敗只記 log，下一輪重試。
func (w *SystemAlertOutboxWorker) RunOnce() int {
	if w == nil || w.db == nil {
		return 0
	}
	w.teePending()
	w.abandonExpired()
	return w.deliverDue()
}

// teePending 把尚未離機轉發的明細各轉發一次並標記。
func (w *SystemAlertOutboxWorker) teePending() {
	var details []model.SystemAlertDetail
	if err := w.db.Where("published_at IS NULL").Order("alert_id").Limit(systemAlertBatch).Find(&details).Error; err != nil {
		log.Printf("[SystemAlertOutbox] 讀取待轉發明細失敗: %v", err)
		return
	}
	for _, d := range details {
		if w.stopped() {
			return
		}
		var rows []model.CommandAlert
		if err := w.db.Where("id = ?", d.AlertID).Limit(1).Find(&rows).Error; err != nil {
			log.Printf("[SystemAlertOutbox] 讀取告警列失敗 (alert_id=%d): %v", d.AlertID, err)
			continue
		}
		if len(rows) == 1 && w.tee != nil {
			w.tee(rows[0])
		}
		now := w.now()
		if err := w.db.Model(&model.SystemAlertDetail{}).
			Where("alert_id = ? AND published_at IS NULL", d.AlertID).
			Update("published_at", now).Error; err != nil {
			log.Printf("[SystemAlertOutbox] 標記離機轉發完成失敗 (alert_id=%d): %v", d.AlertID, err)
		}
	}
}

// abandonExpired 自建立起超過時窗仍未成功的列標為放棄。
func (w *SystemAlertOutboxWorker) abandonExpired() {
	cutoff := w.now().Add(-w.abandonAfter)
	res := w.db.Model(&model.SystemAlertOutbox{}).
		Where("state IN ? AND created_at <= ?", activeOutboxStates(), cutoff).
		Updates(map[string]any{"state": model.SystemAlertOutboxAbandoned, "lease_until": nil})
	if res.Error != nil {
		log.Printf("[SystemAlertOutbox] 標記放棄失敗: %v", res.Error)
		return
	}
	if res.RowsAffected > 0 {
		log.Printf("[SystemAlertOutbox] %d 筆投遞超過 %s 仍未成功，已標記放棄", res.RowsAffected, w.abandonAfter)
	}
}

func activeOutboxStates() []string {
	return []string{model.SystemAlertOutboxPending, model.SystemAlertOutboxRetrying}
}

// deliverDue 依分級高到低、編號小到大認領到期列並逐筆投遞。
func (w *SystemAlertOutboxWorker) deliverDue() int {
	now := w.now()
	var ids []uint
	err := w.db.Table("system_alert_outbox AS o").
		Joins("JOIN command_alerts a ON a.id = o.alert_id").
		Where("o.state IN ? AND o.next_attempt_at <= ? AND (o.lease_until IS NULL OR o.lease_until < ?)",
			activeOutboxStates(), now, now).
		Order("CASE a.severity WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END, o.id").
		Limit(systemAlertBatch).
		Pluck("o.id", &ids).Error
	if err != nil {
		log.Printf("[SystemAlertOutbox] 讀取到期投遞列失敗: %v", err)
		return 0
	}
	delivered := 0
	for _, id := range ids {
		if w.stopped() {
			break
		}
		if w.claimAndDeliver(id) {
			delivered++
		}
	}
	return delivered
}

// claimAndDeliver 以租約認領單列並投遞；回傳是否投遞成功。
func (w *SystemAlertOutboxWorker) claimAndDeliver(id uint) bool {
	now := w.now()
	res := w.db.Model(&model.SystemAlertOutbox{}).
		Where("id = ? AND state IN ? AND (lease_until IS NULL OR lease_until < ?)", id, activeOutboxStates(), now).
		Update("lease_until", now.Add(w.lease))
	if res.Error != nil || res.RowsAffected != 1 {
		return false
	}
	var out model.SystemAlertOutbox
	if err := w.db.First(&out, id).Error; err != nil {
		log.Printf("[SystemAlertOutbox] 讀取投遞列失敗 (id=%d): %v", id, err)
		return false
	}
	plainURL, secret, body, err := w.prepare(out)
	var status int
	if err == nil {
		ch := &model.NotificationChannel{Type: out.DestType, URL: plainURL, Secret: secret}
		status, err = deliverOnce(w.client, ch, body)
		if err != nil {
			err = errors.New(SanitizeDeliveryError(err, plainURL))
		} else if status < 200 || status >= 300 {
			err = fmt.Errorf("HTTP %d", status)
		}
	}
	if err == nil {
		done := w.now()
		if uerr := w.db.Model(&model.SystemAlertOutbox{}).Where("id = ?", id).Updates(map[string]any{
			"state": model.SystemAlertOutboxDelivered, "delivered_at": done,
			"attempts": out.Attempts + 1, "lease_until": nil, "last_error": "",
		}).Error; uerr != nil {
			log.Printf("[SystemAlertOutbox] 標記已送達失敗 (id=%d): %v", id, uerr)
		}
		return true
	}
	w.recordFailure(out, err)
	return false
}

// recordFailure 登記一次失敗：退避後重試，或在時窗用盡時放棄。
func (w *SystemAlertOutboxWorker) recordFailure(out model.SystemAlertOutbox, cause error) {
	attempts := out.Attempts + 1
	now := w.now()
	msg := truncateRunes(cause.Error(), systemAlertErrMax)
	upd := map[string]any{"attempts": attempts, "lease_until": nil, "last_error": msg}
	next := now.Add(w.backoffFor(attempts))
	if !now.Before(out.CreatedAt.Add(w.abandonAfter)) {
		upd["state"] = model.SystemAlertOutboxAbandoned
		log.Printf("[SystemAlertOutbox] 投遞放棄 (outbox_id=%d, alert_id=%d, 嘗試 %d 次): %s", out.ID, out.AlertID, attempts, msg)
	} else {
		upd["state"] = model.SystemAlertOutboxRetrying
		upd["next_attempt_at"] = next
		log.Printf("[SystemAlertOutbox] 投遞失敗將重試 (outbox_id=%d, alert_id=%d, 第 %d 次): %s", out.ID, out.AlertID, attempts, msg)
	}
	if err := w.db.Model(&model.SystemAlertOutbox{}).Where("id = ?", out.ID).Updates(upd).Error; err != nil {
		log.Printf("[SystemAlertOutbox] 登記失敗狀態失敗 (id=%d): %v", out.ID, err)
	}
}

// backoffFor 第 n 次失敗後的等待：base 起倍增，上限 backoffMax。
func (w *SystemAlertOutboxWorker) backoffFor(attempts int) time.Duration {
	d := w.backoffBase
	for i := 1; i < attempts && d < w.backoffMax; i++ {
		d *= 2
	}
	if d > w.backoffMax {
		d = w.backoffMax
	}
	return d
}

// 投遞給 webhook 的機器 payload：散文不入，收端以 delivery_id 去重。
// delivery_id 是佇列列上排入當下隨機產生的識別（不是列編號）：同一列重送不變，
// 還原備份後新建的列必為新值，不會與還原前發出的識別重複。
type systemAlertWebhookPayload struct {
	Event      string                  `json:"event"`
	Alert      systemAlertWebhookAlert `json:"alert"`
	DeliveryID string                  `json:"delivery_id"`
	SentAt     string                  `json:"sent_at"`
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

// prepare 解開目的地快照並組出送出的 body。
func (w *SystemAlertOutboxWorker) prepare(out model.SystemAlertOutbox) (plainURL, secret string, body []byte, err error) {
	if plainURL, err = readChannelValue(w.codec, keyvault.RefSystemAlertOutboxURL, out.URLEnc); err != nil {
		return "", "", nil, errors.New("無法解開投遞目的地")
	}
	if secret, err = readChannelValue(w.codec, keyvault.RefSystemAlertOutboxSecret, out.SecretEnc); err != nil {
		return "", "", nil, errors.New("無法解開投遞目的地")
	}
	var alert model.CommandAlert
	if err = w.db.First(&alert, out.AlertID).Error; err != nil {
		return "", "", nil, fmt.Errorf("讀取告警列失敗: %w", err)
	}
	var detail model.SystemAlertDetail
	if err = w.db.First(&detail, out.AlertID).Error; err != nil {
		return "", "", nil, fmt.Errorf("讀取告警明細失敗: %w", err)
	}
	params := map[string]string{}
	if detail.Params != "" {
		if err = json.Unmarshal([]byte(detail.Params), &params); err != nil {
			return "", "", nil, fmt.Errorf("告警參數格式錯誤: %w", err)
		}
	}
	actor := params["actor"]
	delete(params, "actor")
	event, ok := notifycat.SystemAlertEvent(detail.AlertType)
	if !ok {
		return "", "", nil, fmt.Errorf("未登錄的系統告警類型 %s", detail.AlertType)
	}

	if out.DestType == model.NotificationChannelTypeSlack {
		in := map[string]string{"actor": actor, "severity": alert.Severity}
		for k, v := range params {
			in[k] = v
		}
		var title, text string
		if clean, verr := notifycat.Validate(event, in); verr == nil {
			title, text = notifycat.Render(out.DestLanguage, event, clean)
		} else {
			kept, _ := notifycat.FilterDeclared(event, in)
			title, text = notifycat.RenderDegraded(out.DestLanguage, event, kept)
		}
		body, err = json.Marshal(map[string]string{"text": fmt.Sprintf(":warning: *%s*\n%s", title, text)})
		return plainURL, secret, body, err
	}

	payload := systemAlertWebhookPayload{
		Event: systemAlertWebhookEvent,
		Alert: systemAlertWebhookAlert{
			ID:         alert.ID,
			Type:       detail.AlertType,
			Severity:   alert.Severity,
			OccurredAt: alert.TriggeredAt.UTC().Format(time.RFC3339),
			Actor:      systemAlertWebhookUser{UserID: alert.UserID, Username: actor},
			Target:     systemAlertWebhookTgt{Kind: detail.TargetKind, ID: detail.TargetID},
			Params:     notifycat.WireParams(event, params),
		},
		DeliveryID: out.DeliveryKey,
		SentAt:     w.now().Format(time.RFC3339),
	}
	body, err = json.Marshal(payload)
	return plainURL, secret, body, err
}

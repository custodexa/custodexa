package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strconv"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/keyvault"
	"github.com/custodexa/backend/internal/notifycat"
	"gorm.io/gorm"
)

// 定向通知：需要人處理的四個事件，除了照常送到每個通道的頻道，另為需要處理的人各建立一筆個人訊息紀錄。
//
// 收件人判定由產生端的模組在啟動時經 UseTargetedJudge 登錄（本模組不依賴授權模組），判定一律接受呼叫端的
// 資料庫句柄。投遞程序在認領一則內容之後、開啟分派交易之前以一般連線唯讀求得收件人（recover 與逾時包住），
// 分派交易內在建立頻道紀錄之後以 savepoint 包住寫入個人訊息紀錄。求得失敗或寫入失敗時頻道照送、這則沒有
// 個人訊息，並產生未能送達事件；不重試、不回報稽核失效。
//
// 送出前檢查：四個事件登錄同一個檢查。頻道紀錄一律照送；個人訊息紀錄依通道條件（對個人派送仍開著、型別能以
// 個人為對象、網址屬允許清單）與該事件族的判定決定照送或取消，取消原因分「事情已了結」（request_resolved）、
// 「人不對了」（recipient_ineligible）與「對個人派送已關閉」（direct_message_disabled）。

// TargetedVerdict 送出前重驗的結論。
type TargetedVerdict int

const (
	// TargetedNeeded 仍需要這位收件人處理（照送）。
	TargetedNeeded TargetedVerdict = iota
	// TargetedResolved 收件人的權限仍在，但事情已了結（已被決定、撤回、逾期、他已投完票、所列日子都已簽、功能已關閉）。
	TargetedResolved
	// TargetedIneligible 收件人已不具資格（範圍被移除、角色被收回、帳號停用或刪除）。
	TargetedIneligible
)

// TargetedSubject 判定的對象：事件、事件參數（分派前的原始參數）、單號（每日審閱為 0）與判定時刻。
type TargetedSubject struct {
	Event     notifycat.Event
	Params    map[string]string
	RequestID uint
	Now       time.Time
}

// TargetedJudge 一個事件族的收件人判定。Recipients 求收件人（遞增排序）；Verdict 對一位收件人重驗；
// Awaiting 不含收件人條件判斷這張單或這則提醒是否仍需處理（沒有收件人時決定要不要產生未能送達事件）。
type TargetedJudge struct {
	Recipients func(db *gorm.DB, s TargetedSubject) ([]uint, error)
	Verdict    func(db *gorm.DB, s TargetedSubject, userID uint) (TargetedVerdict, error)
	Awaiting   func(db *gorm.DB, s TargetedSubject) (bool, error)
}

// targetedEventKind 會送個人訊息的事件與其種類（未能送達事件的 event_kind）、定向標題（詞庫 dm_title 的鍵）。
// 只有這四個事件能登錄判定；其餘事件（核准、投票進度、拒絕、撤銷等）一律只送頻道。
var targetedEventKind = map[notifycat.Event]struct{ kind, title string }{
	notifycat.EventAccessRequestCreated:    {notifycat.TargetedKindAccessRequest, notifycat.TargetedKindAccessRequest},
	notifycat.EventBreakGlassUsed:          {notifycat.TargetedKindBreakGlass, notifycat.TargetedKindBreakGlass},
	notifycat.EventBreakGlassReviewOverdue: {notifycat.TargetedKindBreakGlassOverdue, notifycat.TargetedKindBreakGlass},
	notifycat.EventDailyReviewOverdue:      {notifycat.TargetedKindDailyReview, notifycat.TargetedKindDailyReview},
}

// targetedResolveTimeout 分派前求得收件人（與沒有收件人時的仍需處理判斷）的逾時。
const targetedResolveTimeout = 10 * time.Second

// errTargetedTimeout 求得收件人逾時。
var errTargetedTimeout = errors.New("求得收件人逾時")

// ErrTargetedEventUnsupported 這個事件不送個人訊息。
var ErrTargetedEventUnsupported = errors.New("這個事件不送個人訊息")

// UseTargetedJudge 登錄一個事件族的收件人判定（組裝根在 Start 之前呼叫），並為該事件登錄送出前檢查。
func (w *SystemAlertOutboxWorker) UseTargetedJudge(event notifycat.Event, j TargetedJudge) error {
	if _, ok := targetedEventKind[event]; !ok {
		return ErrTargetedEventUnsupported
	}
	if j.Recipients == nil || j.Verdict == nil || j.Awaiting == nil {
		return fmt.Errorf("事件 %s 的收件人判定不完整", event)
	}
	w.targetedMu.Lock()
	if w.targeted == nil {
		w.targeted = map[notifycat.Event]TargetedJudge{}
	}
	w.targeted[event] = j
	w.targetedMu.Unlock()
	RegisterDeliveryPrecheck(event, w.targetedPrecheck)
	return nil
}

func (w *SystemAlertOutboxWorker) targetedJudge(event notifycat.Event) (TargetedJudge, bool) {
	w.targetedMu.RLock()
	defer w.targetedMu.RUnlock()
	j, ok := w.targeted[event]
	return j, ok
}

// targetedTitleKeyFor 個人訊息紀錄的定向標題鍵；頻道紀錄或不送個人訊息的事件回空字串。
func targetedTitleKeyFor(row model.NotificationDelivery, msg model.NotificationMessage) string {
	if audienceOfRow(row) != deliveryAudienceUser {
		return ""
	}
	return targetedEventKind[notifycat.Event(msg.EventKey)].title
}

// subjectOf 由內容列組出判定對象。
func subjectOf(eventKey, rawParams string, now time.Time) TargetedSubject {
	params := map[string]string{}
	if rawParams != "" {
		_ = json.Unmarshal([]byte(rawParams), &params)
	}
	s := TargetedSubject{Event: notifycat.Event(eventKey), Params: params, Now: now}
	if n, err := strconv.ParseUint(params["request_id"], 10, 64); err == nil {
		s.RequestID = uint(n)
	}
	return s
}

// runTargeted 以一般連線執行判定：recover 包住、逾時 targetedResolveTimeout（查詢以逾時的 context 執行）。
func runTargeted[T any](db *gorm.DB, timeout time.Duration, fn func(db *gorm.DB) (T, error)) (T, error) {
	var zero T
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	type result struct {
		v   T
		err error
	}
	done := make(chan result, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				done <- result{err: fmt.Errorf("判定發生 panic: %v", r)}
			}
		}()
		v, err := fn(db.WithContext(ctx))
		done <- result{v: v, err: err}
	}()
	select {
	case r := <-done:
		return r.v, r.err
	case <-ctx.Done():
		return zero, errTargetedTimeout
	}
}

// ---- 分派 ----

// targetedPlan 分派交易前求得的結果（nil＝這則不送個人訊息）。
type targetedPlan struct {
	event      notifycat.Event
	channelID  uint
	recipients []uint
	requestID  uint
	// failed 求得出錯、逾時或 panic；noRecipient 沒有收件人而單仍需處理。兩者都只產生未能送達事件。
	failed      bool
	noRecipient bool
}

// directMessageChannel 目前開著對個人派送、可以送出的通道（至多一個）：啟用中、型別能以個人為對象、網址屬允許清單。
func (w *SystemAlertOutboxWorker) directMessageChannel() (uint, bool) {
	var chs []model.NotificationChannel
	if err := w.db.Where("enabled = ? AND direct_message_enabled = ?", true, true).Order("id").Limit(1).Find(&chs).Error; err != nil {
		log.Printf("[NotificationOutbox] 讀取對個人派送的通道失敗: %v", err)
		return 0, false
	}
	if len(chs) == 0 {
		return 0, false
	}
	ch := chs[0]
	plainURL, err := readChannelValue(w.codec, keyvault.RefChannelURL, ch.URL)
	if err != nil {
		return 0, false
	}
	ch.URL = plainURL
	if directMessageDisabledReason(ch) != "" {
		return 0, false
	}
	return ch.ID, true
}

// prepareTargeted 分派交易之前的唯讀擴充點：這則內容屬定向事件、且有可送出的對個人派送通道時，以一般連線求得收件人。
func (w *SystemAlertOutboxWorker) prepareTargeted(id uint) *targetedPlan {
	w.targetedMu.RLock()
	registered := len(w.targeted) > 0
	w.targetedMu.RUnlock()
	if !registered {
		return nil
	}
	var msgs []model.NotificationMessage
	if err := w.db.Select("id, category, event_key, params").Where("id = ?", id).Limit(1).Find(&msgs).Error; err != nil || len(msgs) == 0 {
		return nil
	}
	msg := msgs[0]
	judge, ok := w.targetedJudge(notifycat.Event(msg.EventKey))
	if !ok || msg.Category != model.NotificationCategorySystemEvent {
		return nil
	}
	channelID, ok := w.directMessageChannel()
	if !ok {
		return nil
	}
	subject := subjectOf(msg.EventKey, msg.Params, w.now())
	plan := &targetedPlan{event: subject.Event, channelID: channelID, requestID: subject.RequestID}
	timeout := w.targetedTimeout
	if timeout <= 0 {
		timeout = targetedResolveTimeout
	}
	recips, err := runTargeted(w.db, timeout, func(db *gorm.DB) ([]uint, error) { return judge.Recipients(db, subject) })
	if err != nil {
		log.Printf("[NotificationOutbox] 求得定向收件人失敗，這則只送頻道 (message_id=%d, event=%s): %v", id, msg.EventKey, err)
		plan.failed = true
		return plan
	}
	if len(recips) > 0 {
		plan.recipients = recips
		return plan
	}
	awaiting, err := runTargeted(w.db, timeout, func(db *gorm.DB) (bool, error) { return judge.Awaiting(db, subject) })
	if err != nil {
		log.Printf("[NotificationOutbox] 判斷定向通知是否仍需處理失敗 (message_id=%d, event=%s): %v", id, msg.EventKey, err)
		plan.failed = true
		return plan
	}
	if !awaiting {
		return nil
	}
	plan.noRecipient = true
	return plan
}

// targetedDispatchSavepoint 分派交易內寫入個人訊息紀錄的 savepoint。
const targetedDispatchSavepoint = "notification_dispatch_targeted"

// writeTargetedInTx 分派交易內、頻道紀錄建立之後：以 savepoint 包住為每位收件人建立一筆個人訊息紀錄；
// 寫入失敗回到 savepoint 並改產生未能送達事件（求得失敗）。沒有收件人或求得失敗時只產生未能送達事件。
func (w *SystemAlertOutboxWorker) writeTargetedInTx(tx *gorm.DB, msg *model.NotificationMessage, plan *targetedPlan, now time.Time) {
	switch {
	case plan.failed:
		w.targetedUndeliveredInTx(tx, plan.channelID, notifycat.TargetedReasonResolveFailed, targetedEventKind[plan.event].kind, plan.requestID, now)
		return
	case plan.noRecipient:
		w.targetedUndeliveredInTx(tx, plan.channelID, notifycat.TargetedReasonNoRecipient, targetedEventKind[plan.event].kind, plan.requestID, now)
		return
	}
	if err := tx.SavePoint(targetedDispatchSavepoint).Error; err != nil {
		log.Printf("[NotificationOutbox] 個人訊息紀錄無法建立 savepoint (message_id=%d): %v", msg.ID, err)
		return
	}
	err := func() (err error) {
		defer func() {
			if r := recover(); r != nil {
				err = fmt.Errorf("panic: %v", r)
			}
		}()
		if w.hooks.beforeTargetedRows != nil {
			if err := w.hooks.beforeTargetedRows(tx); err != nil {
				return err
			}
		}
		for _, uid := range plan.recipients {
			key, err := newDeliveryKey()
			if err != nil {
				return fmt.Errorf("產生投遞識別失敗: %w", err)
			}
			chID, msgID, recipient := plan.channelID, msg.ID, uid
			row := model.NotificationDelivery{
				Category:        model.NotificationCategorySystemEvent,
				MessageID:       &msgID,
				Severity:        msg.Severity,
				SourceChannelID: &chID,
				State:           model.NotificationDeliveryPending,
				NextAttemptAt:   now,
				CreatedAt:       now,
				DeliveryKey:     key,
				Audience:        deliveryAudienceUser,
				RecipientUserID: &recipient,
			}
			if err := tx.Create(&row).Error; err != nil {
				return fmt.Errorf("建立個人訊息紀錄失敗: %w", err)
			}
		}
		return nil
	}()
	if err != nil {
		log.Printf("[NotificationOutbox] 個人訊息紀錄寫入失敗，回到 savepoint，這則只送頻道 (message_id=%d): %v", msg.ID, err)
		if rerr := tx.RollbackTo(targetedDispatchSavepoint).Error; rerr != nil {
			log.Printf("[NotificationOutbox] 回到 savepoint 失敗 (message_id=%d): %v", msg.ID, rerr)
			return
		}
		w.targetedUndeliveredInTx(tx, plan.channelID, notifycat.TargetedReasonResolveFailed, targetedEventKind[plan.event].kind, plan.requestID, now)
	}
}

// ---- 送出前檢查 ----

// targetedPrecheck 四個事件共用的送出前檢查（認領前、查詢後、掃描放棄前都呼叫）。頻道紀錄一律照送。
func (w *SystemAlertOutboxWorker) targetedPrecheck(in DeliveryPrecheckInput) DeliveryPrecheckResult {
	if audienceOfRow(in.Delivery) != deliveryAudienceUser {
		return DeliveryPrecheckResult{}
	}
	cancel := func(reason string) DeliveryPrecheckResult {
		return DeliveryPrecheckResult{Cancel: true, Reason: reason}
	}
	if why := directMessageDisabledReason(in.Channel); why != "" {
		return cancel(model.NotificationEndDirectMessageDisabled)
	}
	judge, ok := w.targetedJudge(notifycat.Event(in.Message.EventKey))
	if !ok {
		return cancel(model.NotificationEndDirectMessageDisabled)
	}
	if in.Delivery.RecipientUserID == nil {
		return cancel(model.NotificationEndRecipientIneligible)
	}
	subject := subjectOf(in.Message.EventKey, in.Message.Params, w.now())
	uid := *in.Delivery.RecipientUserID
	timeout := w.targetedTimeout
	if timeout <= 0 {
		timeout = targetedResolveTimeout
	}
	v, err := runTargeted(w.db, timeout, func(db *gorm.DB) (TargetedVerdict, error) { return judge.Verdict(db, subject, uid) })
	if err != nil {
		return DeliveryPrecheckResult{Err: err}
	}
	switch v {
	case TargetedNeeded:
		return DeliveryPrecheckResult{}
	case TargetedResolved:
		return cancel(model.NotificationEndRequestResolved)
	default:
		return cancel(model.NotificationEndRecipientIneligible)
	}
}

// targetedBeforeAbandon 掃描把個人訊息紀錄標為放棄之前的重驗（唯讀）：取消時回 true 與原因；檢查無法完成時
// 回 false（照常放棄）。
func (w *SystemAlertOutboxWorker) targetedBeforeAbandon(row model.NotificationDelivery) (bool, string) {
	if audienceOfRow(row) != deliveryAudienceUser {
		return false, ""
	}
	pre := w.preReadDelivery(row)
	if pre.outcome == preReadTerminal && pre.state == model.NotificationDeliveryCanceled {
		return true, pre.reason
	}
	return false, ""
}

// ---- 未能送達事件 ----

// targetedNoticeSavepoint 未能送達事件的 savepoint。
const targetedNoticeSavepoint = "notification_targeted_notice"

// targetedNoticeThrottle 同一通道的未能送達事件至多 24 小時一則。
const targetedNoticeThrottle = 24 * time.Hour

// targetedAbandonReasons 個人訊息放棄時會產生未能送達事件的結束原因。
var targetedAbandonReasons = map[string]bool{
	model.NotificationEndNoEmail:           true,
	model.NotificationEndEmailAmbiguous:    true,
	model.NotificationEndRecipientNotFound: true,
	model.NotificationEndMaxAttempts:       true,
	model.NotificationEndRateLimited:       true,
}

// targetedAbandonNoticeInTx 個人訊息紀錄在放棄交易內轉為放棄之後：原因屬觸發條件時產生未能送達事件。
func (w *SystemAlertOutboxWorker) targetedAbandonNoticeInTx(tx *gorm.DB, row model.NotificationDelivery, reason string, now time.Time) {
	if audienceOfRow(row) != deliveryAudienceUser || row.SourceChannelID == nil || !targetedAbandonReasons[reason] {
		return
	}
	w.targetedUndeliveredInTx(tx, *row.SourceChannelID, reason, "", 0, now)
}

// targetedUndeliveredInTx 在呼叫方交易內產生一則未能送達事件：以通道列的條件更新節流（24 小時一則），影響一列才寫
// 內容列；以 savepoint 包住，寫不進去回到 savepoint，呼叫方的放棄或分派照常進行。
// 原因屬個別收件人的放棄時帶截至當下該通道近 24 小時未能送達的去重收件人數；沒有收件人或求得失敗時改帶事件種類
// 與單號（每日審閱沒有單號）。
func (w *SystemAlertOutboxWorker) targetedUndeliveredInTx(tx *gorm.DB, channelID uint, reason, eventKind string, requestID uint, now time.Time) {
	if err := tx.SavePoint(targetedNoticeSavepoint).Error; err != nil {
		log.Printf("[NotificationOutbox] 建立未能送達事件的 savepoint 失敗 (channel_id=%d): %v", channelID, err)
		return
	}
	rollback := func(cause error) {
		if rerr := tx.RollbackTo(targetedNoticeSavepoint).Error; rerr != nil {
			log.Printf("[NotificationOutbox] 回到未能送達事件的 savepoint 失敗 (channel_id=%d): %v", channelID, rerr)
		}
		log.Printf("[NotificationOutbox] 未能送達事件未寫入 (channel_id=%d): %v", channelID, cause)
	}
	if w.hooks.beforeTargetedThrottle != nil {
		w.hooks.beforeTargetedThrottle()
	}
	res := tx.Model(&model.NotificationChannel{}).
		Where("id = ? AND (dm_issue_notified_at IS NULL OR dm_issue_notified_at <= ?)", channelID, now.Add(-targetedNoticeThrottle)).
		Update("dm_issue_notified_at", now)
	if res.Error != nil {
		rollback(res.Error)
		return
	}
	if res.RowsAffected != 1 {
		return
	}
	params := map[string]string{"reason": reason}
	if reason == notifycat.TargetedReasonNoRecipient || reason == notifycat.TargetedReasonResolveFailed {
		params["event_kind"] = eventKind
		if requestID > 0 {
			params["request_id"] = strconv.FormatUint(uint64(requestID), 10)
		}
	} else {
		var count int64
		if err := tx.Model(&model.NotificationDelivery{}).
			Where("source_channel_id = ? AND audience = ? AND state = ? AND ended_at >= ?",
				channelID, deliveryAudienceUser, model.NotificationDeliveryAbandoned, now.Add(-targetedNoticeThrottle)).
			Distinct("recipient_user_id").Count(&count).Error; err != nil {
			rollback(err)
			return
		}
		params["count"] = strconv.FormatInt(count, 10)
	}
	notice := SystemEventNotice(notifycat.EventTargetedNotificationUndelivered, params)
	notice.TargetKind = string(notifycat.IDKindNotificationChannel)
	notice.TargetID = strconv.FormatUint(uint64(channelID), 10)
	notice.OccurredAt = now
	notice.NameRefs = map[string]NotificationNameRef{"channel_name": {Kind: notifycat.IDKindNotificationChannel, ID: channelID}}
	msg, err := buildNotificationMessage(notice, now)
	if err == nil && w.hooks.beforeTargetedNotice != nil {
		err = w.hooks.beforeTargetedNotice()
	}
	if err == nil {
		err = tx.Create(&msg).Error
	}
	if err != nil {
		rollback(err)
	}
}

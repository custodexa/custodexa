package audit

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strconv"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/notifycat"
	"gorm.io/gorm"
)

// 分派：把待分派的通知內容展開成每個通道一筆不帶快照的待投遞紀錄。
//
// 每一列先以條件更新認領（同一句把分派次數加一），再在一個交易內：讀內容列、依名稱參照解析名稱、
// （指令告警）解析會話來源位址與降級原因、決定站內路徑、選通道、建立紀錄、執行擴充點，最後以
// `UPDATE … SET state = 'dispatched' … WHERE id = ? AND state = 'pending'` 收尾並檢查影響一列，
// 不是一列就回滾整個交易（含已建立的紀錄），所以同一則內容只會分派一次。
//
// 名稱解析查不到不是失敗（只留識別碼）；事件未登錄或參數不合契約時降級分派；類別不認得時標為失敗。
// 分派交易出錯或 panic 時交易回滾，租約到期後重新認領；分派次數達上限由掃描標為失敗。

// 指令告警內容列 params 中由分派寫入的鍵（只給渲染用）。
const (
	messageParamClientIP      = "client_ip"
	messageParamDegradeReason = "degrade_reason"
)

// errDispatchLost 收尾的條件更新沒有影響一列（另一個執行個體已分派或狀態已變）。
var errDispatchLost = errors.New("通知內容已不在待分派狀態")

// dispatchSavepoint 分派擴充點用的 savepoint 名稱。
const dispatchSavepoint = "notification_dispatch_extension"

// dispatchPending 取待分派的內容（系統事件先於指令告警，各自依分級由高到低、再依編號），逐列認領並分派。
func (w *SystemAlertOutboxWorker) dispatchPending() {
	now := w.now()
	var ids []uint
	err := w.db.Model(&model.NotificationMessage{}).
		Where("state = ? AND dispatch_attempts < ? AND (lease_until IS NULL OR lease_until < ?)",
			model.NotificationMessagePending, w.dispatchMax, now).
		Order(fmt.Sprintf("CASE category WHEN '%s' THEN 0 WHEN '%s' THEN 1 ELSE 2 END, CASE severity WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END, id",
			model.NotificationCategorySystemEvent, model.NotificationCategoryCommandAlert)).
		Limit(w.batch).
		Pluck("id", &ids).Error
	if err != nil {
		log.Printf("[NotificationOutbox] 讀取待分派內容失敗: %v", err)
		return
	}
	for _, id := range ids {
		if w.stopped() {
			return
		}
		if !w.claimMessage(id, now) {
			continue
		}
		if w.hooks.dispatchAfterClaim != nil && w.hooks.dispatchAfterClaim(id) {
			continue
		}
		w.dispatchClaimed(id)
	}
}

// claimMessage 以條件更新認領一則內容並同時把分派次數加一。
func (w *SystemAlertOutboxWorker) claimMessage(id uint, now time.Time) bool {
	res := w.db.Model(&model.NotificationMessage{}).
		Where("id = ? AND state = ? AND dispatch_attempts < ? AND (lease_until IS NULL OR lease_until < ?)",
			id, model.NotificationMessagePending, w.dispatchMax, now).
		Updates(map[string]any{"lease_until": now.Add(w.lease), "dispatch_attempts": gorm.Expr("dispatch_attempts + 1")})
	return res.Error == nil && res.RowsAffected == 1
}

// dispatchClaimed 分派已認領的一則內容；以 recover 包住，panic 轉成一次分派失敗（交易回滾、等租約到期重試）。
func (w *SystemAlertOutboxWorker) dispatchClaimed(id uint) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[NotificationOutbox] 分派時發生 panic (message_id=%d): %v", id, r)
		}
	}()
	// 交易前的唯讀擴充點：定向事件的收件人以一般連線求得，不佔分派交易
	plan := w.prepareTargeted(id)
	var eventKey string
	outcome := ""
	err := w.db.Transaction(func(tx *gorm.DB) error {
		var err error
		eventKey, outcome, err = w.dispatchInTx(tx, id, plan)
		return err
	})
	if err != nil {
		log.Printf("[NotificationOutbox] 分派失敗，租約到期後重試 (message_id=%d): %v", id, err)
		return
	}
	switch outcome {
	case model.NotificationMessageFailed:
		w.noteDispatchFailed(id, eventKey, model.NotificationMessageFailCategoryUnknown)
	case model.NotificationMessageDispatched:
		if !isAuditFailureFamily(eventKey) {
			w.noteRegularDispatched()
		}
	}
}

// dispatchInTx 分派交易的本體；回傳事件鍵與結果狀態（dispatched 或 failed）。
func (w *SystemAlertOutboxWorker) dispatchInTx(tx *gorm.DB, id uint, plan *targetedPlan) (string, string, error) {
	now := w.now()
	var msg model.NotificationMessage
	if err := tx.First(&msg, id).Error; err != nil {
		return "", "", fmt.Errorf("讀取通知內容失敗: %w", err)
	}
	if w.hooks.dispatchRead != nil {
		if err := w.hooks.dispatchRead(&msg); err != nil {
			return msg.EventKey, "", err
		}
	}
	if msg.Category != model.NotificationCategoryCommandAlert && msg.Category != model.NotificationCategorySystemEvent {
		res := tx.Model(&model.NotificationMessage{}).Where("id = ? AND state = ?", id, model.NotificationMessagePending).
			Updates(map[string]any{"state": model.NotificationMessageFailed, "fail_reason": model.NotificationMessageFailCategoryUnknown, "lease_until": nil})
		if res.Error != nil {
			return msg.EventKey, "", res.Error
		}
		if res.RowsAffected != 1 {
			return msg.EventKey, "", errDispatchLost
		}
		return msg.EventKey, model.NotificationMessageFailed, nil
	}

	params, degraded := w.resolveMessageContent(tx, &msg)
	rawParams, err := json.Marshal(params)
	if err != nil {
		return msg.EventKey, "", fmt.Errorf("通知參數序列化失敗: %w", err)
	}

	channels, err := w.selectDispatchChannels(tx, msg)
	if err != nil {
		return msg.EventKey, "", err
	}
	for _, ch := range channels {
		key, err := newDeliveryKey()
		if err != nil {
			return msg.EventKey, "", fmt.Errorf("產生投遞識別失敗: %w", err)
		}
		chID, msgID := ch.ID, msg.ID
		row := model.NotificationDelivery{
			Category:        msg.Category,
			MessageID:       &msgID,
			Severity:        msg.Severity,
			SourceChannelID: &chID,
			State:           model.NotificationDeliveryPending,
			NextAttemptAt:   now,
			CreatedAt:       now,
			DeliveryKey:     key,
		}
		if err := tx.Create(&row).Error; err != nil {
			return msg.EventKey, "", fmt.Errorf("建立待投遞紀錄失敗: %w", err)
		}
	}
	if plan != nil {
		w.writeTargetedInTx(tx, &msg, plan, now)
	}
	if w.hooks.dispatchExtension != nil {
		w.runDispatchExtension(tx, &msg)
	}
	if w.hooks.beforeDispatchFinalize != nil {
		w.hooks.beforeDispatchFinalize(tx, id)
	}
	res := tx.Model(&model.NotificationMessage{}).Where("id = ? AND state = ?", id, model.NotificationMessagePending).
		Updates(map[string]any{
			"state": model.NotificationMessageDispatched, "dispatched_at": now, "lease_until": nil,
			"params": string(rawParams), "actor_name": msg.ActorName, "target_name": msg.TargetName,
			"link_path": msg.LinkPath, "degraded": degraded,
		})
	if res.Error != nil {
		return msg.EventKey, "", res.Error
	}
	if res.RowsAffected != 1 {
		return msg.EventKey, "", errDispatchLost
	}
	return msg.EventKey, model.NotificationMessageDispatched, nil
}

// runDispatchExtension 執行分派擴充點；以 savepoint 包住，回錯或 panic 只回到 savepoint，分派照常收尾。
func (w *SystemAlertOutboxWorker) runDispatchExtension(tx *gorm.DB, msg *model.NotificationMessage) {
	if err := tx.SavePoint(dispatchSavepoint).Error; err != nil {
		log.Printf("[NotificationOutbox] 分派擴充點無法建立 savepoint (message_id=%d): %v", msg.ID, err)
		return
	}
	var extErr error
	func() {
		defer func() {
			if r := recover(); r != nil {
				extErr = fmt.Errorf("panic: %v", r)
			}
		}()
		extErr = w.hooks.dispatchExtension(tx, msg)
	}()
	if extErr != nil {
		log.Printf("[NotificationOutbox] 分派擴充點失敗，回到 savepoint (message_id=%d): %v", msg.ID, extErr)
		if err := tx.RollbackTo(dispatchSavepoint).Error; err != nil {
			log.Printf("[NotificationOutbox] 回到 savepoint 失敗 (message_id=%d): %v", msg.ID, err)
		}
	}
}

// resolveMessageContent 解析名稱並決定連結與降級；回傳寫回內容列的參數與是否降級（msg 的名稱與路徑欄位就地更新）。
func (w *SystemAlertOutboxWorker) resolveMessageContent(tx *gorm.DB, msg *model.NotificationMessage) (map[string]string, bool) {
	params := map[string]string{}
	degraded := msg.Degraded
	if msg.Params != "" {
		if err := json.Unmarshal([]byte(msg.Params), &params); err != nil {
			params = map[string]string{}
			degraded = true
		}
	}
	refs := map[string]NotificationNameRef{}
	if msg.NameRefs != "" {
		_ = json.Unmarshal([]byte(msg.NameRefs), &refs)
	}
	resolveNameRefs(tx, params, refs)
	if msg.ActorName == "" && msg.ActorUserID != nil && *msg.ActorUserID != 0 {
		msg.ActorName = lookupUserNamesDB(tx, []uint{*msg.ActorUserID})[*msg.ActorUserID]
	}
	if msg.TargetName == "" {
		msg.TargetName = resolveTargetName(tx, msg.TargetKind, msg.TargetID)
	}

	if msg.Category == model.NotificationCategoryCommandAlert {
		var alert model.CommandAlert
		if err := tx.First(&alert, derefUint(msg.AlertID)).Error; err == nil {
			if alert.SessionID != 0 {
				var ip string
				_ = tx.Model(&model.Session{}).Select("client_ip").Where("id = ?", alert.SessionID).Limit(1).Scan(&ip).Error
				if ip != "" {
					params[messageParamClientIP] = ip
				}
				msg.LinkPath = fmt.Sprintf("/sessions/%d", alert.SessionID)
			} else {
				msg.LinkPath = "/alerts"
			}
			if reason := lookupDegradeReason(tx, alert); reason != "" {
				params[messageParamDegradeReason] = reason
			}
		}
		return params, degraded
	}

	event := notifycat.Event(msg.EventKey)
	if _, ok := notifycat.Spec(event); !ok {
		return map[string]string{}, true
	}
	if degraded {
		kept, _ := notifycat.FilterDeclared(event, params)
		return kept, true
	}
	if _, err := notifycat.Validate(event, params); err != nil {
		kept, _ := notifycat.FilterDeclared(event, params)
		log.Printf("[NotificationOutbox] 事件 %s 參數不合契約，降級分派 (message_id=%d): %v", event, msg.ID, err)
		return kept, true
	}
	msg.LinkPath = notifycat.LinkPath(event, params)
	return params, false
}

// resolveNameRefs 依名稱參照解析名稱並寫進參數（參數鍵已有值者不重查；查不到只留識別碼）。
func resolveNameRefs(tx *gorm.DB, params map[string]string, refs map[string]NotificationNameRef) {
	byKind := map[notifycat.IDKind][]uint{}
	for key, ref := range refs {
		if params[key] != "" || ref.ID == 0 {
			continue
		}
		byKind[ref.Kind] = append(byKind[ref.Kind], ref.ID)
	}
	names := map[notifycat.IDKind]map[uint]string{}
	for kind, ids := range byKind {
		names[kind] = lookupNamesByKind(tx, kind, ids)
	}
	for key, ref := range refs {
		if params[key] != "" {
			continue
		}
		if name := names[ref.Kind][ref.ID]; name != "" {
			params[key] = name
		}
	}
}

// lookupNamesByKind 依識別碼種類解析名稱；不支援的種類回空。
func lookupNamesByKind(tx *gorm.DB, kind notifycat.IDKind, ids []uint) map[uint]string {
	switch kind {
	case notifycat.IDKindUser:
		return lookupUserNamesDB(tx, ids)
	case notifycat.IDKindAsset:
		return lookupAssetNamesDB(tx, ids)
	case notifycat.IDKindNotificationChannel:
		return lookupChannelNamesDB(tx, ids)
	default:
		return map[uint]string{}
	}
}

// lookupChannelNamesDB 依識別碼取通知通道名稱（通道是硬刪，刪除後查不到）。
func lookupChannelNamesDB(db *gorm.DB, ids []uint) map[uint]string {
	out := map[uint]string{}
	if db == nil || len(ids) == 0 {
		return out
	}
	var rows []struct {
		ID   uint
		Name string
	}
	db.Model(&model.NotificationChannel{}).Select("id, name").Where("id IN ?", ids).Scan(&rows)
	for _, r := range rows {
		out[r.ID] = r.Name
	}
	return out
}

// resolveTargetName 依目標的種類與識別碼解析名稱；識別碼不是正整數或種類不支援時回空。
func resolveTargetName(tx *gorm.DB, kind, id string) string {
	n, err := strconv.ParseUint(id, 10, strconv.IntSize)
	if err != nil || n == 0 {
		return ""
	}
	return lookupNamesByKind(tx, notifycat.IDKind(kind), []uint{uint(n)})[uint(n)]
}

// selectDispatchChannels 選通道：啟用中；指令告警依推送門檻；宣告「不送往目標通道」的事件排除目標通道。
func (w *SystemAlertOutboxWorker) selectDispatchChannels(tx *gorm.DB, msg model.NotificationMessage) ([]model.NotificationChannel, error) {
	var all []model.NotificationChannel
	if err := tx.Select("id, min_severity, enabled").Where("enabled = ?", true).Order("id").Find(&all).Error; err != nil {
		return nil, fmt.Errorf("讀取啟用通道失敗: %w", err)
	}
	excludeTarget := ""
	if spec, ok := notifycat.Spec(notifycat.Event(msg.EventKey)); ok && spec.ExcludeTargetChannel &&
		msg.TargetKind == string(notifycat.IDKindNotificationChannel) {
		excludeTarget = msg.TargetID
	}
	out := make([]model.NotificationChannel, 0, len(all))
	for _, ch := range all {
		if msg.Category == model.NotificationCategoryCommandAlert && !channelAdmitsSeverity(ch.MinSeverity, msg.Severity) {
			continue
		}
		if excludeTarget != "" && strconv.FormatUint(uint64(ch.ID), 10) == excludeTarget {
			continue
		}
		out = append(out, ch)
	}
	return out, nil
}

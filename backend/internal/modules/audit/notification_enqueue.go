package audit

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strconv"
	"sync"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/notifycat"
	"gorm.io/gorm"
)

// 通知的排入介面（指令告警與系統事件）。
//
// 產生點只寫一列通知內容（識別碼、參數、需要分派解析的名稱參照），不讀通道、不加解密、不查名稱；
// 投遞程序在背景分派。兩個入口：
//   - EnqueueInTx：在呼叫端的業務交易內以 savepoint 包住單一 INSERT。寫入失敗回到 savepoint，
//     業務交易照常提交；業務交易回滾時這一列一起消失。
//   - EnqueueStandalone：沒有業務交易（或完整資料在提交後才有）時，以服務自己的連線獨立寫一筆。
//
// 兩者都不呼叫稽核失效服務的 Report／Resolve，只更新成敗計數（EnqueueStats）；投遞程序每一輪在
// 不持任何交易與鎖的回報檢查點依計數回報或結束 notification_delivery 機制。稽核失效一族另有
// EnqueueAuditFailureNotice，不計入這組計數。
//
// 回傳的 error 只供呼叫端記錄；呼叫端不得把它當成業務失敗回傳（排入失敗不使業務操作失敗）。

// NotificationNameRef 名稱參數的識別碼參照，給分派解析名稱用。
type NotificationNameRef struct {
	Kind notifycat.IDKind `json:"kind"`
	ID   uint             `json:"id"`
}

// NotificationNotice 一則待排入的通知內容。
type NotificationNotice struct {
	// Category 類別：model.NotificationCategoryCommandAlert 或 model.NotificationCategorySystemEvent。
	Category string
	// Event 事件鍵（系統事件）；指令告警不填，內容列的事件鍵固定為 command_alert。
	Event notifycat.Event
	// AlertID 指令告警的告警列（指令告警必填）。
	AlertID *uint
	// Severity 分級；空字串時取事件規格的宣告值。
	Severity string
	// OccurredAt 發生時間；零值時取寫入當下。
	OccurredAt time.Time
	// ActorUserID、ActorName 操作者；名稱可空，由分派解析。
	ActorUserID *uint
	ActorName   string
	// TargetKind、TargetID、TargetName 目標；名稱可空，由分派解析。
	TargetKind string
	TargetID   string
	TargetName string
	// Params 事件參數（字串值）；手上已有的名稱直接放在對應的參數鍵。
	Params map[string]string
	// NameRefs 名稱參數鍵到識別碼的參照；參數鍵已有值時分派不重查。
	NameRefs map[string]NotificationNameRef
}

// SystemEventNotice 由事件鍵與參數組出系統事件的通知內容。
func SystemEventNotice(event notifycat.Event, params map[string]string) NotificationNotice {
	return NotificationNotice{Category: model.NotificationCategorySystemEvent, Event: event, Params: params}
}

// EnqueueStats 排入的成敗計數，由排入介面寫、投遞程序的回報檢查點讀。
//
// 成敗以同一個遞增序號標記先後（不依時鐘），回報檢查點據此判斷「最近一次失敗是否晚於上次檢查」與
// 「最近一次成功是否晚於最近一次失敗」。只用自己的小鎖，不取稽核失效服務的鎖。
type EnqueueStats struct {
	mu        sync.Mutex
	seq       uint64
	failSeq   uint64
	okSeq     uint64
	failEvent string
	failError string
}

func (s *EnqueueStats) markOK() {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.seq++
	s.okSeq = s.seq
	s.mu.Unlock()
}

func (s *EnqueueStats) markFail(event string, err error) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.seq++
	s.failSeq = s.seq
	s.failEvent = event
	s.failError = truncateRunes(err.Error(), 200)
	s.mu.Unlock()
}

// snapshot 回傳最近一次失敗與成功的序號，以及最近一次失敗的事件鍵與錯誤摘要。
func (s *EnqueueStats) snapshot() (failSeq, okSeq uint64, event, errText string) {
	if s == nil {
		return 0, 0, "", ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.failSeq, s.okSeq, s.failEvent, s.failError
}

// errEnqueueNotInTx EnqueueInTx 收到的句柄不是交易。
var errEnqueueNotInTx = errors.New("EnqueueInTx 需要交易句柄")

// enqueueSavepoint 排入用的 savepoint 名稱。
const enqueueSavepoint = "notification_enqueue"

// EnqueueInTx 在呼叫端的交易內排入一則通知（見檔頭）。tx 必須是交易句柄，否則回錯且不寫入。
func (n *AlertNotifier) EnqueueInTx(tx *gorm.DB, notice NotificationNotice) error {
	if n == nil {
		return nil
	}
	if !isTxHandle(tx) {
		log.Printf("[NotificationEnqueue] 事件 %s 未排入: %v", notice.Event, errEnqueueNotInTx)
		n.stats.markFail(string(notice.Event), errEnqueueNotInTx)
		return errEnqueueNotInTx
	}
	row, err := buildNotificationMessage(notice, n.clock())
	if err != nil {
		return n.enqueueFailed(string(notice.Event), err)
	}
	if err := tx.SavePoint(enqueueSavepoint).Error; err != nil {
		return n.enqueueFailed(string(notice.Event), fmt.Errorf("建立 savepoint 失敗: %w", err))
	}
	if err := tx.Create(&row).Error; err != nil {
		if rerr := tx.RollbackTo(enqueueSavepoint).Error; rerr != nil {
			log.Printf("[NotificationEnqueue] 回到 savepoint 失敗 (event=%s): %v", notice.Event, rerr)
		}
		return n.enqueueFailed(string(notice.Event), err)
	}
	n.stats.markOK()
	return nil
}

// EnqueueStandalone 以服務自己的連線獨立排入一則通知（見檔頭）。
func (n *AlertNotifier) EnqueueStandalone(notice NotificationNotice) error {
	if n == nil {
		return nil
	}
	if n.db == nil {
		return n.enqueueFailed(string(notice.Event), errors.New("排入介面未注入資料庫"))
	}
	row, err := buildNotificationMessage(notice, n.clock())
	if err != nil {
		return n.enqueueFailed(string(notice.Event), err)
	}
	if err := n.db.Create(&row).Error; err != nil {
		return n.enqueueFailed(string(notice.Event), err)
	}
	n.stats.markOK()
	return nil
}

func (n *AlertNotifier) enqueueFailed(event string, err error) error {
	log.Printf("[NotificationEnqueue] 事件 %s 排入失敗（業務操作照常完成）: %v", event, err)
	n.stats.markFail(event, err)
	return err
}

// EnqueueStats 排入成敗計數（組裝根交給投遞程序）。
func (n *AlertNotifier) EnqueueStats() *EnqueueStats {
	if n == nil {
		return nil
	}
	return n.stats
}

// isTxHandle 句柄是否在交易內（以 Statement.ConnPool 是否為可提交的交易判斷）。
func isTxHandle(tx *gorm.DB) bool {
	if tx == nil || tx.Statement == nil || tx.Statement.ConnPool == nil {
		return false
	}
	_, ok := tx.Statement.ConnPool.(gorm.TxCommitter)
	return ok
}

// buildNotificationMessage 由通知內容組出待分派的內容列。
func buildNotificationMessage(notice NotificationNotice, now time.Time) (model.NotificationMessage, error) {
	eventKey := string(notice.Event)
	switch notice.Category {
	case model.NotificationCategoryCommandAlert:
		if notice.AlertID == nil || *notice.AlertID == 0 {
			return model.NotificationMessage{}, errors.New("指令告警的通知內容缺少告警列")
		}
		eventKey = alertEventCommandAlert
	case model.NotificationCategorySystemEvent:
		if len(eventKey) == 0 {
			return model.NotificationMessage{}, errors.New("系統事件的通知內容缺少事件鍵")
		}
	default:
		return model.NotificationMessage{}, fmt.Errorf("不支援的通知類別 %q", notice.Category)
	}
	params := notice.Params
	if params == nil {
		params = map[string]string{}
	}
	rawParams, err := json.Marshal(params)
	if err != nil {
		return model.NotificationMessage{}, fmt.Errorf("通知參數序列化失敗: %w", err)
	}
	refs := notice.NameRefs
	if refs == nil {
		refs = map[string]NotificationNameRef{}
	}
	rawRefs, err := json.Marshal(refs)
	if err != nil {
		return model.NotificationMessage{}, fmt.Errorf("名稱參照序列化失敗: %w", err)
	}
	occurred := notice.OccurredAt
	if occurred.IsZero() {
		occurred = now
	}
	return model.NotificationMessage{
		Category:    notice.Category,
		EventKey:    eventKey,
		AlertID:     notice.AlertID,
		Severity:    noticeSeverity(notice),
		OccurredAt:  occurred.UTC(),
		ActorUserID: notice.ActorUserID,
		ActorName:   notice.ActorName,
		TargetKind:  notice.TargetKind,
		TargetID:    notice.TargetID,
		TargetName:  notice.TargetName,
		Params:      string(rawParams),
		NameRefs:    string(rawRefs),
		State:       model.NotificationMessagePending,
		CreatedAt:   now.UTC(),
	}, nil
}

// noticeSeverity 內容列的分級：明示值優先，其次事件規格的宣告值；都不在三值內時，指令告警取 high
// （無法分類的告警不應被通道門檻略過），系統事件取 medium。
func noticeSeverity(notice NotificationNotice) string {
	if severityRank(notice.Severity) > 0 {
		return notice.Severity
	}
	if notice.Category == model.NotificationCategoryCommandAlert {
		return model.AlertSeverityHigh
	}
	if s := eventSeverity(notice.Event); severityRank(s) > 0 {
		return s
	}
	return model.AlertSeverityMedium
}

// enqueueCommandAlerts 為一批已提交的告警列寫通知內容（每筆告警一列，單一批次 INSERT）。
// agent 熔斷（由系統事件通知負責）與系統安全告警（由帶快照的待投遞紀錄負責）不寫。
// 不讀通道、不加解密、不查名稱；失敗只記 log 並計入排入計數。
func (n *AlertNotifier) enqueueCommandAlerts(rows []model.CommandAlert) error {
	if n == nil {
		return nil
	}
	msgs := make([]model.NotificationMessage, 0, len(rows))
	now := n.clock()
	for _, row := range rows {
		if row.Kind == model.AlertKindAgentBreaker || row.Kind == model.AlertKindSystemSecurity {
			continue
		}
		msg, err := buildNotificationMessage(commandAlertNotice(row), now)
		if err != nil {
			return n.enqueueFailed(alertEventCommandAlert, err)
		}
		msgs = append(msgs, msg)
	}
	if len(msgs) == 0 {
		return nil
	}
	if n.db == nil {
		return n.enqueueFailed(alertEventCommandAlert, errors.New("排入介面未注入資料庫"))
	}
	if err := n.db.Create(&msgs).Error; err != nil {
		return n.enqueueFailed(alertEventCommandAlert, err)
	}
	n.stats.markOK()
	return nil
}

// commandAlertNotice 由已入庫的告警列組出指令告警的通知內容（識別碼取自告警列，名稱由分派解析）。
func commandAlertNotice(row model.CommandAlert) NotificationNotice {
	id := row.ID
	notice := NotificationNotice{
		Category:   model.NotificationCategoryCommandAlert,
		AlertID:    &id,
		Severity:   row.Severity,
		OccurredAt: row.TriggeredAt,
	}
	if row.UserID != 0 {
		uid := row.UserID
		notice.ActorUserID = &uid
	}
	if row.AssetID != nil && *row.AssetID != 0 {
		notice.TargetKind = string(notifycat.IDKindAsset)
		notice.TargetID = strconv.FormatUint(uint64(*row.AssetID), 10)
	}
	return notice
}

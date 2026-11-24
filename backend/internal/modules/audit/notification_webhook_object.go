package audit

import (
	"strconv"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit/port"
	"github.com/custodexa/backend/internal/notifycat"
)

// webhook 三種形狀共用的新物件（頂層 notification）。
//
// 既有欄位一律不動（名稱、型別、語義、時區都照舊）；收端可只讀這個物件取得一致的類別、分級、時間（UTC）、
// 投遞識別、操作者、目標、連結與依型別輸出的參數。簽章覆蓋整個本文。

// notificationObjectVersion 新物件的版本；欄位有不相容的變動才遞增。
const notificationObjectVersion = 1

// 新物件 category 的值：三個通知類別之外，測試發送為 test。
const notificationCategoryTest = "test"

type notificationObject struct {
	Version    int                 `json:"version"`
	Category   string              `json:"category"`
	Type       string              `json:"type"`
	Severity   string              `json:"severity"`
	OccurredAt string              `json:"occurred_at"`
	SentAt     string              `json:"sent_at"`
	DeliveryID string              `json:"delivery_id"`
	Actor      *notificationActor  `json:"actor,omitempty"`
	Target     *notificationTarget `json:"target,omitempty"`
	Link       string              `json:"link,omitempty"`
	Params     map[string]any      `json:"params"`
	Degraded   bool                `json:"degraded,omitempty"`
}

type notificationActor struct {
	UserID uint   `json:"user_id"`
	Name   string `json:"name"`
}

type notificationTarget struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
	Name string `json:"name,omitempty"`
}

func utcRFC3339(t time.Time) string {
	return t.UTC().Format(time.RFC3339)
}

// actorOf 操作者；識別碼為 0 且沒有名稱時省略。
func actorOf(userID uint, name string) *notificationActor {
	if userID == 0 && name == "" {
		return nil
	}
	return &notificationActor{UserID: userID, Name: name}
}

// targetOf 目標；種類或識別碼為空時省略。
func targetOf(kind, id, name string) *notificationTarget {
	if kind == "" || id == "" {
		return nil
	}
	return &notificationTarget{Kind: kind, ID: id, Name: name}
}

// commandAlertObject 指令告警的新物件。
func commandAlertObject(alert model.CommandAlert, names alertSubjectNames, deliveryID string, now time.Time) *notificationObject {
	obj := &notificationObject{
		Version:    notificationObjectVersion,
		Category:   model.NotificationCategoryCommandAlert,
		Type:       alertEventCommandAlert,
		Severity:   alert.Severity,
		OccurredAt: utcRFC3339(alert.TriggeredAt),
		SentAt:     utcRFC3339(now),
		DeliveryID: deliveryID,
		Actor:      actorOf(alert.UserID, names.User),
		Link:       commandAlertLink(alert),
		Params:     map[string]any{},
	}
	if alert.AssetID != nil {
		obj.Target = targetOf(string(port.SystemAlertTargetAsset), strconv.FormatUint(uint64(*alert.AssetID), 10), names.Asset)
	}
	return obj
}

// systemEventObject 系統事件的新物件（內容取自分派後的內容列）。
func systemEventObject(msg model.NotificationMessage, clean map[string]string, degraded bool, deliveryID string, now time.Time) *notificationObject {
	event := notifycat.Event(msg.EventKey)
	obj := &notificationObject{
		Version:    notificationObjectVersion,
		Category:   model.NotificationCategorySystemEvent,
		Type:       msg.EventKey,
		Severity:   msg.Severity,
		OccurredAt: utcRFC3339(msg.OccurredAt),
		SentAt:     utcRFC3339(now),
		DeliveryID: deliveryID,
		Actor:      actorOf(derefUint(msg.ActorUserID), msg.ActorName),
		Target:     targetOf(msg.TargetKind, msg.TargetID, msg.TargetName),
		Params:     notifycat.TypedWireParams(event, clean),
		Degraded:   degraded,
	}
	if obj.Severity == "" {
		obj.Severity = eventSeverity(event)
	}
	if !degraded && msg.LinkPath != "" {
		obj.Link = composeNotificationLink(msg.LinkPath)
	}
	return obj
}

// systemAlertTargetNameKeys 系統安全告警各目標種類的名稱參數（依序取第一個有值的）。
var systemAlertTargetNameKeys = map[string][]string{
	string(port.SystemAlertTargetAsset):               {"asset_name"},
	string(port.SystemAlertTargetNotificationChannel): {"channel_name"},
	string(port.SystemAlertTargetUser):                {"target_username", "recipient"},
	string(port.SystemAlertTargetSession):             {"session_username"},
}

// systemAlertObject 系統安全告警的新物件；degraded 時參數為空物件。
func systemAlertObject(alert model.CommandAlert, detail model.SystemAlertDetail, actor string, params map[string]string,
	event notifycat.Event, degraded bool, deliveryID string, now time.Time) *notificationObject {
	obj := &notificationObject{
		Version:    notificationObjectVersion,
		Category:   model.NotificationCategorySystemSecurityAlert,
		Type:       detail.AlertType,
		Severity:   alert.Severity,
		OccurredAt: utcRFC3339(alert.TriggeredAt),
		SentAt:     utcRFC3339(now),
		DeliveryID: deliveryID,
		Actor:      actorOf(alert.UserID, actor),
		Params:     map[string]any{},
		Degraded:   degraded,
	}
	name := ""
	for _, k := range systemAlertTargetNameKeys[detail.TargetKind] {
		if v := params[k]; v != "" {
			name = v
			break
		}
	}
	obj.Target = targetOf(detail.TargetKind, detail.TargetID, name)
	if !degraded {
		obj.Params = notifycat.TypedWireParams(event, params)
		in := map[string]string{"severity": alert.Severity}
		for k, v := range params {
			in[k] = v
		}
		obj.Link = composeNotificationLink(notifycat.LinkPath(event, in))
	}
	return obj
}

// testObject 測試發送的新物件：category 為 test，每次測試產生新的投遞識別。
func testObject(at time.Time) *notificationObject {
	key, err := newDeliveryKey()
	if err != nil {
		key = ""
	}
	return &notificationObject{
		Version:    notificationObjectVersion,
		Category:   notificationCategoryTest,
		Type:       alertEventTest,
		Severity:   model.AlertSeverityLow,
		OccurredAt: utcRFC3339(at),
		SentAt:     utcRFC3339(at),
		DeliveryID: key,
		Params:     map[string]any{},
	}
}

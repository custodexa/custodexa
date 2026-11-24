package audit

import (
	"strconv"

	"github.com/custodexa/backend/internal/notifycat"
	"gorm.io/gorm"
)

// AgentOwnerNotice AI agent 事件的通知事實：參數只放識別碼與數字，名稱以識別碼參照交給分派解析
// （agent 名稱以主體的使用者識別碼解析成登入帳號，不取呼叫端手上的名稱）。
type AgentOwnerNotice struct {
	OwnerID uint
	Event   notifycat.Event
	Params  map[string]string
	// NameRefs 名稱參數鍵到識別碼的參照；Names 產生點手上已有、分派不解析的名稱（例如 token 名稱）。
	NameRefs map[string]NotificationNameRef
	Names    map[string]string
}

// NotifyAgentOwner 在呼叫端的業務交易內排入 AI agent 事件（以 savepoint 包住）：寫不進去只回到 savepoint，
// 業務交易照常提交；業務交易回滾時這一列一起消失。owner_id 是路由資訊，不代表個人收件匣，
// 投遞照既有的通道設定廣播。
func NotifyAgentOwner(tx *gorm.DB, n AgentOwnerNotice) {
	notifier := GetAlertNotifier()
	if notifier == nil {
		return
	}
	_ = notifier.EnqueueInTx(tx, agentOwnerNotificationNotice(n))
}

func agentOwnerNotificationNotice(n AgentOwnerNotice) NotificationNotice {
	params := map[string]string{}
	for k, v := range n.Params {
		params[k] = v
	}
	for k, v := range n.Names {
		if v != "" {
			params[k] = v
		}
	}
	params["owner_id"] = strconv.FormatUint(uint64(n.OwnerID), 10)
	notice := SystemEventNotice(n.Event, params)
	notice.NameRefs = n.NameRefs
	if ref, ok := n.NameRefs["agent_name"]; ok && ref.ID != 0 {
		uid := ref.ID
		notice.ActorUserID = &uid
		notice.TargetKind = string(notifycat.IDKindUser)
		notice.TargetID = strconv.FormatUint(uint64(ref.ID), 10)
	}
	return notice
}

// agentWindowMinutesParam 熔斷時窗的分鐘數；不是整分鐘時不帶（句子以可選段承接）。
func agentWindowMinutesParam(seconds int) string {
	if seconds <= 0 || seconds%60 != 0 {
		return ""
	}
	return strconv.Itoa(seconds / 60)
}

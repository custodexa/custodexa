package audit

import (
	"github.com/custodexa/backend/internal/notifycat"
	"strconv"
)

// NotifyAgentOwner follows the existing broadcast channel configuration. owner_id
// is routing metadata, not a claim of personal delivery or a private inbox.
func NotifyAgentOwner(ownerID uint, event notifycat.Event, params map[string]string) {
	if params == nil {
		params = map[string]string{}
	}
	params["owner_id"] = strconv.FormatUint(uint64(ownerID), 10)
	if notifier := GetAlertNotifier(); notifier != nil {
		notifier.NotifyEvent(event, params)
	}
}

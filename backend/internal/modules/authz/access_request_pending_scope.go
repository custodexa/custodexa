package authz

import "github.com/custodexa/backend/internal/model"

// 待審專用的範圍條件。與 requestItemScopeRouteCondition 的差別只有一處：項目必須仍是 pending。
// 完整範圍函式（歷史、待補審共用）不動；待審列表與計數改用這裡，使「範圍內的項目都已決、
// 只剩範圍外項目 pending」的申請不再被算成可核決（對它的單筆核決必回資格不符）。
// 佔位符：操作者 id ×16，與 requestItemScopeRouteCondition 相同。
func pendingItemScopeRouteCondition() string {
	pending := string(model.AccessRequestPending)
	return "(id IN (SELECT request_id FROM access_request_items WHERE deleted_at IS NULL AND status = '" + pending + "' AND " + approverScopeRouteCondition("requester_id") + ")" +
		" OR (NOT EXISTS (SELECT 1 FROM access_request_items WHERE request_id=access_requests.id AND deleted_at IS NULL) AND " + approverScopeRouteCondition("requester_id") + "))"
}

// 執行者不得核決自己代為執行的申請（單筆核決同一判定，見 selfDecisionBlocked）。
// 佔位符：操作者 id ×1。
const executorExclusionCondition = "(executor_user_id IS NULL OR executor_user_id <> ?)"

// 不經範圍過濾的呼叫端（isAdmin 為真）也只計仍有 pending 項目的申請。
func anyPendingItemCondition() string {
	pending := string(model.AccessRequestPending)
	return "(id IN (SELECT request_id FROM access_request_items WHERE deleted_at IS NULL AND status = '" + pending + "')" +
		" OR NOT EXISTS (SELECT 1 FROM access_request_items WHERE request_id=access_requests.id AND deleted_at IS NULL))"
}

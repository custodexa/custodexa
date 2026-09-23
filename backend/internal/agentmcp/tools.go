package agentmcp

import (
	"context"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

var descriptions = map[string]string{
	"list_assets":    "列出你可見的資產、可用帳號與可連狀態。資產 id 只能從此取得。可連狀態＝此刻能不能連；不是需不需要申請。open 資產仍須有任務 id。失敗時依機器碼處理，不猜測其他 id。",
	"request_access": "用 list_assets 的資產 id 逐資產明確指定 accounts 帳號範圍、事由及時長以申請任務；不可用全部帳號，也不代填。already_connectable 僅表示已有有效核准項並附 request_id；open 資產無單也照建單即時核准。pending 時用 check_request，拒絕時不重送相同申請。",
	"check_request":  "用 request_access 的 request_id 查看 created_at、status、approvals_received、approvals_required、expires_at、closed_at。pending 且未到期並有核准進度時繼續等；仍未足額時改做別的事並稍後再查；rejected、cancelled 或 expired 時判定不會過，停止等待。撤銷逐資產生效，不改變 status，整單仍為 approved；closed_at 有值表示任務已關閉（項目全數撤銷或到期，或已 close_task），同樣判定不會過。",
	"open_session":   "用 list_assets 的 asset_id、account_id 與 request_access 的 request_id 建立有錄影的 SSH／K8s 終端或資料庫查詢會話。request_id 必填，不會替你挑選任務。回傳 session_handle 只限本 MCP 連線及 token 使用；拒絕時依機器碼修正任務或等待核准，不繞過閘序。K8s 必須指定 pod，可選 container 與 exec/logs 模式。",
	"run_command":    "用 open_session 的 session_handle 送出 command，指令以歸位字元結尾。completed 只表示再次觀察到提示符，不代表指令成功；timed_out 的結果未知，逾時後不得盲目重送，先觀察後續輸出或另查狀態；needs_input 表示等待輸入，須自行以 send_keys ctrl-c 復位；blocked 附阻斷機器碼；unknown 為無法判定，running 為仍在執行。提示符可被目標端偽造、背景輸出可交錯，狀態與 stale_output 殘餘來源皆為啟發式。選填 idempotency_key 在同會話 60 秒內同鍵回前次結果且不再寫入；未帶鍵不去重。",
	"send_keys":      "用 open_session 的 session_handle 送 ctrl-c、ctrl-d 或 enter；僅這三個鍵名。needs_input 後由你決定是否 ctrl-c 中止並復位，系統不自動送鍵。不可傳密碼或機密。等待復位完成後再送普通指令；非法鍵被拒且零位元組寫入。",
	"query":          "用資料庫 session_handle 送 SQL，回傳既有查詢主控台的結果形狀。timeout_seconds 預設 60 秒並受後端上限約束；逾時不保證查詢未生效，先確認結果勿盲目重送。錯誤按回傳機器碼處理。",
	"read_screen":    "用 session_handle 取得累積輸出去控制序列後最後 N 行。這是行緩衝，非虛擬螢幕；畫面清除、游標定位、全螢幕程式下與真實終端不一致，不能視為畫面快照。失效的 session_handle 須重建經核准的會話。",
	"close_session":  "關閉 open_session 所發的 session_handle 並結算錄影與指令稽核。已終止時停止使用該 session_handle；不存在時不猜測其他 session_handle。關閉只終止本系統建立的會話，不保證目標端背景程序停止。",
	"close_task":     "用 request_id 與 report 關閉自己的任務並提交報告版本；再次呼叫新增版本、不覆寫舊版，限原提交主體及持久化關閉時刻起 24 小時內，逾窗不重試。close_task 不是關閉的唯一途徑：全部任務項到期或被撤銷也會關閉並終止其餘會話。缺報告以關閉時刻判定，其後 session_handle 回已終止狀態。",
}

func toolSchema(name string) map[string]any {
	props := map[string]any{}
	str := func(key string) { props[key] = map[string]any{"type": "string"} }
	integer := func(key string) { props[key] = map[string]any{"type": "integer", "minimum": 1} }
	var required []string
	switch name {
	case "list_assets":
	case "request_access":
		props["items"] = map[string]any{"type": "array", "minItems": 1, "items": map[string]any{"type": "object", "additionalProperties": false, "properties": map[string]any{"asset_id": map[string]any{"type": "integer", "minimum": 1}, "accounts": map[string]any{"type": "array", "minItems": 1, "items": map[string]any{"type": "string"}}}, "required": []string{"asset_id"}}}
		str("reason")
		integer("duration_minutes")
		required = []string{"items", "reason", "duration_minutes"}
	case "check_request":
		integer("request_id")
		required = []string{"request_id"}
	case "open_session":
		integer("asset_id")
		integer("account_id")
		integer("request_id")
		str("k8s_pod")
		str("k8s_container")
		props["k8s_mode"] = map[string]any{"type": "string", "enum": []string{"exec", "logs"}}
		required = []string{"asset_id", "request_id"}
	case "run_command":
		str("session_handle")
		str("command")
		integer("timeout_seconds")
		str("idempotency_key")
		required = []string{"session_handle", "command"}
	case "send_keys":
		str("session_handle")
		props["key"] = map[string]any{"type": "string", "enum": []string{"ctrl-c", "ctrl-d", "enter"}}
		required = []string{"session_handle", "key"}
	case "query":
		str("session_handle")
		str("sql")
		integer("timeout_seconds")
		required = []string{"session_handle", "sql"}
	case "read_screen":
		str("session_handle")
		integer("lines")
		required = []string{"session_handle"}
	case "close_session":
		str("session_handle")
		required = []string{"session_handle"}
	case "close_task":
		integer("request_id")
		str("report")
		required = []string{"request_id", "report"}
	}
	schema := map[string]any{"type": "object", "additionalProperties": false, "properties": props}
	if len(required) > 0 {
		schema["required"] = required
	}
	return schema
}

// NewServer registers the closed v1 surface. A nil dispatcher is for discovery
// tests only and returns an explicit tool error.
func NewServer(dispatch mcp.ToolHandler) *mcp.Server {
	s := mcp.NewServer(&mcp.Implementation{Name: "custodexa", Version: "1"}, nil)
	if dispatch == nil {
		dispatch = func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return toolError("Tool implementation is not available in this build."), nil
		}
	}
	for name, description := range descriptions {
		s.AddTool(&mcp.Tool{Name: name, Description: description, InputSchema: toolSchema(name)}, dispatch)
	}
	return s
}
func toolError(text string) *mcp.CallToolResult {
	return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: text}}}
}

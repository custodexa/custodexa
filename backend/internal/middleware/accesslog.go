package middleware

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// gin access log 的敏感 query 值遮蔽（access log 憑證遮蔽）。
//
// 背景：gin 內建的 defaultLogFormatter 把 `path?rawquery` 原樣印出，於是所有
// 走 query string 傳遞的憑證都逐字進了 access log——實測可見
// `"/api/v1/recordings/stream?rtoken=a4154a8b…"`。rtoken 是取得錄影本體的通行證，
// 用 capability token 的設計目的之一就是避免長效憑證外流，結果它自己躺在
// access log 裡；log 會被轉存、被收集系統帶走，120 秒 TTL 在自動化面前不算短。
// 同型的還有 WebSocket 認證用的 `?token=`（長效登入 JWT）、一次性
// `?connect_token=`，以及 OIDC 回呼的 `?code=`／`?state=`。
//
// 設計取捨：以**參數名語彙**比對，而非「特定端點白名單」。端點清單會隨每個
// change 漂移，漏登記一支就破防；參數名（token／password／secret…）是跨端點穩定
// 的語彙，新端點只要沿用同一組命名就自動受保護。這與前端
// `frontend/src/api/redact.js` 的 SENSITIVE_FRAGMENTS 同一策略、同一組語彙，
// 兩端刻意保持一致以免同一個欄位在一端被遮、另一端沒被遮。
// 誤殺（遮掉非敏感參數）只損失除錯資訊，漏殺則是外洩——刻意偏保守。
//
// **遮值不遮鍵、不遮路徑**：輸出形如 `?rtoken=***&cols=80`，運維仍看得出
// 「誰在什麼時候打了哪一支端點、帶了哪些參數、回什麼狀態」，只是看不到憑證值。
// 整條 URL 消失會讓 access log 失去它唯一的用途。
//
// 邊界（誠實記載）：本檔提供的是**語彙與遮蔽函式**，呼叫點各自負責。目前的
// 呼叫點有二：gin access log（AccessLogFormatter，走 MaskSensitiveRequestTarget）
// 與審計紀錄的查詢摘要（audit_log.go，走 MaskCredentialQuery）。錯誤訊息與
// panic stack 若各自記到同樣的值，仍須各自處理——不在本機制的保護範圍內。
//
// **兩個遮蔽面、同一組語彙、不同的取捨**：
//   - access log 走 IsSensitiveQueryKey＝憑證 ∪ 個資。log 會被轉存、被收集系統
//     帶走，個資不該跟著跑，而遮掉搜尋字串只損失一點除錯資訊。
//   - 審計 details 走 IsCredentialQueryKey＝**只遮憑證**。audit_logs 受檢查點鏈
//     保護、寫進去刪不掉，憑證進去等於被永久封存，故憑證絕不可留；但個資的取捨
//     相反——PCI 10.2.1.3 要的正是「誰以什麼條件查了誰」，把 `q=`／`search=`
//     一併遮掉會讓「對象」這一維消失，摘要就答不出它存在的理由。審計紀錄本來就
//     存 username／client_ip／request_body 的 email（見 audit.MaskSensitiveFields
//     的 safeFields），對它而言個資是內容而非洩漏面。
//
// 語彙只有這一份：兩個面共用同一批片段與 exact key，新增憑證命名只改這裡，
// 不會出現「一端遮了、另一端沒遮」的漂移。

// QueryValueMask 是敏感 query 參數值在 access log 中的替代字串。
// 刻意不帶長度或前綴等任何原值資訊：帶了就等於把暴力搜尋空間縮小。
const QueryValueMask = "***"

// sensitiveQueryFragments 是敏感參數名的語彙片段。
// 比對前會先移除 `_`／`-` 並轉小寫，故 `connect_token`／`connectToken`／
// `CONNECT-TOKEN` 皆命中；`token` 同時涵蓋 `rtoken`／`connect_token`／
// `refresh_token`。刻意不收單獨的 `key`——會誤殺 `sort_key`／`risk_keys` 等。
var sensitiveQueryFragments = []string{
	"password",
	"passwd",
	"passphrase",
	"privatekey",
	"secret",
	"token",
	"credential",
	"apikey",
	"otp",
	"signature",
}

// sensitiveQueryExactKeys 是不含上列語彙、但實際承載憑證的參數名。
// 只做完整比對（正規化後）：`code`／`state` 太短，當片段比對會誤殺
// `status_code`、`estate` 之類的無辜參數名。
//
//   - code、state：OIDC 授權碼與 CSRF nonce（internal/api/oidc_handler.go）
//   - binding：OIDC 裝置綁定雜湊（同上）
var sensitiveQueryExactKeys = map[string]struct{}{
	"code":    {},
	"state":   {},
	"binding": {},
}

// piiQueryExactKeys 是承載自由文字、實務上常含個資的搜尋參數。
//
// 與憑證分開列是刻意的：這一組不是憑證外洩，而是全域紀律「log 不得含個資」
// 的那一半——管理員以 email 搜使用者時，`?search=someone@example.com` 會整串
// 落進 access log 並被收集系統帶走。遮掉只損失「這次篩選條件是什麼」，
// 端點、狀態碼、延遲、其他參數全部保留。
//
//   - search：使用者／資產列表搜尋（user_handler.go、asset_handler.go）
//   - keyword：會話指令搜尋（session_command_handler.go）
//   - q：稽核時間軸 subject 搜尋（audit_timeline_handler.go）
var piiQueryExactKeys = map[string]struct{}{
	"search":  {},
	"keyword": {},
	"q":       {},
}

// queryKeySeparators 是比對前要剔除的命名分隔符（package 級別，避免每個
// 請求的每個參數都重建一次 Replacer——access log 在熱路徑上）。
var queryKeySeparators = strings.NewReplacer("_", "", "-", "")

// normalizeQueryKey 去掉分隔符並轉小寫，使命名風格差異不影響比對。
func normalizeQueryKey(key string) string {
	return queryKeySeparators.Replace(strings.ToLower(key))
}

// normalizedQueryKey 把參數名化為可比對形式。
// 參數名本身可能是 percent-encoded；解得開就以解開後的形式比對，
// 解不開則沿用原字面（不能因為編碼怪異就當成非敏感放行）。
func normalizedQueryKey(key string) string {
	if decoded, err := url.QueryUnescape(key); err == nil {
		key = decoded
	}
	return normalizeQueryKey(key)
}

// IsCredentialQueryKey 判定某個 query 參數名之值是否為**憑證材料**
// （token／密碼／私鑰／OIDC 授權碼等）。
//
// 與 IsSensitiveQueryKey 的差別只在個資那一組：憑證是任何輸出面都不得留存的，
// 個資則因輸出面而異（理由見檔頭「兩個遮蔽面」）。審計 details 用這一支。
func IsCredentialQueryKey(key string) bool {
	normalized := normalizedQueryKey(key)
	if _, ok := sensitiveQueryExactKeys[normalized]; ok {
		return true
	}
	for _, fragment := range sensitiveQueryFragments {
		if strings.Contains(normalized, fragment) {
			return true
		}
	}
	return false
}

// IsSensitiveQueryKey 判定某個 query 參數名之值是否不得進入 access log
// ——憑證 ∪ 個資。
func IsSensitiveQueryKey(key string) bool {
	if IsCredentialQueryKey(key) {
		return true
	}
	if _, ok := piiQueryExactKeys[normalizedQueryKey(key)]; ok {
		return true
	}
	return false
}

// MaskSensitiveQuery 遮蔽 raw query string 中敏感參數的值，其餘原樣保留。
//
// 刻意手工切分而非 url.ParseQuery＋Encode：後者會重排參數順序、重新編碼，
// 使 access log 與使用者實際送出的 URL 對不起來，除錯時反而更難比對。
// 這裡只動「敏感參數的等號右側」，其他 byte 一律不碰。
func MaskSensitiveQuery(rawQuery string) string {
	return maskQueryValues(rawQuery, IsSensitiveQueryKey)
}

// MaskCredentialQuery 只遮憑證參數的值，個資類搜尋參數（search／keyword／q）
// 原樣保留。供審計紀錄的查詢摘要使用——理由見檔頭「兩個遮蔽面」。
func MaskCredentialQuery(rawQuery string) string {
	return maskQueryValues(rawQuery, IsCredentialQueryKey)
}

// maskQueryValues 是兩個遮蔽面共用的切分邏輯：兩者只在「哪些鍵算敏感」上不同，
// 切分／編碼／裸鍵處理必須完全一致，故只此一份實作。
func maskQueryValues(rawQuery string, isSensitive func(string) bool) string {
	if rawQuery == "" {
		return rawQuery
	}
	parts := strings.Split(rawQuery, "&")
	for i, part := range parts {
		if part == "" {
			continue
		}
		key, _, hasValue := strings.Cut(part, "=")
		if !hasValue {
			// 裸鍵無值（例如 guacamole-js tunnel 附加的 `?undefined`）：
			// 沒有值可遮，原樣保留才看得出來實際送了什麼。
			continue
		}
		if isSensitive(key) {
			parts[i] = key + "=" + QueryValueMask
		}
	}
	return strings.Join(parts, "&")
}

// MaskSensitiveRequestTarget 遮蔽 `path?rawquery` 形式字串中的敏感 query 值。
// 無 query string 時原樣回傳；路徑本身不動（路徑是定位資訊，遮了 log 就沒用了）。
func MaskSensitiveRequestTarget(target string) string {
	path, rawQuery, hasQuery := strings.Cut(target, "?")
	if !hasQuery {
		return target
	}
	return path + "?" + MaskSensitiveQuery(rawQuery)
}

// AccessLogFormatter 是 gin access log 的輸出格式器：版面與 gin 內建
// defaultLogFormatter 逐欄相同（既有 log 解析器不必改），唯一差異是
// request target 先過 MaskSensitiveRequestTarget。
//
// **以 param.Path 為輸入而非 param.Request.URL**：gin 在請求進入時就把
// `path?rawquery` 快照進 param.Path，而 c.Request.URL 可被 handler 中途改寫。
// 記錄實際收到的請求才是 access log 的語義。
func AccessLogFormatter(param gin.LogFormatterParams) string {
	var statusColor, methodColor, resetColor string
	if param.IsOutputColor() {
		statusColor = param.StatusCodeColor()
		methodColor = param.MethodColor()
		resetColor = param.ResetColor()
	}

	if param.Latency > time.Minute {
		param.Latency = param.Latency.Truncate(time.Second)
	}
	return fmt.Sprintf("[GIN] %v |%s %3d %s| %13v | %15s |%s %-7s %s %#v\n%s",
		param.TimeStamp.Format("2006/01/02 - 15:04:05"),
		statusColor, param.StatusCode, resetColor,
		param.Latency,
		param.ClientIP,
		methodColor, param.Method, resetColor,
		MaskSensitiveRequestTarget(param.Path),
		param.ErrorMessage,
	)
}

// AccessLogger 回傳掛載了 AccessLogFormatter 的 gin logger middleware。
//
// 存在的理由是「唯一入口」：只要組裝 engine 的地方一律經此取得 logger，
// 就不會有人不小心用回 gin.Default()／gin.Logger() 而悄悄恢復明文輸出。
func AccessLogger() gin.HandlerFunc {
	return gin.LoggerWithFormatter(AccessLogFormatter)
}

// NewEngineWithAccessLog 是 gin.Default() 的替代品：同樣是「gin.New() ＋
// Logger ＋ Recovery」，唯一差異是 logger 換成會遮蔽敏感 query 值的版本。
//
// **中間件鏈的名稱與順序與 gin.Default() 完全相同**：gin.LoggerWithFormatter
// 內部即 LoggerWithConfig，故鏈上仍是 `gin.LoggerWithConfig.func1` →
// `gin.RecoveryWithWriter.func1`，路由鏈 golden 不受影響。
//
// **組裝落在本套件而非 cmd/server**：cmd/server 有 AST 結構守衛
// （route-registration spec，routes_guard_test.go）禁止在 registerRoutes 以外
// 取用 gin 的路由變更方法，`Use` 正在其列。gin.Default() 過去之所以不觸法，
// 是因為那兩次 Use 發生在 gin 套件內；本函式維持同一個結構事實
// ——cmd/server 依然一次路由變更方法都沒呼叫。
// 本函式只掛這兩段全域中間件，不得在此註冊任何路由。
func NewEngineWithAccessLog() *gin.Engine {
	r := gin.New()
	r.Use(AccessLogger(), gin.Recovery())
	return r
}

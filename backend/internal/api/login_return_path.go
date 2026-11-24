package api

import (
	"net/url"
	"regexp"
	"strings"
)

// 登入後回到原本頁面的判準（帳號密碼登入與單一登入共用）。
//
// 只收通知連結會指到的站內頁面與三個查詢鍵（不以前端全站路由的第一段放行）：
// 進入即建立連線、開啟連線分頁或加入進行中會話的頁面（連線頁、工作區、分享頁、即時監看、
// 按鍵紀錄）一律不可作為登入後的目的地，否則「登入」這個動作就能被人帶去建立連線。
// 不合格一律回預設路徑 "/"，不回錯誤：登入不因目的地壞掉而失敗。

// loginReturnPathPatterns 可作為登入後目的地的路徑樣式（以未解碼的路徑完整比對）。
// 樣式只含小寫字母、數字、斜線與連字號，所以出現 `%`、`.` 或任何需要編碼的字元的路徑都不符合，
// 不必另外處理多重編碼與 dot-segment。前端清單 `frontend/src/router/loginReturnRoutes.js`
// 只決定導向登入頁時要不要帶目的地，由 TestLoginReturnRoutesNoDrift 核對兩邊一致。
var loginReturnPathPatterns = []*regexp.Regexp{
	regexp.MustCompile(`^/approvals$`),
	regexp.MustCompile(`^/audit-logs$`),
	regexp.MustCompile(`^/audit/agent-tasks/[0-9]{1,10}$`),
	regexp.MustCompile(`^/agent-breakers$`),
	regexp.MustCompile(`^/alerts$`),
	regexp.MustCompile(`^/sessions/[0-9]{1,10}$`),
	regexp.MustCompile(`^/notification-channels$`),
}

// loginReturnQueryKeys 保留的查詢鍵與重組順序：審核中心與操作日誌的頁籤、審核中心的單號、
// 熔斷事件頁的使用者識別。各頁另自行驗證自己的參數。
var loginReturnQueryKeys = []string{"tab", "request", "user_id"}

// loginReturnQueryValue 保留鍵的值：英數字、底線與連字號，1 到 32 字。
var loginReturnQueryValue = regexp.MustCompile(`^[A-Za-z0-9_-]{1,32}$`)

// loginReturnMaxLen 輸入與重組結果的長度上限。
const loginReturnMaxLen = 255

// sanitizeLoginReturnPath 回傳判準後的登入後目的地；任何一項不符回 "/"。
//   - 帶 scheme、主機、使用者資訊，以 `//` 開頭，含反斜線或控制字元，或超過長度上限
//   - 路徑（未解碼）不完整符合 loginReturnPathPatterns 之一
//   - 查詢字串解析失敗；任何值解碼一次後仍含 `%`（多重編碼）；保留鍵重複或值不合格
//
// 其餘不認得的查詢鍵與片段丟棄，保留鍵依固定順序重組。
func sanitizeLoginReturnPath(raw string) string {
	const fallback = "/"
	if raw == "" || len(raw) > loginReturnMaxLen || strings.HasPrefix(raw, "//") || strings.Contains(raw, "\\") {
		return fallback
	}
	for i := 0; i < len(raw); i++ {
		if raw[i] < 0x20 || raw[i] == 0x7f {
			return fallback
		}
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "" || u.Host != "" || u.User != nil || u.Opaque != "" {
		return fallback
	}
	path := u.EscapedPath()
	matched := false
	for _, re := range loginReturnPathPatterns {
		if re.MatchString(path) {
			matched = true
			break
		}
	}
	if !matched {
		return fallback
	}
	values, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return fallback
	}
	for _, vs := range values {
		for _, v := range vs {
			if strings.Contains(v, "%") {
				return fallback
			}
		}
	}
	var b strings.Builder
	b.WriteString(path)
	sep := byte('?')
	for _, key := range loginReturnQueryKeys {
		vs, ok := values[key]
		if !ok {
			continue
		}
		if len(vs) != 1 || !loginReturnQueryValue.MatchString(vs[0]) {
			return fallback
		}
		b.WriteByte(sep)
		b.WriteString(key)
		b.WriteByte('=')
		b.WriteString(vs[0])
		sep = '&'
	}
	out := b.String()
	if len(out) > loginReturnMaxLen {
		return fallback
	}
	return out
}

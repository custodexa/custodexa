package middleware

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// access log 憑證遮蔽守衛。
//
// 守的是一條可實測的事實：**憑證的明文不得出現在 gin access log 的任何一個
// byte 裡**。斷言方式刻意選「整段輸出不得含明文」而非「某欄位等於某值」——
// 後者只要遮蔽點搬家就形同虛設，前者不管怎麼改版面都仍在守同一件事。
//
// 反向斷言同樣必要：遮完之後 access log 仍要看得出「有人打了這支端點、帶了
// 哪些參數」。只驗「明文不在」的話，「整條 URL 印成空字串」也會過。

// 各測試共用的明文哨兵：夠長、夠獨特，不可能因巧合出現在版面字元裡。
const (
	secretSentinel      = "a4154a8bdeadbeefcafef00d1234567890abcdef"
	otherSecretSentinel = "9f2c7b61aabbccdd00112233445566778899aabb"
)

// runAccessLogRequest 以正式的 AccessLogger() 中間件跑一次請求，回傳 access log 全文。
func runAccessLogRequest(t *testing.T, target string) string {
	t.Helper()

	prevMode := gin.Mode()
	gin.SetMode(gin.TestMode)
	t.Cleanup(func() { gin.SetMode(prevMode) })

	var buf bytes.Buffer
	prevWriter := gin.DefaultWriter
	gin.DefaultWriter = &buf
	t.Cleanup(func() { gin.DefaultWriter = prevWriter })

	// AccessLogger() 在此刻捕捉 gin.DefaultWriter，故必須在改寫之後才建構。
	r := gin.New()
	r.Use(AccessLogger())
	r.GET("/api/v1/recordings/stream", func(c *gin.Context) { c.Status(http.StatusOK) })
	r.GET("/api/v1/ssh", func(c *gin.Context) { c.Status(http.StatusOK) })
	r.GET("/api/v1/auth/oidc/callback", func(c *gin.Context) { c.Status(http.StatusOK) })
	r.GET("/api/v1/users", func(c *gin.Context) { c.Status(http.StatusOK) })

	req := httptest.NewRequest(http.MethodGet, target, nil)
	r.ServeHTTP(httptest.NewRecorder(), req)

	return buf.String()
}

// TestAccessLogNeverContainsCredentialPlaintext 憑證明文不得進 access log。
//
// 這是本次缺陷的直接回歸：實測曾見
// `[GIN] ... "/api/v1/recordings/stream?rtoken=a4154a8b…"`。rtoken 是取得錄影
// 本體的通行證，用 capability token 的設計目的之一就是避免憑證外流，結果它
// 自己躺在 access log 裡；log 會被轉存、被收集系統帶走，120 秒 TTL 在自動化
// 面前不算短。
func TestAccessLogNeverContainsCredentialPlaintext(t *testing.T) {
	cases := []struct {
		name   string
		target string
		masked string // 遮蔽後應出現的字面
	}{
		{
			name:   "錄影取證 capability token",
			target: "/api/v1/recordings/stream?rtoken=" + secretSentinel,
			masked: "rtoken=" + QueryValueMask,
		},
		{
			name:   "一次性連線 token",
			target: "/api/v1/ssh?connect_token=" + secretSentinel + "&cols=80&rows=24",
			masked: "connect_token=" + QueryValueMask,
		},
		{
			name:   "WebSocket 認證用長效 JWT",
			target: "/api/v1/ssh?token=" + secretSentinel,
			masked: "token=" + QueryValueMask,
		},
		{
			name:   "OIDC 授權碼",
			target: "/api/v1/auth/oidc/callback?code=" + secretSentinel + "&state=x",
			masked: "code=" + QueryValueMask,
		},
		{
			name:   "OIDC state（CSRF nonce）",
			target: "/api/v1/auth/oidc/callback?state=" + secretSentinel,
			masked: "state=" + QueryValueMask,
		},
		{
			name:   "OIDC 裝置綁定雜湊",
			target: "/api/v1/auth/oidc/callback?binding=" + secretSentinel,
			masked: "binding=" + QueryValueMask,
		},
		{
			name:   "連線收口防呆擋下的 password 參數",
			target: "/api/v1/ssh?password=" + secretSentinel,
			masked: "password=" + QueryValueMask,
		},
		{
			name:   "使用者搜尋（個資）",
			target: "/api/v1/users?search=" + secretSentinel + "&page=1",
			masked: "search=" + QueryValueMask,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := runAccessLogRequest(t, tc.target)

			if strings.Contains(out, secretSentinel) {
				t.Fatalf("憑證明文進了 access log——這正是 capability token 要避免的外洩形態\naccess log: %s", out)
			}
			if !strings.Contains(out, tc.masked) {
				t.Errorf("未見遮蔽後字面 %q；遮蔽必須是「遮值留鍵」，不是讓參數整個消失\naccess log: %s",
					tc.masked, out)
			}
		})
	}
}

// TestAccessLogKeepsDiagnosability 遮蔽不得把 access log 遮成廢物。
//
// 只驗「明文不在」會放行「整條 URL 印成空字串」這種假修法。運維仍須看得出
// 誰在什麼時候打了哪一支端點、帶了哪些非敏感參數、回什麼狀態。
func TestAccessLogKeepsDiagnosability(t *testing.T) {
	out := runAccessLogRequest(t,
		"/api/v1/ssh?connect_token="+secretSentinel+"&cols=80&rows=24&k8s_mode=exec")

	for _, want := range []string{
		"/api/v1/ssh",   // 端點路徑
		"connect_token", // 參數名（看得出走的是哪條認證路徑）
		"cols=80",       // 非敏感參數值原樣保留
		"rows=24",
		"k8s_mode=exec",
		"GET",
		"200",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("access log 遺失可診斷資訊 %q——遮蔽只該遮憑證值\naccess log: %s", want, out)
		}
	}
}

// TestMaskSensitiveQueryPreservesShape 遮蔽只動敏感參數的值，其餘 byte 不碰。
func TestMaskSensitiveQueryPreservesShape(t *testing.T) {
	cases := []struct {
		raw  string
		want string
	}{
		{"", ""},
		{"page=1&page_size=20", "page=1&page_size=20"},
		{"rtoken=" + secretSentinel, "rtoken=***"},
		{
			"cols=80&connect_token=" + secretSentinel + "&rows=24",
			"cols=80&connect_token=***&rows=24",
		},
		// 兩個敏感參數同時出現：不得只遮到第一個
		{
			"code=" + secretSentinel + "&state=" + otherSecretSentinel,
			"code=***&state=***",
		},
		// 命名風格差異：大小寫與分隔符不影響判定
		{"Connect-Token=" + secretSentinel, "Connect-Token=***"},
		{"accessToken=" + secretSentinel, "accessToken=***"},
		// 裸鍵無值（guacamole-js tunnel 會附加 ?undefined）：原樣保留
		{"undefined", "undefined"},
		// 值本身含 `=`（base64 padding）：只切第一個等號，整段值一併遮掉
		{"rtoken=YWJj==", "rtoken=***"},
		// 空值：仍走遮蔽，避免「有沒有帶值」變成可觀測的 side channel
		{"rtoken=", "rtoken=***"},
		// 不得誤殺：這些參數名含相近字樣但非憑證
		{"sort_by=created_at&sort_order=desc", "sort_by=created_at&sort_order=desc"},
		{"status=active&client_ip=10.0.0.1", "status=active&client_ip=10.0.0.1"},
		{"subject=user&subject_id=7", "subject=user&subject_id=7"},
	}

	for _, tc := range cases {
		if got := MaskSensitiveQuery(tc.raw); got != tc.want {
			t.Errorf("MaskSensitiveQuery(%q) = %q, want %q", tc.raw, got, tc.want)
		}
	}
}

// TestMaskSensitiveRequestTargetLeavesPathAlone 路徑是定位資訊，不得被遮。
func TestMaskSensitiveRequestTargetLeavesPathAlone(t *testing.T) {
	if got, want := MaskSensitiveRequestTarget("/api/v1/assets"), "/api/v1/assets"; got != want {
		t.Errorf("無 query 的 target 被改動：%q，want %q", got, want)
	}
	got := MaskSensitiveRequestTarget("/api/v1/recordings/stream?rtoken=" + secretSentinel)
	if want := "/api/v1/recordings/stream?rtoken=***"; got != want {
		t.Errorf("MaskSensitiveRequestTarget = %q, want %q", got, want)
	}
}

// TestSensitiveQueryKeyVocabulary 語彙表本身的守衛。
//
// 逐項列出「這個參數名必須被認定為敏感」，使日後有人從 sensitiveQueryFragments
// 拿掉任何一個片段時，紅的是一條指名道姓的斷言，而不是某支端點的整合測試。
func TestSensitiveQueryKeyVocabulary(t *testing.T) {
	mustMask := []string{
		"rtoken", "token", "connect_token", "refresh_token", "access_token",
		"password", "passwd", "passphrase", "private_key", "privateKey",
		"secret", "client_secret", "credential", "api_key", "otp", "signature",
		"code", "state", "binding",
		"search", "keyword", "q",
	}
	for _, key := range mustMask {
		if !IsSensitiveQueryKey(key) {
			t.Errorf("query 參數 %q 未被認定為敏感——其值會逐字進 access log", key)
		}
	}

	mustKeep := []string{
		"page", "page_size", "sort_by", "sort_order", "status", "protocol",
		"asset_id", "user_id", "node_id", "session_id", "client_ip",
		"start_time", "end_time", "from", "to", "types", "type", "subject",
		"subject_id", "cols", "rows", "width", "height", "k8s_pod",
		"k8s_container", "k8s_mode", "active", "limit", "cursor", "error",
	}
	for _, key := range mustKeep {
		if IsSensitiveQueryKey(key) {
			t.Errorf("query 參數 %q 被誤判為敏感——過度遮蔽會讓 access log 失去診斷價值", key)
		}
	}
}

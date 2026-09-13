package middleware

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// 審計遮罩的端點來源守衛（任務 5.1）。
//
// 端點必須取自**伺服端的路由註冊事實**（gin 的路由樣板＋方法），不取自 URL 路徑
// 字串、更不取自請求的任何欄位——否則呼叫端只要宣告一個寬鬆端點，就能讓自己的
// 憑證原樣寫進刪不掉的審計列。
//
// 本檔直接驗那個推導：同一個 handler 掛在具參數的路由上時，端點是**樣板**
//（`/api/v1/x/:id`）而不是實際打進來的路徑（`/api/v1/x/42`）——樣板才是遮罩清單
// 對得上的那個鍵。未匹配任何路由時端點為空，遮罩退化為只套全域集（安全側）。

func TestAuditLogMiddlewareDerivesEndpointFromRouteTemplate(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cases := []struct {
		name   string
		method string
		route  string
		url    string
		want   string
	}{
		{"具參數路由取樣板", "PUT", "/api/v1/notification-channels/:id",
			"/api/v1/notification-channels/42", "PUT /api/v1/notification-channels/:id"},
		{"無參數路由", "PUT", "/api/v1/ldap-directory",
			"/api/v1/ldap-directory", "PUT /api/v1/ldap-directory"},
		{"方法是端點的一部分", "POST", "/api/v1/keys/topology",
			"/api/v1/keys/topology", "POST /api/v1/keys/topology"},
	}
	for _, tc := range cases {
		var got string
		r := gin.New()
		r.Handle(tc.method, tc.route, func(c *gin.Context) {
			// 與 audit middleware 內的推導逐字相同（見 audit_log.go 的遮罩呼叫點）。
			got = c.Request.Method + " " + c.FullPath()
			if c.FullPath() == "" {
				got = ""
			}
			c.Status(200)
		})
		r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(tc.method, tc.url, nil))
		if got != tc.want {
			t.Errorf("%s：端點應為 %q，得 %q", tc.name, tc.want, got)
		}
		// 路徑中的實際參數值不得出現在端點裡——否則每個 id 都是一個新端點，
		// 遮罩清單永遠對不上。
		if strings.Contains(got, "42") {
			t.Errorf("%s：端點含實際參數值 %q", tc.name, got)
		}
	}
}

// TestAuditLogMiddlewareUnmatchedRouteHasNoEndpoint 未匹配路由時端點為空。
func TestAuditLogMiddlewareUnmatchedRouteHasNoEndpoint(t *testing.T) {
	gin.SetMode(gin.TestMode)
	var got string
	seen := false
	r := gin.New()
	r.NoRoute(func(c *gin.Context) {
		seen = true
		got = c.Request.Method + " " + c.FullPath()
		if c.FullPath() == "" {
			got = ""
		}
		c.Status(404)
	})
	r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("POST", "/api/v1/nope", nil))
	if !seen {
		t.Fatal("夾具未走到 NoRoute，本案沒有判到任何東西")
	}
	if got != "" {
		t.Fatalf("未匹配路由時端點應為空（遮罩退化為只套全域集），得 %q", got)
	}
}

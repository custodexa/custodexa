package sshproxy

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/identity"
)

// 唯讀觀看的兩條 WS 一律以一次性觀看票認證，票由掛認證中介層的簽發端點發出。
// 本檔的助手一律**走生產路徑取票**（真的 POST 簽發端點、真的帶 Authorization
// 標頭），而不是直接呼叫 IssueObserverTicket——後者等於替 handler 把准入判定
// 先做完了，簽發端的角色現查、目標會話檢查、分享碼解析全都測不到。

// observerTicketEngine 生產形狀的四條路由：兩支簽發掛 AuthMiddleware，
// 兩條 WS 不掛（與 cmd/server/main.go 一致）
func observerTicketEngine(h *Handler, auth *identity.AuthService) *gin.Engine {
	r := gin.New()
	r.POST("/api/v1/sessions/:id/monitor-token",
		middleware.AuthMiddleware(auth), h.HandleCreateMonitorTicket)
	r.GET("/api/v1/sessions/:id/monitor", h.HandleMonitor)
	r.POST("/api/v1/sessions/share/token",
		middleware.AuthMiddleware(auth), h.HandleCreateShareTicket)
	r.GET("/api/v1/sessions/share/:code/ws", h.HandleShareJoin)
	return r
}

// postObserverTicket 呼叫簽發端點，回傳 HTTP 狀態碼與回應本體。
// body 非空時以 JSON 送出（分享票的碼走請求本體）
func postObserverTicket(r *gin.Engine, path, jwt string, reqBody ...string) (int, map[string]any) {
	var payload io.Reader
	if len(reqBody) > 0 && reqBody[0] != "" {
		payload = strings.NewReader(reqBody[0])
	}
	req := httptest.NewRequest(http.MethodPost, path, payload)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+jwt)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	var body map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	return w.Code, body
}

// mustObserverTicket 取一張票；簽發失敗即 Fatal（呼叫端期待成功路徑）
func mustObserverTicket(t *testing.T, r *gin.Engine, path, jwt string, reqBody ...string) string {
	t.Helper()
	code, body := postObserverTicket(r, path, jwt, reqBody...)
	if code != http.StatusOK {
		t.Fatalf("簽發觀看票 %s 應 200，實得 %d（body=%v）", path, code, body)
	}
	tok, _ := body["connect_token"].(string)
	if tok == "" {
		t.Fatalf("簽發觀看票 %s 未回 connect_token（body=%v）", path, body)
	}
	return tok
}

// monitorTicketPath／shareTicketPath 兩支簽發端點的路徑
func monitorTicketPath(sessionID uint) string {
	return fmt.Sprintf("/api/v1/sessions/%d/monitor-token", sessionID)
}

const shareTicketPath = "/api/v1/sessions/share/token"

// shareTicketBody 分享票簽發的請求本體（碼不進路徑）
func shareTicketBody(code string) string {
	return `{"code":` + strconv.Quote(code) + `}`
}

// monitorWSPath／shareWSPath 兩條 WS 的路徑（帶票）
func monitorWSPath(sessionID uint, ticket string) string {
	return fmt.Sprintf("/api/v1/sessions/%d/monitor?connect_token=%s", sessionID, ticket)
}

func shareWSPath(code, ticket string) string {
	return "/api/v1/sessions/share/" + code + "/ws?connect_token=" + ticket
}

// grantDBRole 給使用者一個 DB 角色列——**角色現查的事實源**。
// 監看票的簽發以 primaryRoleOf 折疊後的現時角色判定，不採信 JWT 內的角色快照，
// 故測試裡的 admin／auditor 觀察者必須真的有這一列
func grantDBRole(t *testing.T, db *gorm.DB, userID uint, roleName string) {
	t.Helper()
	var role model.Role
	if err := db.Where("name = ?", roleName).First(&role).Error; err != nil {
		role = model.Role{Name: roleName}
		if err := db.Create(&role).Error; err != nil {
			t.Fatalf("建立角色 %s: %v", roleName, err)
		}
	}
	var u model.User
	if err := db.First(&u, userID).Error; err != nil {
		t.Fatalf("load user %d: %v", userID, err)
	}
	if err := db.Model(&u).Association("Roles").Append(&role); err != nil {
		t.Fatalf("append role %s: %v", roleName, err)
	}
}

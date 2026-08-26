package api

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/custodexa/backend/config"
	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/session"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// 剪貼簿調閱 API（v2 語義）。
//
// 本檔釘四件事：
//  1. List 為事實投影：回應 JSON **無內容欄位**（content／content_enc 缺席），
//     content_status 在值域內、缺口態可辨識；頁面級審計恰一筆含
//     result_count（真 handler ＋ 真 AuditLogMiddleware 全鏈）。
//  2. List 的頁面級審計寫入失敗不影響回應（既有降級鏈，非 fail-close——
//     與單筆內容端點的 fail-close 分屬兩種粒度，後者在
//     internal/modules/session/clipboard_content_service_test.go）。
//  3. 單筆內容端點的 HTTP 收斂映射：成功 200 帶 content、缺口 200 無 content 鍵、
//     不存在／跨會話 404 收斂碼、其他失敗 500 收斂碼不洩細節。
//  4. 無 audit:view 權限者被真權限中介層擋在 403（List 與單筆端點同閘）。

type stubClipboardLister struct {
	events []model.ClipboardEvent
}

func (s *stubClipboardLister) ListClipboardEvents(sessionID uint) ([]model.ClipboardEvent, error) {
	return s.events, nil
}

type stubClipboardContentReader struct {
	view *session.ClipboardContentView
	err  error
}

func (s *stubClipboardContentReader) ReadContent(_ context.Context, _, _ uint,
	_ session.ClipboardReadOperator) (*session.ClipboardContentView, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.view, nil
}

// installClipboardHandlerAuditDB 換上 :memory: 審計庫並回傳它供讀回斷言。
// MaxOpenConns(1)：sqlite :memory: 每條新連線是獨立空 DB，收斂到 1
// 才能讓 middleware 的寫入與本測試的讀回落在同一個 DB 上（ff51836 教訓）
func installClipboardHandlerAuditDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("取底層 sql.DB: %v", err)
	}
	sqlDB.SetMaxOpenConns(1)
	if err := db.AutoMigrate(&model.AuditLog{}); err != nil {
		t.Fatalf("migrate audit_logs: %v", err)
	}
	old := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = old })
	return db
}

// clipboardListAuditRouter 真 middleware ＋ 真 handler。同步審計
// （AsyncAuditEnabled=false）以免 worker 批次帶入時序不確定
func clipboardListAuditRouter(t *testing.T, lister ClipboardEventLister, flags *config.FeatureFlags) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	svc := audit.NewAuditLogService(flags)
	r := gin.New()
	r.Use(middleware.AuditLogMiddleware(svc))
	r.Use(func(c *gin.Context) {
		c.Set("userID", uint(9))
		c.Set("username", "auditor")
		c.Next()
	})
	h := NewClipboardEventHandler(lister, &stubClipboardContentReader{})
	r.GET("/api/v1/sessions/:id/clipboard-events", h.List)
	return r
}

func twoClipboardEvents() []model.ClipboardEvent {
	base := time.Date(2026, 8, 24, 10, 0, 0, 0, time.UTC)
	return []model.ClipboardEvent{
		{ID: 1, SessionID: 73, Direction: "send", ContentEnc: "enc:a1:v1:ciphertext-alpha",
			ContentLength: 5, ContentStatus: model.ClipboardContentAvailable, CreatedAt: base},
		// 缺口紀錄：內容缺席、失敗標記（可辨識，不與「無此事件」混同）
		{ID: 2, SessionID: 73, Direction: "recv", ContentEnc: "",
			ContentLength: 4, ContentStatus: model.ClipboardContentFailed, CreatedAt: base.Add(time.Minute)},
	}
}

// clipboardFactJSON 以泛型 map 解回應，逐鍵斷言（struct 解碼會把「多出的鍵」吞掉）
type clipboardListRawBody struct {
	Data  []map[string]interface{} `json:"data"`
	Total int                      `json:"total"`
}

func decodeClipboardListRaw(t *testing.T, raw []byte) clipboardListRawBody {
	t.Helper()
	var body clipboardListRawBody
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatalf("回應非預期 JSON: %q (%v)", raw, err)
	}
	return body
}

// TestClipboardListFactsProjection List 為事實投影：無內容欄位、
// content_status 在值域內且缺口態可辨識
func TestClipboardListFactsProjection(t *testing.T) {
	installClipboardHandlerAuditDB(t)
	r := clipboardListAuditRouter(t, &stubClipboardLister{events: twoClipboardEvents()},
		&config.FeatureFlags{AuditLogEnabled: true, AsyncAuditEnabled: false, AuditFallbackToFile: false})

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/api/v1/sessions/73/clipboard-events", nil))
	if w.Code != 200 {
		t.Fatalf("List 應成功，得 %d：%s", w.Code, w.Body.String())
	}
	body := decodeClipboardListRaw(t, w.Body.Bytes())
	if body.Total != 2 || len(body.Data) != 2 {
		t.Fatalf("total=%d len=%d, want 2/2", body.Total, len(body.Data))
	}
	statusDomain := map[string]bool{model.ClipboardContentAvailable: true, model.ClipboardContentFailed: true}
	for i, item := range body.Data {
		for _, forbidden := range []string{"content", "content_enc"} {
			if _, has := item[forbidden]; has {
				t.Errorf("data[%d] 含禁止欄位 %q（列表不得揭露內容）", i, forbidden)
			}
		}
		for _, required := range []string{"id", "session_id", "direction", "content_length", "content_status", "created_at"} {
			if _, has := item[required]; !has {
				t.Errorf("data[%d] 缺事實欄位 %q", i, required)
			}
		}
		if st, _ := item["content_status"].(string); !statusDomain[st] {
			t.Errorf("data[%d].content_status = %q 不在值域 {available, failed}", i, st)
		}
	}
	if st, _ := body.Data[1]["content_status"].(string); st != model.ClipboardContentFailed {
		t.Errorf("缺口紀錄的 content_status = %q, want failed（可辨識）", st)
	}
	// 密文與明文都不得出現在回應位元組裡
	if strings.Contains(w.Body.String(), "ciphertext-alpha") {
		t.Error("回應洩出密文欄")
	}
}

// TestClipboardContentStatusDomainPinned content_status 值域釘住：
// 值即 DB 與前端契約，改值等同 migration，不可隨手改
func TestClipboardContentStatusDomainPinned(t *testing.T) {
	if model.ClipboardContentAvailable != "available" || model.ClipboardContentFailed != "failed" {
		t.Fatalf("content_status 值域漂移: available=%q failed=%q",
			model.ClipboardContentAvailable, model.ClipboardContentFailed)
	}
}

// TestClipboardListWritesSingleAuditRowWithCount List 成功 → 恰一筆審計列，
// 含操作者、會話 id 與筆數
func TestClipboardListWritesSingleAuditRowWithCount(t *testing.T) {
	db := installClipboardHandlerAuditDB(t)
	r := clipboardListAuditRouter(t, &stubClipboardLister{events: twoClipboardEvents()},
		&config.FeatureFlags{AuditLogEnabled: true, AsyncAuditEnabled: false, AuditFallbackToFile: false})

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/api/v1/sessions/73/clipboard-events", nil))
	if w.Code != 200 {
		t.Fatalf("List 應成功（審計斷言須打在被受理的請求上），得 %d：%s", w.Code, w.Body.String())
	}

	var rows []model.AuditLog
	if err := db.Find(&rows).Error; err != nil {
		t.Fatalf("讀 audit_logs: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("audit_logs 應恰一筆（頁面級粒度，不逐事件展開、不重複記），得 %d", len(rows))
	}
	row := rows[0]
	if row.UserID != 9 || row.Username != "auditor" {
		t.Errorf("操作者 = (%d, %q), want (9, \"auditor\")", row.UserID, row.Username)
	}
	if row.Resource != model.ResourceClipboardEvent {
		t.Errorf("resource = %s, want %s", row.Resource, model.ResourceClipboardEvent)
	}
	if row.ResourceID == nil || *row.ResourceID != 73 {
		t.Errorf("resource_id = %v, want 73（會話 id）", row.ResourceID)
	}
	var details map[string]string
	if err := json.Unmarshal([]byte(row.Details), &details); err != nil {
		t.Fatalf("details 非 JSON 物件: %q (%v)", row.Details, err)
	}
	if details["session_id"] != "73" {
		t.Errorf("details.session_id = %q, want \"73\"（實得 details=%s）", details["session_id"], row.Details)
	}
	if details["result_count"] != "2" {
		t.Errorf("details.result_count = %q, want \"2\"（「取走幾筆證物」須留痕；實得 details=%s）",
			details["result_count"], row.Details)
	}
}

// TestClipboardListAuditWriteFailureKeepsResponse 審計寫入失敗 → 回應仍 200
// 且事實 data 完整（頁面級審計走既有降級鏈，非 fail-close）。故障＝拆掉
// audit_logs 表使同步寫庫必敗；「注入點真的走到」以降級檔案為證——該檔只會
// 在寫庫**已嘗試且失敗**後出現，且其列帶 result_count
func TestClipboardListAuditWriteFailureKeepsResponse(t *testing.T) {
	fallbackDir := t.TempDir()
	t.Setenv("AUDIT_LOG_PATH", fallbackDir) // 須在 NewAuditLogService 之前生效

	db := installClipboardHandlerAuditDB(t)
	r := clipboardListAuditRouter(t, &stubClipboardLister{events: twoClipboardEvents()},
		&config.FeatureFlags{AuditLogEnabled: true, AsyncAuditEnabled: false, AuditFallbackToFile: true})

	if err := db.Exec("DROP TABLE audit_logs").Error; err != nil {
		t.Fatalf("故障注入（拆表）失敗: %v", err)
	}

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/api/v1/sessions/73/clipboard-events", nil))
	if w.Code != 200 {
		t.Fatalf("審計寫入失敗不得使請求失敗，得 %d：%s", w.Code, w.Body.String())
	}
	body := decodeClipboardListRaw(t, w.Body.Bytes())
	if body.Total != 2 || len(body.Data) != 2 {
		t.Fatalf("回應 data 須完整，得 total=%d len=%d", body.Total, len(body.Data))
	}

	// 注入點走到的證據：降級檔案存在且該列屬於本請求、帶筆數
	entries, err := os.ReadDir(fallbackDir)
	if err != nil {
		t.Fatalf("讀 fallback 目錄: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("fallback 檔未出現——審計寫入路徑未走到（故障從未觸發），本測試失去證明力")
	}
	raw, err := os.ReadFile(filepath.Join(fallbackDir, entries[0].Name()))
	if err != nil {
		t.Fatalf("讀 fallback 檔: %v", err)
	}
	line := strings.TrimSpace(string(raw))
	var dropped model.AuditLog
	if err := json.Unmarshal([]byte(line), &dropped); err != nil {
		t.Fatalf("fallback 列非 JSON: %q (%v)", line, err)
	}
	if dropped.Path != "/api/v1/sessions/73/clipboard-events" {
		t.Errorf("fallback 列 path = %q，不是本請求", dropped.Path)
	}
	var details map[string]string
	if err := json.Unmarshal([]byte(dropped.Details), &details); err != nil {
		t.Fatalf("fallback 列 details 非 JSON 物件: %q (%v)", dropped.Details, err)
	}
	if details["result_count"] != "2" {
		t.Errorf("fallback 列 details.result_count = %q, want \"2\"——被嘗試寫入的條目未帶筆數", details["result_count"])
	}
}

// clipboardContentRouter 單筆內容端點：身分 stub ＋ 真 handler（服務層以 stub 注入，
// fail-close 語義在 service 測試已驗；此處驗 HTTP 收斂映射）
func clipboardContentRouter(reader ClipboardContentReader) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("userID", uint(9))
		c.Set("username", "auditor")
		c.Next()
	})
	h := NewClipboardEventHandler(&stubClipboardLister{}, reader)
	r.GET("/api/v1/sessions/:id/clipboard-events/:eventID/content", h.GetContent)
	return r
}

func TestClipboardContentEndpointSuccess(t *testing.T) {
	base := time.Date(2026, 8, 24, 10, 0, 0, 0, time.UTC)
	r := clipboardContentRouter(&stubClipboardContentReader{view: &session.ClipboardContentView{
		Event: model.ClipboardEvent{ID: 5, SessionID: 73, Direction: "send",
			ContentLength: 5, ContentStatus: model.ClipboardContentAvailable, CreatedAt: base},
		Content: "alpha",
	}})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/api/v1/sessions/73/clipboard-events/5/content", nil))
	if w.Code != 200 {
		t.Fatalf("code = %d：%s", w.Code, w.Body.String())
	}
	var body struct {
		Data map[string]interface{} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("回應非 JSON: %v", err)
	}
	if body.Data["content"] != "alpha" || body.Data["content_status"] != model.ClipboardContentAvailable {
		t.Errorf("data = %+v", body.Data)
	}
}

// TestClipboardContentEndpointGapOmitsContentKey 缺口紀錄：content 鍵**缺席**
// （不以空字串冒充），content_status=failed 可辨識
func TestClipboardContentEndpointGapOmitsContentKey(t *testing.T) {
	r := clipboardContentRouter(&stubClipboardContentReader{view: &session.ClipboardContentView{
		Event: model.ClipboardEvent{ID: 6, SessionID: 73, Direction: "recv",
			ContentLength: 4, ContentStatus: model.ClipboardContentFailed},
	}})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/api/v1/sessions/73/clipboard-events/6/content", nil))
	if w.Code != 200 {
		t.Fatalf("code = %d：%s", w.Code, w.Body.String())
	}
	var body struct {
		Data map[string]interface{} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("回應非 JSON: %v", err)
	}
	if _, has := body.Data["content"]; has {
		t.Errorf("缺口紀錄的 content 鍵應缺席: %+v", body.Data)
	}
	if body.Data["content_status"] != model.ClipboardContentFailed {
		t.Errorf("content_status = %v, want failed", body.Data["content_status"])
	}
}

// TestClipboardContentEndpointConvergedErrors 不存在／跨會話 → 404 收斂碼；
// 內部失敗（含審計不可用的 fail-close 拒絕）→ 500 收斂碼，原因不外洩
func TestClipboardContentEndpointConvergedErrors(t *testing.T) {
	// 不存在與跨會話由 service 收斂為同一 typed error
	r := clipboardContentRouter(&stubClipboardContentReader{err: session.ErrClipboardEventNotFound})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/api/v1/sessions/73/clipboard-events/999/content", nil))
	if w.Code != 404 {
		t.Fatalf("code = %d, want 404：%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), string(apierror.CodeClipboardEventNotFound)) {
		t.Errorf("回應未帶收斂機器碼: %s", w.Body.String())
	}

	// 其他失敗一律 500 收斂碼；內部原因（此處故意帶敏感字串）不得出現在回應
	r = clipboardContentRouter(&stubClipboardContentReader{
		err: &sensitiveError{msg: "audit sink down at 10.1.2.3 (internal-forensic-detail)"}})
	w = httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/api/v1/sessions/73/clipboard-events/5/content", nil))
	if w.Code != 500 {
		t.Fatalf("code = %d, want 500：%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), string(apierror.CodeInternalClipboardQuery)) {
		t.Errorf("回應未帶收斂機器碼: %s", w.Body.String())
	}
	if strings.Contains(w.Body.String(), "internal-forensic-detail") {
		t.Errorf("內部失敗原因外洩: %s", w.Body.String())
	}

	// eventID 非法：同一收斂 404（不洩「格式錯」與「不存在」的差異）
	r = clipboardContentRouter(&stubClipboardContentReader{})
	w = httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/api/v1/sessions/73/clipboard-events/not-a-number/content", nil))
	if w.Code != 404 || !strings.Contains(w.Body.String(), string(apierror.CodeClipboardEventNotFound)) {
		t.Errorf("非法 eventID 應收斂 404: code=%d body=%s", w.Code, w.Body.String())
	}
}

type sensitiveError struct{ msg string }

func (e *sensitiveError) Error() string { return e.msg }

// TestClipboardRoutesRequireAuditView 無 audit:view 者被真權限中介層擋在 403：
// List 與單筆內容端點同閘（user 角色無 audit:view；權限矩陣見
// authz.RoutePermissions）
func TestClipboardRoutesRequireAuditView(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("userID", uint(7))
		c.Set("username", "plainuser")
		c.Set("role", "user")
		c.Next()
	})
	h := NewClipboardEventHandler(
		&stubClipboardLister{events: twoClipboardEvents()},
		&stubClipboardContentReader{view: &session.ClipboardContentView{
			Event:   model.ClipboardEvent{ID: 5, SessionID: 73, ContentStatus: model.ClipboardContentAvailable},
			Content: "must-not-reach-user",
		}})
	g := r.Group("/api/v1/sessions/:id/clipboard-events")
	g.Use(middleware.RequirePermission(middleware.PermAuditView))
	g.GET("", h.List)
	g.GET("/:eventID/content", h.GetContent)

	for _, path := range []string{
		"/api/v1/sessions/73/clipboard-events",
		"/api/v1/sessions/73/clipboard-events/5/content",
	} {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		if w.Code != 403 {
			t.Errorf("%s：code = %d, want 403（user 角色無 audit:view）", path, w.Code)
		}
		if strings.Contains(w.Body.String(), "must-not-reach-user") {
			t.Errorf("%s：403 回應洩出內容", path)
		}
	}
}

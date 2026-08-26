package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/custodexa/backend/config"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
)

// 位址樞紐的 handler 面：值域（合法／非法位址、保留字）、subject_id 對位址樞紐
// 被忽略、候選端點的另一種形狀，以及候選讀取的留痕。
//
// 為何連候選讀取都要斷言留痕：`/audit/subjects?type=ip&q=…` 是一支
// 「誰在打聽哪些位址」的端點——查詢條件本身就是調查意圖，與時間軸讀取同級。
// 分類與摘要由中介層承擔（非 handler），故此處掛真中介層而非 mock。

const (
	ipHandlerAddr   = "203.0.113.77"
	ipHandlerAddrV6 = "2001:db8::1"
)

// setupIPTimelineDB 位址樞紐 handler 測試用的 :memory: 庫。
// MaxOpenConns(1)：sqlite :memory: 每條連線是各自獨立的空 DB，
// 收斂到 1 才能讓中介層的寫入與本測試的讀回落在同一個 DB 上
func setupIPTimelineDB(t *testing.T) *gorm.DB {
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
	if err := db.AutoMigrate(&model.AuditLog{}, &model.Session{}, &model.User{},
		&model.Asset{}, &model.ClipboardEvent{}, &model.UserSourceIP{},
		&model.AuditRetentionWatermark{}, &model.AuditCheckpoint{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	// 指令與告警兩表在本包無 model 匯入需求，以 DDL 直建（欄位只取查詢會碰到的）
	for _, ddl := range []string{
		`CREATE TABLE session_commands (id integer primary key autoincrement,
			session_id integer, user_id integer, asset_id integer,
			command text, seq integer, executed_at datetime)`,
		`CREATE TABLE command_alerts (id integer primary key autoincrement,
			rule_id integer, rule_name text, session_id integer, user_id integer,
			asset_id integer, command text, severity text, disposition text,
			triggered_at datetime, kind text, reason_code text)`,
	} {
		if err := db.Exec(ddl).Error; err != nil {
			t.Fatalf("建表: %v", err)
		}
	}
	old := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = old })
	return db
}

// ipTimelineRouter 真 handler ＋ 真 AuditLogMiddleware（同步審計，
// 避免 worker 批次帶入時序不確定）。不掛 AuthMiddleware：本測試驗的是
// 值域與留痕，權限由 RegisterRoutes 的群組承擔、另有路由守衛盯著
func ipTimelineRouter(t *testing.T, db *gorm.DB) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	svc := audit.NewAuditLogService(&config.FeatureFlags{
		AuditLogEnabled: true, AsyncAuditEnabled: false, AuditFallbackToFile: false})
	r := gin.New()
	r.Use(middleware.AuditLogMiddleware(svc))
	r.Use(func(c *gin.Context) {
		c.Set("userID", uint(9))
		c.Set("username", "auditor")
		c.Next()
	})
	h := NewAuditTimelineHandler(audit.NewTimelineService(db))
	r.GET("/api/v1/audit/timeline", h.Timeline)
	r.GET("/api/v1/audit/subjects", h.Subjects)
	return r
}

func ipTimelineGet(t *testing.T, r *gin.Engine, url string) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, url, nil))
	return w
}

// timelineWindow 固定時間窗（RFC3339，端點不接受只有日期的參數）
const timelineWindow = "from=2026-08-01T00%3A00%3A00Z&to=2026-09-01T00%3A00%3A00Z"

func TestTimelineIPPivotHandlerValidatesAddress(t *testing.T) {
	db := setupIPTimelineDB(t)
	r := ipTimelineRouter(t, db)

	cases := []struct {
		name string
		url  string
		want int
	}{
		{"合法 IPv4", "subject=ip&subject_ip=" + ipHandlerAddr, http.StatusOK},
		{"合法 IPv6 縮寫", "subject=ip&subject_ip=2001%3A0db8%3A%3A1", http.StatusOK},
		{"非法位址", "subject=ip&subject_ip=not-an-ip", http.StatusBadRequest},
		{"位址樞紐缺 subject_ip", "subject=ip", http.StatusBadRequest},
		{"位址樞紐用保留字", "subject=ip&subject_ip=unknown", http.StatusBadRequest},
		{"位址樞紐再帶篩選", "subject=ip&subject_ip=" + ipHandlerAddr + "&client_ip=" + ipHandlerAddrV6, http.StatusBadRequest},
		{"人樞紐位址篩選合法", "subject=user&subject_id=9&client_ip=" + ipHandlerAddr, http.StatusOK},
		{"人樞紐位址篩選保留字", "subject=user&subject_id=9&client_ip=unknown", http.StatusOK},
		{"人樞紐位址篩選打錯字", "subject=user&subject_id=9&client_ip=zz.zz", http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := ipTimelineGet(t, r, "/api/v1/audit/timeline?"+tc.url+"&"+timelineWindow)
			if w.Code != tc.want {
				t.Fatalf("狀態碼 = %d, want %d（body=%s）", w.Code, tc.want, w.Body.String())
			}
			if tc.want != http.StatusBadRequest {
				return
			}
			// 對外一律機器碼（散文由前端依碼三語呈現）
			var body struct {
				Code string `json:"code"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
				t.Fatalf("回應非預期 JSON: %q", w.Body.String())
			}
			if body.Code == "" {
				t.Errorf("400 回應應帶機器碼，實得 %s", w.Body.String())
			}
		})
	}
}

// TestTimelineIPPivotIgnoresSubjectID 位址樞紐的主體鍵是 subject_ip；
// subject_id 混填**不構成錯誤**（uint 語義只屬於 user／asset 樞紐），
// 但也不得改變結果——否則同一個 URL 在兩種樞紐下語義漂移
func TestTimelineIPPivotIgnoresSubjectID(t *testing.T) {
	db := setupIPTimelineDB(t)
	ts := time.Date(2026, 8, 10, 8, 0, 0, 0, time.UTC)
	if err := db.Create(&model.Session{SessionID: "s-ip-1", Status: "closed", Protocol: "ssh",
		UserID: 9, ClientIP: ipHandlerAddr, StartTime: ts}).Error; err != nil {
		t.Fatalf("seed session: %v", err)
	}
	r := ipTimelineRouter(t, db)

	base := "/api/v1/audit/timeline?subject=ip&subject_ip=" + ipHandlerAddr + "&" + timelineWindow
	plain := ipTimelineGet(t, r, base)
	withID := ipTimelineGet(t, r, base+"&subject_id=4242")
	if plain.Code != http.StatusOK || withID.Code != http.StatusOK {
		t.Fatalf("位址樞紐帶 subject_id 應照常成立：%d / %d", plain.Code, withID.Code)
	}
	if plain.Body.String() != withID.Body.String() {
		t.Errorf("subject_id 對位址樞紐應被忽略，兩次回應卻不同\n無 id: %s\n有 id: %s",
			plain.Body.String(), withID.Body.String())
	}
}

// TestTimelineSubjectsIPShape 候選端點的位址形狀：只有 {ip, last_seen_at}，
// 不混進 TimelineSubjectRef 的整數 id 與啟停欄位
func TestTimelineSubjectsIPShape(t *testing.T) {
	db := setupIPTimelineDB(t)
	t0 := time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC)
	for _, ip := range []string{ipHandlerAddr, "198.51.100.9"} {
		if err := db.Create(&model.UserSourceIP{UserID: 9, ClientIP: ip,
			FirstSeenAt: t0, LastSeenAt: t0}).Error; err != nil {
			t.Fatalf("seed baseline: %v", err)
		}
	}
	r := ipTimelineRouter(t, db)

	w := ipTimelineGet(t, r, "/api/v1/audit/subjects?type=ip&q=203.0")
	if w.Code != http.StatusOK {
		t.Fatalf("狀態碼 = %d（body=%s）", w.Code, w.Body.String())
	}
	var body struct {
		Data  []map[string]any `json:"data"`
		Total int              `json:"total"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("回應非預期 JSON: %q", w.Body.String())
	}
	if body.Total != 1 || len(body.Data) != 1 {
		t.Fatalf("前綴 203.0 應恰 1 筆候選，實得 %+v", body)
	}
	if len(body.Data[0]) != 2 {
		t.Errorf("候選條目欄位集合應恰 {ip, last_seen_at}，實得 %v", body.Data[0])
	}
	if body.Data[0]["ip"] != ipHandlerAddr {
		t.Errorf("候選位址 = %v, want %s", body.Data[0]["ip"], ipHandlerAddr)
	}

	// 既有兩型不受影響（未知 type 仍回 400）
	if w := ipTimelineGet(t, r, "/api/v1/audit/subjects?type=user"); w.Code != http.StatusOK {
		t.Errorf("type=user 應零變動，實得 %d", w.Code)
	}
	if w := ipTimelineGet(t, r, "/api/v1/audit/subjects?type=nope"); w.Code != http.StatusBadRequest {
		t.Errorf("未知 type 應 400，實得 %d", w.Code)
	}
}

// TestTimelineSubjectsIPReadIsAudited 候選讀取留痕：資源為稽核時間軸，
// 且查詢摘要答得出「以什麼條件打聽」——type 與 q 都要在 details 裡
func TestTimelineSubjectsIPReadIsAudited(t *testing.T) {
	db := setupIPTimelineDB(t)
	r := ipTimelineRouter(t, db)

	if w := ipTimelineGet(t, r, "/api/v1/audit/subjects?type=ip&q=203.0"); w.Code != http.StatusOK {
		t.Fatalf("狀態碼 = %d（body=%s）", w.Code, w.Body.String())
	}

	var rows []model.AuditLog
	if err := db.Order("id DESC").Find(&rows).Error; err != nil {
		t.Fatalf("讀回審計列: %v", err)
	}
	if len(rows) == 0 {
		t.Fatal("候選讀取未留痕：audit_logs 零列")
	}
	row := rows[0]
	if row.Resource != model.ResourceAuditTimeline {
		t.Errorf("留痕資源 = %q, want %q", row.Resource, model.ResourceAuditTimeline)
	}
	var details map[string]string
	if err := json.Unmarshal([]byte(row.Details), &details); err != nil {
		t.Fatalf("details 非預期 JSON: %q (%v)", row.Details, err)
	}
	query := details["query"]
	for _, want := range []string{"type=ip", "q=203.0"} {
		if !containsSub(query, want) {
			t.Errorf("查詢摘要應含 %q，實得 %q", want, query)
		}
	}
}

func containsSub(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/custodexa/backend/config"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/policy"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// 多日簽核的批次關聯碼：前端逐日送出時同一批帶同一個值。這些測試走真審計中介層、
// 真權限中介層、真服務（同步寫入的真審計服務），只以替身取代 JWT 驗證。
// 夾具時鐘 2026-10-11 09:00（Asia/Taipei），自 10-01 起啟用：10-10 是準時的昨日、
// 10-05 已逾期、10-09 已由 auditor-a 簽核。

const dailyBatchID = "3f2c9a1e-7b4d-4e8a-9c1f-0a2b3c4d5e6f"

type batchSignEnv struct {
	r  *gin.Engine
	db *gorm.DB
}

func setupBatchSignEnv(t *testing.T) *batchSignEnv {
	t.Helper()
	_, db, now := setupDailyReviewRouter(t)
	old := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = old })
	signed := model.DailyReviewLog{ReviewDate: "2026-10-09", ReviewerID: 7, ReviewerName: "auditor-a", SnapshotJSON: "{}",
		SignedAt: now.Add(-time.Hour), Timezone: "Asia/Taipei", WindowStart: now, WindowEnd: now, DueAt: now,
		Coverage: model.DailyReviewCoverageFullDay, SourceStatus: model.DailyReviewSourceComplete, EnabledBasis: model.DailyReviewBasisRecorded}
	if err := db.Create(&signed).Error; err != nil {
		t.Fatal(err)
	}
	auditSvc := audit.NewAuditLogService(&config.FeatureFlags{AuditLogEnabled: true, AsyncAuditEnabled: false})
	svc := audit.NewDailyReviewService(db, policy.NewSecurityPolicyService(db), auditSvc)
	svc.SetClock(func() time.Time { return now })
	h := NewDailyReviewHandler(svc, nil)

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(middleware.AuditLogMiddleware(auditSvc))
	v1 := r.Group("/api/v1")
	v1.Use(func(c *gin.Context) {
		c.Set("userID", uint(9))
		c.Set("username", "tester")
		middleware.SetPrincipal(c, legacyPrincipal(c.GetHeader("X-Test-Role")))
		c.Next()
	})
	h.registerOn(v1.Group("/daily-reviews"))
	return &batchSignEnv{r: r, db: db}
}

// signRaw 以原始 JSON 本文送出簽核（非字串的關聯碼等型別錯誤只能這樣構造）
func (e *batchSignEnv) signRaw(role, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/daily-reviews", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Test-Role", role)
	w := httptest.NewRecorder()
	e.r.ServeHTTP(w, req)
	return w
}

func (e *batchSignEnv) sign(t *testing.T, role string, payload map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	b, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	return e.signRaw(role, string(b))
}

func (e *batchSignEnv) signedCount(date string) int64 {
	var n int64
	e.db.Model(&model.DailyReviewLog{}).Where("review_date = ?", date).Count(&n)
	return n
}

// signAuditDetails 服務寫的簽核稽核列（action=create、帶 resource_id）的 details
func (e *batchSignEnv) signAuditDetails(t *testing.T) []map[string]any {
	t.Helper()
	var rows []model.AuditLog
	if err := e.db.Where("resource = ? AND action = ? AND resource_id IS NOT NULL", model.ResourceDailyReview, model.ActionCreate).
		Order("id").Find(&rows).Error; err != nil {
		t.Fatal(err)
	}
	var out []map[string]any
	for _, row := range rows {
		var d map[string]any
		if err := json.Unmarshal([]byte(row.Details), &d); err != nil {
			continue // 中介層的請求列不是這個形狀
		}
		if _, ok := d["review_date"]; ok {
			out = append(out, d)
		}
	}
	return out
}

// auditContains 任一稽核列（含中介層的請求列）的任何文字欄位是否含 needle
func (e *batchSignEnv) auditContains(needle string) bool {
	var rows []model.AuditLog
	e.db.Find(&rows)
	for _, row := range rows {
		b, _ := json.Marshal(row)
		if strings.Contains(string(b), needle) {
			return true
		}
	}
	return false
}

// TestDailyReviewSignBatchIDRecordedInAudit 擋：帶批次關聯碼簽核後稽核紀錄沒有該值，
// 稽核面答不出哪幾天是同一批簽的（情境「一次補簽多天」的審計面）
func TestDailyReviewSignBatchIDRecordedInAudit(t *testing.T) {
	e := setupBatchSignEnv(t)
	for _, date := range []string{"2026-10-05", "2026-10-06", "2026-10-07"} {
		w := e.sign(t, "auditor", map[string]any{"review_date": date, "delay_reason": "連假後補簽", "batch_id": dailyBatchID})
		if w.Code != http.StatusOK {
			t.Fatalf("%s = %d (%s), want 200", date, w.Code, w.Body.String())
		}
	}
	details := e.signAuditDetails(t)
	if len(details) != 3 {
		t.Fatalf("簽核稽核列 %d 筆, want 3", len(details))
	}
	for _, d := range details {
		if d["batch_id"] != dailyBatchID {
			t.Errorf("%v 的稽核紀錄 batch_id = %v, want %s", d["review_date"], d["batch_id"], dailyBatchID)
		}
		if d["late"] != true {
			t.Errorf("%v 應標示補簽: %v", d["review_date"], d)
		}
	}
	// 簽核紀錄本身不另外標示：每天各一筆、補簽與延遲原因各自留存
	var logs []model.DailyReviewLog
	e.db.Where("review_date IN ?", []string{"2026-10-05", "2026-10-06", "2026-10-07"}).Find(&logs)
	if len(logs) != 3 {
		t.Fatalf("簽核紀錄 %d 筆, want 3", len(logs))
	}
	for _, l := range logs {
		if !l.Late || l.DelayReason == nil || *l.DelayReason != "連假後補簽" {
			t.Errorf("%s late=%v reason=%v", l.ReviewDate, l.Late, l.DelayReason)
		}
	}
}

// TestDailyReviewSignMixedOnTimeAndLateInBatch 擋：同一批含準時的昨日時，昨日被存了延遲原因
// 或被標成補簽（情境「準時與補簽混選」）
func TestDailyReviewSignMixedOnTimeAndLateInBatch(t *testing.T) {
	e := setupBatchSignEnv(t)
	// 前端只對補簽的日子帶延遲原因；即使昨日也帶了，伺服器也不保存
	for _, p := range []map[string]any{
		{"review_date": "2026-10-05", "delay_reason": "補簽", "batch_id": dailyBatchID},
		{"review_date": "2026-10-06", "delay_reason": "補簽", "batch_id": dailyBatchID},
		{"review_date": "2026-10-10", "delay_reason": "補簽", "batch_id": dailyBatchID},
	} {
		if w := e.sign(t, "auditor", p); w.Code != http.StatusOK {
			t.Fatalf("%v = %d (%s)", p["review_date"], w.Code, w.Body.String())
		}
	}
	var y model.DailyReviewLog
	e.db.Where("review_date = ?", "2026-10-10").First(&y)
	if y.Late || y.DelayReason != nil {
		t.Errorf("昨日 late=%v reason=%v, want 準時且不存延遲原因", y.Late, y.DelayReason)
	}
	var l model.DailyReviewLog
	e.db.Where("review_date = ?", "2026-10-05").First(&l)
	if !l.Late || l.DelayReason == nil {
		t.Errorf("10-05 late=%v reason=%v, want 補簽且保存延遲原因", l.Late, l.DelayReason)
	}
}

// TestDailyReviewSignWithoutBatchIDKeepsAuditShape 擋：單日簽核（不帶關聯碼）的稽核紀錄
// 多出 batch_id 鍵（情境「單日簽核不受影響」）
func TestDailyReviewSignWithoutBatchIDKeepsAuditShape(t *testing.T) {
	e := setupBatchSignEnv(t)
	if w := e.sign(t, "auditor", map[string]any{"review_date": "2026-10-10"}); w.Code != http.StatusOK {
		t.Fatalf("= %d (%s)", w.Code, w.Body.String())
	}
	details := e.signAuditDetails(t)
	if len(details) != 1 {
		t.Fatalf("稽核列 %d 筆, want 1", len(details))
	}
	if _, ok := details[0]["batch_id"]; ok {
		t.Errorf("不帶關聯碼時稽核紀錄不應有 batch_id: %v", details[0])
	}
	// JSON null 視同沒帶
	if w := e.signRaw("auditor", `{"review_date":"2026-10-08","delay_reason":"x","batch_id":null}`); w.Code != http.StatusOK {
		t.Fatalf("batch_id=null = %d (%s)", w.Code, w.Body.String())
	}
	if d := e.signAuditDetails(t); len(d) != 2 {
		t.Fatalf("稽核列 %d 筆, want 2", len(d))
	} else if _, ok := d[1]["batch_id"]; ok {
		t.Errorf("batch_id=null 時稽核紀錄不應有 batch_id: %v", d[1])
	}
}

// TestDailyReviewSignRejectsMalformedBatchID 擋：格式不合的關聯碼被收下、產生簽核紀錄，
// 或原值進了任何稽核列
func TestDailyReviewSignRejectsMalformedBatchID(t *testing.T) {
	cases := []struct {
		name   string
		raw    string // 本文中 batch_id 的 JSON 值
		needle string // 不得出現在稽核列的原值（空字串不檢查）
	}{
		{"空字串", `""`, ""},
		{"數字", `12345`, "12345"},
		{"物件", `{"x":"y"}`, `"x"`},
		{"超長", `"` + dailyBatchID + strings.Repeat("a", 300) + `"`, strings.Repeat("a", 300)},
		{"含控制字元", `"3f2c9a1e-7b4d-4e8a-9c1f-0a2b3c4d5e6\u0007"`, "3f2c9a1e-7b4d-4e8a-9c1f-0a2b3c4d5e6"},
		{"非 UUID", `"batch-of-2026-10"`, "batch-of-2026-10"},
		{"大括號變體", `"{3f2c9a1e-7b4d-4e8a-9c1f-0a2b3c4d5e6f}"`, "{3f2c9a1e"},
		{"urn 變體", `"urn:uuid:3f2c9a1e-7b4d-4e8a-9c1f-0a2b3c4d5e6f"`, "urn:uuid"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := setupBatchSignEnv(t)
			w := e.signRaw("auditor", `{"review_date":"2026-10-10","batch_id":`+tc.raw+`}`)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("= %d (%s), want 400", w.Code, w.Body.String())
			}
			if code, _, _ := decodeEnvelope(t, w); code != "VALIDATION_BAD_REQUEST" {
				t.Errorf("code = %s", code)
			}
			if n := e.signedCount("2026-10-10"); n != 0 {
				t.Errorf("被拒的請求留下 %d 筆簽核紀錄", n)
			}
			if d := e.signAuditDetails(t); len(d) != 0 {
				t.Errorf("被拒的請求留下簽核稽核列: %v", d)
			}
			if tc.needle != "" && e.auditContains(tc.needle) {
				t.Errorf("稽核紀錄含原值 %q", tc.needle)
			}
		})
	}
}

// TestDailyReviewSignBatchIDDeniedWithoutPermission 擋：帶關聯碼就繞過簽核權限
func TestDailyReviewSignBatchIDDeniedWithoutPermission(t *testing.T) {
	e := setupBatchSignEnv(t)
	for _, body := range []string{
		`{"review_date":"2026-10-10"}`,
		`{"review_date":"2026-10-10","batch_id":"` + dailyBatchID + `"}`,
		`{"review_date":"2026-10-10","batch_id":"not-a-uuid"}`,
	} {
		w := e.signRaw("user", body)
		if w.Code != http.StatusForbidden {
			t.Errorf("user %s = %d, want 403", body, w.Code)
		}
	}
	if n := e.signedCount("2026-10-10"); n != 0 {
		t.Errorf("無權限者留下 %d 筆簽核紀錄", n)
	}
	if e.auditContains("not-a-uuid") {
		t.Error("無權限請求的原值進了稽核紀錄")
	}
}

// TestDailyReviewSignRulesUnchangedWithBatchID 擋：帶關聯碼時既有簽核規則被放寬（
// 情境「有未審閱告警的日子不能一起簽」的伺服器端、「部分完成時逐日回報」的 409）
func TestDailyReviewSignRulesUnchangedWithBatchID(t *testing.T) {
	t.Run("未審閱告警拒絕並回報筆數", func(t *testing.T) {
		e := setupBatchSignEnv(t)
		taipei, _ := time.LoadLocation("Asia/Taipei")
		for _, h := range []int{8, 9} {
			if err := e.db.Exec("INSERT INTO command_alerts (triggered_at, disposition) VALUES (?, 'pending')",
				time.Date(2026, 10, 7, h, 0, 0, 0, taipei).UTC()).Error; err != nil {
				t.Fatal(err)
			}
		}
		w := e.sign(t, "auditor", map[string]any{"review_date": "2026-10-07", "delay_reason": "x", "batch_id": dailyBatchID})
		if w.Code != http.StatusBadRequest {
			t.Fatalf("= %d (%s), want 400", w.Code, w.Body.String())
		}
		code, params, _ := decodeEnvelope(t, w)
		if code != "RULE_DAILY_REVIEW_ALERTS_PENDING" || params["count"] != float64(2) {
			t.Errorf("code=%s params=%v, want ALERTS_PENDING count=2", code, params)
		}
		if e.signedCount("2026-10-07") != 0 {
			t.Error("被拒的簽核留下紀錄")
		}
	})
	t.Run("尚未結束與寬限內拒絕", func(t *testing.T) {
		e := setupBatchSignEnv(t)
		w := e.sign(t, "auditor", map[string]any{"review_date": "2026-10-11", "batch_id": dailyBatchID})
		if code, _, _ := decodeEnvelope(t, w); w.Code != http.StatusBadRequest || code != "RULE_DAILY_REVIEW_DAY_NOT_ENDED" {
			t.Errorf("今天 = %d %s", w.Code, code)
		}
		if e.signedCount("2026-10-11") != 0 {
			t.Error("今天留下紀錄")
		}
	})
	t.Run("已簽回 409 並帶對方紀錄", func(t *testing.T) {
		e := setupBatchSignEnv(t)
		w := e.sign(t, "auditor", map[string]any{"review_date": "2026-10-09", "delay_reason": "x", "batch_id": dailyBatchID})
		if w.Code != http.StatusConflict {
			t.Fatalf("= %d (%s), want 409", w.Code, w.Body.String())
		}
		code, params, _ := decodeEnvelope(t, w)
		if code != "CONFLICT_DAILY_REVIEW_SIGNED" || params["signer"] != "auditor-a" || params["signed_at"] == "" {
			t.Errorf("code=%s params=%v", code, params)
		}
		var row model.DailyReviewLog
		e.db.Where("review_date = ?", "2026-10-09").First(&row)
		if row.ReviewerName != "auditor-a" || e.signedCount("2026-10-09") != 1 {
			t.Errorf("既有紀錄被改動: %+v", row)
		}
	})
	t.Run("遲簽未填原因拒絕", func(t *testing.T) {
		e := setupBatchSignEnv(t)
		w := e.sign(t, "auditor", map[string]any{"review_date": "2026-10-05", "delay_reason": "  ", "batch_id": dailyBatchID})
		if code, _, _ := decodeEnvelope(t, w); w.Code != http.StatusBadRequest || code != "VALIDATION_DAILY_REVIEW_DELAY_REASON_REQUIRED" {
			t.Errorf("= %d %s", w.Code, code)
		}
		if e.signedCount("2026-10-05") != 0 {
			t.Error("被拒的簽核留下紀錄")
		}
	})
}

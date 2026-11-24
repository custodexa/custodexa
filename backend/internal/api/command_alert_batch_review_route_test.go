package api

import (
	"context"
	"encoding/json"
	"fmt"
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
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/mock"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

const bulkRouteBatchID = "3c9a1f2e-5b6d-4e7f-8a9b-0c1d2e3f4a5b"

// bulkReviewerID 路由層測試的審閱者（由替身中介層設定）
const bulkReviewerID = uint(8)

// alertBatchRouter 真稽核中介層＋真權限閘＋真 handler＋sqlite 的告警審閱路由
// （僅以替身取代 JWT 驗證：X-Test-Role 指定角色，`audit-viewer` 為只有 audit:view 的自訂角色）
func alertBatchRouter(t *testing.T) (*gin.Engine, *gorm.DB) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = sqlDB.Close() })
	if err := db.AutoMigrate(&model.AuditLog{}, &model.User{}, &model.Asset{}, &model.Session{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if err := db.Exec(`CREATE TABLE command_alerts (id INTEGER PRIMARY KEY AUTOINCREMENT,
		rule_id INTEGER, rule_name TEXT NOT NULL DEFAULT 'r', session_id INTEGER NOT NULL DEFAULT 0,
		user_id INTEGER NOT NULL DEFAULT 3, asset_id INTEGER, command TEXT NOT NULL DEFAULT '',
		severity TEXT NOT NULL DEFAULT 'high', triggered_at DATETIME NOT NULL, reviewed_by INTEGER, reviewed_at DATETIME,
		disposition TEXT NOT NULL DEFAULT 'pending', note TEXT NOT NULL DEFAULT '', blocked BOOLEAN NOT NULL DEFAULT 0,
		kind TEXT NOT NULL DEFAULT 'rule', reason_code TEXT NOT NULL DEFAULT '')`).Error; err != nil {
		t.Fatalf("建表: %v", err)
	}
	old := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = old })

	auditSvc := audit.NewAuditLogService(&config.FeatureFlags{AuditLogEnabled: true})
	svc := audit.NewCommandAlertService(db)
	svc.SetAuditTxSink(audit.NewTxSink())
	h := NewCommandAlertHandler(svc)
	h.SetAuditService(auditSvc)

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(middleware.AuditLogMiddleware(auditSvc))
	v1 := r.Group("/api/v1")
	v1.Use(func(c *gin.Context) {
		c.Set("userID", bulkReviewerID)
		c.Set("username", "auditor-8")
		role := c.GetHeader("X-Test-Role")
		if role == "audit-viewer" {
			middleware.SetPrincipal(c, authz.NewPrincipal(bulkReviewerID, authz.TokenFacts{}, []authz.Assignment{{
				RoleName: "audit-viewer", Via: authz.ViaDirect, Scope: model.ScopeKindGlobal,
				Permissions: []authz.Permission{authz.PermAuditView}, Custom: true,
			}}))
		} else {
			middleware.SetPrincipal(c, legacyPrincipal(role))
		}
		c.Next()
	})
	h.registerOn(v1.Group("/command-alerts"))
	return r, db
}

func seedRouteAlerts(t *testing.T, db *gorm.DB, owners ...uint) []uint {
	t.Helper()
	ids := make([]uint, 0, len(owners))
	for i, owner := range owners {
		if err := db.Exec(`INSERT INTO command_alerts (user_id, triggered_at) VALUES (?, ?)`,
			owner, time.Now().Add(time.Duration(i)*time.Second).UTC()).Error; err != nil {
			t.Fatal(err)
		}
		var id uint
		db.Raw("SELECT max(id) FROM command_alerts").Scan(&id)
		ids = append(ids, id)
	}
	return ids
}

func postBatchReview(r http.Handler, role, body string, ctx context.Context) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/command-alerts/batch-review", strings.NewReader(body))
	if ctx != nil {
		req = req.WithContext(ctx)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Test-Role", role)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func batchBody(ids []uint, ack int, note string) string {
	parts := make([]string, len(ids))
	for i, id := range ids {
		parts[i] = fmt.Sprint(id)
	}
	return fmt.Sprintf(`{"alert_ids":[%s],"disposition":"benign","note":%q,"batch_id":%q,"self_triggered_ack":%d}`,
		strings.Join(parts, ","), note, bulkRouteBatchID, ack)
}

func reviewedCount(db *gorm.DB) int64 {
	var n int64
	db.Raw("SELECT count(*) FROM command_alerts WHERE reviewed_at IS NOT NULL").Scan(&n)
	return n
}

func dispositionAuditCount(db *gorm.DB) int64 {
	var n int64
	db.Model(&model.AuditLog{}).Where("resource = ? AND error_msg LIKE ?", model.ResourceCommandAlert, "alert_disposition_%").Count(&n)
	return n
}

// TestAlertBatchReviewRouteRequiresAlertManage 批次審閱端點的權限與單筆審閱相同（alert:manage）。
//
// 擋的威脅：新端點掛到較寬的權限（例如只要能看告警就能結案），或漏掛權限閘。
func TestAlertBatchReviewRouteRequiresAlertManage(t *testing.T) {
	r, db := alertBatchRouter(t)
	ids := seedRouteAlerts(t, db, 1, 2)
	for _, role := range []string{"audit-viewer", model.RoleUser} {
		w := postBatchReview(r, role, batchBody(ids, 0, "例行"), nil)
		if w.Code != http.StatusForbidden {
			t.Fatalf("%s 呼叫批次審閱 = %d (%s), want 403", role, w.Code, w.Body.String())
		}
	}
	if reviewedCount(db) != 0 || dispositionAuditCount(db) != 0 {
		t.Fatal("被拒的請求不得寫入處置或處置稽核")
	}
	if w := postBatchReview(r, model.RoleAuditor, batchBody(ids, 0, "例行"), nil); w.Code != http.StatusOK {
		t.Fatalf("auditor 呼叫批次審閱 = %d (%s), want 200", w.Code, w.Body.String())
	}
}

// TestAlertBatchReviewRouteRejectsWholeBatch 整批拒收的每一種情況回對的狀態碼、錯誤碼與 meta，且一筆都不寫。
//
// 擋的威脅：直接呼叫端點時不帶確認、確認數錯、超過上限、理由空白仍有部分寫入；
// 或錯誤碼與 meta 鍵和介面依據的契約不同，使介面無法以伺服端計得的筆數重新列出確認。
func TestAlertBatchReviewRouteRejectsWholeBatch(t *testing.T) {
	r, db := alertBatchRouter(t)
	ids := seedRouteAlerts(t, db, 1, bulkReviewerID, 2, bulkReviewerID)
	over := make([]uint, audit.AlertBatchReviewLimit+1)
	for i := range over {
		over[i] = uint(i + 1)
	}
	cases := []struct {
		name   string
		body   string
		status int
		code   string
		meta   map[string]float64
	}{
		{"不是 JSON", `{"alert_ids":`, 400, "VALIDATION_ALERT_REVIEW_REQUEST", nil},
		{"缺 alert_ids", `{"disposition":"benign","note":"x","batch_id":"` + bulkRouteBatchID + `"}`, 400, "VALIDATION_ALERT_REVIEW_REQUEST", nil},
		{"alert_ids 為空", `{"alert_ids":[],"disposition":"benign","note":"x","batch_id":"` + bulkRouteBatchID + `"}`, 400, "VALIDATION_ALERT_REVIEW_REQUEST", nil},
		{"alert_ids 含 0", batchBody([]uint{ids[0], 0}, 0, "x"), 400, "VALIDATION_ALERT_REVIEW_REQUEST", nil},
		{"alert_ids 含負數", `{"alert_ids":[-1],"disposition":"benign","note":"x","batch_id":"` + bulkRouteBatchID + `"}`, 400, "VALIDATION_ALERT_REVIEW_REQUEST", nil},
		{"缺 batch_id", `{"alert_ids":[1],"disposition":"benign","note":"x"}`, 400, "VALIDATION_ALERT_REVIEW_REQUEST", nil},
		{"batch_id 不是 UUID", `{"alert_ids":[1],"disposition":"benign","note":"x","batch_id":"b-1"}`, 400, "VALIDATION_ALERT_REVIEW_REQUEST", nil},
		{"缺 disposition", `{"alert_ids":[1],"note":"x","batch_id":"` + bulkRouteBatchID + `"}`, 400, "VALIDATION_ALERT_REVIEW_REQUEST", nil},
		{"處置分類不合法", strings.Replace(batchBody(ids, 2, "x"), `"benign"`, `"pending"`, 1), 400, "VALIDATION_ALERT_DISPOSITION", nil},
		{"理由只有空白", batchBody(ids, 2, "   "), 400, "VALIDATION_ALERT_BATCH_NOTE", nil},
		{"理由超過 500 字", batchBody(ids, 2, strings.Repeat("字", 501)), 400, "VALIDATION_ALERT_BATCH_NOTE", nil},
		{"超過上限", batchBody(over, 0, "x"), 400, "VALIDATION_ALERT_BATCH_TOO_LARGE", map[string]float64{"limit": 500}},
		{"沒帶確認", strings.Replace(batchBody(ids, 0, "x"), `,"self_triggered_ack":0`, "", 1), 409, "CONFLICT_ALERT_BATCH_SELF_ACK", map[string]float64{"self_triggered": 2}},
		{"確認數錯", batchBody(ids, 1, "x"), 409, "CONFLICT_ALERT_BATCH_SELF_ACK", map[string]float64{"self_triggered": 2}},
	}
	for _, tc := range cases {
		w := postBatchReview(r, model.RoleAuditor, tc.body, nil)
		var body map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &body)
		if w.Code != tc.status || body["code"] != tc.code {
			t.Fatalf("%s：= %d %v, want %d %s", tc.name, w.Code, body, tc.status, tc.code)
		}
		for k, v := range tc.meta {
			if body[k] != v {
				t.Fatalf("%s：meta %s = %v, want %v（%v）", tc.name, k, body[k], v, body)
			}
		}
		if reviewedCount(db) != 0 || dispositionAuditCount(db) != 0 {
			t.Fatalf("%s：整批拒收後不得有任何寫入", tc.name)
		}
	}
}

// paddedBatchBody 以 JSON 空白把本文補到恰好 size 位元組（內容不變）
func paddedBatchBody(t *testing.T, ids []uint, size int) string {
	t.Helper()
	b := batchBody(ids, 0, "例行")
	if len(b) > size {
		t.Fatalf("本文 %d 已超過 %d", len(b), size)
	}
	return b[:len(b)-1] + strings.Repeat(" ", size-len(b)) + "}"
}

// TestAlertBatchReviewRouteBodyLimit 請求本文以 64 KiB 為界：恰為上限照常處理且請求列仍帶理由，超過即整批拒收。
func TestAlertBatchReviewRouteBodyLimit(t *testing.T) {
	r, db := alertBatchRouter(t)
	ids := seedRouteAlerts(t, db, 1, 2)
	over := paddedBatchBody(t, ids, 64<<10+1)
	if w := postBatchReview(r, model.RoleAuditor, over, nil); w.Code != http.StatusBadRequest || batchRespCode(t, w) != "VALIDATION_ALERT_REVIEW_REQUEST" {
		t.Fatalf("超過 64 KiB = %d %s, want 400 VALIDATION_ALERT_REVIEW_REQUEST", w.Code, w.Body.String())
	}
	if reviewedCount(db) != 0 {
		t.Fatal("超過本文上限不得寫入")
	}
	exact := paddedBatchBody(t, ids, 64<<10)
	if len(exact) != 65536 {
		t.Fatalf("本文長度 %d", len(exact))
	}
	if w := postBatchReview(r, model.RoleAuditor, exact, nil); w.Code != http.StatusOK {
		t.Fatalf("恰為 64 KiB = %d (%s), want 200", w.Code, w.Body.String())
	}
	var reqRow model.AuditLog
	if err := db.Where("path = ? AND request_body <> ''", "/api/v1/command-alerts/batch-review").Order("id DESC").First(&reqRow).Error; err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(reqRow.RequestBody, "例行") {
		t.Fatalf("恰為上限時請求列應保有理由: %.200s", reqRow.RequestBody)
	}
}

// TestAlertBatchReviewRouteSuccessShape 200 的形狀照契約：items 依去重後順序，summary 計數正確；
// 中介層的請求列帶理由、關聯碼與確認筆數，不存告警編號清單。
func TestAlertBatchReviewRouteSuccessShape(t *testing.T) {
	r, db := alertBatchRouter(t)
	ids := seedRouteAlerts(t, db, 1, bulkReviewerID, 2)
	// 第三筆事前由他人審閱
	db.Exec(`UPDATE command_alerts SET reviewed_by = 5, reviewed_at = ?, disposition = 'escalated', note = '他人' WHERE id = ?`,
		time.Now().UTC(), ids[2])
	body := batchBody([]uint{ids[2], ids[0], 99999, ids[1], ids[0]}, 1, "對應變更單 CHG-1123")
	w := postBatchReview(r, model.RoleAuditor, body, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("= %d (%s)", w.Code, w.Body.String())
	}
	var resp struct {
		BatchID string         `json:"batch_id"`
		Limit   int            `json:"limit"`
		Summary map[string]int `json:"summary"`
		Items   []map[string]any
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.BatchID != bulkRouteBatchID || resp.Limit != 500 {
		t.Fatalf("batch_id／limit 不符: %s", w.Body.String())
	}
	want := map[string]int{"reviewed": 2, "already_reviewed": 1, "not_found": 1, "self_triggered": 1}
	for k, v := range want {
		if resp.Summary[k] != v {
			t.Fatalf("summary.%s = %d, want %d（%v）", k, resp.Summary[k], v, resp.Summary)
		}
	}
	type exp struct {
		id     uint
		result string
		self   bool
		byYou  any
	}
	wantItems := []exp{{ids[2], "already_reviewed", false, false}, {ids[0], "reviewed", false, nil},
		{99999, "not_found", false, nil}, {ids[1], "reviewed", true, nil}}
	if len(resp.Items) != len(wantItems) {
		t.Fatalf("items %d 筆, want %d: %s", len(resp.Items), len(wantItems), w.Body.String())
	}
	for i, e := range wantItems {
		it := resp.Items[i]
		_, hasByYou := it["reviewed_by_you"]
		if it["id"] != float64(e.id) || it["result"] != e.result || it["self_triggered"] != e.self ||
			(e.byYou == nil && hasByYou) || (e.byYou != nil && it["reviewed_by_you"] != e.byYou) {
			t.Fatalf("items[%d] = %v, want %+v", i, it, e)
		}
	}

	// 中介層請求列：放行 note、batch_id、self_triggered_ack，alert_ids 遮罩
	var reqRow model.AuditLog
	if err := db.Where("path = ? AND request_body <> ''", "/api/v1/command-alerts/batch-review").
		Order("id DESC").First(&reqRow).Error; err != nil {
		t.Fatalf("找不到中介層請求列: %v", err)
	}
	// 請求列的動作與單筆審閱同為審閱，不是預設的建立
	if reqRow.Action != model.ActionReview {
		t.Fatalf("請求列動作 = %s, want review", reqRow.Action)
	}
	// 逐筆列與摘要列帶同一個伺服端請求識別，且等於請求列的請求識別
	var txRows []model.AuditLog
	db.Where("path = ? AND request_body = ''", "/api/v1/command-alerts/batch-review").Find(&txRows)
	if reqRow.RequestID == "" || len(txRows) != 3 {
		t.Fatalf("請求識別 %q、交易內稽核列 %d（want 2 筆處置＋1 摘要）", reqRow.RequestID, len(txRows))
	}
	for _, r := range txRows {
		if r.RequestID != reqRow.RequestID {
			t.Fatalf("交易內稽核列的請求識別 %q 與請求列 %q 不同", r.RequestID, reqRow.RequestID)
		}
	}
	var rb map[string]any
	if err := json.Unmarshal([]byte(reqRow.RequestBody), &rb); err != nil {
		t.Fatalf("request_body 不是 JSON: %q", reqRow.RequestBody)
	}
	if rb["note"] != "對應變更單 CHG-1123" || rb["batch_id"] != bulkRouteBatchID || rb["self_triggered_ack"] != float64(1) {
		t.Fatalf("請求列未放行理由、關聯碼與確認筆數: %v", rb)
	}
	if v, ok := rb["alert_ids"]; ok && v != "***MASKED***" {
		t.Fatalf("請求列不得存告警編號清單: %v", v)
	}
	if strings.Contains(reqRow.RequestBody, "99999") {
		t.Fatalf("請求列含告警編號: %s", reqRow.RequestBody)
	}
	if n := dispositionAuditCount(db); n != 2 {
		t.Fatalf("處置稽核列 %d, want 2", n)
	}
}

// TestAlertBatchReviewRouteSurvivesClientCancel 用戶端在請求受理後斷線，交易照常提交。
//
// 擋的威脅：交易綁在請求的 context 上，用戶端關頁時整批回滾或中途中止，
// 使「沒有收到回應」的批次在伺服端的狀態取決於斷線時刻。
func TestAlertBatchReviewRouteSurvivesClientCancel(t *testing.T) {
	r, db := alertBatchRouter(t)
	ids := seedRouteAlerts(t, db, 1, 2, 3, 4, 5, bulkReviewerID, 6, 7, 9, 10)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	w := postBatchReview(r, model.RoleAuditor, batchBody(ids, 1, "例行"), ctx)
	if w.Code != http.StatusOK {
		t.Fatalf("已取消的 context = %d (%s), want 200", w.Code, w.Body.String())
	}
	if n := reviewedCount(db); n != 10 {
		t.Fatalf("用戶端斷線後已處置 %d 筆, want 10", n)
	}
	if n := dispositionAuditCount(db); n != 10 {
		t.Fatalf("用戶端斷線後處置稽核 %d 列, want 10", n)
	}
}

func postSingleReview(r http.Handler, id uint, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/v1/command-alerts/%d/review", id), strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Test-Role", model.RoleAuditor)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func lastDispositionDetails(t *testing.T, db *gorm.DB, alertID uint) map[string]any {
	t.Helper()
	var row model.AuditLog
	if err := db.Where("resource = ? AND resource_id = ? AND error_msg LIKE ?", model.ResourceCommandAlert, alertID,
		"alert_disposition_%").Order("id DESC").First(&row).Error; err != nil {
		t.Fatalf("告警 %d 沒有處置稽核列: %v", alertID, err)
	}
	var d map[string]any
	if err := json.Unmarshal([]byte(row.Details), &d); err != nil {
		t.Fatalf("details 不是 JSON: %q", row.Details)
	}
	return d
}

// TestAlertSingleReviewMarksSelfReview 逐筆審閱也標出審閱者是否即觸發者；理由仍選填。
//
// 擋的威脅：稽核查「自己審自己」時只查得到批次那條路徑，逐筆審閱本人觸發的告警沒有標示；
// 或為了標示而把逐筆審閱改成理由必填（新增阻擋）。
func TestAlertSingleReviewMarksSelfReview(t *testing.T) {
	r, db := alertBatchRouter(t)
	ids := seedRouteAlerts(t, db, bulkReviewerID, 1, 2)

	if w := postSingleReview(r, ids[0], `{"disposition":"benign"}`); w.Code != http.StatusOK {
		t.Fatalf("逐筆審閱本人觸發、不填理由 = %d (%s), want 200", w.Code, w.Body.String())
	}
	if d := lastDispositionDetails(t, db, ids[0]); d["self_review"] != true {
		t.Fatalf("逐筆審閱本人觸發的 self_review = %v, want true", d["self_review"])
	}
	if w := postSingleReview(r, ids[1], `{"disposition":"benign","note":"看過"}`); w.Code != http.StatusOK {
		t.Fatalf("逐筆審閱他人觸發 = %d", w.Code)
	}
	if d := lastDispositionDetails(t, db, ids[1]); d["self_review"] != false {
		t.Fatalf("逐筆審閱他人觸發的 self_review = %v, want false", d["self_review"])
	}
	body := fmt.Sprintf(`{"disposition":"benign","note":"例行","batch_id":%q}`, bulkRouteBatchID)
	if w := postSingleReview(r, ids[2], body); w.Code != http.StatusOK {
		t.Fatalf("帶關聯碼的舊路徑 = %d", w.Code)
	}
	if d := lastDispositionDetails(t, db, ids[2]); d["self_review"] != false {
		t.Fatalf("帶關聯碼的舊路徑 self_review = %v, want false", d["self_review"])
	}
}

// TestAlertSingleReviewLegacyBatchRuleUnchanged 以單筆端點帶關聯碼送出本人觸發的告警仍被拒；
// 同一筆經批次審閱端點確認後可處置，或不帶關聯碼逐筆處置。
//
// 擋的威脅：放寬批次規則時連帶放寬了無法表達確認的舊路徑，使不經確認的批次可以混入本人告警。
func TestAlertSingleReviewLegacyBatchRuleUnchanged(t *testing.T) {
	r, db := alertBatchRouter(t)
	ids := seedRouteAlerts(t, db, bulkReviewerID, bulkReviewerID)
	body := fmt.Sprintf(`{"disposition":"benign","note":"例行","batch_id":%q}`, bulkRouteBatchID)
	w := postSingleReview(r, ids[0], body)
	if w.Code != http.StatusForbidden || batchRespCode(t, w) != "RULE_ALERT_BATCH_SELF_TRIGGERED" {
		t.Fatalf("舊路徑送本人觸發 = %d %s, want 403 RULE_ALERT_BATCH_SELF_TRIGGERED", w.Code, w.Body.String())
	}
	if reviewedCount(db) != 0 {
		t.Fatal("舊路徑被拒後不得寫入")
	}
	if w := postBatchReview(r, model.RoleAuditor, batchBody(ids[:1], 1, "確認後處置"), nil); w.Code != http.StatusOK {
		t.Fatalf("同一筆經批次審閱端點確認後 = %d (%s)", w.Code, w.Body.String())
	}
	if w := postSingleReview(r, ids[1], `{"disposition":"escalated"}`); w.Code != http.StatusOK {
		t.Fatalf("不帶關聯碼逐筆審閱本人觸發 = %d", w.Code)
	}
	if reviewedCount(db) != 2 {
		t.Fatalf("已處置 %d 筆, want 2", reviewedCount(db))
	}
}

// TestAlertSingleReviewSelfReviewUnknownOmitted 讀不到觸發者時不把「無法判定」記成「不是」。
func TestAlertSingleReviewSelfReviewUnknownOmitted(t *testing.T) {
	_, db := alertBatchRouter(t) // 只用它的稽核表與 database.DB
	svc := new(MockCommandAlertService)
	svc.On("IsTriggeredBy", uint(41), bulkReviewerID).Return(false, fmt.Errorf("查詢失敗"))
	svc.On("Review", uint(41), bulkReviewerID, "benign", "").Return(nil)
	h := NewCommandAlertHandler(svc)
	h.SetAuditService(audit.NewAuditLogService(&config.FeatureFlags{AuditLogEnabled: true}))
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/command-alerts/:id/review", func(c *gin.Context) {
		c.Set("userID", bulkReviewerID)
		c.Set("username", "auditor-8")
		c.Next()
	}, h.Review)
	if w := postAlertReview(r, "41", `{"disposition":"benign"}`); w.Code != http.StatusOK {
		t.Fatalf("= %d", w.Code)
	}
	var row model.AuditLog
	if err := db.Where("resource = ? AND resource_id = ?", model.ResourceCommandAlert, 41).First(&row).Error; err != nil {
		t.Fatalf("沒有處置稽核列: %v", err)
	}
	if strings.Contains(row.Details, "self_review") {
		t.Fatalf("讀不到觸發者時不得寫 self_review: %q", row.Details)
	}
	svc.AssertExpectations(t)
}

// TestAlertBatchReviewRouteOutcomeCodes 整批伺服器錯誤：確定回滾才回 INTERNAL_ALERT_REVIEW，
// 無法確定是否已提交時回另一個碼（介面據此標待確認，不說沒有生效）。
func TestAlertBatchReviewRouteOutcomeCodes(t *testing.T) {
	cases := map[string]struct {
		err    error
		status int
		code   string
	}{
		"確定回滾": {fmt.Errorf("審閱告警失敗: x"), 500, "INTERNAL_ALERT_REVIEW"},
		"無法確定": {fmt.Errorf("%w: commit", audit.ErrAlertBatchOutcomeUnknown), 500, "INTERNAL_COMMAND_ALERT_QUERY"},
	}
	for name, tc := range cases {
		svc := new(MockCommandAlertService)
		svc.On("ReviewBatch", mock.Anything).Return(nil, tc.err)
		gin.SetMode(gin.TestMode)
		r := gin.New()
		r.POST("/api/v1/command-alerts/batch-review", NewCommandAlertHandler(svc).BatchReview)
		w := postBatchReview(r, model.RoleAuditor, batchBody([]uint{1}, 0, "x"), nil)
		if w.Code != tc.status || batchRespCode(t, w) != tc.code {
			t.Fatalf("%s：= %d %s, want %d %s", name, w.Code, w.Body.String(), tc.status, tc.code)
		}
	}
}

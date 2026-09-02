package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/custodexa/backend/config"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// 輪替證據報告端點。
//
// 本檔釘四件事：
//  1. 讀取面要稽核檢視權限：auditor 200、僅 user 角色者 403 且回應收斂。
//  2. 排程面限 admin：auditor 建排程 403、admin 201 且審計列存在。
//  3. 資料集回應**不含任何憑證欄位與計劃的密碼策略**——報告是給稽核看的，
//     它要回答「這個帳號多久沒改密」，不是「它的密碼長什麼樣」。
//  4. 手動產出建立 rotation_report 工作單並入審計。

type rotationTestEnv struct {
	router    *gin.Engine
	db        *gorm.DB
	schedules *asset.RotationReportScheduleService
}

func newRotationTestEnv(t *testing.T) *rotationTestEnv {
	t.Helper()
	gin.SetMode(gin.TestMode)
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("sql.DB: %v", err)
	}
	// `:memory:` 每條連線是各自獨立的空庫
	sqlDB.SetMaxOpenConns(1)
	if err := db.AutoMigrate(&model.Asset{}, &model.AssetAccount{}, &model.AssetGroup{},
		&model.AssetNode{}, &model.AuditLog{}, &model.ChangeSecretPlan{},
		&model.ChangeSecretRecord{}, &model.ChangeSecretCandidate{},
		&model.RotationReportSchedule{}, &model.AuditExportJob{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	oldDB := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = oldDB })

	auditSvc := audit.NewAuditLogService(&config.FeatureFlags{
		AuditLogEnabled: true, AsyncAuditEnabled: false, AuditFallbackToFile: false})
	plans := asset.NewChangeSecretPlanService(db)
	builder := asset.NewRotationReportBuilder(db, plans, func() int { return 90 })
	schedules := asset.NewRotationReportScheduleService(db, audit.NewAuditExportJobService(db), builder)
	h := NewRotationReportHandler(builder, schedules, auditSvc)

	r := gin.New()
	r.Use(func(c *gin.Context) { // 身分注入（AuthMiddleware 的等價出口）
		if uid := c.GetHeader("X-Test-User"); uid != "" {
			id, _ := strconv.ParseUint(uid, 10, 32)
			c.Set("userID", uint(id))
			c.Set("username", "user-"+uid)
		}
		if role := c.GetHeader("X-Test-Role"); role != "" {
			c.Set("role", role)
		}
		c.Next()
	})
	grp := r.Group("/api/v1/rotation-report")
	grp.GET("", middleware.RequirePermission(middleware.PermAuditView), h.Dataset)
	grp.GET("/records", middleware.RequirePermission(middleware.PermAuditView), h.Records)
	grp.POST("/jobs", middleware.RequirePermission(middleware.PermAuditView), h.CreateJob)
	sch := grp.Group("/schedules")
	sch.Use(middleware.RequireRole("admin"))
	sch.GET("", h.ListSchedules)
	sch.POST("", h.CreateSchedule)
	sch.PUT("/:id", h.UpdateSchedule)
	sch.DELETE("/:id", h.DeleteSchedule)
	sch.POST("/:id/run", h.RunSchedule)

	return &rotationTestEnv{router: r, db: db, schedules: schedules}
}

func (e *rotationTestEnv) do(t *testing.T, method, path, role string, userID uint, body any) *httptest.ResponseRecorder {
	t.Helper()
	var reader *bytes.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		reader = bytes.NewReader(raw)
	} else {
		reader = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, reader)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Test-Role", role)
	req.Header.Set("X-Test-User", strconv.FormatUint(uint64(userID), 10))
	w := httptest.NewRecorder()
	e.router.ServeHTTP(w, req)
	return w
}

func (e *rotationTestEnv) seedAccount(t *testing.T) {
	t.Helper()
	a := &model.Asset{Name: "核心-01", Protocol: model.ProtocolSSH, Host: "10.0.0.1", Port: 22}
	if err := e.db.Create(a).Error; err != nil {
		t.Fatalf("建立資產: %v", err)
	}
	acc := &model.AssetAccount{AssetID: a.ID, Username: "root", PasswordEnc: "enc-secret"}
	if err := e.db.Create(acc).Error; err != nil {
		t.Fatalf("建立帳號: %v", err)
	}
	if err := e.db.Create(&model.ChangeSecretRecord{
		PlanID: 1, AssetID: a.ID, AccountID: acc.ID, AccountUsername: "root",
		Status: model.ChangeSecretSuccess, ExecutedAt: time.Now().Add(-24 * time.Hour),
	}).Error; err != nil {
		t.Fatalf("建立改密記錄: %v", err)
	}
}

func scheduleBody(name string) map[string]any {
	return map[string]any{
		"name": name, "cron": "0 1 1 * *", "enabled": true,
		"scope_kind": model.RotationScopeAll, "retention_days": 400, "language": "zh-TW",
	}
}

func TestRotationReportDatasetPermissions(t *testing.T) {
	env := newRotationTestEnv(t)
	env.seedAccount(t)

	w := env.do(t, http.MethodGet, "/api/v1/rotation-report", "auditor", 1, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("auditor 讀資料集應 200，實得 %d：%s", w.Code, w.Body.String())
	}

	denied := env.do(t, http.MethodGet, "/api/v1/rotation-report", "user", 2, nil)
	if denied.Code != http.StatusForbidden {
		t.Fatalf("僅 user 角色者應 403，實得 %d", denied.Code)
	}
	if bytes.Contains(denied.Body.Bytes(), []byte("rotation")) {
		t.Fatalf("拒絕回應不得洩漏端點內部細節：%s", denied.Body.String())
	}

	// 三個讀取端點同一道閘
	for _, path := range []string{
		"/api/v1/rotation-report/records?period_start=2026-08-01T00:00:00Z&period_end=2026-09-01T00:00:00Z",
	} {
		if got := env.do(t, http.MethodGet, path, "user", 2, nil); got.Code != http.StatusForbidden {
			t.Fatalf("%s 對 user 應 403，實得 %d", path, got.Code)
		}
		if got := env.do(t, http.MethodGet, path, "auditor", 1, nil); got.Code != http.StatusOK {
			t.Fatalf("%s 對 auditor 應 200，實得 %d：%s", path, got.Code, got.Body.String())
		}
	}
}

func TestRotationReportDatasetHasNoCredentialFields(t *testing.T) {
	env := newRotationTestEnv(t)
	env.seedAccount(t)
	if err := env.db.Create(&model.ChangeSecretPlan{
		Name: "週度改密", Cron: "0 3 * * 1", Enabled: true, AssetIDs: "[1]",
		Accounts: "@ALL", SecretType: model.ChangeSecretTypePassword,
		PasswordLength: 24, MaxAgeDays: 60,
	}).Error; err != nil {
		t.Fatalf("建立計劃: %v", err)
	}

	w := env.do(t, http.MethodGet, "/api/v1/rotation-report", "auditor", 1, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("資料集應 200，實得 %d", w.Code)
	}
	body := w.Body.String()
	for _, forbidden := range []string{
		"password_length", "password_enc", "private_key", "password_complexity",
		"key_strategy", "credential_group", "secret_type",
	} {
		if bytes.Contains([]byte(body), []byte(forbidden)) {
			t.Fatalf("資料集回應不得含 %q：%s", forbidden, body)
		}
	}
	// 反向：該有的欄位在（否則上面的斷言可能只是驗到一份空回應）
	for _, expected := range []string{"summary", "rows", "max_age_days", "bucket", "plans"} {
		if !bytes.Contains([]byte(body), []byte(expected)) {
			t.Fatalf("資料集回應缺少 %q：%s", expected, body)
		}
	}
}

func TestRotationReportScheduleRequiresAdmin(t *testing.T) {
	env := newRotationTestEnv(t)

	denied := env.do(t, http.MethodPost, "/api/v1/rotation-report/schedules", "auditor", 1,
		scheduleBody("月報"))
	if denied.Code != http.StatusForbidden {
		t.Fatalf("auditor 建排程應 403，實得 %d：%s", denied.Code, denied.Body.String())
	}
	var count int64
	env.db.Model(&model.RotationReportSchedule{}).Count(&count)
	if count != 0 {
		t.Fatalf("被拒的請求不得留下排程列，實得 %d 列", count)
	}

	created := env.do(t, http.MethodPost, "/api/v1/rotation-report/schedules", "admin", 9,
		scheduleBody("月報"))
	if created.Code != http.StatusCreated {
		t.Fatalf("admin 建排程應 201，實得 %d：%s", created.Code, created.Body.String())
	}

	var logs []model.AuditLog
	if err := env.db.Where("resource = ?", model.ResourceRotationReport).Find(&logs).Error; err != nil {
		t.Fatalf("查審計列: %v", err)
	}
	if len(logs) == 0 {
		t.Fatal("排程建立必須入審計——沒有它，「誰要求系統每期產出哪個範圍的報告」無從查起")
	}
	found := false
	for _, l := range logs {
		if l.Status == model.StatusSuccess && l.Username == "user-9" &&
			bytes.Contains([]byte(l.ErrorMsg), []byte("rotation_report.schedule_created")) {
			found = true
		}
	}
	if !found {
		t.Fatalf("審計列須帶事件名與行為者，實得 %+v", logs)
	}

	// 值域越界回 400 機器碼
	bad := scheduleBody("壞排程")
	bad["retention_days"] = 0
	if got := env.do(t, http.MethodPost, "/api/v1/rotation-report/schedules", "admin", 9, bad); got.Code != http.StatusBadRequest {
		t.Fatalf("留存天數越界應 400，實得 %d：%s", got.Code, got.Body.String())
	}
}

func TestRotationReportManualJobCreatesExportJob(t *testing.T) {
	env := newRotationTestEnv(t)
	env.seedAccount(t)

	w := env.do(t, http.MethodPost, "/api/v1/rotation-report/jobs", "auditor", 5, map[string]any{
		"scope_kind":   model.RotationScopeAll,
		"period_start": "2026-07-01T00:00:00Z",
		"period_end":   "2026-09-30T00:00:00Z",
		"language":     "zh-TW",
	})
	if w.Code != http.StatusAccepted {
		t.Fatalf("auditor 手動產出應 202，實得 %d：%s", w.Code, w.Body.String())
	}

	var jobs []model.AuditExportJob
	if err := env.db.Find(&jobs).Error; err != nil {
		t.Fatalf("查工作單: %v", err)
	}
	if len(jobs) != 1 {
		t.Fatalf("應建立一張工作單，實得 %d", len(jobs))
	}
	if jobs[0].Kind != model.ExportJobKindRotationReport {
		t.Fatalf("工作單種類應為 rotation_report，實得 %q", jobs[0].Kind)
	}
	if jobs[0].RequesterID != 5 {
		t.Fatalf("手動產出的申請者應為發起者，實得 %d", jobs[0].RequesterID)
	}

	// 區間反向：400，且不留工作單
	bad := env.do(t, http.MethodPost, "/api/v1/rotation-report/jobs", "auditor", 5, map[string]any{
		"scope_kind":   model.RotationScopeAll,
		"period_start": "2026-09-30T00:00:00Z",
		"period_end":   "2026-07-01T00:00:00Z",
	})
	if bad.Code != http.StatusBadRequest {
		t.Fatalf("區間反向應 400，實得 %d：%s", bad.Code, bad.Body.String())
	}
	var after int64
	env.db.Model(&model.AuditExportJob{}).Count(&after)
	if after != 1 {
		t.Fatalf("被拒的請求不得留下工作單，實得 %d 張", after)
	}
}

// TestRotationReportLanguageRejected 手動產出的語言值非閉集時回 400 機器碼，
// 而不是靜默換成預設語言後照樣受理——後者讓送錯參數的人拿到一份語言與請求
// 不符的報告，卻收到成功的回應。
func TestRotationReportLanguageRejected(t *testing.T) {
	env := newRotationTestEnv(t)
	env.seedAccount(t)
	body := map[string]any{
		"scope_kind":   model.RotationScopeAll,
		"period_start": time.Now().Add(-24 * time.Hour).Format(time.RFC3339),
		"period_end":   time.Now().Format(time.RFC3339),
		"language":     "xx",
	}
	w := env.do(t, http.MethodPost, "/api/v1/rotation-report/jobs", "auditor", 1, body)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("非法語言應 400，實得 %d：%s", w.Code, w.Body.String())
	}
	if !bytes.Contains(w.Body.Bytes(), []byte("VALIDATION_ROTATION_REPORT_BAD_LANGUAGE")) {
		t.Fatalf("應回語言值域的機器碼，實得：%s", w.Body.String())
	}
	var jobs int64
	if err := env.db.Model(&model.AuditExportJob{}).Count(&jobs).Error; err != nil {
		t.Fatalf("計數工作單: %v", err)
	}
	if jobs != 0 {
		t.Fatalf("被拒的請求不得留下工作單，實得 %d 張", jobs)
	}

	// 反向：缺省語言仍受理（否則上面的 400 可能只是這條路徑整個壞了）
	delete(body, "language")
	ok := env.do(t, http.MethodPost, "/api/v1/rotation-report/jobs", "auditor", 1, body)
	if ok.Code != http.StatusAccepted {
		t.Fatalf("缺省語言應受理，實得 %d：%s", ok.Code, ok.Body.String())
	}
}

// TestRotationScheduleNameTooLong 排程名超過長度上限時在服務層回 400 機器碼，
// 而不是讓儲存層的寬度限制把它變成一則內部錯誤。
func TestRotationScheduleNameTooLong(t *testing.T) {
	env := newRotationTestEnv(t)
	long := strings.Repeat("排", 129)
	w := env.do(t, http.MethodPost, "/api/v1/rotation-report/schedules", "admin", 1,
		scheduleBody(long))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("超長名稱應 400，實得 %d：%s", w.Code, w.Body.String())
	}
	if !bytes.Contains(w.Body.Bytes(), []byte("VALIDATION_ROTATION_SCHEDULE_NAME_TOO_LONG")) {
		t.Fatalf("應回名稱長度的機器碼，實得：%s", w.Body.String())
	}

	// 邊界內：128 字應建得起來
	ok := env.do(t, http.MethodPost, "/api/v1/rotation-report/schedules", "admin", 1,
		scheduleBody(strings.Repeat("排", 128)))
	if ok.Code != http.StatusCreated {
		t.Fatalf("128 字應受理，實得 %d：%s", ok.Code, ok.Body.String())
	}

	// 修改路徑同一道閘
	upd := env.do(t, http.MethodPut, "/api/v1/rotation-report/schedules/1", "admin", 1,
		scheduleBody(long))
	if upd.Code != http.StatusBadRequest {
		t.Fatalf("修改成超長名稱應 400，實得 %d：%s", upd.Code, upd.Body.String())
	}
}

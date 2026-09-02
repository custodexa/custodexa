package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/custodexa/backend/config"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// 證據包非同步匯出端點。
//
// 本檔釘六件事：
//  1. **同步路徑負向守衛**：bundle 模式一律機器碼拒絕——不交付任何 bundle
//     位元組（無 ZIP magic）、不產生任何 job；事件報告的同步行為不受影響。
//  2. 發起：202＋job id、入審計含完整篩選快照；去重命中回既有 job；
//     報告模式參數被機器碼拒絕。
//  3. 並行發起不穿透上限（HTTP 層端到端）。
//  4. **下載綁申請者本人**：同樣具 audit:view 的他帳號 403，且回應與
//     「job 不存在」逐位元組相同（無存在性細節）；失敗 job 不阻擋重新發起。
//  5. 本人成功下載：位元組一致、審計含 SHA-256；不可下載態收斂 410。
//  6. 權限閘：無 audit:view 者三端點一律 403（真 RequirePermission）。
//  7. 發起吃樞紐＋類別（4b.1）：快照完整入 job 與審計；未知類別值不靜默忽略。

// exportJobTestEnv 端點測試環境：真 handler、真權限中介層、sqlite job 庫、
// 身分由 X-Test-User/X-Test-Role 標頭注入（模擬 AuthMiddleware 已解出的身分）
type exportJobTestEnv struct {
	router  *gin.Engine
	db      *gorm.DB // job 庫（同時為 database.DB，審計同庫）
	jobs    *audit.AuditExportJobService
	handler *AuditExportHandler
	dir     string
}

func newExportJobTestEnv(t *testing.T) *exportJobTestEnv {
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
	sqlDB.SetMaxOpenConns(1)
	if err := db.AutoMigrate(&model.AuditExportJob{}, &model.AuditLog{},
		&model.User{}, &model.Asset{}, &model.Session{}, &model.ClipboardEvent{},
		&model.AuditRetentionWatermark{}, &model.AuditCheckpoint{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	// 報告模式的兩張 timestamptz 表（沿 audit 模組 fixture 的原生 DDL 作法）
	for _, ddl := range []string{
		`CREATE TABLE session_commands (
			id INTEGER PRIMARY KEY AUTOINCREMENT, session_id INTEGER NOT NULL, user_id INTEGER NOT NULL,
			asset_id INTEGER, command TEXT NOT NULL, seq INTEGER NOT NULL, executed_at DATETIME NOT NULL,
			degraded BOOLEAN NOT NULL DEFAULT 0, degrade_reason TEXT NOT NULL DEFAULT '')`,
		`CREATE TABLE command_alerts (
			id INTEGER PRIMARY KEY AUTOINCREMENT, rule_id INTEGER, rule_name TEXT NOT NULL,
			session_id INTEGER NOT NULL, user_id INTEGER NOT NULL, asset_id INTEGER,
			command TEXT NOT NULL, severity TEXT NOT NULL, triggered_at DATETIME NOT NULL,
			reviewed_by INTEGER, reviewed_at DATETIME, disposition TEXT NOT NULL DEFAULT 'pending',
			note TEXT NOT NULL DEFAULT '', blocked BOOLEAN NOT NULL DEFAULT 0,
			kind TEXT NOT NULL DEFAULT 'rule', reason_code TEXT NOT NULL DEFAULT '')`,
	} {
		if err := db.Exec(ddl).Error; err != nil {
			t.Fatalf("create table: %v", err)
		}
	}
	oldDB := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = oldDB })

	auditSvc := audit.NewAuditLogService(&config.FeatureFlags{
		AuditLogEnabled: true, AsyncAuditEnabled: false, AuditFallbackToFile: false})
	exportSvc := audit.NewAuditExportService(db, auditSvc, audit.NewSessionCommandService(db), exportJobNoRecordings{})
	jobs := audit.NewAuditExportJobService(db)
	h := NewAuditExportHandler(exportSvc, jobs, auditSvc)

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
	grp := r.Group("/api/v1/audit-export")
	grp.GET("", middleware.RequirePermission(middleware.PermAuditView), h.Export)
	grp.POST("/jobs", middleware.RequirePermission(middleware.PermAuditView), h.CreateJob)
	grp.GET("/jobs", middleware.RequirePermission(middleware.PermAuditView), h.ListJobs)
	grp.GET("/jobs/:id/download", middleware.RequirePermission(middleware.PermAuditView), h.DownloadJob)

	return &exportJobTestEnv{router: r, db: db, jobs: jobs, handler: h, dir: t.TempDir()}
}

// exportJobNoRecordings 無錄影替身（同 audit 模組 emptyRecordings 的理由）
type exportJobNoRecordings struct{}

func (exportJobNoRecordings) RecordingProtocol(uint) (string, error) {
	return "", fmt.Errorf("測試環境無錄影檔")
}

func (exportJobNoRecordings) GetRecordingStream(uint) (io.ReadCloser, error) {
	return nil, fmt.Errorf("測試環境無錄影檔")
}

func (env *exportJobTestEnv) do(method, target, userID, role string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	req := httptest.NewRequest(method, target, nil)
	if userID != "" {
		req.Header.Set("X-Test-User", userID)
	}
	if role != "" {
		req.Header.Set("X-Test-Role", role)
	}
	env.router.ServeHTTP(w, req)
	return w
}

func (env *exportJobTestEnv) jobCount(t *testing.T) int64 {
	t.Helper()
	var n int64
	if err := env.db.Model(&model.AuditExportJob{}).Count(&n).Error; err != nil {
		t.Fatalf("count jobs: %v", err)
	}
	return n
}

func respCode(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var body struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("回應非 JSON: %q (%v)", w.Body.String(), err)
	}
	return body.Code
}

// 同步路徑負向守衛：bundle 模式機器碼拒絕、零 bundle 位元組、零 job
func TestSyncExportRejectsBundleModeAndCreatesNoJob(t *testing.T) {
	env := newExportJobTestEnv(t)

	w := env.do("GET", "/api/v1/audit-export?user_id=1", "9", "auditor")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if code := respCode(t, w); code != "RULE_AUDIT_EXPORT_BUNDLE_ASYNC_ONLY" {
		t.Fatalf("code=%s", code)
	}
	// 不交付任何 bundle 位元組：回應非 ZIP（無 PK magic）、非 zip content-type
	if bytes.HasPrefix(w.Body.Bytes(), []byte("PK")) {
		t.Fatal("同步路徑交付了 bundle 位元組")
	}
	if ct := w.Header().Get("Content-Type"); strings.Contains(ct, "zip") {
		t.Fatalf("Content-Type=%s", ct)
	}
	// 不轉 job：零列（GET 不得產生建立副作用）
	if n := env.jobCount(t); n != 0 {
		t.Fatalf("同步拒絕產生了 %d 個 job", n)
	}
}

// 事件報告的同步行為不受影響（同一端點、report 參數照常出 ZIP）
func TestSyncExportReportModeStillServes(t *testing.T) {
	env := newExportJobTestEnv(t)
	from := time.Now().UTC().Add(-24 * time.Hour).Format(time.RFC3339)
	to := time.Now().UTC().Format(time.RFC3339)
	w := env.do("GET", "/api/v1/audit-export?subject=user&user_id=1&start_time="+from+"&end_time="+to, "9", "auditor")
	if w.Code != http.StatusOK {
		t.Fatalf("報告模式受波及: status=%d body=%s", w.Code, w.Body.String())
	}
	if !bytes.HasPrefix(w.Body.Bytes(), []byte("PK")) {
		t.Fatal("報告模式未回 ZIP")
	}
	if n := env.jobCount(t); n != 0 {
		t.Fatalf("報告模式產生了 job: %d", n)
	}
}

func TestCreateJobAcceptedDedupAndAudited(t *testing.T) {
	env := newExportJobTestEnv(t)

	w := env.do("POST", "/api/v1/audit-export/jobs?session_id=42", "9", "auditor")
	if w.Code != http.StatusAccepted {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var body struct {
		Data struct {
			ID     uint              `json:"id"`
			Status string            `json:"status"`
			Filter map[string]string `json:"filter"`
		} `json:"data"`
		Deduplicated bool `json:"deduplicated"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if body.Data.ID == 0 || body.Data.Status != model.ExportJobPending || body.Deduplicated {
		t.Fatalf("發起回應: %+v", body)
	}
	if body.Data.Filter["session_id"] != "42" {
		t.Fatalf("範圍摘要: %v", body.Data.Filter)
	}

	// 去重：同人同範圍回既有 job
	w = env.do("POST", "/api/v1/audit-export/jobs?session_id=42", "9", "auditor")
	var dup struct {
		Data         struct{ ID uint }
		Deduplicated bool
	}
	if err := json.Unmarshal(w.Body.Bytes(), &dup); err != nil {
		t.Fatalf("parse dup: %v", err)
	}
	if w.Code != http.StatusAccepted || !dup.Deduplicated || dup.Data.ID != body.Data.ID {
		t.Fatalf("去重: status=%d %+v", w.Code, dup)
	}
	if n := env.jobCount(t); n != 1 {
		t.Fatalf("去重仍建列: %d", n)
	}

	// 發起入審計：resource=audit_export、action=create、含完整篩選快照與 job id
	var rows []model.AuditLog
	if err := env.db.Where("resource = ? AND action = ?",
		string(model.ResourceAuditExport), string(model.ActionCreate)).Find(&rows).Error; err != nil {
		t.Fatalf("查審計: %v", err)
	}
	found := false
	for _, row := range rows {
		if strings.Contains(row.ErrorMsg, fmt.Sprintf("job=%d", body.Data.ID)) &&
			strings.Contains(row.ErrorMsg, "session_id=42") && row.UserID == 9 {
			found = true
		}
	}
	if !found {
		t.Fatalf("發起審計缺篩選快照或 job id: %+v", rows)
	}
}

func TestCreateJobRejectsReportModeParams(t *testing.T) {
	env := newExportJobTestEnv(t)
	from := time.Now().UTC().Add(-24 * time.Hour).Format(time.RFC3339)
	to := time.Now().UTC().Format(time.RFC3339)
	w := env.do("POST", "/api/v1/audit-export/jobs?subject=user&user_id=1&start_time="+from+"&end_time="+to, "9", "auditor")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if code := respCode(t, w); code != "RULE_EXPORT_JOB_BUNDLE_ONLY" {
		t.Fatalf("code=%s", code)
	}
	if n := env.jobCount(t); n != 0 {
		t.Fatalf("被拒仍建列: %d", n)
	}
}

// 並行發起不得穿透上限（HTTP 端到端；上限檢查與建立同一交易）
func TestCreateJobParallelDoesNotPierceLimit(t *testing.T) {
	env := newExportJobTestEnv(t)
	const parallel = 8
	codes := make([]int, parallel)
	var wg sync.WaitGroup
	for i := 0; i < parallel; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			w := env.do("POST", fmt.Sprintf("/api/v1/audit-export/jobs?session_id=%d", 100+i), "9", "auditor")
			codes[i] = w.Code
		}(i)
	}
	wg.Wait()
	accepted, conflicted := 0, 0
	for _, c := range codes {
		switch c {
		case http.StatusAccepted:
			accepted++
		case http.StatusConflict:
			conflicted++
		default:
			t.Fatalf("非預期狀態碼: %v", codes)
		}
	}
	// 每申請者進行中上限 3（audit 模組常數）；穿透＝accepted 超額
	if accepted != 3 || conflicted != parallel-3 {
		t.Fatalf("並行穿透: accepted=%d conflicted=%d", accepted, conflicted)
	}
	if n := env.jobCount(t); n != 3 {
		t.Fatalf("落庫超額: %d", n)
	}
}

// seedDoneJob 造一個 done job（真產物檔）
func (env *exportJobTestEnv) seedDoneJob(t *testing.T, requester uint, payload string) *model.AuditExportJob {
	t.Helper()
	sid := uint(7000 + requester)
	job, _, err := env.jobs.CreateJob(requester, fmt.Sprintf("user-%d", requester), &audit.ExportFilter{SessionID: &sid})
	if err != nil {
		t.Fatalf("seed job: %v", err)
	}
	artifact := filepath.Join(env.dir, fmt.Sprintf("job-%d.zip", job.ID))
	if err := os.WriteFile(artifact, []byte(payload), 0o600); err != nil {
		t.Fatalf("寫產物: %v", err)
	}
	now := time.Now()
	expires := now.Add(time.Hour)
	if err := env.db.Model(&model.AuditExportJob{}).Where("id = ?", job.ID).Updates(map[string]any{
		"status": model.ExportJobDone, "artifact_path": artifact,
		"artifact_sha256": "deadbeef", "artifact_size": int64(len(payload)),
		"packaged_at": now, "expires_at": expires,
	}).Error; err != nil {
		t.Fatalf("轉 done: %v", err)
	}
	return job
}

// 下載綁申請者本人：同權限他帳號 403，回應與「不存在」逐位元組相同
func TestDownloadDeniesOtherAuditorWithoutExistenceDetails(t *testing.T) {
	env := newExportJobTestEnv(t)
	job := env.seedDoneJob(t, 9, "ZIPBYTES")

	// 申請者本人可下載（對照組——證明拒絕不是因為 job 壞掉）
	own := env.do("GET", fmt.Sprintf("/api/v1/audit-export/jobs/%d/download", job.ID), "9", "auditor")
	if own.Code != http.StatusOK || own.Body.String() != "ZIPBYTES" {
		t.Fatalf("本人下載: status=%d body=%q", own.Code, own.Body.String())
	}

	// 同樣具 audit:view 的他帳號（user 8、auditor 角色）：403
	other := env.do("GET", fmt.Sprintf("/api/v1/audit-export/jobs/%d/download", job.ID), "8", "auditor")
	if other.Code != http.StatusForbidden {
		t.Fatalf("他帳號下載 status=%d body=%s", other.Code, other.Body.String())
	}
	if code := respCode(t, other); code != "AUTH_EXPORT_JOB_REQUESTER_ONLY" {
		t.Fatalf("code=%s", code)
	}
	if strings.Contains(other.Body.String(), "ZIPBYTES") {
		t.Fatal("拒絕回應洩出產物位元組")
	}

	// 無存在性細節：對「他人的存在 job」與「不存在的 job」回應逐位元組相同
	ghost := env.do("GET", "/api/v1/audit-export/jobs/999999/download", "8", "auditor")
	if ghost.Code != other.Code || ghost.Body.String() != other.Body.String() {
		t.Fatalf("存在性可由回應分辨: exist=(%d,%q) ghost=(%d,%q)",
			other.Code, other.Body.String(), ghost.Code, ghost.Body.String())
	}

	// 拒絕入審計（denied 列，細節只在審計）
	var denied int64
	if err := env.db.Model(&model.AuditLog{}).
		Where("resource = ? AND status = ?", string(model.ResourceAuditExport), string(model.StatusDenied)).
		Count(&denied).Error; err != nil {
		t.Fatalf("查審計: %v", err)
	}
	if denied < 2 {
		t.Fatalf("拒絕未入審計: denied=%d", denied)
	}

	// 本人成功下載入審計（含 SHA-256）
	var rows []model.AuditLog
	if err := env.db.Where("resource = ? AND status = ?",
		string(model.ResourceAuditExport), string(model.StatusSuccess)).Find(&rows).Error; err != nil {
		t.Fatalf("查審計: %v", err)
	}
	foundDownload := false
	for _, row := range rows {
		if strings.Contains(row.ErrorMsg, "sha256=deadbeef") && row.UserID == 9 {
			foundDownload = true
		}
	}
	if !foundDownload {
		t.Fatal("下載審計缺 SHA-256 或操作者")
	}
}

// 本人 job 的不可下載態收斂 410（pending 與 expired 同碼，不經下載端點展開細節）
func TestDownloadUnavailableStatesConverge(t *testing.T) {
	env := newExportJobTestEnv(t)
	sid := uint(50)
	pending, _, err := env.jobs.CreateJob(9, "user-9", &audit.ExportFilter{SessionID: &sid})
	if err != nil {
		t.Fatalf("seed pending: %v", err)
	}
	w := env.do("GET", fmt.Sprintf("/api/v1/audit-export/jobs/%d/download", pending.ID), "9", "auditor")
	if w.Code != http.StatusGone || respCode(t, w) != "RULE_EXPORT_ARTIFACT_UNAVAILABLE" {
		t.Fatalf("pending 下載: %d %s", w.Code, w.Body.String())
	}

	done := env.seedDoneJob(t, 9, "Z")
	past := time.Now().Add(-time.Minute)
	if err := env.db.Model(&model.AuditExportJob{}).Where("id = ?", done.ID).
		Update("expires_at", past).Error; err != nil {
		t.Fatalf("倒填過期: %v", err)
	}
	w2 := env.do("GET", fmt.Sprintf("/api/v1/audit-export/jobs/%d/download", done.ID), "9", "auditor")
	if w2.Code != http.StatusGone || respCode(t, w2) != "RULE_EXPORT_ARTIFACT_UNAVAILABLE" {
		t.Fatalf("過期下載未收斂: %d %s", w2.Code, w2.Body.String())
	}
	if w2.Body.String() != w.Body.String() {
		t.Fatal("pending 與 expired 的拒絕可被分辨（未收斂）")
	}
}

// failed job 不阻擋重新發起（端到端：POST 同範圍 → 新 job）
func TestFailedJobDoesNotBlockRefire(t *testing.T) {
	env := newExportJobTestEnv(t)
	w := env.do("POST", "/api/v1/audit-export/jobs?session_id=61", "9", "auditor")
	if w.Code != http.StatusAccepted {
		t.Fatalf("首發: %d", w.Code)
	}
	if err := env.db.Model(&model.AuditExportJob{}).
		Where("requester_id = ?", 9).Update("status", model.ExportJobFailed).Error; err != nil {
		t.Fatalf("轉 failed: %v", err)
	}
	w = env.do("POST", "/api/v1/audit-export/jobs?session_id=61", "9", "auditor")
	var body struct {
		Deduplicated bool
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if w.Code != http.StatusAccepted || body.Deduplicated {
		t.Fatalf("failed 阻擋重發起: %d dedup=%v", w.Code, body.Deduplicated)
	}
}

func TestListJobsOnlyOwn(t *testing.T) {
	env := newExportJobTestEnv(t)
	a1 := env.seedDoneJob(t, 9, "A1")
	sid := uint(9001)
	a2, _, err := env.jobs.CreateJob(9, "user-9", &audit.ExportFilter{SessionID: &sid})
	if err != nil {
		t.Fatalf("a2: %v", err)
	}
	env.seedDoneJob(t, 8, "B1") // 他人

	w := env.do("GET", "/api/v1/audit-export/jobs", "9", "auditor")
	if w.Code != http.StatusOK {
		t.Fatalf("list: %d", w.Code)
	}
	var body struct {
		Data  []map[string]any `json:"data"`
		Total int64            `json:"total"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if body.Total != 2 || len(body.Data) != 2 {
		t.Fatalf("total=%d len=%d", body.Total, len(body.Data))
	}
	// id 降冪；投影不含伺服器路徑
	if uint(body.Data[0]["id"].(float64)) != a2.ID || uint(body.Data[1]["id"].(float64)) != a1.ID {
		t.Fatalf("排序: %v", body.Data)
	}
	if strings.Contains(w.Body.String(), env.dir) {
		t.Fatal("清單洩出伺服器產物路徑")
	}
}

// 無 audit:view（user 角色）三端點一律 403（真 RequirePermission）
func TestJobsEndpointsRequireAuditView(t *testing.T) {
	env := newExportJobTestEnv(t)
	for _, req := range [][2]string{
		{"POST", "/api/v1/audit-export/jobs?session_id=1"},
		{"GET", "/api/v1/audit-export/jobs"},
		{"GET", "/api/v1/audit-export/jobs/1/download"},
	} {
		w := env.do(req[0], req[1], "5", "user")
		if w.Code != http.StatusForbidden {
			t.Fatalf("%s %s: status=%d", req[0], req[1], w.Code)
		}
	}
	if n := env.jobCount(t); n != 0 {
		t.Fatalf("無權限發起建了 job: %d", n)
	}
}

// 發起帶樞紐＋類別（4b.1）：受理、快照完整入 job 與審計
func TestCreateJobAcceptsPivotAndTypes(t *testing.T) {
	env := newExportJobTestEnv(t)
	from := time.Now().UTC().Add(-24 * time.Hour).Format(time.RFC3339)
	to := time.Now().UTC().Format(time.RFC3339)
	q := "/api/v1/audit-export/jobs?pack=evidence_bundle&subject=user&user_id=1" +
		"&start_time=" + from + "&end_time=" + to + "&types=clipboard,command"

	w := env.do("POST", q, "9", "auditor")
	if w.Code != http.StatusAccepted {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var body struct {
		Data struct {
			ID     uint              `json:"id"`
			Filter map[string]string `json:"filter"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("parse: %v", err)
	}
	// 篩選快照完整：樞紐與類別都在（丟掉任一項，包內範圍就與畫面不符）
	if body.Data.Filter["subject"] != "user" || body.Data.Filter["types"] != "clipboard,command" {
		t.Fatalf("job 篩選快照缺樞紐或類別: %v", body.Data.Filter)
	}

	var rows []model.AuditLog
	if err := env.db.Where("resource = ? AND action = ?",
		string(model.ResourceAuditExport), string(model.ActionCreate)).Find(&rows).Error; err != nil {
		t.Fatalf("查審計: %v", err)
	}
	found := false
	for _, row := range rows {
		if strings.Contains(row.ErrorMsg, "subject=user") &&
			strings.Contains(row.ErrorMsg, "types=clipboard,command") {
			found = true
		}
	}
	if !found {
		t.Fatalf("發起審計缺樞紐或類別: %+v", rows)
	}
}

// 未知類別值回錯誤碼、不建列（SHALL NOT 靜默忽略）
func TestCreateJobRejectsUnknownType(t *testing.T) {
	env := newExportJobTestEnv(t)
	w := env.do("POST",
		"/api/v1/audit-export/jobs?pack=evidence_bundle&session_id=42&types=command,telepathy",
		"9", "auditor")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if code := respCode(t, w); code != "VALIDATION_INVALID_QUERY_PARAM" {
		t.Fatalf("code=%s", code)
	}
	if n := env.jobCount(t); n != 0 {
		t.Fatalf("被拒仍建列: %d", n)
	}
}

// 閉集外的 kind 值：錯誤回應須指得出是哪個參數。
//
// 沿既有 apierror 參數慣例（field 為受控 enum）——欄名不在允許清單時整組參數
// 會被丟掉，使用者拿到的是一句斷掉的「無效的 」，前端也標不出錯在哪一欄。
func TestExportJobListRejectsUnknownKindWithField(t *testing.T) {
	env := newExportJobTestEnv(t)
	w := env.do("GET", "/api/v1/audit-export/jobs?kind=bogus", "9", "auditor")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var body struct {
		Code   string            `json:"code"`
		Error  string            `json:"error"`
		Params map[string]string `json:"params"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("回應非 JSON: %q (%v)", w.Body.String(), err)
	}
	if body.Code != "VALIDATION_INVALID_QUERY_PARAM" {
		t.Fatalf("code=%s", body.Code)
	}
	if body.Params["field"] != "kind" {
		t.Fatalf("params.field 應為 kind，實得 %#v", body.Params)
	}
	if strings.TrimSpace(body.Error) == "無效的" || strings.HasSuffix(body.Error, "無效的 ") {
		t.Fatalf("訊息缺欄名（句子沒寫完）: %q", body.Error)
	}
	if !strings.Contains(body.Error, "工作單種類") {
		t.Fatalf("訊息未帶欄位顯示名: %q", body.Error)
	}
}

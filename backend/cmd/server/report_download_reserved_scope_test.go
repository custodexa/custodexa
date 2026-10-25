package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/config"
	"github.com/custodexa/backend/internal/api"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
)

// 報告、匯出、下載、統計與證據端點對節點範圍指派不生效：稽核類權限點範圍屬性預留、設定類只限全域，
// 經節點範圍指派持有必要權限點者一律 403 單一形狀，不回依節點裁切的部分內容，也不留下工作單或排程。
// 同一角色改為全域指派後，輪替報告資料集與證據包工作單列表照常回應，鍵集與超級管理者相同。
//
// 主體每個請求以產品目錄自資料庫重解；指派直接寫表（SQLite；設 TEST_PG_DSN 時改在 PostgreSQL）。
// 輪替報告與證據包工作單掛正式 handler；其餘端點掛哨兵 handler，一旦抵達即判失敗。

// reportReservedRoutes 稽核預留與全域限定兩類的全部端點（method、登錄路徑）。
var reportReservedRoutes = [][2]string{
	// 稽核預留
	{http.MethodGet, "/api/v1/agent-tasks"},
	{http.MethodGet, "/api/v1/agent-tasks/:requestId"},
	{http.MethodGet, "/api/v1/agent-tool-calls"},
	{http.MethodGet, "/api/v1/agent-tool-calls/:id/arguments"},
	{http.MethodGet, "/api/v1/audit-checkpoints"},
	{http.MethodGet, "/api/v1/audit-checkpoints/public-key"},
	{http.MethodGet, "/api/v1/audit-checkpoints/verify"},
	{http.MethodGet, "/api/v1/audit-export"},
	{http.MethodGet, "/api/v1/audit-export/jobs"},
	{http.MethodPost, "/api/v1/audit-export/jobs"},
	{http.MethodGet, "/api/v1/audit-export/jobs/:id/download"},
	{http.MethodGet, "/api/v1/audit-export/public-key"},
	{http.MethodGet, "/api/v1/audit-integrity/verify"},
	{http.MethodPost, "/api/v1/compliance/report-jobs"},
	{http.MethodGet, "/api/v1/compliance/snapshot"},
	{http.MethodGet, "/api/v1/daily-reviews"},
	{http.MethodPost, "/api/v1/daily-reviews"},
	{http.MethodGet, "/api/v1/daily-reviews/days/:date"},
	{http.MethodGet, "/api/v1/daily-reviews/pending"},
	{http.MethodGet, "/api/v1/daily-reviews/pending/count"},
	{http.MethodGet, "/api/v1/daily-reviews/stats"},
	{http.MethodGet, "/api/v1/daily-reviews/status"},
	{http.MethodGet, "/api/v1/recordings/stats"},
	{http.MethodGet, "/api/v1/rotation-report"},
	{http.MethodPost, "/api/v1/rotation-report/jobs"},
	{http.MethodGet, "/api/v1/rotation-report/records"},
	{http.MethodGet, "/api/v1/sessions/:id/recording"},
	{http.MethodGet, "/api/v1/sessions/:id/recording/download"},
	{http.MethodGet, "/api/v1/sessions/:id/recording/stream"},
	// 錄影串流 token 的簽發端點（串流本身為公開登錄、靠不透明 token，不列入）
	{http.MethodPost, "/api/v1/sessions/:id/recording/token"},
	// 全域限定
	{http.MethodPost, "/api/v1/role-definitions/summary"},
	{http.MethodGet, "/api/v1/rotation-report/schedules"},
	{http.MethodPost, "/api/v1/rotation-report/schedules"},
	{http.MethodDelete, "/api/v1/rotation-report/schedules/:id"},
	{http.MethodPut, "/api/v1/rotation-report/schedules/:id"},
	{http.MethodPost, "/api/v1/rotation-report/schedules/:id/run"},
	{http.MethodPost, "/api/v1/security-policies/compliance/preview"},
	{http.MethodDelete, "/api/v1/sessions/:id/recording"},
	{http.MethodGet, "/api/v1/transmission-inventory"},
	{http.MethodPost, "/api/v1/transmission-inventory/export"},
}

type rdrEnv struct {
	*asmEnv
	rotation *api.RotationReportHandler
	exports  *api.AuditExportHandler
	reached  []string // 抵達哨兵 handler 的請求（任何一筆即失敗）
	schedule uint
	job      uint
}

func newRDREnv(t *testing.T) *rdrEnv {
	t.Helper()
	gin.SetMode(gin.TestMode)
	base := newASMEnv(t)
	require.NoError(t, base.db.AutoMigrate(&model.AssetAccount{}, &model.Credential{}, &model.CredentialSecretVersion{},
		&model.ChangeSecretPlan{}, &model.CredentialJobAuthorization{}, &model.ChangeSecretRecord{},
		&model.ChangeSecretCandidate{}, &model.RotationReportSchedule{}, &model.AuditExportJob{}))
	auditSvc := audit.NewAuditLogService(&config.FeatureFlags{AuditLogEnabled: true, AsyncAuditEnabled: false, AuditFallbackToFile: false})
	jobs := audit.NewAuditExportJobService(base.db)
	plans := asset.NewChangeSecretPlanService(base.db)
	builder := asset.NewRotationReportBuilder(base.db, plans, func() int { return 90 })
	schedules := asset.NewRotationReportScheduleService(base.db, jobs, builder)
	e := &rdrEnv{asmEnv: base,
		rotation: api.NewRotationReportHandler(builder, schedules, auditSvc),
		exports:  api.NewAuditExportHandler(nil, jobs, auditSvc)}
	e.node("prod", "")

	sch := model.RotationReportSchedule{Name: "rdr-monthly", Cron: "0 1 1 * *", Enabled: true,
		ScopeKind: model.RotationScopeAll, RetentionDays: 400, Language: "zh-TW", PeriodAnchor: time.Now().UTC()}
	require.NoError(t, base.db.Create(&sch).Error)
	e.schedule = sch.ID
	job := model.AuditExportJob{RequesterID: base.super, RequesterName: "zz-asm-super", Kind: model.ExportJobKindEvidenceBundle,
		FilterJSON: "{}", FilterHash: strings.Repeat("0", 64), Status: model.ExportJobDone, Attempts: 1, RequestedAt: time.Now().UTC()}
	require.NoError(t, base.db.Create(&job).Error)
	e.job = job.ID
	return e
}

func (e *rdrEnv) sentinel(c *gin.Context) {
	e.reached = append(e.reached, c.Request.Method+" "+c.FullPath())
	c.Status(http.StatusTeapot)
}

// engine 與正式組裝同一條守衛：主體注入（認證中介層的等價出口）後經登錄閘。
func (e *rdrEnv) engine(uid uint) *gin.Engine {
	r := gin.New()
	r.Use(func(c *gin.Context) {
		p, err := authz.ResolveUserOn(e.db, uid, authz.TokenFacts{})
		require.NoError(e.t, err)
		middleware.SetPrincipal(c, p)
		c.Set("userID", uid)
		c.Set("username", fmt.Sprintf("u%d", uid))
		c.Next()
	}, middleware.EnforceRegistry())
	wired := map[string]gin.HandlerFunc{
		"GET /api/v1/rotation-report":                    e.rotation.Dataset,
		"GET /api/v1/rotation-report/records":            e.rotation.Records,
		"POST /api/v1/rotation-report/jobs":              e.rotation.CreateJob,
		"GET /api/v1/rotation-report/schedules":          e.rotation.ListSchedules,
		"POST /api/v1/rotation-report/schedules":         e.rotation.CreateSchedule,
		"PUT /api/v1/rotation-report/schedules/:id":      e.rotation.UpdateSchedule,
		"DELETE /api/v1/rotation-report/schedules/:id":   e.rotation.DeleteSchedule,
		"POST /api/v1/rotation-report/schedules/:id/run": e.rotation.RunSchedule,
		"POST /api/v1/audit-export/jobs":                 e.exports.CreateJob,
		"GET /api/v1/audit-export/jobs":                  e.exports.ListJobs,
		"GET /api/v1/audit-export/jobs/:id/download":     e.exports.DownloadJob,
	}
	for _, rt := range reportReservedRoutes {
		h, ok := wired[rt[0]+" "+rt[1]]
		if !ok {
			h = e.sentinel
		}
		r.Handle(rt[0], rt[1], h)
	}
	return r
}

func (e *rdrEnv) concrete(path string) string {
	return strings.NewReplacer(
		"/schedules/:id", fmt.Sprintf("/schedules/%d", e.schedule),
		"/jobs/:id", fmt.Sprintf("/jobs/%d", e.job),
		":requestId", "1", ":date", "2026-10-01", ":id", "1",
	).Replace(path)
}

func (e *rdrEnv) hit(uid uint, method, path string) (int, string) {
	e.t.Helper()
	var body *strings.Reader
	if method == http.MethodGet || method == http.MethodDelete {
		body = strings.NewReader("")
	} else {
		body = strings.NewReader("{}")
	}
	req := httptest.NewRequest(method, e.concrete(path), body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	e.engine(uid).ServeHTTP(w, req)
	return w.Code, w.Body.String()
}

func (e *rdrEnv) counts() (jobs, schedules int64) {
	e.t.Helper()
	require.NoError(e.t, e.db.Model(&model.AuditExportJob{}).Count(&jobs).Error)
	require.NoError(e.t, e.db.Model(&model.RotationReportSchedule{}).Count(&schedules).Error)
	return
}

func TestReportDownloadReservedScope(t *testing.T) {
	e := newRDREnv(t)
	cat := authz.ProductCatalogue()

	// 每條端點的必要權限點取自登錄表；範圍屬性必須是預留或只限全域（否則清單本身已過期）
	perms := map[string]authz.Permission{}
	for _, rt := range reportReservedRoutes {
		entry, ok := authz.LookupRoute(rt[0], rt[1])
		require.True(t, ok, "未登錄：%s %s", rt[0], rt[1])
		require.Equal(t, authz.BasePerm, entry.Base, "%s %s", rt[0], rt[1])
		require.Empty(t, entry.AnyOf, "%s %s", rt[0], rt[1])
		def, ok := cat.Lookup(entry.Perm)
		require.True(t, ok, "%s %s", rt[0], rt[1])
		require.Contains(t, []authz.ScopeAttr{authz.ScopeReserved, authz.ScopeGlobalOnly}, def.Scope,
			"%s %s 的權限點 %s", rt[0], rt[1], entry.Perm)
		perms[rt[0]+" "+rt[1]] = entry.Perm
	}

	// 每個必要權限點一位持有者：自訂角色只含該權限點，以節點範圍指派到 prod
	holder := map[authz.Permission]uint{}
	for _, rt := range reportReservedRoutes {
		p := perms[rt[0]+" "+rt[1]]
		if _, ok := holder[p]; ok {
			continue
		}
		uid := e.user("zz-rdr-" + strings.NewReplacer(":", "-", "_", "-").Replace(string(p)))
		e.grantNodes(uid, e.role(p), "prod")
		holder[p] = uid
	}

	jobsBefore, schedulesBefore := e.counts()
	require.EqualValues(t, 1, jobsBefore)
	require.EqualValues(t, 1, schedulesBefore)

	for _, rt := range reportReservedRoutes {
		rt := rt
		t.Run(rt[0]+" "+rt[1], func(t *testing.T) {
			code, raw := e.hit(holder[perms[rt[0]+" "+rt[1]]], rt[0], rt[1])
			require.Equal(t, http.StatusForbidden, code, raw)
			require.Equal(t, []string{"code", "error"}, asmKeys(t, raw), raw)
			require.Contains(t, raw, `"AUTH_PERMISSION_DENIED"`)
		})
	}
	require.Empty(t, e.reached, "節點範圍指派的請求不得抵達 handler")
	jobsAfter, schedulesAfter := e.counts()
	require.Equal(t, jobsBefore, jobsAfter, "被拒的請求不得留下工作單")
	require.Equal(t, schedulesBefore, schedulesAfter, "被拒的請求不得改動排程")

	// 全域指派對照（不另開子測試：子測試數恰為端點清單列數）
	uid := e.user("zz-rdr-global-audit")
	e.grantGlobal(uid, e.role(authz.PermAuditView))
	for _, path := range []string{"/api/v1/rotation-report", "/api/v1/audit-export/jobs"} {
		code, raw := e.hit(uid, http.MethodGet, path)
		require.Equal(t, http.StatusOK, code, "%s：%s", path, raw)
		superCode, superRaw := e.hit(e.super, http.MethodGet, path)
		require.Equal(t, http.StatusOK, superCode, "%s：%s", path, superRaw)
		require.Equal(t, asmKeys(t, superRaw), asmKeys(t, raw), path)
	}
	fmt.Printf("EVIDENCE report-reserved-routes=%d holders=%d\n", len(reportReservedRoutes), len(holder))
}

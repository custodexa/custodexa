package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

// 報告與匯出工作單端點自行寫出的審計列，其 status_code 必須等於實際回應狀態碼。
//
// 審計出口以 c.Writer.Status() 取值；回應尚未寫出時那個值是預設的 200，
// 所以呼叫順序錯誤時被拒與受理的請求都會被記成 200。每個情境打一次請求，
// 以該端點專屬的訊息前綴找出 handler 寫的那一列（測試路由不掛審計中介層，
// 但仍以前綴篩選），斷言 StatusCode == w.Code；被拒情境另斷言 w.Code != 200，
// 證明測到的是順序錯誤時會記錯的分支。

// handlerAuditRow 取資源上訊息含 marker 的最新一列。
func handlerAuditRow(t *testing.T, db *gorm.DB, resource model.AuditResource, marker string) model.AuditLog {
	t.Helper()
	var rows []model.AuditLog
	if err := db.Where("resource = ?", string(resource)).Order("id DESC").Find(&rows).Error; err != nil {
		t.Fatalf("讀審計列: %v", err)
	}
	for _, row := range rows {
		if strings.Contains(row.ErrorMsg, marker) {
			return row
		}
	}
	t.Fatalf("找不到訊息含 %q 的審計列（共 %d 列）", marker, len(rows))
	return model.AuditLog{}
}

// assertAuditStatus 斷言審計列狀態碼等於回應，並記錄兩者供 -v 輸出留證。
func assertAuditStatus(t *testing.T, name string, w *httptest.ResponseRecorder, row model.AuditLog, rejected bool) {
	t.Helper()
	t.Logf("%s: 回應 %d，審計列 status_code %d（msg %q）", name, w.Code, row.StatusCode, row.ErrorMsg)
	if rejected && w.Code == http.StatusOK {
		t.Fatalf("%s: 拒絕情境的回應不應為 200", name)
	}
	if row.StatusCode != w.Code {
		t.Fatalf("%s: 審計列 status_code=%d，回應=%d", name, row.StatusCode, w.Code)
	}
}

func TestRotationReportAuditStatusMatchesResponse(t *testing.T) {
	env := newRotationTestEnv(t)

	period := map[string]any{
		"period_start": "2026-07-01T00:00:00Z",
		"period_end":   "2026-09-30T00:00:00Z",
	}
	w := env.do(t, http.MethodPost, "/api/v1/rotation-report/jobs", "auditor", 1, map[string]any{
		"language":     "fr-FR",
		"period_start": period["period_start"],
		"period_end":   period["period_end"],
	})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("不支援語言應 400，實得 %d：%s", w.Code, w.Body.String())
	}
	assertAuditStatus(t, "發起被拒", w,
		handlerAuditRow(t, env.db, model.ResourceRotationReport, "rotation_report.job_created denied"), true)

	w = env.do(t, http.MethodPost, "/api/v1/rotation-report/jobs", "auditor", 1, period)
	if w.Code != http.StatusAccepted {
		t.Fatalf("發起應受理，實得 %d：%s", w.Code, w.Body.String())
	}
	assertAuditStatus(t, "發起受理", w,
		handlerAuditRow(t, env.db, model.ResourceRotationReport, "rotation_report.job_created job="), false)

	w = env.do(t, http.MethodPost, "/api/v1/rotation-report/schedules", "admin", 1,
		scheduleBody(strings.Repeat("排", 129)))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("超長名稱應 400，實得 %d：%s", w.Code, w.Body.String())
	}
	assertAuditStatus(t, "排程建立被拒", w,
		handlerAuditRow(t, env.db, model.ResourceRotationReport, "rotation_report.schedule_created denied"), true)

	w = env.do(t, http.MethodPost, "/api/v1/rotation-report/schedules", "admin", 1, scheduleBody("月報"))
	if w.Code != http.StatusCreated {
		t.Fatalf("排程建立應 201，實得 %d：%s", w.Code, w.Body.String())
	}
	assertAuditStatus(t, "排程建立成功", w,
		handlerAuditRow(t, env.db, model.ResourceRotationReport, "rotation_report.schedule_created id="), false)
}

func TestComplianceReportAuditStatusMatchesResponse(t *testing.T) {
	env := newPolicyTestEnv(t)
	env.seedCustomGroup(t)
	const path = "/api/v1/compliance/report-jobs"

	w := env.do(t, http.MethodPost, path, "auditor", map[string]any{"retention_days": 90})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("缺政策組應 400，實得 %d：%s", w.Code, w.Body.String())
	}
	assertAuditStatus(t, "參數不合", w,
		handlerAuditRow(t, env.db, model.ResourceComplianceMap, "reason=bad_params"), true)

	w = env.do(t, http.MethodPost, path, "auditor", map[string]any{"group": "nope", "retention_days": 90})
	if w.Code != http.StatusNotFound {
		t.Fatalf("不存在的政策組應 404，實得 %d：%s", w.Code, w.Body.String())
	}
	assertAuditStatus(t, "政策組不存在", w,
		handlerAuditRow(t, env.db, model.ResourceComplianceMap, "reason=group_lookup"), true)

	w = env.do(t, http.MethodPost, path, "auditor", map[string]any{"group": "inhouse", "retention_days": 90})
	if w.Code != http.StatusAccepted {
		t.Fatalf("發起應受理，實得 %d：%s", w.Code, w.Body.String())
	}
	assertAuditStatus(t, "發起受理", w,
		handlerAuditRow(t, env.db, model.ResourceComplianceMap, "compliance_report.job_created job="), false)
}

func TestExportJobAuditStatusMatchesResponse(t *testing.T) {
	env := newExportJobTestEnv(t)
	const jobs = "/api/v1/audit-export/jobs"

	w := env.do("POST", jobs+"?session_id=1", "9", "auditor")
	if w.Code != http.StatusAccepted {
		t.Fatalf("發起應受理，實得 %d：%s", w.Code, w.Body.String())
	}
	assertAuditStatus(t, "發起受理", w,
		handlerAuditRow(t, env.db, model.ResourceAuditExport, "created=true"), false)

	// 進行中上限為 3：再發兩張後第 4 張被拒
	for _, sid := range []string{"2", "3"} {
		if w := env.do("POST", jobs+"?session_id="+sid, "9", "auditor"); w.Code != http.StatusAccepted {
			t.Fatalf("造量失敗 session_id=%s：%d %s", sid, w.Code, w.Body.String())
		}
	}
	w = env.do("POST", jobs+"?session_id=4", "9", "auditor")
	if w.Code != http.StatusConflict {
		t.Fatalf("超過上限應 409，實得 %d：%s", w.Code, w.Body.String())
	}
	assertAuditStatus(t, "超過上限", w,
		handlerAuditRow(t, env.db, model.ResourceAuditExport, "job_limit_exceeded"), true)

	// 下載非本人
	w = env.do("GET", jobs+"/1/download", "8", "auditor")
	if w.Code != http.StatusForbidden {
		t.Fatalf("非本人下載應 403，實得 %d：%s", w.Code, w.Body.String())
	}
	assertAuditStatus(t, "下載非本人", w,
		handlerAuditRow(t, env.db, model.ResourceAuditExport, "reason=not_found_or_not_requester"), true)

	// 本人下載仍在 pending 的工作單：產物不可用
	w = env.do("GET", jobs+"/1/download", "9", "auditor")
	if w.Code != http.StatusGone {
		t.Fatalf("產物不可用應 410，實得 %d：%s", w.Code, w.Body.String())
	}
	assertAuditStatus(t, "產物不可用", w,
		handlerAuditRow(t, env.db, model.ResourceAuditExport, "reason=artifact_unavailable"), true)
}

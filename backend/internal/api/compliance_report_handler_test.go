package api

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
)

// 合規報告的手動產出端點。
//
// TestComplianceReportJobRoles 擋 B 類：產出入口的角色閘開錯方向——稽核人員被擋
// 就產不出報告（本次事故的形狀），一般使用者能產就等於讀得到整份安全設定。
// TestComplianceReportJobRejectsBadInput 擋 A 類：保留天數越界、組打錯字或對未生效
// 的組產報告，都會得到一份看起來正常、內容卻錯的產物。

func TestComplianceReportJobRoles(t *testing.T) {
	env := newPolicyTestEnv(t)
	env.seedCustomGroup(t)

	body := map[string]any{"group": "inhouse", "language": "en-US", "retention_days": 30}
	for _, role := range []string{"admin", "auditor"} {
		before := time.Now()
		w := env.do(t, http.MethodPost, "/api/v1/compliance/report-jobs", role, body)
		if w.Code != http.StatusAccepted {
			t.Fatalf("%s 產出報告 = %d（body %s）", role, w.Code, w.Body.String())
		}
		var job model.AuditExportJob
		if err := env.db.Order("id DESC").First(&job).Error; err != nil {
			t.Fatalf("%s 未建工作單: %v", role, err)
		}
		if job.Kind != model.ExportJobKindComplianceReport {
			t.Errorf("%s 工作單種類 = %q", role, job.Kind)
		}
		if job.ExpiresAt == nil || job.ExpiresAt.Before(before.AddDate(0, 0, 30).Add(-time.Minute)) ||
			job.ExpiresAt.After(time.Now().AddDate(0, 0, 30).Add(time.Minute)) {
			t.Errorf("%s 預定到期應為發起時刻加 30 天，實得 %v", role, job.ExpiresAt)
		}
		if !strings.Contains(job.FilterJSON, `"group":"inhouse"`) ||
			!strings.Contains(job.FilterJSON, `"language":"`+body["language"].(string)+`"`) {
			t.Errorf("%s 工作單快照缺參數：%s", role, job.FilterJSON)
		}
		body["language"] = "ja-JP" // 第二個角色換語言，避免命中去重而驗不到第二張
	}

	w := env.do(t, http.MethodPost, "/api/v1/compliance/report-jobs", "user", body)
	if w.Code != http.StatusForbidden {
		t.Fatalf("一般使用者產出報告應 403，實得 %d", w.Code)
	}
	var count int64
	env.db.Model(&model.AuditExportJob{}).Count(&count)
	if count != 2 {
		t.Errorf("被拒的請求不得建工作單，實得 %d 張", count)
	}

	found := 0
	for _, row := range env.auditRows(t) {
		if row.Resource == model.ResourceComplianceMap &&
			strings.Contains(row.ErrorMsg, "compliance_report.job_created") &&
			row.Status == model.StatusSuccess {
			found++
		}
	}
	if found != 2 {
		t.Errorf("成功產出應各留一筆審計（compliance_report.job_created），實得 %d", found)
	}
}

func TestComplianceReportJobRejectsBadInput(t *testing.T) {
	env := newPolicyTestEnv(t)
	env.seedCustomGroup(t)
	if err := env.repo.CreateCustomGroup("paused", "暫停", "zh-TW"); err != nil {
		t.Fatalf("建組: %v", err)
	}
	if err := env.repo.SetGroupEnabled("paused", false); err != nil {
		t.Fatalf("停用組: %v", err)
	}

	cases := []struct {
		name string
		body map[string]any
		code int
	}{
		{"保留天數為零", map[string]any{"group": "inhouse", "retention_days": 0}, http.StatusBadRequest},
		{"保留天數超過上限", map[string]any{"group": "inhouse", "retention_days": 3651}, http.StatusBadRequest},
		{"缺政策組", map[string]any{"retention_days": 90}, http.StatusBadRequest},
		{"不存在的政策組", map[string]any{"group": "nope", "retention_days": 90}, http.StatusNotFound},
		{"未生效的政策組", map[string]any{"group": "paused", "retention_days": 90}, http.StatusBadRequest},
		{"不支援的語言", map[string]any{"group": "inhouse", "language": "fr-FR", "retention_days": 90}, http.StatusBadRequest},
	}
	for _, tc := range cases {
		w := env.do(t, http.MethodPost, "/api/v1/compliance/report-jobs", "auditor", tc.body)
		if w.Code != tc.code {
			t.Errorf("%s：狀態 %d，want %d（body %s）", tc.name, w.Code, tc.code, w.Body.String())
		}
	}
	var count int64
	env.db.Model(&model.AuditExportJob{}).Count(&count)
	if count != 0 {
		t.Errorf("被拒的請求不得建工作單，實得 %d 張", count)
	}
}

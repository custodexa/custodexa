package api

import (
	"errors"
	"net/http"
	"testing"

	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/audit/port"
	"github.com/custodexa/backend/internal/modules/policy"
	"gorm.io/gorm"
)

// 政策變更審計與政策寫入同成敗。
//
// 管理介面改政策時，每項實際變更的審計列與政策值在同一交易落地：審計寫不進去，
// 整批政策就不生效。反過來的形態（先提交政策、事後補寫審計）會在審計失敗時
// 留下一個已生效、卻查不到是誰改的政策值。

// failingPolicyAuditSink 第 failAt 次（從 1 起算）寫入時回錯，之前的寫入照常落地。
type failingPolicyAuditSink struct {
	failAt int
	calls  int
}

func (s *failingPolicyAuditSink) WriteInTx(tx *gorm.DB, ev port.AuditEvent) error {
	s.calls++
	if s.calls >= s.failAt {
		return errors.New("audit sink unavailable")
	}
	return audit.NewTxSink().WriteInTx(tx, ev)
}

func newPolicyUpdateEnv(t *testing.T, sink port.TxSink) *policyTestEnv {
	t.Helper()
	env := newPolicyTestEnv(t)
	// 刻意不給非同步審計服務：政策變更審計只能經交易內落地面寫出
	handler := NewSecurityPolicyHandler(env.service, nil, policy.NewComplianceService(env.service, env.repo), env.repo)
	if sink != nil {
		handler.SetAuditTxSink(sink)
	}
	env.router.PUT("/api/v1/security-policies", middleware.EnforceRegistry(), handler.Update)
	return env
}

func policyAuditRows(t *testing.T, db *gorm.DB) []model.AuditLog {
	t.Helper()
	var rows []model.AuditLog
	if err := db.Where("resource = ?", model.ResourceSecurityPolicy).Order("id").Find(&rows).Error; err != nil {
		t.Fatalf("讀審計列: %v", err)
	}
	return rows
}

func storedPolicyRows(t *testing.T, db *gorm.DB, keys ...string) int64 {
	t.Helper()
	var n int64
	if err := db.Model(&model.SecurityPolicy{}).Where("key IN ?", keys).Count(&n).Error; err != nil {
		t.Fatalf("讀政策列: %v", err)
	}
	return n
}

func TestSecurityPolicyChangeAuditAtomic(t *testing.T) {
	update := map[string]any{"policies": map[string]string{
		policy.PolicyPasswordMinLength:        "16",
		policy.PolicyMappingRevalidationHours: "6",
	}}

	for _, tc := range []struct {
		name   string
		failAt int
	}{
		{"第一項審計寫入失敗", 1},
		// 第一項的審計列已在交易內寫出，第二項失敗時要連同它一起回滾
		{"第二項審計寫入失敗", 2},
	} {
		t.Run(tc.name+"時政策值不變且不留審計", func(t *testing.T) {
			sink := &failingPolicyAuditSink{failAt: tc.failAt}
			env := newPolicyUpdateEnv(t, sink)
			beforeLen := env.service.Get(policy.PolicyPasswordMinLength)
			beforeHours := env.service.Get(policy.PolicyMappingRevalidationHours)

			w := env.do(t, http.MethodPut, "/api/v1/security-policies", model.RoleAdmin, update)
			if w.Code != http.StatusInternalServerError {
				t.Fatalf("審計寫入失敗的政策更新 = %d，want 500（body %s）", w.Code, w.Body.String())
			}
			if sink.calls != tc.failAt {
				t.Fatalf("審計落地面被呼叫 %d 次，want %d（失敗點沒有被走到）", sink.calls, tc.failAt)
			}
			if got := env.service.Get(policy.PolicyPasswordMinLength); got != beforeLen {
				t.Errorf("密碼最小長度 = %q，want 維持 %q", got, beforeLen)
			}
			if got := env.service.Get(policy.PolicyMappingRevalidationHours); got != beforeHours {
				t.Errorf("重新驗證時限 = %q，want 維持 %q", got, beforeHours)
			}
			if n := storedPolicyRows(t, env.db, policy.PolicyPasswordMinLength, policy.PolicyMappingRevalidationHours); n != 0 {
				t.Errorf("政策表留下 %d 列，want 0（整批回滾）", n)
			}
			if rows := policyAuditRows(t, env.db); len(rows) != 0 {
				t.Errorf("留下 %d 列政策審計，want 0：%+v", len(rows), rows)
			}
		})
	}

	t.Run("落地面未注入時拒絕寫入", func(t *testing.T) {
		env := newPolicyTestEnv(t)
		handler := NewSecurityPolicyHandler(env.service, nil, policy.NewComplianceService(env.service, env.repo), env.repo)
		handler.SetAuditTxSink(nil)
		env.router.PUT("/api/v1/security-policies", middleware.EnforceRegistry(), handler.Update)
		before := env.service.Get(policy.PolicyPasswordMinLength)

		w := env.do(t, http.MethodPut, "/api/v1/security-policies", model.RoleAdmin, update)
		if w.Code != http.StatusInternalServerError {
			t.Fatalf("未注入落地面的政策更新 = %d，want 500（body %s）", w.Code, w.Body.String())
		}
		if got := env.service.Get(policy.PolicyPasswordMinLength); got != before {
			t.Errorf("密碼最小長度 = %q，want 維持 %q", got, before)
		}
	})

	t.Run("審計與政策值一起落地", func(t *testing.T) {
		env := newPolicyUpdateEnv(t, nil) // 建構函式預設的交易內落地面
		w := env.do(t, http.MethodPut, "/api/v1/security-policies", model.RoleAdmin, update)
		if w.Code != http.StatusOK {
			t.Fatalf("政策更新 = %d（body %s）", w.Code, w.Body.String())
		}
		if got := env.service.Get(policy.PolicyPasswordMinLength); got != "16" {
			t.Errorf("密碼最小長度 = %q，want 16", got)
		}
		rows := policyAuditRows(t, env.db)
		want := map[string]bool{
			model.PolicyChangeAuditMessage(policy.PolicyPasswordMinLength, "12", "16"):       true,
			model.PolicyChangeAuditMessage(policy.PolicyMappingRevalidationHours, "12", "6"): true,
		}
		if len(rows) != len(want) {
			t.Fatalf("政策審計 %d 列，want %d：%+v", len(rows), len(want), rows)
		}
		for _, row := range rows {
			if !want[row.ErrorMsg] {
				t.Errorf("非預期或重複的審計訊息 %q", row.ErrorMsg)
			}
			delete(want, row.ErrorMsg)
			if row.Action != model.ActionUpdate || row.Status != model.StatusSuccess || row.UserID != 1 ||
				row.Username != "tester-admin" || row.Method != http.MethodPut ||
				row.Path != "/api/v1/security-policies" || row.StatusCode != http.StatusOK {
				t.Errorf("審計列形狀不符：%+v", row)
			}
		}
	})
}

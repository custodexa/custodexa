package sshproxy

import (
	"github.com/custodexa/backend/internal/modules/audit"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/custodexa/backend/internal/model"
)

// unwritableRecordingPath 以「路徑為檔案」誘發 probe 失敗（root 也擋得住；
// 權限類誘發對 root 無效）
func unwritableRecordingPath(t *testing.T) string {
	t.Helper()
	f := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(f, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	return f
}

// TestRecordingFailCloseGate 錄影前置檢查（recording-failure-handling D1/D2／
// connection-gating 簽發閘序五道）：政策開啟時 probe 失敗拒發非 admin；
// admin 唯一例外帶豁免標記；政策關閉不擋；閘位於停用後、政策閘前
func TestRecordingFailCloseGate(t *testing.T) {
	failCloseOn := func() bool { return true }

	t.Run("政策開：user 拒發 recording_unavailable", func(t *testing.T) {
		h, db, _ := setupPolicyGateTest(t)
		seedGateFixture(t, db)
		setGroupPolicy(t, db, 1, model.AccessPolicyOpen)
		h.RecordingPath = unwritableRecordingPath(t)
		h.RecordingFailClose = failCloseOn

		code, resp, _ := issueToken(h, 1, model.RoleUser, 1)
		if code != http.StatusForbidden || resp["reason"] != "recording_unavailable" {
			t.Fatalf("probe 失敗應 403+recording_unavailable: code=%d resp=%v", code, resp)
		}
	})

	t.Run("政策開：auditor 在授權閘即被擋（CPG-002）", func(t *testing.T) {
		h, db, _ := setupPolicyGateTest(t)
		seedGateFixture(t, db)
		setGroupPolicy(t, db, 1, model.AccessPolicyOpen)
		h.RecordingPath = unwritableRecordingPath(t)
		h.RecordingFailClose = failCloseOn

		// auditor 稽核唯讀：connect 授權閘（早於錄影閘）即回 403，走不到錄影
		// 前置檢查。錄影閘的非 admin 不豁免由上方 user case 覆蓋
		code, resp, _ := issueToken(h, 3, model.RoleAuditor, 1)
		if code != http.StatusForbidden || resp["reason"] == "recording_unavailable" {
			t.Fatalf("auditor 應在授權閘被擋（非 recording_unavailable）: code=%d resp=%v", code, resp)
		}
	})

	t.Run("政策開：admin 唯一例外放行＋審計豁免標記", func(t *testing.T) {
		h, db, _ := setupPolicyGateTest(t)
		seedGateFixture(t, db)
		setGroupPolicy(t, db, 1, model.AccessPolicyOpen)
		h.RecordingPath = unwritableRecordingPath(t)
		h.RecordingFailClose = failCloseOn

		code, resp, keys := issueToken(h, 2, model.RoleAdmin, 1)
		if code != http.StatusOK || resp["connect_token"] == nil {
			t.Fatalf("admin 應例外放行: code=%d resp=%v", code, resp)
		}
		details, ok := keys["audit_details"].(map[string]string)
		if !ok || details["recording_exemption"] != "admin" {
			t.Fatalf("admin 豁免必須帶審計標記: keys=%v", keys)
		}
	})

	t.Run("政策關：probe 失敗不擋簽發", func(t *testing.T) {
		h, db, _ := setupPolicyGateTest(t)
		seedGateFixture(t, db)
		setGroupPolicy(t, db, 1, model.AccessPolicyOpen)
		h.RecordingPath = unwritableRecordingPath(t)
		// RecordingFailClose 保持 nil＝關閉

		code, resp, _ := issueToken(h, 1, model.RoleUser, 1)
		if code != http.StatusOK || resp["connect_token"] == nil {
			t.Fatalf("政策關閉應照常簽發: code=%d resp=%v", code, resp)
		}
	})

	t.Run("閘序：錄影攔截先於政策閘（approval 段位回 recording_unavailable）", func(t *testing.T) {
		// 錄影儲存壞了不該引導使用者走申請流（申請核准了也連不上）
		h, db, _ := setupPolicyGateTest(t)
		seedGateFixture(t, db)
		setGroupPolicy(t, db, 1, model.AccessPolicyApproval)
		h.RecordingPath = unwritableRecordingPath(t)
		h.RecordingFailClose = failCloseOn

		code, resp, _ := issueToken(h, 1, model.RoleUser, 1)
		if code != http.StatusForbidden || resp["reason"] != "recording_unavailable" {
			t.Fatalf("錄影閘應先於政策閘: code=%d resp=%v", code, resp)
		}
	})

	t.Run("閘序：停用硬擋先於錄影閘", func(t *testing.T) {
		h, db, _ := setupPolicyGateTest(t)
		seedGateFixture(t, db)
		setGroupPolicy(t, db, 1, model.AccessPolicyOpen)
		db.Model(&model.Asset{}).Where("id = ?", 1).Update("active", false)
		h.RecordingPath = unwritableRecordingPath(t)
		h.RecordingFailClose = failCloseOn

		code, resp, _ := issueToken(h, 1, model.RoleUser, 1)
		if code != http.StatusForbidden || resp["reason"] != "asset_disabled" {
			t.Fatalf("停用檢查應先於錄影閘: code=%d resp=%v", code, resp)
		}
	})

	t.Run("probe 失敗開列 recording_probe 失效事件、成功回填", func(t *testing.T) {
		h, db, _ := setupPolicyGateTest(t)
		seedGateFixture(t, db)
		setGroupPolicy(t, db, 1, model.AccessPolicyOpen)
		h.RecordingPath = unwritableRecordingPath(t)

		issueToken(h, 1, model.RoleUser, 1) // 政策關：放行但偵測恆做
		var ev model.AuditFailureEvent
		if err := db.Where("mechanism = ?", model.MechanismRecordingProbe).
			First(&ev).Error; err != nil {
			t.Fatalf("probe 失敗應開列失效事件: %v", err)
		}
		if ev.EndedAt != nil {
			t.Fatal("進行中事件不應有 ended_at")
		}

		h.RecordingPath = t.TempDir()
		issueToken(h, 1, model.RoleUser, 1)
		if err := db.First(&ev, ev.ID).Error; err != nil {
			t.Fatal(err)
		}
		if ev.EndedAt == nil {
			t.Fatal("probe 成功應回填恢復（起訖區間完整）")
		}
	})

	t.Run("機制族分列：健康 probe 不 Resolve 文字路徑事件（flapping 釘住）", func(t *testing.T) {
		// 對抗驗證 High-1：session 級錄製失敗與儲存層 probe 是不同信號流，
		// 健康 probe 不得關閉另一路仍在進行的失效事件
		h, db, _ := setupPolicyGateTest(t)
		seedGateFixture(t, db)
		setGroupPolicy(t, db, 1, model.AccessPolicyOpen)
		audit.GetAuditFailure().Report(model.MechanismRecordingText, model.CauseRecordingWriteFailed,
			map[string]string{"detail": "SessionID=99: 模擬文字路徑寫入失敗"})

		issueToken(h, 1, model.RoleUser, 1) // probe 成功 → 僅 Resolve probe 流

		var ev model.AuditFailureEvent
		if err := db.Where("mechanism = ?", model.MechanismRecordingText).
			First(&ev).Error; err != nil {
			t.Fatal(err)
		}
		if ev.EndedAt != nil {
			t.Fatal("健康 probe 關閉了文字路徑仍在進行的失效事件")
		}
	})

	t.Run("probe 可寫：政策開照常簽發", func(t *testing.T) {
		h, db, _ := setupPolicyGateTest(t)
		seedGateFixture(t, db)
		setGroupPolicy(t, db, 1, model.AccessPolicyOpen)
		h.RecordingFailClose = failCloseOn // RecordingPath 為 setup 的可寫 TempDir

		code, resp, _ := issueToken(h, 1, model.RoleUser, 1)
		if code != http.StatusOK || resp["connect_token"] == nil {
			t.Fatalf("可寫時政策開啟不影響簽發: code=%d resp=%v", code, resp)
		}
	})
}

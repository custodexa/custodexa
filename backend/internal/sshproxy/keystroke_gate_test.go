package sshproxy

import (
	"net/http"
	"testing"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/session"
)

// 簽發點的鍵盤紀錄目錄探測（G-I11 同一道閘）。
func TestKeystrokeConnectGateProbe(t *testing.T) {
	failCloseOn := func() bool { return true }
	withService := func(h *Handler, root string) {
		h.KeystrokeService = session.NewKeystrokeService(nil, nil, root, nil)
	}

	t.Run("政策開：非超管拒發並回鍵盤紀錄專屬碼", func(t *testing.T) {
		h, db, _ := setupPolicyGateTest(t)
		seedGateFixture(t, db)
		setGroupPolicy(t, db, 1, model.AccessPolicyOpen)
		withService(h, unwritableRecordingPath(t))
		h.RecordingFailClose = failCloseOn
		code, resp, _ := issueToken(h, 1, model.RoleUser, 1)
		if code != http.StatusForbidden || resp["reason"] != "keystroke_unavailable" {
			t.Fatalf("code=%d resp=%v", code, resp)
		}
		if string(apierror.CodeKeystrokeUnavailable) != "RULE_KEYSTROKE_UNAVAILABLE" {
			t.Fatal("error code mismatch")
		}
		if resp["reason"] == "recording_unavailable" {
			t.Fatal("must not reuse the recording-unavailable reason")
		}
	})

	t.Run("政策開：超管豁免並留同一審計標記", func(t *testing.T) {
		h, db, _ := setupPolicyGateTest(t)
		seedGateFixture(t, db)
		setGroupPolicy(t, db, 1, model.AccessPolicyOpen)
		withService(h, unwritableRecordingPath(t))
		h.RecordingFailClose = failCloseOn
		code, resp, keys := issueToken(h, 2, model.RoleAdmin, 1)
		if code != http.StatusOK || resp["connect_token"] == nil {
			t.Fatalf("admin 應例外放行: code=%d resp=%v", code, resp)
		}
		details, ok := keys["audit_details"].(map[string]string)
		if !ok || details["recording_exemption"] != "admin" {
			t.Fatalf("豁免必須帶審計標記: keys=%v", keys)
		}
	})

	t.Run("政策關：探測失敗只告警不擋", func(t *testing.T) {
		h, db, _ := setupPolicyGateTest(t)
		seedGateFixture(t, db)
		setGroupPolicy(t, db, 1, model.AccessPolicyOpen)
		withService(h, unwritableRecordingPath(t))
		code, resp, _ := issueToken(h, 1, model.RoleUser, 1)
		if code != http.StatusOK || resp["connect_token"] == nil {
			t.Fatalf("code=%d resp=%v", code, resp)
		}
		var ev model.AuditFailureEvent
		if err := db.Where("mechanism = ?", model.MechanismKeystrokeProbe).First(&ev).Error; err != nil {
			t.Fatalf("探測失敗應開列 keystroke_probe 失效事件: %v", err)
		}
	})

	t.Run("探測成功只解除探測機制，不解除逐會話失敗", func(t *testing.T) {
		h, db, _ := setupPolicyGateTest(t)
		seedGateFixture(t, db)
		setGroupPolicy(t, db, 1, model.AccessPolicyOpen)
		withService(h, t.TempDir())
		audit.GetAuditFailure().Report(model.MechanismKeystrokeRecord, model.CauseKeystrokeWriteFailed,
			map[string]string{"session_id": "99"})
		audit.GetAuditFailure().Report(model.MechanismKeystrokeProbe, model.CauseKeystrokeDirUnwritable, nil)

		code, _, _ := issueToken(h, 1, model.RoleUser, 1) // 探測成功
		if code != http.StatusOK {
			t.Fatalf("code=%d", code)
		}
		var probe, rec model.AuditFailureEvent
		if err := db.Where("mechanism = ?", model.MechanismKeystrokeProbe).First(&probe).Error; err != nil {
			t.Fatal(err)
		}
		if probe.EndedAt == nil {
			t.Fatal("探測成功應解除探測機制的失敗")
		}
		if err := db.Where("mechanism = ?", model.MechanismKeystrokeRecord).First(&rec).Error; err != nil {
			t.Fatal(err)
		}
		if rec.EndedAt != nil {
			t.Fatal("探測成功不得解除逐會話機制的失敗")
		}
	})

	t.Run("可寫：政策開照常簽發", func(t *testing.T) {
		h, db, _ := setupPolicyGateTest(t)
		seedGateFixture(t, db)
		setGroupPolicy(t, db, 1, model.AccessPolicyOpen)
		withService(h, t.TempDir())
		h.RecordingFailClose = failCloseOn
		code, resp, _ := issueToken(h, 1, model.RoleUser, 1)
		if code != http.StatusOK || resp["connect_token"] == nil {
			t.Fatalf("code=%d resp=%v", code, resp)
		}
	})
}

package policy

import (
	"context"
	"testing"

	"github.com/custodexa/backend/internal/model"
)

// setupTransfer 建一組解析器與政策服務（沿 setupPolicyDB，另建 users 表供角色守衛用）。
func setupTransfer(t *testing.T) (*DataTransferService, *SecurityPolicyService) {
	t.Helper()
	svc, db := setupPolicyDB(t)
	if err := db.AutoMigrate(&model.User{}, &model.Role{}); err != nil {
		t.Fatalf("migrate users: %v", err)
	}
	return NewDataTransferService(svc), svc
}

func TestEffectiveTransferDefaultsAllAllowed(t *testing.T) {
	ts, _ := setupTransfer(t)

	caps, err := ts.EffectiveTransfer(context.Background(), 1, 1, TransferChannelWeb)
	if err != nil {
		t.Fatalf("EffectiveTransfer: %v", err)
	}
	want := TransferCapabilities{true, true, true, true, true}
	if caps != want {
		t.Errorf("出廠值 = %+v, want 五項皆 true（出廠允許＝既有行為零變更）", caps)
	}
}

// TestEffectiveTransferEachKeyIndependently 五鍵各自 true/false，且**只影響自己那一項**。
// 逐鍵單獨關閉並斷言其餘四項不變——這擋的是「政策鍵接錯欄位」（例如 upload 讀到
// download 的鍵）：若只斷言「被關的那項為 false」，接錯欄位的實作仍可能通過。
func TestEffectiveTransferEachKeyIndependently(t *testing.T) {
	cases := []struct {
		key  string
		want TransferCapabilities
	}{
		{PolicyClipboardSendEnabled, TransferCapabilities{false, true, true, true, true}},
		{PolicyClipboardRecvEnabled, TransferCapabilities{true, false, true, true, true}},
		{PolicyFileUploadEnabled, TransferCapabilities{true, true, false, true, true}},
		{PolicyFileDownloadEnabled, TransferCapabilities{true, true, true, false, true}},
		{PolicyFileDeleteEnabled, TransferCapabilities{true, true, true, true, false}},
	}
	for _, tc := range cases {
		t.Run(tc.key, func(t *testing.T) {
			ts, pol := setupTransfer(t)
			if _, err := pol.Update(tc.key, "false", "admin"); err != nil {
				t.Fatalf("Update %s: %v", tc.key, err)
			}
			caps, err := ts.EffectiveTransfer(context.Background(), 1, 1, TransferChannelWeb)
			if err != nil {
				t.Fatalf("EffectiveTransfer: %v", err)
			}
			if caps != tc.want {
				t.Errorf("關閉 %s 後 = %+v, want %+v", tc.key, caps, tc.want)
			}
		})
	}
}

// TestEffectiveTransferNoRoleExemption 不豁免任何角色（D5「admin 短路」段、使用者拍板）。
//
// 三種角色的使用者在同一份政策下 SHALL 得到完全相同的結果。
// 自證：在 EffectiveTransfer 內加 `if 該使用者是 admin { return 全允許 }`，本測試必紅。
func TestEffectiveTransferNoRoleExemption(t *testing.T) {
	ts, pol := setupTransfer(t)
	for _, key := range []string{
		PolicyClipboardSendEnabled, PolicyClipboardRecvEnabled,
		PolicyFileUploadEnabled, PolicyFileDownloadEnabled, PolicyFileDeleteEnabled,
	} {
		if _, err := pol.Update(key, "false", "admin"); err != nil {
			t.Fatalf("Update %s: %v", key, err)
		}
	}

	// 三個實體使用者，角色各異：admin／一般／稽核
	users := map[string]uint{}
	for i, role := range []string{model.RoleAdmin, model.RoleUser, model.RoleAuditor} {
		u := &model.User{Username: "u" + role, Roles: []model.Role{{Name: role}}}
		if err := pol.db.Create(u).Error; err != nil {
			t.Fatalf("建立 %s 使用者: %v", role, err)
		}
		users[role] = u.ID
		_ = i
	}

	denied := TransferCapabilities{}
	for role, uid := range users {
		caps, err := ts.EffectiveTransfer(context.Background(), uid, 1, TransferChannelWeb)
		if err != nil {
			t.Fatalf("EffectiveTransfer(%s): %v", role, err)
		}
		if caps != denied {
			t.Errorf("角色 %s（userID=%d）= %+v, want 全禁——資料傳輸閘不留 admin 例外，"+
				"admin 要用就改政策", role, uid, caps)
		}
	}
}

// TestTransferCapabilitiesAllowedMapping action 值對應到正確欄位，未知 action fail-close。
func TestTransferCapabilitiesAllowedMapping(t *testing.T) {
	only := func(action string) TransferCapabilities {
		c := TransferCapabilities{}
		switch action {
		case TransferActionClipboardSend:
			c.ClipboardSend = true
		case TransferActionClipboardRecv:
			c.ClipboardRecv = true
		case TransferActionFileUpload:
			c.FileUpload = true
		case TransferActionFileDownload:
			c.FileDownload = true
		case TransferActionFileDelete:
			c.FileDelete = true
		}
		return c
	}
	actions := []string{
		TransferActionClipboardSend, TransferActionClipboardRecv,
		TransferActionFileUpload, TransferActionFileDownload, TransferActionFileDelete,
	}
	for _, a := range actions {
		caps := only(a)
		if !caps.Allowed(a) {
			t.Errorf("Allowed(%s) = false，want true", a)
		}
		for _, other := range actions {
			if other == a {
				continue
			}
			if caps.Allowed(other) {
				t.Errorf("只開 %s 時 Allowed(%s) 竟為 true（欄位對應接錯）", a, other)
			}
		}
	}
	full := TransferCapabilities{true, true, true, true, true}
	if full.Allowed("file_rename") {
		t.Error("未知 action 應 fail-close 回 false")
	}
}

// TestAllowsActionFailClose 解析器的單動作入口與 EffectiveTransfer 一致。
func TestAllowsActionFailClose(t *testing.T) {
	ts, pol := setupTransfer(t)
	if _, err := pol.Update(PolicyFileUploadEnabled, "false", "admin"); err != nil {
		t.Fatalf("Update: %v", err)
	}
	ok, err := ts.AllowsAction(context.Background(), 1, 1, TransferChannelWeb, TransferActionFileUpload)
	if err != nil {
		t.Fatalf("AllowsAction: %v", err)
	}
	if ok {
		t.Error("file_upload_enabled=false 時 AllowsAction 應為 false")
	}
	ok, err = ts.AllowsAction(context.Background(), 1, 1, TransferChannelWeb, TransferActionFileDownload)
	if err != nil {
		t.Fatalf("AllowsAction: %v", err)
	}
	if !ok {
		t.Error("file_download_enabled 仍為出廠 true，AllowsAction 應為 true")
	}
}

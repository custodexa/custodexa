package policy_test

import (
	"testing"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/policy"
)

// 清冊分列 winrm 通道：只計設定了該通道的資產，依 scheme／TLS 模式分布，偏離數與判定核心一致。
func TestInventoryListsWinRMChannel(t *testing.T) {
	svc, _, db := setupInventorySvc(t, nil)
	for _, a := range []model.Asset{
		{Name: "rdp-plain", Protocol: model.ProtocolRDP, Host: "h", Port: 3389, CreatedBy: 1},
		{Name: "win-http", Protocol: model.ProtocolRDP, Host: "h", Port: 3389, CreatedBy: 1,
			RotationChannel: model.RotationChannelWindowsWinRM, WinrmScheme: model.WinrmSchemeHTTP},
		{Name: "win-insecure", Protocol: model.ProtocolRDP, Host: "h", Port: 3389, CreatedBy: 1,
			RotationChannel: model.RotationChannelWindowsWinRM, WinrmScheme: model.WinrmSchemeHTTPS, WinrmTLSMode: model.WinrmTLSModeInsecure},
		{Name: "win-ca", Protocol: model.ProtocolSSH, Host: "h", Port: 22, CreatedBy: 1,
			RotationChannel: model.RotationChannelWindowsWinRM, WinrmScheme: model.WinrmSchemeHTTPS, WinrmTLSMode: model.WinrmTLSModeCA},
	} {
		asset := a
		if err := db.Create(&asset).Error; err != nil {
			t.Fatal(err)
		}
	}
	inv, err := svc.Build()
	if err != nil {
		t.Fatal(err)
	}
	ch := channelOf(t, inv, policy.TransportChannelWinRM)
	if ch.TotalCount != 3 || ch.AtRiskCount != 2 {
		t.Errorf("winrm total=%d at_risk=%d, want 3/2", ch.TotalCount, ch.AtRiskCount)
	}
	if ch.DetailCodes["scheme=http"] != 1 || ch.DetailCodes["scheme=https,tls=insecure"] != 1 || ch.DetailCodes["scheme=https,tls=ca"] != 1 {
		t.Errorf("detail_codes = %v", ch.DetailCodes)
	}
	if ch.NoteCode != "winrm_rotation_channel" || ch.Note == "" {
		t.Errorf("note = %q/%q", ch.NoteCode, ch.Note)
	}
	if ch.Level != "" {
		t.Errorf("winrm 無政策等級, got %q", ch.Level)
	}
	// rdp 通道的計數不因改密通道而變
	rdp := channelOf(t, inv, policy.TransportChannelRDP)
	if rdp.TotalCount != 3 {
		t.Errorf("rdp total=%d, want 3（三台 rdp 資產）", rdp.TotalCount)
	}
}

package policy

import (
	"testing"

	"github.com/custodexa/backend/internal/model"
)

// WinRM 改密通道的傳輸階梯：http → 訊息層加密風險；https＋insecure → 未驗證憑證；
// https＋ca／system → 無；非 WinRM 通道無。改密風險不進 AssetRisks（連線前同意閘的依據）。
func TestTransmissionWinRMRisks(t *testing.T) {
	svc := newTransmissionSvc(t, nil)
	winrm := func(scheme, tlsMode string) *model.Asset {
		return &model.Asset{Protocol: model.ProtocolRDP, RotationChannel: model.RotationChannelWindowsWinRM,
			WinrmScheme: scheme, WinrmTLSMode: tlsMode, RDPSecurity: model.RDPSecurityNLA, RDPVerifyCert: true}
	}

	assertRisks(t, svc.AssetRotationRisks(winrm(model.WinrmSchemeHTTP, "")), RiskWinRMHTTPNTLM)
	assertRisks(t, svc.AssetRotationRisks(winrm(model.WinrmSchemeHTTPS, model.WinrmTLSModeInsecure)), RiskWinRMTLSInsecure)
	assertRisks(t, svc.AssetRotationRisks(winrm(model.WinrmSchemeHTTPS, model.WinrmTLSModeCA)))
	assertRisks(t, svc.AssetRotationRisks(winrm(model.WinrmSchemeHTTPS, model.WinrmTLSModeSystem)))
	// scheme 空值（髒資料）計為 http 檔：fail-closed
	assertRisks(t, svc.AssetRotationRisks(winrm("", "")), RiskWinRMHTTPNTLM)

	if got := svc.AssetRotationChannel(winrm(model.WinrmSchemeHTTP, "")); got != TransportChannelWinRM {
		t.Errorf("AssetRotationChannel = %q, want %q", got, TransportChannelWinRM)
	}
	plainRDP := &model.Asset{Protocol: model.ProtocolRDP, RDPSecurity: model.RDPSecurityNLA, RDPVerifyCert: true}
	if got := svc.AssetRotationChannel(plainRDP); got != "" {
		t.Errorf("未設 WinRM 的 rdp 資產不屬 winrm 通道, got %q", got)
	}
	assertRisks(t, svc.AssetRotationRisks(plainRDP))
	sshWinRM := &model.Asset{Protocol: model.ProtocolSSH, RotationChannel: model.RotationChannelWindowsSSH}
	assertRisks(t, svc.AssetRotationRisks(sshWinRM))

	// 連線通道不受改密通道影響：rdp 資產的 AssetChannel／AssetRisks 與改密設定無關
	risky := winrm(model.WinrmSchemeHTTP, "")
	if got := svc.AssetChannel(risky); got != TransportChannelRDP {
		t.Errorf("AssetChannel = %q, want rdp（改密通道不得改變連線通道）", got)
	}
	assertRisks(t, svc.AssetRisks(risky))
	if svc.ChannelLevel(TransportChannelWinRM) != TransportLevelOff {
		t.Error("winrm 無政策鍵，等級應為 off（改密不走 connect-token 閘）")
	}
}

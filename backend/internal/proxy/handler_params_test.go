package proxy

import (
	"testing"

	"github.com/custodexa/backend/internal/model"
)

// TestRDPSecurityParamsDefaultUnchanged 回歸：
// 未設定 RDP 安全欄位的存量資產，經注入＋fillDefaults 後的最終參數
// 必須與本 change 之前的預設完全一致（security=any、ignore-cert=true）
func TestRDPSecurityParamsDefaultUnchanged(t *testing.T) {
	asset := &model.Asset{Protocol: model.ProtocolRDP}

	security, ignoreCert := asset.EffectiveRDPParams()
	if security != "any" || !ignoreCert {
		t.Fatalf("EffectiveRDPParams 預設 = (%q, %v), want (any, true)", security, ignoreCert)
	}

	params := map[string]string{"security": security, "ignore-cert": "true"}
	result := fillDefaults(params, "rdp")
	if result["security"] != "any" {
		t.Errorf("security = %q, want any（與現狀一致）", result["security"])
	}
	if result["ignore-cert"] != "true" {
		t.Errorf("ignore-cert = %q, want true（與現狀一致）", result["ignore-cert"])
	}
}

// TestRDPSecurityParamsInjected 設定 nla＋驗憑證後，注入值不被 fillDefaults 覆蓋
func TestRDPSecurityParamsInjected(t *testing.T) {
	asset := &model.Asset{
		Protocol:      model.ProtocolRDP,
		RDPSecurity:   model.RDPSecurityNLA,
		RDPVerifyCert: true,
	}

	security, ignoreCert := asset.EffectiveRDPParams()
	if security != "nla" || ignoreCert {
		t.Fatalf("EffectiveRDPParams = (%q, %v), want (nla, false)", security, ignoreCert)
	}

	params := map[string]string{"security": security, "ignore-cert": "false"}
	result := fillDefaults(params, "rdp")
	if result["security"] != "nla" {
		t.Errorf("security = %q, want nla（注入值不可被預設覆蓋）", result["security"])
	}
	if result["ignore-cert"] != "false" {
		t.Errorf("ignore-cert = %q, want false（注入值不可被預設覆蓋）", result["ignore-cert"])
	}
}

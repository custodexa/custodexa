package policy

import (
	"testing"

	"github.com/custodexa/backend/internal/model"
)

// ldapRiskProvider 測試用的 risk view provider：
// 固定回一份「解析成功」的視圖，取代改動前的 config.LDAPConfig 快照參數。
// **只換注入形狀，判定輸入等價**——判準本身未動
func ldapRiskProvider(view LDAPRiskView) func() LDAPRiskResult {
	return func() LDAPRiskResult {
		return LDAPRiskResult{State: LDAPResolveOK, View: view}
	}
}

// ldapRiskProviderState 三態測試用（unconfigured／failed）
func ldapRiskProviderState(state LDAPResolveState) func() LDAPRiskResult {
	return func() LDAPRiskResult {
		return LDAPRiskResult{State: state}
	}
}

func newTransmissionSvc(t *testing.T, provider func() LDAPRiskResult) *TransmissionPolicyService {
	policy, _ := setupPolicyDB(t)
	return NewTransmissionPolicyService(policy, provider)
}

func riskKeys(risks []RiskItem) []string {
	keys := make([]string, 0, len(risks))
	for _, r := range risks {
		keys = append(keys, r.Key)
	}
	return keys
}

func assertRisks(t *testing.T, got []RiskItem, want ...string) {
	t.Helper()
	gotKeys := riskKeys(got)
	if len(gotKeys) != len(want) {
		t.Fatalf("風險項 = %v, want %v", gotKeys, want)
	}
	for i, k := range want {
		if gotKeys[i] != k {
			t.Fatalf("風險項 = %v, want %v", gotKeys, want)
		}
	}
}

func TestChannelLevelDefaultsOff(t *testing.T) {
	svc := newTransmissionSvc(t, nil)

	for _, ch := range []string{
		TransportChannelRDP, TransportChannelVNC, TransportChannelDB,
		TransportChannelLDAP, TransportChannelSyslog, TransportChannelNotify,
	} {
		if got := svc.ChannelLevel(ch); got != TransportLevelOff {
			t.Errorf("ChannelLevel(%s) = %q, want off", ch, got)
		}
	}
	// 未知通道 fail-open 至 off（不擋未納管通道）
	if got := svc.ChannelLevel("unknown"); got != TransportLevelOff {
		t.Errorf("ChannelLevel(unknown) = %q, want off", got)
	}
}

func TestChannelLevelReadsPolicy(t *testing.T) {
	policy, _ := setupPolicyDB(t)
	svc := NewTransmissionPolicyService(policy, nil)

	if _, err := policy.Update(PolicyTransportDBLevel, TransportLevelStrict, "admin"); err != nil {
		t.Fatal(err)
	}
	if got := svc.ChannelLevel(TransportChannelDB); got != TransportLevelStrict {
		t.Errorf("ChannelLevel(db) = %q, want strict", got)
	}
}

func TestRDPRisks(t *testing.T) {
	svc := newTransmissionSvc(t, nil)

	// 邊界：security 空（=any）→ 兩項全中
	asset := &model.Asset{Protocol: model.ProtocolRDP}
	assertRisks(t, svc.AssetRisks(asset), RiskRDPIgnoreCert, RiskRDPSecurityBelowNLA)

	// tls＋驗憑證：仍未達 NLA
	asset = &model.Asset{Protocol: model.ProtocolRDP, RDPSecurity: model.RDPSecurityTLS, RDPVerifyCert: true}
	assertRisks(t, svc.AssetRisks(asset), RiskRDPSecurityBelowNLA)

	// nla＋不驗憑證：只剩憑證項
	asset = &model.Asset{Protocol: model.ProtocolRDP, RDPSecurity: model.RDPSecurityNLA}
	assertRisks(t, svc.AssetRisks(asset), RiskRDPIgnoreCert)

	// nla＋驗憑證：無風險
	asset = &model.Asset{Protocol: model.ProtocolRDP, RDPSecurity: model.RDPSecurityNLA, RDPVerifyCert: true}
	assertRisks(t, svc.AssetRisks(asset))
}

func TestVNCRisksAlwaysHit(t *testing.T) {
	svc := newTransmissionSvc(t, nil)
	assertRisks(t, svc.AssetRisks(&model.Asset{Protocol: model.ProtocolVNC}), RiskVNCUnencrypted)
}

func TestDBRisksPerTLSMode(t *testing.T) {
	svc := newTransmissionSvc(t, nil)

	cases := []struct {
		mode string
		hit  bool
	}{
		{"", true}, {"disable", true},
		{"require", false}, {"verify-ca", false}, {"verify-full", false},
		// fail-closed：非明確安全值（存量髒資料、大小寫變體）一律計為風險——
		// 這些值在 dbproxy 不加 TLS 旗標，實際連線可降級或明文
		{"prefer", true}, {"DISABLE", true}, {"Require", true},
		{" require", true}, {"verify_full", true},
	}
	for _, c := range cases {
		asset := &model.Asset{Protocol: model.ProtocolMySQL, DBTLSMode: c.mode}
		got := svc.AssetRisks(asset)
		if c.hit {
			assertRisks(t, got, RiskDBTLSDisabled)
		} else {
			assertRisks(t, got)
		}
	}
}

func TestSSHAndK8sOutOfScope(t *testing.T) {
	svc := newTransmissionSvc(t, nil)

	for _, p := range []model.ProtocolType{model.ProtocolSSH, model.ProtocolK8s} {
		asset := &model.Asset{Protocol: p}
		if ch := svc.AssetChannel(asset); ch != "" {
			t.Errorf("AssetChannel(%s) = %q, want 空（範疇外）", p, ch)
		}
		assertRisks(t, svc.AssetRisks(asset))
	}
}

func TestLDAPRisks(t *testing.T) {
	// 未啟用＝通道不存在
	svc := newTransmissionSvc(t, ldapRiskProvider(LDAPRiskView{Enabled: false, URL: "ldap://dir:389"}))
	assertRisks(t, svc.LDAPRisks())

	// ldap:// 明文
	svc = newTransmissionSvc(t, ldapRiskProvider(LDAPRiskView{Enabled: true, URL: "ldap://dir:389"}))
	assertRisks(t, svc.LDAPRisks(), RiskLDAPPlaintext)

	// ldaps＋SkipTLSVerify 組合：加密但跳過驗證
	svc = newTransmissionSvc(t, ldapRiskProvider(LDAPRiskView{Enabled: true, URL: "ldaps://dir:636", SkipTLSVerify: true}))
	assertRisks(t, svc.LDAPRisks(), RiskLDAPSkipVerify)

	// ldaps 正常：無風險
	svc = newTransmissionSvc(t, ldapRiskProvider(LDAPRiskView{Enabled: true, URL: "ldaps://dir:636"}))
	assertRisks(t, svc.LDAPRisks())
}

func TestSyslogAndNotifyRisks(t *testing.T) {
	svc := newTransmissionSvc(t, nil)

	assertRisks(t, svc.SyslogRisks(model.SyslogProtocolUDP), RiskSyslogNonTLS)
	assertRisks(t, svc.SyslogRisks(model.SyslogProtocolTCP), RiskSyslogNonTLS)
	assertRisks(t, svc.SyslogRisks(model.SyslogProtocolTCPTLS))

	assertRisks(t, svc.NotifyRisks("http://hook.example.com/x"), RiskNotifyHTTP)
	assertRisks(t, svc.NotifyRisks("https://hook.example.com/x"))
}

func TestRiskFingerprintDeterministic(t *testing.T) {
	a := []RiskItem{{Key: RiskRDPIgnoreCert}, {Key: RiskRDPSecurityBelowNLA}}
	b := []RiskItem{{Key: RiskRDPSecurityBelowNLA}, {Key: RiskRDPIgnoreCert}}

	// 順序無關
	if TransmissionRiskFingerprint(a) != TransmissionRiskFingerprint(b) {
		t.Error("同集合不同順序 fingerprint 應一致")
	}
	// label 變動不影響（僅雜湊 key）
	c := []RiskItem{{Key: RiskRDPIgnoreCert, Label: "改了說明"}, {Key: RiskRDPSecurityBelowNLA}}
	if TransmissionRiskFingerprint(a) != TransmissionRiskFingerprint(c) {
		t.Error("label 變動不應改變 fingerprint")
	}
	// 集合變更即不符
	d := []RiskItem{{Key: RiskRDPIgnoreCert}}
	if TransmissionRiskFingerprint(a) == TransmissionRiskFingerprint(d) {
		t.Error("集合變更 fingerprint 應不同")
	}
}

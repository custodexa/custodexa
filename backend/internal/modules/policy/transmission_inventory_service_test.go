// 本檔刻意是**外部測試套件**（`package policy_test`）而非包內測試。
//
// 理由：清冊的 notify 通道走 `ChannelInventoryProvider`（拆 4.11 環時
// 宣告的窄介面），其唯一生產實作是 audit 的 `NotificationChannelService`。包內
// 測試（`package policy`）SHALL NOT import `internal/service`——後者 import 本包，
// 會構成「import cycle not allowed in test」。改用外部測試套件即可 import 兩者，
// **維持搬遷前的端到端斷言**（清冊計數確實對得上 audit 實作填的 TransmissionDeviation）；
// 若改以測試替身餵旗標，驗到的就只剩替身自己，是靜默的涵蓋面縮水。

package policy_test

import (
	"github.com/custodexa/backend/internal/modules/audit"
	"testing"

	"github.com/custodexa/backend/internal/modules/policy"

	"github.com/glebarez/sqlite"
	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// 下列三個助手在包內測試（transmission_policy_service_test.go）已有同名同義的
// 宣告，但外部測試套件看不到包內測試的宣告，故在此保留一份（實作逐行相同）。
func ldapRiskProvider(view policy.LDAPRiskView) func() policy.LDAPRiskResult {
	return func() policy.LDAPRiskResult {
		return policy.LDAPRiskResult{State: policy.LDAPResolveOK, View: view}
	}
}

func ldapRiskProviderState(state policy.LDAPResolveState) func() policy.LDAPRiskResult {
	return func() policy.LDAPRiskResult {
		return policy.LDAPRiskResult{State: state}
	}
}

func riskKeys(risks []policy.RiskItem) []string {
	out := make([]string, 0, len(risks))
	for _, r := range risks {
		out = append(out, r.Key)
	}
	return out
}

func setupInventorySvc(t *testing.T, ldapProvider func() policy.LDAPRiskResult) (*policy.TransmissionInventoryService, *policy.SecurityPolicyService, *gorm.DB) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	if err := db.AutoMigrate(&model.Asset{}, &model.AssetGroup{}, &model.AssetNode{}, &model.SecurityPolicy{},
		&model.SyslogSetting{}, &model.NotificationChannel{}, &model.AuditLog{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	policies := policy.NewSecurityPolicyService(db)
	tp := policy.NewTransmissionPolicyService(policies, ldapProvider)
	channels := audit.NewNotificationChannelService(db, nil)
	channels.SetTransmissionPolicy(tp)
	return policy.NewTransmissionInventoryService(db, tp, channels), policies, db
}

func channelOf(t *testing.T, inv *policy.TransmissionInventory, name string) policy.InventoryChannel {
	t.Helper()
	for _, ch := range inv.Channels {
		if ch.Channel == name {
			return ch
		}
	}
	t.Fatalf("清冊缺 %s 通道", name)
	return policy.InventoryChannel{}
}

func TestInventoryAggregatesAssets(t *testing.T) {
	svc, _, db := setupInventorySvc(t, ldapRiskProvider(policy.LDAPRiskView{Enabled: true, URL: "ldap://dir:389"}))

	assets := []model.Asset{
		{Name: "s1", Protocol: model.ProtocolSSH, Host: "h", Port: 22, CreatedBy: 1},
		{Name: "r1", Protocol: model.ProtocolRDP, Host: "h", Port: 3389, CreatedBy: 1},
		{Name: "r2", Protocol: model.ProtocolRDP, Host: "h", Port: 3389, CreatedBy: 1,
			RDPSecurity: model.RDPSecurityNLA, RDPVerifyCert: true},
		{Name: "v1", Protocol: model.ProtocolVNC, Host: "h", Port: 5900, CreatedBy: 1},
		{Name: "d1", Protocol: model.ProtocolMySQL, Host: "h", Port: 3306, CreatedBy: 1},
		{Name: "d2", Protocol: model.ProtocolPostgres, Host: "h", Port: 5432, CreatedBy: 1, DBTLSMode: "verify-full"},
		{Name: "d3", Protocol: model.ProtocolRedis, Host: "h", Port: 6379, CreatedBy: 1, DBTLSMode: "disable"},
	}
	for i := range assets {
		if err := db.Create(&assets[i]).Error; err != nil {
			t.Fatalf("seed asset: %v", err)
		}
	}

	inv, err := svc.Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	ssh := channelOf(t, inv, "ssh")
	if ssh.TotalCount != 1 || ssh.AtRiskCount != 0 {
		t.Errorf("ssh = %+v, want total 1 / at-risk 0", ssh)
	}

	rdp := channelOf(t, inv, policy.TransportChannelRDP)
	if rdp.TotalCount != 2 || rdp.AtRiskCount != 1 {
		t.Errorf("rdp total/at-risk = %d/%d, want 2/1", rdp.TotalCount, rdp.AtRiskCount)
	}
	if rdp.Detail["security=any,verify_cert=false"] != 1 || rdp.Detail["security=nla,verify_cert=true"] != 1 {
		t.Errorf("rdp detail = %v", rdp.Detail)
	}
	if rdp.StrictPreflight == "" {
		t.Error("rdp 有風險資產應附 strict 預檢")
	}

	vnc := channelOf(t, inv, policy.TransportChannelVNC)
	if vnc.TotalCount != 1 || vnc.AtRiskCount != 1 {
		t.Errorf("vnc total/at-risk = %d/%d, want 1/1（恆命中）", vnc.TotalCount, vnc.AtRiskCount)
	}

	dbCh := channelOf(t, inv, policy.TransportChannelDB)
	if dbCh.TotalCount != 3 || dbCh.AtRiskCount != 2 {
		t.Errorf("db total/at-risk = %d/%d, want 3/2（未設定+disable）", dbCh.TotalCount, dbCh.AtRiskCount)
	}
	if dbCh.Detail["(未設定)"] != 1 || dbCh.Detail["disable"] != 1 || dbCh.Detail["verify-full"] != 1 {
		t.Errorf("db detail = %v", dbCh.Detail)
	}

	ldap := channelOf(t, inv, policy.TransportChannelLDAP)
	// Deployment 自設定遷入 DB 後為 false（改由身分管理 UI 維護，
	// 「部署方管理」徽章僅剩 nginx）；風險判定本身未變
	if ldap.Deployment || ldap.AtRiskCount != 1 || len(ldap.Risks) != 1 {
		t.Errorf("ldap = %+v, want 非部署層＋明文風險", ldap)
	}
	if ldap.StrictPreflight == "" {
		t.Error("ldap 不安全時應附「切 strict 將拒絕 LDAP 登入」預檢")
	}

	nginx := channelOf(t, inv, "nginx")
	if !nginx.Deployment || nginx.Note == "" {
		t.Errorf("nginx 應標部署方管理, got %+v", nginx)
	}
}

func TestInventorySyslogAndNotifyStates(t *testing.T) {
	svc, _, db := setupInventorySvc(t, nil)

	// 未設定 syslog、無通知通道
	inv, err := svc.Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if ch := channelOf(t, inv, policy.TransportChannelSyslog); ch.TotalCount != 0 || ch.AtRiskCount != 0 {
		t.Errorf("未設定 syslog = %+v", ch)
	}
	if ch := channelOf(t, inv, policy.TransportChannelNotify); ch.TotalCount != 0 {
		t.Errorf("無通知通道 = %+v", ch)
	}

	// 啟用 UDP 轉發＋一 http 一 https 通道
	if err := db.Create(&model.SyslogSetting{ID: 1, Enabled: true, Host: "log", Port: 514, Protocol: model.SyslogProtocolUDP}).Error; err != nil {
		t.Fatal(err)
	}
	for _, ch := range []model.NotificationChannel{
		{Name: "plain", Type: "webhook", URL: "http://hook/x", Enabled: true},
		{Name: "safe", Type: "webhook", URL: "https://hook/x", Enabled: true},
	} {
		c := ch
		if err := db.Create(&c).Error; err != nil {
			t.Fatal(err)
		}
	}

	inv, err = svc.Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if ch := channelOf(t, inv, policy.TransportChannelSyslog); ch.AtRiskCount != 1 || len(ch.Risks) != 1 {
		t.Errorf("UDP syslog = %+v, want 偏離 1", ch)
	}
	if ch := channelOf(t, inv, policy.TransportChannelNotify); ch.TotalCount != 2 || ch.AtRiskCount != 1 {
		t.Errorf("notify total/at-risk = %d/%d, want 2/1", ch.TotalCount, ch.AtRiskCount)
	}
}

// TestInventoryDisplayCodes 驗證 i18n 顯示碼與 count 來源：
// note_code/preflight_code 正確、preflight count 逐碼來源（RDP/DB=AtRiskCount、VNC=total）、
// detail_codes 用機器鍵 unset（非中文）、syslog channel 帶 display_params.protocol。
func TestInventoryDisplayCodes(t *testing.T) {
	svc, _, db := setupInventorySvc(t, ldapRiskProvider(policy.LDAPRiskView{Enabled: true, URL: "ldap://dir:389"}))

	assets := []model.Asset{
		{Name: "r1", Protocol: model.ProtocolRDP, Host: "h", Port: 3389, CreatedBy: 1},
		{Name: "r2", Protocol: model.ProtocolRDP, Host: "h", Port: 3389, CreatedBy: 1,
			RDPSecurity: model.RDPSecurityNLA, RDPVerifyCert: true},
		{Name: "v1", Protocol: model.ProtocolVNC, Host: "h", Port: 5900, CreatedBy: 1},
		{Name: "d1", Protocol: model.ProtocolMySQL, Host: "h", Port: 3306, CreatedBy: 1},
		{Name: "d2", Protocol: model.ProtocolRedis, Host: "h", Port: 6379, CreatedBy: 1, DBTLSMode: "disable"},
	}
	for i := range assets {
		if err := db.Create(&assets[i]).Error; err != nil {
			t.Fatalf("seed asset: %v", err)
		}
	}
	if err := db.Create(&model.SyslogSetting{ID: 1, Enabled: true, Host: "log", Port: 514, Protocol: model.SyslogProtocolUDP}).Error; err != nil {
		t.Fatal(err)
	}

	inv, err := svc.Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	intParam := func(ch policy.InventoryChannel, key string) int64 {
		v, ok := ch.PreflightParams[key]
		if !ok {
			t.Fatalf("%s preflight_params 缺 %q: %+v", ch.Channel, key, ch.PreflightParams)
		}
		n, ok := v.(int64)
		if !ok {
			t.Fatalf("%s preflight_params[%q] 型別 %T 非 int64（count 須整數）", ch.Channel, key, v)
		}
		return n
	}

	// note code
	if ssh := channelOf(t, inv, "ssh"); ssh.NoteCode != "ssh_encrypted" {
		t.Errorf("ssh note_code = %q, want ssh_encrypted", ssh.NoteCode)
	}
	if nginx := channelOf(t, inv, "nginx"); nginx.NoteCode != "nginx_deploy_managed" {
		t.Errorf("nginx note_code = %q", nginx.NoteCode)
	}
	if ldap := channelOf(t, inv, policy.TransportChannelLDAP); ldap.NoteCode != "ldap_ui_managed" || ldap.PreflightCode != "ldap_reject" {
		t.Errorf("ldap codes = %q/%q", ldap.NoteCode, ldap.PreflightCode)
	}

	// preflight code + count 來源
	rdp := channelOf(t, inv, policy.TransportChannelRDP)
	if rdp.PreflightCode != "rdp_reject" || intParam(rdp, "n") != rdp.AtRiskCount {
		t.Errorf("rdp preflight = %q count=%d, want rdp_reject count=AtRiskCount(%d)", rdp.PreflightCode, intParam(rdp, "n"), rdp.AtRiskCount)
	}
	vnc := channelOf(t, inv, policy.TransportChannelVNC)
	if vnc.PreflightCode != "vnc_reject" || intParam(vnc, "n") != vnc.TotalCount {
		t.Errorf("vnc preflight = %q count=%d, want vnc_reject count=total(%d)", vnc.PreflightCode, intParam(vnc, "n"), vnc.TotalCount)
	}
	dbCh := channelOf(t, inv, policy.TransportChannelDB)
	if dbCh.PreflightCode != "db_reject" || intParam(dbCh, "n") != dbCh.AtRiskCount {
		t.Errorf("db preflight = %q count=%d, want db_reject count=AtRiskCount(%d)", dbCh.PreflightCode, intParam(dbCh, "n"), dbCh.AtRiskCount)
	}

	// detail_codes 用機器鍵 unset（非中文），legacy detail 仍有中文
	if dbCh.DetailCodes["unset"] != 1 || dbCh.DetailCodes["disable"] != 1 {
		t.Errorf("db detail_codes = %v, want unset/disable 機器鍵", dbCh.DetailCodes)
	}
	if dbCh.Detail["(未設定)"] != 1 {
		t.Errorf("db legacy detail 應保留中文 (未設定): %v", dbCh.Detail)
	}

	// syslog channel 帶 display_params.protocol（供清冊 risk label 查譯）
	syslog := channelOf(t, inv, policy.TransportChannelSyslog)
	if syslog.NoteCode != "syslog_protocol" {
		t.Errorf("syslog note_code = %q, want syslog_protocol", syslog.NoteCode)
	}
	if p, _ := syslog.NoteParams["protocol"].(string); p != model.SyslogProtocolUDP {
		t.Errorf("syslog note_params.protocol = %q, want %q", p, model.SyslogProtocolUDP)
	}
	if p, _ := syslog.DisplayParams["protocol"].(string); p != model.SyslogProtocolUDP {
		t.Errorf("syslog display_params.protocol = %q, want %q", p, model.SyslogProtocolUDP)
	}
}

func TestInventoryReflectsPolicyLevels(t *testing.T) {
	svc, policies, _ := setupInventorySvc(t, nil)
	policies.Update(policy.PolicyTransportRDPLevel, policy.TransportLevelStrict, "admin")

	inv, err := svc.Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if ch := channelOf(t, inv, policy.TransportChannelRDP); ch.Level != policy.TransportLevelStrict {
		t.Errorf("rdp level = %q, want strict", ch.Level)
	}
	if ch := channelOf(t, inv, policy.TransportChannelVNC); ch.Level != policy.TransportLevelOff {
		t.Errorf("vnc level = %q, want off", ch.Level)
	}
}

// TestInventoryLDAPResolveStates 清冊 LDAP 列的三態呈現。
//
// **故障必須有專屬狀態**：DEK 事故下若清冊顯示「未啟用」而設定頁顯示「已啟用」，
// 兩個管理面互相打臉，管理員會去找「誰把 LDAP 關掉了」而真因在金鑰。
// 另釘住 Deployment 恆為 false——設定改由身分管理 UI 維護，「部署方管理」
// （無設定開關）語義已退場
func TestInventoryLDAPResolveStates(t *testing.T) {
	cases := []struct {
		name     string
		provider func() policy.LDAPRiskResult
		wantNote string
		wantRisk int
	}{
		{"未接目錄服務", nil, "ldap_disabled_ui_managed", 0},
		{"未設定", ldapRiskProviderState(policy.LDAPResolveUnconfigured), "ldap_disabled_ui_managed", 0},
		{"已設定但停用", ldapRiskProvider(policy.LDAPRiskView{Enabled: false, URL: "ldap://dir:389"}), "ldap_disabled_ui_managed", 0},
		{"啟用且明文", ldapRiskProvider(policy.LDAPRiskView{Enabled: true, URL: "ldap://dir:389"}), "ldap_ui_managed", 1},
		{"啟用且 ldaps", ldapRiskProvider(policy.LDAPRiskView{Enabled: true, URL: "ldaps://dir:636"}), "ldap_ui_managed", 0},
		{"讀取失敗", ldapRiskProviderState(policy.LDAPResolveFailed), "ldap_resolve_failed", 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			svc, _, _ := setupInventorySvc(t, c.provider)
			inv, err := svc.Build()
			if err != nil {
				t.Fatalf("Build: %v", err)
			}
			ch := channelOf(t, inv, policy.TransportChannelLDAP)
			if ch.NoteCode != c.wantNote {
				t.Errorf("note_code = %q, want %q", ch.NoteCode, c.wantNote)
			}
			if len(ch.Risks) != c.wantRisk {
				t.Errorf("風險項 = %v, want %d 筆", riskKeys(ch.Risks), c.wantRisk)
			}
			if ch.Deployment {
				t.Error("LDAP 列不應再標示為部署層設定（該徽章僅剩 nginx）")
			}
		})
	}
}

// TestInventoryDeploymentBadgeOnlyNginx 「部署方管理」徽章的唯一持有者是 nginx：
// LDAP 退出後若日後有人再把某通道標成部署層，
// 本格會要求他顯式改這裡
func TestInventoryDeploymentBadgeOnlyNginx(t *testing.T) {
	svc, _, _ := setupInventorySvc(t, ldapRiskProvider(policy.LDAPRiskView{Enabled: true, URL: "ldap://dir:389"}))
	inv, err := svc.Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	var deployment []string
	for _, ch := range inv.Channels {
		if ch.Deployment {
			deployment = append(deployment, ch.Channel)
		}
	}
	if len(deployment) != 1 || deployment[0] != "nginx" {
		t.Errorf("標示部署方管理的通道 = %v, want [nginx]", deployment)
	}
}

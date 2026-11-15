package audit

import (
	"sort"
	"strings"
	"testing"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit/port"
	"github.com/custodexa/backend/internal/notifycat"
	"gorm.io/gorm"
)

// frozenSystemAlertTable 目錄的凍結表：鍵 → 分組、預設分級。
// 目錄登錄必須與這張表逐鍵相等；新增類型要同時改登錄、出站通知規格、三語文案與本表。
var frozenSystemAlertTable = map[port.SystemAlertType][2]string{
	port.SystemAlertAssetAddressChanged:          {"address_transport", "high"},
	port.SystemAlertTransportVerificationRelaxed: {"address_transport", "high"},
	port.SystemAlertAccessPolicyRelaxed:          {"address_transport", "high"},
	port.SystemAlertHostKeyMismatch:              {"address_transport", "high"},
	port.SystemAlertHostKeyRecordChanged:         {"address_transport", "medium"},
	port.SystemAlertCustomSecretUsed:             {"secret", "high"},
	port.SystemAlertIdentitySourceChanged:        {"identity_privilege", "high"},
	port.SystemAlertSecurityAdminAccountOperated: {"identity_privilege", "high"},
	port.SystemAlertSelfPrivilegeIncreased:       {"identity_privilege", "high"},
	port.SystemAlertSelfPrivilegeDecreased:       {"identity_privilege", "low"},
	port.SystemAlertManagementRoleGranted:        {"identity_privilege", "medium"},
	port.SystemAlertRetentionShortened:           {"security_settings", "high"},
	port.SystemAlertOffsiteOrSyslogChanged:       {"security_settings", "high"},
	port.SystemAlertKeyTopologyChanged:           {"security_settings", "high"},
	port.SystemAlertRecordingFailcloseDisabled:   {"security_settings", "high"},
	port.SystemAlertRecordingDeleted:             {"security_settings", "high"},
	port.SystemAlertMappingRevalidationRelaxed:   {"security_settings", "high"},
	port.SystemAlertNotificationChannelChanged:   {"notification", "high"},
	port.SystemAlertConcurrentInstanceDetected:   {"security_settings", "high"},
	port.SystemAlertUnmanagedPrivilegedAccount:   {"identity_privilege", "high"},
	port.SystemAlertPrivilegedAPITokenCreated:    {"identity_privilege", "high"},
	port.SystemAlertAPITokenCredentialAttached:   {"identity_privilege", "medium"},
}

// nonSecretParamNames 名稱含秘密字樣但值不是秘密的參數：逐一列出並寫明理由，不放寬字樣判準本身。
var nonSecretParamNames = map[string]bool{
	// API token 的顯示名稱（使用者自訂的標籤），不是 token 明文或雜湊
	"token_name": true,
}

// sampleSystemAlertParams 依宣告為每個參數造一個合法值（可選參數也填，讓模板的可選段都走一遍）。
func sampleSystemAlertParams(def SystemAlertTypeDef) map[string]string {
	out := map[string]string{}
	for _, p := range def.Params {
		switch p.Kind {
		case SystemAlertParamEnum:
			out[p.Name] = p.Enum[0]
		case SystemAlertParamInt:
			out[p.Name] = "3"
		case SystemAlertParamTokens:
			out[p.Name] = "host,port"
		default:
			out[p.Name] = "sample"
		}
	}
	return out
}

func TestSystemAlertCatalogRegistry(t *testing.T) {
	cat := SystemAlertCatalog()
	if len(cat) != len(frozenSystemAlertTable) {
		t.Fatalf("目錄 %d 種，凍結表 %d 種", len(cat), len(frozenSystemAlertTable))
	}
	groups := map[SystemAlertGroup]int{}
	seen := map[port.SystemAlertType]bool{}
	for _, d := range cat {
		if seen[d.Type] {
			t.Fatalf("類型 %s 重複登錄", d.Type)
		}
		seen[d.Type] = true
		want, ok := frozenSystemAlertTable[d.Type]
		if !ok {
			t.Fatalf("目錄有凍結表沒有的類型 %s", d.Type)
		}
		if string(d.Group) != want[0] || d.DefaultSeverity != want[1] {
			t.Errorf("%s 分組或預設分級與凍結表不符: %s/%s vs %v", d.Type, d.Group, d.DefaultSeverity, want)
		}
		groups[d.Group]++
		if d.SystemActor != (d.Type == port.SystemAlertConcurrentInstanceDetected) {
			t.Errorf("%s 的 SystemActor 旗標為 %v：只有 concurrent_instance_detected 可由系統主體產生", d.Type, d.SystemActor)
		}
		if len(d.Targets) == 0 {
			t.Errorf("%s 沒有宣告目標種類", d.Type)
		}
		// 宣告參數沒有秘密型：名稱帶 password 之類字樣者只能是布林（例如「綁定密碼已變更」）。
		for _, p := range d.Params {
			lower := strings.ToLower(p.Name)
			for _, bad := range []string{"password", "secret", "token", "private_key"} {
				isBool := p.Kind == SystemAlertParamEnum && strings.Join(p.Enum, ",") == "true,false"
				if strings.Contains(lower, bad) && !isBool && !nonSecretParamNames[p.Name] {
					t.Errorf("%s 的參數 %s 看起來是秘密型", d.Type, p.Name)
				}
			}
			if p.Kind == SystemAlertParamEnum && len(p.Enum) == 0 {
				t.Errorf("%s 的 enum 參數 %s 沒有允許清單", d.Type, p.Name)
			}
		}
	}
	if groups["address_transport"] != 5 || groups["secret"] != 1 || groups["identity_privilege"] != 8 ||
		groups["security_settings"] != 7 || groups["notification"] != 1 {
		t.Errorf("分組計數不符: %v", groups)
	}
	// 預設分級的語義：增高、減低、管理類發放中。
	for key, sev := range map[port.SystemAlertType]string{
		port.SystemAlertSelfPrivilegeIncreased: model.AlertSeverityHigh,
		port.SystemAlertSelfPrivilegeDecreased: model.AlertSeverityLow,
		port.SystemAlertManagementRoleGranted:  model.AlertSeverityMedium,
		port.SystemAlertHostKeyRecordChanged:   model.AlertSeverityMedium,
		// 以 API token 掛載既有憑證：預設中，可由管理者覆寫
		port.SystemAlertAPITokenCredentialAttached: model.AlertSeverityMedium,
	} {
		if d, _ := LookupSystemAlertType(key); d.DefaultSeverity != sev {
			t.Errorf("%s 預設分級 %s，應為 %s", key, d.DefaultSeverity, sev)
		}
	}

	// 出站通知規格：每個類型都有事件，參數＝目錄宣告＋actor＋severity；三語都能渲染且不是降級文案。
	events := map[string]bool{}
	for _, ev := range notifycat.Events() {
		events[string(ev)] = true
	}
	for _, d := range cat {
		ev, ok := notifycat.SystemAlertEvent(string(d.Type))
		if !ok || !events[string(ev)] {
			t.Fatalf("%s 沒有出站通知事件規格", d.Type)
		}
		spec, _ := notifycat.Spec(ev)
		var got, want []string
		for _, p := range spec.Params {
			if p.Name != "actor" && p.Name != "severity" {
				got = append(got, p.Name)
			}
		}
		for _, p := range d.Params {
			want = append(want, p.Name)
		}
		sort.Strings(got)
		sort.Strings(want)
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("%s 出站規格參數 %v 與目錄宣告 %v 不一致", d.Type, got, want)
		}
		params := sampleSystemAlertParams(d)
		params["actor"] = "alice"
		params["severity"] = d.DefaultSeverity
		clean, err := notifycat.Validate(ev, params)
		if err != nil {
			t.Fatalf("%s 範例參數未通過出站規格: %v", d.Type, err)
		}
		for _, lang := range notifycat.SupportedLangs {
			title, text := notifycat.Render(lang, ev, clean)
			degradedTitle, _ := notifycat.RenderDegraded(lang, ev, clean)
			if title == "" || text == "" || title == degradedTitle || strings.ContainsAny(text, "{}") {
				t.Errorf("%s 在 %s 渲染異常: %q / %q", d.Type, lang, title, text)
			}
		}
	}
	// 有效分級＝覆寫或預設；覆寫只接受三值。
	db := setupSystemAlertDB(t)
	if err := db.Transaction(func(tx *gorm.DB) error {
		ch, err := SetSystemAlertSeverityInTx(tx, port.SystemAlertManagementRoleGranted, "low", 7)
		if err != nil || ch.Before != "medium" || ch.After != "low" {
			t.Fatalf("調整分級: %+v %v", ch, err)
		}
		if _, err := SetSystemAlertSeverityInTx(tx, port.SystemAlertManagementRoleGranted, "off", 7); err != ErrSystemAlertSeverityInvalid {
			t.Fatalf("非三值分級應被拒: %v", err)
		}
		if _, err := SetSystemAlertSeverityInTx(tx, "no_such_type", "low", 7); err != ErrSystemAlertTypeUnknown {
			t.Fatalf("未登錄類型應被拒: %v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	views, err := ListSystemAlertSeverities(db)
	if err != nil || len(views) != len(cat) {
		t.Fatalf("列表: %d %v", len(views), err)
	}
	for _, v := range views {
		wantEff, wantAdj := frozenSystemAlertTable[v.Type][1], false
		if v.Type == port.SystemAlertManagementRoleGranted {
			wantEff, wantAdj = "low", true
		}
		if v.Effective != wantEff || v.Adjusted != wantAdj {
			t.Errorf("%s 有效分級/已調整: %s/%v，應為 %s/%v", v.Type, v.Effective, v.Adjusted, wantEff, wantAdj)
		}
	}
}

// 未納管特權帳號告警的登入身分參數：專用帳號身分的值通過目錄驗證，未知值被擋。
func TestSystemAlertUnmanagedPrivilegedIdentityModes(t *testing.T) {
	mk := func(mode string) port.SystemAlertEvent {
		return port.SystemAlertEvent{
			Type:   port.SystemAlertUnmanagedPrivilegedAccount,
			Actor:  port.SystemAlertActor{UserID: 1, Username: "admin"},
			Target: port.SystemAlertTarget{Kind: port.SystemAlertTargetAsset, ID: "7"},
			Params: map[string]string{"new_count": "1", "identity_mode": mode},
		}
	}
	for _, m := range []string{"default_account", "executor"} {
		if _, err := validateSystemAlertEvent(mk(m)); err != nil {
			t.Fatalf("identity_mode=%s 應通過：%v", m, err)
		}
	}
	if _, err := validateSystemAlertEvent(mk("other")); err == nil {
		t.Fatal("未知的 identity_mode 應被擋")
	}
}

// TestSystemAlertCatalogCredentialAttachedEntries 以 API token 掛載既有憑證：入口值域與出站規格一致、
// 單筆與匯入兩種句型照核可的文案渲染、目標只接受資產或使用者、未知入口被擋。
func TestSystemAlertCatalogCredentialAttachedEntries(t *testing.T) {
	def, ok := LookupSystemAlertType(port.SystemAlertAPITokenCredentialAttached)
	if !ok {
		t.Fatal("類型未登錄")
	}
	var catalogEnum []string
	for _, p := range def.Params {
		if p.Name == "entry" {
			catalogEnum = p.Enum
		}
	}
	ev, _ := notifycat.SystemAlertEvent(string(def.Type))
	spec, _ := notifycat.Spec(ev)
	var wireEnum []string
	for _, p := range spec.Params {
		if p.Name == "entry" {
			wireEnum = p.Enum
		}
	}
	if strings.Join(catalogEnum, ",") != strings.Join(wireEnum, ",") ||
		strings.Join(catalogEnum, ",") != "asset_create,account_create,bind,rebind,import" {
		t.Fatalf("入口值域不一致：目錄 %v、出站 %v", catalogEnum, wireEnum)
	}

	single := map[string]string{"actor": "ops-chen", "severity": "medium", "token_name": "tf-prod-apply",
		"entry": "asset_create", "credential_name": "prod-linux-root", "asset_name": "web-21"}
	clean, err := notifycat.Validate(ev, single)
	if err != nil {
		t.Fatalf("單筆參數未通過出站規格：%v", err)
	}
	// 分級短語沿用全站共用的分級詞庫
	sevZh := notifycat.Phrase("zh-TW", notifycat.LexiconSeverity, "medium")
	title, text := notifycat.Render("zh-TW", ev, clean)
	if title != "API token 掛載既有憑證" ||
		text != "ops-chen 以 API token「tf-prod-apply」把憑證「prod-linux-root」掛到資產「web-21」（建立資產時引用；分級："+sevZh+"）。" {
		t.Errorf("單筆渲染：%q / %q", title, text)
	}
	imp := map[string]string{"actor": "ops-chen", "severity": "medium", "token_name": "tf-prod-apply",
		"entry": "import", "asset_count": "6", "credential_count": "2"}
	clean, err = notifycat.Validate(ev, imp)
	if err != nil {
		t.Fatalf("匯入參數未通過出站規格：%v", err)
	}
	_, text = notifycat.Render("zh-TW", ev, clean)
	if text != "ops-chen 以 API token「tf-prod-apply」匯入資產，其中 6 台引用了 2 筆系統已保存的憑證（分級："+sevZh+"）。" {
		t.Errorf("匯入渲染：%q", text)
	}
	for _, lang := range notifycat.SupportedLangs {
		for _, entry := range catalogEnum {
			p := map[string]string{"actor": "a", "severity": "medium", "token_name": "t", "entry": entry,
				"credential_name": "c", "asset_name": "n", "asset_count": "1", "credential_count": "1"}
			_, text := notifycat.Render(lang, ev, p)
			if strings.ContainsAny(text, "{}") {
				t.Errorf("%s/%s 渲染含未代入的佔位符：%q", lang, entry, text)
			}
			// 單筆四種入口在括號內寫出掛載方式的短語（不是機器碼）
			if entry != "import" && !strings.Contains(text, notifycat.Phrase(lang, notifycat.LexiconCredentialAttachEntry, entry)) {
				t.Errorf("%s/%s 渲染缺掛載方式短語：%q", lang, entry, text)
			}
		}
	}

	mk := func(kind port.SystemAlertTargetKind, entry string) port.SystemAlertEvent {
		return port.SystemAlertEvent{
			Type: port.SystemAlertAPITokenCredentialAttached, Actor: port.SystemAlertActor{UserID: 1, Username: "ops"},
			Target: port.SystemAlertTarget{Kind: kind, ID: "7"},
			Params: map[string]string{"token_name": "t", "entry": entry, "credential_name": "c", "asset_name": "n"},
		}
	}
	for _, k := range []port.SystemAlertTargetKind{port.SystemAlertTargetAsset, port.SystemAlertTargetUser} {
		if _, err := validateSystemAlertEvent(mk(k, "bind")); err != nil {
			t.Errorf("目標 %s 應通過：%v", k, err)
		}
	}
	if _, err := validateSystemAlertEvent(mk(port.SystemAlertTargetCredential, "bind")); err == nil {
		t.Error("目標為憑證應被擋")
	}
	if _, err := validateSystemAlertEvent(mk(port.SystemAlertTargetAsset, "detach")); err == nil {
		t.Error("未知入口應被擋")
	}
}

package identity

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

// OIDC provider CRUD 的規格對照測試（openspec/specs/oidc-auth/spec.md）。
//
// 每個測試對照一個 spec Scenario（註解標明 Scenario 名稱；**刻意不寫 spec 行號**
// ——Scenario 名稱穩定，行號會隨 spec 增修整批偏移，是會靜默失準的脆弱資訊），
// 斷言寫在 spec 的字面要求上而非實作細節；實作與 spec 不符者以 t.Skip 標記，
// 不遷就實作改寫斷言。
//
// fixture 沿用 oidc_flow_test.go 的 setupOIDCEnv（sqlite :memory: 已設
// SetMaxOpenConns(1)，避免連線池各拿到不同的空白記憶體庫）。

// newProviderSvcFor 以指定的部署層條件重建 provider 服務（共用同一 DB）。
//
// 部署層輸入（出站政策、專屬 issuer 宣告、對外基準網址）是建構參數而非可變狀態，
// 「宣告移除後行為如何改變」只能以重建服務模擬——這正是 spec 要求「不持久化
// issuer kind、每次現算」的觀測點
func newProviderSvcFor(db *gorm.DB, egress *OIDCEgressPolicy, dedicated []string, baseURL string) *OIDCProviderService {
	return NewOIDCProviderService(db, nil, egress, dedicated, baseURL)
}

// releaseEgress release 模式的出站政策：無任何 http 例外主機
func releaseEgress() *OIDCEgressPolicy { return &OIDCEgressPolicy{} }

// providerReq 一份可通過驗證的建立請求（預設 prebound_only、已啟用）
func providerReq(mutate func(*OIDCProviderRequest)) *OIDCProviderRequest {
	req := &OIDCProviderRequest{
		Name: "corp", Issuer: "https://idp.example.com", ClientID: "cid-1",
		ClientSecret: "s3cret-value", Scopes: "profile email",
		Enabled: boolPtr(true),
	}
	if mutate != nil {
		mutate(req)
	}
	return req
}

func mustCreateProvider(t *testing.T, svc *OIDCProviderService, req *OIDCProviderRequest) *OIDCProviderDTO {
	t.Helper()
	dto, err := svc.Create(req)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	return dto
}

// reloadProvider 直接自 DB 取回（繞過 DTO，用於斷言落庫狀態）
func reloadProvider(t *testing.T, db *gorm.DB, id uint) *model.OIDCProvider {
	t.Helper()
	var p model.OIDCProvider
	if err := db.Unscoped().First(&p, id).Error; err != nil {
		t.Fatalf("reload provider %d: %v", id, err)
	}
	return &p
}

// --- Requirement: OIDC provider 實例管理 ---

// Scenario: 多 provider 並存
func TestOIDCProviderMultipleInstancesCoexist(t *testing.T) {
	_, providers, _ := setupOIDCEnv(t)

	a := mustCreateProvider(t, providers, providerReq(func(r *OIDCProviderRequest) {
		r.Name = "Azure AD"
		r.Issuer = "https://login.microsoftonline.com/tenant-a/v2.0"
		r.ClientID = "cid-azure"
	}))
	b := mustCreateProvider(t, providers, providerReq(func(r *OIDCProviderRequest) {
		r.Name = "Okta"
		r.Issuer = "https://corp.okta.example.com"
		r.ClientID = "cid-okta"
	}))
	if a.ID == b.ID {
		t.Fatalf("兩個 provider 應各有識別碼，實得同值 %d", a.ID)
	}

	methods, err := providers.ListLoginMethods()
	if err != nil {
		t.Fatalf("ListLoginMethods: %v", err)
	}
	names := map[string]bool{}
	for _, m := range methods {
		names[m.Name] = true
	}
	// 「登入方法清單同時含兩者」——各自可獨立登入的部分由 oidc_callback_test.go 覆蓋
	if !names["Azure AD"] || !names["Okta"] {
		t.Errorf("登入方法清單應同時含兩個 provider，實得 %+v", methods)
	}
}

// Scenario: secret write-only（前半）
//
// 「回應不含 client_secret 的明文或密文」——以 DTO 的 JSON 序列化斷言，
// 使日後有人加欄位（例如為了 UI 顯示遮罩值而回傳密文）即轉紅
func TestOIDCProviderSecretNeverAppearsInReadResponses(t *testing.T) {
	_, providers, db := setupOIDCEnv(t)
	const plaintext = "top-secret-client-key"
	dto := mustCreateProvider(t, providers, providerReq(func(r *OIDCProviderRequest) {
		r.ClientSecret = plaintext
	}))
	if !dto.HasSecret {
		t.Error("已設定密鑰時 has_secret 應為 true（供 UI 提示「留空沿用」）")
	}

	stored := reloadProvider(t, db, dto.ID)
	list, err := providers.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	payloads := map[string]any{"detail": dto, "list": list}
	for name, v := range payloads {
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("marshal %s: %v", name, err)
		}
		body := string(raw)
		if strings.Contains(body, plaintext) {
			t.Errorf("%s 回應含 client_secret 明文: %s", name, body)
		}
		// 密文同樣不得外洩（密文可離線攻擊，且洩漏加密格式）
		if stored.ClientSecretEnc != "" && strings.Contains(body, stored.ClientSecretEnc) {
			t.Errorf("%s 回應含 client_secret 密文: %s", name, body)
		}
		var fields map[string]json.RawMessage
		if name == "detail" {
			if err := json.Unmarshal(raw, &fields); err != nil {
				t.Fatalf("unmarshal detail: %v", err)
			}
			for k := range fields {
				if strings.Contains(k, "secret") && k != "has_secret" {
					t.Errorf("DTO 不應有密鑰欄位 %q（僅允許 has_secret 布林旗標）", k)
				}
			}
		}
	}

	// 認證流程仍取得到明文（write-only 指的是對外讀取，非內部不可用）
	_, secret, err := providers.GetForAuth(dto.ID)
	if err != nil {
		t.Fatalf("GetForAuth: %v", err)
	}
	if secret != plaintext {
		t.Errorf("認證路徑取得的密鑰 = %q, want %q", secret, plaintext)
	}
}

// Scenario: secret write-only（後半：更新時未附新 secret 則既有值不變）
func TestOIDCProviderUpdateWithoutSecretKeepsExistingValue(t *testing.T) {
	_, providers, db := setupOIDCEnv(t)
	dto := mustCreateProvider(t, providers, providerReq(nil))
	before := reloadProvider(t, db, dto.ID)

	updated, err := providers.Update(dto.ID, &OIDCProviderRequest{Name: "corp-renamed"})
	if err != nil {
		t.Fatalf("僅改顯示名的更新應成功: %v", err)
	}
	if updated.Name != "corp-renamed" {
		t.Errorf("顯示名 = %q, want corp-renamed", updated.Name)
	}
	after := reloadProvider(t, db, dto.ID)
	if after.ClientSecretEnc != before.ClientSecretEnc {
		t.Errorf("未附新密鑰時既有值不得被覆寫: %q → %q", before.ClientSecretEnc, after.ClientSecretEnc)
	}
	if !updated.HasSecret {
		t.Error("沿用既有密鑰後 has_secret 仍應為 true")
	}
	// 未輪替密鑰即未發生「舊密鑰可能已洩漏」，不得推進世代（否則改個顯示名就把
	// 全部使用者踢下線）
	if after.AuthEpoch != before.AuthEpoch {
		t.Errorf("非輪替的更新不應推進世代: %d → %d", before.AuthEpoch, after.AuthEpoch)
	}
}

// Scenario: 身分域欄位後端不可變
//
// 「以 API 直接送出變更請求（繞過前端）」——本測試直接呼叫 service 層，
// 即前端停用輸入無法涵蓋的路徑
func TestOIDCProviderIdentityDomainImmutableAfterCreate(t *testing.T) {
	_, providers, db := setupOIDCEnv(t)
	dto := mustCreateProvider(t, providers, providerReq(nil))

	cases := map[string]*OIDCProviderRequest{
		"改 issuer":    {Name: "renamed", Issuer: "https://evil.example.com"},
		"改 client_id": {Name: "renamed", ClientID: "cid-other"},
		"兩者同改":        {Name: "renamed", Issuer: "https://evil.example.com", ClientID: "cid-other"},
	}
	for label, req := range cases {
		if _, err := providers.Update(dto.ID, req); !errors.Is(err, ErrOIDCImmutableField) {
			t.Errorf("%s → %v, want ErrOIDCImmutableField（對應 CodeValidationOIDCImmutableField）", label, err)
		}
		// 「設定不變」：連同一請求裡的顯示名也不得被套用（拒絕須發生在任何寫入之前）
		after := reloadProvider(t, db, dto.ID)
		if after.Issuer != "https://idp.example.com" || after.ClientID != "cid-1" || after.Name != "corp" {
			t.Errorf("%s 後設定被改動: issuer=%q client_id=%q name=%q",
				label, after.Issuer, after.ClientID, after.Name)
		}
	}

	// 送出與現值相同的身分域不算變更（前端一律回送完整表單，不得因此失敗）
	if _, err := providers.Update(dto.ID, &OIDCProviderRequest{
		Name: "corp2", Issuer: "https://idp.example.com", ClientID: "cid-1",
	}); err != nil {
		t.Errorf("送出同值身分域應被視為未變更: %v", err)
	}
}

// Requirement 散文：`(issuer, client_id)` SHALL 唯一
func TestOIDCProviderIdentityDomainMustBeUnique(t *testing.T) {
	_, providers, _ := setupOIDCEnv(t)
	mustCreateProvider(t, providers, providerReq(nil))

	_, err := providers.Create(providerReq(func(r *OIDCProviderRequest) { r.Name = "dup" }))
	if !errors.Is(err, ErrOIDCDuplicateIdentityDomain) {
		t.Errorf("重複身分域 → %v, want ErrOIDCDuplicateIdentityDomain（對應 CodeConflictOIDCIdentityDomain）", err)
	}

	// 同 issuer 不同 client_id 是不同身分域，應可並存（身分隔離的設定前提）
	if _, err := providers.Create(providerReq(func(r *OIDCProviderRequest) {
		r.Name = "second-app"
		r.ClientID = "cid-2"
	})); err != nil {
		t.Errorf("同 issuer 不同 client_id 應可並存: %v", err)
	}
}

// Scenario: 有身分關聯不可刪
func TestOIDCProviderDeleteRejectedWhenIdentitiesLinked(t *testing.T) {
	_, providers, db := setupOIDCEnv(t)
	dto := mustCreateProvider(t, providers, providerReq(nil))
	p := reloadProvider(t, db, dto.ID)
	seedIdentity(t, db, seedOIDCUser(t, db, "ext-user"), p, "sub-1")
	before := reloadProvider(t, db, dto.ID)

	if err := providers.Delete(dto.ID); !errors.Is(err, ErrOIDCProviderInUse) {
		t.Fatalf("有身分關聯的刪除 → %v, want ErrOIDCProviderInUse（對應 CodeConflictOIDCProviderInUse）", err)
	}
	// 「資料不變」：provider 未被軟刪、世代未被推進、身分關聯仍在
	after := reloadProvider(t, db, dto.ID)
	if after.DeletedAt.Valid {
		t.Error("被拒的刪除不得留下軟刪標記")
	}
	if after.AuthEpoch != before.AuthEpoch {
		t.Errorf("被拒的刪除不得推進世代: %d → %d", before.AuthEpoch, after.AuthEpoch)
	}
	var identities int64
	db.Model(&model.UserExternalIdentity{}).Where("provider_id = ?", dto.ID).Count(&identities)
	if identities != 1 {
		t.Errorf("身分關聯數 = %d, want 1", identities)
	}

	// 「提示改用停用」需要具體影響面：管理端可見待解綁的身分數
	list, err := providers.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	for _, d := range list {
		if d.ID == dto.ID && d.IdentityCount != 1 {
			t.Errorf("identity_count = %d, want 1（刪除被拒時管理者需知道要解綁幾筆）", d.IdentityCount)
		}
	}
}

// Requirement 散文：provider SHALL NOT 被硬刪除、識別碼 SHALL NOT 被重用；
// 刪除 SHALL 先執行與停用相同的全套失效動作
func TestOIDCProviderDeleteIsSoftAndAdvancesEpoch(t *testing.T) {
	_, providers, db := setupOIDCEnv(t)
	dto := mustCreateProvider(t, providers, providerReq(nil))
	before := reloadProvider(t, db, dto.ID)

	if err := providers.Delete(dto.ID); err != nil {
		t.Fatalf("無身分關聯的刪除應成功: %v", err)
	}
	// 軟刪：列仍在（識別碼因而不會被新 provider 重用）
	deleted := reloadProvider(t, db, dto.ID)
	if !deleted.DeletedAt.Valid {
		t.Error("刪除應為軟刪（列須保留，使識別碼不被重用）")
	}
	// 刪除亦推進世代：否則既建立的協議連線會失去按 provider 收線的途徑
	if deleted.AuthEpoch <= before.AuthEpoch {
		t.Errorf("刪除應推進世代: %d → %d", before.AuthEpoch, deleted.AuthEpoch)
	}
	list, err := providers.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	for _, d := range list {
		if d.ID == dto.ID {
			t.Errorf("已刪除的 provider 不應出現於管理清單: %+v", d)
		}
	}
}

func TestOIDCProviderUnknownIDIsNotFound(t *testing.T) {
	_, providers, _ := setupOIDCEnv(t)
	if _, err := providers.Update(4242, &OIDCProviderRequest{Name: "x"}); !errors.Is(err, ErrOIDCProviderNotFound) {
		t.Errorf("更新不存在的 provider → %v, want ErrOIDCProviderNotFound", err)
	}
	if err := providers.Delete(4242); !errors.Is(err, ErrOIDCProviderNotFound) {
		t.Errorf("刪除不存在的 provider → %v, want ErrOIDCProviderNotFound", err)
	}
}

// --- Requirement: OIDC 登入流程與驗證強度（設定階段的部分） ---

// Scenario: 未知 scope 於設定時拒絕
func TestOIDCProviderRejectsUnknownScope(t *testing.T) {
	_, providers, db := setupOIDCEnv(t)

	// offline_access 刻意不在允許清單：v1 不保存 IdP refresh token，索取它只擴大暴露面
	for _, scope := range []string{"offline_access", "groups", "profile offline_access"} {
		if _, err := providers.Create(providerReq(func(r *OIDCProviderRequest) {
			r.Scopes = scope
		})); !errors.Is(err, ErrOIDCUnknownScope) {
			t.Errorf("scope=%q → %v, want ErrOIDCUnknownScope（對應 CodeValidationOIDCScope）", scope, err)
		}
	}
	var stored int64
	db.Model(&model.OIDCProvider{}).Count(&stored)
	if stored != 0 {
		t.Errorf("被拒的設定不得落庫，實得 %d 筆", stored)
	}

	// 允許清單內的 scope 通過，且 openid 恆被注入
	dto := mustCreateProvider(t, providers, providerReq(func(r *OIDCProviderRequest) {
		r.Scopes = "email"
	}))
	if !strings.Contains(dto.Scopes, "openid") {
		t.Errorf("scope 恆含 openid，實得 %q", dto.Scopes)
	}

	// 更新路徑同樣受檢（否則建立時擋住、更新時放行）
	if _, err := providers.Update(dto.ID, &OIDCProviderRequest{Scopes: "offline_access"}); !errors.Is(err, ErrOIDCUnknownScope) {
		t.Errorf("更新時的未知 scope → %v, want ErrOIDCUnknownScope", err)
	}
}

// Scenario: release 模式拒 http issuer
//
// release 模式的組態即「出站政策無任何 http 例外主機」（cmd/server/stage2.go
// 只在非 release 填入 AllowInsecureHosts），本測試以該組態驅動 service 層
func TestOIDCProviderReleaseModeRejectsHTTPIssuer(t *testing.T) {
	_, _, db := setupOIDCEnv(t)
	release := newProviderSvcFor(db, releaseEgress(), nil, "https://bastion.example.com")

	if _, err := release.Create(providerReq(func(r *OIDCProviderRequest) {
		r.Issuer = "http://idp.example.com"
	})); !errors.Is(err, ErrOIDCIssuerScheme) {
		t.Errorf("release 模式的 http issuer → %v, want ErrOIDCIssuerScheme（對應 CodeValidationOIDCIssuer）", err)
	}
	// 即使主機名列於內部允許清單，release 仍無例外
	releaseWithInternal := newProviderSvcFor(db,
		&OIDCEgressPolicy{AllowedInternalHosts: []string{"idp.internal"}}, nil, "https://bastion.example.com")
	if _, err := releaseWithInternal.Create(providerReq(func(r *OIDCProviderRequest) {
		r.Issuer = "http://idp.internal"
	})); !errors.Is(err, ErrOIDCIssuerScheme) {
		t.Errorf("release 模式對內部主機亦無 http 例外 → %v, want ErrOIDCIssuerScheme", err)
	}

	// 非 release 且列於 dev 靶機清單者為唯一例外
	dev := newProviderSvcFor(db, &OIDCEgressPolicy{AllowInsecureHosts: []string{"127.0.0.1"}},
		nil, "https://bastion.example.com")
	if _, err := dev.Create(providerReq(func(r *OIDCProviderRequest) {
		r.Issuer = "http://127.0.0.1:5556/dex"
	})); err != nil {
		t.Errorf("非 release 的 dev 靶機 http issuer 應被接受: %v", err)
	}
}

// Requirement 散文：issuer 形狀（不得帶使用者資訊／查詢字串／片段）
func TestOIDCProviderRejectsMalformedIssuer(t *testing.T) {
	_, providers, _ := setupOIDCEnv(t)
	shapes := map[string]string{
		"帶 userinfo": "https://user:pw@idp.example.com",
		"帶 query":    "https://idp.example.com?tenant=a",
		"帶 fragment": "https://idp.example.com#frag",
		"無主機":        "https:///path",
	}
	for label, issuer := range shapes {
		_, err := providers.Create(providerReq(func(r *OIDCProviderRequest) { r.Issuer = issuer }))
		if !errors.Is(err, ErrOIDCIssuerShape) {
			t.Errorf("%s (%q) → %v, want ErrOIDCIssuerShape", label, issuer, err)
		}
	}
	// 必填缺漏亦擋（身分域不可事後補，缺值建立等同建出無法修正的列）
	for label, req := range map[string]*OIDCProviderRequest{
		"缺 issuer":    providerReq(func(r *OIDCProviderRequest) { r.Issuer = "  " }),
		"缺 client_id": providerReq(func(r *OIDCProviderRequest) { r.ClientID = "" }),
	} {
		if _, err := providers.Create(req); err == nil {
			t.Errorf("%s 應被拒絕", label)
		}
	}
}

// --- Requirement: 自動供應的准入控制（設定階段） ---

// Scenario: 預設不自動供應（設定面）
func TestOIDCProviderDefaultsToPreboundOnly(t *testing.T) {
	_, providers, _ := setupOIDCEnv(t)
	dto := mustCreateProvider(t, providers, providerReq(func(r *OIDCProviderRequest) {
		r.AdmissionMode = ""
	}))
	if dto.AdmissionMode != string(model.AdmissionPreboundOnly) {
		t.Errorf("預設 admission_mode = %q, want prebound_only（fail-close）", dto.AdmissionMode)
	}
}

// Scenario: 無規則的自動供應組態被拒
func TestOIDCProviderJITRequiresAdmissionRules(t *testing.T) {
	_, providers, db := setupOIDCEnv(t)

	for label, rules := range map[string]string{"空字串": "", "空物件": "{}"} {
		_, err := providers.Create(providerReq(func(r *OIDCProviderRequest) {
			r.AdmissionMode = string(model.AdmissionJITWithRules)
			r.AdmissionRules = rules
		}))
		if !errors.Is(err, ErrAdmissionEmptyRuleSet) {
			t.Errorf("自動供應＋%s規則 → %v, want ErrAdmissionEmptyRuleSet（對應 CodeValidationOIDCAdmissionRules）", label, err)
		}
	}
	var stored int64
	db.Model(&model.OIDCProvider{}).Count(&stored)
	if stored != 0 {
		t.Errorf("被拒的設定不得落庫，實得 %d 筆", stored)
	}

	// 更新路徑：既有 prebound_only（無規則）切換為自動供應時同樣須帶規則
	dto := mustCreateProvider(t, providers, providerReq(nil))
	if _, err := providers.Update(dto.ID, &OIDCProviderRequest{
		AdmissionMode: string(model.AdmissionJITWithRules),
	}); !errors.Is(err, ErrAdmissionEmptyRuleSet) {
		t.Errorf("更新為自動供應但無規則 → %v, want ErrAdmissionEmptyRuleSet", err)
	}
	if reloadProvider(t, db, dto.ID).AdmissionMode != model.AdmissionPreboundOnly {
		t.Error("被拒的更新不得改變 admission_mode")
	}
}

// Scenario: 未知規則鍵於設定時拒絕
func TestOIDCProviderRejectsUnknownAdmissionRuleKey(t *testing.T) {
	_, providers, db := setupOIDCEnv(t)
	// 「不得存入後於執行期被忽略」：一份看似有限制的組態靜默退化為無限制
	for _, rules := range []string{
		`{"groups":["admins"]}`,
		`{"hd":["corp.example"],"upn_suffix":["corp.example"]}`,
	} {
		if _, err := providers.Create(providerReq(func(r *OIDCProviderRequest) {
			r.AdmissionMode = string(model.AdmissionJITWithRules)
			r.AdmissionRules = rules
		})); !errors.Is(err, ErrAdmissionUnknownRule) {
			t.Errorf("rules=%s → %v, want ErrAdmissionUnknownRule", rules, err)
		}
	}
	var stored int64
	db.Model(&model.OIDCProvider{}).Count(&stored)
	if stored != 0 {
		t.Errorf("含未知規則鍵的設定不得落庫，實得 %d 筆", stored)
	}

	// spec 的「於設定時即拒絕」不以模式為條件：prebound_only 下存入的畸形規則
	// 會在日後切換為自動供應時才引爆，屆時已無設定階段可攔
	if _, err := providers.Create(providerReq(func(r *OIDCProviderRequest) {
		r.AdmissionMode = string(model.AdmissionPreboundOnly)
		r.AdmissionRules = `{"groups":["admins"]}`
	})); !errors.Is(err, ErrAdmissionUnknownRule) {
		t.Errorf("prebound_only 下的未知規則鍵 → %v, want ErrAdmissionUnknownRule", err)
	}
}

// Requirement 散文：管理者 SHALL 僅能收緊（標記為共用），SHALL NOT 放寬
func TestOIDCProviderAdminCanTightenToShared(t *testing.T) {
	_, _, db := setupOIDCEnv(t)
	const issuer = "https://corp.okta.example.com"
	svc := newProviderSvcFor(db, testEgress(), []string{issuer}, "https://bastion.example.com")
	dto := mustCreateProvider(t, svc, providerReq(func(r *OIDCProviderRequest) {
		r.Issuer = issuer
		r.AdmissionMode = string(model.AdmissionJITWithRules)
		r.AdmissionRules = `{"email_domain":["corp.example"],"email_verified":true}`
	}))

	// 收緊時一併補上組織歸屬規則：管理者收緊的優先序高於部署層專用宣告
	tightened, err := svc.Update(dto.ID, &OIDCProviderRequest{
		AdmissionRules: `{"hd":["corp.example"]}`,
		ForceShared:    boolPtr(true),
	})
	if err != nil {
		t.Fatalf("管理者收緊為共用應被允許: %v", err)
	}
	if tightened.IssuerKind != "shared" || tightened.IssuerKindSource != "admin_forced" {
		t.Errorf("收緊後 = %q/%q, want shared/admin_forced", tightened.IssuerKind, tightened.IssuerKindSource)
	}

	// 收緊後既有的「僅 email 網域」組態不得繼續有效：要嘛請求被拒，
	// 要嘛 fail-close 停止自動供應——不得留下「共用身分域＋僅 email 規則」仍在自動供應的狀態
	second := mustCreateProvider(t, svc, providerReq(func(r *OIDCProviderRequest) {
		r.Issuer = issuer
		r.ClientID = "cid-2"
		r.AdmissionMode = string(model.AdmissionJITWithRules)
		r.AdmissionRules = `{"email_domain":["corp.example"],"email_verified":true}`
	}))
	_, err = svc.Update(second.ID, &OIDCProviderRequest{ForceShared: boolPtr(true)})
	if err == nil {
		after := reloadProvider(t, db, second.ID)
		if after.AdmissionMode == model.AdmissionJITWithRules {
			t.Error("收緊為共用後不得維持「僅 email 網域規則」的自動供應（要求 fail-close）")
		}
	} else if !errors.Is(err, ErrAdmissionSharedNeedsOrgRule) {
		t.Errorf("收緊致規則不合規 → %v, want ErrAdmissionSharedNeedsOrgRule 或 fail-close 停用自動供應", err)
	}
}

// Scenario: 共用身分域拒絕僅 email 網域規則
//
// 未知 issuer 依固定優先序即視為共用（fail-close），故此處不需特意挑內建清單成員
func TestOIDCProviderSharedIssuerRejectsEmailOnlyRules(t *testing.T) {
	_, providers, _ := setupOIDCEnv(t)
	_, err := providers.Create(providerReq(func(r *OIDCProviderRequest) {
		r.AdmissionMode = string(model.AdmissionJITWithRules)
		r.AdmissionRules = `{"email_domain":["corp.example"],"email_verified":true}`
	}))
	if !errors.Is(err, ErrAdmissionSharedNeedsOrgRule) {
		t.Errorf("共用身分域＋僅 email 網域 → %v, want ErrAdmissionSharedNeedsOrgRule", err)
	}

	// 補上組織歸屬類規則即可通過
	if _, err := providers.Create(providerReq(func(r *OIDCProviderRequest) {
		r.AdmissionMode = string(model.AdmissionJITWithRules)
		r.AdmissionRules = `{"hd":["corp.example"],"email_domain":["corp.example"],"email_verified":true}`
	})); err != nil {
		t.Errorf("含組織歸屬規則的共用身分域組態應被接受: %v", err)
	}
}

// Requirement 散文：採用 email 類規則時 SHALL 同時要求 email 已驗證
func TestOIDCProviderEmailDomainRuleRequiresVerifiedFlag(t *testing.T) {
	_, _, db := setupOIDCEnv(t)
	// 專屬身分域才走得到這條檢查（共用身分域會先被組織歸屬規則擋下）
	svc := newProviderSvcFor(db, testEgress(), []string{"https://idp.example.com"}, "https://bastion.example.com")

	if _, err := svc.Create(providerReq(func(r *OIDCProviderRequest) {
		r.AdmissionMode = string(model.AdmissionJITWithRules)
		r.AdmissionRules = `{"email_domain":["corp.example"]}`
	})); !errors.Is(err, ErrAdmissionEmailNeedsVerified) {
		t.Errorf("email 網域規則未要求已驗證 → %v, want ErrAdmissionEmailNeedsVerified", err)
	}
}

// Scenario: 消費者租戶識別值不可加入允許清單
func TestOIDCProviderRejectsConsumerTenantInAllowlist(t *testing.T) {
	_, providers, _ := setupOIDCEnv(t)
	// 納入該值等同放行全部個人 Microsoft 帳號
	for _, tid := range []string{
		microsoftConsumerTenantID,
		strings.ToUpper(microsoftConsumerTenantID), // 比對須大小寫不敏感，否則改個大小寫即繞過
	} {
		if _, err := providers.Create(providerReq(func(r *OIDCProviderRequest) {
			r.AdmissionMode = string(model.AdmissionJITWithRules)
			r.AdmissionRules = `{"tid":["` + tid + `"]}`
		})); !errors.Is(err, ErrAdmissionConsumerTenant) {
			t.Errorf("tid=%s → %v, want ErrAdmissionConsumerTenant", tid, err)
		}
	}
}

// Scenario: 專屬身分提供者可組態自動供應
func TestOIDCProviderDedicatedIssuerAllowsEmailOnlyRules(t *testing.T) {
	_, _, db := setupOIDCEnv(t)
	const issuer = "https://corp.okta.example.com"
	svc := newProviderSvcFor(db, testEgress(), []string{issuer}, "https://bastion.example.com")

	dto, err := svc.Create(providerReq(func(r *OIDCProviderRequest) {
		r.Issuer = issuer
		r.AdmissionMode = string(model.AdmissionJITWithRules)
		r.AdmissionRules = `{"email_domain":["corp.example"],"email_verified":true}`
	}))
	if err != nil {
		t.Fatalf("部署層宣告為專用者應可設僅含 email 網域的規則: %v", err)
	}
	if dto.IssuerKind != "dedicated" || dto.IssuerKindSource != "deploy_declared" {
		t.Errorf("issuer_kind = %q/%q, want dedicated/deploy_declared（判定來源須可見，"+
			"使「宣告打錯字」表現為來源不符而非規則莫名被拒）", dto.IssuerKind, dto.IssuerKindSource)
	}
}

// Scenario: 已知共用身分域不可經部署層宣告為專用
func TestOIDCProviderBuiltinSharedOverridesDeployDeclaration(t *testing.T) {
	_, _, db := setupOIDCEnv(t)
	const google = "https://accounts.google.com"
	// 部署方把 Google 列入專用宣告——本清單優先，宣告不生效
	svc := newProviderSvcFor(db, testEgress(), []string{google}, "https://bastion.example.com")

	if _, err := svc.Create(providerReq(func(r *OIDCProviderRequest) {
		r.Issuer = google
		r.AdmissionMode = string(model.AdmissionJITWithRules)
		r.AdmissionRules = `{"email_domain":["corp.example"],"email_verified":true}`
	})); !errors.Is(err, ErrAdmissionSharedNeedsOrgRule) {
		t.Errorf("內建共用清單成員仍須組織歸屬規則 → %v, want ErrAdmissionSharedNeedsOrgRule", err)
	}

	dto, err := svc.Create(providerReq(func(r *OIDCProviderRequest) {
		r.Issuer = google
		r.AdmissionMode = string(model.AdmissionJITWithRules)
		r.AdmissionRules = `{"hd":["corp.example"]}`
	}))
	if err != nil {
		t.Fatalf("Google＋hd 規則應可設定: %v", err)
	}
	if dto.IssuerKind != "shared" || dto.IssuerKindSource != "builtin_list" {
		t.Errorf("issuer_kind = %q/%q, want shared/builtin_list", dto.IssuerKind, dto.IssuerKindSource)
	}
}

// Scenario: 共用身分域不可被放寬為專用
//
// force_shared=false 的放寬企圖**於建立與更新兩處皆被拒絕並回
// ErrOIDCSharedCannotWiden**，不再靜默接受。
//
// 原測試以「帶 force_shared=false 建立成功、但判定仍為 shared」表達安全性質；
// 修復後那兩次 Create 本身即被拒，故改以「建立不帶表態 → 判定為 shared →
// 放寬企圖被拒 → 判定未被改動」表達同一性質，並補上 spec 要求的明確錯誤斷言。
// 斷言只增不減：原本的三條性質（內建清單成員仍 shared、未知 issuer 仍
// shared/unknown_default、放寬不得使規則檢查降級）全數保留。
func TestOIDCProviderAdminCannotWidenSharedToDedicated(t *testing.T) {
	_, _, db := setupOIDCEnv(t)
	const google = "https://accounts.google.com"
	svc := newProviderSvcFor(db, testEgress(), nil, "https://bastion.example.com")

	// (1) 內建共用清單成員：管理者宣稱專用無效——建立時即被拒
	if _, err := svc.Create(providerReq(func(r *OIDCProviderRequest) {
		r.Issuer = google
		r.ForceShared = boolPtr(false)
	})); !errors.Is(err, ErrOIDCSharedCannotWiden) {
		t.Errorf("內建共用成員的建立期放寬企圖 → %v, want ErrOIDCSharedCannotWiden", err)
	}
	builtin, err := svc.Create(providerReq(func(r *OIDCProviderRequest) {
		r.Issuer = google
	}))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if builtin.IssuerKind != "shared" {
		t.Errorf("內建共用成員 = %q, want shared", builtin.IssuerKind)
	}
	if _, err := svc.Update(builtin.ID, &OIDCProviderRequest{ForceShared: boolPtr(false)}); !errors.Is(err, ErrOIDCSharedCannotWiden) {
		t.Errorf("內建共用成員的更新期放寬企圖 → %v, want ErrOIDCSharedCannotWiden", err)
	}

	// (2) 未知 issuer（fail-close 視為共用）：同樣不得因管理者表態而變專用
	unknown, err := svc.Create(providerReq(func(r *OIDCProviderRequest) {
		r.ClientID = "cid-2"
	}))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if unknown.IssuerKind != "shared" || unknown.IssuerKindSource != "unknown_default" {
		t.Errorf("未知 issuer = %q/%q, want shared/unknown_default",
			unknown.IssuerKind, unknown.IssuerKindSource)
	}
	if _, err := svc.Update(unknown.ID, &OIDCProviderRequest{ForceShared: boolPtr(false)}); !errors.Is(err, ErrOIDCSharedCannotWiden) {
		t.Errorf("未知 issuer 的放寬企圖 → %v, want ErrOIDCSharedCannotWiden", err)
	}

	// (3) 放寬無效的實質後果：規則檢查仍以共用身分域為準。
	// (3a) 放寬企圖與寬鬆規則同時送出 → 放寬先被拒，規則不會被以專用身分域放行
	if _, err := svc.Update(unknown.ID, &OIDCProviderRequest{
		AdmissionMode:  string(model.AdmissionJITWithRules),
		AdmissionRules: `{"email_domain":["corp.example"],"email_verified":true}`,
		ForceShared:    boolPtr(false),
	}); !errors.Is(err, ErrOIDCSharedCannotWiden) {
		t.Errorf("放寬企圖不得使規則檢查降級 → %v, want ErrOIDCSharedCannotWiden", err)
	}
	// (3b) 拒絕未留殘留：判定仍為共用，僅 email 網域的規則照樣被擋
	if _, err := svc.Update(unknown.ID, &OIDCProviderRequest{
		AdmissionMode:  string(model.AdmissionJITWithRules),
		AdmissionRules: `{"email_domain":["corp.example"],"email_verified":true}`,
	}); !errors.Is(err, ErrAdmissionSharedNeedsOrgRule) {
		t.Errorf("共用身分域的規則檢查 → %v, want ErrAdmissionSharedNeedsOrgRule", err)
	}
	list, err := svc.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	for _, d := range list {
		if d.ID == unknown.ID && (d.IssuerKind != "shared" || d.IssuerKindSource != "unknown_default") {
			t.Errorf("放寬被拒後判定仍須為 %q/%q, got %q/%q",
				"shared", "unknown_default", d.IssuerKind, d.IssuerKindSource)
		}
	}
}

// --- Requirement: 停用/啟用生命週期與世代語義 ---

// Scenario: 重新啟用不復活舊憑證 ＋ 同 Requirement 的散文條款
func TestOIDCProviderDisableAdvancesEpochAndReEnableDoesNotRollBack(t *testing.T) {
	_, providers, db := setupOIDCEnv(t)
	dto := mustCreateProvider(t, providers, providerReq(nil))
	base := reloadProvider(t, db, dto.ID).AuthEpoch

	if _, err := providers.Update(dto.ID, &OIDCProviderRequest{Enabled: boolPtr(false)}); err != nil {
		t.Fatalf("停用: %v", err)
	}
	disabled := reloadProvider(t, db, dto.ID)
	if disabled.Enabled {
		t.Error("停用後 enabled 應為 false")
	}
	if disabled.AuthEpoch <= base {
		t.Fatalf("停用應推進世代: %d → %d", base, disabled.AuthEpoch)
	}

	if _, err := providers.Update(dto.ID, &OIDCProviderRequest{Enabled: boolPtr(true)}); err != nil {
		t.Fatalf("重新啟用: %v", err)
	}
	reEnabled := reloadProvider(t, db, dto.ID)
	if !reEnabled.Enabled {
		t.Error("重新啟用後 enabled 應為 true")
	}
	// 世代不回退：否則停用後短時間重新啟用會使攻擊者手上的未過期憑證全部復活
	if reEnabled.AuthEpoch != disabled.AuthEpoch {
		t.Errorf("重新啟用不得回退世代: %d → %d", disabled.AuthEpoch, reEnabled.AuthEpoch)
	}

	// 再次停用續推進（單調遞增）
	if _, err := providers.Update(dto.ID, &OIDCProviderRequest{Enabled: boolPtr(false)}); err != nil {
		t.Fatalf("再次停用: %v", err)
	}
	if again := reloadProvider(t, db, dto.ID).AuthEpoch; again <= reEnabled.AuthEpoch {
		t.Errorf("再次停用應續推進世代: %d → %d", reEnabled.AuthEpoch, again)
	}
}

// Scenario: 輪替 client_secret 不改變身分 ＋ 同 Requirement 的散文條款
// （輪替 SHALL 推進世代；終斷既有連線與訂閱的部分屬 login/session 層，
// 由 oidc_flow_test.go 的世代閘測試覆蓋，不在 provider service 範圍）
func TestOIDCProviderSecretRotationAdvancesEpochAndKeepsIdentities(t *testing.T) {
	_, providers, db := setupOIDCEnv(t)
	dto := mustCreateProvider(t, providers, providerReq(nil))
	p := reloadProvider(t, db, dto.ID)
	user := seedOIDCUser(t, db, "ext-user")
	seedIdentity(t, db, user, p, "sub-1")
	before := reloadProvider(t, db, dto.ID)

	if _, err := providers.Update(dto.ID, &OIDCProviderRequest{ClientSecret: "rotated-secret"}); err != nil {
		t.Fatalf("輪替密鑰: %v", err)
	}
	after := reloadProvider(t, db, dto.ID)
	if after.ClientSecretEnc == before.ClientSecretEnc {
		t.Error("輪替後密鑰應已更換")
	}
	if after.AuthEpoch <= before.AuthEpoch {
		t.Errorf("密鑰輪替應推進世代（舊密鑰可能已洩漏）: %d → %d", before.AuthEpoch, after.AuthEpoch)
	}

	// 身分以 (issuer, client_id, subject) 為鍵，與密鑰無關：既有身分不變、不新增列
	var identities []model.UserExternalIdentity
	if err := db.Where("provider_id = ?", dto.ID).Find(&identities).Error; err != nil {
		t.Fatalf("查身分: %v", err)
	}
	if len(identities) != 1 {
		t.Fatalf("身分數 = %d, want 1（輪替不得產生新身分記錄）", len(identities))
	}
	if identities[0].UserID != user.ID || identities[0].Subject != "sub-1" ||
		identities[0].Issuer != p.Issuer || identities[0].ClientID != p.ClientID {
		t.Errorf("輪替後身分記錄被改動: %+v", identities[0])
	}
}

// Scenario: 停用後重新啟用不失效
func TestOIDCProviderDisableEnableKeepsExistingIdentities(t *testing.T) {
	_, providers, db := setupOIDCEnv(t)
	dto := mustCreateProvider(t, providers, providerReq(nil))
	p := reloadProvider(t, db, dto.ID)
	user := seedOIDCUser(t, db, "ext-user")
	seedIdentity(t, db, user, p, "sub-1")

	for _, enabled := range []bool{false, true} {
		if _, err := providers.Update(dto.ID, &OIDCProviderRequest{Enabled: boolPtr(enabled)}); err != nil {
			t.Fatalf("設定 enabled=%v: %v", enabled, err)
		}
	}

	// 身分仍可經身分域三元組對應回同一帳號（無須重新綁定）
	var identity model.UserExternalIdentity
	if err := db.Where("issuer = ? AND client_id = ? AND subject = ?",
		p.Issuer, p.ClientID, "sub-1").First(&identity).Error; err != nil {
		t.Fatalf("重新啟用後身分應仍可對應: %v", err)
	}
	if identity.UserID != user.ID {
		t.Errorf("身分對應的使用者 = %d, want %d", identity.UserID, user.ID)
	}
}

// Scenario: 切換為僅預先綁定不收回既有身分
//
// 服務層可驗證的部分：切換成功、既有身分沿用、管理端取得得以明示的身分數量
func TestOIDCProviderSwitchToPreboundKeepsIdentitiesAndExposesCount(t *testing.T) {
	_, _, db := setupOIDCEnv(t)
	svc := newProviderSvcFor(db, testEgress(), []string{"https://idp.example.com"}, "https://bastion.example.com")
	dto := mustCreateProvider(t, svc, providerReq(func(r *OIDCProviderRequest) {
		r.AdmissionMode = string(model.AdmissionJITWithRules)
		r.AdmissionRules = `{"email_domain":["corp.example"],"email_verified":true}`
	}))
	p := reloadProvider(t, db, dto.ID)
	for _, name := range []string{"ext-a", "ext-b"} {
		seedIdentity(t, db, seedOIDCUser(t, db, name), p, "sub-"+name)
	}

	switched, err := svc.Update(dto.ID, &OIDCProviderRequest{
		AdmissionMode: string(model.AdmissionPreboundOnly),
	})
	if err != nil {
		t.Fatalf("切換為 prebound_only: %v", err)
	}
	if switched.AdmissionMode != string(model.AdmissionPreboundOnly) {
		t.Errorf("admission_mode = %q, want prebound_only", switched.AdmissionMode)
	}

	var identities int64
	db.Model(&model.UserExternalIdentity{}).Where("provider_id = ?", dto.ID).Count(&identities)
	if identities != 2 {
		t.Errorf("切換不得收回既有身分，身分數 = %d, want 2", identities)
	}
	// 「管理介面於切換時明示既有身分數量」的資料來源
	list, err := svc.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	found := false
	for _, d := range list {
		if d.ID == dto.ID {
			found = true
			if d.IdentityCount != 2 {
				t.Errorf("identity_count = %d, want 2", d.IdentityCount)
			}
		}
	}
	if !found {
		t.Fatal("切換後 provider 應仍在管理清單內")
	}
}

// Scenario: 移除部署層宣告後立即回復共用
func TestOIDCProviderDeployDeclarationRemovalRevertsToShared(t *testing.T) {
	_, _, db := setupOIDCEnv(t)
	const issuer = "https://corp.okta.example.com"
	declared := newProviderSvcFor(db, testEgress(), []string{issuer}, "https://bastion.example.com")
	dto := mustCreateProvider(t, declared, providerReq(func(r *OIDCProviderRequest) {
		r.Issuer = issuer
		r.AdmissionMode = string(model.AdmissionJITWithRules)
		r.AdmissionRules = `{"email_domain":["corp.example"],"email_verified":true}`
	}))

	// 部署方移除宣告（判定不持久化，故重建服務即等同重啟後的新組態）
	withoutDeclaration := newProviderSvcFor(db, testEgress(), nil, "https://bastion.example.com")
	list, err := withoutDeclaration.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	var current *OIDCProviderDTO
	for i := range list {
		if list[i].ID == dto.ID {
			current = &list[i]
		}
	}
	if current == nil {
		t.Fatal("provider 應仍存在")
	}
	if current.IssuerKind != "shared" || current.IssuerKindSource != "unknown_default" {
		t.Errorf("移除宣告後 = %q/%q, want shared/unknown_default（判定須現算，不得沿用舊值）",
			current.IssuerKind, current.IssuerKindSource)
	}
	// 新設定的規則已依共用身分域判定（收緊即刻生效）
	if _, err := withoutDeclaration.Update(dto.ID, &OIDCProviderRequest{
		AdmissionRules: `{"email_domain":["corp.example"],"email_verified":true}`,
	}); !errors.Is(err, ErrAdmissionSharedNeedsOrgRule) {
		t.Errorf("移除宣告後的規則更新 → %v, want ErrAdmissionSharedNeedsOrgRule", err)
	}

	// 同 Scenario 的後半：既有 provider 的規則集合規性須被**重新驗證**，
	// 不合規者於管理端標示。
	// 宣告仍在時合規、宣告移除後即不合規——同一份規則、同一列資料，判定現算
	for i := range list {
		if list[i].ID != dto.ID {
			continue
		}
		if list[i].AdmissionCompliant {
			t.Error("宣告移除後，僅 email 網域的規則集須被標示為不合規")
		}
		if list[i].AdmissionIssue != "shared_needs_org_rule" {
			t.Errorf("不合規成因 = %q, want shared_needs_org_rule", list[i].AdmissionIssue)
		}
	}
	declaredList, err := declared.List()
	if err != nil {
		t.Fatalf("List（宣告仍在）: %v", err)
	}
	for i := range declaredList {
		if declaredList[i].ID == dto.ID && !declaredList[i].AdmissionCompliant {
			t.Error("宣告仍在時同一份規則須為合規（否則標示與判定不同源）")
		}
	}
}

// --- Requirement: 登入頁 SSO 入口 ---

// Scenario: 清單不洩漏設定；停用者不列
func TestOIDCProviderLoginMethodsExposeOnlyIdentityFields(t *testing.T) {
	_, providers, _ := setupOIDCEnv(t)
	mustCreateProvider(t, providers, providerReq(func(r *OIDCProviderRequest) {
		r.Name = "Corp SSO"
	}))
	mustCreateProvider(t, providers, providerReq(func(r *OIDCProviderRequest) {
		r.Name = "Disabled IdP"
		r.ClientID = "cid-disabled"
		r.Enabled = boolPtr(false)
	}))

	methods, err := providers.ListLoginMethods()
	if err != nil {
		t.Fatalf("ListLoginMethods: %v", err)
	}
	if len(methods) != 1 || methods[0].Name != "Corp SSO" {
		t.Fatalf("清單應僅含啟用中的 provider，實得 %+v", methods)
	}
	raw, err := json.Marshal(methods)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// 「回應僅含識別與顯示所需欄位」——逐項檢查設定值不外洩（未認證端點）
	for _, leak := range []string{"issuer", "client_id", "client_secret", "idp.example.com",
		"cid-1", "s3cret-value", "scope", "admission"} {
		if strings.Contains(string(raw), leak) {
			t.Errorf("登入方法清單洩漏 %q: %s", leak, raw)
		}
	}
	var fields []map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for k := range fields[0] {
		if k != "id" && k != "name" {
			t.Errorf("登入方法清單含非必要欄位 %q", k)
		}
	}
}

// Scenario: 設定不完整不顯示
func TestOIDCProviderIncompleteConfigHiddenFromLoginPage(t *testing.T) {
	_, providers, db := setupOIDCEnv(t)
	dto := mustCreateProvider(t, providers, providerReq(nil))

	// 未設定對外基準網址：begin 無法組出 redirect_uri，按鈕看得到必按不動
	noBaseURL := newProviderSvcFor(db, testEgress(), nil, "")
	methods, err := noBaseURL.ListLoginMethods()
	if err != nil {
		t.Fatalf("ListLoginMethods: %v", err)
	}
	if len(methods) != 0 {
		t.Errorf("缺對外基準網址時不應列出任何 provider，實得 %+v", methods)
	}
	if _, err := noBaseURL.RedirectURI(); !errors.Is(err, ErrOIDCBaseURLMissing) {
		t.Errorf("RedirectURI → %v, want ErrOIDCBaseURLMissing", err)
	}

	// 「管理頁以狀態標示其設定不完整」
	list, err := noBaseURL.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	for _, d := range list {
		if d.ID != dto.ID {
			continue
		}
		if d.ConfigComplete {
			t.Error("缺對外基準網址時 config_complete 應為 false")
		}
		if d.IncompleteHint == "" {
			t.Error("設定不完整須附可辨識的原因提示")
		}
	}

	// 設定齊備者維持可見
	if got, err := providers.ListLoginMethods(); err != nil || len(got) != 1 {
		t.Errorf("設定齊備時應列出，得 %+v err=%v", got, err)
	}
}

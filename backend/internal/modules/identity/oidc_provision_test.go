package identity

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

// 身分對應與供應測試（idp-oidc-integration tasks 4.5/4.6，design D7b/D7c/D7d）。
//
// 覆蓋固定順序（准入判定不因身分已存在而被略過）、同名不接管、並發首登收斂、
// username 映射順序，以及回訪時本體與快照的分離。

// oidcClaims 組出一組已驗證 claims
func oidcClaims(subject string, extra map[string]any) *VerifiedClaims {
	raw := map[string]any{"sub": subject}
	for k, v := range extra {
		raw[k] = v
	}
	c := &VerifiedClaims{Subject: subject, Raw: raw}
	if v, ok := raw["preferred_username"].(string); ok {
		c.PreferredUsername = v
	}
	if v, ok := raw["email"].(string); ok {
		c.Email = v
	}
	if v, ok := raw["email_verified"].(bool); ok {
		c.EmailVerified = v
	}
	if v, ok := raw["name"].(string); ok {
		c.Name = v
	}
	return c
}

// seedIdentity 為既有使用者建立外部身分關聯
func seedIdentity(t *testing.T, db *gorm.DB, u *model.User, p *model.OIDCProvider, subject string) {
	t.Helper()
	id := model.UserExternalIdentity{
		UserID: u.ID, ProviderID: p.ID,
		Issuer: p.Issuer, ClientID: p.ClientID, Subject: subject,
	}
	if err := db.Create(&id).Error; err != nil {
		t.Fatalf("seed identity: %v", err)
	}
}

// jitProvider 啟用自動供應且限定 Workspace 網域的 provider
func jitProvider(t *testing.T, db *gorm.DB) *model.OIDCProvider {
	t.Helper()
	return seedProvider(t, db, func(p *model.OIDCProvider) {
		p.AdmissionMode = model.AdmissionJITWithRules
		p.AdmissionRules = `{"hd":["corp.example"]}`
	})
}

// --- prebound_only ---

func TestPreboundOnlyRejectsUnboundIdentity(t *testing.T) {
	login, _, db := setupOIDCEnv(t)
	p := seedProvider(t, db, nil) // 出廠即 prebound_only（fail-close 預設）

	_, err := login.resolveOrProvision(p, oidcClaims("sub-new", map[string]any{
		"preferred_username": "stranger",
	}), &oidcAuditTrail{})
	if !errors.Is(err, ErrOIDCAdmissionDenied) {
		t.Fatalf("未預先綁定的身分 = %v, want ErrOIDCAdmissionDenied", err)
	}
	var cnt int64
	db.Model(&model.User{}).Count(&cnt)
	if cnt != 0 {
		t.Fatal("prebound_only 不得自動供應任何帳號")
	}
}

func TestPreboundOnlyAcceptsBoundIdentity(t *testing.T) {
	login, _, db := setupOIDCEnv(t)
	p := seedProvider(t, db, nil)
	user := seedOIDCUser(t, db, "alice")
	seedIdentity(t, db, user, p, "sub-1")

	got, err := login.resolveOrProvision(p, oidcClaims("sub-1", nil), &oidcAuditTrail{})
	if err != nil {
		t.Fatalf("已綁定身分應通過: %v", err)
	}
	if got.ID != user.ID {
		t.Errorf("對應到 user %d, want %d", got.ID, user.ID)
	}
}

// --- 准入判定於每次認證求值（D7b） ---

func TestAdmissionEvaluatedOnEveryAuthNotOnlyProvisioning(t *testing.T) {
	login, _, db := setupOIDCEnv(t)
	p := jitProvider(t, db)
	user := seedOIDCUser(t, db, "alice")
	seedIdentity(t, db, user, p, "sub-1")

	// 身分已存在，但 claims 不再符合現行規則（使用者已離開該 Workspace，
	// 或管理者把規則收緊）→ 必須被拒。**身分存在不使判定被略過**
	_, err := login.resolveOrProvision(p, oidcClaims("sub-1", map[string]any{
		"hd": "other.example",
	}), &oidcAuditTrail{})
	if !errors.Is(err, ErrOIDCAdmissionDenied) {
		t.Fatalf("既有身分不符現行規則 = %v, want ErrOIDCAdmissionDenied", err)
	}

	// 對照：符合規則時同一身分正常登入
	got, err := login.resolveOrProvision(p, oidcClaims("sub-1", map[string]any{
		"hd": "corp.example",
	}), &oidcAuditTrail{})
	if err != nil {
		t.Fatalf("符合規則應通過: %v", err)
	}
	if got.ID != user.ID {
		t.Errorf("對應到 user %d, want %d", got.ID, user.ID)
	}
}

func TestAdmissionMissingClaimIsNoMatch(t *testing.T) {
	login, _, db := setupOIDCEnv(t)
	p := jitProvider(t, db)
	// claim 缺失／null／型別不符一律視為不匹配（fail-close，不做寬鬆轉型）
	for name, extra := range map[string]map[string]any{
		"缺 hd":      {"preferred_username": "bob"},
		"hd 為 null": {"hd": nil},
		"hd 型別不符":   {"hd": 123},
	} {
		_, err := login.resolveOrProvision(p, oidcClaims("sub-"+name, extra), &oidcAuditTrail{})
		if !errors.Is(err, ErrOIDCAdmissionDenied) {
			t.Errorf("%s → %v, want ErrOIDCAdmissionDenied", name, err)
		}
	}
}

// --- 供應影子帳號 ---

func TestProvisionCreatesShadowAccount(t *testing.T) {
	login, _, db := setupOIDCEnv(t)
	p := jitProvider(t, db)

	got, err := login.resolveOrProvision(p, oidcClaims("sub-1", map[string]any{
		"hd": "corp.example", "preferred_username": "bob",
		"email": "bob@corp.example", "email_verified": true, "name": "Bob",
	}), &oidcAuditTrail{})
	if err != nil {
		t.Fatalf("首登供應應成功: %v", err)
	}
	if got.Username != "bob" {
		t.Errorf("username = %q, want bob", got.Username)
	}
	if !got.ExternalCredential {
		t.Error("影子帳號的 external_credential 應為 true（GORM default 覆寫陷阱的防線）")
	}
	if got.ProvisioningOrigin != model.AuthSourceOIDC {
		t.Errorf("provisioning_origin = %q, want oidc", got.ProvisioningOrigin)
	}
	if !got.IsExternal() {
		t.Error("影子帳號應被判定為外部身分（密碼類 gate 一律不適用）")
	}
	if got.Email == nil || *got.Email != "bob@corp.example" {
		t.Errorf("email = %v, want bob@corp.example", got.Email)
	}

	var identity model.UserExternalIdentity
	if err := db.Where("subject = ?", "sub-1").First(&identity).Error; err != nil {
		t.Fatalf("外部身分應一併建立: %v", err)
	}
	if identity.Issuer != p.Issuer || identity.ClientID != p.ClientID {
		t.Error("身分域三元組應完整落庫")
	}
	if identity.UserID != got.ID {
		t.Error("身分應指向新建的使用者")
	}

	var roleCnt int64
	db.Table("user_roles").Where("user_id = ?", got.ID).Count(&roleCnt)
	if roleCnt != 1 {
		t.Errorf("應綁定 1 個預設角色，實得 %d", roleCnt)
	}
}

func TestProvisionUnverifiedEmailNotAdopted(t *testing.T) {
	login, _, db := setupOIDCEnv(t)
	p := jitProvider(t, db)

	got, err := login.resolveOrProvision(p, oidcClaims("sub-1", map[string]any{
		"hd": "corp.example", "preferred_username": "bob",
		"email": "ceo@corp.example", "email_verified": false,
	}), &oidcAuditTrail{})
	if err != nil {
		t.Fatalf("供應失敗: %v", err)
	}
	// 未驗證 email 可被任意設定；採用即讓外部使用者自選本地識別
	if got.Email != nil {
		t.Errorf("未驗證的 email 不得採用，實得 %v", *got.Email)
	}
	var identity model.UserExternalIdentity
	db.Where("subject = ?", "sub-1").First(&identity)
	if identity.ClaimEmail != "" {
		t.Errorf("未驗證 email 不得入快照，實得 %q", identity.ClaimEmail)
	}
}

// --- 同名不接管（D7d） ---

func TestProvisionDoesNotTakeOverExistingLocalAccount(t *testing.T) {
	login, _, db := setupOIDCEnv(t)
	p := jitProvider(t, db)
	// 本地帳號（含密碼）先存在
	local := &model.User{Username: "admin", Password: "local-hash", Active: true,
		ProvisioningOrigin: model.AuthSourceLocal}
	if err := db.Create(local).Error; err != nil {
		t.Fatalf("seed local: %v", err)
	}

	// 外部使用者把 preferred_username 設成 admin：以 username 做 get_or_create 的供應
	// 方式會直接讓他登進本地管理員帳號，本系統一律拒絕
	_, err := login.resolveOrProvision(p, oidcClaims("sub-evil", map[string]any{
		"hd": "corp.example", "preferred_username": "admin",
	}), &oidcAuditTrail{})
	if !errors.Is(err, ErrOIDCUsernameConflict) {
		t.Fatalf("同名應拒絕而非接管，實得 %v", err)
	}

	var reloaded model.User
	db.First(&reloaded, local.ID)
	if reloaded.Password != "local-hash" || reloaded.ExternalCredential {
		t.Fatal("既有本地帳號不得被改寫")
	}
	var idCnt int64
	db.Model(&model.UserExternalIdentity{}).Count(&idCnt)
	if idCnt != 0 {
		t.Fatal("不得為既有帳號建立外部身分關聯")
	}
}

// --- 並發首登收斂（D7b） ---

func TestConcurrentFirstLoginConvergesToSameUser(t *testing.T) {
	login, _, db := setupOIDCEnv(t)
	p := jitProvider(t, db)
	claims := oidcClaims("sub-1", map[string]any{
		"hd": "corp.example", "preferred_username": "bob",
	})

	// 兩個分頁同時首登：兩者都在對方提交前查到「身分不存在」，故都會進入供應路徑。
	// 第二次呼叫即模擬落後者的狀態——它必須收斂到同一使用者，
	// 而非回報撞名（使用者雙擊 SSO 就報冒名衝突是誤報）
	firstTrail, secondTrail := &oidcAuditTrail{}, &oidcAuditTrail{}
	first, err := login.provisionFromClaims(p, claims, firstTrail)
	if err != nil {
		t.Fatalf("首次供應失敗: %v", err)
	}
	second, err := login.provisionFromClaims(p, claims, secondTrail)
	if err != nil {
		t.Fatalf("落後者應收斂而非報錯: %v", err)
	}
	if second.ID != first.ID {
		t.Fatalf("應收斂到同一使用者，got %d want %d", second.ID, first.ID)
	}

	var userCnt, idCnt int64
	db.Model(&model.User{}).Count(&userCnt)
	db.Model(&model.UserExternalIdentity{}).Count(&idCnt)
	if userCnt != 1 || idCnt != 1 {
		t.Errorf("不得重複建立，users=%d identities=%d", userCnt, idCnt)
	}

	// **收斂不得落安全事件**：這是本修正的動機本身。少了這條斷言，
	// 「收斂成功但仍記一筆冒名衝突」的退化不會被任何測試發現，
	// 而其後果是真正的衝突淹沒在雙擊 SSO 的雜訊裡
	if n := countAuditIntent(secondTrail.events, "oidc_username_conflict"); n != 0 {
		t.Errorf("並發收斂不得落冒名衝突事件，實得 %d 筆", n)
	}
	// 反面：首次供應**必須**留下建帳號事件（JIT 首登建帳號原本只在衝突時留痕），
	// 且落後者收斂時不得再記一次——否則一次雙擊 SSO 看起來像建了兩個帳號
	prov := auditEvents(firstTrail.events, "oidc_user_provisioned")
	if len(prov) != 1 {
		t.Fatalf("首次供應應恰落 1 筆建帳號事件，實得 %d 筆", len(prov))
	}
	if prov[0].Resource != model.ResourceUser || prov[0].Status != model.StatusSuccess ||
		prov[0].ResourceID == nil || *prov[0].ResourceID != first.ID {
		t.Errorf("建帳號事件應為 resource=user／status=success／resource_id=%d，實得 %+v",
			first.ID, prov[0])
	}
	if n := countAuditIntent(secondTrail.events, "oidc_user_provisioned"); n != 0 {
		t.Errorf("並發收斂不得再記一次建帳號，實得 %d 筆", n)
	}

	// 收斂後的行為須與正常回訪相同：快照與 last_login_at 應已更新
	var identity model.UserExternalIdentity
	db.Where("subject = ?", "sub-1").First(&identity)
	if identity.LastLoginAt == nil {
		t.Error("收斂路徑亦應更新 last_login_at（與既有身分回訪一致）")
	}
}

func TestConvergesWhenIdentityUniqueConstraintFails(t *testing.T) {
	login, _, db := setupOIDCEnv(t)
	p := jitProvider(t, db)

	// 另一條收斂路徑：username 未被占用（故通過預查），但身分域三元組已存在，
	// 交易於建立身分時撞唯一約束。兩條路徑各自獨立，只測其一會漏掉另一條
	winner := seedOIDCUser(t, db, "alice")
	seedIdentity(t, db, winner, p, "sub-1")

	got, err := login.provisionFromClaims(p, oidcClaims("sub-1", map[string]any{
		"hd": "corp.example", "preferred_username": "bob", // 映射成未被占用的 bob
	}), &oidcAuditTrail{})
	if err != nil {
		t.Fatalf("唯一約束失敗後應收斂: %v", err)
	}
	if got.ID != winner.ID {
		t.Fatalf("應收斂到既有身分的使用者 %d，實得 %d", winner.ID, got.ID)
	}

	// 收斂即不得留下半成品：交易回滾後不該有孤兒 bob
	var bobCnt int64
	db.Model(&model.User{}).Where("username = ?", "bob").Count(&bobCnt)
	if bobCnt != 0 {
		t.Errorf("交易失敗應完整回滾，殘留 %d 筆 bob", bobCnt)
	}
	var idCnt int64
	db.Model(&model.UserExternalIdentity{}).Count(&idCnt)
	if idCnt != 1 {
		t.Errorf("身分應仍只有 1 筆，實得 %d", idCnt)
	}
}

func TestRealUsernameConflictStillAudited(t *testing.T) {
	login, _, db := setupOIDCEnv(t)
	p := jitProvider(t, db)
	local := &model.User{Username: "admin", Password: "local-hash", Active: true,
		ProvisioningOrigin: model.AuthSourceLocal}
	if err := db.Create(local).Error; err != nil {
		t.Fatalf("seed local: %v", err)
	}

	// 收斂的反面：真正的撞名**必須**落安全事件。
	// 若為了消除誤報而把事件整個拿掉，這格會紅
	trail := &oidcAuditTrail{}
	if _, err := login.resolveOrProvision(p, oidcClaims("sub-evil", map[string]any{
		"hd": "corp.example", "preferred_username": "admin",
	}), trail); !errors.Is(err, ErrOIDCUsernameConflict) {
		t.Fatalf("真撞名應被拒，實得 %v", err)
	}
	got := auditEvents(trail.events, "oidc_username_conflict")
	if len(got) != 1 {
		t.Fatalf("真撞名應恰落 1 筆冒名衝突事件，實得 %d", len(got))
	}
	// 撞名是「身分成立但不准接管既有帳號」＝授權拒絕語義（D3），不得與憑證
	// 不成立的認證失敗混為一談
	if got[0].Status != model.StatusDenied || got[0].Resource != model.ResourceAuth {
		t.Errorf("撞名事件應為 status=denied／resource=auth，實得 status=%q resource=%q",
			got[0].Status, got[0].Resource)
	}
}

func TestAdmissionDeniedIsAudited(t *testing.T) {
	login, _, db := setupOIDCEnv(t)
	p := jitProvider(t, db)

	trail := &oidcAuditTrail{}
	if _, err := login.resolveOrProvision(p, oidcClaims("sub-1", map[string]any{
		"hd": "other.example",
	}), trail); !errors.Is(err, ErrOIDCAdmissionDenied) {
		t.Fatalf("應被准入拒絕，實得 %v", err)
	}
	got := auditEvents(trail.events, "oidc_admission_denied")
	if len(got) != 1 {
		t.Fatalf("准入拒絕應落 1 筆事件，實得 %d", len(got))
	}
	// **准入拒絕是授權拒絕（denied），不是認證失敗（failure）**（D3）：身分已在
	// IdP 端驗證通過，被拒的是「不符本系統准入條件」。一刀切成 failure 會使
	// 既有授權拒絕列不可解釋
	if got[0].Status != model.StatusDenied {
		t.Errorf("准入拒絕的 status 應為 %q，實得 %q", model.StatusDenied, got[0].Status)
	}
	if got[0].Resource != model.ResourceAuth {
		t.Errorf("准入拒絕的 resource 應為 %q（非 user），實得 %q", model.ResourceAuth, got[0].Resource)
	}
	// 事件內不得含 claim 明文或 subject 原值——審計本身不該成為身分資訊的外洩面
	for _, e := range trail.events {
		if strings.Contains(e.DetailsJSON(), "other.example") || strings.Contains(e.DetailsJSON(), `"sub-1"`) {
			t.Errorf("審計不得回填 claim 明文或 subject 原值，實得: %s", e.DetailsJSON())
		}
	}
}

// --- username 映射順序（D7c） ---

func TestMapUsernamePrefersPreferredUsername(t *testing.T) {
	login, _, _ := setupOIDCEnv(t)
	got := login.mapUsername(oidcClaims("sub-1", map[string]any{
		"preferred_username": "bob", "email": "carol@corp.example", "email_verified": true,
	}))
	if got != "bob" {
		t.Errorf("mapUsername = %q, want bob", got)
	}
}

func TestMapUsernameFallsBackToVerifiedEmailLocalPart(t *testing.T) {
	login, _, _ := setupOIDCEnv(t)
	got := login.mapUsername(oidcClaims("sub-1", map[string]any{
		"email": "carol@corp.example", "email_verified": true,
	}))
	if got != "carol" {
		t.Errorf("mapUsername = %q, want carol", got)
	}
}

func TestMapUsernameIgnoresUnverifiedEmail(t *testing.T) {
	login, _, _ := setupOIDCEnv(t)
	// 未驗證 email 可被任意設定，據以產生 username 等同讓外部使用者自選本地身分
	got := login.mapUsername(oidcClaims("sub-1", map[string]any{
		"email": "admin@corp.example", "email_verified": false,
	}))
	if got != "sub-1" {
		t.Errorf("mapUsername = %q, want 退回 subject（sub-1）", got)
	}
}

func TestMapUsernameRejectsControlCharacters(t *testing.T) {
	login, _, _ := setupOIDCEnv(t)
	got := login.mapUsername(oidcClaims("sub-1", map[string]any{
		"preferred_username": "bo\nb",
	}))
	if got != "sub-1" {
		t.Errorf("含控制字元的 preferred_username 應被丟棄並退回 subject，實得 %q", got)
	}
}

func TestMapUsernameTruncatesOverlong(t *testing.T) {
	login, _, _ := setupOIDCEnv(t)
	got := login.mapUsername(oidcClaims("sub-1", map[string]any{
		"preferred_username": strings.Repeat("x", 120),
	}))
	if len([]rune(got)) != 50 {
		t.Errorf("username 應截至 50 字元，實得 %d", len([]rune(got)))
	}
}

// --- 回訪：本體與快照分離（D7b） ---

func TestTouchIdentityDoesNotRewriteUserRecord(t *testing.T) {
	login, _, db := setupOIDCEnv(t)
	p := seedProvider(t, db, nil)
	user := seedOIDCUser(t, db, "alice")
	seedIdentity(t, db, user, p, "sub-1")

	// IdP 端改名並自報 email。users 本體是授權主體識別（授權綁定與審計歸屬皆依它），
	// 靜默改寫會使既有授權與稽核歸屬失準
	if _, err := login.resolveOrProvision(p, oidcClaims("sub-1", map[string]any{
		"preferred_username": "administrator", "name": "New Name",
		"email": "new@corp.example", "email_verified": true,
	}), &oidcAuditTrail{}); err != nil {
		t.Fatalf("回訪應成功: %v", err)
	}

	var reloaded model.User
	db.First(&reloaded, user.ID)
	if reloaded.Username != "alice" {
		t.Errorf("本體 username 被改寫為 %q，應保持 alice", reloaded.Username)
	}
	if reloaded.Email != nil {
		t.Errorf("本體 email 被改寫為 %v，回訪不得寫入", *reloaded.Email)
	}

	var identity model.UserExternalIdentity
	db.Where("subject = ?", "sub-1").First(&identity)
	if identity.ClaimUsername != "administrator" {
		t.Errorf("快照 claim_username = %q, want administrator（IdP 自報值）", identity.ClaimUsername)
	}
	if identity.ClaimEmail != "new@corp.example" {
		t.Errorf("快照 claim_email = %q", identity.ClaimEmail)
	}
	if identity.LastLoginAt == nil || time.Since(*identity.LastLoginAt) > time.Minute {
		t.Error("last_login_at 應更新為本次登入時間")
	}
}

func TestIdentityDomainIsolatedByClientID(t *testing.T) {
	login, _, db := setupOIDCEnv(t)
	// 同一 IdP 上的兩個應用註冊：issuer 相同、client_id 不同。
	// Entra 的 sub 是 per-application pairwise，同一人在兩者拿到的 subject 本就不同；
	// 但即使 IdP 送出相同 subject（如 Google 的全域穩定 sub），兩者也**不得**互通——
	// 否則管理者在 A 應用綁定的身分會被 B 應用的 token 冒用
	appA := seedProvider(t, db, func(p *model.OIDCProvider) {
		p.Name = "app-a"
		p.ClientID = "client-a"
	})
	appB := seedProvider(t, db, func(p *model.OIDCProvider) {
		p.Name = "app-b"
		p.ClientID = "client-b"
	})
	if appA.Issuer != appB.Issuer {
		t.Fatal("兩者應同 issuer（前提不成立則本測試無意義）")
	}

	user := seedOIDCUser(t, db, "alice")
	seedIdentity(t, db, user, appA, "shared-subject")

	// 經 app A 登入：命中既有身分
	if got, err := login.resolveOrProvision(appA, oidcClaims("shared-subject", nil), &oidcAuditTrail{}); err != nil {
		t.Fatalf("app A 應命中既有身分: %v", err)
	} else if got.ID != user.ID {
		t.Errorf("app A 對應到 user %d, want %d", got.ID, user.ID)
	}

	// 經 app B 以相同 subject 登入：**不得**命中 A 的身分。
	// prebound_only 下即表現為准入拒絕（B 尚無預先綁定的身分）
	_, err := login.resolveOrProvision(appB, oidcClaims("shared-subject", nil), &oidcAuditTrail{})
	if !errors.Is(err, ErrOIDCAdmissionDenied) {
		t.Fatalf("不同 client_id 不得共用身分，實得 %v", err)
	}
}

func TestIdentityKeyIsTripleNotProviderID(t *testing.T) {
	login, providers, db := setupOIDCEnv(t)
	p := seedProvider(t, db, nil)
	user := seedOIDCUser(t, db, "alice")
	seedIdentity(t, db, user, p, "sub-1")

	// admin 誤刪 provider 後以同 (issuer, client_id) 重建：若身分域鍵是 provider_id，
	// 既有身分全數未命中，全體使用者將被鎖出（繼而撞名被拒）
	db.Where("user_id = ?", user.ID).Delete(&model.UserExternalIdentity{})
	seedIdentity(t, db, user, p, "sub-1")
	if err := db.Where("id = ?", p.ID).Delete(&model.OIDCProvider{}).Error; err != nil {
		t.Fatalf("刪除 provider: %v", err)
	}
	rebuilt, err := providers.Create(&OIDCProviderRequest{
		Name: "corp-again", Issuer: p.Issuer, ClientID: p.ClientID, Scopes: "profile email",
	})
	if err != nil {
		t.Fatalf("重建 provider: %v", err)
	}
	if rebuilt.ID == p.ID {
		t.Fatal("重建應產生不同的 provider id（前提不成立則本測試無意義）")
	}

	var newP model.OIDCProvider
	db.First(&newP, rebuilt.ID)
	got, err := login.resolveOrProvision(&newP, oidcClaims("sub-1", nil), &oidcAuditTrail{})
	if err != nil {
		t.Fatalf("provider 重建後既有身分仍應可登入: %v", err)
	}
	if got.ID != user.ID {
		t.Errorf("對應到 user %d, want %d", got.ID, user.ID)
	}

	// provider_id 指向於下次登入自動修正
	var identity model.UserExternalIdentity
	db.Where("subject = ?", "sub-1").First(&identity)
	if identity.ProviderID != newP.ID {
		t.Errorf("provider_id 應修正為 %d，實得 %d", newP.ID, identity.ProviderID)
	}
}

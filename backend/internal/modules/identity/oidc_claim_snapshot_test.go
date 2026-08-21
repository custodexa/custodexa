package identity

import (
	"github.com/custodexa/backend/internal/modules/authz"
	"testing"

	"github.com/custodexa/backend/internal/model"
)

// claim 快照欄（ClaimUsername／ClaimEmail）的語義測試（idp-oidc-integration 1.11）。
//
// 三條不變式：
//  1. admin 綁定時無 IdP 自報值可填，兩欄留空；首登時由 touchIdentity 補上。
//  2. 快照更新**不動 users 本體**——本體是授權主體識別，靜默改寫會使既有授權與
//     稽核歸屬失準（本體側的斷言另見 TestTouchIdentityDoesNotRewriteUserRecord，
//     本檔補的是「經 admin 綁定進來」這條路徑，其起點是本地帳號而非影子帳號）。
//  3. 未驗證的 email 不入快照——管理端會把快照當作 IdP 現況，未驗證值一旦入欄
//     即成為可由使用者自行填寫的「看起來可信」的識別依據。
//
// 回訪路徑的既有覆蓋見 oidc_provision_test.go；本檔不重複那些格。

var snapshotActor = IdentityAdminActor{UserID: 7, Username: "root", ClientIP: "10.0.0.7"}

// Scenario: admin 綁定 → 快照為空 → 首登補上，且 users 本體不變
func TestAdminBoundIdentitySnapshotEmptyUntilFirstLogin(t *testing.T) {
	login, _, db := setupOIDCEnv(t)
	p := seedProvider(t, db, nil) // 出廠即 prebound_only：本情境的正常組態
	users := NewUserService(db, authz.NewAssetAuthorizationService(db))

	// 本地帳號（有密碼、非影子供應）——admin 綁定外部身分的典型對象
	alice := &model.User{Username: "alice", Password: "local-hash", Active: true}
	if err := db.Create(alice).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}

	dto, err := users.BindExternalIdentity(alice.ID, p.ID, "sub-ext-1", snapshotActor)
	if err != nil {
		t.Fatalf("綁定應成功: %v", err)
	}
	if dto.ClaimUsername != "" || dto.ClaimEmail != "" {
		t.Errorf("綁定回應的快照 = %q/%q，應為空——admin 綁定時我方尚未見過任何 id_token，"+
			"填入我方輸入會使「IdP 自報值」的語義失真",
			dto.ClaimUsername, dto.ClaimEmail)
	}

	var row model.UserExternalIdentity
	if err := db.First(&row, dto.ID).Error; err != nil {
		t.Fatalf("讀回身分列: %v", err)
	}
	if row.ClaimUsername != "" || row.ClaimEmail != "" || row.LastLoginAt != nil {
		t.Errorf("落庫的快照 = %q/%q（last_login=%v），綁定不得寫入任何 IdP 自報值",
			row.ClaimUsername, row.ClaimEmail, row.LastLoginAt)
	}

	// 首次登入：以該身分回訪
	resolved, err := login.resolveOrProvision(p, oidcClaims("sub-ext-1", map[string]any{
		"preferred_username": "a.chen",
		"email":              "a.chen@corp.example",
		"email_verified":     true,
		"name":               "Alice Chen",
	}), &oidcAuditTrail{})
	if err != nil {
		t.Fatalf("已綁定身分的首登應成功: %v", err)
	}
	if resolved.ID != alice.ID {
		t.Fatalf("登入解析到 user %d，應為既有帳號 %d", resolved.ID, alice.ID)
	}

	// 快照補上
	list, err := users.ListExternalIdentities(alice.ID)
	if err != nil {
		t.Fatalf("列出外部身分: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("外部身分數 = %d, want 1", len(list))
	}
	got := list[0]
	if got.ClaimUsername != "a.chen" {
		t.Errorf("claim_username = %q, want a.chen（首登後由 touchIdentity 補上）", got.ClaimUsername)
	}
	if got.ClaimEmail != "a.chen@corp.example" {
		t.Errorf("claim_email = %q, want a.chen@corp.example", got.ClaimEmail)
	}
	if got.LastLoginAt == nil {
		t.Error("last_login_at 應於首登後填入")
	}
	if got.ProviderName != p.Name {
		t.Errorf("provider_name = %q, want %q（列表須帶出 provider 實例名）", got.ProviderName, p.Name)
	}

	// users 本體不變：快照是 IdP 自報值，本體是授權主體識別，兩者不得互相污染
	var reloaded model.User
	if err := db.First(&reloaded, alice.ID).Error; err != nil {
		t.Fatalf("讀回使用者: %v", err)
	}
	if reloaded.Username != "alice" {
		t.Errorf("本體 username = %q，應保持 alice（IdP 自報 a.chen 不得改寫本體）", reloaded.Username)
	}
	if reloaded.Password != "local-hash" {
		t.Error("本體密碼雜湊被改寫——回訪不得觸碰本地憑證")
	}
	if reloaded.Email != nil {
		t.Errorf("本體 email = %v，回訪不得寫入", *reloaded.Email)
	}
	if reloaded.FullName != "" {
		t.Errorf("本體 full_name = %q，回訪不得寫入", reloaded.FullName)
	}
}

// Scenario: 未驗證的 email 不入快照（快照被當作 IdP 現況顯示）
func TestIdentitySnapshotOmitsUnverifiedEmail(t *testing.T) {
	login, _, db := setupOIDCEnv(t)
	p := seedProvider(t, db, nil)
	user := seedOIDCUser(t, db, "bob")
	seedIdentity(t, db, user, p, "sub-ext-2")

	if _, err := login.resolveOrProvision(p, oidcClaims("sub-ext-2", map[string]any{
		"preferred_username": "bob.x",
		"email":              "spoofed@corp.example",
		"email_verified":     false,
	}), &oidcAuditTrail{}); err != nil {
		t.Fatalf("回訪應成功: %v", err)
	}

	var row model.UserExternalIdentity
	if err := db.Where("subject = ?", "sub-ext-2").First(&row).Error; err != nil {
		t.Fatalf("讀回身分列: %v", err)
	}
	if row.ClaimUsername != "bob.x" {
		t.Errorf("claim_username = %q, want bob.x", row.ClaimUsername)
	}
	if row.ClaimEmail != "" {
		t.Errorf("claim_email = %q，未驗證的 email 不得入快照——管理端會把快照當成"+
			"IdP 現況，未驗證值等於讓使用者自行決定要顯示成誰", row.ClaimEmail)
	}
}

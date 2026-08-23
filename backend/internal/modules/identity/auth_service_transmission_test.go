package identity

import (
	"errors"
	"github.com/custodexa/backend/internal/modules/policy"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// setupLDAPGateEnv LDAP 登入傳輸閘測試環境：
// 真 sqlite 換入 database.DB（登入全流程真跑），LDAP 以 fake 替身控制。
//
// **目錄設定遷入 DB 之後只換注入形狀**：同一份 view 同時餵給登入
// resolver（產出 Risks）與清冊 provider（供 TransmissionPolicyService），
// 與生產組裝「閘與撥號同源」的形狀一致；行為斷言全數未改
func setupLDAPGateEnv(t *testing.T, view policy.LDAPRiskView) (*AuthService, *policy.SecurityPolicyService, *gorm.DB, *fakeLDAPAuthenticator) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	if err := db.AutoMigrate(&model.User{}, &model.Role{}, &model.RefreshToken{},
		&model.AuditLog{}, &model.SecurityPolicy{}, &model.PasswordHistory{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	// 影子用戶供應需要預設 user 角色
	if err := db.Create(&model.Role{Name: model.RoleUser}).Error; err != nil {
		t.Fatalf("seed role: %v", err)
	}
	oldDB := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = oldDB })

	authService := NewAuthService("test-secret", 15*time.Minute)
	fake := &fakeLDAPAuthenticator{info: &LDAPUserInfo{Username: "ldapuser", FullName: "LDAP User"}}
	authService.SetLDAPResolver(riskyLDAPResolver(fake, view))
	policies := policy.NewSecurityPolicyService(db)
	authService.SetTransmissionPolicy(policy.NewTransmissionPolicyService(policies, ldapRiskProvider(view)))
	return authService, policies, db, fake
}

func countTransmissionAudit(t *testing.T, db *gorm.DB, status model.AuditStatus) int64 {
	t.Helper()
	var n int64
	if err := db.Model(&model.AuditLog{}).
		Where("resource = ? AND status = ?", model.ResourceTransmission, status).
		Count(&n).Error; err != nil {
		t.Fatalf("count: %v", err)
	}
	return n
}

var plaintextLDAP = policy.LDAPRiskView{Enabled: true, URL: "ldap://dir.internal:389"}

// off（出廠預設）：明文通道照常登入、無任何傳輸審計——零影響
func TestLDAPGateOffZeroImpact(t *testing.T) {
	authService, _, db, _ := setupLDAPGateEnv(t, plaintextLDAP)

	resp, err := authService.Login(&LoginRequest{Username: "ldapuser", Password: "pass123"})
	if err != nil {
		t.Fatalf("off 檔 LDAP 登入應成功: %v", err)
	}
	if resp.AuthSource != model.AuthSourceLDAP {
		t.Errorf("auth_source = %q, want ldap", resp.AuthSource)
	}
	if n := countTransmissionAudit(t, db, model.StatusSuccess) + countTransmissionAudit(t, db, model.StatusDenied); n != 0 {
		t.Errorf("off 檔不應有傳輸審計, got %d", n)
	}
}

// warn＋ldap:// 明文：登入放行，每次成功登入落偏離審計；無同意對話框介入
func TestLDAPGateWarnLogsDeviation(t *testing.T) {
	authService, policies, db, _ := setupLDAPGateEnv(t, plaintextLDAP)
	policies.Update(policy.PolicyTransportLDAPLevel, policy.TransportLevelWarn, "admin")

	if _, err := authService.Login(&LoginRequest{Username: "ldapuser", Password: "pass123"}); err != nil {
		t.Fatalf("warn 檔登入應放行: %v", err)
	}
	if n := countTransmissionAudit(t, db, model.StatusSuccess); n != 1 {
		t.Fatalf("偏離審計筆數 = %d, want 1", n)
	}

	// 再登入一次：每次登入各落一筆
	if _, err := authService.Login(&LoginRequest{Username: "ldapuser", Password: "pass123"}); err != nil {
		t.Fatalf("第二次登入: %v", err)
	}
	if n := countTransmissionAudit(t, db, model.StatusSuccess); n != 2 {
		t.Errorf("偏離審計筆數 = %d, want 2（每次登入一筆）", n)
	}
}

// strict＋ldaps+SkipTLSVerify：拒絕且撥號前擋下（密碼不出門）＋拒絕入審計
func TestLDAPGateStrictRejectsBeforeDial(t *testing.T) {
	authService, policies, db, fake := setupLDAPGateEnv(t, policy.LDAPRiskView{
		Enabled: true, URL: "ldaps://dir.internal:636", SkipTLSVerify: true,
	})
	policies.Update(policy.PolicyTransportLDAPLevel, policy.TransportLevelStrict, "admin")

	_, err := authService.Login(&LoginRequest{Username: "ldapuser", Password: "pass123"})
	if !errors.Is(err, ErrLDAPTransportRejected) {
		t.Fatalf("err = %v, want ErrLDAPTransportRejected", err)
	}
	if fake.calls != 0 {
		t.Errorf("strict 拒絕應在撥號前，目錄呼叫次數 = %d, want 0", fake.calls)
	}
	if n := countTransmissionAudit(t, db, model.StatusDenied); n != 1 {
		t.Errorf("拒絕審計筆數 = %d, want 1", n)
	}
}

// strict 下本地帳號完全不受影響（bcrypt 路徑不經 LDAP 閘；admin 可登入調回政策）
func TestLDAPGateStrictLocalAccountUnaffected(t *testing.T) {
	authService, policies, db, fake := setupLDAPGateEnv(t, plaintextLDAP)
	policies.Update(policy.PolicyTransportLDAPLevel, policy.TransportLevelStrict, "admin")

	hashed, err := bcrypt.GenerateFromPassword([]byte("localpass123"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&model.User{
		Username: "localadmin", Password: string(hashed), Active: true,
	}).Error; err != nil {
		t.Fatalf("seed local user: %v", err)
	}

	resp, err := authService.Login(&LoginRequest{Username: "localadmin", Password: "localpass123"})
	if err != nil {
		t.Fatalf("strict 下本地登入應成功: %v", err)
	}
	if resp.Token == "" {
		t.Error("本地登入應取得 token")
	}
	if fake.calls != 0 {
		t.Errorf("本地路徑不應打目錄, calls = %d", fake.calls)
	}
	// ldaps 正常通道（無風險）時 strict 也不擋 LDAP 登入
	authService2, policies2, _, _ := setupLDAPGateEnv(t, policy.LDAPRiskView{
		Enabled: true, URL: "ldaps://dir.internal:636",
	})
	policies2.Update(policy.PolicyTransportLDAPLevel, policy.TransportLevelStrict, "admin")
	if _, err := authService2.Login(&LoginRequest{Username: "ldapuser", Password: "pass123"}); err != nil {
		t.Errorf("無風險通道 strict 不應擋 LDAP 登入: %v", err)
	}
}

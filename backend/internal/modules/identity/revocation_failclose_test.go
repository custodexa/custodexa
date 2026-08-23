package identity

import (
	"errors"
	"testing"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/pkg/crypto"
	"gorm.io/gorm"
)

// 撤銷／不變式的 fail-close 補洞（~ F-E）。
//
// 五項的共同形態都是「判定用的輸入比實際能力寬」：計數把不能登入的列算進去、
// 判準把不能用的身分算進去、簽發用的世代比驗證過的世代新、閘門把不一致的
// 脈絡當成安全組合、撤銷失敗卻回報成功。每一項單獨看都只是少一個條件，
// 合起來則是「停用/解綁看似生效、實際沒生效」。

// --- F-A：本地 admin 計數須要求密碼可用 ---

// TestCountLocalAdminsExcludesEmptyPasswordDrift 空密碼的漂移列不得計為本地 admin。
//
// 漂移列＝external_credential=false 但密碼為空字串（任一建號路徑漏設旗標即成立，
// oidc_invariant_matrix_test.go 的橫向守衛正是為了偵測它）。此類列**無法以本地
// 密碼登入**，卻墊高計數：兩列時 total=2，移除唯一的真 admin 被判為 2→1 而放行，
// 系統實際落入零個可登入的本地 admin——遇 KEK 重啟即無人能解封。
func TestCountLocalAdminsExcludesEmptyPasswordDrift(t *testing.T) {
	db := localAdminDB(t)
	real := seedAccount(t, db, adminSpec{username: "real-admin", admin: true, active: true})
	drift := seedAccount(t, db, adminSpec{username: "drift-admin", admin: true, active: true})
	if err := db.Model(&model.User{}).Where("id = ?", drift.ID).
		Update("password", "").Error; err != nil {
		t.Fatalf("製造漂移列: %v", err)
	}

	if n := mustCountLocalAdmins(t, db); n != 1 {
		t.Errorf("CountLocalAdmins = %d, want 1（空密碼列不可計入）", n)
	}

	// 不變式與計數同源：移除唯一可用的本地 admin 必須被拒
	err := WithLocalAdminInvariant(db, real.ID, func(tx *gorm.DB) error { return nil })
	if !errors.Is(err, ErrLastLocalAdmin) {
		t.Errorf("移除最後一個可登入的本地 admin = %v, want ErrLastLocalAdmin", err)
	}

	// 漂移列本身不是本地 admin，對它的操作不受不變式限制（不得反向誤擋）
	if err := WithLocalAdminInvariant(db, drift.ID, func(tx *gorm.DB) error { return nil }); err != nil {
		t.Errorf("對漂移列的操作 = %v, want nil（它本就不計為本地 admin）", err)
	}
}

// TestCountLocalAdminsExcludesWhitespaceOnlyPassword 僅含空白的密碼同樣不可用。
// 與 hasLoginPathAfterUnbind 的 strings.TrimSpace 判準保持同一寬嚴度
func TestCountLocalAdminsExcludesWhitespaceOnlyPassword(t *testing.T) {
	db := localAdminDB(t)
	seedAccount(t, db, adminSpec{username: "real-admin", admin: true, active: true})
	blank := seedAccount(t, db, adminSpec{username: "blank-admin", admin: true, active: true})
	if err := db.Model(&model.User{}).Where("id = ?", blank.ID).
		Update("password", "   ").Error; err != nil {
		t.Fatalf("製造空白密碼列: %v", err)
	}
	if n := mustCountLocalAdmins(t, db); n != 1 {
		t.Errorf("CountLocalAdmins = %d, want 1（空白密碼列不可計入）", n)
	}
}

// --- F-B：登入途徑判準須要求身分所屬 provider 仍可用 ---

// disableProvider 停用 provider（模擬管理者停用）
func disableProvider(t *testing.T, db *gorm.DB, p *model.OIDCProvider) {
	t.Helper()
	if err := db.Model(&model.OIDCProvider{}).Where("id = ?", p.ID).
		Update("enabled", false).Error; err != nil {
		t.Fatalf("停用 provider: %v", err)
	}
}

// TestUnbindRejectsWhenRemainingIdentityProviderDisabled 剩餘身分屬於已停用 provider
// 時，解綁必須被拒——該身分無法登入，放行等於製造零登入途徑的孤兒帳號
func TestUnbindRejectsWhenRemainingIdentityProviderDisabled(t *testing.T) {
	db := extIdentityDB(t)
	env := newExtIdentityEnv(t, db)
	u := seedAccount(t, db, adminSpec{username: "ext-only", active: true, extCred: true})
	live := seedExtProvider(t, db, "live", "https://live.example.com", "cid-live")
	dead := seedExtProvider(t, db, "dead", "https://dead.example.com", "cid-dead")
	idLive := mustBind(t, env, u.ID, live, "sub-live")
	mustBind(t, env, u.ID, dead, "sub-dead")
	disableProvider(t, db, dead)

	if err := env.svc.UnbindExternalIdentity(u.ID, idLive, testActor); !errors.Is(err, ErrLastLoginPath) {
		t.Fatalf("解綁唯一可用身分 = %v, want ErrLastLoginPath", err)
	}
	if n := identityCount(t, db, u.ID); n != 2 {
		t.Errorf("被拒的解綁不得有副作用：身分數 = %d, want 2", n)
	}
}

// TestUnbindRejectsWhenRemainingIdentityProviderDeleted 同上，provider 已軟刪
func TestUnbindRejectsWhenRemainingIdentityProviderDeleted(t *testing.T) {
	db := extIdentityDB(t)
	env := newExtIdentityEnv(t, db)
	u := seedAccount(t, db, adminSpec{username: "ext-only", active: true, extCred: true})
	live := seedExtProvider(t, db, "live", "https://live.example.com", "cid-live")
	gone := seedExtProvider(t, db, "gone", "https://gone.example.com", "cid-gone")
	idLive := mustBind(t, env, u.ID, live, "sub-live")
	mustBind(t, env, u.ID, gone, "sub-gone")
	if err := db.Delete(&model.OIDCProvider{}, gone.ID).Error; err != nil {
		t.Fatalf("軟刪 provider: %v", err)
	}

	if err := env.svc.UnbindExternalIdentity(u.ID, idLive, testActor); !errors.Is(err, ErrLastLoginPath) {
		t.Fatalf("解綁唯一可用身分（另一 provider 已刪）= %v, want ErrLastLoginPath", err)
	}
}

// TestUnbindAllowedWhenRemainingIdentityProviderEnabled 對照組：剩餘身分的 provider
// 仍啟用時必須放行（收緊判準不得把正常情境一併擋掉）
func TestUnbindAllowedWhenRemainingIdentityProviderEnabled(t *testing.T) {
	db := extIdentityDB(t)
	env := newExtIdentityEnv(t, db)
	u := seedAccount(t, db, adminSpec{username: "ext-only", active: true, extCred: true})
	pa := seedExtProvider(t, db, "a", "https://a.example.com", "cid-a")
	pb := seedExtProvider(t, db, "b", "https://b.example.com", "cid-b")
	idA := mustBind(t, env, u.ID, pa, "sub-a")
	mustBind(t, env, u.ID, pb, "sub-b")

	if err := env.svc.UnbindExternalIdentity(u.ID, idA, testActor); err != nil {
		t.Fatalf("剩餘身分屬啟用中 provider，解綁 = %v, want nil", err)
	}
	if n := identityCount(t, db, u.ID); n != 1 {
		t.Errorf("解綁後身分數 = %d, want 1", n)
	}
}

// TestConvertToExternalOnlyRejectsUnusableIdentity 「改為僅外部登入」的前提同樣
// 須為可用身分：僅有的身分屬已停用 provider 時轉換必被拒，否則清掉密碼當下
// 即製造零登入途徑的孤兒帳號
func TestConvertToExternalOnlyRejectsUnusableIdentity(t *testing.T) {
	db := extIdentityDB(t)
	env := newExtIdentityEnv(t, db)
	u := seedAccount(t, db, adminSpec{username: "local-user", active: true})
	dead := seedExtProvider(t, db, "dead", "https://dead.example.com", "cid-dead")
	mustBind(t, env, u.ID, dead, "sub-dead")
	disableProvider(t, db, dead)

	if err := env.svc.ConvertToExternalOnly(u.ID, testActor); !errors.Is(err, ErrExternalIdentityRequired) {
		t.Fatalf("僅有不可用身分時轉換 = %v, want ErrExternalIdentityRequired", err)
	}
	after := reloadUser(t, db, u.ID)
	if after.ExternalCredential || after.Password == "" {
		t.Error("被拒的轉換不得有副作用（旗標與密碼皆應保持原狀）")
	}
}

// TestConvertToExternalOnlyAllowsUsableIdentity 對照組：身分屬啟用中 provider 時放行
func TestConvertToExternalOnlyAllowsUsableIdentity(t *testing.T) {
	db := extIdentityDB(t)
	env := newExtIdentityEnv(t, db)
	u := seedAccount(t, db, adminSpec{username: "local-user", active: true})
	live := seedExtProvider(t, db, "live", "https://live.example.com", "cid-live")
	mustBind(t, env, u.ID, live, "sub-live")

	if err := env.svc.ConvertToExternalOnly(u.ID, testActor); err != nil {
		t.Fatalf("身分屬啟用中 provider，轉換 = %v, want nil", err)
	}
	after := reloadUser(t, db, u.ID)
	if !after.ExternalCredential || after.Password != "" {
		t.Errorf("轉換後 external_credential=%v password=%q, want true/空", after.ExternalCredential, after.Password)
	}
}

// --- F-C：輪替後的 access token 須沿用 refresh 列自身的世代 ---

// TestRefreshSignsAccessWithRowGeneration 交易內驗過的世代與簽發用的世代必須同源。
//
// 缺陷形態：交易內以 refresh 列的世代驗證通過 → 交易外改以「現查 DB」的世代簽 access。
// 兩步之間若世代被推進（改密／停用／解綁／provider 輪替），簽出的 token 會帶
// **新**世代而通過後續所有驗證點——該次刷新等於把舊能力洗白。
// 修正後非競態情況兩者相等（交易剛驗過），競態下則簽出舊世代而立即失效＝fail-close。
func TestRefreshSignsAccessWithRowGeneration(t *testing.T) {
	auth, _, db := setupLockoutEnv(t)
	user := seedLockoutUser(t, db, "right-pass-1")
	first := loginForRefresh(t, auth, "bob", "right-pass-1")

	var row model.RefreshToken
	if err := db.Where("user_id = ?", user.ID).First(&row).Error; err != nil {
		t.Fatalf("load refresh row: %v", err)
	}

	// 於「輪替交易已提交、access 尚未簽發」的精確位置推進世代（確定性重現競態）
	prev := refreshPostRotateHook
	refreshPostRotateHook = func() {
		if err := db.Model(&model.User{}).Where("id = ?", user.ID).
			UpdateColumn("credential_epoch", gorm.Expr("credential_epoch + 1")).Error; err != nil {
			t.Errorf("推進世代: %v", err)
		}
	}
	t.Cleanup(func() { refreshPostRotateHook = prev })

	resp, err := auth.RefreshSession(first.RefreshToken)
	if err != nil {
		t.Fatalf("刷新 = %v, want nil", err)
	}
	claims, err := auth.ValidateToken(resp.Token)
	if err != nil {
		t.Fatalf("驗證換發的 access = %v", err)
	}
	if claims.CredEpoch != row.CredEpoch {
		t.Errorf("access token 的 cred_epoch = %d, want %d（refresh 列自身的世代）",
			claims.CredEpoch, row.CredEpoch)
	}
	// 該 token 對推進後的現值必然不符 → 立即失效（正確的 fail-close）
	if err := epochGateForTest.VerifyCredentialGenerationByUserID(claims.AuthContext, user.ID); !errors.Is(err, ErrCredentialGenerationStale) {
		t.Errorf("競態下換發的 token 世代閘 = %v, want ErrCredentialGenerationStale", err)
	}
}

// TestRefreshNonRacyKeepsTokenUsable 對照組：無競態時換發的 token 必須可用
// （沿用列世代不得使正常刷新出來的 token 當場失效）
func TestRefreshNonRacyKeepsTokenUsable(t *testing.T) {
	auth, _, db := setupLockoutEnv(t)
	user := seedLockoutUser(t, db, "right-pass-1")
	first := loginForRefresh(t, auth, "bob", "right-pass-1")

	resp, err := auth.RefreshSession(first.RefreshToken)
	if err != nil {
		t.Fatalf("刷新 = %v, want nil", err)
	}
	claims, err := auth.ValidateToken(resp.Token)
	if err != nil {
		t.Fatalf("驗證換發的 access = %v", err)
	}
	if err := epochGateForTest.VerifyCredentialGenerationByUserID(claims.AuthContext, user.ID); err != nil {
		t.Errorf("正常刷新換發的 token 世代閘 = %v, want nil", err)
	}
	_ = db
}

// --- F-D：世代閘須拒絕 oidc 方法卻無 provider 的脈絡 ---

// TestEpochGateRejectsOIDCWithoutProvider EffectiveMethod()==oidc 但 ProviderID==0
// 是不可能由任何簽發點產生的組合（issueTicket 一律寫入 freshProvider.ID）。
// 放行等於讓構造此組合的 token 被當成本地登入，跳過全部 provider 撤銷
func TestEpochGateRejectsOIDCWithoutProvider(t *testing.T) {
	db := localAdminDB(t)
	user := &model.User{CredentialEpoch: 0}

	err := VerifyCredentialGenerationTx(db, crypto.AuthContext{
		AuthMethod: crypto.AuthMethodOIDC, ProviderID: 0}, user)
	if !errors.Is(err, ErrCredentialGenerationStale) {
		t.Fatalf("oidc 但無 provider = %v, want ErrCredentialGenerationStale", err)
	}
}

// TestEpochGateAcceptsUpgradeEraAndLocalContexts 不得誤傷：升級期舊 token 的
// AuthMethod 為空（EffectiveMethod() 回 local_password），與本地／LDAP 一樣
// 天然帶 ProviderID=0，必須續放行
func TestEpochGateAcceptsUpgradeEraAndLocalContexts(t *testing.T) {
	db := localAdminDB(t)
	user := &model.User{CredentialEpoch: 0}

	cases := map[string]crypto.AuthContext{
		"升級期舊 token（AuthMethod 空）": {},
		"本地密碼":                     {AuthMethod: crypto.AuthMethodLocalPassword},
		"LDAP":                     {AuthMethod: crypto.AuthMethodLDAP},
	}
	for name, ctx := range cases {
		if err := VerifyCredentialGenerationTx(db, ctx, user); err != nil {
			t.Errorf("%s = %v, want nil", name, err)
		}
	}
}

// --- F-E：reuse detection 的家族撤銷失敗不得回報成功 ---

// failFamilyRevoke 讓「家族撤銷」的 UPDATE 失敗（其餘 refresh 寫入不受影響）。
// 以 gorm callback 精準命中 revoked_reason=reuse_detected 的更新
func failFamilyRevoke(t *testing.T, db *gorm.DB) {
	t.Helper()
	const name = "test:fail_family_revoke"
	err := db.Callback().Update().Before("gorm:update").Register(name, func(tx *gorm.DB) {
		dest, ok := tx.Statement.Dest.(map[string]interface{})
		if !ok {
			return
		}
		if dest["revoked_reason"] == model.RefreshRevokeReuseDetected {
			tx.AddError(errors.New("模擬 DB 短暫失敗"))
		}
	})
	if err != nil {
		t.Fatalf("register callback: %v", err)
	}
	t.Cleanup(func() { _ = db.Callback().Update().Remove(name) })
}

// TestReuseDetectionFailClosesWhenRevokeFails 家族撤銷失敗時必須回錯。
//
// 舊行為只記日誌卻回 RefreshReuseError，handler 據以寫下「已撤銷該使用者全部
// refresh」的審計——但攻擊者持有的分叉鏈其實還活著，稽核紀錄與現實相反，
// 且無任何訊號促使運維重試
func TestReuseDetectionFailClosesWhenRevokeFails(t *testing.T) {
	auth, _, db := setupLockoutEnv(t)
	user := seedLockoutUser(t, db, "right-pass-1")
	first := loginForRefresh(t, auth, "bob", "right-pass-1")
	if _, err := auth.RefreshSession(first.RefreshToken); err != nil {
		t.Fatalf("首次刷新: %v", err)
	}

	failFamilyRevoke(t, db)

	_, err := auth.RefreshSession(first.RefreshToken) // 重放已 rotated 憑證
	var revokeErr *RefreshFamilyRevokeError
	if !errors.As(err, &revokeErr) {
		t.Fatalf("撤銷失敗時 = %v, want RefreshFamilyRevokeError", err)
	}
	if revokeErr.UserID != user.ID {
		t.Errorf("RefreshFamilyRevokeError.UserID = %d, want %d", revokeErr.UserID, user.ID)
	}
	var reuse *RefreshReuseError
	if errors.As(err, &reuse) {
		t.Error("撤銷失敗不得回報為「已撤銷」的 reuse 事件（審計會寫下與現實相反的紀錄）")
	}
}

// TestReuseDetectionSucceedsWhenRevokeWorks 對照組：撤銷成功時維持既有語義
func TestReuseDetectionSucceedsWhenRevokeWorks(t *testing.T) {
	auth, _, db := setupLockoutEnv(t)
	user := seedLockoutUser(t, db, "right-pass-1")
	first := loginForRefresh(t, auth, "bob", "right-pass-1")
	if _, err := auth.RefreshSession(first.RefreshToken); err != nil {
		t.Fatalf("首次刷新: %v", err)
	}

	_, err := auth.RefreshSession(first.RefreshToken)
	var reuse *RefreshReuseError
	if !errors.As(err, &reuse) {
		t.Fatalf("撤銷成功時 = %v, want RefreshReuseError", err)
	}
	var revoked int64
	db.Model(&model.RefreshToken{}).
		Where("user_id = ? AND revoked_reason = ?", user.ID, model.RefreshRevokeReuseDetected).
		Count(&revoked)
	if revoked == 0 {
		t.Error("撤銷成功應留下 reuse_detected 標記")
	}
}

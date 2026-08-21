package identity

import (
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// 本檔為 characterization 測試（ldap-settings-migration tasks.md 2.12 / design.md D9、D7）：
// 釘住三條「既有的、非本 change 引入」的結構性行為，供本 change 把 LDAP 設定
// 自 env 遷到 DB＋UI 後，回歸驗證這些不變式未被動到。三條皆有現況即可、不代表
// 理想設計——第三條屬已知殘留（design.md D7「殘留誠實記載」），修法記 backlog。

// ---------------------------------------------------------------------------
// 不變式一：本地帳號不可被目錄接管
// ---------------------------------------------------------------------------
//
// verifyCredentials（auth_service.go:344-385）的 switch 分支序保證：
// 本地查到「非 is_ldap 且非 external」的帳號時恆走 bcrypt 路徑（case 二），
// LDAP 路徑（default case）僅在「帳號 is_ldap」或「查無此帳號」時可達。
// 這代表本地帳號（含 admin）在分支序上就不可能落入 LDAP 驗證——不靠
// 「硬編排除 admin」這類名單式防護，而是靠分支序天然保證。
//
// 本測試刻意讓 fake LDAP authenticator「會成功」（模擬攻擊者已完全控制/
// 冒名目錄伺服器，能以任意帳密通過目錄驗證），驗證即便如此，本地非 is_ldap
// 帳號仍只吃本地密碼比對結果，且目錄從未被呼叫——證明的是分支「不可達」，
// 不是「剛好目錄那次沒被打贏」。
func TestCharacterization_LocalAccountNeverReachesLDAPPath(t *testing.T) {
	_, mock, _ := setupAuthMockDB(t)
	authService := NewAuthService("secret", 15*time.Minute)

	// fake 目錄：對任何帳密都放行，模擬「目錄已被攻擊者接管，會冒充 admin 通過驗證」
	fake := &fakeLDAPAuthenticator{info: &LDAPUserInfo{Username: "admin"}}
	authService.SetLDAPResolver(staticLDAPResolver(fake))

	correctPassword := "correct-local-password"
	hashed, err := bcrypt.GenerateFromPassword([]byte(correctPassword), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("bcrypt hash 失敗: %v", err)
	}

	// 本地帳號：is_ldap=false、非 external（ldapUserRows 未填 external_credential/
	// provisioning_origin 欄位，GORM 零值 false/"" 使 IsExternal() 為 false）
	mock.ExpectQuery(`SELECT .+ FROM "users" WHERE username`).
		WillReturnRows(ldapUserRows(1, "admin", "admin@example.com", true, false, false, string(hashed)))
	expectEmptyRolesPreload(mock)

	// 密碼故意給錯（非 correctPassword）：若分支序被破壞而落入 LDAP 路徑，
	// fake 會放行、Login 會成功——藉此讓「分支序錯誤」這個突變可觀測
	resp, err := authService.Login(&LoginRequest{Username: "admin", Password: "wrong-password"})

	assert.Nil(t, resp)
	assert.Equal(t, ErrInvalidCredentials, err)
	assert.Equal(t, 0, fake.calls, "本地非 is_ldap 帳號登入時，LDAP 分支必須完全不可達（即使目錄會放行）")
	assert.NoError(t, mock.ExpectationsWereMet())
}

// ---------------------------------------------------------------------------
// 不變式二：username 查詢大小寫敏感 -> 目錄側大小寫變體供應獨立影子帳號
// ---------------------------------------------------------------------------
//
// verifyCredentials 以 `Where("username = ?", req.Username)` 查詢（既有行為，
// 非本 change 引入），未對輸入做大小寫正規化（不 lower()/upper()、不用
// ILIKE），故若本地已有帳號「admin」，目錄側存在「Admin」時查詢視為查無
// 此帳號 -> 落入 LDAP 分支 -> 供應一個獨立影子帳號，而非合併/接管既有
// 本地 admin。影子帳號預設 user 角色、無提權，本身不構成安全問題；
// 這條測試釘住的是「現況如此」，防日後有人為了「大小寫不敏感更友善」
// 把查詢改成 LOWER()/ILIKE，從而讓分支序（不變式一）的前提被破壞。
func TestCharacterization_CaseVariantUsernameGetsIndependentShadowAccount(t *testing.T) {
	_, mock, _ := setupAuthMockDB(t)
	authService := NewAuthService("secret", 15*time.Minute)

	fake := &fakeLDAPAuthenticator{info: &LDAPUserInfo{
		Username: "Admin", // 目錄端回報的帳號名與本地既有的 "admin" 大小寫不同
		Email:    "directory-admin@example.org",
		FullName: "Directory Admin",
	}}
	authService.SetLDAPResolver(staticLDAPResolver(fake))

	// 大小寫敏感查詢：查 "Admin" 對不到本地既有的 "admin" 列 -> 視為查無帳號
	mock.ExpectQuery(`SELECT .+ FROM "users" WHERE username`).
		WillReturnError(gorm.ErrRecordNotFound)

	mock.ExpectQuery(`SELECT count\(\*\) FROM "users"`).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))

	mock.ExpectBegin()
	mock.ExpectQuery(`INSERT INTO "users"`).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(99))
	mock.ExpectQuery(`SELECT .+ FROM "roles" WHERE name`).
		WillReturnRows(sqlmock.NewRows([]string{"id", "name"}).AddRow(2, "user"))
	mock.ExpectExec(`INSERT INTO user_roles`).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	expectFinishLoginUpdate(mock)

	resp, err := authService.Login(&LoginRequest{Username: "Admin", Password: "directory-password"})

	assert.NoError(t, err)
	if assert.NotNil(t, resp) {
		// 帳號名原樣保留大小寫，不與本地 "admin" 合併為同一身分
		assert.Equal(t, "Admin", resp.User.Username)
		// 影子帳號只拿預設 user 角色，不因帳號名撞近本地 admin 而提權
		assert.Equal(t, []string{"user"}, resp.User.Roles)
		assert.Equal(t, "ldap", resp.AuthSource)
	}
	assert.Equal(t, 1, fake.calls)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// ---------------------------------------------------------------------------
// 不變式三（已知殘留，design.md D7/D9 明載）：影子帳號名取自請求端輸入，
// 而非目錄 entry 的屬性
// ---------------------------------------------------------------------------
//
// 鏈路：AuthService.provisionShadowUser（auth_service.go:637 一帶）直接採用
// LDAPAuthenticator 回傳的 LDAPUserInfo.Username，不做任何二次查證或改採
// email/fullname 等其他欄位衍生帳號名。而真實實作 ldap_authenticator.go 的
// Authenticate()（74-78 行一帶）建構 LDAPUserInfo 時寫的是
// `Username: username`——這個 username 是登入請求的原始輸入參數，
// 不是從目錄 entry 讀出的屬性（entry 只貢獻 Email/FullName）。
//
// 本測試在 AuthService 這一端釘住「provisionShadowUser 信任 info.Username
// 原樣入庫，不受 Email/FullName 影響」；配合上述 ldap_authenticator.go 的
// 既有事實（未變、非本測試檔可驗證範圍），完整鏈路即為「影子帳號名＝
// 請求端輸入」。這是已知殘留（filter 驗證只是縱深防禦而非完整封閉，
// design.md D7），根本修法（以 entry 穩定屬性回填帳號名）記 backlog、
// 不在本 change 範圍——測試釘住的是「現況如此」，供未來變更時能明確
// 看到行為改變。
func TestCharacterization_ShadowUsernameComesFromRequestInputNotDirectoryAttributes(t *testing.T) {
	_, mock, _ := setupAuthMockDB(t)
	authService := NewAuthService("secret", 15*time.Minute)

	const requestUsername = "shadow-login-name"

	// Email/FullName 刻意與 Username 完全無關聯，藉此排除「帳號名其實是從
	// email local-part 或 fullname 衍生」的另一種可能實作
	fake := &fakeLDAPAuthenticator{info: &LDAPUserInfo{
		Username: requestUsername,
		Email:    "totally.unrelated@example.org",
		FullName: "Totally Unrelated Person",
	}}
	authService.SetLDAPResolver(staticLDAPResolver(fake))

	mock.ExpectQuery(`SELECT .+ FROM "users" WHERE username`).
		WillReturnError(gorm.ErrRecordNotFound)

	mock.ExpectQuery(`SELECT count\(\*\) FROM "users"`).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))

	mock.ExpectBegin()
	mock.ExpectQuery(`INSERT INTO "users"`).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(100))
	mock.ExpectQuery(`SELECT .+ FROM "roles" WHERE name`).
		WillReturnRows(sqlmock.NewRows([]string{"id", "name"}).AddRow(2, "user"))
	mock.ExpectExec(`INSERT INTO user_roles`).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	expectFinishLoginUpdate(mock)

	resp, err := authService.Login(&LoginRequest{Username: requestUsername, Password: "any-directory-password"})

	assert.NoError(t, err)
	if assert.NotNil(t, resp) {
		assert.Equal(t, requestUsername, resp.User.Username,
			"影子帳號名須恰為 LDAPUserInfo.Username（=登入請求輸入），不得受 Email/FullName 影響")
	}
	assert.Equal(t, 1, fake.calls)
	assert.NoError(t, mock.ExpectationsWereMet())
}

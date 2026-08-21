package identity

import (
	"testing"
	"time"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/policy"
	"github.com/custodexa/backend/pkg/crypto"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// === 登入後的密碼雜湊升級：**寫入行為**的 runtime 證據 ===
//
// 獨立驗收（2026-08-19）指出本路徑「靜態 PASS，runtime 證據＝零」，
// 且 `pkg/crypto/password_rehash_test.go` 的註解曾宣稱「寫入行為在 identity 側測試」
// ——**當時那個測試並不存在**。本檔補上，該註解同步訂正。
//
// `pkg/crypto` 側測的是**判定**（NeedsRehash 該不該回 true，含空 hash／外部化帳號
// 不升級、參數新舊比較等格）；本檔**只測判定測不到的那一半**——寫入。
//
// **刻意只留兩條**：「升級真的落到 DB」與「並發改密不被蓋掉」。
// 「歷史列不被動」與「外部化帳號跳過」的判定已由 crypto 側涵蓋，
// 在此重測一次只是換個地方跑同一段邏輯，不值那個測試時間。

func setupRehashEnv(t *testing.T) (*AuthService, *gorm.DB) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	if err := db.AutoMigrate(&model.User{}, &model.Role{}, &model.SecurityPolicy{},
		&model.PasswordHistory{}, &model.RefreshToken{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	oldDB := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = oldDB })

	auth := NewAuthService("test-secret", 15*time.Minute)
	auth.SetSecurityPolicies(policy.NewSecurityPolicyService(db))
	return auth, db
}

// seedRehashUser 建立一個以**舊參數**（較低 cost）雜湊的本地帳號，並寫入一筆密碼歷史。
func seedRehashUser(t *testing.T, db *gorm.DB, username, password string) *model.User {
	t.Helper()
	oldHash, err := crypto.NewBcryptHasher(crypto.BcryptMinCost).Hash([]byte(password))
	if err != nil {
		t.Fatalf("產生舊參數雜湊失敗: %v", err)
	}
	email := username + "@example.test"
	u := &model.User{
		Username: username, Email: &email, Password: oldHash, Active: true,
		ProvisioningOrigin: model.AuthSourceLocal,
	}
	if err := db.Create(u).Error; err != nil {
		t.Fatalf("建立帳號失敗: %v", err)
	}
	// 密碼歷史：後續要斷言它**不被**動到
	if err := db.Create(&model.PasswordHistory{UserID: u.ID, PasswordHash: oldHash}).Error; err != nil {
		t.Fatalf("建立密碼歷史失敗: %v", err)
	}
	return u
}

// TestLoginUpgradesLegacyHash 以舊參數雜湊登入 → 登入成功且雜湊被升級（tasks 6.4）。
//
// 這是漸進遷移**唯一**會實際發生的時機：登入成功是同時握有明文與該帳號雜湊的那一刻。
func TestLoginUpgradesLegacyHash(t *testing.T) {
	auth, db := setupRehashEnv(t)
	const password = "Rehash-Login-2026#a"
	u := seedRehashUser(t, db, "rehash-login", password)

	before := u.Password
	if !crypto.DefaultPasswordVerifier().NeedsRehash(before) {
		t.Fatal("前置條件不成立：seed 的雜湊未被判定為需升級，本測試將驗不到東西")
	}

	if _, err := auth.Login(&LoginRequest{Username: "rehash-login", Password: password}); err != nil {
		t.Fatalf("登入失敗: %v", err)
	}

	var after model.User
	if err := db.First(&after, u.ID).Error; err != nil {
		t.Fatalf("重讀帳號失敗: %v", err)
	}
	if after.Password == before {
		t.Error("登入成功但雜湊未被升級——漸進遷移不會發生，介面白抽了")
	}
	if crypto.DefaultPasswordVerifier().NeedsRehash(after.Password) {
		t.Error("升級後仍被判定為需升級——每次登入都會重寫")
	}
	// 升級後必須仍能驗證同一個密碼，否則使用者會被自己的密碼擋在門外
	if err := crypto.DefaultPasswordVerifier().Verify(after.Password, []byte(password)); err != nil {
		t.Errorf("升級後的雜湊無法驗證原密碼: %v", err)
	}
	if _, err := auth.Login(&LoginRequest{Username: "rehash-login", Password: password}); err != nil {
		t.Errorf("升級後再次登入失敗: %v——使用者被自己的密碼鎖在門外", err)
	}
}

// TestRehashDoesNotClobberConcurrentPasswordChange 條件 UPDATE 的實際效果。
//
// 情境：登入時判定需升級，但在寫回之前，該帳號的密碼已被改掉（並發改密）。
// 此時升級**必須作廢**——否則會把剛設好的新密碼蓋回舊的，使用者的改密靜默失效。
//
// 以「先改密碼、再拿舊快照呼叫升級」直接驅動該條件，
// 這正是 `WHERE id = ? AND password = ?` 要擋的那一格。
func TestRehashDoesNotClobberConcurrentPasswordChange(t *testing.T) {
	auth, db := setupRehashEnv(t)
	const oldPassword = "Rehash-Race-Old-2026#a"
	u := seedRehashUser(t, db, "rehash-race", oldPassword)
	staleSnapshot := *u // 保留舊雜湊的快照，模擬「登入時讀到的那一份」

	// 並發的改密先落地
	newHash, err := crypto.DefaultPasswordHasher().Hash([]byte("Rehash-Race-New-2026#b"))
	if err != nil {
		t.Fatalf("產生新密碼雜湊失敗: %v", err)
	}
	if err := db.Model(&model.User{}).Where("id = ?", u.ID).
		Update("password", newHash).Error; err != nil {
		t.Fatalf("模擬並發改密失敗: %v", err)
	}

	// 登入路徑此時才拿著舊快照嘗試升級
	auth.rehashPasswordIfNeeded(&staleSnapshot, []byte(oldPassword))

	var after model.User
	if err := db.First(&after, u.ID).Error; err != nil {
		t.Fatalf("重讀帳號失敗: %v", err)
	}
	if after.Password != newHash {
		t.Error("並發改密後的新密碼被雜湊升級蓋掉了——" +
			"使用者剛改的密碼會靜默失效，且他無從得知")
	}
	if err := crypto.DefaultPasswordVerifier().Verify(after.Password,
		[]byte("Rehash-Race-New-2026#b")); err != nil {
		t.Errorf("新密碼無法驗證: %v", err)
	}
}

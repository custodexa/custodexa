package identity

import (
	"testing"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/pkg/crypto"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// newMigrationTestService sqlite in-memory ＋ UserService（真 DB，
// 遷移統計與標記都是逐列判定，sqlmock 對此過於脆弱）。
func newMigrationTestService(t *testing.T) *UserService {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	if err := db.AutoMigrate(&model.User{}, &model.Role{}, &model.PasswordHistory{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return &UserService{db: db}
}

// === 遷移可見性與觸發===
//
// 這兩個能力存在的理由：批次重雜湊在密碼學上做不到（需要明文，系統沒有明文），
// 故管理員想立刻收斂時，能做的是**看見還有多少沒遷移**＋**要求他們下次登入改密**。

// seedMigrationUsers 建立三類帳號：待遷移（舊參數）、已遷移（當前參數）、外部化（空密碼）。
func seedMigrationUsers(t *testing.T, s *UserService) (pendingID, migratedID, externalID uint) {
	t.Helper()

	// 舊參數：以低於當前的 cost 產生
	oldHasher := crypto.NewBcryptHasher(crypto.BcryptMinCost)
	oldHash, err := oldHasher.Hash([]byte("old-params-password"))
	if err != nil {
		t.Fatalf("產生舊參數雜湊失敗: %v", err)
	}
	// 當前參數
	curHash, err := crypto.DefaultPasswordHasher().Hash([]byte("current-password"))
	if err != nil {
		t.Fatalf("產生當前參數雜湊失敗: %v", err)
	}

	pending := model.User{Username: "mig-pending", Password: oldHash, Active: true,
		ProvisioningOrigin: model.AuthSourceLocal}
	migrated := model.User{Username: "mig-migrated", Password: curHash, Active: true,
		ProvisioningOrigin: model.AuthSourceLocal}
	external := model.User{Username: "mig-external", Password: "", Active: true,
		IsLDAP: true, ProvisioningOrigin: model.AuthSourceLDAP}

	for _, u := range []*model.User{&pending, &migrated, &external} {
		if err := s.db.Create(u).Error; err != nil {
			t.Fatalf("建立測試帳號 %s 失敗: %v", u.Username, err)
		}
	}
	return pending.ID, migrated.ID, external.ID
}

// TestPasswordMigrationStatusClassifies 三類帳號必須被正確歸類。
func TestPasswordMigrationStatusClassifies(t *testing.T) {
	s := newMigrationTestService(t)
	seedMigrationUsers(t, s)

	got, err := s.PasswordMigrationStatus()
	if err != nil {
		t.Fatalf("PasswordMigrationStatus 失敗: %v", err)
	}

	if got.CurrentAlgorithm != crypto.DefaultPasswordHasher().ID() {
		t.Errorf("CurrentAlgorithm = %q, want %q", got.CurrentAlgorithm,
			crypto.DefaultPasswordHasher().ID())
	}
	if got.Pending < 1 {
		t.Errorf("Pending = %d，舊參數帳號未被算進待遷移——管理員看不到還有多少要處理", got.Pending)
	}
	if got.Migrated < 1 {
		t.Errorf("Migrated = %d，當前參數帳號未被算進已遷移", got.Migrated)
	}
	if got.External < 1 {
		t.Errorf("External = %d，外部化帳號未被排除——它們沒有本地密碼，不在遷移射程", got.External)
	}
}

// TestMarkPendingDoesNotTouchPasswords 標記強制改密**不得碰任何密碼欄位**。
//
// 這是本組最重要的一條：若實作誤把它寫成「順便重雜湊」，
// 對舊參數帳號會寫入一個**用錯誤明文產生**的雜湊（因為根本沒有明文），
// 使用者將完全無法登入且無法自行恢復。
func TestMarkPendingDoesNotTouchPasswords(t *testing.T) {
	s := newMigrationTestService(t)
	pendingID, migratedID, externalID := seedMigrationUsers(t, s)

	before := map[uint]string{}
	for _, id := range []uint{pendingID, migratedID, externalID} {
		var u model.User
		if err := s.db.First(&u, id).Error; err != nil {
			t.Fatalf("讀取帳號 %d 失敗: %v", id, err)
		}
		before[id] = u.Password
	}

	if _, err := s.MarkPendingForPasswordChange(); err != nil {
		t.Fatalf("MarkPendingForPasswordChange 失敗: %v", err)
	}

	for _, id := range []uint{pendingID, migratedID, externalID} {
		var u model.User
		if err := s.db.First(&u, id).Error; err != nil {
			t.Fatalf("讀取帳號 %d 失敗: %v", id, err)
		}
		if u.Password != before[id] {
			t.Errorf("帳號 %d 的密碼欄位被改動了——標記強制改密不得重雜湊，"+
				"沒有明文的重雜湊會產生無法登入的帳號", id)
		}
	}
}

// TestMarkPendingOnlyTargetsPending 只有待遷移的本地帳號會被標記。
func TestMarkPendingOnlyTargetsPending(t *testing.T) {
	s := newMigrationTestService(t)
	pendingID, migratedID, externalID := seedMigrationUsers(t, s)

	n, err := s.MarkPendingForPasswordChange()
	if err != nil {
		t.Fatalf("MarkPendingForPasswordChange 失敗: %v", err)
	}
	if n < 1 {
		t.Fatalf("標記數 = %d，待遷移帳號未被標記", n)
	}

	check := func(id uint, want bool, why string) {
		t.Helper()
		var u model.User
		if err := s.db.First(&u, id).Error; err != nil {
			t.Fatalf("讀取帳號 %d 失敗: %v", id, err)
		}
		if u.MustChangePassword != want {
			t.Errorf("帳號 %d 的 MustChangePassword = %v, want %v（%s）",
				id, u.MustChangePassword, want, why)
		}
	}
	check(pendingID, true, "舊參數帳號應被要求改密以完成遷移")
	check(migratedID, false, "已是當前參數，標記它只是無謂打擾使用者")
	check(externalID, false, "外部化帳號沒有本地密碼可改，標記它會造成無法完成的流程")
}

// TestMarkPendingIsIdempotent 重複執行不得重複計數或反覆打擾。
func TestMarkPendingIsIdempotent(t *testing.T) {
	s := newMigrationTestService(t)
	seedMigrationUsers(t, s)

	first, err := s.MarkPendingForPasswordChange()
	if err != nil {
		t.Fatalf("第一次標記失敗: %v", err)
	}
	second, err := s.MarkPendingForPasswordChange()
	if err != nil {
		t.Fatalf("第二次標記失敗: %v", err)
	}
	if first < 1 {
		t.Fatalf("第一次標記數 = %d", first)
	}
	if second != 0 {
		t.Errorf("第二次標記數 = %d, want 0——已標記者被重複計入，"+
			"管理員會以為還有帳號待處理", second)
	}
}

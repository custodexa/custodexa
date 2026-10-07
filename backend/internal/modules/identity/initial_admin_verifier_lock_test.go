package identity

import (
	"errors"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/pkg/crypto"
)

// 管理員帳密驗證器（封存期、初始化解封、攔下確認共用）對既有鎖定的唯讀尊重。
//
// 守三件事：
//
//	(a) 鎖定未到期即拒，密碼正確也一樣，且錯誤與「密碼錯」相同（不可區分）；
//	(b) 鎖定已到期或未鎖定時照常通過——判定看的是期限，不是欄位有無值；
//	(c) 只讀不寫：驗證失敗不累加失敗次數、不寫鎖定期限（攔下期零寫入）。

const lockVerifierPassword = "lock-verifier-pw-2026"

func lockVerifierDB(t *testing.T) (*gorm.DB, *model.User) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	sqlDB.SetMaxOpenConns(1)
	if err := db.AutoMigrate(&model.User{}, &model.Role{}, &model.UserRole{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	email := "lock-admin@example.invalid"
	u := &model.User{Username: "lock-admin", Email: &email,
		Password: crypto.MustHashForTest(lockVerifierPassword), Active: true,
		Roles: []model.Role{{Name: model.RoleAdmin}}}
	if err := db.Create(u).Error; err != nil {
		t.Fatalf("seed admin: %v", err)
	}
	return db, u
}

func setLockedUntil(t *testing.T, db *gorm.DB, u *model.User, until *time.Time) {
	t.Helper()
	if err := db.Model(&model.User{}).Where("id = ?", u.ID).Update("locked_until", until).Error; err != nil {
		t.Fatalf("set locked_until: %v", err)
	}
}

func TestVerifyInitialAdminCredentialRejectsLockedAccount(t *testing.T) {
	db, u := lockVerifierDB(t)
	future := time.Now().Add(30 * time.Minute)
	setLockedUntil(t, db, u, &future)

	errLocked := VerifyInitialAdminCredential(db, "lock-admin", []byte(lockVerifierPassword))
	if !errors.Is(errLocked, ErrSealInitialAdminInvalid) {
		t.Fatalf("鎖定中＋正確密碼應拒絕（ErrSealInitialAdminInvalid），得 %v", errLocked)
	}
	errWrong := VerifyInitialAdminCredential(db, "lock-admin", []byte("wrong-password"))
	if errLocked == nil || errWrong == nil || errLocked.Error() != errWrong.Error() {
		t.Fatalf("鎖定與密碼錯的錯誤必須相同：locked=%v wrong=%v", errLocked, errWrong)
	}
	if _, err := VerifySealAdminCredential(db, "lock-admin", []byte(lockVerifierPassword)); !errors.Is(err, ErrSealInitialAdminInvalid) {
		t.Fatalf("封存期驗證器同樣應拒絕鎖定中帳號，得 %v", err)
	}
}

func TestVerifyInitialAdminCredentialAcceptsWhenLockExpiredOrAbsent(t *testing.T) {
	db, u := lockVerifierDB(t)
	if err := VerifyInitialAdminCredential(db, "lock-admin", []byte(lockVerifierPassword)); err != nil {
		t.Fatalf("未鎖定＋正確密碼應通過，得 %v", err)
	}
	past := time.Now().Add(-time.Minute)
	setLockedUntil(t, db, u, &past)
	if err := VerifyInitialAdminCredential(db, "lock-admin", []byte(lockVerifierPassword)); err != nil {
		t.Fatalf("鎖定已到期＋正確密碼應通過，得 %v", err)
	}
	id, err := VerifySealAdminCredential(db, "lock-admin", []byte(lockVerifierPassword))
	if err != nil || id != u.ID {
		t.Fatalf("封存期驗證器應回該帳號識別，得 id=%d err=%v", id, err)
	}
}

func TestVerifyInitialAdminCredentialIsReadOnly(t *testing.T) {
	future := time.Now().Add(30 * time.Minute)
	cases := []struct {
		name  string
		until *time.Time
	}{
		{"未鎖定時密碼錯", nil},
		{"鎖定中", &future},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db, u := lockVerifierDB(t)
			setLockedUntil(t, db, u, tc.until)
			var before model.User
			if err := db.First(&before, u.ID).Error; err != nil {
				t.Fatal(err)
			}
			for i := 0; i < 3; i++ {
				_ = VerifyInitialAdminCredential(db, "lock-admin", []byte("wrong-password"))
				_, _ = VerifySealAdminCredential(db, "lock-admin", []byte("wrong-password"))
			}
			var after model.User
			if err := db.First(&after, u.ID).Error; err != nil {
				t.Fatal(err)
			}
			if after.FailedLoginAttempts != before.FailedLoginAttempts {
				t.Fatalf("驗證器不得累加失敗次數：前 %d 後 %d", before.FailedLoginAttempts, after.FailedLoginAttempts)
			}
			if (before.LockedUntil == nil) != (after.LockedUntil == nil) ||
				(before.LockedUntil != nil && !before.LockedUntil.Equal(*after.LockedUntil)) {
				t.Fatalf("驗證器不得寫入鎖定期限：前 %v 後 %v", before.LockedUntil, after.LockedUntil)
			}
			if !after.UpdatedAt.Equal(before.UpdatedAt) {
				t.Fatalf("驗證器不得更新帳號列：updated_at 前 %v 後 %v", before.UpdatedAt, after.UpdatedAt)
			}
		})
	}
}

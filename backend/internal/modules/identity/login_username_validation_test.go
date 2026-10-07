package identity

import (
	"errors"
	"testing"

	"gorm.io/gorm"
)

// 登入帳號的字元層判定：含控制字元或非法 UTF-8 者在查詢之前即以憑證錯誤拒絕。
//
// 「查詢之前」以計數 callback 證明：判定若落在查詢之後，正式環境的資料庫會先
// 拒收含 NUL 的參數，回應變成 500。

func countUserQueries(t *testing.T, db *gorm.DB) *int {
	t.Helper()
	n := 0
	if err := db.Callback().Query().Before("gorm:query").Register("test:count_queries", func(*gorm.DB) { n++ }); err != nil {
		t.Fatalf("register callback: %v", err)
	}
	return &n
}

func TestLoginRejectsControlCharUsernameBeforeQuery(t *testing.T) {
	auth, _, db := setupLockoutEnv(t)
	seedLockoutUser(t, db, "right-pass-1")
	queries := countUserQueries(t, db)

	_, errMissing := auth.Login(&LoginRequest{Username: "no-such-user", Password: "x"})
	if !errors.Is(errMissing, ErrInvalidCredentials) {
		t.Fatalf("前置：不存在的帳號應回 ErrInvalidCredentials，得 %v", errMissing)
	}

	for _, name := range []string{"\x00", "bob\x00", "bo\nb", "bob\r", "bob\t", "bob\x7f", "bob\u0085", "bob\xff"} {
		*queries = 0
		_, err := auth.Login(&LoginRequest{Username: name, Password: "right-pass-1"})
		if !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("帳號 %q 應回 ErrInvalidCredentials，得 %v", name, err)
		}
		if err.Error() != errMissing.Error() {
			t.Fatalf("帳號 %q 的錯誤與不存在的帳號可區分：%q vs %q", name, err, errMissing)
		}
		if *queries != 0 {
			t.Fatalf("帳號 %q 不應送進資料庫查詢，實際查詢 %d 次", name, *queries)
		}
	}
}

func TestLoginUsernameAcceptable(t *testing.T) {
	accept := []string{"bob", "admin.ops", "user@example.com", "王小明", "ユーザー", "a b"}
	for _, s := range accept {
		if !LoginUsernameAcceptable(s) {
			t.Errorf("%q 應被接受", s)
		}
	}
	reject := []string{"\x00", "bob\x00", "bo\nb", "bob\t", "\x1b[31m", "bob\x7f", "bob\u0085", "bob\xff", "\xc3"}
	for _, s := range reject {
		if LoginUsernameAcceptable(s) {
			t.Errorf("%q 應被拒絕", s)
		}
	}
}

// TestLoginOrdinaryUsernameStillQueries 正例：一般帳號照常查詢並可登入。
func TestLoginOrdinaryUsernameStillQueries(t *testing.T) {
	auth, _, db := setupLockoutEnv(t)
	seedLockoutUser(t, db, "right-pass-1")
	queries := countUserQueries(t, db)

	if _, err := auth.Login(&LoginRequest{Username: "bob", Password: "right-pass-1"}); err != nil {
		t.Fatalf("一般帳號＋正確密碼應登入成功，得 %v", err)
	}
	if *queries == 0 {
		t.Fatal("一般帳號應送進資料庫查詢")
	}
}

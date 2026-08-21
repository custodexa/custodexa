package dberr

import (
	"errors"
	"fmt"
	"testing"
)

// TestIsUniqueViolationRecognizesBothDialects 兩種驅動的唯一鍵衝突形態都須認得。
//
// 判定是跨方言的字串比對而非型別斷言，故正負兩側都要釘：認不出 postgres 的
// 23505 或 sqlite 的 UNIQUE 訊息，呼叫端會把 409 衝突回成 500；反過來把任意
// 錯誤都當成衝突，則會把真正的寫入失敗偽裝成「名稱已存在」。
func TestIsUniqueViolationRecognizesBothDialects(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"postgres 23505", errors.New(`ERROR: duplicate key value violates unique constraint "idx_users_email" (SQLSTATE 23505)`), true},
		{"postgres 文字形態", errors.New("pq: duplicate key value violates unique constraint"), true},
		{"sqlite", errors.New("UNIQUE constraint failed: users.email"), true},
		{"包裹後仍認得", fmt.Errorf("建立使用者失敗: %w", errors.New("UNIQUE constraint failed: users.email")), true},
		{"外鍵違反不算", errors.New("FOREIGN KEY constraint failed"), false},
		{"連線錯誤不算", errors.New("dial tcp 127.0.0.1:5432: connect: connection refused"), false},
		{"空訊息不算", errors.New(""), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := IsUniqueViolation(c.err); got != c.want {
				t.Fatalf("IsUniqueViolation(%v) = %v, want %v", c.err, got, c.want)
			}
		})
	}
}

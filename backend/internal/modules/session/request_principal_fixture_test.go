package session

import (
	"testing"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/authz"
	"gorm.io/gorm"
)

// requestPrincipalForTest 測試用：以帳號當下的完整指派解析請求主體（人類工作階段的形狀，未帶角色限定）。
// userID 為 0 回 nil。
func requestPrincipalForTest(t testing.TB, db *gorm.DB, userID uint) *authz.Principal {
	t.Helper()
	if userID == 0 {
		return nil
	}
	var u model.User
	if err := db.Unscoped().Select("id", "kind").First(&u, userID).Error; err != nil {
		t.Fatalf("解析測試主體 %d: %v", userID, err)
	}
	kind := u.Kind
	if kind == "" {
		kind = model.KindHuman
	}
	p, err := authz.ResolveUserOn(db, userID, authz.TokenFacts{SubjectKind: kind})
	if err != nil {
		t.Fatalf("解析測試主體 %d: %v", userID, err)
	}
	return p
}

// testSessionPrincipal 測試用：人類工作階段的請求主體（未帶角色限定）。關卡只取用它的事實並在交易內
// 以帳號當下的指派重解，故不需預先解析指派。
func testSessionPrincipal(userID uint) *authz.Principal {
	return authz.NewPrincipal(userID, authz.TokenFacts{SubjectKind: model.KindHuman}, nil)
}

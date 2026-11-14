package identity

import (
	"context"
	"testing"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/authz"
	"gorm.io/gorm"
)

// principalOf 測試用：以帳號當下的完整指派解析請求主體（等同人類工作階段的主體，未帶角色限定）。
// userID 為 0 回 nil。
func principalOf(t testing.TB, db *gorm.DB, userID uint) *authz.Principal {
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

// filteredPrincipalOf 測試用：帶角色限定的請求主體（API token 請求的形狀）。
func filteredPrincipalOf(t testing.TB, db *gorm.DB, userID uint, roleIDs ...uint) *authz.Principal {
	t.Helper()
	p, err := authz.ResolveUserOn(db, userID, authz.TokenFacts{SubjectKind: model.KindHuman,
		AuthMethod: "api_token", RoleFilter: authz.NewRoleFilter(roleIDs)})
	if err != nil {
		t.Fatalf("解析帶限定的測試主體 %d: %v", userID, err)
	}
	return p
}

// withOpPrincipal 測試用：替由請求建構的操作者補上請求主體（人類工作階段）。
func withOpPrincipal(t testing.TB, db *gorm.DB, op Operator) Operator {
	t.Helper()
	op.Principal = principalOf(t, db, op.UserID)
	return op
}

// withActorPrincipal 測試用：替映射寫入的操作者補上請求主體（人類工作階段）。
func withActorPrincipal(t testing.TB, db *gorm.DB, a GroupRoleMappingActor) GroupRoleMappingActor {
	t.Helper()
	a.Principal = principalOf(t, db, a.ID)
	return a
}

// testSessionPrincipal 測試用：人類工作階段的請求主體（未帶角色限定）。關卡只取用它的事實並在交易內
// 以帳號當下的指派重解，故不需預先解析指派。
func testSessionPrincipal(userID uint) *authz.Principal {
	return authz.NewPrincipal(userID, authz.TokenFacts{SubjectKind: model.KindHuman}, nil)
}

// asSession 測試用：在 ctx 上標示人類工作階段並放入該帳號的請求主體（角色定義寫入的操作者）。
// 角色定義寫入沒有系統路徑，缺請求主體一律拒絕；主體不預先解析指派，寫入交易內以帳號當下的指派重解。
func asSession(ctx context.Context, userID uint) context.Context {
	return authz.ContextWithPrincipal(model.WithRequestCredential(ctx, model.RequestCredentialHumanSession), testSessionPrincipal(userID))
}

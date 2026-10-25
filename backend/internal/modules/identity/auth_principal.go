package identity

import (
	"errors"
	"time"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/authz"
	"gorm.io/gorm"
)

// 主體解析入口。
//
// 認證中介層與手動認證入口（連線兌換、WebSocket）都經這裡取得主體：每次都由資料庫
// 現查有效指派，不快取、不讀 JWT 內的角色；解析失敗回傳 error，呼叫端一律拒絕。

// ResolvePrincipal 以 userID 解析主體。facts 取自 token（主體種類、認證來源、憑證世代）。
func (s *AuthService) ResolvePrincipal(userID uint, facts authz.TokenFacts) (*authz.Principal, error) {
	if facts.SubjectKind == model.KindAgent {
		// agent 主體：能力固定為一般使用者範本，不受角色列影響，無需查詢指派
		return authz.NewPrincipal(userID, facts, nil), nil
	}
	return authz.NewResolver(s.epochDB()).ResolveUser(userID, facts)
}

// CurrentConnectPrincipal 一次查詢完成 connect 路徑的「可連線複查」與「現查主體」：
// 不可連線回既有 sentinel（與 CheckUserConnectable 對齊），可連線回現時解析的主體。
// connect token 簽發與兌換 SHALL 以此現況主體判定超管／稽核員特權，不得憑 JWT／token
// 攜帶的角色快照——降權即時生效、撤權殘窗歸零。
func (s *AuthService) CurrentConnectPrincipal(userID uint) (*authz.Principal, error) {
	p, _, err := s.CurrentConnectPrincipalAndSourcePolicy(userID)
	return p, err
}

// CurrentConnectPrincipalAndSourcePolicy 同上，另帶出該使用者的允許來源網段儲存字串。
//
// **來源閘不另查一趟**：它緊接在主體現查之後，兩道閘吃的是同一列使用者。
// 分成兩次查詢除了多一次 round-trip，還會在兩次讀取之間開一個新的 TOCTOU 窗口
// ——角色以舊列判、來源以新列判，而那正是「換個位址在 60 秒內兌換」這類
// 攻擊要找的縫。
//
// 回傳的字串**不在此判定**：交由呼叫端以 `sourceip.Evaluate` 作成裁決，
// 判定邏輯全庫只有一份。讀取本身的可用性記帳（政策不可用的降級訊號）在此完成。
func (s *AuthService) CurrentConnectPrincipalAndSourcePolicy(userID uint) (*authz.Principal, string, error) {
	var user model.User
	if err := database.DB.First(&user, userID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, "", ErrUserNotFound
		}
		// 使用者列讀不到＝政策不可讀：閘序對此 fail-close，
		// 但降級訊號要看得見（否則 DB 抖動期間全部連線被擋卻沒有任何面板顯示原因）
		s.noteSourcePolicyRead(userID, "", err)
		return nil, "", err
	}
	if !user.Active {
		return nil, "", ErrUserInactive
	}
	if user.LockedUntil != nil && time.Now().Before(*user.LockedUntil) {
		return nil, "", ErrAccountLocked
	}
	s.noteSourcePolicyRead(userID, user.AllowedCIDRs, nil)
	p, err := authz.NewResolver(database.DB).ResolveUser(userID, authz.TokenFacts{SubjectKind: user.Kind})
	if err != nil {
		return nil, "", err
	}
	return p, user.AllowedCIDRs, nil
}

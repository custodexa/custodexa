package identity

import (
	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

// 還原世代閘。
//
// refresh、agent 長效憑證在簽發時記下當下的持久還原世代，驗證／兌換時與目前世代比對：
// 備份帶回的舊列（含已被備份後撤銷、在備份內仍顯示有效的）世代不符即拒絕，不刪除、
// 不改撤銷旗標。世代的資料表歸 authz，這裡只經組裝根注入的讀取函式取值，不直讀他模組的表。

// RestoreGenerationSource 讀目前持久還原世代（組裝根注入 authz.RestoreGeneration）。
type RestoreGenerationSource func(db *gorm.DB) (string, error)

// SetRestoreGenerationSource 注入世代來源。未注入（單元測試夾具）＝不啟用世代閘，
// 簽發記空世代、驗證不比對；正式組裝一律注入。
func (s *AuthService) SetRestoreGenerationSource(src RestoreGenerationSource) {
	s.restoreGen = src
	if s.agentTokens != nil {
		s.agentTokens.restoreGen = src
	}
}

func currentRestoreGeneration(src RestoreGenerationSource, db *gorm.DB) (string, error) {
	if src == nil {
		return "", nil
	}
	return src(db)
}

// restoreGenerationAccepts 憑證列的簽發世代是否等於目前世代。讀取失敗一律不接受（fail-close）。
func restoreGenerationAccepts(src RestoreGenerationSource, db *gorm.DB, rowGeneration string) bool {
	if src == nil {
		return true
	}
	cur, err := src(db)
	return err == nil && cur == rowGeneration
}

// markRestoreInvalidated 填列表投影 RestoreInvalidated：簽發世代與目前還原世代不同＝真實入口已拒絕。
// 如實標示，列表不得仍顯示有效。讀不到目前世代就讓整個列表失敗（與入口 fail-close 一致），不猜。
// 接呼叫方的查詢錯誤並原樣回傳，使 List 維持單一表達式。
func (s *AgentTokenService) markRestoreInvalidated(tokens []model.AgentToken, err error) error {
	if err != nil || s.restoreGen == nil {
		return err
	}
	cur, err := currentRestoreGeneration(s.restoreGen, s.db)
	if err != nil {
		return err
	}
	for i := range tokens {
		tokens[i].RestoreInvalidated = tokens[i].RestoreGeneration != cur
	}
	return nil
}

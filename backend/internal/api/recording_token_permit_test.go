package api

import (
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/modules/authz"
)

// permitRecordingIssue 讓簽發與重驗的錄影檢視權判定一律放行。只給測其他撤銷管道（帳號、
// provider、會話）或取流行為的既有測試用：那些夾具的主體沒有角色列，與權限判定無關。
// 權限判定本身由 TestRecordingTokenActiveRevocation 以真解析驗。
func permitRecordingIssue(m *RecordingTokenManager) {
	m.decide = func(*gorm.DB, uint, authz.TokenFacts) (authz.Decision, error) {
		return authz.Decision{Allowed: true}, nil
	}
}

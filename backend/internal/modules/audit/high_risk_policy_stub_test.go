package audit

import (
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/modules/policy"
)

// acceptHighRiskPolicyAlerts 測試替身：接受政策服務的高危設定告警（保留天數下調等）。
// 這些測試以政策服務設定保留天數作為前置，測的是保留清理本身，不是告警。
type acceptHighRiskPolicyAlerts struct{}

func (acceptHighRiskPolicyAlerts) RaiseHighRiskInTx(*gorm.DB, policy.HighRiskAlert) error { return nil }

// newTestPolicyService 建政策服務並接上接受高危告警的替身。
func newTestPolicyService(db *gorm.DB) *policy.SecurityPolicyService {
	svc := policy.NewSecurityPolicyService(db)
	svc.SetHighRiskAlertRaiser(acceptHighRiskPolicyAlerts{})
	return svc
}

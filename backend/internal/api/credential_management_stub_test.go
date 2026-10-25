package api

import (
	"context"

	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/audit/port"
	"github.com/custodexa/backend/internal/modules/authz"
)

// principalCredentialAuthorizer 以 context 內已解析的主體判憑證管理能力的測試替身，
// 語義與生產組裝（資料庫重新解析）相同，只是主體取自測試建好的 context。
// 沒有主體即全部拒絕，與生產的空主體拒絕一致。
type principalCredentialAuthorizer struct{}

func (principalCredentialAuthorizer) AuthorizeCredentialManagement(ctx context.Context, _ *gorm.DB,
	_ asset.CredentialManagementActor, req asset.CredentialManagementRequest) (asset.CredentialManagementDecision, error) {
	p := authz.PrincipalFromContext(ctx)
	for _, c := range req.Capabilities {
		if !p.Has(authz.Permission(c)) {
			return asset.CredentialManagementDecision{Missing: c, AuthzVersion: 1}, nil
		}
	}
	return asset.CredentialManagementDecision{Allowed: true, AuthzVersion: 1}, nil
}

// allowAllCredentialManagement 全放行的測試替身（只用於不驗授權的裝置建構）。
type allowAllCredentialManagement struct{}

func (allowAllCredentialManagement) AuthorizeCredentialManagement(context.Context, *gorm.DB,
	asset.CredentialManagementActor, asset.CredentialManagementRequest) (asset.CredentialManagementDecision, error) {
	return asset.CredentialManagementDecision{Allowed: true, AuthzVersion: 1}, nil
}

// recordingSystemAlerts 不落庫的系統告警落地面測試替身（只用於不驗告警的裝置建構）。
type recordingSystemAlerts struct{}

func (recordingSystemAlerts) RaiseInTx(*gorm.DB, port.SystemAlertEvent) (port.SystemAlertReceipt, error) {
	return port.SystemAlertReceipt{}, nil
}

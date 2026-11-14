package main

import (
	"github.com/custodexa/backend/internal/api"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/audit/port"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/identity"
)

// newAPITokenService 組出個人 API token 服務：建立與撤銷的交易內留痕（稽核與高權限告警）、
// 還原世代與還原時刻來源。留痕落地面未注入時建立與撤銷一律失敗，不在沒有留痕的情況下完成。
func newAPITokenService(auditTx port.TxSink, alerts port.SystemAlertSink) *identity.APITokenService {
	svc := identity.NewAPITokenService(database.DB, identity.NewAPITokenEventRecorder(auditTx, alerts))
	svc.SetRestoreGenerationSource(authz.RestoreGeneration)
	svc.SetRestoredAtSource(authz.RestoredAt)
	return svc
}

// newAPITokenHandler 組出個人 API token 端點；範圍內節點的呈現名稱取資產模組的節點路徑。
func newAPITokenHandler(auditTx port.TxSink, alerts port.SystemAlertSink) *api.APITokenHandler {
	return api.NewAPITokenHandler(newAPITokenService(auditTx, alerts),
		func() (map[uint]string, error) { return asset.NodePathMap(database.DB) })
}

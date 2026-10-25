package middleware

import (
	"github.com/custodexa/backend/internal/modules/authz"
)

// Permission 權限常數
//
// **型別已搬入**
// `internal/modules/authz`（`authz.Permission`；舊的角色→權限對照函式已移除）。
// 此處保留的是**型別別名與常數轉出**，不是第二份定義；路由的授權判定已改為
// 登錄執行中介層（`EnforceRegistry`），權限真相在 authz 的目錄與登錄表。
type Permission = authz.Permission

const (
	// Asset 權限
	PermAssetView   = authz.PermAssetView
	PermAssetCreate = authz.PermAssetCreate
	PermAssetUpdate = authz.PermAssetUpdate
	PermAssetDelete = authz.PermAssetDelete
	PermAssetTest   = authz.PermAssetTest

	// Session 權限
	PermSessionView      = authz.PermSessionView
	PermSessionTerminate = authz.PermSessionTerminate

	// Audit 權限
	PermAuditView = authz.PermAuditView

	// Alert 權限
	PermAlertView   = authz.PermAlertView
	PermAlertManage = authz.PermAlertManage

	// Credential 權限（憑證庫的建立、掛載、卸載、改密、範圍轉換與脫離共用）
	PermCredentialManage = authz.PermCredentialManage
)

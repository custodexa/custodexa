package authz

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/require"
)

// 執行身分管理權限點：可指派、依賴資產檢視、不進資產管理員範圍化範本（升級後既有角色能力不變）。
func TestAssetExecutorManageCatalogue(t *testing.T) {
	require.True(t, slices.Contains(AssignableKeys(), PermAssetExecutorManage), "可指派給自訂角色")
	require.False(t, slices.Contains(ScopedTemplateAssetAdminPermissions(), PermAssetExecutorManage),
		"不進資產管理員範本")
	// account:discover 由主機帳號盤點加入範本（與本權限點無關），一併列入現行集合。
	require.Equal(t, []Permission{
		PermAccountDiscover, PermAccountRotate, PermAssetCreate, PermAssetDelete, PermAssetTest, PermAssetUpdate, PermAssetView,
		PermAssetGroupManage, PermChangeSecretManage,
		PermCredentialBind, PermCredentialConvertScope, PermCredentialCreate, PermCredentialDelete,
		PermCredentialDetach, PermCredentialRotate, PermCredentialSetSecret, PermCredentialUpdate, PermCredentialView,
	}, ScopedTemplateAssetAdminPermissions(), "資產管理員範本集合不因執行身分權限點改變")
}

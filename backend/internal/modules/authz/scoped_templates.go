package authz

import "sort"

// 兩個範圍化範本（資產管理員、授權管理員）的精確權限集合。
//
// 這裡是範本集合的唯一來源：TemplatePermissions 的兩個分支回它們的副本，啟動資料步驟依同一識別
// 種入鎖定的角色列。集合內容依範圍判定契約的凍結表逐鍵列出。
// 資產管理員只列 scoped-enforced 鍵：相容的 credential:manage 在節點範圍指派上不生效，九個憑證語義鍵已涵蓋其能力。

var scopedTemplateAssetAdmin = []Permission{
	PermAssetView, PermAssetCreate, PermAssetUpdate, PermAssetDelete, PermAssetTest,
	PermAssetGroupManage, PermChangeSecretManage, PermAccountRotate,
	PermCredentialView, PermCredentialCreate, PermCredentialUpdate, PermCredentialSetSecret,
	PermCredentialRotate, PermCredentialConvertScope, PermCredentialDetach,
	PermCredentialDelete, PermCredentialBind,
}

var scopedTemplateAuthorizationAdmin = []Permission{
	PermAuthorizationManage, PermApproverScopeManage, PermAccessPolicyManage,
}

// ScopedTemplateAssetAdminPermissions 資產管理員範本的權限集合（副本，依鍵排序）。
func ScopedTemplateAssetAdminPermissions() []Permission {
	return sortedCopy(scopedTemplateAssetAdmin)
}

// ScopedTemplateAuthorizationAdminPermissions 授權管理員範本的權限集合（副本，依鍵排序）。
func ScopedTemplateAuthorizationAdminPermissions() []Permission {
	return sortedCopy(scopedTemplateAuthorizationAdmin)
}

func sortedCopy(in []Permission) []Permission {
	out := make([]Permission, len(in))
	copy(out, in)
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

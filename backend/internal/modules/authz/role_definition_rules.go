package authz

import (
	"errors"
	"fmt"
	"sort"
)

// 自訂角色權限集合的驗證規則與編輯描述資料。
//
// 純資料與純函式：不碰資料庫。角色集合只存**明列的權限鍵**；三態只是 UI 預設組合，
// 不保存「管理整組」萬用值。缺依賴允許儲存並明示缺漏，**不自動補授**。

// ErrRolePermissionInvalid 集合含不合法的鍵（未知、呈現專用 ui:、保留身分、連線豁免、明文讀取等）。
// 整筆拒絕，不保留其中合法部分。
type ErrRolePermissionInvalid struct{ Keys []string }

func (e *ErrRolePermissionInvalid) Error() string {
	return fmt.Sprintf("權限集合含不合法的鍵: %v", e.Keys)
}

// MissingDependency 某個已勾權限缺少的必要依賴。依賴缺漏不阻擋儲存：
// 只明示「持有者無法使用哪個畫面」，並進審計；不自動補授。
type MissingDependency struct {
	Permission Permission   `json:"permission"`
	Missing    []Permission `json:"missing"`
}

// permissionDependencies 明列的讀取／選擇器依賴（鍵 → 必須同時持有的鍵）。
// 依據是各畫面現行實際呼叫的讀取與選擇器端點；本表即依賴的唯一定義，入口表的依賴閉包由 TestRoleEditorDescriptors 核對。
func permissionDependencies() map[Permission][]Permission {
	return map[Permission][]Permission{
		PermAssetCreate:                  {PermAssetView},
		PermAssetUpdate:                  {PermAssetView},
		PermAssetDelete:                  {PermAssetView},
		PermAssetTest:                    {PermAssetView},
		PermAssetGroupManage:             {PermAssetView},
		PermCredentialManage:             {PermAssetView},
		PermCredentialView:               {PermAssetView},
		PermCredentialCreate:             {PermAssetView},
		PermCredentialUpdate:             {PermAssetView},
		PermCredentialSetSecret:          {PermAssetView},
		PermCredentialRotate:             {PermAssetView},
		PermCredentialConvertScope:       {PermAssetView},
		PermCredentialDetach:             {PermAssetView},
		PermCredentialDelete:             {PermAssetView},
		PermCredentialBind:               {PermAssetView},
		PermAccountRotate:                {PermAssetView},
		PermChangeSecretManage:           {PermAssetView},
		PermApproverScopeApplicantManage: {PermApproverScopeManage},
		PermUserGroupManage:              {PermUserManage},
		PermRoleAssign:                   {PermRoleView, PermUserManage},
		PermSessionTerminate:             {PermSessionView},
		PermAlertView:                    {PermAuditView},
		PermAlertManage:                  {PermAlertView, PermAuditView},
		PermAccessReviewManage:           {PermAuditView},
		PermAuditIntegrityView:           {PermAuditView},
		PermPolicyGroupManage:            {PermPolicyGroupView},
	}
}

// PermissionDependencies 某鍵的必要依賴（排序副本）。
func PermissionDependencies(key Permission) []Permission {
	d := append([]Permission(nil), permissionDependencies()[key]...)
	sort.Slice(d, func(i, j int) bool { return d[i] < d[j] })
	return d
}

// NormalizeRolePermissions 驗證並正規化一份自訂角色的權限集合（去重、排序）。
// 空集合合法（代表沒有額外能力）。不合法的鍵回 *ErrRolePermissionInvalid；
// 缺依賴不是錯誤，改由 MissingDependencies 另行描述（允許儲存、明示缺漏）。
func NormalizeRolePermissions(keys []string) ([]Permission, error) {
	seen := map[Permission]bool{}
	var invalid []string
	for _, k := range keys {
		p := Permission(k)
		if _, ok := LookupPermission(p); !ok || !IsAssignable(p) {
			invalid = append(invalid, k)
			continue
		}
		seen[p] = true
	}
	if len(invalid) > 0 {
		sort.Strings(invalid)
		return nil, &ErrRolePermissionInvalid{Keys: dedupStrings(invalid)}
	}
	out := make([]Permission, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out, nil
}

// MissingDependencies 集合中缺必要依賴的鍵與其缺少的依賴（依鍵排序；皆齊備回空切片）。
func MissingDependencies(perms []Permission) []MissingDependency {
	have := map[Permission]bool{}
	for _, p := range perms {
		have[p] = true
	}
	deps := permissionDependencies()
	out := []MissingDependency{}
	for _, p := range perms {
		var miss []Permission
		for _, d := range deps[p] {
			if !have[d] {
				miss = append(miss, d)
			}
		}
		if len(miss) > 0 {
			sort.Slice(miss, func(i, j int) bool { return miss[i] < miss[j] })
			out = append(out, MissingDependency{Permission: p, Missing: miss})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Permission < out[j].Permission })
	return out
}

func dedupStrings(in []string) []string {
	out := in[:0:0]
	for i, s := range in {
		if i == 0 || s != in[i-1] {
			out = append(out, s)
		}
	}
	return out
}

// IsInvalidRolePermission 供呼叫端判型別。
func IsInvalidRolePermission(err error) bool {
	var e *ErrRolePermissionInvalid
	return errors.As(err, &e)
}

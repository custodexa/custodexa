package authz

import (
	"encoding/json"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func entryByID(t *testing.T, id string) EntryDescriptor {
	t.Helper()
	for _, e := range entryDescriptors() {
		if e.ID == id {
			return e
		}
	}
	t.Fatalf("入口 %s 不存在", id)
	return EntryDescriptor{}
}

// TestRoleSummaryPartialManage 擋：持有某入口寫入鍵、卻因湊不齊管理態而被稱為只能檢視或未授予，
// 以及寫入鍵歸屬規則被日後新增的入口或依賴悄悄破壞。
func TestRoleSummaryPartialManage(t *testing.T) {
	t.Run("檢視加編輯內容：資產為部分管理，不在唯讀", func(t *testing.T) {
		s := SummarizeRole([]Permission{PermAssetView, PermAssetUpdate})
		assert.Contains(t, s.Partial, "assets")
		assert.NotContains(t, s.Read, "assets")
		assert.NotContains(t, s.Manage, "assets")
	})
	t.Run("資產管理員範本：憑證庫部分管理、資產管理，憑證鍵不再未歸屬", func(t *testing.T) {
		s := SummarizeRole(ScopedTemplateAssetAdminPermissions())
		assert.Contains(t, s.Partial, "credentials")
		assert.Contains(t, s.Manage, "assets")
		for _, k := range s.Unattributed {
			assert.NotContains(t, string(k), "credential:", "憑證鍵由部分管理的憑證庫涵蓋")
			assert.NotEqual(t, PermAccountRotate, k)
		}
	})
	t.Run("只持 user:manage：帳號管理、使用者群組隱藏", func(t *testing.T) {
		s := SummarizeRole([]Permission{PermUserManage})
		assert.Contains(t, s.Manage, "users")
		assert.Contains(t, s.Hidden, "user_groups")
		assert.NotContains(t, s.Partial, "user_groups")
	})
	t.Run("審核範圍的兩個管理鍵", func(t *testing.T) {
		one := SummarizeRole([]Permission{PermApproverScopeManage})
		assert.Contains(t, one.Partial, "approver_scopes")
		app := []Permission{PermApproverScopeApplicantManage}
		assert.Contains(t, SummarizeRole(app).Partial, "approver_scopes")
		assert.Contains(t, BlockedScreens(app), BlockedScreen{ID: "approver_scopes", Missing: []Permission{PermApproverScopeManage}})
		both := SummarizeRole([]Permission{PermApproverScopeManage, PermApproverScopeApplicantManage})
		assert.Contains(t, both.Manage, "approver_scopes")
		assert.NotContains(t, both.Partial, "approver_scopes")
	})
	t.Run("空集合全隱藏、單一檢視鍵仍是唯讀", func(t *testing.T) {
		none := SummarizeRole(nil)
		assert.Empty(t, none.Partial)
		assert.Len(t, none.Hidden, len(entryDescriptors()))
		one := SummarizeRole([]Permission{PermAssetView})
		assert.Equal(t, []string{"assets"}, one.Read)
		assert.Empty(t, one.Partial)
	})

	t.Run("守衛：每個管理態鍵恰一個歸屬入口", func(t *testing.T) {
		for k, o := range writeKeyOwners() {
			assert.Len(t, o, 1, "%s 的歸屬入口 %v 不唯一，請在描述表處理", k, o)
		}
	})
	t.Run("守衛：各入口寫入鍵兩兩不相交，且不含本入口唯讀態的鍵", func(t *testing.T) {
		seen := map[Permission]string{}
		for _, e := range entryDescriptors() {
			readKeys := map[Permission]bool{}
			for _, stt := range e.States {
				if stt.Name == StateRead {
					for _, k := range stt.Keys {
						readKeys[k] = true
					}
				}
			}
			for _, k := range EntryWriteKeys(e) {
				if prev, dup := seen[k]; dup {
					t.Errorf("寫入鍵 %s 同時屬於 %s 與 %s", k, prev, e.ID)
				}
				seen[k] = e.ID
				assert.False(t, readKeys[k], "%s 的寫入鍵 %s 與唯讀態相交", e.ID, k)
			}
		}
	})
	t.Run("四個入口的寫入鍵", func(t *testing.T) {
		out := map[string][]string{}
		for _, id := range []string{"assets", "credentials", "approver_scopes", "user_groups"} {
			ks := EntryWriteKeys(entryByID(t, id))
			names := make([]string, len(ks))
			for i, k := range ks {
				names[i] = string(k)
			}
			sort.Strings(names)
			out[id] = names
		}
		require.NotEmpty(t, out["assets"])
		b, err := json.MarshalIndent(out, "", "  ")
		require.NoError(t, err)
		t.Logf("write_keys JSON:\n%s", b)
		assert.Contains(t, out["approver_scopes"], string(PermApproverScopeManage))
		assert.NotContains(t, out["user_groups"], string(PermUserManage))
		assert.NotContains(t, out["assets"], string(PermAssetView))
	})
}

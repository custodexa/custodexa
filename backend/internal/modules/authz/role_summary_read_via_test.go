package authz

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRoleSummaryReadVia 擋：入口頁面內容的讀取只要另一入口某一態的鍵，摘要卻把它報為沒有授予。
// 帶 ReadVia 的入口在來源入口不是沒有授予、本身沒有授予時歸為可檢視；寫入鍵（部分管理）優先；
// 隨附可檢視只是呈現，不補不移除任何鍵。
func TestRoleSummaryReadVia(t *testing.T) {
	t.Run("只持 audit:view：操作日誌可使用，告警與存取複審可檢視", func(t *testing.T) {
		s := SummarizeRole([]Permission{PermAuditView})
		assert.Contains(t, s.Available, "audit_logs")
		assert.Contains(t, s.Read, "alerts", "只持稽核檢視就讀得到告警記錄")
		assert.Contains(t, s.Read, "access_reviews", "只持稽核檢視就讀得到存取複審清單")
		assert.NotContains(t, s.Hidden, "alerts")
		assert.NotContains(t, s.Hidden, "access_reviews")
		assert.Empty(t, s.Unattributed)
		assert.Empty(t, BlockedScreens([]Permission{PermAuditView}))
	})
	t.Run("audit:view 加告警管理：告警為部分管理且缺依賴列 alert:view，存取複審仍可檢視", func(t *testing.T) {
		perms := []Permission{PermAuditView, PermAlertManage}
		s := SummarizeRole(perms)
		assert.Contains(t, s.Partial, "alerts")
		assert.NotContains(t, s.Read, "alerts", "寫入鍵優先於隨附可檢視")
		assert.Contains(t, s.Read, "access_reviews")
		assert.Contains(t, BlockedScreens(perms), BlockedScreen{ID: "alerts", Missing: []Permission{PermAlertView}})
	})
	t.Run("audit:view 加存取複審管理：存取複審為管理", func(t *testing.T) {
		s := SummarizeRole([]Permission{PermAuditView, PermAccessReviewManage})
		assert.Contains(t, s.Manage, "access_reviews")
		assert.NotContains(t, s.Read, "access_reviews")
	})
	t.Run("只持 alert:view：來源入口沒有授予，告警仍是沒有授予且列入無法使用的畫面", func(t *testing.T) {
		perms := []Permission{PermAlertView}
		s := SummarizeRole(perms)
		assert.Contains(t, s.Hidden, "alerts")
		assert.NotContains(t, s.Read, "alerts")
		assert.Contains(t, s.Hidden, "access_reviews")
		assert.Contains(t, BlockedScreens(perms), BlockedScreen{ID: "alerts", Missing: []Permission{PermAuditView}})
	})
	t.Run("空集合全隱藏", func(t *testing.T) {
		s := SummarizeRole(nil)
		assert.Len(t, s.Hidden, len(entryDescriptors()))
		assert.Empty(t, s.Read)
		assert.Empty(t, s.Available)
		assert.Empty(t, s.Partial)
		assert.Empty(t, s.Manage)
	})
	t.Run("稽核員範本：告警仍可管理，存取複審改為可檢視", func(t *testing.T) {
		s := SummarizeRole(TemplatePermissions("auditor"))
		assert.Contains(t, s.Manage, "alerts")
		assert.Contains(t, s.Read, "access_reviews")
		assert.NotContains(t, s.Hidden, "access_reviews")
	})
	t.Run("alerts 唯讀（alert:view 加 audit:view）仍是唯讀，不重複列入", func(t *testing.T) {
		s := SummarizeRole([]Permission{PermAlertView, PermAuditView})
		count := 0
		for _, id := range s.Read {
			if id == "alerts" {
				count++
			}
		}
		assert.Equal(t, 1, count)
	})

	t.Run("來源不變式：來源入口存在、本身不帶來源、沒有寫入鍵；帶來源的入口有自己的頁面", func(t *testing.T) {
		seen := 0
		for _, e := range entryDescriptors() {
			if e.ReadVia == "" {
				continue
			}
			seen++
			src := entryByID(t, e.ReadVia)
			assert.Empty(t, src.ReadVia, "%s 的來源 %s 不得再帶來源", e.ID, src.ID)
			assert.Empty(t, EntryWriteKeys(src), "%s 的來源 %s 不得有寫入鍵", e.ID, src.ID)
			assert.Equal(t, PlacementPage, e.PlacementKind(), "%s 帶隨附來源，必須有自己的頁面", e.ID)
			assert.NotEqual(t, e.ID, src.ID)
		}
		require.Equal(t, 2, seen, "目前只有告警與存取複審帶隨附來源；新增時請同步本測試與編輯畫面的說明")
	})
}

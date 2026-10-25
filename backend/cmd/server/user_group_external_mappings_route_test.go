package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/authz"
)

// TestUserGroupExternalMappingsRoute 擋：路由缺登錄、無群組管理能力者得知規則內容或存在性差異、
// 停用規則或其他群組的規則被列出、來源停用態與標籤規則偏離、回應夾帶成員資料、讀取改動資料。
func TestUserGroupExternalMappingsRoute(t *testing.T) {
	const method, pattern = "GET", "/api/v1/user-groups/:id/external-mappings"

	t.Run("路由在登錄表、agent 登錄與路由清冊都有", func(t *testing.T) {
		routes, _ := buildRouter(t, "release", true)
		e, ok := authz.LookupRoute(method, pattern)
		require.True(t, ok, "未登錄")
		assert.Equal(t, authz.BasePerm, e.Base)
		assert.Equal(t, authz.PermUserGroupManage, e.Perm)
		allowed, registered := middleware.AgentRouteDecision(method, pattern)
		assert.True(t, registered, "未在 agent 路由登錄")
		assert.False(t, allowed, "不得開放給 agent")
		_, inInventory := routes[[2]string{method, pattern}]
		assert.True(t, inInventory, "不在路由清冊")
	})

	env := newBaselineEnv(t)
	db := env.db

	// 夾具：一個目標群組與一個旁觀群組；LDAP 目錄沿用環境既有的一筆（單例），OIDC 來源另建一筆停用的。
	target := model.UserGroup{Name: "ext-map-target"}
	other := model.UserGroup{Name: "ext-map-other"}
	require.NoError(t, db.Create(&target).Error)
	require.NoError(t, db.Create(&other).Error)
	var dir model.LDAPDirectory
	require.NoError(t, db.First(&dir).Error)
	require.True(t, dir.Enabled)
	idp := model.OIDCProvider{Name: "ext-map-idp", Issuer: "https://idp.ext-map.example.com", ClientID: "c", GroupsClaim: "groups",
		AdmissionMode: model.AdmissionPreboundOnly, ClientSecretEnc: "enc"}
	require.NoError(t, db.Create(&idp).Error)
	require.False(t, idp.Enabled)

	mkGroup := func(ldap bool, value, note string) model.ExternalGroup {
		g := model.ExternalGroup{MatchValue: value, Note: note}
		if ldap {
			g.LDAPDirectoryID = &dir.ID
		} else {
			g.OIDCProviderID = &idp.ID
		}
		require.NoError(t, db.Create(&g).Error)
		return g
	}
	mkRule := func(ldap bool, g model.ExternalGroup, ug uint, enabled bool) model.GroupUserGroupMapping {
		r := model.GroupUserGroupMapping{ExternalGroupID: g.ID, UserGroupID: ug, CreatedBy: env.subjects["S01"].UserID}
		if ldap {
			r.LDAPDirectoryID = &dir.ID
		} else {
			r.OIDCProviderID = &idp.ID
		}
		require.NoError(t, db.Create(&r).Error)
		if !enabled {
			require.NoError(t, db.Model(&r).Update("enabled", false).Error)
		}
		return r
	}
	const ldapValue = "cn=ext-map-ops,ou=groups,dc=example,dc=test"
	ldapRule := mkRule(true, mkGroup(true, ldapValue, "維運組"), target.ID, true)
	oidcRule := mkRule(false, mkGroup(false, "ext-map-claim-a", ""), target.ID, true)
	disabledRule := mkRule(false, mkGroup(false, "ext-map-claim-disabled", "停用規則備註"), target.ID, false)
	otherRule := mkRule(true, mkGroup(true, "cn=ext-map-other,ou=groups,dc=example,dc=test", "旁觀群組備註"), other.ID, true)
	member := env.createUser("ext-map-member", nil)
	require.NoError(t, db.Create(&model.UserGroupMember{UserGroupID: target.ID, UserID: member, Manual: true}).Error)

	path := func(id uint) string { return fmt.Sprintf("/api/v1/user-groups/%d/external-mappings", id) }
	call := func(subject, p string) (int, []byte) {
		req := httptest.NewRequest("GET", p, nil)
		if tok := env.subjects[subject].Token; tok != "" {
			req.Header.Set("Authorization", "Bearer "+tok)
		}
		w := env.serve(req)
		return w.Code, w.Body.Bytes()
	}
	counts := func() []int64 {
		var out []int64
		for _, tbl := range []string{"group_user_group_mappings", "group_role_mappings", "external_groups",
			"user_group_mapping_rule_supports", "user_role_mapping_rule_supports", "user_group_members", "authz_state"} {
			var n int64
			require.NoError(t, db.Table(tbl).Count(&n).Error)
			out = append(out, n)
		}
		v, err := authz.CurrentVersion(db)
		require.NoError(t, err)
		return append(out, v)
	}
	auditRows := func(action model.AuditAction) int64 {
		var n int64
		require.NoError(t, db.Model(&model.AuditLog{}).
			Where("method = ? AND path = ? AND action = ? AND resource = ?", "GET", path(target.ID), action, model.ResourceUserGroup).
			Count(&n).Error)
		return n
	}

	t.Run("無群組管理能力者被拒，有規則與不存在的群組回應相同且不含規則內容", func(t *testing.T) {
		for _, sub := range []string{"S02", "S03"} {
			c1, b1 := call(sub, path(target.ID))
			c2, b2 := call(sub, path(999999))
			assert.Equal(t, http.StatusForbidden, c1, sub)
			assert.Equal(t, c1, c2, sub)
			assert.Equal(t, string(b1), string(b2), "%s 不得因群組是否存在或有無規則而回應不同", sub)
			for _, leak := range []string{"維運組", ldapValue, "ext-map-claim-a", "ext-map-idp", "source_type", "total", "rule_id"} {
				assert.NotContains(t, string(b1), leak, sub)
			}
		}
		c, _ := call("S00", path(target.ID))
		assert.Equal(t, http.StatusUnauthorized, c)
	})

	t.Run("不存在的群組回既有 not-found 形狀，非法編號回 400", func(t *testing.T) {
		c, b := call("S01", path(999999))
		assert.Equal(t, http.StatusNotFound, c)
		assert.Contains(t, string(b), string(apierror.CodeUserGroupNotFound))
		c, b = call("S01", "/api/v1/user-groups/abc/external-mappings")
		assert.Equal(t, http.StatusBadRequest, c)
		assert.Contains(t, string(b), string(apierror.CodeInvalidID))
	})

	t.Run("回傳兩筆啟用規則，來源停用態如實標示，停用規則與其他群組的規則不出現", func(t *testing.T) {
		before := counts()
		auditBefore := auditRows(model.ActionRead)
		c, b := call("S01", path(target.ID))
		require.Equal(t, http.StatusOK, c, string(b))
		var out struct {
			Data  []map[string]any `json:"data"`
			Total int              `json:"total"`
		}
		require.NoError(t, json.Unmarshal(b, &out))
		assert.Equal(t, 2, out.Total)
		require.Len(t, out.Data, 2)
		byRule := map[uint]map[string]any{}
		for _, row := range out.Data {
			for _, key := range []string{"source_type", "source_name", "source_enabled", "external_group_label", "rule_id"} {
				assert.Contains(t, row, key)
			}
			byRule[uint(row["rule_id"].(float64))] = row
		}
		require.Contains(t, byRule, ldapRule.ID)
		require.Contains(t, byRule, oidcRule.ID)
		assert.NotContains(t, byRule, disabledRule.ID, "停用規則不出現")
		assert.NotContains(t, byRule, otherRule.ID, "其他群組的規則不出現")
		assert.Equal(t, "ldap", byRule[ldapRule.ID]["source_type"])
		assert.Equal(t, dir.Name, byRule[ldapRule.ID]["source_name"])
		assert.Equal(t, true, byRule[ldapRule.ID]["source_enabled"])
		assert.Equal(t, "oidc", byRule[oidcRule.ID]["source_type"])
		assert.Equal(t, "ext-map-idp", byRule[oidcRule.ID]["source_name"])
		assert.Equal(t, false, byRule[oidcRule.ID]["source_enabled"], "來源已停用")
		// 有備註時標籤為備註；無備註時為原始識別碼
		assert.Equal(t, "維運組", byRule[ldapRule.ID]["external_group_label"])
		assert.Equal(t, "ext-map-claim-a", byRule[oidcRule.ID]["external_group_label"])
		assert.NotContains(t, string(b), "旁觀群組備註")
		assert.NotContains(t, string(b), "停用規則備註")

		// 不含成員名單或成員數
		for _, row := range out.Data {
			for k := range row {
				lk := strings.ToLower(k)
				assert.False(t, strings.Contains(lk, "member") || strings.Contains(lk, "user") || strings.Contains(lk, "count"), "欄位 %s 不得揭露成員", k)
			}
		}
		assert.NotContains(t, string(b), "ext-map-member")

		// 呼叫前後規則、支持、成員與權限版本不變；請求留痕恰增一筆 read/user_group（審計為非同步，輪詢等待）
		assert.Equal(t, before, counts())
		require.Eventually(t, func() bool { return auditRows(model.ActionRead) == auditBefore+1 },
			5*time.Second, 50*time.Millisecond, "成功的讀取應留下一列 read/user_group")
		time.Sleep(200 * time.Millisecond)
		assert.Equal(t, auditBefore+1, auditRows(model.ActionRead))
		assert.Equal(t, int64(0), auditRows(model.ActionCreate)+auditRows(model.ActionUpdate)+auditRows(model.ActionDelete))
	})

	t.Run("沒有啟用規則的群組回空陣列而非 null", func(t *testing.T) {
		empty := model.UserGroup{Name: "ext-map-empty"}
		require.NoError(t, db.Create(&empty).Error)
		c, b := call("S01", path(empty.ID))
		require.Equal(t, http.StatusOK, c)
		assert.Contains(t, string(b), `"data":[]`)
		assert.Contains(t, string(b), `"total":0`)
	})
}

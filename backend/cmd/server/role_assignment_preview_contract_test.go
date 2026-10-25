package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/identity"
)

// 預覽契約：整筆彙總 operation 與實際寫入的標記審計、事件逐案對照。
// 每案以同一份夾具先預覽、再寫入；需要指派自訂窄權限角色的案例，寫入走測試限定注入完整目錄的服務
// （正式組裝實際注入的目錄另由一案分派驗證：該種目錄走正式組裝的路由，另一種明示注入）。

type contractWorld struct {
	t   *testing.T
	f   *previewFixture
	env *baselineEnv
	// 服務層寫入用：測試限定注入完整目錄。
	users  *identity.UserService
	groups *identity.UserGroupService
	op     identity.Operator
}

func newContractWorld(t *testing.T) *contractWorld {
	env := newBaselineEnv(t)
	f := newPreviewFixture(t, env)
	grader := identity.NewGrantGrader(audit.NewTxSink(), audit.NewSystemAlertSink(nil))
	guard := identity.NewAssignmentGuard(identity.FullCatalog())
	users := identity.NewUserService(env.db, nil)
	users.SetAssignmentGuard(guard)
	users.SetGrantGrader(grader)
	groups := identity.NewUserGroupService(env.db, audit.NewTxSink(), nil)
	groups.SetAssignmentGuard(guard)
	groups.SetGrantGrader(grader)
	return &contractWorld{t: t, f: f, env: env, users: users, groups: groups,
		op: identity.Operator{UserID: f.sup, Username: env.subjects["S01"].Username}}
}

// counts 預覽前後必須相同的資料量與授權變更痕跡的累計。
type counts struct {
	userRoles, members, bindings, alerts, graded, auditAll, version int64
}

func (w *contractWorld) count(table, where string, args ...any) int64 {
	w.t.Helper()
	var n int64
	q := w.env.db.Table(table)
	if where != "" {
		q = q.Where(where, args...)
	}
	require.NoError(w.t, q.Count(&n).Error)
	return n
}

func (w *contractWorld) counts() counts {
	w.t.Helper()
	v, err := authz.CurrentVersion(w.env.db)
	require.NoError(w.t, err)
	return counts{
		userRoles: w.count("user_roles", ""), members: w.count("user_group_members", ""),
		bindings: w.count("user_group_roles", ""), alerts: w.count("system_alert_details", ""),
		graded:   w.count("audit_logs", "details LIKE ?", "%grant_marks%"),
		auditAll: w.count("audit_logs", ""), version: v,
	}
}

// authzTables 預覽前後必須逐列相同的授權相關表。
var authzTables = []string{"user_roles", "user_group_members", "user_group_roles",
	"user_group_mapping_rule_supports", "role_binding_nodes", "roles", "role_permissions", "authz_state",
	"group_role_mappings", "group_user_group_mappings", "user_role_mapping_rule_supports", "user_role_mappings"}

// snapshot 相關表的逐列完整快照（所有欄位，每表依列內容排序），抓得到原地改寫。
func (w *contractWorld) snapshot() map[string][]string {
	w.t.Helper()
	out := map[string][]string{}
	for _, tb := range authzTables {
		var rows []map[string]any
		require.NoError(w.t, w.env.db.Table(tb).Find(&rows).Error, tb)
		lines := make([]string, 0, len(rows))
		for _, r := range rows {
			b, err := json.Marshal(r)
			require.NoError(w.t, err)
			lines = append(lines, string(b))
		}
		sort.Strings(lines)
		out[tb] = lines
	}
	return out
}

// apiRaw 以原樣字串當請求本文（測試 JSON 鍵是否存在這類 map 表達不了的輸入）。
func (e *baselineEnv) apiRaw(subject, method, path, body string) (int, map[string]any) {
	req := httptest.NewRequest(method, path, bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	if tok := e.subjects[subject].Token; tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	rec := e.serve(req)
	out := map[string]any{}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

func strs(v any) []string {
	arr, _ := v.([]any)
	out := make([]string, 0, len(arr))
	for _, x := range arr {
		out = append(out, fmt.Sprint(x))
	}
	return out
}

// preview 以超管呼叫預覽路由，並斷言它沒有改動任何授權資料：指派、成員、權限版本、授權變更服務審計與
// 系統告警都不增；預覽路由既有的 HTTP 請求留痕（create／role）照舊恰增一列。
func (w *contractWorld) preview(body map[string]any) map[string]any {
	return w.previewAs("S01", body)
}

// previewAs 以指定主體的憑證呼叫預覽，其餘斷言同 preview。
func (w *contractWorld) previewAs(subj string, body map[string]any) map[string]any {
	w.t.Helper()
	before := w.counts()
	snapBefore := w.snapshot()
	code, out := w.env.api(subj, "POST", "/api/v1/role-assignment-previews", body)
	require.Equal(w.t, http.StatusOK, code, "%v", out)
	after := w.counts()
	snapAfter := w.snapshot()
	for _, tb := range authzTables {
		assert.Equal(w.t, snapBefore[tb], snapAfter[tb], "預覽不得改動 %s 的任何一列", tb)
	}
	assert.Equal(w.t, before.userRoles, after.userRoles, "預覽不得改指派")
	assert.Equal(w.t, before.members, after.members, "預覽不得改成員")
	assert.Equal(w.t, before.bindings, after.bindings, "預覽不得改群組角色")
	assert.Equal(w.t, before.version, after.version, "預覽不得推進權限版本")
	assert.Equal(w.t, before.alerts, after.alerts, "預覽不得產生系統告警")
	assert.Equal(w.t, before.graded, after.graded, "預覽不得寫授權變更服務審計")
	assert.Equal(w.t, before.auditAll+1, after.auditAll, "預覽路由既有的請求留痕恰增一列")
	var last model.AuditLog
	require.NoError(w.t, w.env.db.Order("id DESC").First(&last).Error)
	assert.Equal(w.t, model.ActionCreate, last.Action)
	assert.Equal(w.t, model.ResourceRole, last.Resource)
	w.assertNoAssetsRoute(out)
	return out
}

// assertNoAssetsRoute 登入即可的入口（/assets）不出現在任何增減。
func (w *contractWorld) assertNoAssetsRoute(out map[string]any) {
	w.t.Helper()
	op, _ := out["operation"].(map[string]any)
	for _, k := range []string{"routes_gained", "routes_lost"} {
		assert.NotContains(w.t, strs(op[k]), "/assets")
	}
	subjects, _ := out["subjects"].([]any)
	for _, s := range subjects {
		for _, k := range []string{"routes_gained", "routes_lost"} {
			assert.NotContains(w.t, strs(s.(map[string]any)[k]), "/assets")
		}
	}
}

func opOf(out map[string]any) map[string]any {
	op, _ := out["operation"].(map[string]any)
	return op
}

// mark 寫入前的累計位置：告警編號與審計編號。
type mark struct{ alert, audit int64 }

func (w *contractWorld) mark() mark {
	w.t.Helper()
	var a, b int64
	require.NoError(w.t, w.env.db.Table("system_alert_details").Select("COALESCE(MAX(alert_id),0)").Scan(&a).Error)
	require.NoError(w.t, w.env.db.Table("audit_logs").Select("COALESCE(MAX(id),0)").Scan(&b).Error)
	return mark{a, b}
}

// written 自 m 之後寫入的事件（類型/目標種類/目標編號，已排序）與帶標記的服務審計列數。
func (w *contractWorld) written(m mark) (events []string, graded int64) {
	w.t.Helper()
	var rows []model.SystemAlertDetail
	require.NoError(w.t, w.env.db.Where("alert_id > ?", m.alert).Order("alert_id").Find(&rows).Error)
	for _, r := range rows {
		events = append(events, r.AlertType+"/"+r.TargetKind+"/"+r.TargetID)
	}
	sort.Strings(events)
	return events, w.count("audit_logs", "id > ? AND details LIKE ?", m.audit, "%grant_marks%")
}

// expectEvents 預覽的 marks 與寫入的標記審計、事件（種類、目標種類、筆數）逐項相同。
// mgmtKind／mgmtID 為管理類發放的目標；自我授權的目標恆為操作者本人。
func (w *contractWorld) expectEvents(op map[string]any, m mark, mgmtKind string, mgmtID uint) {
	w.t.Helper()
	var want []string
	marks := strs(op["marks"])
	for _, mk := range marks {
		switch mk {
		case authz.GrantMarkSelfAuthorization:
			typ := authz.AlertKeySelfIncreased
			if op["self_direction"] == string(authz.GrantDecrease) {
				typ = authz.AlertKeySelfDecreased
			}
			want = append(want, fmt.Sprintf("%s/user/%d", typ, w.f.sup))
		case authz.GrantMarkManagementGrant:
			want = append(want, fmt.Sprintf("%s/%s/%d", authz.AlertKeyManagementGranted, mgmtKind, mgmtID))
		default:
			w.t.Fatalf("未知標記 %q", mk)
		}
	}
	sort.Strings(want)
	got, graded := w.written(m)
	assert.Equal(w.t, want, got, "寫入產生的事件（類型/目標）與預覽 marks 對應")
	assert.EqualValues(w.t, len(marks), graded, "帶標記的服務審計列數等於 marks 數")
}

// routesFromGolden 以共用 golden 為準求某組能力放行的入口（不含登入即可與依本人資格的入口），升冪。
func routesFromGolden(t *testing.T, perms ...string) []string {
	t.Helper()
	raw, err := os.ReadFile("../../internal/api/testdata/route-entry-rules.json")
	require.NoError(t, err)
	var rows []struct {
		Path        string   `json:"path"`
		Kind        string   `json:"kind"`
		Permissions []string `json:"permissions"`
	}
	require.NoError(t, json.Unmarshal(raw, &rows))
	has := map[string]bool{}
	for _, p := range perms {
		has[p] = true
	}
	out := []string{}
	for _, r := range rows {
		if r.Kind == authz.RouteEntrySignedIn || len(r.Permissions) == 0 || strings.HasPrefix(r.Permissions[0], authz.UIPrefix) {
			continue
		}
		ok := r.Kind == authz.RouteEntryAll
		for _, p := range r.Permissions {
			if r.Kind == authz.RouteEntryAll && !has[p] {
				ok = false
			}
			if r.Kind == authz.RouteEntryAny && has[p] {
				ok = true
			}
		}
		if ok {
			out = append(out, r.Path)
		}
	}
	sort.Strings(out)
	return out
}

func TestRoleAssignmentPreviewContract(t *testing.T) {
	w := newContractWorld(t)
	f := w.f
	adminID := w.env.roleID(model.RoleAdmin)

	t.Run("舊用戶端的四種既有輸入（夾具最先建立，編號與基底對照檔一致）：除 operation 與列出主體的 routes_* 外與基底實作逐欄相同", func(t *testing.T) {
		raw, err := os.ReadFile("testdata/role-assignment-preview-legacy.json")
		require.NoError(t, err)
		var base map[string]map[string]any
		require.NoError(t, json.Unmarshal(raw, &base))
		reqs := f.legacyPreviewRequests()
		require.Len(t, reqs, 4)
		for name, body := range reqs {
			out := w.preview(body)
			require.Contains(t, out, "operation", name)
			delete(out, "operation")
			for _, s := range out["subjects"].([]any) {
				sm := s.(map[string]any)
				require.Contains(t, sm, "routes_gained")
				require.Contains(t, sm, "routes_lost")
				delete(sm, "routes_gained")
				delete(sm, "routes_lost")
			}
			assert.Equal(t, base[name], out, "%s 的其餘欄位與基底逐欄相同", name)
		}
	})

	t.Run("直接指派含 asset:update 的窄權限角色給無其他能力的他人：subjects 為空，一筆管理類發放", func(t *testing.T) {
		cam := f.role("c1-cam", "asset:view", "asset:update")
		target := f.user("c1-target")
		out := w.preview(map[string]any{"kind": "direct_roles", "user_id": target, "role_ids": []uint{cam}})
		assert.EqualValues(t, 1, out["total"])
		assert.Empty(t, out["subjects"])
		op := opOf(out)
		assert.Equal(t, []string{authz.GrantMarkManagementGrant}, strs(op["marks"]))
		assert.Equal(t, true, op["management_granted"])
		assert.Equal(t, "", op["self_direction"])
		assert.EqualValues(t, 1, op["evaluated"])
		assert.Equal(t, routesFromGolden(t, "asset:view", "asset:update"), strs(op["routes_gained"]), "與以同組能力經鏡像表求得的增減相同")
		assert.Empty(t, strs(op["routes_lost"]))

		m := w.mark()
		_, err := w.users.AssignRolesBy(w.op, target, []string{"c1-cam"})
		require.NoError(t, err)
		w.expectEvents(op, m, "user", target)
	})

	t.Run("直接指派的假設狀態只替換手動成分，保留映射來源（預覽與真實寫入同夾具對照）", func(t *testing.T) {
		auditorID := w.env.roleID(model.RoleAuditor)

		t.Run("目標以映射持有 auditor、送空角色集：入口不減少、不錯報，寫入後映射仍在", func(t *testing.T) {
			target := f.user("m1a-target")
			f.holdMapped(target, auditorID)
			out := w.preview(map[string]any{"kind": "direct_roles", "user_id": target, "role_ids": []uint{}})
			op := opOf(out)
			assert.Empty(t, strs(op["routes_lost"]), "只由映射提供的入口不會因手動集清空而失去")
			assert.Empty(t, strs(op["routes_gained"]))
			assert.Equal(t, "", op["self_direction"])
			assert.Empty(t, strs(op["marks"]))
			assert.Empty(t, out["subjects"], "對該目標本身沒有任何能力變化")

			m := w.mark()
			code, resp := w.env.api("S01", "PUT", fmt.Sprintf("/api/v1/users/%d/roles", target), map[string]any{"manual_roles": []string{}})
			require.Equal(t, http.StatusOK, code, "%v", resp)
			assert.Equal(t, model.RoleSourceMapped, f.roleSource(target, auditorID), "寫入保留映射來源")
			w.expectEvents(op, m, "user", target)
		})

		t.Run("目標以 both 持有 auditor、送空角色集：降為映射，入口不減少", func(t *testing.T) {
			target := f.user("m1b-target")
			f.holdBoth(target, auditorID)
			out := w.preview(map[string]any{"kind": "direct_roles", "user_id": target, "role_ids": []uint{}})
			op := opOf(out)
			assert.Empty(t, strs(op["routes_lost"]))
			assert.Empty(t, strs(op["routes_gained"]))
			assert.Equal(t, "", op["self_direction"])

			code, resp := w.env.api("S01", "PUT", fmt.Sprintf("/api/v1/users/%d/roles", target), map[string]any{"manual_roles": []string{}})
			require.Equal(t, http.StatusOK, code, "%v", resp)
			assert.Equal(t, model.RoleSourceMapped, f.roleSource(target, auditorID), "寫入把 both 降為 mapped")
		})

		t.Run("目標只以手動持有 auditor、送空角色集：入口確實失去（對照組）", func(t *testing.T) {
			target := f.user("m1c-target")
			f.hold(target, auditorID)
			out := w.preview(map[string]any{"kind": "direct_roles", "user_id": target, "role_ids": []uint{}})
			assert.Subset(t, strs(opOf(out)["routes_lost"]), []string{"/alerts", "/audit-logs"}, "手動成分被移除時才失去")
			code, resp := w.env.api("S01", "PUT", fmt.Sprintf("/api/v1/users/%d/roles", target), map[string]any{"manual_roles": []string{}})
			require.Equal(t, http.StatusOK, code, "%v", resp)
			assert.Equal(t, "", f.roleSource(target, auditorID))
		})

		t.Run("危險組合只在保留映射時才成立：預覽必須報出該組合，寫入後映射仍在", func(t *testing.T) {
			authzMgr := f.role("m1d-authz", "authorization:manage")
			cam := f.role("m1d-cam", "asset:view", "asset:update")
			target := f.user("m1d-target")
			f.holdMapped(target, authzMgr)
			out := w.preview(map[string]any{"kind": "direct_roles", "user_id": target, "role_ids": []uint{cam}})
			subjects, _ := out["subjects"].([]any)
			require.Len(t, subjects, 1, "映射持有的 authorization:manage 與新指派的 asset:update 構成新組合")
			subj := subjects[0].(map[string]any)
			assert.EqualValues(t, target, subj["user_id"])
			assert.NotEmpty(t, strs(subj["new_combos"]), "新組合必須列出")
			op := opOf(out)
			assert.Equal(t, []string{authz.GrantMarkManagementGrant}, strs(op["marks"]))

			m := w.mark()
			_, err := w.users.AssignRolesBy(w.op, target, []string{"m1d-cam"})
			require.NoError(t, err)
			assert.Equal(t, model.RoleSourceMapped, f.roleSource(target, authzMgr), "寫入保留映射來源")
			assert.Equal(t, model.RoleSourceManual, f.roleSource(target, cam))
			w.expectEvents(op, m, "user", target)
			// 寫入後的有效能力確實同時含兩者
			p, err := authz.NewResolver(w.env.db).ResolveUser(target, authz.TokenFacts{})
			require.NoError(t, err)
			assert.True(t, p.Has(authz.PermAuthorizationManage) && p.Has(authz.Permission("asset:update")), "實際有效能力含映射與新指派")
		})
	})

	t.Run("本人目標：持有映射或 both 的角色，預覽的 self_direction 與實際寫入後的有效指派摘要一致", func(t *testing.T) {
		auditorID := w.env.roleID(model.RoleAuditor)
		// 另建一位超管當本人，保留原超管；本人身分以自己的憑證呼叫預覽，才會走 self 分支。
		newSelf := func(name string) (uint, string, identity.Operator) {
			id := f.user(name)
			f.hold(id, adminID)
			subj := "SELF-" + name
			w.env.subjects[subj] = &baselineSubject{ID: subj, Username: name, UserID: id, Kind: "session", Token: w.env.issueSessionToken(id)}
			return id, subj, identity.Operator{UserID: id, Username: name}
		}
		// summaryDirection 以寫入前後的有效指派摘要求本人方向（與寫入關卡同一個分類器）。
		summaryDirection := func(id uint, write func()) (authz.GrantDirection, authz.GrantClassification) {
			before, err := authz.SummarizeGrants(w.env.db, id)
			require.NoError(t, err)
			write()
			after, err := authz.SummarizeGrants(w.env.db, id)
			require.NoError(t, err)
			cl := authz.ClassifyGrantChange(before, after, true)
			return cl.SelfDirection, cl
		}
		previewSelf := func(subj string, id uint, roleIDs []uint) map[string]any {
			code, out := w.env.api(subj, "POST", "/api/v1/role-assignment-previews",
				map[string]any{"kind": "direct_roles", "user_id": id, "role_ids": roleIDs})
			require.Equal(t, http.StatusOK, code, "%v", out)
			return out
		}

		t.Run("本人以映射持有 auditor、保留超管只清掉手動 auditor 之外的集合：方向為空，寫入後摘要不變", func(t *testing.T) {
			id, subj, op := newSelf("lc01-mapped")
			f.holdMapped(id, auditorID)
			out := previewSelf(subj, id, []uint{adminID})
			pre := opOf(out)
			assert.Equal(t, "", pre["self_direction"])
			assert.Empty(t, strs(pre["marks"]))
			dir, cl := summaryDirection(id, func() {
				_, err := w.users.AssignRolesBy(op, id, []string{model.RoleAdmin})
				require.NoError(t, err)
			})
			assert.Equal(t, authz.GrantNone, dir, "寫入後有效指派摘要沒有增減")
			assert.Equal(t, string(dir), pre["self_direction"], "預覽方向等於實際摘要方向")
			assert.Empty(t, cl.Marks)
			assert.Equal(t, model.RoleSourceMapped, f.roleSource(id, auditorID), "映射來源仍在")
		})

		t.Run("本人以 both 持有 auditor、請求集合不含它：降為映射，方向為空，與寫入後摘要一致", func(t *testing.T) {
			id, subj, op := newSelf("lc01-both")
			f.holdBoth(id, auditorID)
			out := previewSelf(subj, id, []uint{adminID})
			pre := opOf(out)
			dir, _ := summaryDirection(id, func() {
				_, err := w.users.AssignRolesBy(op, id, []string{model.RoleAdmin})
				require.NoError(t, err)
			})
			assert.Equal(t, "", pre["self_direction"])
			assert.Equal(t, authz.GrantNone, dir)
			assert.Equal(t, model.RoleSourceMapped, f.roleSource(id, auditorID))
		})

		t.Run("本人手動持有 auditor、移出請求集合：預覽與寫入後摘要都是減少（對照組）", func(t *testing.T) {
			id, subj, op := newSelf("lc01-manual")
			f.hold(id, auditorID)
			out := previewSelf(subj, id, []uint{adminID})
			pre := opOf(out)
			dir, _ := summaryDirection(id, func() {
				_, err := w.users.AssignRolesBy(op, id, []string{model.RoleAdmin})
				require.NoError(t, err)
			})
			assert.Equal(t, authz.GrantDecrease, dir)
			assert.Equal(t, string(dir), pre["self_direction"])
			assert.Equal(t, []string{authz.GrantMarkSelfAuthorization}, strs(pre["marks"]))
		})

		t.Run("本人送空集合（含手動超管一併移出）：寫入成功，預覽方向與實際摘要方向一致", func(t *testing.T) {
			id, subj, op := newSelf("lc01-empty")
			f.holdMapped(id, auditorID)
			out := previewSelf(subj, id, []uint{})
			pre := opOf(out)
			// 本人降權只告警、不被關卡拒絕：寫入必須成功，任何錯誤都是失敗。
			dir, _ := summaryDirection(id, func() {
				_, err := w.users.AssignRolesBy(op, id, []string{})
				require.NoError(t, err)
			})
			assert.Equal(t, authz.GrantDecrease, dir, "超管移出後本人有效指派減少")
			assert.Equal(t, string(dir), pre["self_direction"], "預覽方向等於實際摘要方向")
			assert.Equal(t, model.RoleSourceMapped, f.roleSource(id, auditorID), "映射 auditor 仍在")
		})
	})

	t.Run("自訂角色指派依目標集合：相容目錄拒絕，完整目錄放行並走既有分級與告警", func(t *testing.T) {
		cam := f.role("c1b-cam", "asset:view", "asset:update")
		assembledFull := assembledCatalogIsFull()
		put := func(target uint) (int, map[string]any) {
			return w.env.api("S01", "PUT", fmt.Sprintf("/api/v1/users/%d/roles", target), map[string]any{"manual_roles": []string{"c1b-cam"}})
		}

		// 正式組裝的路由只代表它實際注入的那一種目錄；另一種以明示注入的服務驗同一個指派
		t.Run("相容目錄（"+catalogVia(false)+"）", func(t *testing.T) {
			target := f.user("c1b-target")
			before := w.counts()
			if !assembledFull {
				code, out := put(target)
				assert.Equal(t, http.StatusBadRequest, code, "%v", out)
				assert.Equal(t, "VALIDATION_ROLE_NOT_FOUND", out["code"], "%v", out)
			} else {
				users := identity.NewUserService(w.env.db, nil)
				users.SetAssignmentGuard(identity.NewAssignmentGuard(identity.CompatCatalog()))
				users.SetGrantGrader(identity.NewGrantGrader(audit.NewTxSink(), audit.NewSystemAlertSink(nil)))
				_, err := users.AssignRolesBy(w.op, target, []string{"c1b-cam"})
				assert.ErrorIs(t, err, identity.ErrRoleNotFound)
			}
			after := w.counts()
			assert.Equal(t, before.userRoles, after.userRoles, "被拒的指派沒有寫入")
			assert.Equal(t, before.alerts, after.alerts)
		})

		t.Run("完整目錄（"+catalogVia(true)+"）", func(t *testing.T) {
			target := f.user("c1b-target-full")
			before := w.counts()
			if assembledFull {
				code, out := put(target)
				assert.Equal(t, http.StatusOK, code, "%v", out)
			} else {
				_, err := w.users.AssignRolesBy(w.op, target, []string{"c1b-cam"})
				require.NoError(t, err)
			}
			after := w.counts()
			assert.Equal(t, before.userRoles+1, after.userRoles, "指派寫入一列")
			assert.Equal(t, model.RoleSourceManual, f.roleSource(target, cam))
			assert.Equal(t, before.graded+1, after.graded, "寫入經既有分級留下標記審計")
			require.Equal(t, before.alerts+1, after.alerts, "寫入經既有告警恰一筆")
			var ev model.SystemAlertDetail
			require.NoError(t, w.env.db.Order("alert_id DESC").First(&ev).Error)
			assert.Equal(t, authz.AlertKeyManagementGranted, ev.AlertType)
		})
	})

	t.Run("目標已有某組合、變更後無新組合但有管理類發放：subjects 為空，management_granted 為真", func(t *testing.T) {
		cx := f.role("c2-cx", "authorization:manage", "asset:update")
		cy := f.role("c2-cy", "asset:delete")
		target := f.user("c2-target")
		f.hold(target, cx)
		out := w.preview(map[string]any{"kind": "direct_roles", "user_id": target, "role_ids": []uint{cx, cy}})
		assert.Empty(t, out["subjects"], "沒有新組合，不列出")
		op := opOf(out)
		assert.Equal(t, true, op["management_granted"])
		assert.Equal(t, []string{authz.GrantMarkManagementGrant}, strs(op["marks"]))

		m := w.mark()
		_, err := w.users.AssignRolesBy(w.op, target, []string{"c2-cx", "c2-cy"})
		require.NoError(t, err)
		w.expectEvents(op, m, "user", target)
	})

	t.Run("空群組新增管理類角色：total 0，marks 含管理類發放，寫入產生一筆以群組為目標的事件", func(t *testing.T) {
		cam := f.role("c3-cam", "asset:view", "asset:update")
		gid := f.group("c3-group", nil, nil, nil)
		out := w.preview(map[string]any{"kind": "group_roles", "group_id": gid, "role_ids": []uint{cam}})
		assert.EqualValues(t, 0, out["total"])
		assert.Empty(t, out["subjects"])
		op := opOf(out)
		assert.Equal(t, []string{authz.GrantMarkManagementGrant}, strs(op["marks"]))
		assert.EqualValues(t, 0, op["evaluated"])
		m := w.mark()
		_, err := w.groups.ReplaceRoleBindings(w.op, gid, identity.GroupRoleBindingsRequest{RoleIDs: []uint{cam}})
		require.NoError(t, err)
		w.expectEvents(op, m, "user_group", gid)
	})

	t.Run("空群組新增內建管理角色：先預覽、再經真實路由寫入", func(t *testing.T) {
		gid := f.group("c3b-group", nil, nil, nil)
		out := w.preview(map[string]any{"kind": "group_roles", "group_id": gid, "role_ids": []uint{adminID}})
		assert.EqualValues(t, 0, out["total"])
		op := opOf(out)
		assert.Equal(t, []string{authz.GrantMarkManagementGrant}, strs(op["marks"]))
		m := w.mark()
		code, resp := w.env.api("S01", "PUT", fmt.Sprintf("/api/v1/user-groups/%d/role-bindings", gid), map[string]any{"role_ids": []uint{adminID}})
		require.Equal(t, http.StatusOK, code, "%v", resp)
		w.expectEvents(op, m, "user_group", gid)
	})

	t.Run("內建管理角色給他人：新命中組合列出主體，標記與寫入相同（真實路由）", func(t *testing.T) {
		target := f.user("c1c-target")
		out := w.preview(map[string]any{"kind": "direct_roles", "user_id": target, "role_ids": []uint{adminID}})
		assert.NotEmpty(t, out["subjects"])
		op := opOf(out)
		assert.Equal(t, []string{authz.GrantMarkManagementGrant}, strs(op["marks"]))
		assert.NotEmpty(t, strs(op["routes_gained"]))
		m := w.mark()
		code, resp := w.env.api("S01", "PUT", fmt.Sprintf("/api/v1/users/%d/roles", target), map[string]any{"manual_roles": []string{model.RoleAdmin}})
		require.Equal(t, http.StatusOK, code, "%v", resp)
		w.expectEvents(op, m, "user", target)
	})

	t.Run("群組手動成員與映射成員", func(t *testing.T) {
		t.Run("清掉手動成員 A：映射成員 B 不被回報失去授權，寫入後 B 仍是成員", func(t *testing.T) {
			a, b := f.user("c4a-a"), f.user("c4a-b")
			gid := f.group("c4a-group", []uint{a}, []uint{b}, []uint{adminID})
			out := w.preview(map[string]any{"kind": "group_members", "group_id": gid, "manual_member_ids": []uint{}})
			assert.EqualValues(t, 1, out["total"], "受影響者只有 A")
			assert.EqualValues(t, 1, opOf(out)["evaluated"])
			assert.Empty(t, strs(opOf(out)["marks"]))
			// 對照：舊的整組有效成員語義把 B 也當成被移出
			legacy := w.preview(map[string]any{"kind": "group_members", "group_id": gid, "member_ids": []uint{}})
			assert.EqualValues(t, 2, legacy["total"])
			m := w.mark()
			code, resp := w.env.api("S01", "PUT", fmt.Sprintf("/api/v1/user-groups/%d/members", gid), map[string]any{"manual_user_ids": []uint{}})
			require.Equal(t, http.StatusOK, code, "%v", resp)
			w.expectEvents(opOf(out), m, "user_group", gid)
			assert.EqualValues(t, 1, w.count("user_group_members", "user_group_id = ?", gid))
			assert.EqualValues(t, 1, w.count("user_group_members", "user_group_id = ? AND user_id = ?", gid, b))
		})

		t.Run("映射成員 B 是操作者本人：self_direction 為空，寫入結果相同", func(t *testing.T) {
			a := f.user("c4b-a")
			gid := f.group("c4b-group", []uint{a}, []uint{f.sup}, []uint{w.env.roleID(model.RoleAuditor)})
			out := w.preview(map[string]any{"kind": "group_members", "group_id": gid, "manual_member_ids": []uint{}})
			op := opOf(out)
			assert.Equal(t, "", op["self_direction"])
			assert.NotContains(t, strs(op["marks"]), authz.GrantMarkSelfAuthorization)
			m := w.mark()
			code, resp := w.env.api("S01", "PUT", fmt.Sprintf("/api/v1/user-groups/%d/members", gid), map[string]any{"manual_user_ids": []uint{}})
			require.Equal(t, http.StatusOK, code, "%v", resp)
			w.expectEvents(op, m, "user_group", gid)
			assert.EqualValues(t, 1, w.count("user_group_members", "user_group_id = ? AND user_id = ?", gid, f.sup))
		})

		t.Run("映射成員 B 改列為手動：有效成員不變，仍算加入，群組帶管理類角色時一筆群組事件", func(t *testing.T) {
			a, b := f.user("c4c-a"), f.user("c4c-b")
			gid := f.group("c4c-group", []uint{a}, []uint{b}, []uint{adminID})
			out := w.preview(map[string]any{"kind": "group_members", "group_id": gid, "manual_member_ids": []uint{a, b}})
			assert.EqualValues(t, 0, out["total"], "有效成員不變")
			op := opOf(out)
			assert.Equal(t, []string{authz.GrantMarkManagementGrant}, strs(op["marks"]))
			m := w.mark()
			code, resp := w.env.api("S01", "PUT", fmt.Sprintf("/api/v1/user-groups/%d/members", gid), map[string]any{"manual_user_ids": []uint{a, b}})
			require.Equal(t, http.StatusOK, code, "%v", resp)
			w.expectEvents(op, m, "user_group", gid)
		})

		t.Run("同時送 member_ids 與 manual_member_ids 回 400", func(t *testing.T) {
			gid := f.group("c4d-group", nil, nil, nil)
			code, _ := w.env.api("S01", "POST", "/api/v1/role-assignment-previews",
				map[string]any{"kind": "group_members", "group_id": gid, "member_ids": []uint{}, "manual_member_ids": []uint{}})
			assert.Equal(t, http.StatusBadRequest, code)
		})

		t.Run("兩個成員鍵其中一個是 null 也算同時送，回 400", func(t *testing.T) {
			gid := f.group("c4e-group", nil, nil, nil)
			for name, body := range map[string]string{
				"manual 為 null": fmt.Sprintf(`{"kind":"group_members","group_id":%d,"manual_member_ids":null,"member_ids":[]}`, gid),
				"member 為 null": fmt.Sprintf(`{"kind":"group_members","group_id":%d,"manual_member_ids":[],"member_ids":null}`, gid),
				"兩者皆為 null":     fmt.Sprintf(`{"kind":"group_members","group_id":%d,"manual_member_ids":null,"member_ids":null}`, gid),
			} {
				code, _ := w.env.apiRaw("S01", "POST", "/api/v1/role-assignment-previews", body)
				assert.Equal(t, http.StatusBadRequest, code, name)
			}
			// 只送一個鍵（含 null）仍照舊處理
			code, _ := w.env.apiRaw("S01", "POST", "/api/v1/role-assignment-previews",
				fmt.Sprintf(`{"kind":"group_members","group_id":%d,"manual_member_ids":[]}`, gid))
			assert.Equal(t, http.StatusOK, code)
		})
	})

	t.Run("映射規則變更", w.mappingRuleCases)

	t.Run("可管理資產台數：選用欄位只回數字，其他三種輸入帶此欄時不回台數", func(t *testing.T) {
		node := model.AssetGroup{Name: "pc-node"}
		require.NoError(t, w.env.db.Create(&node).Error)
		ast := model.Asset{Name: "zz-pc-asset", Protocol: model.ProtocolSSH, Host: "zz-pc-host.example", Port: 22}
		require.NoError(t, w.env.db.Create(&ast).Error)
		require.NoError(t, w.env.db.Create(&model.AssetNode{AssetID: ast.ID, NodeID: node.ID}).Error)
		var perms []string
		for _, p := range authz.ScopedTemplateAssetAdminPermissions() {
			perms = append(perms, string(p))
		}
		mgr := f.role("pc-mgr", perms...)
		target := f.user("pc-target")
		countKeys := []string{"managed_assets", "group_assets", "role_assets"}
		stripCounts := func(out map[string]any) map[string]any {
			for _, k := range countKeys {
				delete(out, k)
			}
			return out
		}
		noCounts := func(out map[string]any, what string) {
			for _, k := range countKeys {
				assert.NotContains(t, out, k, what)
			}
		}

		// 具 role:assign 與 user:manage、沒有任何資產權限的身分管理者
		opRole := f.role("pc-op", "role:assign", "user:manage")
		opUser := f.user("pc-op-user")
		f.hold(opUser, opRole)
		w.env.subjects["PCOP"] = &baselineSubject{ID: "PCOP", Username: "pc-op-user", UserID: opUser, Kind: "session", Token: w.env.issueSessionToken(opUser)}

		body := map[string]any{"kind": "direct_roles", "user_id": target, "role_ids": []uint{mgr},
			"role_nodes": map[string]any{fmt.Sprint(mgr): []uint{node.ID}}}
		plain := w.previewAs("PCOP", body)
		noCounts(plain, "不帶此欄")
		withBody := map[string]any{"include_managed_asset_counts": true}
		for k, v := range body {
			withBody[k] = v
		}
		out := w.previewAs("PCOP", withBody)
		ma, _ := out["managed_assets"].(map[string]any)
		require.NotNil(t, ma, "%v", out)
		assert.EqualValues(t, 0, ma["before"])
		assert.EqualValues(t, 1, ma["after"])
		rows, _ := out["role_assets"].([]any)
		require.Len(t, rows, 1)
		row := rows[0].(map[string]any)
		assert.EqualValues(t, mgr, row["role_id"])
		assert.EqualValues(t, 1, row["total"])
		for k := range row {
			assert.Contains(t, []string{"role_id", "direct", "from_groups_extra", "total"}, k)
		}
		raw, err := json.Marshal(out)
		require.NoError(t, err)
		assert.NotContains(t, string(raw), "zz-pc-asset")
		assert.NotContains(t, string(raw), "zz-pc-host")
		assert.Equal(t, plain, stripCounts(out), "除台數欄位外與不帶此欄的回應逐欄相同")

		// 其他三種輸入：帶此欄與不帶時狀態碼相同、回應不含台數鍵
		gMembers := f.group("pc-members", []uint{target}, nil, nil)
		rd := f.role("pc-rd", "asset:view")
		m := w.newMappingWorld()
		gRule := f.group(m.name("pc-group"), nil, nil, []uint{m.admin})
		mapBody := m.previewBody(map[string]any{"rule_type": "user_group", "match_value": m.name("pc-hit"), "group_id": gRule})
		for name, b := range map[string]map[string]any{
			"群組成員異動": {"kind": "group_members", "group_id": gMembers, "member_ids": []uint{target, f.user("pc-m2")}},
			"角色定義修改": {"kind": "role_definition", "role_id": rd, "permissions": []string{"asset:view", "asset:update"}},
			"映射規則變更": mapBody,
		} {
			without := w.preview(b)
			with := map[string]any{"include_managed_asset_counts": true}
			for k, v := range b {
				with[k] = v
			}
			got := w.preview(with)
			noCounts(got, name)
			assert.Equal(t, without, got, name)
		}
		// 映射規則變更另帶 subject_ids 或其他未知鍵時照舊 400
		for _, extra := range []map[string]any{{"subject_ids": []uint{1}}, {"unknown_key": 1}} {
			bad := map[string]any{"include_managed_asset_counts": true}
			for k, v := range mapBody {
				bad[k] = v
			}
			for k, v := range extra {
				bad[k] = v
			}
			c, resp := w.env.api("S01", "POST", "/api/v1/role-assignment-previews", bad)
			assert.Equal(t, http.StatusBadRequest, c, "%v", resp)
		}
	})

	t.Run("頁面入口增減取自鏡像表", func(t *testing.T) {
		for _, c := range []struct {
			name, perm, must string
		}{
			{"r-secret", "credential:set-secret", "/credentials"},
			{"r-audit", "audit:view", "/alerts"},
		} {
			role := f.role(c.name, c.perm)
			target := f.user(c.name + "-target")
			out := w.preview(map[string]any{"kind": "direct_roles", "user_id": target, "role_ids": []uint{role}})
			got := strs(opOf(out)["routes_gained"])
			assert.Equal(t, routesFromGolden(t, c.perm), got)
			assert.Contains(t, got, c.must)
			assert.NotContains(t, got, "/assets")
		}
		// 只新增 credential:set-secret 不會讓告警頁出現
		role := f.role("r-secret2", "credential:set-secret")
		out := w.preview(map[string]any{"kind": "direct_roles", "user_id": f.user("r-secret2-target"), "role_ids": []uint{role}})
		assert.NotContains(t, strs(opOf(out)["routes_gained"]), "/alerts")
	})
}

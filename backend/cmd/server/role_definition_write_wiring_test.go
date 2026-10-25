package main

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/api"
	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/identity"
)

// TestRoleDefinitionWriteWiring 擋：寫入方法的錯誤映射偏離、請求本文的未列鍵或尾端內容被接受、
// 內部寫入失敗洩漏原因或用錯機器碼、stage2 組裝的 handler 沒拿到已注入分級器的服務。
// 以測試專用引擎直接掛 handler 方法，涵蓋正式路由表之外的畸形輸入與依賴缺席案例；
// 經正式路由的案例在 TestRoleDefinitionRoutes。
func TestRoleDefinitionWriteWiring(t *testing.T) {
	env := newBaselineEnv(t)
	f := newPreviewFixture(t, env)
	super := f.sup
	auditorID := env.roleID(model.RoleAuditor)

	type snapshot struct {
		roles, perms, version, alerts int64
		defVersion                    int64
	}
	snap := func(roleID uint) snapshot {
		var s snapshot
		require.NoError(t, env.db.Unscoped().Model(&model.Role{}).Count(&s.roles).Error)
		require.NoError(t, env.db.Model(&model.RolePermission{}).Count(&s.perms).Error)
		v, err := authz.CurrentVersion(env.db)
		require.NoError(t, err)
		s.version = v
		require.NoError(t, env.db.Table("system_alert_details").Count(&s.alerts).Error)
		if roleID != 0 {
			var r model.Role
			require.NoError(t, env.db.Unscoped().First(&r, roleID).Error)
			s.defVersion = r.DefinitionVersion
		}
		return s
	}
	codeOf := func(out map[string]any) string { s, _ := out["code"].(string); return s }

	assembled := newRoleWriteHarness(t, env.graph.deps.roleDefinition)

	t.Run("stage2 組裝的 handler 帶著已注入分級器的服務：修改他人持有的角色並加入管理權限，同交易有一筆管理類發放事件", func(t *testing.T) {
		role := f.role("w-held", "asset:view")
		holder := f.user("w-holder")
		f.hold(holder, role)
		before := snap(role)
		code, out, raw := assembled.do(super, "PUT", fmt.Sprintf("/defs/%d", role),
			fmt.Sprintf(`{"name":"w-held","description":"","permissions":["asset:view","asset:update"],"expected_version":%d}`, before.defVersion))
		require.Equal(t, http.StatusOK, code, raw)
		assert.Contains(t, out, "missing_dependencies")
		after := snap(role)
		assert.Equal(t, before.alerts+1, after.alerts, "管理類發放事件恰一筆（分級器非 nil）")
		var ev model.SystemAlertDetail
		require.NoError(t, env.db.Order("alert_id DESC").First(&ev).Error)
		assert.Equal(t, authz.AlertKeyManagementGranted, ev.AlertType)
		assert.Equal(t, "role", ev.TargetKind)
		assert.Equal(t, fmt.Sprint(role), ev.TargetID)
	})

	t.Run("成功形狀：新增與複製 201、修改 200、刪除 204，回應含缺依賴欄位", func(t *testing.T) {
		code, out, raw := assembled.do(super, "POST", "/defs", `{"name":"w-new","description":"d","permissions":["asset:update"]}`)
		require.Equal(t, http.StatusCreated, code, raw)
		assert.Contains(t, out, "missing_dependencies")
		assert.NotEmpty(t, out["missing_dependencies"], "缺依賴的集合允許儲存並明示缺漏")
		id := uint(out["id"].(float64))

		code, cp, raw := assembled.do(super, "POST", fmt.Sprintf("/defs/%d/copy", id), `{"name":"w-new-copy","description":""}`)
		require.Equal(t, http.StatusCreated, code, raw)
		copyID := uint(cp["id"].(float64))

		code, _, raw = assembled.do(super, "PUT", fmt.Sprintf("/defs/%d", id),
			`{"name":"w-new","description":"d2","permissions":["asset:view"],"expected_version":1}`)
		require.Equal(t, http.StatusOK, code, raw)

		code, _, raw = assembled.do(super, "DELETE", fmt.Sprintf("/defs/%d?expected_version=1", copyID), "")
		assert.Equal(t, http.StatusNoContent, code, raw)
	})

	t.Run("錯誤映射：既有業務拒絕沿用既有機器碼，拒絕回應不含角色名或權限名", func(t *testing.T) {
		held := f.role("w-map-held", "asset:view")
		f.hold(f.user("w-map-holder"), held)
		free := f.role("w-map-free", "asset:view")
		nonSuper := f.user("w-map-nonsuper")
		f.hold(nonSuper, auditorID)

		cases := []struct {
			name         string
			actor        uint
			method, path string
			body         string
			status       int
			code         apierror.ErrCode
		}{
			{"非超管四種寫入：新增", nonSuper, "POST", "/defs", `{"name":"w-x","permissions":[]}`, 403, apierror.CodePermissionDenied},
			{"非超管四種寫入：複製", nonSuper, "POST", fmt.Sprintf("/defs/%d/copy", free), `{"name":"w-x"}`, 403, apierror.CodePermissionDenied},
			{"非超管四種寫入：修改", nonSuper, "PUT", fmt.Sprintf("/defs/%d", free), `{"name":"w-map-free","permissions":["asset:view"],"expected_version":1}`, 403, apierror.CodePermissionDenied},
			{"非超管四種寫入：刪除", nonSuper, "DELETE", fmt.Sprintf("/defs/%d?expected_version=1", free), "", 403, apierror.CodePermissionDenied},
			{"修改查無角色", super, "PUT", "/defs/999999", `{"name":"w-x","permissions":[],"expected_version":1}`, 404, apierror.CodeRoleNotFound},
			{"修改內建範本", super, "PUT", fmt.Sprintf("/defs/%d", auditorID), `{"name":"w-x","permissions":[],"expected_version":1}`, 409, apierror.CodeRoleDefinitionLocked},
			{"複製超級管理者", super, "POST", fmt.Sprintf("/defs/%d/copy", env.roleID(model.RoleAdmin)), `{"name":"w-x"}`, 409, apierror.CodeRoleDefinitionLocked},
			{"舊版本修改", super, "PUT", fmt.Sprintf("/defs/%d", free), `{"name":"w-map-free","permissions":["asset:view"],"expected_version":99}`, 409, apierror.CodeRoleDefinitionConflict},
			{"名稱已被使用", super, "POST", "/defs", `{"name":"w-map-free","permissions":[]}`, 409, apierror.CodeRoleDefinitionConflict},
			{"仍有直接指派的刪除", super, "DELETE", fmt.Sprintf("/defs/%d?expected_version=1", held), "", 409, apierror.CodeRoleDefinitionInUse},
			{"名稱空白", super, "POST", "/defs", `{"name":"  ","permissions":[]}`, 400, apierror.CodeBadParams},
			{"不合法的權限鍵", super, "POST", "/defs", `{"name":"w-bad","permissions":["no:such"]}`, 400, apierror.CodeRolePermissionInvalid},
			{"起手來源不存在", super, "POST", "/defs", `{"name":"w-bad","permissions":[],"template_role_id":999999}`, 400, apierror.CodeBadParams},
		}
		for _, tc := range cases {
			before := snap(free)
			code, out, raw := assembled.do(tc.actor, tc.method, tc.path, tc.body)
			assert.Equal(t, tc.status, code, "%s: %s", tc.name, raw)
			assert.Equal(t, string(tc.code), codeOf(out), "%s: %s", tc.name, raw)
			for _, leak := range []string{"w-map-held", "w-map-free", "asset:view", "no:such"} {
				assert.NotContains(t, raw, leak, "%s：拒絕回應不得含角色名或權限名", tc.name)
			}
			assert.Equal(t, before, snap(free), "%s：被拒的寫入不改任何資料", tc.name)
		}
	})

	t.Run("未列鍵、型別不符、尾端內容與缺必要欄位一律 400，角色不變", func(t *testing.T) {
		role := f.role("w-strict", "asset:view")
		id := fmt.Sprint(role)
		cases := []struct{ name, method, path, body string }{
			{"新增多帶 scope", "POST", "/defs", `{"name":"w-s1","permissions":[],"scope":"global"}`},
			{"新增多帶任意鍵", "POST", "/defs", `{"name":"w-s1","permissions":[],"builtin":true}`},
			{"新增本文串接第二份", "POST", "/defs", `{"name":"w-s1","permissions":[]}{"name":"w-s2"}`},
			{"新增尾端多餘右括號", "POST", "/defs", `{"name":"w-s1","permissions":[]}}`},
			{"新增權限鍵型別錯", "POST", "/defs", `{"name":"w-s1","permissions":"asset:view"}`},
			{"新增空本文", "POST", "/defs", ``},
			{"複製多帶權限鍵", "POST", "/defs/" + id + "/copy", `{"name":"w-s1","permissions":["asset:view"]}`},
			{"複製多帶 scope", "POST", "/defs/" + id + "/copy", `{"name":"w-s1","scope":"global"}`},
			{"修改多帶 scope", "PUT", "/defs/" + id, `{"name":"w-strict","permissions":["asset:view"],"expected_version":1,"scope":"global"}`},
			{"修改缺期望版本", "PUT", "/defs/" + id, `{"name":"w-strict","permissions":["asset:view"]}`},
			{"修改期望版本為 null", "PUT", "/defs/" + id, `{"name":"w-strict","permissions":["asset:view"],"expected_version":null}`},
			{"修改缺權限集合", "PUT", "/defs/" + id, `{"name":"w-strict","expected_version":1}`},
			{"修改權限集合為 null", "PUT", "/defs/" + id, `{"name":"w-strict","permissions":null,"expected_version":1}`},
			{"修改非數字 ID", "PUT", "/defs/abc", `{"name":"x","permissions":[],"expected_version":1}`},
			{"刪除缺期望版本", "DELETE", "/defs/" + id, ""},
			{"刪除期望版本非數字", "DELETE", "/defs/" + id + "?expected_version=x", ""},
			{"刪除多帶查詢參數", "DELETE", "/defs/" + id + "?expected_version=1&force=1", ""},
			{"刪除帶本文", "DELETE", "/defs/" + id + "?expected_version=1", `{"expected_version":1}`},
			{"刪除重複期望版本參數", "DELETE", "/defs/" + id + "?expected_version=1&expected_version=999", ""},
			{"刪除查詢字串含無效跳脫", "DELETE", "/defs/" + id + "?expected_version=1&x=%zz", ""},
		}
		for _, tc := range cases {
			before := snap(role)
			code, out, raw := assembled.do(super, tc.method, tc.path, tc.body)
			assert.Equal(t, http.StatusBadRequest, code, "%s: %s", tc.name, raw)
			assert.Contains(t, []string{string(apierror.CodeBadParams), string(apierror.CodeInvalidID)}, codeOf(out), "%s: %s", tc.name, raw)
			assert.Equal(t, before, snap(role), "%s：不寫入", tc.name)
		}
	})

	t.Run("刪除帶長度未知的本文（chunked）一律 400 且角色不變", func(t *testing.T) {
		role := f.role("w-chunk", "asset:view")
		before := snap(role)
		code, out, raw := assembled.doUnknownLength(super, "DELETE", fmt.Sprintf("/defs/%d?expected_version=1", role),
			`{"expected_version":999,"scope":"global"}`)
		assert.Equal(t, http.StatusBadRequest, code, raw)
		assert.Equal(t, string(apierror.CodeBadParams), codeOf(out), raw)
		assert.Equal(t, before, snap(role), "不寫入")
	})

	t.Run("內部寫入失敗一律 500 INTERNAL_ROLE_DEFINITION_WRITE，不回內部原因", func(t *testing.T) {
		held := f.role("w-internal", "asset:view")
		f.hold(f.user("w-internal-holder"), held)
		update := `{"name":"w-internal","permissions":["asset:view","asset:update"],"expected_version":1}`

		check := func(name string, h *roleWriteHarness, method, path, body string, roleID uint) {
			before := snap(roleID)
			code, out, raw := h.do(super, method, path, body)
			assert.Equal(t, http.StatusInternalServerError, code, "%s: %s", name, raw)
			assert.Equal(t, string(apierror.CodeInternalRoleDefinitionWrite), codeOf(out), "%s: %s", name, raw)
			for _, leak := range []string{"grader", "writer", "event", "missing", "w-internal"} {
				assert.NotContains(t, raw, leak, "%s：泛化訊息不得含內部原因", name)
			}
			assert.Equal(t, before, snap(roleID), "%s：失敗不改任何資料", name)
		}

		noGrader := newRoleWriteHarness(t, api.NewRoleDefinitionHandler(nil, newRoleDefinitionServiceForTest(env, false, true)))
		check("分級器未注入而角色有持有者", noGrader, "PUT", fmt.Sprintf("/defs/%d", held), update, held)
		noEvents := newRoleWriteHarness(t, api.NewRoleDefinitionHandler(nil, newRoleDefinitionServiceForTest(env, true, false)))
		check("事件寫入器未注入", noEvents, "POST", "/defs", `{"name":"w-internal-new","permissions":[]}`, 0)
		noWriter := newRoleWriteHarness(t, api.NewRoleDefinitionHandler(nil, nil))
		var typedNil *identity.RoleDefinitionService
		typedNilWriter := newRoleWriteHarness(t, api.NewRoleDefinitionHandler(nil, typedNil))
		check("寫入服務為 typed-nil 指標：新增", typedNilWriter, "POST", "/defs", `{"name":"w-internal-new3","permissions":[]}`, 0)
		check("寫入服務未注入：新增", noWriter, "POST", "/defs", `{"name":"w-internal-new2","permissions":[]}`, 0)
		check("寫入服務未注入：刪除", noWriter, "DELETE", fmt.Sprintf("/defs/%d?expected_version=1", held), "", held)

		// 無持有者也無引用者的角色，分級器未注入仍可照常修改（只擋有持有者或引用者的修改）
		free := f.role("w-internal-free", "asset:view")
		code, _, raw := noGrader.do(super, "PUT", fmt.Sprintf("/defs/%d", free),
			`{"name":"w-internal-free","permissions":["asset:view","asset:update"],"expected_version":1}`)
		assert.Equal(t, http.StatusOK, code, raw)
	})
}

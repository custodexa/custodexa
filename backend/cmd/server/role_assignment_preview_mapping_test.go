package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/authz"
)

// 映射規則變更預覽的契約案例（由 TestRoleAssignmentPreviewContract 的子案例呼叫）。
// 每案先預覽、再經真實映射寫入路由寫入，比對預覽的 operation 與寫入產生的標記審計與事件。

// writeWatch 「寫入即失敗」掛點：目標為映射規則、兩種支持表、角色指派、群組成員、權限版本或審計表，
// 或為任何儲存點的寫入，記錄並回錯誤。預覽路由自己的請求留痕（create／role）不算在內。
type writeWatch struct {
	mu   sync.Mutex
	hits []string
	db   *gorm.DB
	tag  string
}

var watchedTables = []string{"group_role_mappings", "group_user_group_mappings", "user_role_mapping_rule_supports",
	"user_group_mapping_rule_supports", "user_roles", "user_group_members", "authz_state", "audit_logs"}

// isPreviewTrace 預覽路由自己的 HTTP 請求留痕（read／role，批次寫入）；服務層的授權變更審計不屬於它。
func isPreviewTrace(dest any) bool {
	rows, ok := dest.([]*model.AuditLog)
	if !ok || len(rows) == 0 {
		return false
	}
	for _, r := range rows {
		if r.Action != model.ActionRead || r.Resource != model.ResourceRole || !strings.HasSuffix(r.Path, "/role-assignment-previews") {
			return false
		}
	}
	return true
}

func installWriteWatch(t *testing.T, db *gorm.DB) *writeWatch {
	t.Helper()
	ww := &writeWatch{db: db, tag: fmt.Sprintf("nowrite_%s", strings.ReplaceAll(t.Name(), "/", "_"))}
	check := func(table string, dest any) bool {
		for _, w := range watchedTables {
			if table != w {
				continue
			}
			if table == "audit_logs" && isPreviewTrace(dest) {
				return false
			}
			return true
		}
		return false
	}
	fail := func(kind string) func(*gorm.DB) {
		return func(tx *gorm.DB) {
			if check(tx.Statement.Table, tx.Statement.Dest) {
				ww.mu.Lock()
				ww.hits = append(ww.hits, fmt.Sprintf("%s:%s:%T:%+v", kind, tx.Statement.Table, tx.Statement.Dest, tx.Statement.Dest))
				ww.mu.Unlock()
				_ = tx.AddError(fmt.Errorf("寫入掛點攔截 %s %s", kind, tx.Statement.Table))
			}
		}
	}
	require.NoError(t, db.Callback().Create().Before("gorm:create").Register(ww.tag+"_c", fail("create")))
	require.NoError(t, db.Callback().Update().Before("gorm:update").Register(ww.tag+"_u", fail("update")))
	require.NoError(t, db.Callback().Delete().Before("gorm:delete").Register(ww.tag+"_d", fail("delete")))
	require.NoError(t, db.Callback().Raw().Before("gorm:raw").Register(ww.tag+"_r", func(tx *gorm.DB) {
		sql := strings.ToUpper(strings.TrimSpace(tx.Statement.SQL.String()))
		hit := strings.HasPrefix(sql, "SAVEPOINT")
		for _, p := range []string{"INSERT", "UPDATE", "DELETE", "REPLACE"} {
			if !strings.HasPrefix(sql, p) {
				continue
			}
			for _, tb := range watchedTables {
				if strings.Contains(sql, strings.ToUpper(tb)) {
					hit = true
				}
			}
		}
		if hit {
			ww.mu.Lock()
			ww.hits = append(ww.hits, "raw:"+sql[:min(len(sql), 60)])
			ww.mu.Unlock()
			_ = tx.AddError(fmt.Errorf("寫入掛點攔截 raw"))
		}
	}))
	return ww
}

func (ww *writeWatch) remove(t *testing.T) {
	t.Helper()
	require.NoError(t, ww.db.Callback().Create().Remove(ww.tag+"_c"))
	require.NoError(t, ww.db.Callback().Update().Remove(ww.tag+"_u"))
	require.NoError(t, ww.db.Callback().Delete().Remove(ww.tag+"_d"))
	require.NoError(t, ww.db.Callback().Raw().Remove(ww.tag+"_r"))
}

func (ww *writeWatch) count() int {
	ww.mu.Lock()
	defer ww.mu.Unlock()
	return len(ww.hits)
}

// mappingWorld 映射案例共用的小工具。
type mappingWorld struct {
	*contractWorld
	prov    uint
	channel string
	admin   uint // 內建 admin 角色編號
	seq     int
}

func (w *contractWorld) newMappingWorld() *mappingWorld {
	prov, ok := w.env.object("oidcProvider.1").(uint)
	require.True(w.t, ok)
	return &mappingWorld{contractWorld: w, prov: prov,
		channel: model.RoleMappingChannel(model.RoleMappingChannelKindProvider, prov), admin: w.env.roleID(model.RoleAdmin)}
}

func (m *mappingWorld) name(prefix string) string {
	m.seq++
	return fmt.Sprintf("%s-%d", prefix, m.seq)
}

func (m *mappingWorld) base() string {
	return fmt.Sprintf("/api/v1/identity-sources/oidc/%d", m.prov)
}

// groupRule 經真實路由建立一條使用者群組規則，回傳規則編號。
func (m *mappingWorld) groupRule(match string, gid uint) uint {
	m.t.Helper()
	d := m.env.mustAPI("S01", http.MethodPost, m.base()+"/user-group-mappings", map[string]any{
		"match_value": match, "user_group_id": gid, "enabled": true, "risk_acknowledged": true, "source_config_acknowledged": true})
	return m.env.idOf(d, "user group rule")
}

// roleRule 經真實路由建立一條角色規則。
func (m *mappingWorld) roleRule(match, role string) uint {
	m.t.Helper()
	d := m.env.mustAPI("S01", http.MethodPost, m.base()+"/role-mappings", map[string]any{
		"match_value": match, "role": role, "enabled": true, "risk_acknowledged": true})
	return m.env.idOf(d, "role rule")
}

// supportGroup 讓 uid 目前由這條規則支持（manual 為真時同時是手動成員，否則是只受映射支持的成員）。
func (m *mappingWorld) supportGroup(uid, gid, ruleID uint, manual bool) {
	m.t.Helper()
	var n int64
	require.NoError(m.t, m.env.db.Table("user_group_members").Where("user_group_id = ? AND user_id = ?", gid, uid).Count(&n).Error)
	if n == 0 {
		require.NoError(m.t, m.env.db.Exec("INSERT INTO user_group_members(user_group_id,user_id,manual) VALUES (?,?,?)", gid, uid, manual).Error)
	}
	require.NoError(m.t, m.env.db.Create(&model.UserGroupMappingRuleSupport{UserID: uid, UserGroupID: gid, Channel: m.channel, RuleID: ruleID}).Error)
}

// snapshot 設定帳號最近一次已知群組觀測。
func (m *mappingWorld) observe(ids []uint, groups ...string) {
	m.t.Helper()
	raw, err := json.Marshal(groups)
	require.NoError(m.t, err)
	require.NoError(m.t, m.env.db.Model(&model.User{}).Where("id IN ?", ids).Updates(map[string]any{
		"group_snapshot_channel": m.channel, "group_snapshot_groups": string(raw)}).Error)
}

func (m *mappingWorld) disableGroupRule(ruleID uint, match string, gid uint) (int, map[string]any) {
	return m.env.api("S01", http.MethodPut, fmt.Sprintf("%s/user-group-mappings/%d", m.base(), ruleID), map[string]any{
		"match_value": match, "user_group_id": gid, "enabled": false, "risk_acknowledged": true, "source_config_acknowledged": true})
}

func (m *mappingWorld) previewBody(extra map[string]any) map[string]any {
	body := map[string]any{"kind": authz.PreviewMappingRuleChange, "source_type": "oidc", "source_id": m.prov}
	for k, v := range extra {
		body[k] = v
	}
	return body
}

func (m *mappingWorld) memberCount(uid, gid uint) int64 {
	return m.count("user_group_members", "user_id = ? AND user_group_id = ?", uid, gid)
}

func (m *mappingWorld) latestGroupRule(gid uint) uint {
	m.t.Helper()
	var id uint
	require.NoError(m.t, m.env.db.Model(&model.GroupUserGroupMapping{}).Where("user_group_id = ?", gid).Select("COALESCE(MAX(id),0)").Scan(&id).Error)
	return id
}

// selfOperator 另建一位超管當操作者本人，以自己的憑證呼叫預覽與寫入，才會走 self 分支。
func (m *mappingWorld) selfOperator(name string) (uint, string) {
	m.t.Helper()
	id := m.f.user(name)
	m.f.hold(id, m.admin)
	subj := "MAP-" + name
	m.env.subjects[subj] = &baselineSubject{ID: subj, Username: name, UserID: id, Kind: "session", Token: m.env.issueSessionToken(id)}
	return id, subj
}

// selfEvents 自 mk 之後針對 uid 本人寫入的自我授權事件類型。
func (m *mappingWorld) selfEvents(mk mark, uid uint) []string {
	events, _ := m.written(mk)
	var out []string
	for _, e := range events {
		if strings.HasSuffix(e, fmt.Sprintf("/user/%d", uid)) {
			out = append(out, e)
		}
	}
	return out
}

// mappingRuleCases 映射規則變更預覽的子案例。
func (w *contractWorld) mappingRuleCases(t *testing.T) {
	f := w.f
	m := w.newMappingWorld()
	groupBody := func(ruleID uint, match string, gid uint, extra map[string]any) map[string]any {
		b := map[string]any{"rule_type": "user_group", "match_value": match, "group_id": gid}
		if ruleID != 0 {
			b["rule_id"] = ruleID
		}
		for k, v := range extra {
			b[k] = v
		}
		return m.previewBody(b)
	}

	t.Run("新增零命中規則、目標為帶管理角色的群組：total 0，marks 含管理類發放，寫入一筆以映射規則為目標的事件", func(t *testing.T) {
		gid := f.group(m.name("m1-group"), nil, nil, []uint{m.admin})
		match := m.name("zero-hit")
		out := w.preview(groupBody(0, match, gid, nil))
		assert.EqualValues(t, 0, out["total"])
		op := opOf(out)
		assert.Equal(t, []string{authz.GrantMarkManagementGrant}, strs(op["marks"]))
		assert.EqualValues(t, 0, op["evaluated"])
		mk := w.mark()
		ruleID := m.groupRule(match, gid)
		w.expectEvents(op, mk, "role_mapping", ruleID)
	})

	t.Run("以既有規則識別與相同新值預覽：marks 為空、total 0，寫入不產生事件", func(t *testing.T) {
		gid := f.group(m.name("m2-group"), nil, nil, []uint{m.admin})
		match := m.name("same-value")
		ruleID := m.groupRule(match, gid)
		u := f.user(m.name("m2-user"))
		m.supportGroup(u, gid, ruleID, false)
		out := w.preview(groupBody(ruleID, match, gid, map[string]any{"enabled": true}))
		assert.EqualValues(t, 0, out["total"])
		assert.Empty(t, strs(opOf(out)["marks"]))
		mk := w.mark()
		code, resp := w.env.api("S01", http.MethodPut, fmt.Sprintf("%s/user-group-mappings/%d", m.base(), ruleID), map[string]any{
			"match_value": match, "user_group_id": gid, "enabled": true, "risk_acknowledged": true, "source_config_acknowledged": true})
		require.Equal(t, http.StatusOK, code, "%v", resp)
		events, graded := w.written(mk)
		assert.Empty(t, events)
		assert.EqualValues(t, 0, graded)
	})

	t.Run("停用時本人的分類只看是否真的失去授權", func(t *testing.T) {
		t.Run("操作者只經 R1 取得管理群組：減少，受影響者含所有目前受 R1 支持的帳號，寫入後恰一筆低分級自我授權", func(t *testing.T) {
			op, subj := m.selfOperator(m.name("m3a-op"))
			gid := f.group(m.name("m3a-group"), nil, nil, []uint{m.admin})
			match := m.name("m3a")
			r1 := m.groupRule(match, gid)
			u1, u2 := f.user(m.name("m3a-u")), f.user(m.name("m3a-u"))
			for _, id := range []uint{op, u1, u2} {
				m.supportGroup(id, gid, r1, false)
			}
			out := w.previewAs(subj, groupBody(r1, match, gid, map[string]any{"enabled": false}))
			assert.EqualValues(t, 3, out["total"])
			pre := opOf(out)
			assert.Equal(t, string(authz.GrantDecrease), pre["self_direction"])
			assert.Equal(t, []string{authz.GrantMarkSelfAuthorization}, strs(pre["marks"]))
			subjects, _ := out["subjects"].([]any)
			require.NotEmpty(t, subjects)
			first := subjects[0].(map[string]any)
			assert.EqualValues(t, op, first["user_id"])
			assert.Equal(t, true, first["self"])
			mk := w.mark()
			code, resp := w.env.api(subj, http.MethodPut, fmt.Sprintf("%s/user-group-mappings/%d", m.base(), r1), map[string]any{
				"match_value": match, "user_group_id": gid, "enabled": false, "risk_acknowledged": true, "source_config_acknowledged": true})
			require.Equal(t, http.StatusOK, code, "%v", resp)
			assert.EqualValues(t, 0, m.memberCount(op, gid), "寫入後操作者不再是群組成員")
			assert.Equal(t, []string{fmt.Sprintf("%s/user/%d", authz.AlertKeySelfDecreased, op)}, m.selfEvents(mk, op))
			_, graded := w.written(mk)
			assert.EqualValues(t, 1, graded)
		})

		t.Run("同一來源的 R1、R2 都把操作者帶入群組：受影響者含操作者，方向為空，寫入後仍是成員、自我授權事件 0 筆", func(t *testing.T) {
			op, subj := m.selfOperator(m.name("m3b-op"))
			gid := f.group(m.name("m3b-group"), nil, nil, []uint{m.admin})
			match1, match2 := m.name("m3b-1"), m.name("m3b-2")
			r1, r2 := m.groupRule(match1, gid), m.groupRule(match2, gid)
			m.supportGroup(op, gid, r1, false)
			m.supportGroup(op, gid, r2, false)
			out := w.previewAs(subj, groupBody(r1, match1, gid, map[string]any{"enabled": false}))
			assert.EqualValues(t, 1, out["total"])
			pre := opOf(out)
			assert.Equal(t, "", pre["self_direction"])
			assert.NotContains(t, strs(pre["marks"]), authz.GrantMarkSelfAuthorization)
			subjects, _ := out["subjects"].([]any)
			require.Len(t, subjects, 1)
			assert.EqualValues(t, op, subjects[0].(map[string]any)["user_id"])
			mk := w.mark()
			code, resp := w.env.api(subj, http.MethodPut, fmt.Sprintf("%s/user-group-mappings/%d", m.base(), r1), map[string]any{
				"match_value": match1, "user_group_id": gid, "enabled": false, "risk_acknowledged": true, "source_config_acknowledged": true})
			require.Equal(t, http.StatusOK, code, "%v", resp)
			assert.EqualValues(t, 1, m.memberCount(op, gid))
			assert.Empty(t, m.selfEvents(mk, op))
		})

		t.Run("操作者另是群組的手動成員：同上", func(t *testing.T) {
			op, subj := m.selfOperator(m.name("m3c-op"))
			gid := f.group(m.name("m3c-group"), nil, nil, []uint{m.admin})
			match := m.name("m3c")
			r1 := m.groupRule(match, gid)
			m.supportGroup(op, gid, r1, true)
			out := w.previewAs(subj, groupBody(r1, match, gid, map[string]any{"enabled": false}))
			assert.EqualValues(t, 1, out["total"])
			pre := opOf(out)
			assert.Equal(t, "", pre["self_direction"])
			assert.NotContains(t, strs(pre["marks"]), authz.GrantMarkSelfAuthorization)
			mk := w.mark()
			code, resp := w.env.api(subj, http.MethodPut, fmt.Sprintf("%s/user-group-mappings/%d", m.base(), r1), map[string]any{
				"match_value": match, "user_group_id": gid, "enabled": false, "risk_acknowledged": true, "source_config_acknowledged": true})
			require.Equal(t, http.StatusOK, code, "%v", resp)
			assert.EqualValues(t, 1, m.memberCount(op, gid))
			assert.Empty(t, m.selfEvents(mk, op))
		})

		t.Run("角色規則 R1 把角色映射給操作者，操作者另有手動指派：同上，寫入後角色仍在有效指派", func(t *testing.T) {
			op, subj := m.selfOperator(m.name("m3d-op"))
			auditor := w.env.roleID(model.RoleAuditor)
			match := m.name("m3d")
			r1 := m.roleRule(match, model.RoleAuditor)
			f.holdBoth(op, auditor)
			require.NoError(t, w.env.db.Create(&model.UserRoleMapping{UserID: op, RoleID: auditor, Channel: m.channel}).Error)
			require.NoError(t, w.env.db.Create(&model.UserRoleMappingRuleSupport{UserID: op, RoleID: auditor, Channel: m.channel, RuleID: r1}).Error)
			out := w.previewAs(subj, m.previewBody(map[string]any{"rule_type": "role", "rule_id": r1, "match_value": match,
				"role_id": auditor, "enabled": false}))
			assert.EqualValues(t, 1, out["total"])
			pre := opOf(out)
			assert.Equal(t, "", pre["self_direction"])
			assert.NotContains(t, strs(pre["marks"]), authz.GrantMarkSelfAuthorization)
			mk := w.mark()
			code, resp := w.env.api(subj, http.MethodPut, fmt.Sprintf("%s/role-mappings/%d", m.base(), r1), map[string]any{
				"match_value": match, "role": model.RoleAuditor, "enabled": false, "risk_acknowledged": true})
			require.Equal(t, http.StatusOK, code, "%v", resp)
			assert.Equal(t, model.RoleSourceManual, f.roleSource(op, auditor), "手動成分仍在")
			sum, err := authz.SummarizeGrants(w.env.db, op)
			require.NoError(t, err)
			has := false
			for _, e := range sum.Entries {
				has = has || e.RoleID == auditor
			}
			assert.True(t, has, "角色仍在有效指派")
			assert.Empty(t, m.selfEvents(mk, op))
		})
	})

	t.Run("修改規則目標由 A 群組改為 B 群組：受影響者含舊規則支持者與新值命中者，分類與寫入相同", func(t *testing.T) {
		ga := f.group(m.name("m4-a"), nil, nil, []uint{w.env.roleID(model.RoleAuditor)})
		gb := f.group(m.name("m4-b"), nil, nil, []uint{m.admin})
		oldMatch, newMatch := m.name("m4-old"), m.name("m4-new")
		ruleID := m.groupRule(oldMatch, ga)
		u1, u2, u3, u4 := f.user(m.name("m4-u")), f.user(m.name("m4-u")), f.user(m.name("m4-u")), f.user(m.name("m4-u"))
		m.supportGroup(u1, ga, ruleID, false)
		m.supportGroup(u2, ga, ruleID, false)
		m.observe([]uint{u3, u4}, newMatch)
		out := w.preview(groupBody(ruleID, newMatch, gb, nil))
		assert.EqualValues(t, 4, out["total"])
		op := opOf(out)
		assert.EqualValues(t, 4, op["evaluated"])
		assert.Equal(t, []string{authz.GrantMarkManagementGrant}, strs(op["marks"]))
		assert.Equal(t, "", op["self_direction"])
		listed := map[uint]bool{}
		subjects, _ := out["subjects"].([]any)
		for _, s := range subjects {
			listed[uint(s.(map[string]any)["user_id"].(float64))] = true
		}
		assert.True(t, listed[u3] && listed[u4], "新值命中者在假設授出後新命中組合")
		mk := w.mark()
		code, resp := w.env.api("S01", http.MethodPut, fmt.Sprintf("%s/user-group-mappings/%d", m.base(), ruleID), map[string]any{
			"match_value": newMatch, "user_group_id": gb, "risk_acknowledged": true, "source_config_acknowledged": true})
		require.Equal(t, http.StatusOK, code, "%v", resp)
		w.expectEvents(op, mk, "role_mapping", m.latestGroupRule(gb))
	})

	t.Run("命中 250 人且操作者本人編號最大：total 250、evaluated 200、truncated，操作者在 subjects 內", func(t *testing.T) {
		gid := f.group(m.name("m5-group"), nil, nil, []uint{m.admin})
		match := m.name("m5-hit")
		users := make([]model.User, 0, 249)
		for i := 0; i < 249; i++ {
			name := fmt.Sprintf("m5-bulk-%d", i)
			email := name + "@baseline.test"
			users = append(users, model.User{Username: name, Email: &email, Password: "!", FullName: name,
				Active: true, Kind: model.KindHuman, ProvisioningOrigin: model.AuthSourceLocal})
		}
		require.NoError(t, w.env.db.CreateInBatches(&users, 100).Error)
		ids := make([]uint, 0, 250)
		for _, u := range users {
			ids = append(ids, u.ID)
		}
		op, subj := m.selfOperator(m.name("m5-op"))
		ids = append(ids, op)
		for _, id := range ids {
			require.Less(t, id, op+1)
		}
		m.observe(ids, match)
		out := w.previewAs(subj, groupBody(0, match, gid, nil))
		assert.EqualValues(t, 250, out["total"])
		pre := opOf(out)
		assert.EqualValues(t, 200, pre["evaluated"])
		assert.Equal(t, true, out["truncated"])
		subjects, _ := out["subjects"].([]any)
		require.NotEmpty(t, subjects)
		first := subjects[0].(map[string]any)
		assert.EqualValues(t, op, first["user_id"])
		assert.Equal(t, true, first["self"])
		assert.Equal(t, string(authz.GrantIncrease), pre["self_direction"], "規則層分類不因抽樣遺失")
	})

	t.Run("輸入驗證與權限", func(t *testing.T) {
		gid := f.group(m.name("m6-group"), nil, nil, []uint{m.admin})
		match := m.name("m6")
		ruleID := m.groupRule(match, gid)
		spare, ok := w.env.object("oidcProvider.spare").(uint)
		require.True(t, ok)
		post := func(subj string, body map[string]any) (int, map[string]any) {
			return w.env.api(subj, http.MethodPost, "/api/v1/role-assignment-previews", body)
		}
		t.Run("本文帶 subject_ids 或其他未列鍵回 400", func(t *testing.T) {
			code, _ := post("S01", groupBody(0, match, gid, map[string]any{"subject_ids": []uint{1}}))
			assert.Equal(t, http.StatusBadRequest, code)
			code, _ = post("S01", groupBody(0, match, gid, map[string]any{"user_id": 1}))
			assert.Equal(t, http.StatusBadRequest, code)
			code, _ = post("S01", groupBody(0, match, gid, map[string]any{"manual_member_ids": []uint{1}}))
			assert.Equal(t, http.StatusBadRequest, code)
		})
		t.Run("rule_id 不屬於該來源或不存在回 400", func(t *testing.T) {
			code, other := post("S01", groupBody(ruleID, match, gid, map[string]any{"source_id": spare}))
			assert.Equal(t, http.StatusBadRequest, code)
			code2, missing := post("S01", groupBody(999999, match, gid, nil))
			assert.Equal(t, http.StatusBadRequest, code2)
			assert.Equal(t, other, missing, "屬於他來源與不存在的回應相同，不洩漏規則存在與否")
			code, _ = post("S01", m.previewBody(map[string]any{"rule_type": "role", "rule_id": ruleID, "match_value": match, "role_id": m.admin}))
			assert.Equal(t, http.StatusBadRequest, code, "規則類別不符視同不存在")
		})
		t.Run("持 role:assign 但缺 identity_source:manage 者被拒，兩者兼具者通過", func(t *testing.T) {
			mk := func(name string, perms ...string) string {
				role := f.role(name, perms...)
				id := f.user(name + "-user")
				f.hold(id, role)
				subj := "MAP-" + name
				w.env.subjects[subj] = &baselineSubject{ID: subj, Username: name, UserID: id, Kind: "session", Token: w.env.issueSessionToken(id)}
				return subj
			}
			weak := mk("m6-assign-only", "role:assign")
			code, body := post(weak, groupBody(ruleID, match, gid, map[string]any{"enabled": false}))
			assert.Equal(t, http.StatusForbidden, code, "%v", body)
			raw, _ := json.Marshal(body)
			assert.NotContains(t, string(raw), match, "拒絕的回應不含規則內容")
			assert.NotContains(t, string(raw), "total")
			strong := mk("m6-assign-source", "role:assign", "identity_source:manage")
			code, body = post(strong, groupBody(ruleID, match, gid, map[string]any{"enabled": false}))
			assert.Equal(t, http.StatusOK, code, "%v", body)
		})
	})

	t.Run("預覽唯讀：寫入即失敗掛點下結果不變且零記錄，同一掛點下真實寫入必失敗", func(t *testing.T) {
		// 輸入一：停用 R1（操作者只經 R1 取得管理群組）。輸入二：修改規則目標。
		op, subj := m.selfOperator(m.name("m7-op"))
		ga := f.group(m.name("m7-a"), nil, nil, []uint{m.admin})
		gb := f.group(m.name("m7-b"), nil, nil, []uint{w.env.roleID(model.RoleAuditor)})
		match1 := m.name("m7-r1")
		r1 := m.groupRule(match1, ga)
		u := f.user(m.name("m7-u"))
		m.supportGroup(op, ga, r1, false)
		m.supportGroup(u, ga, r1, false)
		match2 := m.name("m7-r2")
		r2 := m.groupRule(match2, gb)
		m.supportGroup(u, gb, r2, false)
		hit := f.user(m.name("m7-hit"))
		newMatch := m.name("m7-new")
		m.observe([]uint{hit}, newMatch)
		bodies := []map[string]any{
			groupBody(r1, match1, ga, map[string]any{"enabled": false}),
			groupBody(r2, newMatch, ga, nil),
		}
		var plain []map[string]any
		for _, b := range bodies {
			plain = append(plain, w.previewAs(subj, b))
		}
		ww := installWriteWatch(t, w.env.db)
		defer func() {
			if ww != nil {
				ww.remove(t)
			}
		}()
		for i, b := range bodies {
			out := w.previewAs(subj, b)
			assert.Equal(t, plain[i]["total"], out["total"])
			assert.Equal(t, plain[i]["operation"], out["operation"])
			assert.Equal(t, plain[i]["subjects"], out["subjects"])
		}
		assert.Equal(t, 0, ww.count(), "預覽期間掛點記錄 0 筆：%v", ww.hits)
		code, resp := w.env.api(subj, http.MethodPut, fmt.Sprintf("%s/user-group-mappings/%d", m.base(), r1), map[string]any{
			"match_value": match1, "user_group_id": ga, "enabled": false, "risk_acknowledged": true, "source_config_acknowledged": true})
		assert.NotEqual(t, http.StatusOK, code, "掛點下真實映射寫入必失敗：%v", resp)
		assert.GreaterOrEqual(t, ww.count(), 1, "掛點攔得到寫入")
		ww.remove(t)
		ww = nil
		var enabled bool
		require.NoError(t, w.env.db.Model(&model.GroupUserGroupMapping{}).Where("id = ?", r1).Select("enabled").Scan(&enabled).Error)
		assert.True(t, enabled, "失敗的寫入整筆回滾：規則維持啟用")
	})
}

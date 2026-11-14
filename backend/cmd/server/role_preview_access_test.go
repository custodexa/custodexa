package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/api"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/identity"
)

// 全部資料表的寫入掛點：任何 Create／Update／Delete，以及以 INSERT、UPDATE、DELETE、REPLACE 開頭的
// Raw／Exec 陳述句都計入。唯一排除：中介層對每個已認證請求都寫的那一列請求留痕（預設為路徑以
// preview-capabilities 結尾的讀取列，可由呼叫端指定受測路由）——那是通用審計口徑，不是端點自己寫的，
// 另以 traces 計數留證。
type allTablesWriteWatch struct {
	mu     sync.Mutex
	hits   []string
	traces int
	db     *gorm.DB
	tag    string
}

func isPreviewCapabilitiesTrace(r *model.AuditLog) bool {
	return r.Method == http.MethodGet && strings.HasSuffix(r.Path, "/preview-capabilities")
}

func isPreviewRequestTrace(dest any) bool { return isRequestTrace(dest, isPreviewCapabilitiesTrace) }

// isRequestTrace 寫入目標是否全為符合 match 的請求留痕列。
func isRequestTrace(dest any, match func(*model.AuditLog) bool) bool {
	one := func(r *model.AuditLog) bool { return r != nil && match(r) }
	switch v := dest.(type) {
	case *model.AuditLog:
		return one(v)
	case []*model.AuditLog:
		if len(v) == 0 {
			return false
		}
		for _, r := range v {
			if !one(r) {
				return false
			}
		}
		return true
	}
	return false
}

func installAllTablesWriteWatch(t *testing.T, db *gorm.DB) *allTablesWriteWatch {
	t.Helper()
	return installAllTablesWriteWatchFor(t, db, isPreviewCapabilitiesTrace)
}

// installAllTablesWriteWatchFor 同上，請求留痕列的判定由 trace 指定（只排除受測路由自己的那一列）。
func installAllTablesWriteWatchFor(t *testing.T, db *gorm.DB, trace func(*model.AuditLog) bool) *allTablesWriteWatch {
	t.Helper()
	ww := &allTablesWriteWatch{db: db, tag: "pvw_" + strings.ReplaceAll(t.Name(), "/", "_")}
	hit := func(kind string) func(*gorm.DB) {
		return func(tx *gorm.DB) {
			ww.mu.Lock()
			defer ww.mu.Unlock()
			if kind == "create" && tx.Statement.Table == "audit_logs" && isRequestTrace(tx.Statement.Dest, trace) {
				ww.traces++
				return
			}
			ww.hits = append(ww.hits, fmt.Sprintf("%s:%s", kind, tx.Statement.Table))
		}
	}
	// 只記錄、不攔截：寫入是否發生由計數與內容快照判定
	require.NoError(t, db.Callback().Create().Before("gorm:create").Register(ww.tag+"_c", hit("create")))
	require.NoError(t, db.Callback().Update().Before("gorm:update").Register(ww.tag+"_u", hit("update")))
	require.NoError(t, db.Callback().Delete().Before("gorm:delete").Register(ww.tag+"_d", hit("delete")))
	require.NoError(t, db.Callback().Raw().Before("gorm:raw").Register(ww.tag+"_r", func(tx *gorm.DB) {
		sql := strings.ToUpper(strings.TrimSpace(tx.Statement.SQL.String()))
		for _, p := range []string{"INSERT", "UPDATE", "DELETE", "REPLACE"} {
			if strings.HasPrefix(sql, p) {
				ww.mu.Lock()
				ww.hits = append(ww.hits, "raw:"+sql[:min(len(sql), 60)])
				ww.mu.Unlock()
				return
			}
		}
	}))
	return ww
}

func (ww *allTablesWriteWatch) remove(t *testing.T) {
	t.Helper()
	require.NoError(t, ww.db.Callback().Create().Remove(ww.tag+"_c"))
	require.NoError(t, ww.db.Callback().Update().Remove(ww.tag+"_u"))
	require.NoError(t, ww.db.Callback().Delete().Remove(ww.tag+"_d"))
	require.NoError(t, ww.db.Callback().Raw().Remove(ww.tag+"_r"))
}

func (ww *allTablesWriteWatch) snapshot() ([]string, int) {
	ww.mu.Lock()
	defer ww.mu.Unlock()
	return append([]string{}, ww.hits...), ww.traces
}

func (ww *allTablesWriteWatch) reset() {
	ww.mu.Lock()
	defer ww.mu.Unlock()
	ww.hits, ww.traces = nil, 0
}

// contentSnapshot 全部資料表的內容雜湊：逐表把每列序列化後排序再雜湊（不依賴主鍵或列序）。
// 請求留痕列（路徑以 preview-capabilities 結尾的審計列）不納入。
func contentSnapshot(t *testing.T, db *gorm.DB) map[string]string {
	t.Helper()
	return contentSnapshotSkipping(t, db, func(method, path string) bool {
		return strings.HasSuffix(path, "/preview-capabilities")
	})
}

// contentSnapshotSkipping 同上，審計列中 skip 判定為請求留痕者不納入。
func contentSnapshotSkipping(t *testing.T, db *gorm.DB, skip func(method, path string) bool) map[string]string {
	t.Helper()
	var names []string
	require.NoError(t, db.Raw(`SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'`).Scan(&names).Error)
	sort.Strings(names)
	out := map[string]string{}
	for _, name := range names {
		var rows []map[string]any
		require.NoError(t, db.Table(name).Find(&rows).Error, name)
		lines := make([]string, 0, len(rows))
		for _, r := range rows {
			if name == "audit_logs" {
				if skip(fmt.Sprintf("%s", r["method"]), fmt.Sprintf("%s", r["path"])) {
					continue
				}
			}
			for k, v := range r {
				if b, ok := v.([]byte); ok {
					r[k] = string(b)
				}
			}
			b, err := json.Marshal(r)
			require.NoError(t, err)
			lines = append(lines, string(b))
		}
		sort.Strings(lines)
		sum := sha256.Sum256([]byte(strings.Join(lines, "\n")))
		out[name] = fmt.Sprintf("%d:%s", len(lines), hex.EncodeToString(sum[:]))
	}
	return out
}

func diffSnapshots(a, b map[string]string) []string {
	var out []string
	for k, v := range a {
		if b[k] != v {
			out = append(out, k)
		}
	}
	for k := range b {
		if _, ok := a[k]; !ok {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// TestRolePreviewAccess 擋：預覽端點的授權裁決錯誤（超管保留、只持指派能力者可讀、agent 可讀）、
// 錯誤形狀分岔、預覽期間發生任何寫入、預覽改變操作者本人的讀取結果或讓本人做到原本做不到的寫入。
func TestRolePreviewAccess(t *testing.T) {
	const route = "/api/v1/role-definitions/:id/preview-capabilities"
	t.Run("路由在登錄表、agent 登錄（預設拒絕）與路由清冊都有，且不是超管保留", func(t *testing.T) {
		routes, _ := buildRouter(t, "release", true)
		e, ok := authz.LookupRoute("GET", route)
		require.True(t, ok, "未登錄")
		assert.Equal(t, authz.BasePerm, e.Base)
		assert.NotEqual(t, authz.BaseSuperAdmin, e.Base)
		assert.Equal(t, authz.PermRoleView, e.Perm)
		allowed, registered := middleware.AgentRouteDecision("GET", route)
		assert.True(t, registered)
		assert.False(t, allowed)
		_, inInventory := routes[[2]string{"GET", route}]
		assert.True(t, inInventory, "不在路由清冊")
	})

	env := newBaselineEnv(t)
	ctx := context.Background()
	defs := identity.NewRoleDefinitionService(env.db, audit.NewTxSink(), identity.NewPermissionChainEventWriter(),
		identity.NewGrantGrader(audit.NewTxSink(), audit.NewSystemAlertSink(nil)))
	super := env.subjects["S01"].UserID

	mkRole := func(name string, perms ...string) *identity.RoleDefinition {
		d, err := defs.Create(roleWriterSession(ctx, super), super, identity.RoleInput{Name: name, Permissions: perms})
		require.NoError(t, err)
		return d
	}
	holder := func(username string, roleIDs ...uint) (uint, string) {
		uid := env.createUser(username, nil)
		for _, rid := range roleIDs {
			require.NoError(t, model.AssignUserRoleWithSource(env.db, uid, rid, model.RoleSourceManual, model.RoleOriginSystem))
		}
		return uid, env.issueSessionToken(uid)
	}
	do := func(token, method, path string, body any) (int, []byte) {
		var rd *bytes.Reader
		if body != nil {
			b, err := json.Marshal(body)
			require.NoError(t, err)
			rd = bytes.NewReader(b)
		} else {
			rd = bytes.NewReader(nil)
		}
		req := httptest.NewRequest(method, path, rd)
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		w := env.serve(req)
		return w.Code, w.Body.Bytes()
	}
	previewPath := func(id any) string { return fmt.Sprintf("/api/v1/role-definitions/%v/preview-capabilities", id) }
	decode := func(b []byte) map[string]any {
		out := map[string]any{}
		require.NoError(t, json.Unmarshal(b, &out), string(b))
		return out
	}

	viewRole := mkRole("pv-viewer", "role:view")
	assignOnly := mkRole("pv-assign-only", "role:assign")
	assetUpdate := mkRole("pv-asset-update", "asset:view", "asset:update")
	creator := mkRole("pv-asset-creator", "asset:view", "asset:create", "asset:update", "asset:delete", "session:view")
	_, viewerTok := holder("pv-viewer-user", viewRole.ID)
	_, assignTok := holder("pv-assign-user", assignOnly.ID)
	_, zeroTok := holder("pv-zero-user")
	superTok := env.subjects["S01"].Token
	idKey := model.BuiltinIdentityAdmin
	var idRow model.Role
	if err := env.db.Where("name = ?", "identity_admin").First(&idRow).Error; err != nil {
		idRow = model.Role{Name: "identity_admin", BuiltinKey: &idKey, DefinitionVersion: 1}
		require.NoError(t, env.db.Create(&idRow).Error)
	}
	idaRole := idRow.ID
	_, idaTok := holder("pv-ida-user", idaRole)

	var superRoleID uint
	require.NoError(t, env.db.Raw(`SELECT id FROM roles WHERE builtin_key = ? AND deleted_at IS NULL`, model.BuiltinSuperAdmin).Scan(&superRoleID).Error)
	require.NotZero(t, superRoleID)

	t.Run("超管與持角色檢視能力者可讀；回應契約與欄位", func(t *testing.T) {
		for name, tok := range map[string]string{"超管": superTok, "角色檢視持有者": viewerTok, "identity_admin": idaTok} {
			c, b := do(tok, "GET", previewPath(creator.ID), nil)
			require.Equal(t, http.StatusOK, c, "%s: %s", name, b)
			out := decode(b)
			assert.Equal(t, true, out["previewable"], name)
			assert.NotContains(t, out, "reason", "可預覽時省略 reason")
			role := out["role"].(map[string]any)
			assert.EqualValues(t, creator.ID, role["id"])
			assert.Equal(t, "pv-asset-creator", role["name"])
			assert.IsType(t, []any{}, out["permissions"])
			assert.IsType(t, []any{}, out["entry_states"])
			for _, banned := range []string{"scope_summary", "nodes", "binding_scope"} {
				assert.NotContains(t, string(b), banned, name)
			}
			assert.Subset(t, pvStrings(out["permissions"]), []string{"asset:create", "asset:view", "session:view"})
		}
	})

	t.Run("預覽集合等於只持該角色者的 GET /auth/me permissions", func(t *testing.T) {
		for _, role := range []struct {
			name string
			id   uint
		}{{"自訂", assetUpdate.ID}, {"identity_admin", idaRole}, {"空集合自訂", mkRole("pv-empty").ID}} {
			_, tok := holder("pv-me-"+role.name, role.id)
			c, b := do(tok, "GET", "/api/v1/auth/me", nil)
			require.Equal(t, http.StatusOK, c, string(b))
			me := pvStrings(decode(b)["permissions"])
			c, b = do(superTok, "GET", previewPath(role.id), nil)
			require.Equal(t, http.StatusOK, c)
			assert.Equal(t, me, pvStrings(decode(b)["permissions"]), role.name)
		}
	})

	t.Run("超管角色回不可預覽與空陣列，狀態 200", func(t *testing.T) {
		c, b := do(superTok, "GET", previewPath(superRoleID), nil)
		require.Equal(t, http.StatusOK, c, string(b))
		out := decode(b)
		assert.Equal(t, false, out["previewable"])
		assert.Equal(t, "reserved_super_admin", out["reason"])
		assert.Equal(t, []any{}, out["permissions"])
		assert.Equal(t, []any{}, out["entry_states"])
	})

	t.Run("只持角色指派能力、零角色、無檢視能力者與未登入被拒，forbidden 形狀單一", func(t *testing.T) {
		s02 := env.subjects["S02"].Token
		var shapes []string
		for name, tok := range map[string]string{"只持指派": assignTok, "零角色": zeroTok, "一般使用者": s02} {
			c, b := do(tok, "GET", previewPath(creator.ID), nil)
			assert.Equal(t, http.StatusForbidden, c, name)
			out := decode(b)
			shapes = append(shapes, fmt.Sprint(out["code"], "|", pvSortedKeys(out)))
			assert.NotContains(t, string(b), "permissions", name)
		}
		for _, s := range shapes {
			assert.Equal(t, shapes[0], s, "forbidden 回應形狀不一致")
		}
		c, _ := do("", "GET", previewPath(creator.ID), nil)
		assert.Equal(t, http.StatusUnauthorized, c)
	})

	t.Run("agent token 被拒", func(t *testing.T) {
		c, _ := do(env.subjects["S12"].Token, "GET", previewPath(creator.ID), nil)
		assert.Equal(t, http.StatusForbidden, c)
	})

	t.Run("不存在與已刪除角色的回應與單筆讀取逐位元組相同；非數字 ID 回 VALIDATION_INVALID_ID", func(t *testing.T) {
		gone := mkRole("pv-gone", "asset:view")
		require.NoError(t, defs.Delete(roleWriterSession(ctx, super), super, gone.ID, gone.DefinitionVersion))
		for _, id := range []any{999999, gone.ID} {
			pc, pb := do(idaTok, "GET", previewPath(id), nil)
			gc, gb := do(idaTok, "GET", fmt.Sprintf("/api/v1/role-definitions/%v", id), nil)
			assert.Equal(t, http.StatusNotFound, pc)
			assert.Equal(t, gc, pc)
			assert.Equal(t, pvNormalizeRequestID(gb), pvNormalizeRequestID(pb), "id=%v", id)
		}
		c, b := do(idaTok, "GET", previewPath("abc"), nil)
		assert.Equal(t, http.StatusBadRequest, c)
		assert.Equal(t, "VALIDATION_INVALID_ID", decode(b)["code"])
	})

	h := env.graph.deps.roleDefinition
	t.Run("解析失敗回 INTERNAL_ROLE_QUERY 且不洩內部錯誤；未注入同樣回 INTERNAL_ROLE_QUERY", func(t *testing.T) {
		h.SetRolePreviewer(func(string, int64, []string) (*authz.RolePreview, error) {
			return nil, errors.New("secret-internal-detail-xyz")
		})
		defer h.SetRolePreviewer(api.DefaultRolePreviewFunc())
		c, b := do(idaTok, "GET", previewPath(creator.ID), nil)
		assert.Equal(t, http.StatusInternalServerError, c)
		assert.Equal(t, "INTERNAL_ROLE_QUERY", decode(b)["code"])
		assert.NotContains(t, string(b), "secret-internal-detail-xyz")

		h.SetRolePreviewer(nil)
		c, b = do(idaTok, "GET", previewPath(creator.ID), nil)
		assert.Equal(t, http.StatusInternalServerError, c)
		assert.Equal(t, "INTERNAL_ROLE_QUERY", decode(b)["code"])
	})

	t.Run("無寫入：五個分支的寫入計數為 0、全部資料表內容與權限版本不變", func(t *testing.T) {
		gone := mkRole("pv-gone2", "asset:view")
		require.NoError(t, defs.Delete(roleWriterSession(ctx, super), super, gone.ID, gone.DefinitionVersion))
		branches := []struct {
			name  string
			tok   string
			id    any
			setup func() func()
			want  int
		}{
			{"成功", idaTok, creator.ID, nil, 200},
			{"forbidden", zeroTok, creator.ID, nil, 403},
			{"未找到", idaTok, 999999, nil, 404},
			{"已刪除", idaTok, gone.ID, nil, 404},
			{"參數不合法", idaTok, "abc", nil, 400},
			{"解析失敗", idaTok, creator.ID, func() func() {
				h.SetRolePreviewer(func(string, int64, []string) (*authz.RolePreview, error) { return nil, errors.New("boom") })
				return func() { h.SetRolePreviewer(api.DefaultRolePreviewFunc()) }
			}, 500},
		}
		for _, br := range branches {
			if br.setup != nil {
				restore := br.setup()
				defer restore()
			}
			ww := installAllTablesWriteWatch(t, env.db)
			verBefore, err := authz.CurrentVersion(env.db)
			require.NoError(t, err)
			before := contentSnapshot(t, env.db)
			c, _ := do(br.tok, "GET", previewPath(br.id), nil)
			after := contentSnapshot(t, env.db)
			verAfter, err := authz.CurrentVersion(env.db)
			require.NoError(t, err)
			hits, traces := ww.snapshot()
			ww.remove(t)
			assert.Equal(t, br.want, c, br.name)
			assert.Empty(t, hits, "%s: 寫入計數必須為 0", br.name)
			assert.Empty(t, diffSnapshots(before, after), "%s: 內容快照不同", br.name)
			assert.Equal(t, verBefore, verAfter, "%s: 權限版本改變", br.name)
			t.Logf("%s: status=%d 寫入計數=0 請求層通用留痕列=%d（不計入）", br.name, c, traces)
			if br.setup != nil {
				h.SetRolePreviewer(api.DefaultRolePreviewFunc())
			}
		}
	})

	t.Run("正向對照：組裝依賴在請求期間寫入一筆時，攔截計數非 0 且快照不同", func(t *testing.T) {
		h.SetRolePreviewer(func(b string, v int64, p []string) (*authz.RolePreview, error) {
			if err := env.db.Create(&model.Role{Name: "pv-positive-control"}).Error; err != nil {
				return nil, err
			}
			return authz.PreviewRole(b, v, p), nil
		})
		defer h.SetRolePreviewer(api.DefaultRolePreviewFunc())
		ww := installAllTablesWriteWatch(t, env.db)
		before := contentSnapshot(t, env.db)
		c, _ := do(idaTok, "GET", previewPath(creator.ID), nil)
		after := contentSnapshot(t, env.db)
		hits, _ := ww.snapshot()
		ww.remove(t)
		require.Equal(t, http.StatusOK, c)
		assert.NotEmpty(t, hits, "攔截沒看到寫入")
		assert.Contains(t, diffSnapshots(before, after), "roles", "快照沒看到寫入")
		require.NoError(t, env.db.Unscoped().Where("name = ?", "pv-positive-control").Delete(&model.Role{}).Error)
	})

	t.Run("本人裁決不變：預覽高權角色前後同一 token 的讀取逐位元組相同，直接寫入仍被拒", func(t *testing.T) {
		reads := []string{"/api/v1/auth/me", "/api/v1/assets", fmt.Sprintf("/api/v1/role-definitions/%d", creator.ID)}
		type resp struct {
			code int
			body string
		}
		read := func() map[string]resp {
			m := map[string]resp{}
			for _, p := range reads {
				c, b := do(viewerTok, "GET", p, nil)
				m[p] = resp{c, string(pvNormalizeRequestID(b))}
			}
			return m
		}
		assetsBefore := contentSnapshot(t, env.db)["assets"]
		before := read()
		c, b := do(viewerTok, "GET", previewPath(creator.ID), nil)
		require.Equal(t, http.StatusOK, c, string(b))
		assert.Contains(t, pvStrings(decode(b)["permissions"]), "asset:create", "預覽的角色具有本人沒有的 asset:create")
		after := read()
		assert.Equal(t, before, after, "預覽前後本人的讀取回應不同")
		t.Logf("本人 GET /assets 狀態=%d（預覽前後相同）", before["/api/v1/assets"].code)

		c, b = do(viewerTok, "POST", "/api/v1/assets", map[string]any{"name": "pv-bypass", "protocol": "ssh", "host": "10.0.0.1", "port": 22})
		assert.Equal(t, http.StatusForbidden, c, string(b))
		assert.Equal(t, assetsBefore, contentSnapshot(t, env.db)["assets"], "資產表內容改變")
		c, _ = do(viewerTok, "GET", fmt.Sprintf("/api/v1/role-definitions/%d", creator.ID), nil)
		assert.Equal(t, http.StatusOK, c, "本人仍可讀角色檢視")
	})
}

func pvStrings(v any) []string {
	out := []string{}
	if list, ok := v.([]any); ok {
		for _, x := range list {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
	}
	return out
}

func pvSortedKeys(m map[string]any) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

// pvNormalizeRequestID 錯誤回應若帶請求識別碼，比對前移除（兩次請求的識別碼本來就不同）。
func pvNormalizeRequestID(b []byte) []byte {
	m := map[string]any{}
	if json.Unmarshal(b, &m) != nil {
		return b
	}
	delete(m, "request_id")
	out, _ := json.Marshal(m)
	return out
}

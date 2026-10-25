package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/audit/port"
	"github.com/custodexa/backend/internal/modules/authz"
)

// 存取政策權限點經節點範圍生效時的寫入規則（更新、建立、批次新增），經正式 handler 與真判定器。
// 樹沿用 saTree；注入目錄另把存取政策權限點標為 scoped-enforced。

// apAlertRecorder 系統告警落地面替身：記事件種類與是否在交易內寫入。
type apAlertRecorder struct {
	mu     sync.Mutex
	events []apAlert
}

type apAlert struct {
	typ  port.SystemAlertType
	inTx bool
	id   string
}

func (r *apAlertRecorder) RaiseInTx(tx *gorm.DB, ev port.SystemAlertEvent) (port.SystemAlertReceipt, error) {
	_, inTx := tx.Statement.ConnPool.(gorm.TxCommitter)
	r.mu.Lock()
	r.events = append(r.events, apAlert{typ: ev.Type, inTx: inTx, id: ev.Target.ID})
	r.mu.Unlock()
	return port.SystemAlertReceipt{}, nil
}

func (r *apAlertRecorder) relaxed() []apAlert {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []apAlert
	for _, e := range r.events {
		if e.typ == port.SystemAlertAccessPolicyRelaxed {
			out = append(out, e)
		}
	}
	return out
}

// newAPEnv 範圍化資產夾具，另把存取政策權限點注入為 scoped-enforced，並接上覆寫清單投影與告警記錄。
func newAPEnv(t *testing.T) (*saEnv, *apAlertRecorder) {
	t.Helper()
	e := newSAEnv(t)
	cat, err := authz.CatalogueWithScopedEnforcedForTest(append(append([]authz.Permission(nil), saPerms...),
		authz.PermAccessPolicyManage)...)
	require.NoError(t, err)
	e.cat = cat
	e.eval = authz.NewScopeEvaluator(cat, asset.NewScopeTopologyReader())
	e.assets.SetAssetWriteScopePort(authz.NewAssetWriteScope(e.eval))
	e.assets.SetAccessPolicyOverrideScopePort(authz.NewAccessPolicyOverrideScope(e.eval))
	rec := &apAlertRecorder{}
	e.assets.SetSecurityChangeAlertSink(rec)
	saTree(e)
	return e, rec
}

// apSetPolicy 直接寫表設定覆寫值（空字串＝清除）。
func apSetPolicy(t *testing.T, e *saEnv, id uint, v string) {
	t.Helper()
	var val any
	if v != "" {
		val = v
	}
	require.NoError(t, e.db.Model(&model.Asset{}).Where("id = ?", id).Update("access_policy", val).Error)
}

func apPolicyOf(t *testing.T, e *saEnv, id uint) string {
	t.Helper()
	var a model.Asset
	require.NoError(t, e.db.First(&a, id).Error)
	if a.AccessPolicy == nil {
		return ""
	}
	return *a.AccessPolicy
}

// apLastAudit 最近一筆審計列。
func apLastAudit(t *testing.T, e *saEnv) model.AuditLog {
	t.Helper()
	var row model.AuditLog
	require.NoError(t, e.db.Unscoped().Order("id desc").First(&row).Error)
	return row
}

// apLockProbe 計拓撲序列化鎖與資產列鎖（lockAssetForUpdateTx 的 FOR UPDATE 查詢）的先後。
type apLockProbe struct {
	mu     sync.Mutex
	events []string
}

func (p *apLockProbe) add(ev string) {
	p.mu.Lock()
	p.events = append(p.events, ev)
	p.mu.Unlock()
}

func (p *apLockProbe) reset() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := p.events
	p.events = nil
	return out
}

func installAPLockProbe(t *testing.T, db *gorm.DB) *apLockProbe {
	t.Helper()
	p := &apLockProbe{}
	restore := authz.SetTopologyLockAcquiredHookForTest(func(*gorm.DB) { p.add("topology") })
	t.Cleanup(restore)
	name := "zz_ap_asset_row_lock"
	require.NoError(t, db.Callback().Query().Before("gorm:query").Register(name, func(tx *gorm.DB) {
		if _, locking := tx.Statement.Clauses["FOR"]; locking && tx.Statement.Table == "assets" {
			p.add("asset_row")
		}
	}))
	t.Cleanup(func() { _ = db.Callback().Query().Remove(name) })
	return p
}

func apCount(evs []string, ev string) int {
	n := 0
	for _, e := range evs {
		if e == ev {
			n++
		}
	}
	return n
}

func apIndex(evs []string, ev string) int {
	for i, e := range evs {
		if e == ev {
			return i
		}
	}
	return -1
}

func TestScopedAccessPolicyWrites(t *testing.T) {
	policyPerms := []authz.Permission{authz.PermAccessPolicyManage, authz.PermAssetView}

	t.Run("update_in_scope_relaxes_with_alert", func(t *testing.T) {
		e, rec := newAPEnv(t)
		holder := e.user("zz-sa-ap-holder")
		e.grantNodes(holder, e.role(policyPerms...), "zz-sa-a")
		x := e.asset("zz-sa-ap-x", "zz-sa-a1")
		apSetPolicy(t, e, x, model.AccessPolicyApproval)
		code, raw := e.do(holder, true, "PUT", idPath(x), `{"access_policy":"reason"}`)
		require.Equal(t, http.StatusOK, code, raw)
		assert.Equal(t, model.AccessPolicyReason, apPolicyOf(t, e, x))
		got := rec.relaxed()
		require.Len(t, got, 1, "approval→reason 為降級，告警一筆")
		assert.True(t, got[0].inTx, "告警與更新同交易寫入")
		assert.Equal(t, fmt.Sprint(x), got[0].id)
		var updates int64
		require.NoError(t, e.db.Unscoped().Model(&model.AuditLog{}).
			Where("action = ? AND status = ? AND resource_id = ?", model.ActionUpdate, model.StatusSuccess, x).Count(&updates).Error)
		assert.GreaterOrEqual(t, updates, int64(1), "有資產更新審計")
		t.Logf("EVIDENCE ap-update-in-scope status=%d relaxed=%d update_audits=%d", code, len(got), updates)
	})

	t.Run("update_out_of_scope_same_as_missing", func(t *testing.T) {
		e, rec := newAPEnv(t)
		holder := e.user("zz-sa-ap-holder")
		e.grantNodes(holder, e.role(policyPerms...), "zz-sa-a")
		y := e.asset("zz-sa-ap-y-secret", "zz-sa-b")
		apSetPolicy(t, e, y, model.AccessPolicyApproval)
		cY, rY := e.do(holder, true, "PUT", idPath(y), `{"access_policy":"reason"}`)
		audit := apLastAudit(t, e)
		cM, rM := e.do(holder, true, "PUT", "/api/v1/assets/"+saMissing, `{"access_policy":"reason"}`)
		assert.Equal(t, http.StatusNotFound, cY, rY)
		assert.Equal(t, cM, cY, "範圍外與不存在：狀態相同")
		assert.JSONEq(t, rM, rY, "範圍外與不存在：本文逐欄相同")
		assert.Equal(t, model.AccessPolicyApproval, apPolicyOf(t, e, y), "範圍外資產不變")
		assert.Empty(t, rec.relaxed(), "範圍外不產生告警")
		assert.Equal(t, model.StatusDenied, audit.Status, "範圍外請求的審計列為 denied")
		assert.Contains(t, audit.Details, `"denial":"scope"`, "details 為範圍拒絕形狀")
		assert.NotContains(t, audit.Details, "zz-sa-ap-y-secret", "審計 details 不含範圍外資產名稱")
		assert.NotContains(t, rY, "zz-sa-ap-y-secret")

		// 範圍判定先於值驗證：非法段位到範圍外與到不存在仍同形
		cYb, rYb := e.do(holder, true, "PUT", idPath(y), `{"access_policy":"bogus"}`)
		cMb, rMb := e.do(holder, true, "PUT", "/api/v1/assets/"+saMissing, `{"access_policy":"bogus"}`)
		assert.Equal(t, http.StatusNotFound, cYb, rYb)
		assert.Equal(t, cMb, cYb)
		assert.JSONEq(t, rMb, rYb, "非法段位：範圍外與不存在逐欄相同")
		assert.Equal(t, model.AccessPolicyApproval, apPolicyOf(t, e, y))
		t.Logf("EVIDENCE ap-update-out-of-scope status=%d body=%s audit=%s details=%s", cY, rY, audit.Status, audit.Details)
	})

	t.Run("readable_but_policy_out_of_scope_is_404", func(t *testing.T) {
		e, _ := newAPEnv(t)
		mixed := e.user("zz-sa-ap-mixed")
		e.grantNodes(mixed, e.role(authz.PermAssetView, authz.PermAssetUpdate), "zz-sa-a", "zz-sa-b")
		e.grantNodes(mixed, e.role(authz.PermAccessPolicyManage), "zz-sa-a")
		y := e.asset("zz-sa-ap-y", "zz-sa-b")
		code, raw := e.do(mixed, true, "PUT", idPath(y), `{"access_policy":"open","description":"d"}`)
		assert.Equal(t, http.StatusNotFound, code, "編輯範圍涵蓋、存取政策範圍不涵蓋：夾帶覆寫也 404：%s", raw)
		code, raw = e.do(mixed, true, "PUT", idPath(y), `{"description":"d"}`)
		assert.Equal(t, http.StatusOK, code, "不帶覆寫的編輯照常：%s", raw)
	})

	t.Run("default_not_writable_by_holder", func(t *testing.T) {
		e, _ := newAPEnv(t)
		holder := e.user("zz-sa-ap-holder")
		e.grantNodes(holder, e.role(policyPerms...), "zz-sa-a")
		saved := map[string]string{"access_policy_default": model.AccessPolicyApproval}
		r := gin.New()
		r.Use(func(c *gin.Context) {
			p, err := authz.ResolveUserOnWithCatalogue(e.db, e.cat, holder, authz.TokenFacts{})
			require.NoError(t, err)
			middleware.SetPrincipal(c, p)
			c.Next()
		})
		r.PUT("/api/v1/security-policies", middleware.EnforceRegistry(), func(c *gin.Context) {
			saved["access_policy_default"] = model.AccessPolicyOpen
			c.Status(http.StatusOK)
		})
		w := httptest.NewRecorder()
		req := httptest.NewRequest("PUT", "/api/v1/security-policies", strings.NewReader(`{"access_policy_default":"open"}`))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		assert.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
		assert.Equal(t, model.AccessPolicyApproval, saved["access_policy_default"], "全系統預設不變")
	})

	t.Run("neither_capability_frozen_shape", func(t *testing.T) {
		e, _ := newAPEnv(t)
		viewer := e.user("zz-sa-ap-viewer")
		e.grantGlobal(viewer, e.role(authz.PermAssetView))
		code, raw := e.do(viewer, true, "PUT", "/api/v1/assets/"+saMissing, `{"access_policy":"approval"}`)
		var body map[string]any
		require.NoError(t, json.Unmarshal([]byte(raw), &body), raw)
		assert.Equal(t, http.StatusForbidden, code, raw)
		assert.Len(t, body, 2, "能力拒絕單一形狀只有 code、error")
		assert.Equal(t, "AUTH_PERMISSION_DENIED", body["code"])
	})

	t.Run("policy_only_update_locks_unconditionally", func(t *testing.T) {
		e, _ := newAPEnv(t)
		holder := e.user("zz-sa-ap-holder")
		e.grantNodes(holder, e.role(policyPerms...), "zz-sa-a")
		x := e.asset("zz-sa-ap-x", "zz-sa-a")
		y := e.asset("zz-sa-ap-y", "zz-sa-b")
		probe := installAPLockProbe(t, e.db)
		code, raw := e.do(holder, true, "PUT", idPath(x), `{"access_policy":"approval"}`)
		require.Equal(t, http.StatusOK, code, raw)
		evX := probe.reset()
		assert.Equal(t, 1, apCount(evX, "topology"), "範圍內：取鎖恰一次 %v", evX)
		assert.GreaterOrEqual(t, apCount(evX, "asset_row"), 1, "範圍內：有資產列鎖 %v", evX)
		assert.Less(t, apIndex(evX, "topology"), apIndex(evX, "asset_row"), "取鎖先於資產列鎖 %v", evX)
		code, raw = e.do(holder, true, "PUT", idPath(y), `{"access_policy":"approval"}`)
		require.Equal(t, http.StatusNotFound, code, raw)
		evY := probe.reset()
		assert.Equal(t, 1, apCount(evY, "topology"), "範圍外：取鎖恰一次 %v", evY)
		assert.Equal(t, 0, apCount(evY, "asset_row"), "範圍外：判定在資產列鎖之前拒絕 %v", evY)
		t.Logf("EVIDENCE ap-lock-order in_scope=%v out_of_scope=%v", evX, evY)
	})

	t.Run("policy_only_holder_update_response_masks_nodes", func(t *testing.T) {
		e, _ := newAPEnv(t)
		holder := e.user("zz-sa-ap-only")
		e.grantNodes(holder, e.role(authz.PermAccessPolicyManage), "zz-sa-a")
		x := e.asset("zz-sa-ap-x", "zz-sa-a1", "zz-sa-b", "zz-sa-c")
		code, raw := e.do(holder, true, "PUT", idPath(x), `{"access_policy":"approval"}`)
		require.Equal(t, http.StatusOK, code, raw)
		assert.Equal(t, model.AccessPolicyApproval, apPolicyOf(t, e, x))
		var body map[string]any
		require.NoError(t, json.Unmarshal([]byte(raw), &body), raw)
		assert.Equal(t, []any{float64(e.nodes["zz-sa-a1"])}, body["node_ids"], "歸屬識別碼只含範圍內：%s", raw)
		for _, n := range []string{"zz-sa-b", "zz-sa-c"} {
			assert.NotContains(t, raw, n, "回應不含範圍外節點路徑")
		}
		row := apList(t, e, holder, "").row("zz-sa-ap-x")
		require.NotNil(t, row, "覆寫清單有此列")
		for _, k := range []string{"id", "name", "protocol", "access_policy", "node_ids", "node_paths", "out_of_scope_node_count"} {
			assert.Equal(t, row[k], body[k], "成功回應與覆寫清單同列同值：%s", k)
		}
		assert.Len(t, body, len(row), "成功回應與覆寫清單列同形：%s", raw)
		t.Logf("EVIDENCE ap-only-update-response status=%d body=%s", code, raw)
	})

	t.Run("null_policy_out_of_scope_same_as_missing", func(t *testing.T) {
		e, rec := newAPEnv(t)
		holder := e.user("zz-sa-ap-only")
		e.grantNodes(holder, e.role(authz.PermAccessPolicyManage), "zz-sa-a")
		x := e.asset("zz-sa-ap-x", "zz-sa-a")
		y := e.asset("zz-sa-ap-y-secret", "zz-sa-b")
		apSetPolicy(t, e, x, model.AccessPolicyApproval)
		apSetPolicy(t, e, y, model.AccessPolicyApproval)
		var before model.Asset
		require.NoError(t, e.db.First(&before, y).Error)
		cY, rY := e.do(holder, true, "PUT", idPath(y), `{"access_policy":null}`)
		cM, rM := e.do(holder, true, "PUT", "/api/v1/assets/"+saMissing, `{"access_policy":null}`)
		assert.Equal(t, http.StatusNotFound, cY, rY)
		assert.Equal(t, cM, cY, "null：範圍外與不存在狀態相同")
		assert.Equal(t, rM, rY, "null：範圍外與不存在本文逐位元相同")
		var after model.Asset
		require.NoError(t, e.db.First(&after, y).Error)
		assert.Equal(t, before, after, "範圍外資產零變更")
		assert.Empty(t, rec.relaxed())
		cX, rX := e.do(holder, true, "PUT", idPath(x), `{"access_policy":null}`)
		assert.Equal(t, http.StatusOK, cX, rX)
		assert.Equal(t, model.AccessPolicyApproval, apPolicyOf(t, e, x), "null 不改覆寫值")
		t.Logf("EVIDENCE ap-null-policy out_of_scope=%d body=%s missing=%d body=%s in_scope=%d", cY, rY, cM, rM, cX)
	})

	t.Run("create_requires_policy_scope_on_some_node", func(t *testing.T) {
		e, _ := newAPEnv(t)
		creator := e.user("zz-sa-ap-creator")
		e.grantNodes(creator, e.role(authz.PermAssetView, authz.PermAssetCreate), "zz-sa-a", "zz-sa-b")
		e.grantNodes(creator, e.role(authz.PermAccessPolicyManage), "zz-sa-a")
		noPolicy := e.user("zz-sa-ap-nopolicy")
		e.grantNodes(noPolicy, e.role(authz.PermAssetView, authz.PermAssetCreate), "zz-sa-a", "zz-sa-b")
		body := func(name, nodes, ap string) string {
			s := fmt.Sprintf(`{"name":%q,"protocol":"ssh","host":"10.66.0.%d","port":22,"node_ids":%s`, name, len(name), saNodeIDs(e, strings.Split(nodes, ",")...))
			if ap != "" {
				s += fmt.Sprintf(`,"access_policy":%q`, ap)
			}
			return s + "}"
		}
		before := saAssetCount(t, e)
		cOut, rOut := e.do(creator, true, "POST", "/api/v1/assets", body("zz-sa-ap-new-b", "zz-sa-b", model.AccessPolicyApproval))
		cNo, rNo := e.do(noPolicy, true, "POST", "/api/v1/assets", body("zz-sa-ap-new-b", "zz-sa-b", model.AccessPolicyApproval))
		assert.Equal(t, http.StatusForbidden, cOut, rOut)
		assert.Equal(t, cNo, cOut, "存取政策範圍不符與不持權限點同形：狀態")
		assert.JSONEq(t, rNo, rOut, "存取政策範圍不符與不持權限點同形：本文")
		assert.Equal(t, before, saAssetCount(t, e), "被拒不建立")
		code, raw := e.do(creator, true, "POST", "/api/v1/assets", body("zz-sa-ap-new-ab", "zz-sa-a,zz-sa-b", model.AccessPolicyApproval))
		require.Equal(t, http.StatusCreated, code, "A＋B 帶覆寫成功：%s", raw)
		code, raw = e.do(creator, true, "POST", "/api/v1/assets", body("zz-sa-ap-new-bare", "zz-sa-b", ""))
		require.Equal(t, http.StatusCreated, code, "只放 B、不帶覆寫成功：%s", raw)
		t.Logf("EVIDENCE ap-create out_of_scope=%d body=%s no_policy=%d", cOut, rOut, cNo)
	})

	t.Run("import_policy_scope_whole_batch", func(t *testing.T) {
		e, _ := newAPEnv(t)
		creator := e.user("zz-sa-ap-creator")
		e.grantNodes(creator, e.role(authz.PermAssetView, authz.PermAssetCreate), "zz-sa-a", "zz-sa-b")
		e.grantNodes(creator, e.role(authz.PermAccessPolicyManage), "zz-sa-a")
		noPolicy := e.user("zz-sa-ap-nopolicy")
		e.grantNodes(noPolicy, e.role(authz.PermAssetView, authz.PermAssetCreate), "zz-sa-a", "zz-sa-b")
		batch := func(thirdNode string) string {
			row := func(i int, node, ap string) string {
				s := fmt.Sprintf(`{"name":"zz-sa-ap-imp-%d","protocol":"ssh","host":"10.55.0.%d","port":22,"node_ids":%s`, i, i, saNodeIDs(e, node))
				if ap != "" {
					s += fmt.Sprintf(`,"access_policy":%q`, ap)
				}
				return s + "}"
			}
			return `{"rows":[` + row(1, "zz-sa-a", "") + "," + row(2, "zz-sa-b", "") + "," + row(3, thirdNode, model.AccessPolicyOpen) + `]}`
		}
		before := saAssetCount(t, e)
		for _, path := range []string{"/api/v1/assets/import/preview", "/api/v1/assets/import"} {
			cOut, rOut := e.do(creator, true, "POST", path, batch("zz-sa-b"))
			cNo, rNo := e.do(noPolicy, true, "POST", path, batch("zz-sa-b"))
			assert.Equal(t, http.StatusForbidden, cOut, "%s：%s", path, rOut)
			assert.Equal(t, "AUTH_PERMISSION_DENIED", saErrorCode(t, rOut), path)
			assert.Equal(t, cNo, cOut, "%s：與不持權限點同形（狀態）", path)
			assert.JSONEq(t, rNo, rOut, "%s：與不持權限點同形（本文）", path)
			assert.NotContains(t, rOut, "rows", "%s：回應不含逐列結果", path)
			t.Logf("EVIDENCE ap-import path=%s status=%d body=%s", path, cOut, rOut)
		}
		assert.Equal(t, before, saAssetCount(t, e), "正式匯入資產數不變")
		code, raw := e.do(creator, true, "POST", "/api/v1/assets/import", batch("zz-sa-a"))
		require.Equal(t, http.StatusCreated, code, "改放 A 後整批成功：%s", raw)
		assert.Equal(t, before+3, saAssetCount(t, e))
	})
}

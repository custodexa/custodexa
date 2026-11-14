package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/api"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/identity"
)

// failingPreviewer 預覽計算失敗（走 500 分支）；write 非 nil 時先在請求期間寫入（正向對照）。
type failingPreviewer struct {
	write func() error
}

func (f failingPreviewer) Preview(authz.PreviewRequest) (authz.PreviewResult, error) {
	if f.write != nil {
		if err := f.write(); err != nil {
			return authz.PreviewResult{}, err
		}
		return authz.PreviewResult{}, nil
	}
	return authz.PreviewResult{}, errors.New("preview-boom")
}

// TestReadOnlyPostNoWrite 擋：三個以 POST 承載的唯讀試算端點（角色草稿摘要、指派預覽、排程時刻預覽）在任何分支寫入資料。
// 證據不以列數判定：請求期間對全部資料表掛寫入攔截（Create／Update／Delete 與 Raw 的 INSERT、UPDATE、
// DELETE、REPLACE），並比對全部資料表的內容快照與權限版本。唯一排除的是中介層對每個已認證請求都寫的
// 那一列請求留痕（受測方法與路徑），且每次請求恰好一列，避免端點自寫同路徑的審計列被一併排除。
// 正向對照證明攔截與快照看得到請求期間的寫入。
func TestReadOnlyPostNoWrite(t *testing.T) {
	const (
		summaryPath  = "/api/v1/role-definitions/summary"
		previewPath  = "/api/v1/role-assignment-previews"
		nextRunsPath = "/api/v1/schedules/next-runs"
	)
	env := newBaselineEnv(t)
	ctx := context.Background()
	defs := identity.NewRoleDefinitionService(env.db, audit.NewTxSink(), identity.NewPermissionChainEventWriter(),
		identity.NewGrantGrader(audit.NewTxSink(), audit.NewSystemAlertSink(nil)))
	super := env.subjects["S01"].UserID
	superTok := env.subjects["S01"].Token
	userTok := env.subjects["S02"].Token

	custom, err := defs.Create(roleWriterSession(ctx, super), super, identity.RoleInput{Name: "nw-custom", Permissions: []string{"asset:view"}})
	require.NoError(t, err)
	assignOnly, err := defs.Create(roleWriterSession(ctx, super), super, identity.RoleInput{Name: "nw-assign-only", Permissions: []string{"role:assign", "role:view"}})
	require.NoError(t, err)
	assignHolder := env.createUser("nw-assign-holder", nil)
	require.NoError(t, model.AssignUserRoleWithSource(env.db, assignHolder, assignOnly.ID, model.RoleSourceManual, model.RoleOriginSystem))
	assignTok := env.issueSessionToken(assignHolder)
	target := env.createUser("nw-target", nil)
	var superRoleID uint
	require.NoError(t, env.db.Raw(`SELECT id FROM roles WHERE builtin_key = ? AND deleted_at IS NULL`, model.BuiltinSuperAdmin).Scan(&superRoleID).Error)
	require.NotZero(t, superRoleID)

	h := env.graph.deps.roleAssignmentPreview
	original := *h
	restore := func() { *h = original }
	defer restore()
	failing := func() { *h = *api.NewRoleAssignmentPreviewHandler(failingPreviewer{}) }

	post := func(tok, path, body string) (int, []byte) {
		req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader([]byte(body)))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+tok)
		w := env.serve(req)
		return w.Code, w.Body.Bytes()
	}

	type branch struct {
		name  string
		tok   string
		body  string
		setup func()
		want  int
		code  string
	}
	run := func(t *testing.T, path string, branches []branch) {
		trace := func(r *model.AuditLog) bool { return r.Method == http.MethodPost && r.Path == path }
		skip := func(method, p string) bool { return method == http.MethodPost && p == path }
		for _, br := range branches {
			t.Run(br.name, func(t *testing.T) {
				if br.setup != nil {
					br.setup()
					defer restore()
				}
				ww := installAllTablesWriteWatchFor(t, env.db, trace)
				verBefore, err := authz.CurrentVersion(env.db)
				require.NoError(t, err)
				before := contentSnapshotSkipping(t, env.db, skip)
				c, b := post(br.tok, path, br.body)
				after := contentSnapshotSkipping(t, env.db, skip)
				verAfter, err := authz.CurrentVersion(env.db)
				require.NoError(t, err)
				hits, traces := ww.snapshot()
				ww.remove(t)
				require.Equal(t, br.want, c, string(b))
				if br.code != "" {
					assert.Contains(t, string(b), fmt.Sprintf(`"code":"%s"`, br.code))
				}
				assert.Empty(t, hits, "寫入計數必須為 0")
				assert.Empty(t, diffSnapshots(before, after), "內容快照不同")
				assert.Equal(t, verBefore, verAfter, "權限版本改變")
				assert.Equal(t, 1, traces, "請求留痕列應恰為中介層的一列")
				t.Logf("status=%d 寫入計數=0 快照相同 請求層通用留痕列=%d（不計入）", c, traces)
			})
		}
	}

	t.Run("角色草稿摘要", func(t *testing.T) {
		run(t, summaryPath, []branch{
			{name: "成功", tok: superTok, body: `{"permissions":["asset:view","asset:update"]}`, want: 200},
			{name: "空集合成功", tok: superTok, body: `{"permissions":[]}`, want: 200},
			{name: "不可指派鍵", tok: superTok, body: `{"permissions":["hostkey:reset"]}`, want: 400, code: "ROLE_PERMISSION_INVALID"},
			{name: "目錄外鍵", tok: superTok, body: `{"permissions":["nope:x"]}`, want: 400, code: "ROLE_PERMISSION_INVALID"},
			{name: "多餘頂層欄位", tok: superTok, body: `{"permissions":[],"extra":1}`, want: 400},
			{name: "本文不合法", tok: superTok, body: `{`, want: 400},
			{name: "無角色檢視能力", tok: userTok, body: `{"permissions":[]}`, want: 403},
		})
	})

	t.Run("指派預覽", func(t *testing.T) {
		run(t, previewPath, []branch{
			{name: "直接指派成功", tok: superTok, body: fmt.Sprintf(`{"kind":"direct_roles","user_id":%d,"role_ids":[%d]}`, target, custom.ID), want: 200},
			{name: "角色定義修改成功", tok: superTok, body: fmt.Sprintf(`{"kind":"role_definition","role_id":%d,"permissions":["asset:view","asset:update"]}`, custom.ID), want: 200},
			{name: "內建角色不可做角色定義預覽", tok: superTok, body: fmt.Sprintf(`{"kind":"role_definition","role_id":%d,"permissions":[]}`, superRoleID), want: 400},
			{name: "角色不存在", tok: superTok, body: `{"kind":"role_definition","role_id":999999,"permissions":[]}`, want: 400},
			{name: "種類不明", tok: superTok, body: `{"kind":"nope"}`, want: 400},
			{name: "本文不合法", tok: superTok, body: `{`, want: 400},
			{name: "路由層拒絕", tok: userTok, body: fmt.Sprintf(`{"kind":"direct_roles","user_id":%d,"role_ids":[]}`, target), want: 403},
			{name: "種類能力不足", tok: assignTok, body: fmt.Sprintf(`{"kind":"direct_roles","user_id":%d,"role_ids":[]}`, target), want: 403},
			{name: "計算失敗", tok: superTok, body: fmt.Sprintf(`{"kind":"direct_roles","user_id":%d,"role_ids":[]}`, target), setup: failing, want: 500, code: "INTERNAL_ROLE_ASSIGNMENT_PREVIEW"},
		})
	})

	t.Run("排程時刻預覽", func(t *testing.T) {
		run(t, nextRunsPath, []branch{
			{name: "成功", tok: superTok, body: `{"cron":"*/5 * * * *","count":3}`, want: 200},
			{name: "未給筆數用預設成功", tok: superTok, body: `{"cron":"0 3 * * *"}`, want: 200},
			{name: "永不發生的日期成功", tok: superTok, body: `{"cron":"0 0 30 2 *"}`, want: 200},
			{name: "排程式不合法", tok: superTok, body: `{"cron":"not a cron"}`, want: 400, code: "VALIDATION_SCHEDULE_BAD_CRON"},
			{name: "筆數超過上限", tok: superTok, body: `{"cron":"* * * * *","count":999}`, want: 400, code: "VALIDATION_SCHEDULE_RUN_COUNT"},
			{name: "本文不合法", tok: superTok, body: `{`, want: 400},
			{name: "無能力的使用者", tok: userTok, body: `{"cron":"* * * * *"}`, want: 403},
		})
	})

	t.Run("正向對照：請求期間寫入一筆時攔截計數非 0 且快照不同", func(t *testing.T) {
		*h = *api.NewRoleAssignmentPreviewHandler(failingPreviewer{
			write: func() error { return env.db.Create(&model.Role{Name: "nw-positive-control"}).Error },
		})
		defer restore()
		trace := func(r *model.AuditLog) bool { return r.Method == http.MethodPost && r.Path == previewPath }
		ww := installAllTablesWriteWatchFor(t, env.db, trace)
		skip := func(method, p string) bool { return method == http.MethodPost && p == previewPath }
		before := contentSnapshotSkipping(t, env.db, skip)
		c, b := post(superTok, previewPath, fmt.Sprintf(`{"kind":"direct_roles","user_id":%d,"role_ids":[]}`, target))
		after := contentSnapshotSkipping(t, env.db, skip)
		hits, _ := ww.snapshot()
		ww.remove(t)
		require.Equal(t, http.StatusOK, c, string(b))
		assert.NotEmpty(t, hits, "攔截沒看到寫入")
		assert.Contains(t, diffSnapshots(before, after), "roles", "快照沒看到寫入")
		require.NoError(t, env.db.Unscoped().Where("name = ?", "nw-positive-control").Delete(&model.Role{}).Error)
	})
}

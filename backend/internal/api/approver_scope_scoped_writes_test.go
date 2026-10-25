package api

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/testgate"
)

// 非超級管理者的審核範圍 DTO 可出現的鍵（標量恆在、巢狀物件依型別出現）。
var apsDTOKeys = map[string]bool{"id": true, "approver_id": true, "approver_group_id": true, "asset_id": true,
	"asset_group_id": true, "subject_user_id": true, "subject_group_id": true, "granted_by": true, "created_at": true,
	"approver": true, "approver_group": true, "asset": true, "asset_group": true, "subject_user": true, "subject_group": true}

var apsDTOScalars = []string{"id", "approver_id", "approver_group_id", "asset_id", "asset_group_id",
	"subject_user_id", "subject_group_id", "granted_by", "created_at"}

func requireDTOShape(t *testing.T, raw string, nested map[string][]string) {
	t.Helper()
	var m map[string]json.RawMessage
	require.NoError(t, json.Unmarshal([]byte(raw), &m), raw)
	for k := range m {
		require.True(t, apsDTOKeys[k], "非超管 DTO 出現凍結集合外的鍵 %q：%s", k, raw)
	}
	for _, k := range apsDTOScalars {
		_, ok := m[k]
		require.True(t, ok, "缺標量鍵 %q：%s", k, raw)
	}
	for k, want := range nested {
		require.Contains(t, m, k, raw)
		require.Equal(t, want, keysOf(t, string(m[k])), "巢狀 %s 鍵集：%s", k, raw)
	}
}

type apsWritesFx struct {
	e                                *apsEnv
	ap1, ap2, subj                   uint
	kNode, kNodeBoth, kNodeKA        uint
	kGlobal, kGlobalKA               uint
	assetIn, assetOut                uint
	sitRow, applicantRow, prodWebRow uint
	fixtureEmails, fixtureHosts      []string
}

func newAPSWritesFx(t *testing.T, prefix string) *apsWritesFx {
	e := apsEnvFor(t, prefix)
	fx := &apsWritesFx{e: e}
	fx.ap1, fx.ap2 = e.approver("aps-ap1"), e.approver("aps-ap2")
	fx.subj = e.user("aps-subject")
	k := e.role(authz.PermApproverScopeManage)
	ka := e.role(authz.PermApproverScopeApplicantManage)
	both := e.role(authz.PermApproverScopeManage, authz.PermApproverScopeApplicantManage)
	fx.kNode = e.user("aps-k-node")
	e.grantNodes(fx.kNode, k, "prod")
	fx.kNodeBoth = e.user("aps-k-node-both")
	e.grantNodes(fx.kNodeBoth, both, "prod")
	fx.kNodeKA = e.user("aps-k-node-ka-global")
	e.grantNodes(fx.kNodeKA, k, "prod")
	e.grantGlobal(fx.kNodeKA, ka)
	fx.kGlobal = e.user("aps-k-global")
	e.grantGlobal(fx.kGlobal, k)
	fx.kGlobalKA = e.user("aps-k-global-ka")
	e.grantGlobal(fx.kGlobalKA, both)
	fx.assetIn = e.hostAsset("aps-asset-in", "10.66.1.11", "prod/db")
	fx.assetOut = e.hostAsset("aps-asset-out", "10.66.2.22", "sit/web")
	fx.sitRow = e.seedScope(model.ApproverScope{ApproverID: &fx.ap2, AssetGroupID: ptrU(e.id("sit"))})
	fx.applicantRow = e.seedScope(model.ApproverScope{ApproverID: &fx.ap2, SubjectUserID: &fx.subj})
	fx.prodWebRow = e.seedScope(model.ApproverScope{ApproverID: &fx.ap2, AssetGroupID: ptrU(e.id("prod/web"))})
	fx.fixtureEmails = []string{"aps-ap1@aps-fixture.test", "aps-ap2@aps-fixture.test"}
	fx.fixtureHosts = []string{"10.66.1.11", "10.66.2.22"}
	return fx
}

func (fx *apsWritesFx) noLeak(t *testing.T, raw string) {
	t.Helper()
	for _, s := range append(append([]string{}, fx.fixtureEmails...), fx.fixtureHosts...) {
		assert.NotContains(t, raw, s, "序列化原文不得含 fixture 的 email 或位址")
	}
}

func auditDetails(t *testing.T, row model.AuditLog) map[string]any {
	t.Helper()
	m := map[string]any{}
	if row.Details != "" {
		require.NoError(t, json.Unmarshal([]byte(row.Details), &m), row.Details)
	}
	return m
}

func TestScopedApproverScopeWrites(t *testing.T) {
	pg := os.Getenv(testgate.EnvPGDSN) != "" || testgate.RequireIntegration()

	t.Run("create", func(t *testing.T) {
		fx := newAPSWritesFx(t, "aps_writes_create")
		e := fx.e

		// 範圍內節點型與資產型建立成功，回應為精簡 DTO
		r := e.do(fx.kNode, http.MethodPost, "/api/v1/approver-scopes", map[string]any{"approver_id": fx.ap1, "asset_group_id": e.id("prod/db")})
		require.Equal(t, http.StatusCreated, r.code, r.raw)
		requireDTOShape(t, r.raw, map[string][]string{"approver": {"id", "username"}, "asset_group": {"id", "name"}})
		fx.noLeak(t, r.raw)
		r = e.do(fx.kNode, http.MethodPost, "/api/v1/approver-scopes", map[string]any{"approver_id": fx.ap1, "asset_id": fx.assetIn})
		require.Equal(t, http.StatusCreated, r.code, r.raw)
		requireDTOShape(t, r.raw, map[string][]string{"approver": {"id", "username"}, "asset": {"id", "name"}})
		fx.noLeak(t, r.raw)

		// 顯示名稱查詢失敗：巢狀物件只有 id
		e.failNames.Store(true)
		r = e.do(fx.kNode, http.MethodPost, "/api/v1/approver-scopes", map[string]any{"approver_id": fx.ap1, "asset_group_id": e.id("prod/db/a")})
		e.failNames.Store(false)
		e.armed.Store(false)
		require.Equal(t, http.StatusCreated, r.code, r.raw)
		requireDTOShape(t, r.raw, map[string][]string{"approver": {"id"}, "asset_group": {"id"}})

		// 範圍外與不存在：節點、資產各兩回應逐位元相同，不寫入，審計為 denied
		for _, pair := range [][2]map[string]any{
			{{"approver_id": fx.ap1, "asset_group_id": e.id("sit/web")}, {"approver_id": fx.ap1, "asset_group_id": apsMissing}},
			{{"approver_id": fx.ap1, "asset_id": fx.assetOut}, {"approver_id": fx.ap1, "asset_id": apsMissing}},
		} {
			before := e.scopeCount()
			out := e.do(fx.kNode, http.MethodPost, "/api/v1/approver-scopes", pair[0])
			outAudit := e.lastAudit()
			missing := e.do(fx.kNode, http.MethodPost, "/api/v1/approver-scopes", pair[1])
			missingAudit := e.lastAudit()
			assert.Equal(t, http.StatusNotFound, out.code, out.raw)
			assert.Equal(t, missing.code, out.code)
			assert.Equal(t, missing.raw, out.raw, "範圍外與不存在逐位元相同")
			assert.Equal(t, before, e.scopeCount(), "範圍拒絕不寫入")
			assert.Equal(t, model.StatusDenied, outAudit.Status)
			assert.Equal(t, model.StatusDenied, missingAudit.Status)
			d := auditDetails(t, outAudit)
			assert.Equal(t, "scope", d["denial"], outAudit.Details)
			assert.Equal(t, "out_of_scope", d["scope_reason"], outAudit.Details)
			fx.noLeak(t, out.raw)
		}

		// 申請人型：節點範圍兩鍵、只持全域 K、節點範圍 K＋全域 KA 皆 403 單一形狀；全域 K＋KA 成功
		for _, uid := range []uint{fx.kNodeBoth, fx.kGlobal, fx.kNodeKA} {
			before := e.scopeCount()
			r := e.do(uid, http.MethodPost, "/api/v1/approver-scopes", map[string]any{"approver_id": fx.ap1, "subject_user_id": fx.subj})
			bodyOnlyCodeError(t, r)
			assert.Equal(t, before, e.scopeCount())
		}
		r = e.do(fx.kGlobalKA, http.MethodPost, "/api/v1/approver-scopes", map[string]any{"approver_id": fx.ap1, "subject_user_id": fx.subj})
		require.Equal(t, http.StatusCreated, r.code, r.raw)
		requireDTOShape(t, r.raw, map[string][]string{"approver": {"id", "username"}, "subject_user": {"id", "username"}})

		// 超級管理者：不存在資產維持現行 500 碼；成功回應與現行實作逐欄相同（去除列識別與時間）
		r = e.do(e.super, http.MethodPost, "/api/v1/approver-scopes", map[string]any{"approver_id": fx.ap1, "asset_id": apsMissing})
		assert.Equal(t, http.StatusInternalServerError, r.code, r.raw)
		assert.Contains(t, r.raw, `"INTERNAL_APPROVER_SCOPE_CREATE"`)
		spec := map[string]any{"approver_id": fx.ap2, "asset_group_id": e.id("prod/db/b")}
		scoped := e.do(e.super, http.MethodPost, "/api/v1/approver-scopes", spec)
		require.Equal(t, http.StatusCreated, scoped.code, scoped.raw)
		var created model.ApproverScope
		require.NoError(t, json.Unmarshal([]byte(scoped.raw), &created))
		require.NoError(t, e.db.Unscoped().Delete(&model.ApproverScope{}, created.ID).Error)
		plain := e.call(e.super, false, http.MethodPost, "/api/v1/approver-scopes", spec)
		require.Equal(t, http.StatusCreated, plain.code, plain.raw)
		assert.Equal(t, stripRowIdentity(t, plain.raw), stripRowIdentity(t, scoped.raw), "超級管理者建立回應與現行逐欄相同")
	})

	t.Run("delete", func(t *testing.T) {
		fx := newAPSWritesFx(t, "aps_writes_delete")
		e := fx.e
		// 範圍內列移除成功並入審計
		in := e.seedScope(model.ApproverScope{ApproverID: &fx.ap1, AssetGroupID: ptrU(e.id("prod/db"))})
		r := e.do(fx.kNode, http.MethodDelete, apsPath(in), nil)
		require.Equal(t, http.StatusOK, r.code, r.raw)
		assert.False(t, e.scopeExists(in))
		assert.Equal(t, model.StatusSuccess, e.lastAudit().Status)

		// sit 上的列、申請人型列、不存在 ID：三回應逐位元相同，資料不變
		sit := e.do(fx.kNode, http.MethodDelete, apsPath(fx.sitRow), nil)
		appl := e.do(fx.kNode, http.MethodDelete, apsPath(fx.applicantRow), nil)
		missing := e.do(fx.kNode, http.MethodDelete, apsPath(apsMissing), nil)
		assert.Equal(t, http.StatusNotFound, missing.code, missing.raw)
		assert.Contains(t, missing.raw, `"NOTFOUND_APPROVER_SCOPE"`)
		assert.Equal(t, missing, sit, "範圍外列與不存在同形")
		assert.Equal(t, missing, appl, "申請人型列與不存在同形")
		assert.True(t, e.scopeExists(fx.sitRow))
		assert.True(t, e.scopeExists(fx.applicantRow))

		// 全域 K 無 KA：申請人型列同為不存在回應（不是 403 kind_unmapped）；審計也與移除不存在 ID 相同：
		// 各寫一列 failure，不帶拒絕標記
		auditCount := func() int64 {
			var n int64
			require.NoError(t, e.db.Unscoped().Model(&model.AuditLog{}).Count(&n).Error)
			return n
		}
		auditsBefore := auditCount()
		gAppl := e.do(fx.kGlobal, http.MethodDelete, apsPath(fx.applicantRow), nil)
		gApplAudit := e.lastAudit()
		assert.Equal(t, auditsBefore+1, auditCount(), "申請人型列的移除寫一列審計")
		gMissing := e.do(fx.kGlobal, http.MethodDelete, apsPath(apsMissing), nil)
		gMissingAudit := e.lastAudit()
		assert.Equal(t, auditsBefore+2, auditCount(), "不存在 ID 的移除寫一列審計")
		assert.Equal(t, gMissing, gAppl)
		assert.Equal(t, http.StatusNotFound, gAppl.code, gAppl.raw)
		assert.Equal(t, gMissing.raw, gAppl.raw, "申請人型列與不存在 ID 逐位元相同")
		assert.Contains(t, gAppl.raw, `"NOTFOUND_APPROVER_SCOPE"`)
		assert.NotContains(t, gAppl.raw, "kind_unmapped")
		for _, row := range []model.AuditLog{gApplAudit, gMissingAudit} {
			assert.Equal(t, fx.kGlobal, row.UserID)
			assert.Equal(t, http.MethodDelete, row.Method)
			assert.Equal(t, model.StatusFailure, row.Status, row.Details)
			assert.Equal(t, http.StatusNotFound, row.StatusCode)
			d := auditDetails(t, row)
			assert.NotContains(t, d, "denial", row.Details)
			assert.NotContains(t, d, "scope_reason", row.Details)
		}
		assert.Equal(t, gMissingAudit.Details, gApplAudit.Details, "兩列審計細節相同")
		assert.True(t, e.scopeExists(fx.applicantRow))
		// 節點範圍 K＋全域 KA 同為不存在
		assert.Equal(t, missing, e.do(fx.kNodeKA, http.MethodDelete, apsPath(fx.applicantRow), nil))

		// 超級管理者移除與現行相同
		other := e.seedScope(model.ApproverScope{ApproverID: &fx.ap1, SubjectUserID: &fx.subj})
		superScoped := e.do(e.super, http.MethodDelete, apsPath(fx.applicantRow), nil)
		superPlain := e.call(e.super, false, http.MethodDelete, apsPath(other), nil)
		assert.Equal(t, superPlain, superScoped)
		assert.Equal(t, http.StatusOK, superScoped.code)
		assert.Equal(t, e.call(e.super, false, http.MethodDelete, apsPath(apsMissing), nil), e.do(e.super, http.MethodDelete, apsPath(apsMissing), nil))
	})

	t.Run("pg_move_first", func(t *testing.T) {
		if !pg {
			t.Skip("兩條連線與 advisory 鎖等待證明只在 PostgreSQL 跑（設 TEST_PG_DSN）")
		}
		runAPSRace(t, true)
	})
	t.Run("pg_create_first", func(t *testing.T) {
		if !pg {
			t.Skip("兩條連線與 advisory 鎖等待證明只在 PostgreSQL 跑（設 TEST_PG_DSN）")
		}
		runAPSRace(t, false)
	})
}

// stripRowIdentity 去除列識別與時間戳（兩次建立必然不同）後的 JSON。
func stripRowIdentity(t *testing.T, raw string) string {
	t.Helper()
	var m map[string]any
	require.NoError(t, json.Unmarshal([]byte(raw), &m), raw)
	for _, k := range []string{"id", "created_at", "updated_at"} {
		_, ok := m[k]
		require.True(t, ok, "缺 %s", k)
		delete(m, k)
	}
	b, err := json.Marshal(m)
	require.NoError(t, err)
	return strings.TrimSpace(string(b))
}

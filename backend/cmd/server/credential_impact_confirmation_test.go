package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
)

// 範圍外影響確認：夾具為一筆歸屬在範圍內節點的共用憑證，掛範圍內五台、範圍外九台。
type icEnv struct {
	*scEnv
	cred           uint
	inAssets       []uint
	outAssets      []uint
	mgr, mgr2, glb uint
}

func newICEnv(t *testing.T) *icEnv {
	t.Helper()
	e := &icEnv{scEnv: newSCEnv(t)}
	e.node("zz-ic-in", "")
	e.node("zz-ic-out", "")
	e.cred = e.scEnv.cred("zz-ic-shared", e.nodeID("zz-ic-in"))
	for i := 0; i < 5; i++ {
		a := e.asset(fmt.Sprintf("zz-ic-asset-in-%d", i), "zz-ic-in")
		e.inAssets = append(e.inAssets, a)
		e.mount(e.cred, a)
	}
	for i := 0; i < 9; i++ {
		a := e.asset(fmt.Sprintf("zz-ic-asset-out-%d", i), "zz-ic-out")
		e.outAssets = append(e.outAssets, a)
		e.mount(e.cred, a)
	}
	perms := []authz.Permission{authz.PermCredentialView, authz.PermCredentialSetSecret, authz.PermCredentialRotate,
		authz.PermCredentialDetach}
	e.mgr, e.mgr2 = e.user("zz-ic-mgr"), e.user("zz-ic-mgr2")
	e.grant(e.mgr, []string{"zz-ic-in"}, perms...)
	e.grant(e.mgr2, []string{"zz-ic-in"}, perms...)
	e.glb = e.user("zz-ic-global")
	e.grantGlobal(e.glb, e.role(perms...))
	return e
}

type icResult struct {
	Required       bool   `json:"required"`
	ConfirmationID string `json:"confirmation_id"`
	InScope        int    `json:"in_scope_count"`
}

func (e *icEnv) confirm(uid uint, credID uint, op string) (int, string) {
	return e.call(uid, "POST", credPath(credID)+"/impact-confirmations", fmt.Sprintf(`{"operation":%q}`, op))
}

func (e *icEnv) rows(credID uint) []model.CredentialImpactConfirmation {
	e.t.Helper()
	var rs []model.CredentialImpactConfirmation
	require.NoError(e.t, e.db.Where("credential_id = ?", credID).Find(&rs).Error)
	return rs
}

func (e *icEnv) versions(credID uint) int64 {
	e.t.Helper()
	var n int64
	require.NoError(e.t, e.db.Model(&model.CredentialSecretVersion{}).Where("credential_id = ?", credID).Count(&n).Error)
	return n
}

func (e *icEnv) effectiveSet(credID uint) int64 {
	e.t.Helper()
	var n int64
	require.NoError(e.t, e.db.Model(&model.AssetAccount{}).
		Where("credential_id = ? AND effective_version_id IS NOT NULL", credID).Count(&n).Error)
	return n
}

func (e *icEnv) setSecret(uid uint, credID uint, confirmationID string) (int, string) {
	body := `{"password":"zz-ic-new-secret"}`
	if confirmationID != "" {
		body = fmt.Sprintf(`{"password":"zz-ic-new-secret","impact_confirmation_id":%q}`, confirmationID)
	}
	return e.call(uid, "POST", credPath(credID)+"/secret", body)
}

func (e *icEnv) requiredCount(t *testing.T, uid uint, confirmationID string) int {
	t.Helper()
	code, body := e.setSecret(uid, e.cred, confirmationID)
	return icRequiredCount(t, code, body)
}

func icRequiredCount(t *testing.T, code int, body string) int {
	t.Helper()
	require.Equal(t, http.StatusConflict, code, body)
	var out struct {
		Code   string         `json:"code"`
		Params map[string]any `json:"params"`
	}
	require.NoError(t, json.Unmarshal([]byte(body), &out))
	require.Equal(t, "RULE_CREDENTIAL_IMPACT_CONFIRMATION_REQUIRED", out.Code, body)
	n, ok := out.Params["count"].(float64)
	require.True(t, ok, body)
	return int(n)
}

func TestCredentialImpactConfirmation(t *testing.T) {
	t.Run("全域主體回 required false 且不建紀錄", func(t *testing.T) {
		e := newICEnv(t)
		code, body := e.confirm(e.glb, e.cred, "set_secret")
		require.Equal(t, http.StatusOK, code, body)
		var r icResult
		require.NoError(t, json.Unmarshal([]byte(body), &r))
		require.False(t, r.Required)
		require.Equal(t, 14, r.InScope)
		require.Empty(t, e.rows(e.cred))
		// 全域主體不帶確認照常成功
		code, body = e.setSecret(e.glb, e.cred, "")
		require.Equal(t, http.StatusOK, code, body)
	})

	t.Run("範圍化主體回範圍內五台與範圍外九台，表內集合恰為那九台且回應不洩漏", func(t *testing.T) {
		e := newICEnv(t)
		code, body := e.confirm(e.mgr, e.cred, "set_secret")
		require.Equal(t, http.StatusOK, code, body)
		var r icResult
		require.NoError(t, json.Unmarshal([]byte(body), &r))
		require.True(t, r.Required)
		require.Equal(t, 5, r.InScope)
		require.NotEmpty(t, r.ConfirmationID)
		require.Contains(t, body, scOutCountJSON(9))
		var keys map[string]json.RawMessage
		require.NoError(t, json.Unmarshal([]byte(body), &keys))
		got := make([]string, 0, len(keys))
		for k := range keys {
			got = append(got, k)
		}
		sort.Strings(got)
		require.Equal(t, []string{"confirmation_id", "in_scope_count", "out_of_scope_asset_count", "required"}, got,
			"回應只有這四個欄位，不含任何資產識別、名稱或節點")
		require.False(t, strings.Contains(body, "zz-ic-"), "回應不含資產或節點名稱")

		rows := e.rows(e.cred)
		require.Len(t, rows, 1)
		var ids []uint
		require.NoError(t, json.Unmarshal([]byte(rows[0].OutOfScopeAssetIDs), &ids))
		want := append([]uint{}, e.outAssets...)
		sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
		sort.Slice(want, func(i, j int) bool { return want[i] < want[j] })
		require.Equal(t, want, ids)
		require.Equal(t, r.ConfirmationID, rows[0].ID)
	})

	t.Run("看得到但無改密能力的資產計入範圍外", func(t *testing.T) {
		e := newICEnv(t)
		// 範圍內節點持檢視、宣告與輪替；範圍外節點只持檢視：九台看得到，但不在兩種動作能力的範圍內
		viewer := e.user("zz-ic-viewer")
		e.grant(viewer, []string{"zz-ic-in"}, authz.PermCredentialView, authz.PermCredentialSetSecret,
			authz.PermCredentialRotate)
		e.grant(viewer, []string{"zz-ic-out"}, authz.PermCredentialView)
		want := append([]uint{}, e.outAssets...)
		sort.Slice(want, func(i, j int) bool { return want[i] < want[j] })
		for _, op := range []string{"set_secret", "rotate"} {
			code, body := e.confirm(viewer, e.cred, op)
			require.Equal(t, http.StatusOK, code, body)
			var r icResult
			require.NoError(t, json.Unmarshal([]byte(body), &r))
			require.True(t, r.Required, op)
			require.Equal(t, 5, r.InScope, op)
			require.Contains(t, body, scOutCountJSON(9), op)
			rows := e.rowsFor(e.cred, op)
			require.Len(t, rows, 1, op)
			var ids []uint
			require.NoError(t, json.Unmarshal([]byte(rows[0].OutOfScopeAssetIDs), &ids))
			sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
			require.Equal(t, want, ids, "%s：確認集合以動作能力的資產範圍計，不以檢視範圍計", op)
		}
		// 提交重算與確認端點同一口徑：未帶確認回 409 且 count=9，密文版本不變
		before := e.versions(e.cred)
		require.Equal(t, 9, e.requiredCount(t, viewer, ""))
		require.Equal(t, before, e.versions(e.cred))
	})

	t.Run("同一操作者重建後該組只剩一列；動作值域外回 400；範圍外與不存在同形", func(t *testing.T) {
		e := newICEnv(t)
		e.confirm(e.mgr, e.cred, "set_secret")
		first := e.rows(e.cred)
		require.Len(t, first, 1)
		e.confirm(e.mgr, e.cred, "set_secret")
		second := e.rows(e.cred)
		require.Len(t, second, 1)
		require.NotEqual(t, first[0].ID, second[0].ID)
		e.confirm(e.mgr, e.cred, "rotate")
		require.Len(t, e.rows(e.cred), 2, "不同動作各保留一列")

		code, body := e.confirm(e.mgr, e.cred, "delete")
		require.Equal(t, http.StatusBadRequest, code, body)

		out := e.scEnv.cred("zz-ic-out-cred", e.nodeID("zz-ic-out"))
		e.mount(out, e.outAssets[0])
		wantCode, wantBody := e.confirm(e.mgr, 999991, "set_secret")
		code, body = e.confirm(e.mgr, out, "set_secret")
		require.Equal(t, wantCode, code)
		require.Equal(t, wantBody, body)
		require.Empty(t, e.rows(out))
	})

	t.Run("宣告新秘密：缺漏、已用、不符與擴大回 409 且零變更，子集通過並留痕", func(t *testing.T) {
		e := newICEnv(t)
		v0 := e.versions(e.cred)

		// 缺漏
		require.Equal(t, 9, e.requiredCount(t, e.mgr, ""))
		require.Equal(t, v0, e.versions(e.cred))
		require.Zero(t, e.effectiveSet(e.cred))

		// 別的操作者用該識別
		_, body := e.confirm(e.mgr, e.cred, "set_secret")
		var r icResult
		require.NoError(t, json.Unmarshal([]byte(body), &r))
		require.Equal(t, 9, e.requiredCount(t, e.mgr2, r.ConfirmationID))
		// 動作不符：宣告用的確認不能拿去發輪替
		_, body = e.confirm(e.mgr, e.cred, "rotate")
		var rot icResult
		require.NoError(t, json.Unmarshal([]byte(body), &rot))
		require.Equal(t, 9, e.requiredCount(t, e.mgr, rot.ConfirmationID))

		// 擴大：確認後再掛一台範圍外資產
		extra := e.asset("zz-ic-asset-out-extra", "zz-ic-out")
		extraAcc := e.mount(e.cred, extra)
		require.Equal(t, 10, e.requiredCount(t, e.mgr, r.ConfirmationID))
		require.Equal(t, v0, e.versions(e.cred), "擴大時秘密不變")
		require.Zero(t, e.effectiveSet(e.cred))

		// 縮小：重新確認（十台），再卸載兩台範圍外 → 通過，審計記範圍外台數與確認識別
		_, body = e.confirm(e.mgr, e.cred, "set_secret")
		require.NoError(t, json.Unmarshal([]byte(body), &r))
		require.NoError(t, e.db.Delete(&model.AssetAccount{}, extraAcc).Error)
		var oneOut model.AssetAccount
		require.NoError(t, e.db.Where("credential_id = ? AND asset_id = ?", e.cred, e.outAssets[0]).First(&oneOut).Error)
		require.NoError(t, e.db.Delete(&model.AssetAccount{}, oneOut.ID).Error)
		code, rb := e.setSecret(e.mgr, e.cred, r.ConfirmationID)
		require.Equal(t, http.StatusOK, code, rb)
		require.Equal(t, v0+1, e.versions(e.cred))
		require.EqualValues(t, 13, e.effectiveSet(e.cred), "剩餘十三台全部就位新版")
		var logs []model.AuditLog
		require.NoError(t, e.db.Where("resource_id = ? AND details LIKE ?", e.cred, "%\"operation\":\"set_secret\"%").Find(&logs).Error)
		require.NotEmpty(t, logs)
		var details map[string]any
		require.NoError(t, json.Unmarshal([]byte(logs[len(logs)-1].Details), &details))
		require.Equal(t, "8", details["out_of_scope_count"])
		require.Equal(t, r.ConfirmationID, details["impact_confirmation_id"])

		// 已用
		require.Equal(t, 8, e.requiredCount(t, e.mgr, r.ConfirmationID))
		require.Empty(t, e.rowsFor(e.cred, "set_secret"), "通過後確認列已刪除")
	})

	t.Run("整組與拆分輪替未帶確認時零輪替列、零遠端", func(t *testing.T) {
		e := newICEnv(t)
		rot := asset.NewCredentialRotationService(e.db, e.assets, nil, nil, e.codec, audit.NewTxSink(), e.adapter).
			WithScopeSource(authz.NewCredentialScopeReader(e.eval, e.db))
		ctx := e.ctx(e.mgr)
		_, err := rot.Start(ctx, e.cred, asset.StartRotationRequest{})
		var need *asset.CredentialImpactConfirmationRequiredError
		require.ErrorAs(t, err, &need)
		require.Equal(t, 9, need.Count)
		_, err = rot.StartSplit(ctx, e.cred, asset.StartRotationRequest{})
		require.ErrorAs(t, err, &need)
		require.Equal(t, 9, need.Count)
		var n int64
		require.NoError(t, e.db.Model(&model.CredentialRotation{}).Count(&n).Error)
		require.Zero(t, n, "輪替列為 0（遠端只在輪替列之後才會被碰觸）")
		var c model.Credential
		require.NoError(t, e.db.First(&c, e.cred).Error)
		require.Nil(t, c.ActiveRotationID)
		require.Nil(t, c.PendingVersionID)
	})
}

func (e *icEnv) rowsFor(credID uint, op string) []model.CredentialImpactConfirmation {
	e.t.Helper()
	var rs []model.CredentialImpactConfirmation
	require.NoError(e.t, e.db.Where("credential_id = ? AND operation = ?", credID, op).Find(&rs).Error)
	return rs
}

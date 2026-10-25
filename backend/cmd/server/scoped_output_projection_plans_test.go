package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/model"
)

// soCredPlan 建立憑證目標計畫。
func (e *outEnv) soCredPlan(name string, credID uint, assetIDs ...uint) model.ChangeSecretPlan {
	e.t.Helper()
	p := e.soPlan(name, assetIDs...)
	cid := credID
	require.NoError(e.t, e.db.Model(&model.ChangeSecretPlan{}).Where("id = ?", p.ID).
		Updates(map[string]any{"target_kind": model.PlanTargetCredential, "target_credential_id": &cid}).Error)
	p.TargetKind, p.TargetCredentialID = model.PlanTargetCredential, &cid
	return p
}

// soPlanAssetIDs 解出列中 asset_ids 字串內的資產識別。
func soPlanAssetIDs(t *testing.T, row map[string]any) []uint {
	t.Helper()
	s, ok := row["asset_ids"].(string)
	require.True(t, ok, "PRECONDITION: asset_ids 應為字串: %v", row)
	var ids []uint
	require.NoError(t, json.Unmarshal([]byte(s), &ids), s)
	return ids
}

func TestScopedChangeSecretPlanListProjection(t *testing.T) {
	e := newOutEnv(t, soWithChangeSecret())
	acctPlan := e.soPlan("zz-so-plan-acct", e.assetIn0, e.assetIn1)
	mixed := e.soCredPlan("zz-so-plan-mixed", e.inCred, e.assetIn0, e.assetOut0)
	globalTarget := e.soCredPlan("zz-so-plan-gtarget", e.gcred, e.assetIn0)
	const listPath = "/api/v1/change-secret-plans"

	t.Run("credential_target_hides_out_of_view_credential", func(t *testing.T) {
		code, raw := soServe(e.soChangeSecretRouter(e.glbCsOnly), http.MethodGet, listPath, "")
		soAssertOK(t, code, raw, http.StatusOK, []string{"data", "total"})
		soAssertNoLeak(t, raw, []soToken{soNum("target_credential_id", e.gcred), soNum("target_credential_id", e.inCred)},
			[]string{`"credential_out_of_scope":true`})
		row := soJSONRowBy(t, soJSONRows(t, raw, "data"), "id", globalTarget.ID)
		if v, present := row["target_credential_id"]; !present || v != nil {
			t.Fatalf("ASSERT: 範圍外憑證應輸出 target_credential_id:null\n列: %v", row)
		}
	})

	t.Run("assets_outside_view_are_dropped", func(t *testing.T) {
		code, raw := soServe(e.soChangeSecretRouter(e.mgr), http.MethodGet, listPath, "")
		soAssertOK(t, code, raw, http.StatusOK, []string{"data", "total"})
		row := soJSONRowBy(t, soJSONRows(t, raw, "data"), "id", mixed.ID)
		if got := soPlanAssetIDs(t, row); fmt.Sprint(got) != fmt.Sprint([]uint{e.assetIn0}) {
			t.Fatalf("LEAK: 資產集合應只留檢視範圍內的資產 [%d]，實際 %v\n列: %v", e.assetIn0, got, row)
		}
		if n, _ := row["out_of_scope_asset_count"].(float64); n != 1 {
			t.Fatalf("ASSERT: 應帶 out_of_scope_asset_count:1\n列: %v", row)
		}
		if _, marked := row["credential_out_of_scope"]; marked {
			t.Fatalf("ASSERT: 範圍內憑證不應帶憑證標記\n列: %v", row)
		}
		if v, _ := row["target_credential_id"].(float64); uint(v) != e.inCred {
			t.Fatalf("ASSERT: 範圍內憑證的識別應保留\n列: %v", row)
		}
		soAssertNoLeak(t, raw, nil, []string{fmt.Sprintf(`"id":%d`, acctPlan.ID)})
		if r := soJSONRowBy(t, soJSONRows(t, raw, "data"), "id", acctPlan.ID); r["out_of_scope_asset_count"] != nil {
			t.Fatalf("ASSERT: 資產全在範圍內的計畫不應帶計數\n列: %v", r)
		}
	})

	t.Run("global_matches_service_bytes", func(t *testing.T) {
		code, raw := soServe(e.soChangeSecretRouter(e.glb), http.MethodGet, listPath, "")
		soAssertOK(t, code, raw, http.StatusOK, []string{"data", "total"})
		ctx := context.WithValue(e.soPrincipalCtx(e.glb), "userID", e.glb) //nolint:staticcheck // 與請求脈絡相同的鍵
		plans, err := e.plans.ListFor(ctx)
		require.NoError(t, err)
		require.Len(t, plans, 3, raw)
		want, err := json.Marshal(map[string]any{"data": plans, "total": len(plans)})
		require.NoError(t, err)
		if raw != string(want) {
			t.Fatalf("ASSERT: 全量檢視者的計畫列表應與服務層序列化逐字相同\n回應: %s\n服務層: %s", raw, want)
		}
	})
}

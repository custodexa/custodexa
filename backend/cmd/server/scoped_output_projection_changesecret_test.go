package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/authz"
)

const (
	soVerG    uint = 90001 // recG 的目標版本識別
	soVerI    uint = 90002 // recI 的目標版本識別
	soVerHist uint = 90003 // 歷史紀錄的目標版本識別
)

// soCSData 改密選項下的衍生資料。
type soCSData struct {
	batchID                   uint
	inPlan, outPlan, histPlan model.ChangeSecretPlan
	histAcc, assetIn2         uint
	candOut, candIn           model.ChangeSecretCandidate
	recG, recI                model.ChangeSecretRecord
	batchRecG, batchRecI      model.ChangeSecretRecord
}

func (e *outEnv) soRecord(batchID, planID, assetID, accID uint, username string, credID uint, credName string,
	ver uint) model.ChangeSecretRecord {
	e.t.Helper()
	r := model.ChangeSecretRecord{BatchID: batchID, PlanID: planID, AssetID: assetID, AccountID: accID,
		AccountUsername: username, SecretType: model.ChangeSecretTypePassword, CredentialID: credID,
		CredentialName: credName, TargetVersionID: ver, Status: "skipped", ExecutedAt: time.Now()}
	require.NoError(e.t, e.db.Create(&r).Error)
	return r
}

func (e *outEnv) soPlan(name string, assetIDs ...uint) model.ChangeSecretPlan {
	e.t.Helper()
	ids, err := json.Marshal(assetIDs)
	require.NoError(e.t, err)
	p := model.ChangeSecretPlan{Name: name, AssetIDs: string(ids), Accounts: `["@ALL"]`, Enabled: true,
		TargetKind: model.PlanTargetAccount, SecretType: model.ChangeSecretTypePassword}
	require.NoError(e.t, e.db.Create(&p).Error)
	return p
}

func (e *outEnv) soCandidate(accID, assetID, planID uint, username string) model.ChangeSecretCandidate {
	e.t.Helper()
	c := model.ChangeSecretCandidate{AccountID: accID, AssetID: assetID, PlanID: planID,
		AccountUsername: username, SecretType: model.ChangeSecretTypePassword}
	require.NoError(e.t, e.db.Create(&c).Error)
	return c
}

// soPrincipalCtx 以指定使用者的主體建立服務層呼叫脈絡。
func (e *outEnv) soPrincipalCtx(uid uint) context.Context {
	e.t.Helper()
	p, err := authz.ResolveUserOnWithCatalogue(e.db, e.cat, uid, authz.TokenFacts{})
	require.NoError(e.t, err)
	return authz.ContextWithPrincipal(context.Background(), p)
}

// soBuildCS 建立批次、計畫、紀錄與候選。
func (e *outEnv) soBuildCS() *soCSData {
	e.t.Helper()
	d := &soCSData{}
	d.assetIn2 = e.asset("zz-so-asset-in-2", soNodeIn)
	d.histAcc = e.mount(e.histCred, d.assetIn2)

	batch, _, err := e.batches.CreateFor(e.soPrincipalCtx(e.mgr), &asset.ChangeSecretBatchRequest{
		Username: "zz-so-g", All: true, PasswordMode: model.BatchPasswordPerTarget}, e.mgr, "zz-so-mgr")
	require.NoError(e.t, err)
	d.batchID = batch.ID
	d.batchRecG = e.soRecord(batch.ID, 0, e.assetIn0, e.gcredAcc, "zz-so-g", e.gcred, "zz-so-out-gcred", soVerG)
	d.batchRecI = e.soRecord(batch.ID, 0, e.assetIn1, e.accI, "zz-so-g", e.inCred, "zz-so-in-cred", soVerI)

	d.inPlan = e.soPlan("zz-so-in-plan", e.assetIn0, e.assetIn1)
	d.outPlan = e.soPlan("zz-so-out-plan", e.assetIn0, e.assetOut0)
	d.histPlan = e.soPlan("zz-so-hist-plan", d.assetIn2)
	d.recG = e.soRecord(0, d.inPlan.ID, e.assetIn0, e.gcredAcc, "zz-so-g", e.gcred, "zz-so-out-gcred", soVerG)
	d.recI = e.soRecord(0, d.inPlan.ID, e.assetIn1, e.accI, "zz-so-g", e.inCred, "zz-so-in-cred", soVerI)

	d.candOut = e.soCandidate(e.gcredAcc, e.assetIn0, d.outPlan.ID, "zz-so-g")
	d.candIn = e.soCandidate(e.accI, e.assetIn1, d.inPlan.ID, "zz-so-g")
	return d
}

// soRows 取回應中的列陣列：path 依序為物件鍵。
func soJSONRows(t *testing.T, raw string, path ...string) []map[string]any {
	t.Helper()
	var cur any = soDecode(t, raw)
	for _, k := range path {
		m, _ := cur.(map[string]any)
		require.NotNil(t, m, raw)
		cur = m[k]
	}
	arr, _ := cur.([]any)
	out := make([]map[string]any, 0, len(arr))
	for _, a := range arr {
		m, _ := a.(map[string]any)
		out = append(out, m)
	}
	return out
}

func soJSONRowBy(t *testing.T, rows []map[string]any, key string, id uint) map[string]any {
	t.Helper()
	for _, r := range rows {
		if v, ok := r[key].(float64); ok && uint(v) == id {
			return r
		}
	}
	t.Fatalf("PRECONDITION: 找不到 %s=%d 的列\n列: %v", key, id, rows)
	return nil
}

// soRawData 取外框中 data 的原始位元組（detail 取 data.records）。
func soRawData(t *testing.T, raw string, inner string) string {
	t.Helper()
	var top map[string]json.RawMessage
	require.NoError(t, json.Unmarshal([]byte(raw), &top))
	b := top["data"]
	if inner != "" {
		var in map[string]json.RawMessage
		require.NoError(t, json.Unmarshal(b, &in))
		b = in[inner]
	}
	return string(b)
}

func TestScopedChangeSecretOutputProjection(t *testing.T) {
	e := newOutEnv(t, soWithChangeSecret())
	d := e.soBuildCS()
	r := func(uid uint) func(path string) (int, string) {
		router := e.soChangeSecretRouter(uid)
		return func(path string) (int, string) { return soServe(router, http.MethodGet, path, "") }
	}
	const targetsPath = "/api/v1/change-secret-batches/targets?username=zz-so-g"
	batchPath := fmt.Sprintf("/api/v1/change-secret-batches/%d", d.batchID)
	recordsPath := func(p model.ChangeSecretPlan) string {
		return fmt.Sprintf("/api/v1/change-secret-plans/%d/records", p.ID)
	}

	gForbidden := []soToken{soName("zz-so-out-gcred"), soNum("credential_id", e.gcred), soNum("target_version_id", soVerG)}
	iForbidden := []soToken{soName("zz-so-in-cred"), soNum("credential_id", e.inCred), soNum("target_version_id", soVerI)}
	hForbidden := []soToken{soName("zz-so-out-hist"), soNum("credential_id", e.histCred), soNum("target_version_id", soVerHist)}
	visible := []soToken{soName("zz-so-asset-in-0"), soName("zz-so-asset-in-1"), soName("zz-so-g"), soName("zz-so-in-cred"),
		soName("zz-so-hist-next"), soNum("plan_id", d.inPlan.ID), soNum("credential_id", e.inCred),
		soNum("target_version_id", soVerI)}
	soCheckFixture(t, gForbidden, visible)
	soCheckFixture(t, []soToken{soName("zz-so-out-hist"), soNum("credential_id", e.histCred), soNum("target_version_id", soVerHist),
		soNum("plan_id", d.outPlan.ID)}, visible)

	hasMarker := func(m map[string]any) bool { v, _ := m["credential_out_of_scope"].(bool); return v }
	assertMasked := func(t *testing.T, row map[string]any, fields ...string) {
		t.Helper()
		if !hasMarker(row) {
			t.Fatalf("ASSERT: 範圍外憑證的列應帶 credential_out_of_scope:true\n列: %v", row)
		}
		for _, f := range fields {
			if _, ok := row[f]; ok {
				t.Fatalf("ASSERT: 範圍外憑證的列不應含 %s\n列: %v", f, row)
			}
		}
	}

	t.Run("batch_targets", func(t *testing.T) {
		code, raw := r(e.mgr)(targetsPath)
		soAssertOK(t, code, raw, http.StatusOK, []string{"data", "total"})
		soAssertNoLeak(t, raw, gForbidden, []string{`"credential_name":"zz-so-in-cred"`, `"username":"zz-so-g"`})
		rows := soJSONRows(t, raw, "data")
		require.Len(t, rows, 2, raw)
		assertMasked(t, soJSONRowBy(t, rows, "account_id", e.gcredAcc), "credential_name")
		if in := soJSONRowBy(t, rows, "account_id", e.accI); hasMarker(in) {
			t.Fatalf("ASSERT: 範圍內憑證的列不應帶標記\n列: %v", in)
		}
	})

	t.Run("batch_detail", func(t *testing.T) {
		code, raw := r(e.mgr)(batchPath)
		soAssertOK(t, code, raw, http.StatusOK, []string{"data"})
		soAssertNoLeak(t, raw, gForbidden, []string{`"credential_name":"zz-so-in-cred"`, `"account_username":"zz-so-g"`})
		rows := soJSONRows(t, raw, "data", "records")
		assertMasked(t, soJSONRowBy(t, rows, "id", d.batchRecG.ID), "credential_id", "credential_name", "target_version_id")
		if in := soJSONRowBy(t, rows, "id", d.batchRecI.ID); hasMarker(in) {
			t.Fatalf("ASSERT: 範圍內憑證的紀錄不應帶標記\n列: %v", in)
		}
	})

	t.Run("plan_records", func(t *testing.T) {
		code, raw := r(e.mgr)(recordsPath(d.inPlan))
		soAssertOK(t, code, raw, http.StatusOK, []string{"data", "total"})
		soAssertNoLeak(t, raw, gForbidden, []string{`"credential_name":"zz-so-in-cred"`, `"account_username":"zz-so-g"`})
		rows := soJSONRows(t, raw, "data")
		assertMasked(t, soJSONRowBy(t, rows, "id", d.recG.ID), "credential_id", "credential_name", "target_version_id")
		if in := soJSONRowBy(t, rows, "id", d.recI.ID); hasMarker(in) {
			t.Fatalf("ASSERT: 範圍內憑證的紀錄不應帶標記\n列: %v", in)
		}
	})

	t.Run("plan_records_history", func(t *testing.T) {
		rec := e.soRecord(0, d.histPlan.ID, d.assetIn2, d.histAcc, "zz-so-hist-user", e.histCred, "zz-so-out-hist", soVerHist)
		// 紀錄之後，該憑證改歸範圍外，帳號改掛範圍內的另一筆憑證
		require.NoError(t, e.db.Model(&model.Credential{}).Where("id = ?", e.histCred).
			Update("owner_node_id", e.nodes[soNodeOut]).Error)
		require.NoError(t, e.db.Model(&model.AssetAccount{}).Where("id = ?", d.histAcc).
			Update("credential_id", e.histNext).Error)
		code, raw := r(e.mgr)(recordsPath(d.histPlan))
		soAssertOK(t, code, raw, http.StatusOK, []string{"data", "total"})
		soAssertNoLeak(t, raw, hForbidden, []string{`"account_username":"zz-so-hist-user"`})
		assertMasked(t, soJSONRowBy(t, soJSONRows(t, raw, "data"), "id", rec.ID), "credential_id", "credential_name", "target_version_id")
	})

	t.Run("candidates_plan_ref", func(t *testing.T) {
		code, raw := r(e.mgr)("/api/v1/change-secret-candidates")
		soAssertOK(t, code, raw, http.StatusOK, []string{"data", "total"})
		soAssertNoLeak(t, raw, []soToken{soNum("plan_id", d.outPlan.ID)},
			[]string{fmt.Sprintf(`"plan_id":%d`, d.inPlan.ID), `"plan_id":0`})
		rows := soJSONRows(t, raw, "data")
		require.Len(t, rows, 2, raw)
		if v := soJSONRowBy(t, rows, "id", d.candOut.ID)["plan_id"].(float64); v != 0 {
			t.Fatalf("ASSERT: 來自不可見計畫的候選 plan_id 應為 0，實際 %v", v)
		}
	})

	t.Run("global_unchanged", func(t *testing.T) {
		get := r(e.glb)
		// 目標
		code, raw := get(targetsPath)
		soAssertOK(t, code, raw, http.StatusOK, []string{"data", "total", "as_of"})
		var asOf time.Time
		require.NoError(t, json.Unmarshal([]byte(`"`+soDecode(t, raw)["as_of"].(string)+`"`), &asOf))
		wantTargets, err := e.batches.Targets("zz-so-g", asOf)
		require.NoError(t, err)
		wb, err := json.Marshal(wantTargets)
		require.NoError(t, err)
		if got := soRawData(t, raw, ""); got != string(wb) {
			t.Fatalf("PRECONDITION: 全域檢視者的目標與服務層結果不同\n回應: %s\n服務層: %s", got, wb)
		}
		soAssertNoLeak(t, raw, nil, []string{`"credential_name":"zz-so-out-gcred"`, `"credential_name":"zz-so-in-cred"`})
		soGoldenLog(t, "batch_targets", soKeyset(t, raw))
		// 批次明細
		code, raw = get(batchPath)
		soAssertOK(t, code, raw, http.StatusOK, []string{"data"})
		wantRecs, err := e.batches.Records(d.batchID)
		require.NoError(t, err)
		wb, err = json.Marshal(wantRecs)
		require.NoError(t, err)
		if got := soRawData(t, raw, "records"); got != string(wb) {
			t.Fatalf("PRECONDITION: 全域檢視者的批次紀錄與服務層結果不同\n回應: %s\n服務層: %s", got, wb)
		}
		soAssertNoLeak(t, raw, nil, []string{`"credential_name":"zz-so-out-gcred"`, `"target_version_id":90001`})
		soGoldenLog(t, "batch_detail", soKeyset(t, raw))
		// 計畫紀錄
		code, raw = get(recordsPath(d.inPlan))
		soAssertOK(t, code, raw, http.StatusOK, []string{"data", "total"})
		wantRecs, err = e.plans.Records(d.inPlan.ID, 100)
		require.NoError(t, err)
		wb, err = json.Marshal(wantRecs)
		require.NoError(t, err)
		if got := soRawData(t, raw, ""); got != string(wb) {
			t.Fatalf("PRECONDITION: 全域檢視者的計畫紀錄與服務層結果不同\n回應: %s\n服務層: %s", got, wb)
		}
		soAssertNoLeak(t, raw, nil, []string{`"credential_name":"zz-so-out-gcred"`, `"target_version_id":90001`})
		soGoldenLog(t, "plan_records", soKeyset(t, raw))
		// 候選：不可見計畫的識別對全域檢視者仍在
		code, raw = get("/api/v1/change-secret-candidates")
		soAssertOK(t, code, raw, http.StatusOK, []string{"data", "total"})
		soAssertNoLeak(t, raw, nil, []string{fmt.Sprintf(`"plan_id":%d`, d.outPlan.ID), fmt.Sprintf(`"plan_id":%d`, d.inPlan.ID)})
		soGoldenLog(t, "candidates", soKeyset(t, raw))
	})

	// 改密入口與改密能力不授予憑證識別：三種主體讀三個回應，列照列、憑證欄位全部收窄
	both := append(append([]soToken{}, gForbidden...), iForbidden...)
	notGranted := func(uid uint) func(t *testing.T) {
		return func(t *testing.T) {
			get := r(uid)
			code, raw := get(targetsPath)
			soAssertOK(t, code, raw, http.StatusOK, []string{"data", "total"})
			soAssertNoLeak(t, raw, both, []string{"zz-so-asset-in-0", `"username":"zz-so-g"`})
			rows := soJSONRows(t, raw, "data")
			require.Len(t, rows, 2, raw)
			for _, id := range []uint{e.gcredAcc, e.accI} {
				assertMasked(t, soJSONRowBy(t, rows, "account_id", id), "credential_name")
			}

			code, raw = get(batchPath)
			soAssertOK(t, code, raw, http.StatusOK, []string{"data"})
			soAssertNoLeak(t, raw, both, []string{`"account_username":"zz-so-g"`, `"asset_id":` + fmt.Sprint(e.assetIn0)})
			rows = soJSONRows(t, raw, "data", "records")
			for _, id := range []uint{d.batchRecG.ID, d.batchRecI.ID} {
				assertMasked(t, soJSONRowBy(t, rows, "id", id), "credential_id", "credential_name", "target_version_id")
			}

			code, raw = get(recordsPath(d.inPlan))
			soAssertOK(t, code, raw, http.StatusOK, []string{"data", "total"})
			soAssertNoLeak(t, raw, both, []string{`"account_username":"zz-so-g"`, `"asset_id":` + fmt.Sprint(e.assetIn0)})
			rows = soJSONRows(t, raw, "data")
			for _, id := range []uint{d.recG.ID, d.recI.ID} {
				assertMasked(t, soJSONRowBy(t, rows, "id", id), "credential_id", "credential_name", "target_version_id")
			}
		}
	}
	t.Run("global_cs_only", notGranted(e.glbCsOnly))
	t.Run("mixed_global_entry", notGranted(e.csMixed))
	t.Run("view_nodes_gone", notGranted(e.csGone))
}

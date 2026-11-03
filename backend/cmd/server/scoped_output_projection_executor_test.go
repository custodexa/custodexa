package main

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/model"
)

// 代改專用帳號的識別（帳號、帳號名、憑證）只在檢視者的憑證檢視範圍涵蓋該專用帳號憑證時輸出，
// 與紀錄自身的憑證是否在範圍內無關；範圍外兩者都不輸出並帶 executor_out_of_scope。
func TestScopedChangeSecretExecutorProjection(t *testing.T) {
	e := newOutEnv(t, soWithChangeSecret())
	d := e.soBuildCS()
	router := func(uid uint) func(path string) (int, string) {
		rt := e.soChangeSecretRouter(uid)
		return func(path string) (int, string) { return soServe(rt, http.MethodGet, path, "") }
	}
	const outName, inName = "zz-so-exec-out", "zz-so-exec-in"
	mk := func(batchID, planID, assetID, accID uint, recCred uint, execCred uint, execName string, execAcc uint) model.ChangeSecretRecord {
		r := e.soRecord(batchID, planID, assetID, accID, "zz-so-g", recCred, "zz-so-in-cred", soVerI)
		require.NoError(t, e.db.Model(&model.ChangeSecretRecord{}).Where("id = ?", r.ID).Updates(map[string]any{
			"execution_method": model.ChangeSecretExecutionExecutorRoot, "executor_account_id": execAcc,
			"executor_username": execName, "executor_credential_id": execCred}).Error)
		return r
	}
	// 專用帳號憑證在範圍外、紀錄自身憑證在範圍內
	pOut := mk(0, d.inPlan.ID, e.assetIn1, e.accI, e.inCred, e.gcred, outName, 70001)
	bOut := mk(d.batchID, 0, e.assetIn1, e.accI, e.inCred, e.gcred, outName, 70001)
	// 專用帳號憑證在範圍內、紀錄自身憑證在範圍外
	pIn := mk(0, d.inPlan.ID, e.assetIn0, e.gcredAcc, e.gcred, e.inCred, inName, 70002)
	bIn := mk(d.batchID, 0, e.assetIn0, e.gcredAcc, e.gcred, e.inCred, inName, 70002)
	// 專用帳號憑證在範圍內，且它只以專用帳號的身分出現在這批紀錄裡（沒有任何列以它當自身憑證）
	pOnly := mk(0, d.inPlan.ID, e.assetIn1, e.accI, e.inCred, e.histNext, "zz-so-exec-only", 70003)
	// 缺憑證識別卻帶帳號名的列：不信任，視為範圍外
	pHalf := mk(0, d.inPlan.ID, e.assetIn1, e.accI, e.inCred, 0, outName, 70001)

	planPath := fmt.Sprintf("/api/v1/change-secret-plans/%d/records", d.inPlan.ID)
	batchPath := fmt.Sprintf("/api/v1/change-secret-batches/%d", d.batchID)
	execKeys := []string{"executor_account_id", "executor_username", "executor_credential_id"}
	assertHidden := func(t *testing.T, row map[string]any) {
		t.Helper()
		require.Contains(t, row, "execution_method", "ASSERT: 紀錄回應帶執行方式欄")
		require.Equal(t, true, row["executor_out_of_scope"], "ASSERT: 範圍外專用帳號的列應帶 executor_out_of_scope:true: %v", row)
		for _, k := range execKeys {
			require.NotContains(t, row, k, "ASSERT: 範圍外專用帳號的列不應含 %s", k)
		}
	}
	assertShown := func(t *testing.T, row map[string]any, name string, cred uint) {
		t.Helper()
		require.Contains(t, row, "execution_method", "ASSERT: 紀錄回應帶執行方式欄")
		require.NotContains(t, row, "executor_out_of_scope")
		require.Equal(t, name, row["executor_username"])
		require.EqualValues(t, cred, row["executor_credential_id"])
	}

	t.Run("scoped_viewer", func(t *testing.T) {
		for _, c := range []struct {
			path string
			rows func(raw string) []map[string]any
			out  uint
			in   uint
		}{
			{planPath, func(raw string) []map[string]any { return soJSONRows(t, raw, "data") }, pOut.ID, pIn.ID},
			{batchPath, func(raw string) []map[string]any { return soJSONRows(t, raw, "data", "records") }, bOut.ID, bIn.ID},
		} {
			code, raw := router(e.mgr)(c.path)
			soAssertOK(t, code, raw, http.StatusOK, []string{"data"})
			soAssertNoLeak(t, raw, []soToken{soName(outName), soNum("executor_credential_id", e.gcred)},
				[]string{`"executor_username":"` + inName + `"`})
			rows := c.rows(raw)
			assertHidden(t, soJSONRowBy(t, rows, "id", c.out))
			assertShown(t, soJSONRowBy(t, rows, "id", c.in), inName, e.inCred)
		}
		_, raw := router(e.mgr)(planPath)
		assertHidden(t, soJSONRowBy(t, soJSONRows(t, raw, "data"), "id", pHalf.ID))
		assertShown(t, soJSONRowBy(t, soJSONRows(t, raw, "data"), "id", pOnly.ID), "zz-so-exec-only", e.histNext)
		// 紀錄自身憑證在範圍內的列，自身欄位照舊輸出；專用帳號被遮不影響
		out := soJSONRowBy(t, soJSONRows(t, raw, "data"), "id", pOut.ID)
		require.NotContains(t, out, "credential_out_of_scope")
		require.EqualValues(t, e.inCred, out["credential_id"])
	})

	t.Run("global_viewer_sees_all", func(t *testing.T) {
		code, raw := router(e.glb)(planPath)
		soAssertOK(t, code, raw, http.StatusOK, []string{"data", "total"})
		rows := soJSONRows(t, raw, "data")
		assertShown(t, soJSONRowBy(t, rows, "id", pOut.ID), outName, e.gcred)
		assertShown(t, soJSONRowBy(t, rows, "id", pIn.ID), inName, e.inCred)
	})
}

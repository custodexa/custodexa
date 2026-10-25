package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
)

// soAccountService 與路由組裝相同的帳號服務，供取回同一時刻的完整 DTO 做逐位元比對。
func (e *outEnv) soAccountService() *asset.AssetAccountService {
	return asset.NewAssetAccountService(e.assets, e.codec, audit.NewTxSink()).
		WithManagementAuthorizer(e.adapter).WithSystemAlertSink(noopAlertSink{}).
		WithAccountWriteScope(authz.NewAssetWriteScope(e.eval))
}

// soTopKeys 物件頂層鍵（排序）。
func soTopKeys(t *testing.T, raw string) []string {
	t.Helper()
	out := make([]string, 0)
	for k := range soDecode(t, raw) {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// soSlimKeys 精簡版帳號 DTO 的鍵集。
func soSlimKeys(t *testing.T) []string {
	t.Helper()
	b, err := json.Marshal(asset.AssetAccountSlimDTO{})
	require.NoError(t, err)
	return soTopKeys(t, string(b))
}

func TestScopedAccountWriteProjection(t *testing.T) {
	e := newOutEnv(t, soWithAccounts())
	accPath := func(assetID, accID uint) string {
		return fmt.Sprintf("/api/v1/assets/%d/accounts/%d", assetID, accID)
	}
	updateBody := `{"note":"zz-so-note"}`

	// 全域憑證出站字串：名稱、識別鍵、掛載數鍵
	gForbidden := []soToken{soName("zz-so-out-gcred"), soName(`"credential_id"`), soName(`"binding_count"`)}
	bForbidden := []soToken{soName("zz-so-out-bindsrc"), soName(`"credential_id"`), soName(`"binding_count"`)}
	soCheckFixture(t, append(append([]soToken{}, gForbidden...), bForbidden...),
		[]soToken{soName("zz-so-g"), soName("zz-so-bind-user"), soName("zz-so-r-user"), soName("zz-so-note")})

	t.Run("update", func(t *testing.T) {
		code, raw := soServe(e.soAccountRouter(e.mgr), http.MethodPut, accPath(e.assetU, e.gcredAcc), updateBody)
		soAssertOK(t, code, raw, http.StatusOK, []string{"id", "username"})
		soAssertNoLeak(t, raw, gForbidden, []string{`"credential_out_of_scope":true`, `"username":"zz-so-g"`})
	})

	t.Run("set_default", func(t *testing.T) {
		code, raw := soServe(e.soAccountRouter(e.mgr), http.MethodPost, accPath(e.assetU, e.gcredAcc)+"/set-default", "")
		soAssertOK(t, code, raw, http.StatusOK, []string{"id", "username"})
		soAssertNoLeak(t, raw, gForbidden, []string{`"credential_out_of_scope":true`, `"username":"zz-so-g"`})
	})

	slim := func(t *testing.T, raw string) {
		t.Helper()
		if got, want := soTopKeys(t, raw), soSlimKeys(t); fmt.Sprint(got) != fmt.Sprint(want) {
			t.Fatalf("LEAK: 鍵集應恰為精簡版帳號 DTO %v，實際 %v\n本文: %s", want, got, raw)
		}
	}

	t.Run("create", func(t *testing.T) {
		code, raw := soServe(e.soAccountRouter(e.bindOnly), http.MethodPost,
			fmt.Sprintf("/api/v1/assets/%d/accounts", e.assetC), fmt.Sprintf(`{"credential_id":%d}`, e.bindSrc))
		soAssertOK(t, code, raw, http.StatusCreated, []string{"id", "username"})
		soAssertNoLeak(t, raw, bForbidden, []string{`"username":"zz-so-bind-user"`})
		slim(t, raw)
	})

	t.Run("bind", func(t *testing.T) {
		code, raw := soServe(e.soAccountRouter(e.bindOnly), http.MethodPost,
			fmt.Sprintf("/api/v1/credentials/%d/bindings", e.bindSrc), fmt.Sprintf(`{"asset_id":%d}`, e.assetB))
		soAssertOK(t, code, raw, http.StatusCreated, []string{"id", "username"})
		soAssertNoLeak(t, raw, bForbidden, []string{`"username":"zz-so-bind-user"`})
		slim(t, raw)
	})

	t.Run("rebind", func(t *testing.T) {
		code, raw := soServe(e.soAccountRouter(e.bindOnly), http.MethodPut,
			accPath(e.assetR, e.accR)+"/credential", fmt.Sprintf(`{"credential_id":%d}`, e.bindSrc))
		soAssertOK(t, code, raw, http.StatusOK, []string{"id", "username"})
		soAssertNoLeak(t, raw, bForbidden, []string{`"username":"zz-so-bind-user"`})
		slim(t, raw)
	})

	// 與服務層同一時刻的完整 DTO 逐位元相同
	sameAsService := func(t *testing.T, raw string) {
		t.Helper()
		dto, err := e.soAccountService().Get(e.assetU, e.gcredAcc)
		require.NoError(t, err)
		want, err := json.Marshal(dto)
		require.NoError(t, err)
		if raw != string(want) {
			t.Fatalf("PRECONDITION: 回應與服務層完整 DTO 不同\n回應: %s\n服務層: %s", raw, want)
		}
	}

	t.Run("global_unchanged", func(t *testing.T) {
		code, raw := soServe(e.soAccountRouter(e.glb), http.MethodPut, accPath(e.assetU, e.gcredAcc), `{"note":"zz-so-note-glb"}`)
		soAssertOK(t, code, raw, http.StatusOK, []string{"id", "credential_name"})
		soAssertNoLeak(t, raw, nil, []string{`"credential_name":"zz-so-out-gcred"`, `"credential_id"`, `"binding_count"`})
		sameAsService(t, raw)
	})

	t.Run("global_no_view", func(t *testing.T) {
		code, raw := soServe(e.soAccountRouter(e.glbNoView), http.MethodPut, accPath(e.assetU, e.gcredAcc), `{"note":"zz-so-note-nv"}`)
		soAssertOK(t, code, raw, http.StatusOK, []string{"id", "username"})
		soAssertNoLeak(t, raw, gForbidden, []string{`"username":"zz-so-g"`})
		slim(t, raw)
	})

	t.Run("global_compat", func(t *testing.T) {
		code, raw := soServe(e.soAccountRouter(e.glbCompat), http.MethodPut, accPath(e.assetU, e.gcredAcc), `{"note":"zz-so-note-cp"}`)
		soAssertOK(t, code, raw, http.StatusOK, []string{"id", "credential_name"})
		soAssertNoLeak(t, raw, nil, []string{`"credential_name":"zz-so-out-gcred"`})
		sameAsService(t, raw)
	})
}

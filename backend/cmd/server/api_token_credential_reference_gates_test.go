package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
)

// 以 API token 引用既有憑證的各層關卡分別驗證（同一組服務、正式的判定器與交易內重驗）：
//   - 缺掛載能力：外層（路由的欄位條件、接入層的欄位閘）先放行，請求真的到達服務層的掛載判定才被拒；
//     五個入口逐一驗證，token 與只持那些角色的本人同樣被拒、不寫入。
//   - 憑證在範圍內，但既有資產或目的節點在範圍外：五個入口經正式的路由與接入層，token 與本人結果相同且被拒。

// newRefGateEnv 建在 sqlite 上的同一組服務（掛載告警以不落地的替身承接；本檔只驗拒絕）。
func newRefGateEnv(t *testing.T) *pgRefEnv {
	t.Helper()
	e := &pgRefEnv{scEnv: newSCEnv(t)}
	e.accounts = asset.NewAssetAccountService(e.assets, e.codec, audit.NewTxSink()).WithAuthorization(e.authzSvc).
		WithManagementAuthorizer(e.adapter).WithSystemAlertSink(noopAlertSink{}).WithAccountWriteScope(authz.NewAssetWriteScope(e.eval))
	e.assets.WithSystemAlertSink(noopAlertSink{})
	e.creds.WithSystemAlertSink(noopAlertSink{})
	e.node("n1", "")
	e.node("n2", "")
	return e
}

// serviceCtx 與接入層組出的服務 context 相同（操作者、主體、請求憑證種類），唯欄位閘以替身一律放行：
// 用來證明在欄位閘之後，服務層自己的掛載判定仍會拒絕。
func (e *pgRefEnv) serviceCtx(s pgRefSubject) context.Context {
	e.t.Helper()
	p, err := authz.ResolveUserOnWithCatalogue(e.db, e.cat, s.userID, authz.TokenFacts{RoleFilter: s.filter})
	require.NoError(e.t, err)
	ctx := context.Background()
	if s.filter != nil {
		ctx = model.WithRequestCredential(ctx, model.RequestCredentialAPIToken)
		ctx = model.WithAPITokenRef(ctx, model.APITokenRef{ID: s.tokenID, Name: fmt.Sprintf("gate-token-%d", s.tokenID)})
	} else {
		ctx = model.WithRequestCredential(ctx, model.RequestCredentialHumanSession)
	}
	ctx = context.WithValue(ctx, "userID", s.userID)                       //nolint:staticcheck // 沿用審計 context 慣例
	ctx = context.WithValue(ctx, "username", fmt.Sprintf("u%d", s.userID)) //nolint:staticcheck
	ctx = authz.ContextWithPrincipal(ctx, p)
	return asset.WithFieldCapability(ctx, func(string) asset.FieldCapGrant { return asset.FieldCapViaPerm })
}

// refGateOutcome 一次呼叫的結果形狀。
type refGateOutcome struct {
	Rejected      bool
	AssetsDelta   int64
	AccountsDelta int64
	Bound         bool
}

func refGateDecode(t *testing.T, v any, out any) {
	t.Helper()
	raw, err := json.Marshal(v)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(raw, out))
}

// TestAPITokenCredentialReferenceServiceGate 缺掛載能力的請求越過外層後，由服務層的掛載判定拒絕（五個入口）。
func TestAPITokenCredentialReferenceServiceGate(t *testing.T) {
	e := newRefGateEnv(t)
	// 不含掛載能力、但含憑證建立（越過掛載與更換的路由條件）的角色；所屬帳號另以全域持有掛載能力（token 不得借用）
	noBind := e.role(append(append([]authz.Permission{}, saPerms...), authz.PermCredentialView, authz.PermCredentialCreate)...)
	owner, twin := e.user("gate-owner"), e.user("gate-twin")
	e.grantGlobal(owner, noBind)
	e.grantGlobal(owner, e.role(authz.PermCredentialBind, authz.PermCredentialView))
	e.grantGlobal(twin, noBind)
	subjects := map[string]pgRefSubject{
		"token": {userID: owner, filter: authz.NewRoleFilter([]uint{noBind}), tokenID: owner},
		"本人":    {userID: twin},
	}
	n1 := e.nodes["n1"]

	type entry struct {
		name string
		do   func(s pgRefSubject, x pgRefTargets) error
	}
	entries := []entry{
		{"建立資產", func(s pgRefSubject, x pgRefTargets) error {
			var req asset.CreateAssetRequest
			refGateDecode(t, map[string]any{"name": "gate-new-" + x.suffix, "protocol": "ssh", "host": "198.51.100.90", "port": 22,
				"credential_id": x.credGlobal, "node_ids": []uint{n1}}, &req)
			req.CreatedBy, req.CreatedByName = s.userID, fmt.Sprintf("u%d", s.userID)
			_, err := e.assets.Create(e.serviceCtx(s), &req)
			return err
		}},
		{"匯入預覽", func(s pgRefSubject, x pgRefTargets) error {
			var batch asset.ImportBatch
			refGateDecode(t, map[string]any{"Source": "form", "Rows": pgRefImport(x, x.credGlobal, n1)["rows"]}, &batch)
			p, err := e.assets.PreviewImport(e.serviceCtx(s), &batch)
			if err == nil && p != nil && !p.OK {
				return fmt.Errorf("預覽以列錯誤回報")
			}
			return err
		}},
		{"匯入提交", func(s pgRefSubject, x pgRefTargets) error {
			var batch asset.ImportBatch
			refGateDecode(t, map[string]any{"Source": "form", "Rows": pgRefImport(x, x.credGlobal, n1)["rows"]}, &batch)
			_, err := e.assets.ImportAssets(e.serviceCtx(s), &batch, s.userID, fmt.Sprintf("u%d", s.userID))
			return err
		}},
		{"建立資產帳號", func(s pgRefSubject, x pgRefTargets) error {
			var req asset.CreateAssetAccountRequest
			refGateDecode(t, map[string]any{"credential_id": x.credGlobal}, &req)
			_, err := e.accounts.Create(e.serviceCtx(s), x.asset, &req)
			return err
		}},
		{"掛載", func(s pgRefSubject, x pgRefTargets) error {
			_, err := e.creds.Bind(e.serviceCtx(s), x.credGlobal, &asset.BindCredentialRequest{AssetID: x.asset})
			return err
		}},
		{"更換憑證", func(s pgRefSubject, x pgRefTargets) error {
			_, err := e.creds.Rebind(e.serviceCtx(s), x.asset, x.account, x.credGlobal)
			return err
		}},
	}
	for _, en := range entries {
		en := en
		t.Run(en.name, func(t *testing.T) {
			got := map[string]refGateOutcome{}
			for label, s := range subjects {
				x := e.targets()
				assets, accounts := e.count("assets", "deleted_at IS NULL"), e.count("asset_accounts", "deleted_at IS NULL")
				err := en.do(s, x)
				got[label] = refGateOutcome{Rejected: err != nil,
					AssetsDelta:   e.count("assets", "deleted_at IS NULL") - assets,
					AccountsDelta: e.count("asset_accounts", "deleted_at IS NULL") - accounts,
					Bound:         e.count("asset_accounts", "credential_id = ? AND deleted_at IS NULL", x.credGlobal) > 0}
			}
			require.Equal(t, got["本人"], got["token"], "token 與只持有授權角色的本人結果應相同")
			require.Equal(t, refGateOutcome{Rejected: true}, got["token"], "欄位閘放行後，缺掛載能力仍應由服務層拒絕且不寫入")
		})
	}
}

// TestAPITokenCredentialReferenceAssetOutOfScope 憑證在節點範圍內，既有資產或目的節點在範圍外：五個入口皆拒絕且不寫入，
// token 與本人結果相同（經正式的路由與接入層）。
func TestAPITokenCredentialReferenceAssetOutOfScope(t *testing.T) {
	e := newRefGateEnv(t)
	full := append(append([]authz.Permission{}, saPerms...), authz.PermCredentialView, authz.PermCredentialCreate, authz.PermCredentialBind)
	nodeRole := e.role(full...)
	owner, twin := e.user("oos-owner"), e.user("oos-twin")
	e.grantNodes(owner, nodeRole, "n1")
	e.grantNodes(twin, nodeRole, "n1")
	tok := pgRefSubject{userID: owner, filter: authz.NewRoleFilter([]uint{nodeRole}), tokenID: owner}
	hum := pgRefSubject{userID: twin}
	n2 := e.nodes["n2"]

	// 目標在節點 2：資產與其專用掛載；引用的憑證歸屬節點 1（範圍內）
	type target struct {
		asset, account, cred uint
		suffix               string
	}
	mk := func() target {
		x := e.targets()
		a := e.asset("oos-host-"+x.suffix, "n2")
		ded := e.dedicated(a)
		var acc model.AssetAccount
		require.NoError(t, e.db.Where("credential_id = ?", ded).First(&acc).Error)
		return target{asset: a, account: acc.ID, cred: x.credNode1, suffix: x.suffix}
	}
	imp := func(x target) map[string]any {
		return map[string]any{"source": "form", "rows": []map[string]any{
			{"name": "oos-imp-" + x.suffix, "protocol": "ssh", "host": "203.0.113.90", "port": 22, "credential_id": x.cred, "node_ids": []uint{n2}},
		}}
	}
	entries := []struct {
		name string
		do   func(s pgRefSubject, x target) (int, map[string]any)
	}{
		{"建立資產（目的節點在範圍外）", func(s pgRefSubject, x target) (int, map[string]any) {
			return e.call(s, http.MethodPost, "/api/v1/assets", map[string]any{"name": "oos-new-" + x.suffix, "protocol": "ssh",
				"host": "198.51.100.91", "port": 22, "credential_id": x.cred, "node_ids": []uint{n2}})
		}},
		{"匯入預覽（目的節點在範圍外）", func(s pgRefSubject, x target) (int, map[string]any) {
			return e.call(s, http.MethodPost, "/api/v1/assets/import/preview", imp(x))
		}},
		{"匯入提交（目的節點在範圍外）", func(s pgRefSubject, x target) (int, map[string]any) {
			return e.call(s, http.MethodPost, "/api/v1/assets/import", imp(x))
		}},
		{"建立資產帳號（既有資產在範圍外）", func(s pgRefSubject, x target) (int, map[string]any) {
			return e.call(s, http.MethodPost, fmt.Sprintf("/api/v1/assets/%d/accounts", x.asset), map[string]any{"credential_id": x.cred})
		}},
		{"掛載（既有資產在範圍外）", func(s pgRefSubject, x target) (int, map[string]any) {
			return e.call(s, http.MethodPost, fmt.Sprintf("/api/v1/credentials/%d/bindings", x.cred), map[string]any{"asset_id": x.asset})
		}},
		{"更換憑證（既有資產在範圍外）", func(s pgRefSubject, x target) (int, map[string]any) {
			return e.call(s, http.MethodPut, fmt.Sprintf("/api/v1/assets/%d/accounts/%d/credential", x.asset, x.account),
				map[string]any{"credential_id": x.cred})
		}},
	}
	for _, en := range entries {
		en := en
		t.Run(en.name, func(t *testing.T) {
			run := func(s pgRefSubject) pgRefOutcome {
				x := mk()
				assets, accounts := e.count("assets", "deleted_at IS NULL"), e.count("asset_accounts", "deleted_at IS NULL")
				code, body := en.do(s, x)
				out := pgRefOutcome{Status: code, ImportOK: body["ok"],
					AssetsDelta:   e.count("assets", "deleted_at IS NULL") - assets,
					AccountsDelta: e.count("asset_accounts", "deleted_at IS NULL") - accounts,
					Bound:         e.count("asset_accounts", "credential_id = ? AND deleted_at IS NULL", x.cred) > 0}
				out.Code, _ = body["code"].(string)
				return out
			}
			tokOut, humOut := run(tok), run(hum)
			t.Logf("token：%+v", tokOut)
			require.Equal(t, humOut, tokOut, "token 與只持有授權角色的本人結果應相同")
			rejected := !is2xx(tokOut.Status) || tokOut.ImportOK == false
			require.True(t, rejected, "範圍外的資產或節點應被拒：%+v", tokOut)
			require.Zero(t, tokOut.AssetsDelta+tokOut.AccountsDelta, "被拒不寫入")
			require.False(t, tokOut.Bound, "被拒不掛載")
		})
	}
	// 建立資產帳號在接入層先以資產可視判定回資產不存在；另以服務直接呼叫（外層放行）驗服務層的資產側判定
	t.Run("建立資產帳號（服務層，既有資產在範圍外）", func(t *testing.T) {
		got := map[string]refGateOutcome{}
		for label, s := range map[string]pgRefSubject{"token": tok, "本人": hum} {
			x := mk()
			accounts := e.count("asset_accounts", "deleted_at IS NULL")
			var req asset.CreateAssetAccountRequest
			refGateDecode(t, map[string]any{"credential_id": x.cred}, &req)
			_, err := e.accounts.Create(e.serviceCtx(s), x.asset, &req)
			got[label] = refGateOutcome{Rejected: err != nil, AccountsDelta: e.count("asset_accounts", "deleted_at IS NULL") - accounts,
				Bound: e.count("asset_accounts", "credential_id = ? AND deleted_at IS NULL", x.cred) > 0}
		}
		require.Equal(t, got["本人"], got["token"], "token 與只持有授權角色的本人結果應相同")
		require.Equal(t, refGateOutcome{Rejected: true}, got["token"], "既有資產在範圍外應由服務層拒絕且不寫入")
	})
}

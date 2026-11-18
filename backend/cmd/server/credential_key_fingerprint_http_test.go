package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/api"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/keyvault"
	"github.com/custodexa/backend/pkg/crypto"
)

// 公鑰指紋的揭露範圍（HTTP 層，正式授權判定）：回傳憑證或帳號內容的每一個寫入端點，
// 有修改能力而沒有檢視範圍的主體拿不到指紋；檢視與修改皆具者拿得到。另含堡壘機專用帳號的交叉矩陣。

const fpKeyName = `"private_key_fingerprint"`

// fpKeyVersion 為憑證寫一筆帶私鑰與公鑰的現行版本，並把該憑證全部掛載就位到它；回指紋與私鑰。
// 私鑰於測試當下產生。
func fpKeyVersion(t *testing.T, db *gorm.DB, codec crypto.ColumnCodec, credID uint) (fp, private string) {
	t.Helper()
	private, line, err := asset.GenerateSSHKeyPair("fp-http")
	require.NoError(t, err)
	enc, err := codec.EncryptFor(context.Background(), keyvault.RefCredentialVersionPrivateKey, private)
	require.NoError(t, err)
	fields := strings.Fields(line)
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
	require.NoError(t, err)
	var maxNo int
	require.NoError(t, db.Model(&model.CredentialSecretVersion{}).Where("credential_id = ?", credID).
		Select("COALESCE(MAX(version_no), 0)").Scan(&maxNo).Error)
	v := model.CredentialSecretVersion{CredentialID: credID, VersionNo: maxNo + 1, SecretType: model.ChangeSecretTypeSSHKey,
		PrivateKeyEnc: enc, PublicKey: fields[0] + " " + fields[1], CreatedReason: model.CredentialVersionReasonManual}
	require.NoError(t, db.Create(&v).Error)
	require.NoError(t, db.Model(&model.Credential{}).Where("id = ?", credID).
		Updates(map[string]any{"current_version_id": v.ID, "secret_type": model.ChangeSecretTypeSSHKey}).Error)
	require.NoError(t, db.Model(&model.AssetAccount{}).Where("credential_id = ?", credID).
		Update("effective_version_id", v.ID).Error)
	return ssh.FingerprintSHA256(pub), private
}

func fpAssertAbsent(t *testing.T, code int, raw string, wantCode int) {
	t.Helper()
	require.Equal(t, wantCode, code, "PRECONDITION: 寫入應成功\n本文: %s", raw)
	assert.NotContains(t, raw, fpKeyName, "LEAK: 沒有檢視範圍卻拿到指紋\n本文: %s", raw)
	assert.NotContains(t, raw, "SHA256:", "LEAK: 回應含指紋值\n本文: %s", raw)
}

func fpAssertPresent(t *testing.T, code int, raw string, wantCode int, fp string) {
	t.Helper()
	require.Equal(t, wantCode, code, "PRECONDITION: 寫入應成功\n本文: %s", raw)
	assert.Contains(t, raw, fmt.Sprintf(`%s:%q`, fpKeyName, fp), "檢視與修改皆具：回應帶指紋\n本文: %s", raw)
}

// 憑證的寫入端點：建立、修改中繼資料、更正秘密、範圍轉換
func TestCredentialFingerprintHTTPWriteResponses(t *testing.T) {
	e := newOutEnv(t)
	credPath := func(id uint) string { return fmt.Sprintf("/api/v1/credentials/%d", id) }

	// 全域：具修改、更正秘密、範圍轉換與建立，沒有檢視
	noView := e.user("zz-fp-noview")
	e.grantGlobal(noView, e.role(authz.PermAssetView, authz.PermCredentialCreate, authz.PermCredentialUpdate,
		authz.PermCredentialSetSecret, authz.PermCredentialConvertScope))
	// 範圍化：檢視範圍只有節點 in，修改能力涵蓋節點 out
	split := e.user("zz-fp-split")
	e.grant(split, []string{soNodeIn}, authz.PermAssetView, authz.PermCredentialView)
	e.grant(split, []string{soNodeOut}, authz.PermAssetView, authz.PermCredentialCreate, authz.PermCredentialUpdate,
		authz.PermCredentialSetSecret, authz.PermCredentialConvertScope)

	newKeyCred := func(name string, node *uint) (uint, string) {
		id := e.soCred(name, "zz-fp-user-"+name, node)
		a := e.asset("zz-fp-asset-"+name, soNodeOut)
		e.mount(id, a)
		fp, _ := fpKeyVersion(t, e.db, e.codec, id)
		return id, fp
	}
	outCred, outFP := newKeyCred("zz-fp-outcred", e.nodeID(soNodeOut))

	t.Run("precondition_split_cannot_view", func(t *testing.T) {
		code, raw := e.call(split, http.MethodGet, credPath(outCred), "")
		require.Equal(t, http.StatusNotFound, code, "PRECONDITION: 範圍化主體看不到這筆憑證\n本文: %s", raw)
		code, raw = e.call(noView, http.MethodGet, credPath(outCred), "")
		require.NotEqual(t, http.StatusOK, code, "PRECONDITION: 沒有檢視能力者讀不到詳情\n本文: %s", raw)
	})

	t.Run("read_list_and_detail", func(t *testing.T) {
		code, raw := e.call(e.glb, http.MethodGet, credPath(outCred), "")
		fpAssertPresent(t, code, raw, http.StatusOK, outFP)
		code, raw = e.call(e.glb, http.MethodGet, "/api/v1/credentials", "")
		fpAssertPresent(t, code, raw, http.StatusOK, outFP)
	})

	for _, who := range []struct {
		name string
		uid  uint
	}{{"global_no_view", noView}, {"view_in_update_out", split}} {
		t.Run("update/"+who.name, func(t *testing.T) {
			code, raw := e.call(who.uid, http.MethodPut, credPath(outCred), `{"note":"zz-fp-note"}`)
			fpAssertAbsent(t, code, raw, http.StatusOK)
		})
		t.Run("set_secret/"+who.name, func(t *testing.T) {
			code, raw := e.call(who.uid, http.MethodPost, credPath(outCred)+"/secret", `{"password":"zz-fp-pw-1"}`)
			fpAssertAbsent(t, code, raw, http.StatusOK)
		})
	}
	t.Run("update/view_and_update", func(t *testing.T) {
		code, raw := e.call(e.glb, http.MethodPut, credPath(outCred), `{"note":"zz-fp-note-glb"}`)
		fpAssertPresent(t, code, raw, http.StatusOK, outFP)
	})
	t.Run("set_secret/view_and_update", func(t *testing.T) {
		code, raw := e.call(e.glb, http.MethodPost, credPath(outCred)+"/secret", `{"password":"zz-fp-pw-2"}`)
		fpAssertPresent(t, code, raw, http.StatusOK, outFP)
	})

	t.Run("convert_scope", func(t *testing.T) {
		c1, _ := newKeyCred("zz-fp-conv1", e.nodeID(soNodeOut))
		code, raw := e.call(split, http.MethodPost, credPath(c1)+"/scope", `{"scope":"dedicated"}`)
		fpAssertAbsent(t, code, raw, http.StatusOK)
		c2, _ := newKeyCred("zz-fp-conv2", nil)
		code, raw = e.call(noView, http.MethodPost, credPath(c2)+"/scope", `{"scope":"dedicated"}`)
		fpAssertAbsent(t, code, raw, http.StatusOK)
		c3, fp3 := newKeyCred("zz-fp-conv3", nil)
		code, raw = e.call(e.glb, http.MethodPost, credPath(c3)+"/scope", `{"scope":"dedicated"}`)
		fpAssertPresent(t, code, raw, http.StatusOK, fp3)
	})

	t.Run("create", func(t *testing.T) {
		private, _, err := asset.GenerateSSHKeyPair("fp-create")
		require.NoError(t, err)
		body := func(name string, owner string) string {
			b, err := json.Marshal(map[string]any{"name": name, "username": "zz-fp-cu", "protocol_family": "ssh",
				"private_key": private, "ownership": json.RawMessage(owner)})
			require.NoError(t, err)
			return string(b)
		}
		create := func(uid uint, b string) (int, string) {
			r := gin.New()
			r.Use(e.scPrincipal(uid))
			h := api.NewCredentialHandler(e.creds, scRotations{}, scStatus{})
			r.POST("/api/v1/credentials", middleware.EnforceRegistry(), h.Create)
			return soServe(r, http.MethodPost, "/api/v1/credentials", b)
		}
		code, raw := create(noView, body("zz-fp-create-nv", `{"kind":"global"}`))
		fpAssertAbsent(t, code, raw, http.StatusCreated)
		code, raw = create(split,
			body("zz-fp-create-split", fmt.Sprintf(`{"kind":"node","node_id":%d}`, *e.nodeID(soNodeOut))))
		fpAssertAbsent(t, code, raw, http.StatusCreated)
		signer, err := ssh.ParsePrivateKey([]byte(private))
		require.NoError(t, err)
		code, raw = create(e.glb, body("zz-fp-create-glb", `{"kind":"global"}`))
		fpAssertPresent(t, code, raw, http.StatusCreated, ssh.FingerprintSHA256(signer.PublicKey()))
	})
}

// 帳號列的寫入端點：建立、修改、設預設、掛載、改綁（同一個投影器）
func TestAccountFingerprintHTTPWriteResponses(t *testing.T) {
	e := newOutEnv(t, soWithAccounts())
	accPath := func(assetID, accID uint) string {
		return fmt.Sprintf("/api/v1/assets/%d/accounts/%d", assetID, accID)
	}
	// 全域憑證（對範圍化管理者 mgr 而言在範圍外）換成私鑰版本
	gFP, _ := fpKeyVersion(t, e.db, e.codec, e.gcred)
	// 節點 in 的可掛載來源也換成私鑰版本（bindOnly 只有掛載能力、沒有檢視）
	bFP, _ := fpKeyVersion(t, e.db, e.codec, e.bindSrc)
	require.NotEqual(t, gFP, bFP)

	t.Run("update", func(t *testing.T) {
		code, raw := soServe(e.soAccountRouter(e.mgr), http.MethodPut, accPath(e.assetU, e.gcredAcc), `{"note":"zz-fp-a"}`)
		fpAssertAbsent(t, code, raw, http.StatusOK)
		require.Contains(t, raw, `"credential_out_of_scope":true`, "PRECONDITION: 範圍外收窄的形狀")
		code, raw = soServe(e.soAccountRouter(e.glbNoView), http.MethodPut, accPath(e.assetU, e.gcredAcc), `{"note":"zz-fp-b"}`)
		fpAssertAbsent(t, code, raw, http.StatusOK)
		code, raw = soServe(e.soAccountRouter(e.glb), http.MethodPut, accPath(e.assetU, e.gcredAcc), `{"note":"zz-fp-c"}`)
		fpAssertPresent(t, code, raw, http.StatusOK, gFP)
	})
	t.Run("set_default", func(t *testing.T) {
		for _, uid := range []uint{e.mgr, e.glbNoView} {
			code, raw := soServe(e.soAccountRouter(uid), http.MethodPost, accPath(e.assetU, e.gcredAcc)+"/set-default", "")
			fpAssertAbsent(t, code, raw, http.StatusOK)
		}
		code, raw := soServe(e.soAccountRouter(e.glb), http.MethodPost, accPath(e.assetU, e.gcredAcc)+"/set-default", "")
		fpAssertPresent(t, code, raw, http.StatusOK, gFP)
	})
	t.Run("create_bind_rebind_without_view", func(t *testing.T) {
		code, raw := soServe(e.soAccountRouter(e.bindOnly), http.MethodPost,
			fmt.Sprintf("/api/v1/assets/%d/accounts", e.assetC), fmt.Sprintf(`{"credential_id":%d}`, e.bindSrc))
		fpAssertAbsent(t, code, raw, http.StatusCreated)
		code, raw = soServe(e.soAccountRouter(e.bindOnly), http.MethodPost,
			fmt.Sprintf("/api/v1/credentials/%d/bindings", e.bindSrc), fmt.Sprintf(`{"asset_id":%d}`, e.assetB))
		fpAssertAbsent(t, code, raw, http.StatusCreated)
		code, raw = soServe(e.soAccountRouter(e.bindOnly), http.MethodPut,
			accPath(e.assetR, e.accR)+"/credential", fmt.Sprintf(`{"credential_id":%d}`, e.bindSrc))
		fpAssertAbsent(t, code, raw, http.StatusOK)
	})
	t.Run("bind_with_view", func(t *testing.T) {
		a := e.asset("zz-fp-bind-glb", soNodeIn)
		code, raw := soServe(e.soAccountRouter(e.glb), http.MethodPost,
			fmt.Sprintf("/api/v1/credentials/%d/bindings", e.bindSrc), fmt.Sprintf(`{"asset_id":%d}`, a))
		fpAssertPresent(t, code, raw, http.StatusCreated, bFP)
	})
	t.Run("create_with_view", func(t *testing.T) {
		a := e.asset("zz-fp-create-glb", soNodeIn)
		code, raw := soServe(e.soAccountRouter(e.glb), http.MethodPost,
			fmt.Sprintf("/api/v1/assets/%d/accounts", a), fmt.Sprintf(`{"credential_id":%d}`, e.bindSrc))
		fpAssertPresent(t, code, raw, http.StatusCreated, bFP)
	})
}

// 堡壘機專用帳號：頂層指紋與公鑰匯出沿用它自己的規則，巢狀帳號列依帳號列的揭露規則
func TestExecutorFingerprintMatrix(t *testing.T) {
	env := newSAEnv(t)
	cat, err := authz.CatalogueWithScopedEnforcedForTest(append(saPerms, authz.PermAssetExecutorManage)...)
	require.NoError(t, err)
	env.cat = cat
	env.eval = authz.NewScopeEvaluator(cat, asset.NewScopeTopologyReader())
	env.assets.SetAssetWriteScopePort(authz.NewAssetWriteScope(env.eval))
	env.node("zz-fp-ex-in", "")
	outNode := env.node("zz-fp-ex-out", "")
	inNode := env.nodes["zz-fp-ex-in"]

	setup := env.user("zz-fp-ex-setup")
	env.grantNodes(setup, env.role(authz.PermAssetView, authz.PermAssetExecutorManage, authz.PermCredentialView,
		authz.PermCredentialCreate, authz.PermCredentialBind), "zz-fp-ex-in")
	execOnly := env.user("zz-fp-ex-only")
	env.grantNodes(execOnly, env.role(authz.PermAssetView, authz.PermAssetExecutorManage), "zz-fp-ex-in")
	execCred := env.user("zz-fp-ex-cred")
	env.grantNodes(execCred, env.role(authz.PermAssetView, authz.PermAssetExecutorManage, authz.PermCredentialView), "zz-fp-ex-in")
	// 全域持有執行身分管理與憑證管理能力、沒有憑證檢視能力：帳號列是完整形狀，但看不到任何憑證的詳情
	execManage := env.user("zz-fp-ex-manage")
	env.grantGlobal(execManage, env.role(authz.PermAssetView, authz.PermAssetExecutorManage, authz.PermCredentialManage))

	type cell struct {
		assetID uint
		fp      string
	}
	cells := map[string]cell{}

	// 專用憑證：平台產生
	{
		a := env.asset("zz-fp-ex-gen", "zz-fp-ex-in")
		res := env.doExecutor(setup, "PUT", idPath(a)+"/executor", executorGenerateBody)
		require.Equal(t, http.StatusOK, res.code, res.body)
		res = env.doExecutor(setup, "GET", idPath(a)+"/executor", "")
		require.Equal(t, http.StatusOK, res.code, res.body)
		var m map[string]any
		require.NoError(t, json.Unmarshal([]byte(res.body), &m))
		fp, _ := m["fingerprint"].(string)
		require.NotEmpty(t, fp, "PRECONDITION: 產生的鑰有指紋: %s", res.body)
		cells["dedicated_generated"] = cell{a, fp}
	}
	// 專用憑證：直填私鑰
	{
		a := env.asset("zz-fp-ex-inline", "zz-fp-ex-in")
		private, line, err := asset.GenerateSSHKeyPair("fp-inline")
		require.NoError(t, err)
		pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
		require.NoError(t, err)
		body, err := json.Marshal(map[string]any{"source": "inline", "username": "cx-exec", "private_key": private, "expected_account_id": 0})
		require.NoError(t, err)
		res := env.doExecutor(setup, "PUT", idPath(a)+"/executor", string(body))
		require.Equal(t, http.StatusOK, res.code, res.body)
		cells["dedicated_inline"] = cell{a, ssh.FingerprintSHA256(pub)}
	}
	// 共用憑證：範圍內與範圍外（直接寫表建專用帳號列，同既有夾具）
	sharedOn := func(name string, owner uint) cell {
		a := env.asset("zz-fp-ex-"+name, "zz-fp-ex-in")
		kind := model.CredentialOwnerNode
		credName := "zz-fp-ex-cred-" + name
		c := model.Credential{Name: &credName, Scope: model.CredentialScopeShared, Username: "svc-" + name,
			SecretType: model.ChangeSecretTypeSSHKey, AuthMethod: "sql", ProtocolFamily: model.ProtocolFamilySSH,
			OwnerKind: &kind, OwnerNodeID: &owner}
		require.NoError(t, env.db.Create(&c).Error)
		acct := model.AssetAccount{AssetID: a, CredentialID: c.ID, Username: c.Username,
			Purpose: model.AccountPurposeExecutor, ExecutorSource: "shared", Privileged: true}
		require.NoError(t, env.db.Create(&acct).Error)
		fp, _ := fpKeyVersion(t, env.db, env.codec, c.ID)
		return cell{a, fp}
	}
	cells["shared_in_scope"] = sharedOn("sin", inNode)
	cells["shared_out_of_scope"] = sharedOn("sout", outNode)
	// 全域主體不是範圍化檢視者，資產可見性取自連線授權：每台給一筆
	for _, c := range cells {
		env.connGrant(execManage, c.assetID)
	}

	get := func(uid, assetID uint) (map[string]any, string) {
		res := env.doExecutor(uid, "GET", idPath(assetID)+"/executor", "")
		require.Equal(t, http.StatusOK, res.code, res.body)
		m := map[string]any{}
		require.NoError(t, json.Unmarshal([]byte(res.body), &m))
		return m, res.body
	}
	// 公鑰匯出只對專用憑證的格子打。共用憑證的匯出在交易內另開一條連線判定可見性，本測試的
	// 夾具只有一條連線，會在那裡互等，所以共用憑證的匯出格不在本矩陣驗證（不能算作已驗過）；
	// 本矩陣只驗共用憑證讀取回應的 fingerprint／has_public_key。匯出的揭露判定另由服務層測試涵蓋。
	export := func(uid, assetID uint, cname string) (int, bool) {
		if strings.HasPrefix(cname, "shared_") {
			return 0, false
		}
		return env.doExecutor(uid, "GET", idPath(assetID)+"/executor/public-key", "").code, true
	}
	nested := func(t *testing.T, m map[string]any, raw string) map[string]any {
		t.Helper()
		c, ok := m["credential"].(map[string]any)
		require.True(t, ok, "credential 欄存在: %s", raw)
		return c
	}

	// 期望：頂層指紋（含匯出）與巢狀帳號列的指紋
	type want struct {
		top, nestedFP bool
		nestedShape   string // slim | full | out_of_scope
	}
	matrix := map[string]map[string]want{
		"exec_only": {
			"dedicated_generated": {top: true, nestedShape: "slim"},
			"dedicated_inline":    {top: true, nestedShape: "slim"},
			"shared_in_scope":     {top: false, nestedShape: "slim"},
			"shared_out_of_scope": {top: false, nestedShape: "slim"},
		},
		"exec_and_credential_view": {
			"dedicated_generated": {top: true, nestedFP: true, nestedShape: "full"},
			"dedicated_inline":    {top: true, nestedFP: true, nestedShape: "full"},
			"shared_in_scope":     {top: true, nestedFP: true, nestedShape: "full"},
			"shared_out_of_scope": {top: false, nestedShape: "out_of_scope"},
		},
		// 專用憑證的頂層沿用執行身分管理者的規則；共用憑證與巢狀帳號列的指紋都要憑證檢視能力
		"exec_and_global_manage_without_view": {
			"dedicated_generated": {top: true, nestedShape: "full"},
			"dedicated_inline":    {top: true, nestedShape: "full"},
			"shared_in_scope":     {top: false, nestedShape: "full"},
			"shared_out_of_scope": {top: false, nestedShape: "full"},
		},
	}
	principals := map[string]uint{"exec_only": execOnly, "exec_and_credential_view": execCred,
		"exec_and_global_manage_without_view": execManage}
	for pname, row := range matrix {
		for cname, w := range row {
			t.Run(pname+"/"+cname, func(t *testing.T) {
				c := cells[cname]
				m, raw := get(principals[pname], c.assetID)
				if w.top {
					assert.Equal(t, c.fp, m["fingerprint"], "頂層指紋: %s", raw)
					if code, ok := export(principals[pname], c.assetID, cname); ok {
						assert.Equal(t, http.StatusOK, code, "可匯出公鑰")
					}
				} else {
					assert.NotContains(t, m, "fingerprint", "不帶頂層指紋: %s", raw)
					assert.NotContains(t, m, "has_public_key")
					if code, ok := export(principals[pname], c.assetID, cname); ok {
						assert.NotEqual(t, http.StatusOK, code, "不可匯出公鑰")
					}
				}
				n := nested(t, m, raw)
				switch w.nestedShape {
				case "slim":
					assert.NotContains(t, n, "credential_id", "精簡形狀: %s", raw)
				case "full":
					assert.Contains(t, n, "credential_id", "完整形狀: %s", raw)
				case "out_of_scope":
					assert.Equal(t, true, n["credential_out_of_scope"], "範圍外收窄: %s", raw)
				}
				if w.nestedFP {
					assert.Equal(t, c.fp, n["private_key_fingerprint"], "巢狀帳號列帶指紋: %s", raw)
				} else {
					assert.NotContains(t, n, "private_key_fingerprint", "巢狀帳號列不帶指紋: %s", raw)
				}
			})
		}
	}
}

// fpAccountRouter 帳號列的讀取與寫入路由（列表、單筆、修改、設預設），handler 與投影來源同正式組裝。
func fpAccountRouter(e *outEnv, uid uint) *gin.Engine {
	r := gin.New()
	r.Use(middleware.AuditLogMiddleware(newCoverageAuditService()))
	r.Use(e.scPrincipal(uid))
	svc := asset.NewAssetAccountService(e.assets, e.codec, audit.NewTxSink()).
		WithManagementAuthorizer(e.adapter).WithSystemAlertSink(noopAlertSink{}).
		WithAccountWriteScope(authz.NewAssetWriteScope(e.eval))
	h := api.NewAssetAccountHandler(svc, e.authzSvc)
	src := authz.NewAssetScopeReader(e.eval, e.db)
	h.SetAssetManagementVisibility(src)
	h.SetAccountCredentialScope(authz.NewCredentialScopeReader(e.eval, e.db))
	h.SetAccountRowActions(asset.NewAccountRowActionJudge(e.creds, svc))
	reg := middleware.EnforceRegistry()
	visible := middleware.RequireAssetVisibleOrManaged(e.authzSvc, src)
	r.GET("/api/v1/assets/:id/accounts", reg, visible, h.List)
	r.GET("/api/v1/assets/:id/accounts/:accountId", reg, visible, h.Get)
	r.PUT("/api/v1/assets/:id/accounts/:accountId", reg, h.Update)
	r.POST("/api/v1/assets/:id/accounts/:accountId/set-default", reg, h.SetDefault)
	return r
}

// 全域持有憑證管理能力而沒有憑證檢視能力的主體：帳號列照舊是完整形狀（憑證識別欄位不變），
// 但列表、單筆讀取與寫入回應都不帶指紋——與憑證讀取的檢視判定一致（他讀憑證詳情被拒）。
func TestAccountFingerprintHTTPManageWithoutView(t *testing.T) {
	e := newOutEnv(t, soWithAccounts())
	gFP, _ := fpKeyVersion(t, e.db, e.codec, e.gcred)
	listPath := fmt.Sprintf("/api/v1/assets/%d/accounts", e.assetU)
	onePath := fmt.Sprintf("%s/%d", listPath, e.gcredAcc)
	idKey := fmt.Sprintf(`"credential_id":%d`, e.gcred)
	// 帳號列表依連線授權決定看得到哪些帳號：兩個主體都給這台的連線授權
	e.connGrant(e.glbCompat, e.assetU)
	e.connGrant(e.glb, e.assetU)

	t.Run("precondition_cannot_read_credential", func(t *testing.T) {
		code, raw := e.call(e.glbCompat, http.MethodGet, fmt.Sprintf("/api/v1/credentials/%d", e.gcred), "")
		require.NotEqual(t, http.StatusOK, code, "PRECONDITION: 沒有檢視能力者讀不到憑證詳情\n本文: %s", raw)
	})

	for _, c := range []struct {
		name, method, path, body string
	}{
		{"list", http.MethodGet, listPath, ""},
		{"get", http.MethodGet, onePath, ""},
		{"update", http.MethodPut, onePath, `{"note":"zz-fp-compat"}`},
		{"set_default", http.MethodPost, onePath + "/set-default", ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			code, raw := soServe(fpAccountRouter(e, e.glbCompat), c.method, c.path, c.body)
			fpAssertAbsent(t, code, raw, http.StatusOK)
			assert.Contains(t, raw, idKey, "完整形狀照舊帶憑證識別欄位\n本文: %s", raw)
			assert.NotContains(t, raw, `"credential_out_of_scope"`, "不是範圍外收窄的形狀\n本文: %s", raw)

			// 對照：檢視與管理皆具的全域主體在同一端點拿得到指紋
			code, raw = soServe(fpAccountRouter(e, e.glb), c.method, c.path, c.body)
			fpAssertPresent(t, code, raw, http.StatusOK, gFP)
		})
	}
}

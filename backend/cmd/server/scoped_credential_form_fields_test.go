package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"github.com/custodexa/backend/internal/api"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
)

// 資產與帳號表單的憑證欄位（帳號名稱、登入秘密、內嵌憑證、SFTP 側車）與帳號列表的憑證識別欄位：
// 經憑證語義鍵通過者在寫入交易內以送出節點或路徑資產為目標判定，範圍不符與不存在同形、零寫入；
// 只持全域相容憑證管理能力者維持現行。PostgreSQL、正式 migration、真判定器、正式目錄、正式 handler。

// sfEnv 夾具：節點 X、Y、範圍外節點與一個已刪除節點（X 之下）。
type sfEnv struct {
	*scEnv
	x, y, out, gone uint
	hostSeq         int
}

const (
	sfMissingNode  = 999901
	sfMissingAsset = 999902
)

func newSFEnv(t *testing.T, schema string) *sfEnv {
	t.Helper()
	e := newSCEnvPG(t, schema)
	sfUseProductCatalogue(e)
	f := &sfEnv{scEnv: e}
	f.x = e.node("zz-sf-x", "")
	f.y = e.node("zz-sf-y", "")
	f.out = e.node("zz-sf-out", "")
	f.gone = e.node("zz-sf-gone", "zz-sf-x")
	require.NoError(t, e.db.Delete(&model.AssetGroup{}, f.gone).Error)
	return f
}

// sfUseProductCatalogue 主體解析、範圍判定器、管理授權轉接頭與資產寫入範圍一律改用正式目錄。
func sfUseProductCatalogue(e *scEnv) {
	cat := authz.ProductCatalogue()
	e.cat = cat
	e.eval = authz.NewScopeEvaluator(cat, asset.NewScopeTopologyReader(), authz.CredentialScopeResolver())
	e.adapter = newCredentialManagementAdapter(authz.NewResolver(e.db)).withScope(e.eval, e.db)
	e.assets.WithManagementAuthorizer(e.adapter)
	e.assets.SetAssetWriteScopePort(authz.NewAssetWriteScope(e.eval))
	e.creds = asset.NewCredentialService(e.assets, e.codec, audit.NewTxSink()).
		WithManagementAuthorizer(e.adapter).WithSystemAlertSink(noopAlertSink{}).
		WithOwnershipScope(authz.NewCredentialOwnershipScope(e.eval)).
		WithScopeSource(authz.NewCredentialScopeReader(e.eval, e.db))
}

// router 與正式組裝同形：資產建立、更新，帳號列表、建立、更新（登錄閘帶範圍宣告、管理可視、帳號列投影）。
// principal 非 nil 時以它作請求主體（撤權前的快照），否則每個請求自資料庫重解。
func (f *sfEnv) router(uid uint, principal *authz.Principal) *gin.Engine {
	r := gin.New()
	r.Use(middleware.AuditLogMiddleware(newCoverageAuditService()))
	if principal != nil {
		r.Use(func(c *gin.Context) {
			middleware.SetPrincipal(c, principal)
			c.Set("userID", uid)
			c.Set("username", fmt.Sprintf("u%d", uid))
			c.Next()
		})
	} else {
		r.Use(f.scPrincipal(uid))
	}
	gate := middleware.NewScopeGate(f.db, f.eval, authz.RouteScopeDeclarations())
	src := authz.NewAssetScopeReader(f.eval, f.db)
	h := api.NewAssetHandler(f.assets, f.authzSvc, nil)
	h.SetAssetScope(src)
	r.POST("/api/v1/assets", middleware.EnforceRegistry(gate), h.Create)
	r.PUT("/api/v1/assets/:id", middleware.EnforceRegistry(gate), h.Update)
	svc := asset.NewAssetAccountService(f.assets, f.codec, audit.NewTxSink()).
		WithManagementAuthorizer(f.adapter).WithSystemAlertSink(noopAlertSink{}).
		WithAccountWriteScope(authz.NewAssetWriteScope(f.eval))
	ah := api.NewAssetAccountHandler(svc, f.authzSvc)
	ah.SetAssetManagementVisibility(src)
	ah.SetAccountCredentialScope(authz.NewCredentialScopeReader(f.eval, f.db))
	ah.SetAccountRowActions(asset.NewAccountRowActionJudge(f.creds, svc))
	g := r.Group("/api/v1/assets/:id/accounts")
	g.GET("", middleware.EnforceRegistry(gate), middleware.RequireAssetVisibleOrManaged(f.authzSvc, src), ah.List)
	g.POST("", middleware.EnforceRegistry(gate), ah.Create)
	g.PUT("/:accountId", middleware.EnforceRegistry(gate), ah.Update)
	return r
}

func (f *sfEnv) do(uid uint, method, path, body string) (int, string) {
	f.t.Helper()
	return scServe(f.router(uid, nil), method, path, body)
}

// seedAsset 以系統呼叫者建一台掛在 node 的資產（SSH 帶預設專用帳號；VNC 帶 SFTP 側車），回資產與預設帳號。
func (f *sfEnv) seedAsset(name string, vnc bool, node uint) (assetID, accountID uint) {
	f.t.Helper()
	f.hostSeq++
	req := &asset.CreateAssetRequest{Name: name, Protocol: model.ProtocolSSH, Host: fmt.Sprintf("10.93.0.%d", f.hostSeq),
		Port: 22, Username: "root", Password: "zz-sf-seed-pw", NodeIDs: []uint{node}, CreatedBy: f.super}
	if vnc {
		req.Protocol, req.Port, req.Username, req.Password = model.ProtocolVNC, 5900, "", "zz-sf-vnc-pw"
		req.SftpEnabled, req.SftpPort, req.SftpUsername, req.SftpPassword = true, 22, "zz-sf-sftp0", "zz-sf-sftp-pw0"
	}
	a, err := f.assets.Create(asset.WithSystemCaller(operatorCtx()), req)
	require.NoError(f.t, err)
	var acc model.AssetAccount
	if err := f.db.Where("asset_id = ? AND is_default = ?", a.ID, true).First(&acc).Error; err != nil && !vnc {
		f.t.Fatal(err)
	}
	return a.ID, acc.ID
}

// snapshot 零寫入的比對基準：資產、帳號、憑證、憑證版本全列與成功審計列數。
func (f *sfEnv) snapshot() string {
	f.t.Helper()
	var b strings.Builder
	for _, table := range []string{"assets", "asset_accounts", "credentials", "credential_secret_versions", "asset_nodes"} {
		var rows []map[string]any
		require.NoError(f.t, f.db.Unscoped().Table(table).Order("1").Find(&rows).Error)
		fmt.Fprintf(&b, "%s=%v\n", table, rows)
	}
	var n int64
	require.NoError(f.t, f.db.Model(&model.AuditLog{}).Where("status = ?", model.StatusSuccess).Count(&n).Error)
	fmt.Fprintf(&b, "success_audits=%d", n)
	return b.String()
}

func (f *sfEnv) versionCount(accountID uint) int64 {
	f.t.Helper()
	var acc model.AssetAccount
	require.NoError(f.t, f.db.First(&acc, accountID).Error)
	var n int64
	require.NoError(f.t, f.db.Model(&model.CredentialSecretVersion{}).Where("credential_id = ?", acc.CredentialID).Count(&n).Error)
	return n
}

// sfSameAsMissing 範圍拒絕：404，且狀態與本文都與「目標不存在」的回應相同。
func sfSameAsMissing(t *testing.T, label string, code int, raw string, missCode int, missRaw string) {
	t.Helper()
	require.Equal(t, http.StatusNotFound, code, "%s：%s", label, raw)
	require.Equal(t, missCode, code, "%s：與不存在同形（狀態）", label)
	require.JSONEq(t, missRaw, raw, "%s：與不存在同形（本文）", label)
	assertNoLeak(t, label, raw)
}

func sfForbidden(t *testing.T, label string, code int, raw string) {
	t.Helper()
	require.Equal(t, http.StatusForbidden, code, "%s：%s", label, raw)
	require.Contains(t, raw, "AUTH_PERMISSION_DENIED", label)
	assertNoLeak(t, label, raw)
}

func sfPrivateKey(t *testing.T) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	block, err := ssh.MarshalPrivateKey(priv, "")
	require.NoError(t, err)
	return string(pem.EncodeToMemory(block))
}

func sfCreateBody(name string, extra string, nodes ...uint) string {
	ids, _ := json.Marshal(nodes)
	if nodes == nil {
		return fmt.Sprintf(`{"name":%q,"protocol":"ssh","host":"10.94.0.1","port":22%s}`, name, extra)
	}
	return fmt.Sprintf(`{"name":%q,"protocol":"ssh","host":"10.94.0.1","port":22%s,"node_ids":%s}`, name, extra, ids)
}

func TestScopedCredentialFormFields(t *testing.T) {
	f := newSFEnv(t, "sc_form_fields")
	e := f.scEnv
	credAll := []authz.Permission{authz.PermCredentialView, authz.PermCredentialCreate, authz.PermCredentialUpdate,
		authz.PermCredentialSetSecret}
	// 範圍內：資產與憑證能力都在 X
	inScope := e.user("zz-sf-in")
	e.grant(inScope, []string{"zz-sf-x"}, append([]authz.Permission{authz.PermAssetView, authz.PermAssetCreate,
		authz.PermAssetUpdate}, credAll...)...)
	// 語義範圍不符：資產能力在 X，憑證語義鍵只在 Y
	mismatch := e.user("zz-sf-mismatch")
	e.grant(mismatch, []string{"zz-sf-x"}, authz.PermAssetView, authz.PermAssetCreate, authz.PermAssetUpdate)
	e.grant(mismatch, []string{"zz-sf-y"}, credAll...)
	secret := `,"username":"zz-sf-svc","password":"Zz-sf-pw1"`

	t.Run("create_dedicated_in_scope", func(t *testing.T) {
		code, raw := f.do(inScope, "POST", "/api/v1/assets", sfCreateBody("zz-sf-new-in", secret, f.x))
		require.Equal(t, http.StatusCreated, code, raw)
		var a model.Asset
		require.NoError(t, f.db.Where("name = ?", "zz-sf-new-in").First(&a).Error)
		var acc model.AssetAccount
		require.NoError(t, f.db.Where("asset_id = ?", a.ID).First(&acc).Error)
		require.Equal(t, "zz-sf-svc", acc.Username)
		var cred model.Credential
		require.NoError(t, f.db.First(&cred, acc.CredentialID).Error)
		require.Equal(t, model.CredentialScopeDedicated, cred.Scope, "建立的是這台專用的憑證")
	})

	t.Run("create_dedicated_out_of_scope_node", func(t *testing.T) {
		before := f.snapshot()
		code, raw := f.do(inScope, "POST", "/api/v1/assets", sfCreateBody("zz-sf-new-out", secret, f.out))
		mc, mr := f.do(inScope, "POST", "/api/v1/assets", sfCreateBody("zz-sf-new-miss", secret, sfMissingNode))
		sfSameAsMissing(t, "範圍外節點", code, raw, mc, mr)
		require.Equal(t, before, f.snapshot(), "零寫入")
	})

	t.Run("create_dedicated_cred_scope_mismatch", func(t *testing.T) {
		before := f.snapshot()
		code, raw := f.do(mismatch, "POST", "/api/v1/assets", sfCreateBody("zz-sf-new-mm", secret, f.x))
		mc, mr := f.do(mismatch, "POST", "/api/v1/assets", sfCreateBody("zz-sf-new-mm-miss", secret, sfMissingNode))
		sfSameAsMissing(t, "建立憑證能力只在另一節點", code, raw, mc, mr)
		require.Equal(t, before, f.snapshot(), "零寫入")
	})

	t.Run("create_mixed_nodes_partial", func(t *testing.T) {
		mixed := e.user("zz-sf-mixed")
		e.grant(mixed, []string{"zz-sf-x", "zz-sf-y"}, authz.PermAssetView, authz.PermAssetCreate)
		e.grant(mixed, []string{"zz-sf-x"}, authz.PermCredentialCreate)
		before := f.snapshot()
		code, raw := f.do(mixed, "POST", "/api/v1/assets", sfCreateBody("zz-sf-new-mixed", secret, f.x, f.y))
		mc, mr := f.do(mixed, "POST", "/api/v1/assets", sfCreateBody("zz-sf-new-mixed-miss", secret, f.x, sfMissingNode))
		sfSameAsMissing(t, "兩個節點只涵蓋其一", code, raw, mc, mr)
		require.Equal(t, before, f.snapshot(), "零寫入")
	})

	t.Run("create_nodes_omitted_or_empty", func(t *testing.T) {
		omit := e.user("zz-sf-omit")
		e.grantGlobal(omit, e.role(authz.PermAssetView, authz.PermAssetCreate))
		e.grant(omit, []string{"zz-sf-x"}, authz.PermCredentialCreate)
		before := f.snapshot()
		code, raw := f.do(omit, "POST", "/api/v1/assets", sfCreateBody("zz-sf-new-omit", secret))
		sfForbidden(t, "省略節點", code, raw)
		code, raw = f.do(omit, "POST", "/api/v1/assets", sfCreateBody("zz-sf-new-empty", secret+`,"node_ids":[]`))
		sfForbidden(t, "空節點集合", code, raw)
		require.Equal(t, before, f.snapshot(), "零寫入")
	})

	t.Run("create_soft_deleted_node", func(t *testing.T) {
		before := f.snapshot()
		code, raw := f.do(inScope, "POST", "/api/v1/assets", sfCreateBody("zz-sf-new-gone", secret, f.gone))
		mc, mr := f.do(inScope, "POST", "/api/v1/assets", sfCreateBody("zz-sf-new-gone-miss", secret, sfMissingNode))
		sfSameAsMissing(t, "已刪除節點", code, raw, mc, mr)
		require.Equal(t, before, f.snapshot(), "零寫入")
	})

	t.Run("create_node_manage_only", func(t *testing.T) {
		mo := e.user("zz-sf-manage-only")
		e.grant(mo, []string{"zz-sf-x"}, authz.PermAssetView, authz.PermAssetCreate, authz.PermCredentialManage)
		before := f.snapshot()
		code, raw := f.do(mo, "POST", "/api/v1/assets", sfCreateBody("zz-sf-new-mo", `,"username":"zz-sf-svc"`, f.x))
		sfForbidden(t, "節點指派的相容鍵不生效", code, raw)
		require.Equal(t, before, f.snapshot(), "零寫入")
	})

	t.Run("sftp_create_cred_scope_mismatch", func(t *testing.T) {
		before := f.snapshot()
		vnc := func(name string, node uint) string {
			return fmt.Sprintf(`{"name":%q,"protocol":"vnc","host":"10.94.0.2","port":5900,"sftp_enabled":true,"sftp_port":22,`+
				`"sftp_username":"zz-sf-sftp","sftp_password":"Zz-sf-sftp1","node_ids":[%d]}`, name, node)
		}
		code, raw := f.do(mismatch, "POST", "/api/v1/assets", vnc("zz-sf-new-vnc", f.x))
		mc, mr := f.do(mismatch, "POST", "/api/v1/assets", vnc("zz-sf-new-vnc-miss", sfMissingNode))
		sfSameAsMissing(t, "SFTP 側車：建立憑證能力只在另一節點", code, raw, mc, mr)
		require.Equal(t, before, f.snapshot(), "零寫入")
	})

	t.Run("rename_asset_username_in_scope", func(t *testing.T) {
		a, acc := f.seedAsset("zz-sf-ren-in", false, f.x)
		code, raw := f.do(inScope, "PUT", idPath(a), `{"username":"zz-sf-root2"}`)
		require.Equal(t, http.StatusOK, code, raw)
		var row model.AssetAccount
		require.NoError(t, f.db.First(&row, acc).Error)
		require.Equal(t, "zz-sf-root2", row.Username)
	})

	t.Run("rename_asset_username_out_of_scope", func(t *testing.T) {
		a, _ := f.seedAsset("zz-sf-ren-out", false, f.out)
		before := f.snapshot()
		code, raw := f.do(inScope, "PUT", idPath(a), `{"username":"zz-sf-root3"}`)
		mc, mr := f.do(inScope, "PUT", idPath(sfMissingAsset), `{"username":"zz-sf-root3"}`)
		sfSameAsMissing(t, "範圍外資產改名", code, raw, mc, mr)
		require.Equal(t, before, f.snapshot(), "零寫入")
	})

	mismatchUpdate := func(t *testing.T, label string, vnc bool, bodies ...string) {
		t.Helper()
		a, _ := f.seedAsset("zz-sf-mm-"+strings.ReplaceAll(label, " ", "-"), vnc, f.x)
		for _, body := range bodies {
			before := f.snapshot()
			code, raw := f.do(mismatch, "PUT", idPath(a), body)
			mc, mr := f.do(mismatch, "PUT", idPath(sfMissingAsset), body)
			sfSameAsMissing(t, label, code, raw, mc, mr)
			require.Equal(t, before, f.snapshot(), "%s：零寫入", label)
		}
	}

	t.Run("rename_asset_username_cred_scope_mismatch", func(t *testing.T) {
		mismatchUpdate(t, "rename", false, `{"username":"zz-sf-root4"}`)
	})

	t.Run("sftp_rename_cred_scope_mismatch", func(t *testing.T) {
		mismatchUpdate(t, "sftp rename", true, `{"sftp_username":"zz-sf-sftp2"}`)
	})

	t.Run("sftp_secret_cred_scope_mismatch", func(t *testing.T) {
		mismatchUpdate(t, "sftp secret", true, `{"sftp_password":"Zz-sf-sftp2"}`)
	})

	t.Run("asset_secret_cred_scope_mismatch", func(t *testing.T) {
		key, _ := json.Marshal(sfPrivateKey(t))
		mismatchUpdate(t, "asset secret", false, `{"password":"Zz-sf-pw2"}`, fmt.Sprintf(`{"private_key":%s}`, key))
	})

	t.Run("sftp_secret_in_scope", func(t *testing.T) {
		a, _ := f.seedAsset("zz-sf-sftp-in", true, f.x)
		var before model.Asset
		require.NoError(t, f.db.First(&before, a).Error)
		code, raw := f.do(inScope, "PUT", idPath(a), `{"sftp_password":"Zz-sf-sftp3"}`)
		require.Equal(t, http.StatusOK, code, raw)
		var after model.Asset
		require.NoError(t, f.db.First(&after, a).Error)
		require.NotEqual(t, before.SftpPasswordEnc, after.SftpPasswordEnc, "SFTP 密碼已更換")
	})

	// 只持範圍化的更換秘密能力（不持相容鍵）：資產表單與帳號端點的登錄密碼、私鑰在範圍內成功且版本各加一
	secretOnly := e.user("zz-sf-secret-only")
	e.grant(secretOnly, []string{"zz-sf-x"}, authz.PermAssetView, authz.PermAssetUpdate, authz.PermCredentialSetSecret)
	secretBodies := func(t *testing.T) []string {
		key, _ := json.Marshal(sfPrivateKey(t))
		return []string{`{"password":"Zz-sf-pw5"}`, fmt.Sprintf(`{"private_key":%s}`, key)}
	}

	t.Run("asset_secret_in_scope", func(t *testing.T) {
		a, acc := f.seedAsset("zz-sf-secret-in", false, f.x)
		for _, body := range secretBodies(t) {
			n := f.versionCount(acc)
			code, raw := f.do(secretOnly, "PUT", idPath(a), body)
			require.Equal(t, http.StatusOK, code, raw)
			require.Equal(t, n+1, f.versionCount(acc), "專用憑證版本加一")
		}
	})

	accountPath := func(a uint) string { return fmt.Sprintf("/api/v1/assets/%d/accounts", a) }
	accountItem := func(a, acc uint) string { return fmt.Sprintf("/api/v1/assets/%d/accounts/%d", a, acc) }

	t.Run("account_create_named_in_scope", func(t *testing.T) {
		a, _ := f.seedAsset("zz-sf-acc-in", false, f.x)
		code, raw := f.do(inScope, "POST", accountPath(a), `{"username":"zz-sf-svc1"}`)
		require.Equal(t, http.StatusCreated, code, raw)
		var n int64
		require.NoError(t, f.db.Model(&model.AssetAccount{}).Where("asset_id = ? AND username = ?", a, "zz-sf-svc1").Count(&n).Error)
		require.EqualValues(t, 1, n)
	})

	t.Run("account_create_named_cred_scope_mismatch", func(t *testing.T) {
		a, _ := f.seedAsset("zz-sf-acc-mm", false, f.x)
		before := f.snapshot()
		code, raw := f.do(mismatch, "POST", accountPath(a), `{"username":"zz-sf-svc2"}`)
		mc, mr := f.do(mismatch, "POST", accountPath(sfMissingAsset), `{"username":"zz-sf-svc2"}`)
		sfSameAsMissing(t, "帳號建立：建立憑證能力只在另一節點", code, raw, mc, mr)
		require.Equal(t, before, f.snapshot(), "零寫入")
	})

	t.Run("account_rename_out_of_scope", func(t *testing.T) {
		a, acc := f.seedAsset("zz-sf-acc-out", false, f.out)
		before := f.snapshot()
		code, raw := f.do(inScope, "PUT", accountItem(a, acc), `{"username":"zz-sf-svc3"}`)
		mc, mr := f.do(inScope, "PUT", accountItem(sfMissingAsset, acc), `{"username":"zz-sf-svc3"}`)
		sfSameAsMissing(t, "範圍外資產的帳號改名", code, raw, mc, mr)
		require.Equal(t, before, f.snapshot(), "零寫入")
	})

	t.Run("account_rename_cred_scope_mismatch", func(t *testing.T) {
		a, acc := f.seedAsset("zz-sf-acc-ren-mm", false, f.x)
		before := f.snapshot()
		code, raw := f.do(mismatch, "PUT", accountItem(a, acc), `{"username":"zz-sf-svc4"}`)
		mc, mr := f.do(mismatch, "PUT", accountItem(sfMissingAsset, acc), `{"username":"zz-sf-svc4"}`)
		sfSameAsMissing(t, "帳號改名：更新憑證能力只在另一節點", code, raw, mc, mr)
		require.Equal(t, before, f.snapshot(), "零寫入")
	})

	t.Run("account_secret_in_scope", func(t *testing.T) {
		a, acc := f.seedAsset("zz-sf-acc-secret-in", false, f.x)
		for _, body := range secretBodies(t) {
			n := f.versionCount(acc)
			code, raw := f.do(secretOnly, "PUT", accountItem(a, acc), body)
			require.Equal(t, http.StatusOK, code, raw)
			require.Equal(t, n+1, f.versionCount(acc), "專用憑證版本加一")
		}
	})

	t.Run("account_secret_cred_scope_mismatch", func(t *testing.T) {
		a, acc := f.seedAsset("zz-sf-acc-secret-mm", false, f.x)
		for _, body := range secretBodies(t) {
			before := f.snapshot()
			code, raw := f.do(mismatch, "PUT", accountItem(a, acc), body)
			mc, mr := f.do(mismatch, "PUT", accountItem(sfMissingAsset, acc), body)
			sfSameAsMissing(t, "帳號秘密：更換秘密能力只在另一節點", code, raw, mc, mr)
			require.Equal(t, before, f.snapshot(), "零寫入")
		}
	})

	t.Run("compat_global_manage_unchanged", func(t *testing.T) {
		compatBase := []authz.Permission{authz.PermAssetView, authz.PermAssetCreate, authz.PermAssetUpdate, authz.PermCredentialManage}
		compat := e.user("zz-sf-compat")
		e.grantGlobal(compat, e.role(compatBase...))
		// 另持範圍不涵蓋目標的語義鍵：仍依相容鍵判定
		compatPlus := e.user("zz-sf-compat-plus")
		e.grantGlobal(compatPlus, e.role(compatBase...))
		e.grant(compatPlus, []string{"zz-sf-y"}, authz.PermCredentialCreate, authz.PermCredentialUpdate)

		firstThree := func(t *testing.T, who uint, tag string) {
			t.Helper()
			for i, extra := range []string{`,"username":"zz-sf-c-top"`, `,"credential":{"username":"zz-sf-c-inline"}`} {
				name := fmt.Sprintf("zz-sf-compat-%s-%d", tag, i)
				code, raw := f.do(who, "POST", "/api/v1/assets", sfCreateBody(name, extra, f.x))
				require.Equal(t, http.StatusCreated, code, "%s 無秘密以名稱建立資產：%s", tag, raw)
			}
			a, acc := f.seedAsset("zz-sf-compat-acc-"+tag, false, f.x)
			code, raw := f.do(who, "POST", accountPath(a), `{"username":"zz-sf-c-acc"}`)
			require.Equal(t, http.StatusCreated, code, "%s 無秘密以名稱建立帳號：%s", tag, raw)
			code, raw = f.do(who, "PUT", accountItem(a, acc), `{"username":"zz-sf-c-renamed"}`)
			require.Equal(t, http.StatusOK, code, "%s 既有帳號改名：%s", tag, raw)
		}
		firstThree(t, compat, "base")

		code, raw := f.do(compat, "POST", "/api/v1/assets", fmt.Sprintf(`{"name":"zz-sf-compat-vnc","protocol":"vnc",`+
			`"host":"10.94.0.3","port":5900,"sftp_enabled":true,"sftp_port":22,"sftp_username":"zz-sf-c-sftp",`+
			`"sftp_password":"Zz-sf-c-sftp1","node_ids":[%d]}`, f.x))
		require.Equal(t, http.StatusCreated, code, "VNC 建立帶 SFTP 側車：%s", raw)
		v, _ := f.seedAsset("zz-sf-compat-vnc-upd", true, f.x)
		code, raw = f.do(compat, "PUT", idPath(v), `{"sftp_password":"Zz-sf-c-sftp2"}`)
		require.Equal(t, http.StatusOK, code, "更新 SFTP 密碼：%s", raw)

		a, acc := f.seedAsset("zz-sf-compat-secret", false, f.x)
		n := f.versionCount(acc)
		code, raw = f.do(compat, "PUT", idPath(a), `{"password":"Zz-sf-c-pw"}`)
		sfForbidden(t, "相容鍵不代替更換秘密能力", code, raw)
		require.Equal(t, n, f.versionCount(acc), "版本不變")

		firstThree(t, compatPlus, "plus")
	})
}

// 帳號列表的憑證識別欄位：形狀與可見集合由讀取當下重解的同一份主體決定。
func TestScopedAccountListIdentityFields(t *testing.T) {
	f := newSFEnv(t, "sc_account_list_fields")
	e := f.scEnv
	a := e.asset("zz-sf-list-asset", "zz-sf-x")
	var ded model.AssetAccount
	require.NoError(t, f.db.Where("credential_id = ?", e.dedicated(a)).First(&ded).Error)
	accDedicated := ded.ID
	inCred := e.cred("zz-sf-cred-in", &f.x)
	outCred := e.cred("zz-sf-cred-out-y", &f.y)
	accIn := e.mount(inCred, a)
	accOut := e.mount(outCred, a)
	// 範圍外憑證另掛兩台，台數 3 不得出現在回應裡
	e.mount(outCred, e.asset("zz-sf-list-other-1", "zz-sf-y"))
	e.mount(outCred, e.asset("zz-sf-list-other-2", "zz-sf-y"))
	path := fmt.Sprintf("/api/v1/assets/%d/accounts", a)

	noLeak := func(t *testing.T, raw string) {
		t.Helper()
		// 以 JSON 字串值比對：帳號自身的 username 由憑證名衍生（u-<名稱>），那不在移除之列
		require.NotContains(t, raw, `"zz-sf-cred-out-y"`, "回應原文不含範圍外憑證名稱")
		require.NotContains(t, raw, fmt.Sprintf(`"credential_id":%d`, outCred), "回應原文不含範圍外憑證識別")
		require.NotContains(t, raw, `"binding_count":3`, "回應原文不含範圍外憑證台數")
	}
	slimShape := func(t *testing.T, raw string) {
		t.Helper()
		var out struct {
			Data []map[string]any `json:"data"`
		}
		require.NoError(t, json.Unmarshal([]byte(raw), &out), raw)
		require.NotEmpty(t, out.Data)
		for _, row := range out.Data {
			keys := make([]string, 0, len(row))
			for k := range row {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			require.Equal(t, []string{"has_password", "has_private_key", "id", "is_default", "username"}, keys, "精簡形狀")
		}
	}

	scoped := e.user("zz-sf-list-scoped")
	e.grant(scoped, []string{"zz-sf-x"}, authz.PermAssetView, authz.PermCredentialView)

	t.Run("scoped_full_shape_in_scope", func(t *testing.T) {
		code, raw := f.do(scoped, "GET", path, "")
		require.Equal(t, http.StatusOK, code, raw)
		in := scAccountRow(t, raw, accIn)
		require.EqualValues(t, inCred, in["credential_id"], "範圍內憑證的列為完整形狀")
		require.NotContains(t, in, "credential_out_of_scope")
		require.Contains(t, scAccountRow(t, raw, accDedicated), "credential_id", "專用憑證的列為完整形狀")
	})

	t.Run("scoped_out_of_scope_shared_marked", func(t *testing.T) {
		code, raw := f.do(scoped, "GET", path, "")
		require.Equal(t, http.StatusOK, code, raw)
		row := scAccountRow(t, raw, accOut)
		require.Equal(t, true, row["credential_out_of_scope"], "範圍外標記")
		require.Equal(t, true, row["shared_credential"], "共用標記（不呈現為這台專用）")
	})

	t.Run("scoped_out_of_scope_no_leak", func(t *testing.T) {
		code, raw := f.do(scoped, "GET", path, "")
		require.Equal(t, http.StatusOK, code, raw)
		noLeak(t, raw)
		row := scAccountRow(t, raw, accOut)
		for _, k := range []string{"credential_id", "credential_name", "binding_count", "ownership"} {
			require.NotContains(t, row, k)
		}
	})

	t.Run("scoped_revoked_after_field_check_slim", func(t *testing.T) {
		revoked := e.user("zz-sf-list-revoked")
		e.grantGlobal(revoked, e.role(authz.PermAssetView))
		e.grant(revoked, []string{"zz-sf-x"}, authz.PermCredentialView)
		e.connGrant(revoked, a)
		// 撤權前的主體快照：欄位能力判定在此刻成立（等同請求已通過欄位檢查）
		stale, err := authz.ResolveUserOnWithCatalogue(e.db, e.cat, revoked, authz.TokenFacts{})
		require.NoError(t, err)
		require.True(t, authz.FieldCapability("GET", "/api/v1/assets/:id/accounts", "credential_identity_fields", stale))
		e.dropNodeAssignments(revoked)
		code, raw := scServe(f.router(revoked, stale), "GET", path, "")
		require.Equal(t, http.StatusOK, code, raw)
		slimShape(t, raw)
		noLeak(t, raw)
	})

	t.Run("global_manage_unchanged", func(t *testing.T) {
		global := e.user("zz-sf-list-global")
		e.grantGlobal(global, e.role(authz.PermAssetView, authz.PermCredentialManage))
		e.connGrant(global, a)
		code, withProj := f.do(global, "GET", path, "")
		require.Equal(t, http.StatusOK, code, withProj)
		// 對照：不注入投影的現行路徑（以請求主體判可見性、不收窄）
		r := gin.New()
		r.Use(e.scPrincipal(global))
		svc := asset.NewAssetAccountService(e.assets, e.codec, audit.NewTxSink()).
			WithManagementAuthorizer(e.adapter).WithSystemAlertSink(noopAlertSink{})
		h := api.NewAssetAccountHandler(svc, e.authzSvc)
		r.GET("/api/v1/assets/:id/accounts", middleware.EnforceRegistry(), middleware.RequireAssetVisible(e.authzSvc), h.List)
		code, without := scServe(r, "GET", path, "")
		require.Equal(t, http.StatusOK, code, without)
		require.JSONEq(t, without, withProj, "只持全域相容鍵者鍵集與值逐筆相同")
		require.EqualValues(t, outCred, scAccountRow(t, withProj, accOut)["credential_id"], "全域主體照完整形狀")
	})

	t.Run("no_credential_capability_slim", func(t *testing.T) {
		none := e.user("zz-sf-list-none")
		e.grant(none, []string{"zz-sf-x"}, authz.PermAssetView)
		code, raw := f.do(none, "GET", path, "")
		require.Equal(t, http.StatusOK, code, raw)
		slimShape(t, raw)
		noLeak(t, raw)
	})
}

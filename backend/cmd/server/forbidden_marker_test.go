package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/api"
	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/identity"
)

// TestForbiddenMarkerOutlets 「補標記」類能力拒絕寫出點：回應形狀本來就是單一形狀，本守衛鎖兩件事。
//
//   - 回應不變：狀態碼與本文和改為單一寫出函式之前的寫法（apierror.Respond 403 權限不足、無參數）
//     逐位元相同，也與登錄閘的能力拒絕相同。
//   - 依據入脈絡：拒絕依據經 WriteCapabilityDenial 存進請求脈絡。服務層錯誤值帶出缺的權限點鍵；
//     無從得知缺哪一項的分支（空主體、主體不存在或停用）記該操作層級要求的權限點（all_of）；
//     錯誤值未附鍵者記該路由登錄項的要求；角色定義寫入記超管保留條件。
//
// 涵蓋：資產帳號建立／更新、資產建立／更新、匯入預檢／提交、批次改密建立、角色定義四種寫入。
func TestForbiddenMarkerOutlets(t *testing.T) {
	legacy := legacyPermissionDeniedBody(t)
	gate := probeGate("GET", "/api/v1/assets", principalOf(model.BuiltinApprover, ""))
	require.Equal(t, http.StatusForbidden, gate.code)
	require.Equal(t, legacy, gate.raw, "基準：改前寫法與登錄閘能力拒絕須逐位元相同")

	for _, c := range markerAssetCases() {
		t.Run(c.name, func(t *testing.T) {
			env := newMarkerEnv(t, c.missing)
			pr := env.probe(c.who, c.userID, c.method, c.path(env.seed), c.bodyFor(env.seed), c.mount)
			assertMarker(t, c.name, legacy, pr, authz.DenialAllOf, c.want)
		})
	}
	// 對照：無缺鍵分支的主體在正常主體下放行，上列拒絕只來自該分支
	t.Run("放行對照", func(t *testing.T) {
		for _, c := range markerAllowCases() {
			env := newMarkerEnv(t, "")
			pr := env.probe(c.who, nil, c.method, c.path(env.seed), c.bodyFor(env.seed), c.mount)
			assert.Equal(t, c.status, pr.code, "%s：%s", c.name, pr.raw)
			assert.False(t, pr.hasDeny, "%s：放行不得存拒絕依據", c.name)
		}
	})
	t.Run("角色定義寫入", func(t *testing.T) {
		for _, c := range markerRoleCases(t) {
			t.Run(c.name, func(t *testing.T) {
				pr := c.run()
				assertMarker(t, c.name, legacy, pr, authz.DenialReserved, []string{authz.ReservedSuperAdmin})
			})
		}
	})
}

// legacyPermissionDeniedBody 改前寫法的回應本文（基準快照）。
func legacyPermissionDeniedBody(t *testing.T) string {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/legacy", func(c *gin.Context) {
		apierror.Respond(c, http.StatusForbidden, apierror.CodePermissionDenied, nil)
	})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/legacy", nil))
	require.Equal(t, http.StatusForbidden, w.Code)
	return w.Body.String()
}

func assertMarker(t *testing.T, name, legacy string, pr shapeProbe, basis authz.DenialBasis, want []string) {
	t.Helper()
	assert.Equal(t, http.StatusForbidden, pr.code, "%s：狀態碼", name)
	assert.Equal(t, legacy, pr.raw, "%s：本文須與改前逐位元相同", name)
	require.True(t, pr.hasDeny, "%s：拒絕依據未存入脈絡", name)
	assert.Equal(t, basis, pr.denial.Basis, "%s：依據種類", name)
	assert.Equal(t, want, pr.denial.Required, "%s：依據所列鍵", name)
}

// markerSeed 每個案例各自的資料：一份共用憑證、一台帶專用憑證帳號的資產。
type markerSeed struct {
	credID, assetID, accountID uint
}

type markerEnv struct {
	*fieldCapEnv
	seed    markerSeed
	auth    asset.CredentialManagementAuthorizer
	batches *asset.ChangeSecretBatchService
}

// markerAuthorizer 憑證管理關卡替身：missing 非空時一律回該缺漏（模擬主體不存在或停用的「principal」），
// 否則以本次請求主體判定（與 fieldCapManagementAuthorizer 相同）。
type markerAuthorizer struct {
	env     *fieldCapEnv
	missing string
}

func (a markerAuthorizer) AuthorizeCredentialManagement(ctx context.Context, db *gorm.DB,
	actor asset.CredentialManagementActor, req asset.CredentialManagementRequest) (asset.CredentialManagementDecision, error) {
	if a.missing != "" {
		return asset.CredentialManagementDecision{Missing: a.missing, AuthzVersion: 1}, nil
	}
	return fieldCapManagementAuthorizer{env: a.env}.AuthorizeCredentialManagement(ctx, db, actor, req)
}

func newMarkerEnv(t *testing.T, missing string) *markerEnv {
	t.Helper()
	return newMarkerEnvOn(t, newFieldCapEnv(t), missing)
}

// newMarkerEnvOn 在既有夾具上建；PostgreSQL 的表由正式 migration 建立，不再 AutoMigrate。
func newMarkerEnvOn(t *testing.T, base *fieldCapEnv, missing string) *markerEnv {
	t.Helper()
	if base.db.Dialector.Name() != "postgres" {
		require.NoError(t, base.db.AutoMigrate(&model.ChangeSecretBatch{}, &model.CredentialJobAuthorization{}))
	}
	env := &markerEnv{fieldCapEnv: base, auth: markerAuthorizer{env: base, missing: missing}}
	cred, err := base.creds.Create(operatorCtx(), &asset.CreateCredentialRequest{
		Name: "marker-shared", Username: "shared", Password: "pw", ProtocolFamily: model.ProtocolFamilySSH})
	require.NoError(t, err)
	a, err := base.assets.Create(asset.WithSystemCaller(operatorCtx()), &asset.CreateAssetRequest{
		Name: "marker-host", Protocol: model.ProtocolSSH, Host: "10.9.0.1", Port: 22, CreatedBy: 1,
		Username: "root", Password: "Pw-0",
	})
	require.NoError(t, err)
	var acc model.AssetAccount
	require.NoError(t, base.db.Where("asset_id = ?", a.ID).First(&acc).Error)
	env.seed = markerSeed{credID: cred.ID, assetID: a.ID, accountID: acc.ID}
	// 種子建好後才換上本案例的關卡替身
	base.assets.WithManagementAuthorizer(env.auth)
	env.batches = asset.NewChangeSecretBatchService(base.db, nil).WithManagementAuthorizer(env.auth).
		WithOwnershipScope(globalOwnershipScopeForTest{})
	return env
}

// markerMount 掛與正式組裝相同的「登錄閘＋handler」守衛鏈。
type markerMount func(e *markerEnv, r gin.IRoutes)

func mountAssets(e *markerEnv, r gin.IRoutes) {
	h := api.NewAssetHandler(e.assets, nil, nil)
	r.POST("/api/v1/assets", middleware.EnforceRegistry(), h.Create)
	r.PUT("/api/v1/assets/:id", middleware.EnforceRegistry(), h.Update)
	r.POST("/api/v1/assets/import/preview", middleware.EnforceRegistry(), h.PreviewImport)
	r.POST("/api/v1/assets/import", middleware.EnforceRegistry(), h.Import)
}

func mountAccounts(e *markerEnv, r gin.IRoutes) {
	svc := asset.NewAssetAccountService(e.assets, e.codec, audit.NewTxSink()).
		WithManagementAuthorizer(e.auth).WithSystemAlertSink(noopAlertSink{}).WithAccountWriteScope(allowAllAccountWriteScope{})
	mountAccountHandler(r, api.NewAssetAccountHandler(svc, nil))
}

func mountAccountHandler(r gin.IRoutes, h *api.AssetAccountHandler) {
	r.POST("/api/v1/assets/:id/accounts", middleware.EnforceRegistry(), h.Create)
	r.PUT("/api/v1/assets/:id/accounts/:accountId", middleware.EnforceRegistry(), h.Update)
}

// mountAccountsReturning 帳號服務替身：寫入一律回 err（驗錯誤值未附鍵時退回路由要求）。
func mountAccountsReturning(err error) markerMount {
	return func(_ *markerEnv, r gin.IRoutes) {
		mountAccountHandler(r, api.NewAssetAccountHandler(failingAccountService{err: err}, nil))
	}
}

func mountBatches(e *markerEnv, r gin.IRoutes) {
	h := api.NewChangeSecretHandler(nil, nil, nil, nil, e.batches, nil)
	r.POST("/api/v1/change-secret-batches", middleware.EnforceRegistry(), h.CreateBatch)
}

type failingAccountService struct {
	api.AssetAccountServiceInterface
	err error
}

func (f failingAccountService) Create(context.Context, uint, *asset.CreateAssetAccountRequest) (*asset.AssetAccountDTO, error) {
	return nil, f.err
}

func (f failingAccountService) Update(context.Context, uint, uint, *asset.UpdateAssetAccountRequest) (*asset.AssetAccountDTO, error) {
	return nil, f.err
}

// probe 以指定主體打一發；userID 為 nil 時用 7，非 nil 時照設（含 0＝空主體）。
func (e *markerEnv) probe(p *authz.Principal, userID *uint, method, path, body string, mount markerMount) shapeProbe {
	e.current = p
	defer func() { e.current = nil }()
	uid := uint(7)
	if userID != nil {
		uid = *userID
	}
	return markerServe(p, uid, method, path, body, func(r gin.IRoutes) { mount(e, r) })
}

func markerServe(p *authz.Principal, userID uint, method, path, body string, mount func(r gin.IRoutes)) shapeProbe {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	var out shapeProbe
	r.Use(func(c *gin.Context) {
		c.Set("userID", userID)
		c.Set("username", "marker-probe")
		middleware.SetPrincipal(c, p)
		c.Next()
		out.denial, out.hasDeny = middleware.CapabilityDenialFrom(c)
	})
	mount(r)
	var rd *strings.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	var req *http.Request
	if rd != nil {
		req = httptest.NewRequest(method, path, rd)
		req.Header.Set("Content-Type", "application/json")
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	out.code = w.Code
	out.raw = w.Body.String()
	_ = json.Unmarshal(w.Body.Bytes(), &out.body)
	return out
}

type markerCase struct {
	name, method, body string
	path               func(s markerSeed) string
	who                *authz.Principal
	userID             *uint
	missing            string // 憑證管理關卡回報的缺漏（非空即模擬主體不存在或停用）
	mount              markerMount
	want               []string
}

func fixed(p string) func(markerSeed) string { return func(markerSeed) string { return p } }

func markerAssetCases() []markerCase {
	zero := uint(0)
	base := []authz.Permission{authz.PermAssetView, authz.PermAssetCreate, authz.PermAssetUpdate, authz.PermCredentialManage}
	with := func(extra ...authz.Permission) *authz.Principal {
		return customPrincipal(append(append([]authz.Permission{}, base...), extra...)...)
	}
	manageOnly := with()
	withCreate := with(authz.PermCredentialCreate)
	createOnly := customPrincipal(authz.PermAssetView, authz.PermAssetCreate)
	updateOnly := customPrincipal(authz.PermAssetView, authz.PermAssetUpdate)
	batcher := customPrincipal(authz.PermChangeSecretManage)
	batcherNoCreate := customPrincipal(authz.PermChangeSecretManage, authz.PermAccountRotate)
	// 無缺鍵分支用持全部相關能力的主體：拒絕只可能來自空主體或判定器回報的主體缺漏
	full := with(authz.PermCredentialCreate, authz.PermCredentialBind, authz.PermCredentialSetSecret, authz.PermAccessPolicyManage)
	batcherFull := customPrincipal(authz.PermChangeSecretManage, authz.PermAccountRotate, authz.PermCredentialCreate, authz.PermCredentialBind)

	bind, create, setSecret := string(authz.PermCredentialBind), string(authz.PermCredentialCreate), string(authz.PermCredentialSetSecret)
	credUpdate, policy, upd := string(authz.PermCredentialUpdate), string(authz.PermAccessPolicyManage), string(authz.PermAssetUpdate)
	rotate := string(authz.PermAccountRotate)

	createBody := func(extra string) string {
		return `{"name":"m-new","protocol":"ssh","host":"10.9.0.2","port":22,` + extra + `}`
	}
	assetPath := func(s markerSeed) string { return fmt.Sprintf("/api/v1/assets/%d", s.assetID) }
	accountsPath := func(s markerSeed) string { return fmt.Sprintf("/api/v1/assets/%d/accounts", s.assetID) }
	accountPath := func(s markerSeed) string {
		return fmt.Sprintf("/api/v1/assets/%d/accounts/%d", s.assetID, s.accountID)
	}
	// 本文需要種子 ID 的案例以 %d 佔位，執行時由 bodyFor 代入共用憑證 ID
	bindBody := createBody(`"credential_id":%d`)
	importBody := `{"source":"form","rows":[{"name":"i1","protocol":"ssh","host":"10.9.1.1"},` +
		`{"name":"i2","protocol":"ssh","host":"10.9.1.2","credential_id":%d}]}`
	policyImport := `{"source":"form","rows":[{"name":"i3","protocol":"ssh","host":"10.9.1.3","access_policy":"approval"}]}`
	batchBody := `{"username":"root","all":true,"password_mode":"per_target"}`
	sharedBatch := `{"username":"root","all":true,"password_mode":"shared","credential_name":"marker-batch"}`

	cases := []markerCase{
		// 資產建立（B024）
		{name: "資產建立：掛共用憑證缺掛載能力", method: "POST", path: fixed("/api/v1/assets"), body: bindBody, who: manageOnly, mount: mountAssets, want: []string{bind}},
		{name: "資產建立：內嵌密碼缺建立能力", method: "POST", path: fixed("/api/v1/assets"), body: createBody(`"username":"root","password":"Pw-1"`), who: manageOnly, mount: mountAssets, want: []string{create}},
		{name: "資產建立：帳號名欄位缺憑證建立能力", method: "POST", path: fixed("/api/v1/assets"), body: createBody(`"username":"root"`), who: createOnly, mount: mountAssets, want: []string{create}},
		{name: "資產建立：存取政策欄位缺存取政策能力", method: "POST", path: fixed("/api/v1/assets"), body: createBody(`"access_policy":"approval"`), who: createOnly, mount: mountAssets, want: []string{policy}},
		{name: "資產建立：空主體記操作要求", method: "POST", path: fixed("/api/v1/assets"), body: bindBody, who: full, userID: &zero, mount: mountAssets, want: []string{bind}},
		{name: "資產建立：主體不存在或停用記操作要求", method: "POST", path: fixed("/api/v1/assets"), body: bindBody, who: full, missing: "principal", mount: mountAssets, want: []string{bind}},
		// 資產更新（B024）
		{name: "資產更新：改密碼缺改秘密能力", method: "PUT", path: assetPath, body: `{"password":"Pw-2"}`, who: manageOnly, mount: mountAssets, want: []string{setSecret}},
		{name: "資產更新：改帳號名缺憑證更新能力", method: "PUT", path: assetPath, body: `{"username":"other"}`, who: updateOnly, mount: mountAssets, want: []string{credUpdate}},
		{name: "資產更新：主體不存在或停用記操作要求", method: "PUT", path: assetPath, body: `{"password":"Pw-2"}`, who: full, missing: "principal", mount: mountAssets, want: []string{setSecret}},
		// 匯入（B033）
		{name: "匯入預檢：掛共用憑證缺掛載能力", method: "POST", path: fixed("/api/v1/assets/import/preview"), body: importBody, who: manageOnly, mount: mountAssets, want: []string{bind}},
		{name: "匯入提交：掛共用憑證缺掛載能力", method: "POST", path: fixed("/api/v1/assets/import"), body: importBody, who: manageOnly, mount: mountAssets, want: []string{bind}},
		{name: "匯入提交：存取政策欄位缺存取政策能力", method: "POST", path: fixed("/api/v1/assets/import"), body: policyImport, who: createOnly, mount: mountAssets, want: []string{policy}},
		{name: "匯入提交：空主體記操作要求", method: "POST", path: fixed("/api/v1/assets/import"), body: importBody, who: full, userID: &zero, mount: mountAssets, want: []string{bind}},
		{name: "匯入預檢：主體不存在或停用記操作要求", method: "POST", path: fixed("/api/v1/assets/import/preview"), body: importBody, who: full, missing: "principal", mount: mountAssets, want: []string{bind}},
		// 資產帳號（B018）
		{name: "帳號建立：掛共用憑證缺掛載能力", method: "POST", path: accountsPath, body: `{"credential_id":%d}`, who: withCreate, mount: mountAccounts, want: []string{bind}},
		{name: "帳號建立：內嵌密碼缺建立能力", method: "POST", path: accountsPath, body: `{"username":"ops","password":"Pw-3"}`, who: manageOnly, mount: mountAccounts, want: []string{create}},
		{name: "帳號建立：帳號名欄位缺憑證建立能力", method: "POST", path: accountsPath, body: `{"username":"nopw"}`, who: updateOnly, mount: mountAccounts, want: []string{create}},
		{name: "帳號建立：主體不存在或停用記操作要求", method: "POST", path: accountsPath, body: `{"credential_id":%d}`, who: full, missing: "principal", mount: mountAccounts, want: []string{bind}},
		{name: "帳號更新：改密碼缺改秘密能力", method: "PUT", path: accountPath, body: `{"password":"Pw-4"}`, who: manageOnly, mount: mountAccounts, want: []string{setSecret}},
		{name: "帳號更新：改帳號名缺憑證更新能力", method: "PUT", path: accountPath, body: `{"username":"renamed"}`, who: updateOnly, mount: mountAccounts, want: []string{credUpdate}},
		{name: "帳號建立：錯誤值未附鍵（掛載拒絕）退回路由要求", method: "POST", path: accountsPath, body: `{"username":"x"}`, who: manageOnly, mount: mountAccountsReturning(asset.ErrCredentialBindForbidden), want: []string{upd}},
		{name: "帳號更新：錯誤值未附鍵（欄位能力，包裝）退回路由要求", method: "PUT", path: accountPath, body: `{"username":"x"}`, who: manageOnly, mount: mountAccountsReturning(fmt.Errorf("更新帳號失敗: %w", asset.ErrFieldCapabilityDenied)), want: []string{upd}},
		// 批次改密（B061）
		{name: "批次改密：缺帳號改密能力", method: "POST", path: fixed("/api/v1/change-secret-batches"), body: batchBody, who: batcher, mount: mountBatches, want: []string{rotate}},
		{name: "批次改密：整批同一組缺憑證建立能力", method: "POST", path: fixed("/api/v1/change-secret-batches"), body: sharedBatch, who: batcherNoCreate, mount: mountBatches, want: []string{create}},
		{name: "批次改密：空主體記操作要求", method: "POST", path: fixed("/api/v1/change-secret-batches"), body: batchBody, who: batcherFull, userID: &zero, mount: mountBatches, want: []string{rotate}},
		{name: "批次改密：主體不存在或停用記操作要求（整批同一組）", method: "POST", path: fixed("/api/v1/change-secret-batches"), body: sharedBatch, who: batcherFull, missing: "principal", mount: mountBatches, want: []string{rotate, create, bind}},
	}
	return cases
}

type markerAllowCase struct {
	markerCase
	status int
}

func markerAllowCases() []markerAllowCase {
	full := customPrincipal(authz.PermAssetView, authz.PermAssetCreate, authz.PermAssetUpdate, authz.PermCredentialManage,
		authz.PermCredentialCreate, authz.PermCredentialBind, authz.PermCredentialSetSecret, authz.PermAccessPolicyManage)
	// 批次改密放行會啟動背景執行器（本夾具未注入），放行面由既有批次測試承擔
	return []markerAllowCase{
		{markerCase{name: "資產建立掛共用憑證", method: "POST", path: fixed("/api/v1/assets"),
			body: `{"name":"ok-new","protocol":"ssh","host":"10.9.0.3","port":22,"credential_id":%d}`, who: full, mount: mountAssets}, http.StatusCreated},
		{markerCase{name: "資產更新改密碼", method: "PUT", path: func(s markerSeed) string { return fmt.Sprintf("/api/v1/assets/%d", s.assetID) },
			body: `{"password":"Pw-9"}`, who: full, mount: mountAssets}, http.StatusOK},
		{markerCase{name: "匯入預檢掛共用憑證", method: "POST", path: fixed("/api/v1/assets/import/preview"),
			body: `{"source":"form","rows":[{"name":"ok-i","protocol":"ssh","host":"10.9.2.1","credential_id":%d}]}`, who: full, mount: mountAssets}, http.StatusOK},
		{markerCase{name: "帳號建立掛共用憑證", method: "POST", path: func(s markerSeed) string { return fmt.Sprintf("/api/v1/assets/%d/accounts", s.assetID) },
			body: `{"credential_id":%d}`, who: full, mount: mountAccounts}, http.StatusCreated},
	}
}

// bodyFor 代入種子共用憑證 ID（本文以 %d 佔位者）。
func (c markerCase) bodyFor(s markerSeed) string {
	if strings.Contains(c.body, "%d") {
		return fmt.Sprintf(c.body, s.credID)
	}
	return c.body
}

type markerRoleCase struct {
	name string
	run  func() shapeProbe
}

// markerRoleCases 角色定義四種寫入：以正式服務在交易內重驗操作者（不存在、停用、agent、非超管
// 同一哨兵），另以替身驗包裝後的哨兵。
func markerRoleCases(t *testing.T) []markerRoleCase {
	env := newOwnerTransferEnv(t)
	inactive := model.User{Username: "gone", Active: true, Kind: model.KindHuman}
	require.NoError(t, env.db.Create(&inactive).Error)
	require.NoError(t, env.db.Model(&model.User{}).Where("id = ?", inactive.ID).Update("active", false).Error)
	svc := identity.NewRoleDefinitionService(env.db, audit.NewTxSink(), nil, nil)
	wrapped := failingRoleWriter{err: fmt.Errorf("寫入角色失敗: %w", identity.ErrRoleDefinitionForbidden)}

	actors := []struct {
		label string
		id    uint
	}{
		{"操作者不存在", 999}, {"操作者停用", inactive.ID}, {"操作者為 agent", otAgentX}, {"非超管", otUserU},
	}
	verbs := []struct {
		label, method, path, body string
	}{
		{"新增", "POST", "/api/v1/role-definitions", `{"name":"r1","permissions":["asset:view"]}`},
		{"複製", "POST", "/api/v1/role-definitions/1/copy", `{"name":"r2"}`},
		{"修改", "PUT", "/api/v1/role-definitions/1", `{"name":"r3","permissions":[],"expected_version":1}`},
		{"刪除", "DELETE", "/api/v1/role-definitions/1?expected_version=1", ""},
	}
	var out []markerRoleCase
	for _, v := range verbs {
		v := v
		for _, a := range actors {
			a := a
			out = append(out, markerRoleCase{name: v.label + "：" + a.label, run: func() shapeProbe {
				return markerServe(principalOf(model.BuiltinUser, ""), a.id, v.method, v.path, v.body, mountRoles(svc))
			}})
		}
		out = append(out, markerRoleCase{name: v.label + "：包裝後的哨兵", run: func() shapeProbe {
			return markerServe(principalOf(model.BuiltinUser, ""), otUserU, v.method, v.path, v.body, mountRoles(wrapped))
		}})
	}
	return out
}

func mountRoles(w api.RoleDefinitionWriter) func(r gin.IRoutes) {
	return func(r gin.IRoutes) {
		h := api.NewRoleDefinitionHandler(nil, w)
		r.POST("/api/v1/role-definitions", middleware.EnforceRegistry(), h.Create)
		r.POST("/api/v1/role-definitions/:id/copy", middleware.EnforceRegistry(), h.Copy)
		r.PUT("/api/v1/role-definitions/:id", middleware.EnforceRegistry(), h.Update)
		r.DELETE("/api/v1/role-definitions/:id", middleware.EnforceRegistry(), h.Delete)
	}
}

type failingRoleWriter struct{ err error }

func (f failingRoleWriter) Create(context.Context, uint, identity.RoleInput) (*identity.RoleDefinition, error) {
	return nil, f.err
}

func (f failingRoleWriter) Copy(context.Context, uint, uint, string, string) (*identity.RoleDefinition, error) {
	return nil, f.err
}

func (f failingRoleWriter) Update(context.Context, uint, uint, int64, identity.RoleInput) (*identity.RoleDefinition, error) {
	return nil, f.err
}

func (f failingRoleWriter) Delete(context.Context, uint, uint, int64) error { return f.err }

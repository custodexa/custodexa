package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/api"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
)

// 範圍外資訊的回應出口夾具：三組選項（輪替、帳號寫入、改密）各自從同一個建構函式建一個獨立環境。
// 範圍外的名稱一律以 zz-so-out 起頭，且不得是任何合法可見字串的子字串（soCheckFixture 自檢）。
// 回應以原始本文比對，不以重新序列化的物件代替。

const (
	soNodeIn   = "zz-so-in"
	soNodeOut  = "zz-so-out"
	soNodeGone = "zz-so-gone"
)

// soToken 禁止出現在回應原文的內容：名稱以子字串比對；數字識別以鍵加值加 JSON 邊界比對。
type soToken struct {
	Name string
	Key  string
	ID   uint
}

func soName(n string) soToken           { return soToken{Name: n} }
func soNum(key string, id uint) soToken { return soToken{Key: key, ID: id} }

func (t soToken) String() string {
	if t.Name != "" {
		return t.Name
	}
	return fmt.Sprintf("%q:%d", t.Key, t.ID)
}

func (t soToken) pattern() *regexp.Regexp {
	return regexp.MustCompile(fmt.Sprintf(`"%s"\s*:\s*%d(?:[,}\]\s]|$)`, regexp.QuoteMeta(t.Key), t.ID))
}

// soFindLeaks 純函式：回傳原文中命中的 token。
func soFindLeaks(raw string, forbidden []soToken) []string {
	var hits []string
	for _, t := range forbidden {
		if t.Name != "" {
			if strings.Contains(raw, t.Name) {
				hits = append(hits, t.String())
			}
			continue
		}
		if t.pattern().MatchString(raw) {
			hits = append(hits, t.String())
		}
	}
	return hits
}

// soAssertNoLeak raw 必須是 HTTP 原始本文。先判外洩（LEAK:），再判必含字串（PRECONDITION:）。
func soAssertNoLeak(t *testing.T, raw string, forbidden []soToken, mustContain []string) {
	t.Helper()
	if hits := soFindLeaks(raw, forbidden); len(hits) > 0 {
		t.Fatalf("LEAK: 回應原文含範圍外內容 %v\n本文: %s", hits, raw)
	}
	for _, s := range mustContain {
		if !strings.Contains(raw, s) {
			t.Fatalf("PRECONDITION: 回應原文缺少 %q\n本文: %s", s, raw)
		}
	}
}

// soAssertOK 狀態碼與外框鍵；不符以 PRECONDITION: 失敗，必須在 soAssertNoLeak 之前呼叫。
func soAssertOK(t *testing.T, code int, raw string, wantCode int, wantTopKeys []string) {
	t.Helper()
	if code != wantCode {
		t.Fatalf("PRECONDITION: 狀態碼 %d，預期 %d\n本文: %s", code, wantCode, raw)
	}
	var top map[string]any
	if err := json.Unmarshal([]byte(raw), &top); err != nil {
		t.Fatalf("PRECONDITION: 本文不是 JSON 物件: %v\n本文: %s", err, raw)
	}
	for _, k := range wantTopKeys {
		if _, ok := top[k]; !ok {
			t.Fatalf("PRECONDITION: 外框缺少鍵 %q\n本文: %s", k, raw)
		}
	}
}

// soCheckFixture 夾具自檢：禁止名稱不得是合法可見字串的子字串；禁止的（鍵, 值）不得等於合法可見實體的（鍵, 值）。
func soCheckFixture(t *testing.T, forbidden, visible []soToken) {
	t.Helper()
	for _, f := range forbidden {
		for _, v := range visible {
			if f.Name != "" && v.Name != "" && strings.Contains(v.Name, f.Name) {
				t.Fatalf("FIXTURE: 禁止名稱 %q 是可見字串 %q 的子字串", f.Name, v.Name)
			}
			if f.Name == "" && v.Name == "" && f.Key == v.Key && f.ID == v.ID {
				t.Fatalf("FIXTURE: 禁止的 %s 與可見實體相同", f)
			}
		}
	}
}

// soRotations 輪替包裝：嵌入真實服務，背景推進為空操作；逐台補跑不連遠端，只回固定的主機身分檢視。
type soRotations struct {
	*asset.CredentialRotationService
}

func (soRotations) Run(context.Context, uint) error { return nil }

func (soRotations) RunMemberResult(context.Context, uint, uint, asset.RotationRecordOrigin) (*asset.MemberRunResult, error) {
	return &asset.MemberRunResult{HostIdentity: &asset.HostIdentityView{Status: "changed", Detail: "zz-so-hostid"}}, nil
}

// soOpt 夾具選項。
type soOpt func(*outEnv)

// outEnv 一個獨立環境。
type outEnv struct {
	*scEnv
	// 主體
	mgr, rotWide, bindOnly, glb, glbNoView, glbCompat, glbCsOnly, csMixed, csGone uint

	// 輪替選項
	rot      soRotations
	rotCred  uint
	rotIn    []uint
	rotOut   []uint
	rotInAcc []uint

	// 帳號寫入與改密選項共用的全域憑證與帳號
	gcred, gcredAcc uint
	// 帳號寫入選項
	bindSrc, assetU, assetC, assetB, assetR, accR, rebindFrom uint
	// 改密選項
	inCred, accI, assetIn0, assetIn1, assetOut0, histCred, histNext uint
	plans                                                           *asset.ChangeSecretPlanService
	batches                                                         *asset.ChangeSecretBatchService
	candidates                                                      *asset.ChangeSecretCandidateService
	csScope                                                         *authz.ChangeSecretScope
}

// newOutEnv 建構函式：節點、主體與選項資料。
func newOutEnv(t *testing.T, opts ...soOpt) *outEnv {
	t.Helper()
	e := &outEnv{scEnv: newSCEnv(t)}
	e.node(soNodeIn, "")
	e.node(soNodeOut, "")
	e.node(soNodeGone, "")

	mgrPerms := append(append([]authz.Permission{}, saPerms...), scCredentialPerms...)
	mgrPerms = append(mgrPerms, authz.PermAccountRotate, authz.PermChangeSecretManage)
	e.mgr = e.user("zz-so-mgr")
	e.grant(e.mgr, []string{soNodeIn}, mgrPerms...)

	e.rotWide = e.user("zz-so-rotwide")
	e.grantNodes(e.rotWide, e.role(authz.PermAssetView, authz.PermCredentialRotate), soNodeIn, soNodeOut)
	e.grantNodes(e.rotWide, e.role(authz.PermCredentialView), soNodeIn)

	e.bindOnly = e.user("zz-so-bindonly")
	e.grant(e.bindOnly, []string{soNodeIn}, authz.PermAssetView, authz.PermAssetUpdate, authz.PermCredentialBind)

	e.glb = e.user("zz-so-glb")
	e.grantGlobal(e.glb, e.role(mgrPerms...))
	e.glbNoView = e.user("zz-so-glbnoview")
	e.grantGlobal(e.glbNoView, e.role(authz.PermAssetView, authz.PermAssetUpdate))
	e.glbCompat = e.user("zz-so-glbcompat")
	e.grantGlobal(e.glbCompat, e.role(authz.PermAssetView, authz.PermAssetUpdate, authz.PermCredentialManage))
	e.glbCsOnly = e.user("zz-so-glbcsonly")
	e.grantGlobal(e.glbCsOnly, e.role(authz.PermAssetView, authz.PermAccountRotate, authz.PermChangeSecretManage))

	e.csMixed = e.user("zz-so-csmixed")
	e.grantGlobal(e.csMixed, e.role(authz.PermChangeSecretManage))
	e.grant(e.csMixed, []string{soNodeIn}, authz.PermAssetView, authz.PermAccountRotate)

	e.csGone = e.user("zz-so-csgone")
	e.grantGlobal(e.csGone, e.role(authz.PermChangeSecretManage))
	e.grant(e.csGone, []string{soNodeIn}, authz.PermAssetView, authz.PermAccountRotate)
	e.grant(e.csGone, []string{soNodeGone}, authz.PermCredentialView)
	// 檢視指派所在節點軟刪除（指派列保留），使該檢視指派的有效節點為空
	require.NoError(t, e.db.Delete(&model.AssetGroup{}, e.nodes[soNodeGone]).Error)

	for _, o := range opts {
		o(e)
	}
	return e
}

// soCred 建立共用憑證，帳號名明訂。
func (e *outEnv) soCred(name, username string, node *uint) uint {
	e.t.Helper()
	kind := model.CredentialOwnerGlobal
	if node != nil {
		kind = model.CredentialOwnerNode
	}
	c := model.Credential{Name: &name, Scope: model.CredentialScopeShared, Username: username,
		SecretType: model.ChangeSecretTypePassword, AuthMethod: "sql",
		ProtocolFamily: model.ProtocolFamilySSH, OwnerKind: &kind, OwnerNodeID: node}
	require.NoError(e.t, e.db.Create(&c).Error)
	return c.ID
}

// soWithRotation 輪替選項：共用憑證掛範圍內二台與範圍外三台。
func soWithRotation() soOpt {
	return func(e *outEnv) {
		e.rotCred = e.soCred("zz-so-rot", "zz-so-rot-user", e.nodeID(soNodeIn))
		for i := 0; i < 2; i++ {
			a := e.asset(fmt.Sprintf("zz-so-asset-in-%d", i), soNodeIn)
			e.rotIn = append(e.rotIn, a)
			e.rotInAcc = append(e.rotInAcc, e.mount(e.rotCred, a))
		}
		for i := 0; i < 3; i++ {
			a := e.asset(fmt.Sprintf("zz-so-out-asset-%d", i), soNodeOut)
			e.rotOut = append(e.rotOut, a)
			e.mount(e.rotCred, a)
		}
		// 脫離（拆分）會建立候選，服務必須存在；資料表只在此處補建
		require.NoError(e.t, e.db.AutoMigrate(&model.ChangeSecretCandidate{}, &model.CredentialJobAuthorization{}))
		cands, err := asset.NewChangeSecretCandidateService(e.db, e.codec, e.assets, audit.NewTxSink())
		require.NoError(e.t, err)
		e.rot = soRotations{asset.NewCredentialRotationService(e.db, e.assets, cands, nil, e.codec, audit.NewTxSink(), e.adapter).
			WithScopeSource(authz.NewCredentialScopeReader(e.eval, e.db)).WithSystemAlertSink(noopAlertSink{}).
			WithOutputScope(authz.NewCredentialScopeReader(e.eval, e.db))}
	}
}

// soWithAccounts 帳號寫入選項（與輪替選項不共用憑證）。
func soWithAccounts() soOpt {
	return func(e *outEnv) {
		e.gcred = e.soCred("zz-so-out-gcred", "zz-so-g", nil)
		e.assetU = e.asset("zz-so-asset-u", soNodeIn)
		e.gcredAcc = e.mount(e.gcred, e.assetU)
		e.bindSrc = e.soCred("zz-so-out-bindsrc", "zz-so-bind-user", e.nodeID(soNodeIn))
		e.assetC = e.asset("zz-so-asset-c", soNodeIn)
		e.assetB = e.asset("zz-so-asset-b", soNodeIn)
		e.assetR = e.asset("zz-so-asset-r", soNodeIn)
		e.rebindFrom = e.soCred("zz-so-rebind-from", "zz-so-r-user", e.nodeID(soNodeIn))
		e.accR = e.mount(e.rebindFrom, e.assetR)
	}
}

// soWithChangeSecret 改密選項：全域憑證與範圍內憑證同帳號名，各掛範圍內一台。
func soWithChangeSecret() soOpt {
	return func(e *outEnv) {
		require.NoError(e.t, e.db.AutoMigrate(&model.ChangeSecretPlan{}, &model.ChangeSecretRecord{},
			&model.ChangeSecretCandidate{}, &model.ChangeSecretBatch{}, &model.CredentialJobAuthorization{}))
		e.gcred = e.soCred("zz-so-out-gcred", "zz-so-g", nil)
		e.assetIn0 = e.asset("zz-so-asset-in-0", soNodeIn)
		e.assetIn1 = e.asset("zz-so-asset-in-1", soNodeIn)
		e.assetOut0 = e.asset("zz-so-out-asset-0", soNodeOut)
		e.gcredAcc = e.mount(e.gcred, e.assetIn0)
		e.inCred = e.soCred("zz-so-in-cred", "zz-so-g", e.nodeID(soNodeIn))
		e.accI = e.mount(e.inCred, e.assetIn1)
		e.histCred = e.soCred("zz-so-out-hist", "zz-so-hist-user", e.nodeID(soNodeIn))
		e.histNext = e.soCred("zz-so-hist-next", "zz-so-hist-user", e.nodeID(soNodeIn))

		e.csScope = authz.NewChangeSecretScope(e.eval)
		e.plans = asset.NewChangeSecretPlanService(e.db)
		builder := asset.NewRotationReportBuilder(e.db, e.plans, func() int { return 90 })
		e.batches = asset.NewChangeSecretBatchService(e.db, builder).WithManagementAuthorizer(e.adapter).
			WithScope(e.csScope).WithOwnershipScope(authz.NewCredentialOwnershipScope(e.eval))
		cands, err := asset.NewChangeSecretCandidateService(e.db, e.codec, e.assets, audit.NewTxSink())
		require.NoError(e.t, err)
		e.candidates = cands.WithScope(e.csScope)
		e.plans.WithScope(e.csScope, authz.NewCredentialScopeReader(e.eval, e.db))
	}
}

// soServe 送出請求，回狀態碼與原始本文。
func soServe(r *gin.Engine, method, path, body string) (int, string) {
	var req *http.Request
	if body != "" {
		req = httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w.Code, w.Body.String()
}

// soRotationRouter 輪替路由組裝：正式 handler 加登錄閘。
func (e *outEnv) soRotationRouter(uid uint) *gin.Engine {
	r := gin.New()
	r.Use(middleware.AuditLogMiddleware(newCoverageAuditService()))
	r.Use(e.scPrincipal(uid))
	h := api.NewCredentialHandler(e.creds, e.rot, scStatus{})
	h.SetRotationMemberProjection(e.rot)
	reg := middleware.EnforceRegistry()
	g := r.Group("/api/v1/credentials")
	g.POST("/:id/impact-confirmations", reg, h.ConfirmImpact)
	g.POST("/:id/rotations", reg, h.StartRotation)
	g.GET("/:id/rotations/:rid", reg, h.GetRotation)
	g.POST("/:id/rotations/:rid/members/:mid/retry", reg, h.RetryMember)
	g.POST("/:id/rotations/:rid/abandon", reg, h.AbandonRotation)
	g.POST("/:id/bindings/:accountId/detach", reg, h.Detach)
	return r
}

// soAccountRouter 帳號寫入路由組裝：帳號 handler 與憑證 handler 的五個寫入出口。
func (e *outEnv) soAccountRouter(uid uint) *gin.Engine {
	return e.soAccountRouterWith(uid, authz.NewCredentialScopeReader(e.eval, e.db))
}

// soAccountRouterWith 同上，帳號 handler 的憑證投影來源由呼叫端指定（失權時序測試的包裝）。
func (e *outEnv) soAccountRouterWith(uid uint, scope api.AccountCredentialScope) *gin.Engine {
	r := gin.New()
	r.Use(middleware.AuditLogMiddleware(newCoverageAuditService()))
	r.Use(e.scPrincipal(uid))
	svc := asset.NewAssetAccountService(e.assets, e.codec, audit.NewTxSink()).
		WithManagementAuthorizer(e.adapter).WithSystemAlertSink(noopAlertSink{}).
		WithAccountWriteScope(authz.NewAssetWriteScope(e.eval))
	h := api.NewAssetAccountHandler(svc, e.authzSvc)
	ch := api.NewCredentialHandler(e.creds, scRotations{}, scStatus{})
	h.SetAccountRowActions(asset.NewAccountRowActionJudge(e.creds, svc))
	reader := authz.NewCredentialScopeReader(e.eval, e.db)
	h.SetAccountCredentialScope(scope)
	ch.SetAccountRowProjector(reader, asset.NewAccountRowActionJudge(e.creds, svc))
	reg := middleware.EnforceRegistry()
	r.POST("/api/v1/assets/:id/accounts", reg, h.Create)
	r.PUT("/api/v1/assets/:id/accounts/:accountId", reg, h.Update)
	r.POST("/api/v1/assets/:id/accounts/:accountId/set-default", reg, h.SetDefault)
	r.PUT("/api/v1/assets/:id/accounts/:accountId/credential", reg, ch.RebindAccount)
	r.POST("/api/v1/credentials/:id/bindings", reg, ch.Bind)
	return r
}

// soChangeSecretRouter 改密路由組裝：批次目標、批次詳情、計畫紀錄與候選。
func (e *outEnv) soChangeSecretRouter(uid uint) *gin.Engine {
	return e.soChangeSecretRouterWith(uid, authz.NewCredentialScopeReader(e.eval, e.db))
}

// soChangeSecretRouterWith 同上，輸出判定來源由呼叫端指定（失權時序測試的包裝）。
func (e *outEnv) soChangeSecretRouterWith(uid uint, src asset.CredentialOutputScopeSource) *gin.Engine {
	r := gin.New()
	r.Use(middleware.AuditLogMiddleware(newCoverageAuditService()))
	r.Use(e.scPrincipal(uid))
	h := api.NewChangeSecretHandler(e.plans, nil, e.candidates, nil, e.batches, nil)
	h.SetCredentialOutputScope(src)
	reg := middleware.EnforceRegistry()
	r.GET("/api/v1/change-secret-batches/targets", reg, h.BatchTargets)
	r.GET("/api/v1/change-secret-batches/:id", reg, h.GetBatch)
	r.GET("/api/v1/change-secret-plans", reg, h.List)
	r.POST("/api/v1/change-secret-plans", reg, h.Create)
	r.PUT("/api/v1/change-secret-plans/:id", reg, h.Update)
	r.GET("/api/v1/change-secret-plans/:id/records", reg, h.Records)
	r.GET("/api/v1/change-secret-candidates", reg, h.ListCandidates)
	return r
}

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/custodexa/backend/internal/api"
	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/authz/disclosure"
)

// TestGlobalNameConflictSameShape 全域唯一名稱衝突的回應不因衝突對象在不在範圍內而不同。
//
// 名稱在全系統唯一的物件，範圍化管理者建立時撞名：若回應依衝突對象是否落在自己的
// 管理範圍而有差異，建立請求就成了範圍外物件的存在性探測器。本測試對每個衝突寫出點
// 各建一案，以注入測試目錄讓節點範圍的指派生效，同一個範圍化主體送出逐位元相同的請求，
// 兩次只差在衝突對象掛在範圍內節點或範圍外節點（各自一份全新資料庫、相同的建立次序，
// 識別碼因此一致）；兩次回應的狀態碼與本文必須逐位元相同。
//
// 寫出點：資產建立、共用憑證建立、批次改密轉共用憑證、改密計畫建立、改密報告排程建立
// （皆為無參數 409，本文只有 code、error）；資產匯入的預檢列錯誤（400，逐列錯誤在 meta）
// 與交易內重驗的列錯誤（409，逐列錯誤在 meta）。

// conflictFullOutputScope 改密計畫建立的輸出判定替身：本測試只比衝突回應的形狀，
// 成功建立的夾具回應不是被測對象，一律視為可見全部內容。
type conflictFullOutputScope struct{}

type conflictFullScope struct{}

func (conflictFullScope) Full() bool { return true }

func (conflictFullScope) AssetsInView(ids []uint) (map[uint]bool, error) {
	return map[uint]bool{}, nil
}

func (conflictFullScope) CredentialsInView(ids []uint) (map[uint]bool, error) {
	return map[uint]bool{}, nil
}

func (conflictFullOutputScope) CredentialOutputScope(context.Context) (asset.CredentialOutputScope, error) {
	return conflictFullScope{}, nil
}

// conflictTakenName 每案衝突對象與請求共用的名稱。
const conflictTakenName = "taken-name"

// conflictPlacement 衝突對象相對於範圍化主體的位置。
type conflictPlacement string

const (
	placedInScope    conflictPlacement = "與範圍內既有同名"
	placedOutOfScope conflictPlacement = "與範圍外既有同名"
)

// conflictEnv 一份全新資料庫上的夾具：兩個節點、一個範圍化主體與全部被測路由。
type conflictEnv struct {
	*fieldCapEnv
	nodeIn, nodeOut uint
	scoped          *authz.Principal
	seeder          *authz.Principal
	plans           *asset.ChangeSecretPlanService
	batches         *asset.ChangeSecretBatchService
	schedules       *asset.RotationReportScheduleService
}

// conflictScopedPerms 範圍化主體經節點指派持有的權限點（注入目錄改標為範圍生效）。
var conflictScopedPerms = []authz.Permission{
	authz.PermAssetCreate, authz.PermAssetView, authz.PermCredentialManage, authz.PermChangeSecretManage,
}

func newConflictEnv(t *testing.T) *conflictEnv {
	t.Helper()
	base := newFieldCapEnv(t)
	if err := base.db.AutoMigrate(&model.ChangeSecretPlan{}, &model.ChangeSecretBatch{},
		&model.RotationReportSchedule{}, &model.CredentialJobAuthorization{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	env := &conflictEnv{fieldCapEnv: base}
	env.nodeIn = conflictNode(t, env, "scope-in")
	env.nodeOut = conflictNode(t, env, "scope-out")

	cat, err := authz.CatalogueWithScopedEnforcedForTest(conflictScopedPerms...)
	if err != nil {
		t.Fatalf("注入目錄：%v", err)
	}
	env.scoped = authz.NewPrincipalOn(cat, 7, authz.TokenFacts{}, []authz.Assignment{
		{RoleName: "scoped-manager", Via: authz.ViaDirect, Scope: model.ScopeKindNodes,
			LiveNodeIDs: []uint{env.nodeIn}, Permissions: conflictScopedPerms, Custom: true},
		// 報告排程權限點只能全域生效（節點指派不授予），故另以全域指派持有；
		// 主體的資產類能力仍只限範圍內節點
		{RoleName: "schedule-manager", Via: authz.ViaDirect, Scope: model.ScopeKindGlobal,
			Permissions: []authz.Permission{authz.PermRotationSchedule}, Custom: true},
	})
	var all []authz.Permission
	for _, d := range authz.Catalog() {
		all = append(all, d.Key)
	}
	env.seeder = customPrincipal(all...)
	env.plans = asset.NewChangeSecretPlanService(base.db)
	// 批次建立先判模式所需能力、名稱查重在其後；本測試只比衝突回應的形狀，能力以放行替身視為具備
	env.batches = asset.NewChangeSecretBatchService(base.db, nil).WithManagementAuthorizer(fieldCapSeedAuthorizer{}).
		WithOwnershipScope(globalOwnershipScopeForTest{})
	env.schedules = asset.NewRotationReportScheduleService(base.db, nil, nil)
	return env
}

func conflictNode(t *testing.T, env *conflictEnv, name string) uint {
	t.Helper()
	n := model.AssetGroup{Name: name}
	if err := env.db.Create(&n).Error; err != nil {
		t.Fatalf("建節點 %s：%v", name, err)
	}
	return n.ID
}

// router 被測路由，各掛正式登錄閘；請求脈絡帶入本次主體。
func (e *conflictEnv) router(p *authz.Principal) *gin.Engine {
	assets := api.NewAssetHandler(e.assets, nil, nil)
	creds := api.NewCredentialHandler(e.creds, nil, nil)
	secrets := api.NewChangeSecretHandler(e.plans, nil, nil, nil, e.batches, nil)
	secrets.SetCredentialOutputScope(conflictFullOutputScope{})
	reports := api.NewRotationReportHandler(nil, e.schedules, nil)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("userID", uint(7))
		c.Set("username", "scoped-manager")
		middleware.SetPrincipal(c, p)
	})
	v1 := r.Group("/api/v1")
	v1.POST("/assets", middleware.EnforceRegistry(), assets.Create)
	v1.POST("/assets/import/preview", middleware.EnforceRegistry(), assets.PreviewImport)
	v1.POST("/assets/import", middleware.EnforceRegistry(), assets.Import)
	v1.POST("/credentials", middleware.EnforceRegistry(), creds.Create)
	v1.POST("/change-secret-batches", middleware.EnforceRegistry(), secrets.CreateBatch)
	v1.POST("/change-secret-plans", middleware.EnforceRegistry(), secrets.Create)
	v1.POST("/rotation-report/schedules", middleware.EnforceRegistry(), reports.CreateSchedule)
	return r
}

// send 以指定主體送一個 JSON 請求，回狀態與原始本文。
func (e *conflictEnv) send(p *authz.Principal, method, path, body string) (int, string) {
	e.current = p
	defer func() { e.current = nil }()
	req := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	e.router(p).ServeHTTP(w, req)
	return w.Code, w.Body.String()
}

// mustCreate 夾具建立：以全權主體送出並要求成功，回新列 ID。
func (e *conflictEnv) mustCreate(t *testing.T, path, body string) uint {
	t.Helper()
	code, resp := e.send(e.seeder, http.MethodPost, path, body)
	if code != http.StatusCreated {
		t.Fatalf("夾具建立 %s：狀態 %d：%s", path, code, resp)
	}
	var out struct {
		ID   uint `json:"id"`
		Data struct {
			ID uint `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(resp), &out); err != nil {
		t.Fatalf("夾具建立 %s：本文無法解析：%s", path, resp)
	}
	if out.ID == 0 {
		out.ID = out.Data.ID
	}
	if out.ID == 0 {
		t.Fatalf("夾具建立 %s：回應無 id：%s", path, resp)
	}
	return out.ID
}

// node 依位置取衝突對象要掛的節點。
func (e *conflictEnv) node(at conflictPlacement) uint {
	if at == placedInScope {
		return e.nodeIn
	}
	return e.nodeOut
}

// assetBody 資產建立本文（不帶任何秘密或憑證欄位）。
func assetBody(name, host string, node uint) string {
	return fmt.Sprintf(`{"name":%q,"protocol":"ssh","host":%q,"port":22,"node_ids":[%d]}`, name, host, node)
}

// requireAssetPlacement 確認資產確實落在預期節點（範圍內外的區別是真的，不是名目）。
func (e *conflictEnv) requireAssetPlacement(t *testing.T, assetID uint, at conflictPlacement) {
	t.Helper()
	cover, ok, err := asset.NewScopeTopologyReader().AssetCoverNodes(e.db, assetID)
	if err != nil || !ok {
		t.Fatalf("讀資產 %d 的掛載節點：ok=%v err=%v", assetID, ok, err)
	}
	want, other := e.node(at), e.nodeIn+e.nodeOut-e.node(at)
	if !containsID(cover, want) || containsID(cover, other) {
		t.Fatalf("資產 %d 掛載 %v，應只在節點 %d（%s）", assetID, cover, want, at)
	}
}

func containsID(ids []uint, id uint) bool {
	for _, x := range ids {
		if x == id {
			return true
		}
	}
	return false
}

// conflictCase 一個衝突寫出點。
type conflictCase struct {
	name string
	// code 回應本文的頂層碼；rowCode 非空時為列錯誤（逐列錯誤在 meta.rows）的碼
	code    apierror.ErrCode
	rowCode apierror.ErrCode
	status  int
	// seedsDuringRequest 衝突對象在請求處理中途才建立（交易內重驗），不做「零變更」比對
	seedsDuringRequest bool
	// seed 依位置建立衝突對象與請求所需的其他夾具（兩個位置的建立次序必須一致）
	seed func(t *testing.T, e *conflictEnv, at conflictPlacement)
	// method、path、body 範圍化主體送出的請求（兩次逐位元相同）
	method, path, body string
}

// seedConflictAsset 名為衝突名的資產，掛在依位置決定的節點。
func seedConflictAsset(t *testing.T, e *conflictEnv, at conflictPlacement) {
	t.Helper()
	id := e.mustCreate(t, "/api/v1/assets", assetBody(conflictTakenName, "10.9.0.1", e.node(at)))
	e.requireAssetPlacement(t, id, at)
}

// seedConflictCredential 名為衝突名的共用憑證，掛在一台依位置決定節點的資產上。
func seedConflictCredential(t *testing.T, e *conflictEnv, at conflictPlacement) {
	t.Helper()
	credID := e.mustCreate(t, "/api/v1/credentials",
		fmt.Sprintf(`{"name":%q,"username":"ops","password":"pw","protocol_family":%q}`,
			conflictTakenName, model.ProtocolFamilySSH))
	holder := e.mustCreate(t, "/api/v1/assets", fmt.Sprintf(
		`{"name":"holder","protocol":"ssh","host":"10.9.0.2","port":22,"node_ids":[%d],"credential_id":%d}`,
		e.node(at), credID))
	e.requireAssetPlacement(t, holder, at)
	var n int64
	if err := e.db.Model(&model.AssetAccount{}).
		Where("asset_id = ? AND credential_id = ?", holder, credID).Count(&n).Error; err != nil || n != 1 {
		t.Fatalf("共用憑證應掛在資產 %d 上：n=%d err=%v", holder, n, err)
	}
}

// seedConflictPlan 名為衝突名的改密計畫，目標為依位置決定節點的資產；另建一台範圍內資產供請求使用。
func seedConflictPlan(t *testing.T, e *conflictEnv, at conflictPlacement) {
	t.Helper()
	target := e.mustCreate(t, "/api/v1/assets", assetBody("plan-target", "10.9.0.3", e.node(at)))
	e.requireAssetPlacement(t, target, at)
	e.mustCreate(t, "/api/v1/assets", assetBody("request-target", "10.9.0.4", e.nodeIn))
	e.mustCreate(t, "/api/v1/change-secret-plans",
		fmt.Sprintf(`{"name":%q,"asset_ids":[%d],"cron":"0 3 * * *"}`, conflictTakenName, target))
}

// seedConflictSchedule 名為衝突名的報告排程，報告範圍為依位置決定的節點。
func seedConflictSchedule(t *testing.T, e *conflictEnv, at conflictPlacement) {
	t.Helper()
	id := e.mustCreate(t, "/api/v1/rotation-report/schedules", scheduleBody(e.node(at)))
	var row model.RotationReportSchedule
	if err := e.db.First(&row, id).Error; err != nil || row.ScopeKind != model.RotationScopeNode || row.ScopeID != e.node(at) {
		t.Fatalf("排程範圍應為節點 %d：%+v err=%v", e.node(at), row, err)
	}
}

func scheduleBody(node uint) string {
	return fmt.Sprintf(`{"name":%q,"cron":"0 3 * * *","enabled":true,"scope_kind":%q,"scope_id":%d,`+
		`"retention_days":30,"language":%q}`, conflictTakenName, model.RotationScopeNode, node,
		model.NotificationChannelLanguageZhTW)
}

// importBody 匯入本文：一列，名稱為衝突名，掛範圍內節點（節點 ID 在每份資料庫相同）。
func importBody(node uint) string {
	return fmt.Sprintf(`{"source":"form","rows":[{"name":%q,"protocol":"ssh","host":"10.9.1.1","node_ids":[%d]}]}`,
		conflictTakenName, node)
}

// conflictCases 全部寫出點。節點 ID 在每份全新資料庫相同（1＝範圍內、2＝範圍外），
// 請求本文以範圍內節點組裝；newConflictEnv 會核對此前提。
func conflictCases() []conflictCase {
	const nodeIn = 1
	return []conflictCase{
		{
			name: "資產建立", code: apierror.CodeAssetNameExists, status: http.StatusConflict,
			seed:   seedConflictAsset,
			method: http.MethodPost, path: "/api/v1/assets", body: assetBody(conflictTakenName, "10.9.2.1", nodeIn),
		},
		{
			name: "共用憑證建立", code: apierror.CodeCredentialNameExists, status: http.StatusConflict,
			seed:   seedConflictCredential,
			method: http.MethodPost, path: "/api/v1/credentials",
			body: fmt.Sprintf(`{"name":%q,"username":"ops","password":"pw2","protocol_family":%q}`,
				conflictTakenName, model.ProtocolFamilySSH),
		},
		{
			name: "批次改密轉共用憑證", code: apierror.CodeCredentialNameExists, status: http.StatusConflict,
			seed:   seedConflictCredential,
			method: http.MethodPost, path: "/api/v1/change-secret-batches",
			body: fmt.Sprintf(`{"username":"ops","all":true,"password_mode":%q,"credential_name":%q}`,
				model.BatchPasswordShared, conflictTakenName),
		},
		{
			name: "改密計畫建立", code: apierror.CodePlanNameExists, status: http.StatusConflict,
			seed: seedConflictPlan,
			// 請求目標為範圍內資產（第二台建立的資產，ID 恆為 2）
			method: http.MethodPost, path: "/api/v1/change-secret-plans",
			body: fmt.Sprintf(`{"name":%q,"asset_ids":[2],"cron":"0 4 * * *"}`, conflictTakenName),
		},
		{
			name: "改密報告排程建立", code: apierror.CodeReportNameExists, status: http.StatusConflict,
			seed:   seedConflictSchedule,
			method: http.MethodPost, path: "/api/v1/rotation-report/schedules", body: scheduleBody(nodeIn),
		},
		{
			name: "資產匯入預檢列錯誤", code: apierror.CodeAssetImportRowsInvalid, rowCode: apierror.CodeAssetNameExists,
			status: http.StatusBadRequest, seed: seedConflictAsset,
			method: http.MethodPost, path: "/api/v1/assets/import", body: importBody(nodeIn),
		},
		{
			name: "資產匯入預覽列錯誤", code: "", rowCode: apierror.CodeAssetNameExists,
			status: http.StatusOK, seed: seedConflictAsset,
			method: http.MethodPost, path: "/api/v1/assets/import/preview", body: importBody(nodeIn),
		},
		{
			name: "資產匯入交易內重驗列錯誤", code: apierror.CodeAssetImportStateChanged, rowCode: apierror.CodeAssetNameExists,
			status: http.StatusConflict, seedsDuringRequest: true,
			// 預檢通過之後、開交易之前才出現同名資產（模擬他人同時建立）
			seed: func(t *testing.T, e *conflictEnv, at conflictPlacement) {
				t.Helper()
				e.assets.SetImportPreTxHookForTest(func() {
					e.assets.SetImportPreTxHookForTest(nil)
					req := &asset.CreateAssetRequest{Name: conflictTakenName, Protocol: model.ProtocolSSH,
						Host: "10.9.0.9", Port: 22, NodeIDs: []uint{e.node(at)}}
					a, err := e.assets.Create(operatorCtx(), req)
					if err != nil {
						t.Errorf("預檢後建立同名資產：%v", err)
						return
					}
					e.requireAssetPlacement(t, a.ID, at)
				})
			},
			method: http.MethodPost, path: "/api/v1/assets/import", body: importBody(nodeIn),
		},
	}
}

// conflictProbe 一次請求的結果與衝突後的資料列數。
type conflictProbe struct {
	status int
	raw    string
	rows   map[string]int64
}

func (e *conflictEnv) tableCounts(t *testing.T) map[string]int64 {
	t.Helper()
	return map[string]int64{
		"assets":      e.count(t, &model.Asset{}),
		"credentials": e.count(t, &model.Credential{}),
		"plans":       e.count(t, &model.ChangeSecretPlan{}),
		"batches":     e.count(t, &model.ChangeSecretBatch{}),
		"schedules":   e.count(t, &model.RotationReportSchedule{}),
	}
}

// runConflict 在一份全新資料庫上依位置建夾具，再以範圍化主體送出被測請求。
func runConflict(t *testing.T, c conflictCase, at conflictPlacement) conflictProbe {
	t.Helper()
	env := newConflictEnv(t)
	t.Cleanup(func() { env.assets.SetImportPreTxHookForTest(nil) })
	if env.nodeIn != 1 || env.nodeOut != 2 {
		t.Fatalf("節點 ID 前提不成立：範圍內 %d、範圍外 %d", env.nodeIn, env.nodeOut)
	}
	for _, perm := range conflictScopedPerms {
		if !env.scoped.Has(perm) {
			t.Fatalf("範圍化主體應經節點指派持有 %s", perm)
		}
	}
	c.seed(t, env, at)
	before := env.tableCounts(t)
	status, raw := env.send(env.scoped, c.method, c.path, c.body)
	after := env.tableCounts(t)
	if !c.seedsDuringRequest && fmt.Sprint(before) != fmt.Sprint(after) {
		t.Errorf("%s／%s：被拒的建立改動了資料列：%v → %v", c.name, at, before, after)
	}
	return conflictProbe{status: status, raw: raw, rows: after}
}

// assertConflictShape 單次回應的外形：狀態、碼、無參數；409 類本文的鍵恰為 code、error。
func assertConflictShape(t *testing.T, c conflictCase, at conflictPlacement, p conflictProbe) {
	t.Helper()
	if p.status != c.status {
		t.Errorf("%s／%s：狀態 %d，應 %d：%s", c.name, at, p.status, c.status, p.raw)
		return
	}
	var body map[string]json.RawMessage
	if err := json.Unmarshal([]byte(p.raw), &body); err != nil {
		t.Errorf("%s／%s：本文非 JSON：%s", c.name, at, p.raw)
		return
	}
	if _, ok := body["params"]; ok {
		t.Errorf("%s／%s：本文帶 params：%s", c.name, at, p.raw)
	}
	if c.code != "" {
		var code string
		_ = json.Unmarshal(body["code"], &code)
		if code != string(c.code) {
			t.Errorf("%s／%s：碼 %q，應 %q：%s", c.name, at, code, c.code, p.raw)
		}
	}
	if c.rowCode == "" {
		keys := make([]string, 0, len(body))
		for k := range body {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		if strings.Join(keys, ",") != "code,error" {
			t.Errorf("%s／%s：本文鍵應恰為 code、error，實為 %v：%s", c.name, at, keys, p.raw)
		}
		return
	}
	if !strings.Contains(p.raw, `"`+string(c.rowCode)+`"`) {
		t.Errorf("%s／%s：列錯誤應含 %s：%s", c.name, at, c.rowCode, p.raw)
	}
	// 列內容只回顯請求自身（含請求所指的範圍內節點路徑），不得帶出衝突對象的節點或位址
	if strings.Contains(p.raw, "scope-out") || strings.Contains(p.raw, "10.9.0.") {
		t.Errorf("%s／%s：列錯誤帶出衝突對象的資訊：%s", c.name, at, p.raw)
	}
}

func TestGlobalNameConflictSameShape(t *testing.T) {
	t.Run("各碼登錄描述無參數", func(t *testing.T) {
		for _, code := range []apierror.ErrCode{
			apierror.CodeAssetNameExists, apierror.CodeCredentialNameExists, apierror.CodePlanNameExists,
			apierror.CodeReportNameExists, apierror.CodeAssetImportRowsInvalid, apierror.CodeAssetImportStateChanged,
		} {
			d, ok := apierror.DescriptorOf(code)
			if !ok {
				t.Errorf("%s 未登錄", code)
				continue
			}
			if len(d.Params) != 0 || d.AuditOnly {
				t.Errorf("%s 的登錄描述應無參數且為回應碼：%+v", code, d)
			}
			if strings.ContainsAny(d.ZhFallback, "{}%") {
				t.Errorf("%s 的文案含插值記號：%q", code, d.ZhFallback)
			}
		}
	})

	t.Run("揭露登錄的名稱衝突條目不輸出欄位", func(t *testing.T) {
		found := false
		for _, e := range disclosure.Entries() {
			if e.Kind != disclosure.GlobalNameConflict {
				continue
			}
			found = true
			if len(e.Fields) != 0 || len(e.RuleCodes) != 0 {
				t.Errorf("名稱衝突條目不得帶輸出欄位或計數碼：%+v", e)
			}
		}
		if !found {
			t.Error("揭露登錄缺名稱衝突條目")
		}
	})

	for _, c := range conflictCases() {
		c := c
		t.Run(c.name, func(t *testing.T) {
			in := runConflict(t, c, placedInScope)
			out := runConflict(t, c, placedOutOfScope)
			assertConflictShape(t, c, placedInScope, in)
			assertConflictShape(t, c, placedOutOfScope, out)
			t.Logf("%s：%d %s", placedInScope, in.status, in.raw)
			t.Logf("%s：%d %s", placedOutOfScope, out.status, out.raw)
			if in.status != out.status || in.raw != out.raw {
				t.Errorf("%s：範圍內外兩次回應不同\n%s：%d %s\n%s：%d %s",
					c.name, placedInScope, in.status, in.raw, placedOutOfScope, out.status, out.raw)
			}
			if fmt.Sprint(in.rows) != fmt.Sprint(out.rows) {
				t.Errorf("%s：範圍內外兩次的資料列數不同：%v／%v", c.name, in.rows, out.rows)
			}
		})
	}
}

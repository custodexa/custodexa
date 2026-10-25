package asset_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/api"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
)

// 改密計畫的範圍收斂：建立與修改（帳號目標整份拒絕、憑證目標同形、範圍化發起者的影響確認與掛載上界）、
// 讀取與操作投影（列表、修改、刪除、執行、記錄、一鍵重新授權）。夾具沿用批次改密的樹（bs-in／bs-out）。

type psEnv struct {
	*bsEnv
	svc       *asset.ChangeSecretPlanService
	h, legacy *api.ChangeSecretHandler
	// planCred 歸屬 bs-in 的共用憑證：範圍內 bs-in-1（兩個帳號）與 bs-in-2，範圍外 9 台
	planCred uint
	outIDs   []uint
	// remoteCalls 計畫 handler 所用 runner 的遠端呼叫累計（替身只計數、不連線）
	remoteCalls func() int64
}

func newPsEnv(t *testing.T) *psEnv {
	t.Helper()
	e := newBsEnv(t)
	require.NoError(t, e.db.AutoMigrate(&model.CredentialImpactConfirmation{}))
	p := &psEnv{bsEnv: e}
	p.svc = asset.NewChangeSecretPlanService(e.db).WithAuthorizer(e.mgmt).WithAuditSink(audit.NewTxSink()).
		WithScope(e.scope, authz.NewCredentialScopeReader(e.eval, e.db))
	runner := asset.NewChangeSecretRunner(e.db, nil, nil, nil, nil)
	p.remoteCalls = asset.CountRemoteCallsForTest(runner)
	p.h = api.NewChangeSecretHandler(p.svc, runner, nil, nil, nil, nil)
	p.legacy = api.NewChangeSecretHandler(asset.NewChangeSecretPlanService(e.db).WithAuthorizer(e.mgmt).
		WithAuditSink(audit.NewTxSink()), runner,
		nil, nil, nil, nil)
	p.planCred = p.credential("bs-plan-cred", "bs-in")
	e.account(e.assets["bs-in-1"], "pc", p.planCred)
	e.account(e.assets["bs-in-1"], "pc2", p.planCred)
	e.account(e.assets["bs-in-2"], "pc", p.planCred)
	for i := 1; i <= 9; i++ {
		id := e.asset(fmt.Sprintf("bs-out-p%d", i), "bs-out")
		e.account(id, "pc", p.planCred)
		p.outIDs = append(p.outIDs, id)
	}
	return p
}

func (p *psEnv) credential(name, node string) uint {
	p.t.Helper()
	owner, nodeID := model.CredentialOwnerNode, p.nodes[node]
	c := model.Credential{Name: &name, Scope: model.CredentialScopeShared, Username: "pc",
		ProtocolFamily: model.ProtocolFamilySSH, OwnerKind: &owner, OwnerNodeID: &nodeID}
	require.NoError(p.t, p.db.Create(&c).Error)
	return c.ID
}

func (p *psEnv) do(fn func(*gin.Context), method, userKey, path string, params gin.Params, body any) (int, []byte) {
	p.t.Helper()
	var rd *bytes.Reader
	if body != nil {
		b, err := json.Marshal(body)
		require.NoError(p.t, err)
		rd = bytes.NewReader(b)
	} else {
		rd = bytes.NewReader(nil)
	}
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(method, path, rd)
	c.Request.Header.Set("Content-Type", "application/json")
	c.Params = params
	uid := p.users[userKey]
	c.Set("userID", uid)
	c.Set("username", "bs-"+userKey)
	middleware.SetPrincipal(c, &authz.Principal{UserID: uid})
	fn(c)
	return w.Code, w.Body.Bytes()
}

func idParam(id uint) gin.Params { return gin.Params{{Key: "id", Value: fmt.Sprint(id)}} }

func accountPlanReq(name string, assetIDs ...uint) *asset.ChangeSecretPlanRequest {
	return &asset.ChangeSecretPlanRequest{Name: name, AssetIDs: assetIDs, Accounts: []string{"postgres"}}
}

func credPlanReq(name string, credID, anyAsset uint, confirmation string) *asset.ChangeSecretPlanRequest {
	return &asset.ChangeSecretPlanRequest{Name: name, AssetIDs: []uint{anyAsset}, TargetKind: model.PlanTargetCredential,
		TargetCredentialID: credID, ImpactConfirmationID: confirmation}
}

func (p *psEnv) planCount() int64 {
	var n int64
	require.NoError(p.t, p.db.Model(&model.ChangeSecretPlan{}).Count(&n).Error)
	return n
}

// confirm 寫一列影響確認（同確認端點的形狀）：操作者對該憑證輪替的範圍外資產集合
func (p *psEnv) confirm(userKey string, credID uint, outAssets []uint) string {
	p.t.Helper()
	ids, _ := json.Marshal(outAssets)
	id := fmt.Sprintf("%032x", time.Now().UnixNano())
	require.NoError(p.t, p.db.Where("credential_id = ? AND user_id = ? AND operation = ?", credID, p.users[userKey],
		model.CredentialImpactOpRotate).Delete(&model.CredentialImpactConfirmation{}).Error)
	require.NoError(p.t, p.db.Create(&model.CredentialImpactConfirmation{ID: id, CredentialID: credID,
		UserID: p.users[userKey], Operation: model.CredentialImpactOpRotate, OutOfScopeAssetIDs: string(ids)}).Error)
	return id
}

func (p *psEnv) planAuth(planID uint) model.CredentialJobAuthorization {
	p.t.Helper()
	var plan model.ChangeSecretPlan
	require.NoError(p.t, p.db.First(&plan, planID).Error)
	require.NotNil(p.t, plan.AuthorizationID)
	var row model.CredentialJobAuthorization
	require.NoError(p.t, p.db.First(&row, *plan.AuthorizationID).Error)
	return row
}

func (p *psEnv) mountsOf(credID uint) string {
	var ids []uint
	require.NoError(p.t, p.db.Model(&model.AssetAccount{}).Where("credential_id = ?", credID).
		Order("id ASC").Pluck("id", &ids).Error)
	b, _ := json.Marshal(ids)
	return string(b)
}

func (p *psEnv) create(userKey string, req *asset.ChangeSecretPlanRequest) (int, []byte) {
	return p.do(p.h.Create, http.MethodPost, userKey, "/api/v1/change-secret-plans", nil, req)
}

func requireCodeCount(t *testing.T, body []byte, code string, count int) {
	t.Helper()
	var out struct {
		Code   string         `json:"code"`
		Params map[string]any `json:"params"`
	}
	require.NoError(t, json.Unmarshal(body, &out), string(body))
	require.Equal(t, code, out.Code, string(body))
	require.Equal(t, map[string]any{"count": float64(count)}, out.Params, string(body))
}

func planIDOf(t *testing.T, body []byte) uint {
	var out struct {
		ID uint `json:"id"`
	}
	require.NoError(t, json.Unmarshal(body, &out))
	require.NotZero(t, out.ID)
	return out.ID
}

func TestScopedRotationPlanScope(t *testing.T) {
	t.Run("create_and_update_scope", testPlanCreateScope)
	t.Run("read_and_operation_projection", testPlanReadProjection)
	t.Run("update_rereads_plan_after_lock", testPlanUpdateRereadsAfterLock)
	t.Run("reauthorize_rereads_plan_after_lock", testPlanReauthorizeRereadsAfterLock)
	t.Run("global_records_after_delete", testPlanGlobalRecordsAfterDelete)
}

func testPlanCreateScope(t *testing.T) {
	p := newPsEnv(t)
	before := p.planCount()

	// 帳號目標：1 範圍外＋1 不存在 → 整份拒絕、只帶筆數
	code, body := p.create("scoped", accountPlanReq("mixed", p.assets["bs-out-1"], 999999))
	require.Equal(t, http.StatusNotFound, code, string(body))
	requireCodeCount(t, body, "NOTFOUND_BATCH_ITEMS_UNAVAILABLE", 2)
	require.Equal(t, before, p.planCount(), "計畫表不變")

	// 憑證目標：範圍外憑證與不存在憑證逐欄相同
	outCred := p.credential("bs-out-cred", "bs-out")
	p.account(p.assets["bs-out-1"], "oc", outCred)
	c1, b1 := p.create("scoped", credPlanReq("out-cred", outCred, p.assets["bs-in-1"], ""))
	c2, b2 := p.create("scoped", credPlanReq("out-cred", 999999, p.assets["bs-in-1"], ""))
	require.Equal(t, http.StatusNotFound, c1, string(b1))
	require.Equal(t, c1, c2)
	require.Equal(t, string(b2), string(b1))
	require.Equal(t, before, p.planCount())

	// 範圍化發起者未帶確認：回確認回應，只有範圍外台數、無名稱
	code, body = p.create("scoped", credPlanReq("cred-plan", p.planCred, p.assets["bs-in-1"], ""))
	require.Equal(t, http.StatusConflict, code, string(body))
	requireCodeCount(t, body, "RULE_CREDENTIAL_IMPACT_CONFIRMATION_REQUIRED", 9)
	p.noOutOfScopeNames(body)
	require.Equal(t, before, p.planCount())

	// 帶確認後儲存成功，掛載上界＝儲存交易內的全部掛載（同一資產兩個帳號各一筆）
	confirmID := p.confirm("scoped", p.planCred, p.outIDs)
	code, body = p.create("scoped", credPlanReq("cred-plan", p.planCred, p.assets["bs-in-1"], confirmID))
	require.Equal(t, http.StatusCreated, code, string(body))
	p.noOutOfScopeNames(body)
	planID := planIDOf(t, body)
	auth := p.planAuth(planID)
	require.Equal(t, p.mountsOf(p.planCred), auth.TargetMountBound)
	var bound []uint
	require.NoError(t, json.Unmarshal([]byte(auth.TargetMountBound), &bound))
	require.Len(t, bound, 12)
	require.Equal(t, fmt.Sprintf("[%d]", p.assets["bs-in-1"]), auth.TargetBound, "資產 ID 上界與現行同一請求相同")
	var left int64
	require.NoError(t, p.db.Model(&model.CredentialImpactConfirmation{}).Count(&left).Error)
	require.EqualValues(t, 0, left, "確認在儲存交易內單次消費")

	// 全部掛載都在範圍內：不需確認，掛載上界仍為全部掛載
	inCred := p.credential("bs-in-cred", "bs-in")
	p.account(p.assets["bs-in-2"], "ic", inCred)
	code, body = p.create("scoped", credPlanReq("in-cred-plan", inCred, p.assets["bs-in-2"], ""))
	require.Equal(t, http.StatusCreated, code, string(body))
	require.Equal(t, p.mountsOf(inCred), p.planAuth(planIDOf(t, body)).TargetMountBound)

	// 確認之後另一交易加掛一台範圍外再提交：退回重新確認（台數 10）
	confirmID = p.confirm("scoped", p.planCred, p.outIDs)
	extra := p.asset("bs-out-p10", "bs-out")
	p.account(extra, "pc", p.planCred)
	code, body = p.do(p.h.Update, http.MethodPut, "scoped", fmt.Sprintf("/api/v1/change-secret-plans/%d", planID),
		idParam(planID), credPlanReq("cred-plan", p.planCred, p.assets["bs-in-1"], confirmID))
	require.Equal(t, http.StatusConflict, code, string(body))
	requireCodeCount(t, body, "RULE_CREDENTIAL_IMPACT_CONFIRMATION_REQUIRED", 10)
	require.Equal(t, auth.ID, p.planAuth(planID).ID, "計畫該版不變")

	// 全域發起者：同一請求一次成功，回應與授權脈絡列與現行相同（掛載上界為空）
	gc, gb := p.create("global", credPlanReq("g-scoped-svc", p.planCred, p.assets["bs-in-1"], ""))
	lc, lb := p.do(p.legacy.Create, http.MethodPost, "global", "/api/v1/change-secret-plans", nil,
		credPlanReq("g-legacy-svc", p.planCred, p.assets["bs-in-1"], ""))
	require.Equal(t, http.StatusCreated, gc, string(gb))
	require.Equal(t, lc, gc)
	ga, la := p.planAuth(planIDOf(t, gb)), p.planAuth(planIDOf(t, lb))
	require.Equal(t, "", ga.TargetMountBound)
	require.Equal(t, la.TargetMountBound, ga.TargetMountBound)
	require.Equal(t, la.TargetBound, ga.TargetBound)
	require.Equal(t, la.Capabilities, ga.Capabilities)
	require.Equal(t, la.PermissionSources, ga.PermissionSources)
	require.Equal(t, normalizePlanBody(t, lb), normalizePlanBody(t, gb))
}

// normalizePlanBody 去掉每列各自不同的識別、名稱與時間
func normalizePlanBody(t *testing.T, body []byte) map[string]any {
	var m map[string]any
	require.NoError(t, json.Unmarshal(body, &m))
	for _, k := range []string{"id", "name", "created_at", "updated_at", "authorization_id"} {
		delete(m, k)
	}
	return m
}

func testPlanReadProjection(t *testing.T) {
	p := newPsEnv(t)
	inPlanCode, inPlanBody := p.create("scoped", accountPlanReq("in-plan", p.assets["bs-in-1"], p.assets["bs-in-2"]))
	require.Equal(t, http.StatusCreated, inPlanCode, string(inPlanBody))
	inPlan := planIDOf(t, inPlanBody)
	_, mixedBody := p.create("global", accountPlanReq("mixed-plan", p.assets["bs-in-1"], p.assets["bs-out-1"]))
	mixed := planIDOf(t, mixedBody)
	confirmID := p.confirm("scoped", p.planCred, p.outIDs)
	_, credBody := p.create("scoped", credPlanReq("cred-plan", p.planCred, p.assets["bs-in-1"], confirmID))
	credPlan := planIDOf(t, credBody)
	var bound []uint
	require.NoError(t, json.Unmarshal([]byte(p.planAuth(credPlan).TargetMountBound), &bound))
	require.Len(t, bound, 12, "掛載上界含 9 台範圍外")

	// 列表只含資產全在範圍內的帳號計畫與憑證歸屬在範圍內的憑證計畫
	code, list := p.do(p.h.List, http.MethodGet, "scoped", "/api/v1/change-secret-plans", nil, nil)
	require.Equal(t, http.StatusOK, code)
	var lr struct {
		Data []struct {
			ID uint `json:"id"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(list, &lr))
	var listed []uint
	for _, d := range lr.Data {
		listed = append(listed, d.ID)
	}
	require.ElementsMatch(t, []uint{inPlan, credPlan}, listed)
	p.noOutOfScopeNames(list)

	// 憑證計畫：重新確認流程只帶範圍外台數 9；執行與記錄成功
	path := fmt.Sprintf("/api/v1/change-secret-plans/%d", credPlan)
	code, body := p.do(p.h.Update, http.MethodPut, "scoped", path, idParam(credPlan),
		credPlanReq("cred-plan", p.planCred, p.assets["bs-in-1"], ""))
	require.Equal(t, http.StatusConflict, code, string(body))
	requireCodeCount(t, body, "RULE_CREDENTIAL_IMPACT_CONFIRMATION_REQUIRED", 9)
	p.noOutOfScopeNames(body)
	code, body = p.do(p.h.Run, http.MethodPost, "scoped", path+"/run", idParam(credPlan), nil)
	require.Equal(t, http.StatusAccepted, code, string(body))
	p.noOutOfScopeNames(body)
	in1, in2, out1 := p.assets["bs-in-1"], p.assets["bs-in-2"], p.outIDs[0]
	for _, a := range []uint{in1, in2, out1} {
		require.NoError(t, p.db.Create(&model.ChangeSecretRecord{PlanID: credPlan, AssetID: a, AccountID: 1,
			Status: model.ChangeSecretSuccess, ExecutedAt: time.Now()}).Error)
	}
	recordAssets := func() []uint {
		code, body := p.do(p.h.Records, http.MethodGet, "scoped", path+"/records", idParam(credPlan), nil)
		require.Equal(t, http.StatusOK, code, string(body))
		p.noOutOfScopeNames(body)
		var rr struct {
			Data []struct {
				AssetID uint `json:"asset_id"`
			} `json:"data"`
		}
		require.NoError(t, json.Unmarshal(body, &rr))
		var out []uint
		for _, r := range rr.Data {
			out = append(out, r.AssetID)
		}
		return out
	}
	require.ElementsMatch(t, []uint{in1, in2}, recordAssets(), "記錄只列範圍內目標")

	// 不可見的帳號計畫：改、刪、執行、記錄與不存在 ID 逐欄相同，計畫不變
	var beforeMixed model.ChangeSecretPlan
	require.NoError(t, p.db.First(&beforeMixed, mixed).Error)
	callsBefore := p.remoteCalls()
	for _, ep := range []struct {
		fn     func(*gin.Context)
		method string
		suffix string
		body   any
	}{
		{p.h.Update, http.MethodPut, "", accountPlanReq("mixed-plan", p.assets["bs-in-1"])},
		{p.h.Delete, http.MethodDelete, "", nil},
		{p.h.Run, http.MethodPost, "/run", nil},
		{p.h.Records, http.MethodGet, "/records", nil},
	} {
		mc, mb := p.do(ep.fn, ep.method, "scoped", fmt.Sprintf("/api/v1/change-secret-plans/%d%s", mixed, ep.suffix),
			idParam(mixed), ep.body)
		nc, nb := p.do(ep.fn, ep.method, "scoped", "/api/v1/change-secret-plans/999999"+ep.suffix,
			idParam(999999), ep.body)
		require.Equal(t, nc, mc, "%s %s", ep.method, ep.suffix)
		require.Equal(t, string(nb), string(mb), "%s %s", ep.method, ep.suffix)
	}
	var afterMixed model.ChangeSecretPlan
	require.NoError(t, p.db.First(&afterMixed, mixed).Error)
	require.Equal(t, beforeMixed.Revision, afterMixed.Revision)
	require.Equal(t, beforeMixed.AssetIDs, afterMixed.AssetIDs)
	require.Equal(t, callsBefore, p.remoteCalls(), "不可見計畫的手動執行沒有遠端呼叫")
	var mixedRecords int64
	require.NoError(t, p.db.Model(&model.ChangeSecretRecord{}).Where("plan_id = ?", mixed).Count(&mixedRecords).Error)
	require.Zero(t, mixedRecords)

	// 一鍵重新授權：範圍化點擊者只承接可見計畫，回應不含不可見計畫 ID
	pause := func() {
		require.NoError(t, p.db.Model(&model.ChangeSecretPlan{}).Where("id IN ?", []uint{inPlan, mixed}).
			Update("authorization_state", model.PlanAuthNeedsReauthorization).Error)
	}
	pause()
	code, body = p.do(p.h.Reauthorize, http.MethodPost, "scoped", "/api/v1/change-secret-plans/reauthorize", nil, nil)
	require.Equal(t, http.StatusOK, code, string(body))
	require.JSONEq(t, fmt.Sprintf(`{"plan_ids":[%d],"count":1,"skipped_plan_ids":null}`, inPlan), string(body))
	var still model.ChangeSecretPlan
	require.NoError(t, p.db.First(&still, mixed).Error)
	require.Equal(t, model.PlanAuthNeedsReauthorization, still.AuthorizationState, "不可見計畫狀態不變")

	// 全域主體：列表與一鍵重新授權回應與現行相同
	_, gl := p.do(p.h.List, http.MethodGet, "global", "/api/v1/change-secret-plans", nil, nil)
	_, ll := p.do(p.legacy.List, http.MethodGet, "global", "/api/v1/change-secret-plans", nil, nil)
	require.Equal(t, string(ll), string(gl))
	pause()
	_, lr2 := p.do(p.legacy.Reauthorize, http.MethodPost, "global", "/api/v1/change-secret-plans/reauthorize", nil, nil)
	pause()
	_, gr := p.do(p.h.Reauthorize, http.MethodPost, "global", "/api/v1/change-secret-plans/reauthorize", nil, nil)
	require.Equal(t, string(lr2), string(gr))

	// 憑證計畫的範圍內資產事後移出範圍：記錄不再出現該資產，計畫仍可見
	require.NoError(t, p.db.Where("asset_id = ?", in2).Delete(&model.AssetNode{}).Error)
	require.NoError(t, p.db.Create(&model.AssetNode{AssetID: in2, NodeID: p.nodes["bs-out"]}).Error)
	require.ElementsMatch(t, []uint{in1}, recordAssets())
}

// authRowsOf 某計畫的授權脈絡列數
func (p *psEnv) authRowsOf(planID uint) int64 {
	var n int64
	require.NoError(p.t, p.db.Model(&model.CredentialJobAuthorization{}).
		Where("source_kind = ? AND source_id = ?", model.JobAuthSourcePlan, planID).Count(&n).Error)
	return n
}

// 鎖前讀到的計畫在交易開始前被另一主體改成範圍外目標：修改以鎖後最新列判可見，回不存在、最新列與授權列不變
func testPlanUpdateRereadsAfterLock(t *testing.T) {
	p := newPsEnv(t)
	_, body := p.create("scoped", accountPlanReq("race-plan", p.assets["bs-in-1"]))
	id := planIDOf(t, body)
	asset.SetPlanPreTxHookForTest(p.svc, func() {
		asset.SetPlanPreTxHookForTest(p.svc, nil)
		_, err := p.svc.Update(p.ctxOf("global"), id, accountPlanReq("race-plan", p.assets["bs-in-1"], p.assets["bs-out-1"]))
		require.NoError(t, err)
	})
	var afterGlobal model.ChangeSecretPlan
	code, resp := p.do(p.h.Update, http.MethodPut, "scoped", fmt.Sprintf("/api/v1/change-secret-plans/%d", id),
		idParam(id), accountPlanReq("race-plan-scoped", p.assets["bs-in-2"]))
	_, notFound := p.do(p.h.Update, http.MethodPut, "scoped", "/api/v1/change-secret-plans/999999",
		idParam(999999), accountPlanReq("race-plan-scoped", p.assets["bs-in-2"]))
	require.Equal(t, http.StatusNotFound, code, string(resp))
	require.Equal(t, string(notFound), string(resp))
	require.NoError(t, p.db.First(&afterGlobal, id).Error)
	require.Equal(t, "race-plan", afterGlobal.Name)
	require.Equal(t, 2, afterGlobal.Revision, "最新列停在另一主體寫入的修訂")
	require.ElementsMatch(t, []uint{p.assets["bs-in-1"], p.assets["bs-out-1"]}, asset.AssetIDList(&afterGlobal))
	require.EqualValues(t, 2, p.authRowsOf(id), "本請求沒有新增授權列")
	require.Equal(t, p.users["global"], p.planAuth(id).ActorID, "授權引用仍指向另一主體的那一列")
}

// 鎖前列入承接的計畫在交易開始前被改成範圍外目標：鎖後重讀判為不可見，不承接、不出現在 done 與 skipped
func testPlanReauthorizeRereadsAfterLock(t *testing.T) {
	p := newPsEnv(t)
	_, body := p.create("scoped", accountPlanReq("reauth-race", p.assets["bs-in-1"]))
	id := planIDOf(t, body)
	pause := func() {
		require.NoError(t, p.db.Model(&model.ChangeSecretPlan{}).Where("id = ?", id).
			Update("authorization_state", model.PlanAuthNeedsReauthorization).Error)
	}
	pause()
	var authBefore uint
	asset.SetPlanPreTxHookForTest(p.svc, func() {
		asset.SetPlanPreTxHookForTest(p.svc, nil)
		_, err := p.svc.Update(p.ctxOf("global"), id, accountPlanReq("reauth-race", p.assets["bs-in-1"], p.assets["bs-out-1"]))
		require.NoError(t, err)
		pause()
		authBefore = *p.planOf(id).AuthorizationID
	})
	code, resp := p.do(p.h.Reauthorize, http.MethodPost, "scoped", "/api/v1/change-secret-plans/reauthorize", nil, nil)
	require.Equal(t, http.StatusOK, code, string(resp))
	require.JSONEq(t, `{"plan_ids":null,"count":0,"skipped_plan_ids":null}`, string(resp))
	after := p.planOf(id)
	require.Equal(t, model.PlanAuthNeedsReauthorization, after.AuthorizationState)
	require.Equal(t, authBefore, *after.AuthorizationID)
	require.Equal(t, 2, after.Revision)
}

// 全域主體刪除計畫後仍讀得到保留的執行記錄；範圍化主體對同一識別與不存在同形
func testPlanGlobalRecordsAfterDelete(t *testing.T) {
	p := newPsEnv(t)
	_, body := p.create("global", accountPlanReq("deleted-plan", p.assets["bs-in-1"]))
	id := planIDOf(t, body)
	require.NoError(t, p.db.Create(&model.ChangeSecretRecord{PlanID: id, AssetID: p.assets["bs-in-1"], AccountID: 1,
		Status: model.ChangeSecretSuccess, ExecutedAt: time.Now()}).Error)
	path := fmt.Sprintf("/api/v1/change-secret-plans/%d", id)
	code, resp := p.do(p.h.Delete, http.MethodDelete, "global", path, idParam(id), nil)
	require.Less(t, code, 300, string(resp))
	_, legacy := p.do(p.legacy.Records, http.MethodGet, "global", path+"/records", idParam(id), nil)
	code, got := p.do(p.h.Records, http.MethodGet, "global", path+"/records", idParam(id), nil)
	require.Equal(t, http.StatusOK, code, string(got))
	require.Equal(t, string(legacy), string(got))
	var rr struct {
		Total int `json:"total"`
	}
	require.NoError(t, json.Unmarshal(got, &rr))
	require.Equal(t, 1, rr.Total, "已刪計畫的記錄仍在")
	_, scoped := p.do(p.h.Records, http.MethodGet, "scoped", path+"/records", idParam(id), nil)
	_, none := p.do(p.h.Records, http.MethodGet, "scoped", "/api/v1/change-secret-plans/999999/records", idParam(999999), nil)
	require.Equal(t, string(none), string(scoped))
}

// ctxOf 服務層呼叫的操作者脈絡（同 handler 的 accountContext）
func (p *psEnv) ctxOf(userKey string) context.Context {
	uid := p.users[userKey]
	ctx := context.WithValue(context.Background(), "userID", uid) //nolint:staticcheck // 沿用既有審計 context 慣例
	ctx = context.WithValue(ctx, "username", "bs-"+userKey)       //nolint:staticcheck
	return authz.ContextWithPrincipal(ctx, &authz.Principal{UserID: uid})
}

func (p *psEnv) planOf(id uint) model.ChangeSecretPlan {
	p.t.Helper()
	var plan model.ChangeSecretPlan
	require.NoError(p.t, p.db.First(&plan, id).Error)
	return plan
}

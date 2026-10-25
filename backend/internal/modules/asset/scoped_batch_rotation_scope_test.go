package asset_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/api"
	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/testgate"
)

// 批次改密的範圍交集：建立先判模式決定的能力、再於交易內以帳號改密的資產範圍收斂目標。
//
// 樹：bs-in（範圍化主體的指派節點）、bs-out（範圍外）。帳號名 postgres 在範圍內 2 台、範圍外 3 台；
// bulk 在範圍內 24 台、範圍外 2 台；svc 是全域歸屬共用憑證在範圍內 2 台上的成員。

var bsPerms = []authz.Permission{authz.PermAccountRotate, authz.PermCredentialCreate, authz.PermCredentialBind,
	authz.PermCredentialDetach, authz.PermCredentialRotate}

type bsEnv struct {
	t   *testing.T
	db  *gorm.DB
	svc *asset.ChangeSecretBatchService
	h   *api.ChangeSecretHandler
	// legacy 未注入範圍判定的同一服務：讀取投影的「現行」對照
	legacy   *api.ChangeSecretHandler
	nodes    map[string]uint
	users    map[string]uint
	acc      map[string]uint // 「資產名/帳號名」→ 帳號 id
	assets   map[string]uint
	sharedID uint
	seq      int
	// scope 與正式組裝同一個改密範圍判定（批次與候選共用）
	scope *authz.ChangeSecretScope
	eval  *authz.ScopeEvaluator
	mgmt  riAuthorizer
}

func newBsEnv(t *testing.T) *bsEnv {
	t.Helper()
	db, _ := openRaceDB(t)
	first, tail := raceModels()
	require.NoError(t, db.AutoMigrate(first...))
	require.NoError(t, db.AutoMigrate(tail...))
	require.NoError(t, db.AutoMigrate(&model.AssetAccount{}, &model.ChangeSecretCandidate{},
		&model.ChangeSecretBatch{}, &model.ChangeSecretRecord{}, &model.CredentialJobAuthorization{},
		&model.ChangeSecretPlan{}, &model.CredentialSecretVersion{}))
	require.NoError(t, db.Exec("INSERT INTO authz_state (id, version) VALUES (1, 0)").Error)
	old := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = old })

	e := &bsEnv{t: t, db: db, nodes: map[string]uint{}, users: map[string]uint{}, acc: map[string]uint{},
		assets: map[string]uint{}}
	for _, n := range []string{"bs-in", "bs-out"} {
		g := model.AssetGroup{Name: n}
		require.NoError(t, db.Create(&g).Error)
		e.nodes[n] = g.ID
	}
	// 正式產品目錄（不注入測試目錄）：範圍化主體的帳號改密是否生效，取決於目錄本身
	eval := authz.NewScopeEvaluator(authz.ProductCatalogue(), asset.NewScopeTopologyReader(), authz.CredentialScopeResolver(),
		authz.ChangeSecretCandidateScopeResolver())
	e.scope = authz.NewChangeSecretScope(eval)
	reports := asset.NewRotationReportBuilder(db, asset.NewChangeSecretPlanService(db), func() int { return 0 })
	mgmt := riAuthorizer{res: authz.NewResolver(db), eval: eval, db: db}
	e.eval, e.mgmt = eval, mgmt
	ownership := authz.NewCredentialOwnershipScope(eval)
	e.svc = asset.NewChangeSecretBatchService(db, reports).
		WithManagementAuthorizer(mgmt).
		WithScope(e.scope).
		WithOwnershipScope(ownership)
	e.h = api.NewChangeSecretHandler(nil, nil, nil, nil, e.svc, nil)
	e.legacy = api.NewChangeSecretHandler(nil, nil, nil, nil,
		asset.NewChangeSecretBatchService(db, reports).WithManagementAuthorizer(mgmt).WithOwnershipScope(ownership), nil)

	e.users["super"] = e.user("bs-super")
	adminRole := model.Role{Name: model.RoleAdmin}
	require.NoError(t, db.Create(&adminRole).Error)
	require.NoError(t, db.Create(&model.UserRole{UserID: e.users["super"], RoleID: adminRole.ID,
		Source: model.RoleSourceManual, ScopeKind: model.ScopeKindGlobal}).Error)

	full := e.role("bs-rotator", bsPerms...)
	e.users["scoped"] = e.user("bs-scoped")
	e.bind(e.users["scoped"], full, "bs-in")
	e.users["global"] = e.user("bs-global")
	e.bindGlobal(e.users["global"], full)
	// 全系統只有帳號改密：整批同一組缺建立與掛入
	e.users["rotonly"] = e.user("bs-rotonly")
	e.bindGlobal(e.users["rotonly"], e.role("bs-rotonly", authz.PermAccountRotate))
	// 沒有任何指派
	e.users["nocap"] = e.user("bs-nocap")
	// 帳號改密與建立、掛入在 bs-in；脫離與憑證改密只在 bs-out
	e.users["split"] = e.user("bs-split")
	e.bind(e.users["split"], e.role("bs-split-in", authz.PermAccountRotate, authz.PermCredentialCreate,
		authz.PermCredentialBind), "bs-in")
	e.bind(e.users["split"], e.role("bs-split-out", authz.PermCredentialDetach, authz.PermCredentialRotate), "bs-out")

	name, owner := "bs-shared-global", model.CredentialOwnerGlobal
	shared := model.Credential{Name: &name, Scope: model.CredentialScopeShared, Username: "svc",
		ProtocolFamily: model.ProtocolFamilySSH, OwnerKind: &owner}
	require.NoError(t, db.Create(&shared).Error)
	e.sharedID = shared.ID

	for i := 1; i <= 2; i++ {
		a := e.asset(fmt.Sprintf("bs-in-%d", i), "bs-in")
		e.account(a, "postgres", 0)
		e.account(a, "svc", shared.ID)
	}
	e.account(e.assets["bs-in-1"], "root", 0)
	for i := 1; i <= 3; i++ {
		e.account(e.asset(fmt.Sprintf("bs-out-%d", i), "bs-out"), "postgres", 0)
	}
	for i := 1; i <= 24; i++ {
		e.account(e.asset(fmt.Sprintf("bs-bulk-in-%02d", i), "bs-in"), "bulk", 0)
	}
	e.account(e.assets["bs-out-1"], "bulk", 0)
	e.account(e.assets["bs-out-2"], "bulk", 0)
	return e
}

func (e *bsEnv) user(name string) uint {
	e.t.Helper()
	u := model.User{Username: name, Password: "x", Active: true}
	require.NoError(e.t, e.db.Create(&u).Error)
	return u.ID
}

func (e *bsEnv) role(name string, perms ...authz.Permission) uint {
	e.t.Helper()
	r := model.Role{Name: name, DefinitionVersion: 1}
	require.NoError(e.t, e.db.Create(&r).Error)
	for _, p := range perms {
		require.NoError(e.t, e.db.Create(&model.RolePermission{RoleID: r.ID, PermissionKey: string(p)}).Error)
	}
	return r.ID
}

func (e *bsEnv) bind(userID, roleID uint, node string) {
	e.t.Helper()
	require.NoError(e.t, e.db.Create(&model.UserRole{UserID: userID, RoleID: roleID,
		Source: model.RoleSourceManual, ScopeKind: model.ScopeKindNodes}).Error)
	require.NoError(e.t, e.db.Create(&model.RoleBindingNode{SubjectKind: model.BindingSubjectUser,
		SubjectID: userID, RoleID: roleID, NodeID: e.nodes[node]}).Error)
}

func (e *bsEnv) bindGlobal(userID, roleID uint) {
	e.t.Helper()
	require.NoError(e.t, e.db.Create(&model.UserRole{UserID: userID, RoleID: roleID,
		Source: model.RoleSourceManual, ScopeKind: model.ScopeKindGlobal}).Error)
}

func (e *bsEnv) asset(name, node string) uint {
	e.t.Helper()
	e.seq++
	a := model.Asset{Name: name, Protocol: model.ProtocolSSH, Host: fmt.Sprintf("10.81.%d.%d", e.seq/200, e.seq%200+1),
		Port: 22, CreatedBy: e.users["super"], Active: true}
	require.NoError(e.t, e.db.Create(&a).Error)
	require.NoError(e.t, e.db.Create(&model.AssetNode{AssetID: a.ID, NodeID: e.nodes[node]}).Error)
	e.assets[name] = a.ID
	return a.ID
}

func (e *bsEnv) account(assetID uint, username string, credID uint) uint {
	e.t.Helper()
	acc := model.AssetAccount{AssetID: assetID, Username: username, CredentialID: credID}
	require.NoError(e.t, e.db.Create(&acc).Error)
	for n, id := range e.assets {
		if id == assetID {
			e.acc[n+"/"+username] = acc.ID
		}
	}
	return acc.ID
}

// writes 建立可能寫入的四張表的筆數
func (e *bsEnv) writes() [4]int64 {
	e.t.Helper()
	var out [4]int64
	for i, m := range []any{&model.ChangeSecretBatch{}, &model.ChangeSecretRecord{},
		&model.ChangeSecretCandidate{}, &model.CredentialJobAuthorization{}} {
		require.NoError(e.t, e.db.Model(m).Count(&out[i]).Error)
	}
	return out
}

func (e *bsEnv) ids(keys ...string) []uint {
	out := make([]uint, 0, len(keys))
	for _, k := range keys {
		id, ok := e.acc[k]
		require.True(e.t, ok, k)
		out = append(out, id)
	}
	return out
}

func bsReq(username string, ids ...uint) *asset.ChangeSecretBatchRequest {
	return &asset.ChangeSecretBatchRequest{Username: username, AccountIDs: ids, All: len(ids) == 0,
		PasswordMode: model.BatchPasswordPerTarget}
}

// post 經 handler 建立（只用在失敗路徑：成功會交給執行器背景執行）；回狀態碼與回應原文
func (e *bsEnv) post(userKey string, req *asset.ChangeSecretBatchRequest) (int, []byte) {
	e.t.Helper()
	body, err := json.Marshal(req)
	require.NoError(e.t, err)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/api/v1/change-secret-batches", bytes.NewReader(body))
	c.Request.Header.Set("Content-Type", "application/json")
	uid := e.users[userKey]
	c.Set("userID", uid)
	c.Set("username", "bs-"+userKey)
	middleware.SetPrincipal(c, &authz.Principal{UserID: uid})
	e.h.CreateBatch(c)
	return w.Code, w.Body.Bytes()
}

// get 經 handler 讀取；回狀態碼與回應原文
func (e *bsEnv) get(h func(*gin.Context), userKey, path string, params gin.Params) (int, []byte) {
	e.t.Helper()
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, path, nil)
	c.Params = params
	uid := e.users[userKey]
	c.Set("userID", uid)
	c.Set("username", "bs-"+userKey)
	middleware.SetPrincipal(c, &authz.Principal{UserID: uid})
	h(c)
	return w.Code, w.Body.Bytes()
}

// post2 經 handler 以空本文 POST；回狀態碼與回應原文
func (e *bsEnv) post2(h func(*gin.Context), userKey, path string, params gin.Params) (int, []byte) {
	e.t.Helper()
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, path, nil)
	c.Params = params
	uid := e.users[userKey]
	c.Set("userID", uid)
	c.Set("username", "bs-"+userKey)
	middleware.SetPrincipal(c, &authz.Principal{UserID: uid})
	h(c)
	return w.Code, w.Body.Bytes()
}

// readEndpoints 四個讀取端點（帳號名、目標、列表、詳情）在指定 handler 上的回應
func (e *bsEnv) readEndpoints(h *api.ChangeSecretHandler, userKey string, batchID uint) [][]byte {
	e.t.Helper()
	idp := gin.Params{{Key: "id", Value: fmt.Sprint(batchID)}}
	var out [][]byte
	for _, r := range []struct {
		fn     func(*gin.Context)
		path   string
		params gin.Params
	}{
		{h.BatchUsernames, "/api/v1/change-secret-batches/usernames", nil},
		{h.BatchTargets, "/api/v1/change-secret-batches/targets?username=postgres", nil},
		{h.ListBatches, "/api/v1/change-secret-batches", nil},
		{h.GetBatch, fmt.Sprintf("/api/v1/change-secret-batches/%d", batchID), idp},
	} {
		code, body := e.get(r.fn, userKey, r.path, r.params)
		require.Equal(e.t, http.StatusOK, code, "%s：%s", r.path, body)
		out = append(out, body)
	}
	return out
}

// noOutOfScopeNames 回應原文不含任何範圍外資產名
func (e *bsEnv) noOutOfScopeNames(body []byte) {
	e.t.Helper()
	for name := range e.assets {
		if len(name) > 7 && name[:7] == "bs-out-" {
			require.NotContains(e.t, string(body), name)
		}
	}
}

func sortedUints(in []uint) []uint {
	out := append([]uint(nil), in...)
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func TestScopedBatchRotationScope(t *testing.T) {
	gin.SetMode(gin.TestMode)
	e := newBsEnv(t)
	if os.Getenv(testgate.EnvPGDSN) != "" {
		require.Equal(t, "postgres", e.db.Dialector.Name())
		fmt.Println("EVIDENCE dialect=postgres")
	}
	scoped, global := e.users["scoped"], e.users["global"]

	t.Run("all_expands_in_scope_only", func(t *testing.T) {
		batch, assetIDs, err := e.svc.Create(bsReq("postgres"), scoped, "bs-scoped")
		require.NoError(t, err)
		want := sortedUints([]uint{e.assets["bs-in-1"], e.assets["bs-in-2"]})
		require.Equal(t, want, sortedUints(assetIDs))
		require.Equal(t, 2, batch.TargetCount)
		var auth model.CredentialJobAuthorization
		require.NoError(t, e.db.First(&auth, *batch.AuthorizationID).Error)
		var bound []uint
		require.NoError(t, json.Unmarshal([]byte(auth.TargetBound), &bound))
		require.Equal(t, want, sortedUints(bound), "授權脈絡上界只含範圍內資產")

		// 全域主體同一請求：五台全部
		_, gIDs, err := e.svc.Create(bsReq("postgres"), global, "bs-global")
		require.NoError(t, err)
		require.Len(t, gIDs, 5)
	})

	t.Run("explicit_unavailable_rejects_whole_batch", func(t *testing.T) {
		// 建立端點接上計數遠端替身的 runner（同 4.2 的寫法）：整批拒絕時不得啟動任何派送、遠端呼叫 0
		runner := asset.NewChangeSecretRunner(e.db, nil, nil, nil, nil)
		remoteCalls := asset.CountRemoteCallsForTest(runner)
		h0 := e.h
		e.h = api.NewChangeSecretHandler(nil, runner, nil, nil, e.svc, nil)
		defer func() { e.h = h0 }()
		var keys []string
		for i := 1; i <= 24; i++ {
			keys = append(keys, fmt.Sprintf("bs-bulk-in-%02d/bulk", i))
		}
		ids := e.ids(keys...)
		ids = append(ids, e.ids("bs-out-1/bulk", "bs-out-2/bulk")...)
		ids = append(ids, 987654)
		before := e.writes()
		code, body := e.post("scoped", bsReq("bulk", ids...))
		require.Equal(t, http.StatusNotFound, code, string(body))
		var resp map[string]any
		require.NoError(t, json.Unmarshal(body, &resp))
		keysOf := make([]string, 0, len(resp))
		for k := range resp {
			keysOf = append(keysOf, k)
		}
		sort.Strings(keysOf)
		require.Equal(t, []string{"code", "error", "params"}, keysOf)
		require.Equal(t, string(apierror.CodeBatchItemsUnavailable), resp["code"])
		require.Equal(t, map[string]any{"count": float64(3)}, resp["params"])
		require.Equal(t, before, e.writes(), "批次、記錄、候選、授權脈絡零寫入")
		require.Zero(t, remoteCalls(), "整批拒絕：遠端 stub 呼叫 0")
		for name := range e.assets {
			if len(name) > 7 && name[:7] == "bs-out-" {
				require.NotContains(t, string(body), name)
			}
		}

		// 只混不存在與只混範圍外：回應逐欄相同
		inOnly := e.ids("bs-bulk-in-01/bulk")
		c1, b1 := e.post("scoped", bsReq("bulk", append(append([]uint(nil), inOnly...), 987655)...))
		c2, b2 := e.post("scoped", bsReq("bulk", append(append([]uint(nil), inOnly...), e.acc["bs-out-1/bulk"])...))
		require.Equal(t, http.StatusNotFound, c1)
		require.Equal(t, c1, c2)
		require.JSONEq(t, string(b1), string(b2))
		require.Equal(t, before, e.writes())
		time.Sleep(50 * time.Millisecond) // 若誤建立批次，背景派送在此期間啟動
		require.Zero(t, remoteCalls(), "只混不存在與只混範圍外：遠端 stub 呼叫 0")
	})

	t.Run("in_scope_username_mismatch_keeps_current_code", func(t *testing.T) {
		_, _, err := e.svc.Create(bsReq("postgres", e.ids("bs-in-1/postgres", "bs-in-1/root")...), scoped, "bs-scoped")
		require.ErrorIs(t, err, asset.ErrBatchTargetMismatch)
		// 全域主體明列不存在 ID：沿現行不符碼
		_, _, err = e.svc.Create(bsReq("postgres", e.acc["bs-in-1/postgres"], 987656), global, "bs-global")
		require.ErrorIs(t, err, asset.ErrBatchTargetMismatch)
		var un *asset.BatchItemsUnavailableError
		require.False(t, errors.As(err, &un))
	})

	// 缺能力者在讀目標資料之前即被拒：不存在、範圍外、帳號名不符、零目標與撞名都得到同一個 403
	t.Run("capability_before_data", func(t *testing.T) {
		before := e.writes()
		cases := []*asset.ChangeSecretBatchRequest{
			bsReq("bulk", e.acc["bs-out-1/bulk"], 987657),
			bsReq("postgres", e.ids("bs-in-1/postgres", "bs-in-1/root")...),
			bsReq("no-such-username"),
		}
		var first []byte
		for i, req := range cases {
			code, body := e.post("nocap", req)
			require.Equal(t, http.StatusForbidden, code, "案例 %d：%s", i, body)
			if first == nil {
				first = body
			}
			require.JSONEq(t, string(first), string(body), "案例 %d 與其他案例同形", i)
		}
		// 全系統只有帳號改密者以整批同一組、撞名送出：403，不是名稱已被使用
		shared := bsReq("postgres")
		shared.PasswordMode = model.BatchPasswordShared
		shared.CredentialName = "bs-shared-global"
		code, body := e.post("rotonly", shared)
		require.Equal(t, http.StatusForbidden, code, string(body))
		require.NotContains(t, string(body), string(apierror.CodeCredentialNameExists))
		require.Equal(t, before, e.writes())

		// 有能力者撞名：沿現行 409
		code, body = e.post("global", shared)
		require.Equal(t, http.StatusConflict, code, string(body))
		require.Equal(t, before, e.writes())
	})

	// 每台各自隨機遇全域歸屬共用憑證的成員：判定依所選資產，不要求來源憑證歸屬在範圍內
	t.Run("per_target_shared_members_judged_by_asset", func(t *testing.T) {
		_, assetIDs, err := e.svc.Create(bsReq("svc", e.ids("bs-in-1/svc", "bs-in-2/svc")...), scoped, "bs-scoped")
		require.NoError(t, err)
		require.Len(t, assetIDs, 2)
	})

	// 依目標追加的能力（脫離、憑證改密）在所選資產上範圍外：單一 403，不是內部錯誤
	t.Run("extra_capability_out_of_scope_forbidden", func(t *testing.T) {
		before := e.writes()
		code, body := e.post("split", bsReq("svc", e.ids("bs-in-1/svc")...))
		require.Equal(t, http.StatusForbidden, code, string(body))
		require.Equal(t, before, e.writes())
		// 同一主體對專用帳號（不需追加能力）照常建立
		_, ids, err := e.svc.Create(bsReq("postgres", e.ids("bs-in-1/postgres")...), e.users["split"], "bs-split")
		require.NoError(t, err)
		require.Len(t, ids, 1)
	})

	// 讀取投影：帳號名、目標、列表、詳情與逐目標記錄只計範圍內資產；全域主體與現行逐欄相同
	t.Run("read_projection_in_scope_only", func(t *testing.T) {
		e.account(e.assets["bs-out-3"], "outonly", 0)
		// 歷史批次：範圍內 1 台、範圍外 2 台，已完成且三筆記錄皆成功
		mixed, _, err := e.svc.Create(bsReq("postgres", e.ids("bs-in-1/postgres", "bs-out-1/postgres",
			"bs-out-2/postgres")...), global, "bs-global")
		require.NoError(t, err)
		for _, k := range []string{"bs-in-1", "bs-out-1", "bs-out-2"} {
			require.NoError(t, e.db.Create(&model.ChangeSecretRecord{BatchID: mixed.ID, AssetID: e.assets[k],
				AccountID: e.acc[k+"/postgres"], AccountUsername: "postgres", Status: model.ChangeSecretSuccess,
				ExecutedAt: time.Now()}).Error)
		}
		require.NoError(t, e.db.Model(&model.ChangeSecretBatch{}).Where("id = ?", mixed.ID).Updates(map[string]any{
			"status": model.ChangeSecretBatchCompleted, "success_count": 3, "finished_at": time.Now()}).Error)
		// 全範圍外的批次
		outside, _, err := e.svc.Create(bsReq("postgres", e.ids("bs-out-3/postgres")...), global, "bs-global")
		require.NoError(t, err)
		// 範圍化主體剛建立、還沒有逐目標記錄的批次
		fresh, _, err := e.svc.Create(bsReq("postgres", e.ids("bs-in-2/postgres")...), scoped, "bs-scoped")
		require.NoError(t, err)

		// 帳號名清單：postgres 只計範圍內 2 台；只在範圍外的帳號名不出現
		code, body := e.get(e.h.BatchUsernames, "scoped", "/api/v1/change-secret-batches/usernames", nil)
		require.Equal(t, http.StatusOK, code, string(body))
		var names struct {
			Data []asset.BatchUsername `json:"data"`
		}
		require.NoError(t, json.Unmarshal(body, &names))
		byName := map[string]int{}
		for _, n := range names.Data {
			byName[n.Username] = n.AssetCount
		}
		require.Equal(t, 2, byName["postgres"])
		require.Equal(t, 24, byName["bulk"])
		require.NotContains(t, byName, "outonly")
		e.noOutOfScopeNames(body)

		// 目標列表：2 筆，都是範圍內資產
		code, body = e.get(e.h.BatchTargets, "scoped", "/api/v1/change-secret-batches/targets?username=postgres", nil)
		require.Equal(t, http.StatusOK, code, string(body))
		var targets struct {
			Data  []asset.BatchTarget `json:"data"`
			Total int                 `json:"total"`
		}
		require.NoError(t, json.Unmarshal(body, &targets))
		require.Equal(t, 2, targets.Total)
		got := []uint{}
		for _, tg := range targets.Data {
			got = append(got, tg.AssetID)
		}
		require.Equal(t, sortedUints([]uint{e.assets["bs-in-1"], e.assets["bs-in-2"]}), sortedUints(got))
		e.noOutOfScopeNames(body)

		// 歷史批次詳情：只列範圍內 1 筆記錄，目標數 1、四種計數總和 1
		idp := func(id uint) gin.Params { return gin.Params{{Key: "id", Value: fmt.Sprint(id)}} }
		code, body = e.get(e.h.GetBatch, "scoped", fmt.Sprintf("/api/v1/change-secret-batches/%d", mixed.ID), idp(mixed.ID))
		require.Equal(t, http.StatusOK, code, string(body))
		var detail struct {
			Data struct {
				Batch   map[string]any             `json:"batch"`
				Records []model.ChangeSecretRecord `json:"records"`
			} `json:"data"`
		}
		require.NoError(t, json.Unmarshal(body, &detail))
		require.Len(t, detail.Data.Records, 1)
		require.Equal(t, e.assets["bs-in-1"], detail.Data.Records[0].AssetID)
		require.Equal(t, float64(1), detail.Data.Batch["target_count"])
		sum := 0.0
		for _, k := range []string{"success_count", "failed_count", "unverified_count", "skipped_count"} {
			sum += detail.Data.Batch[k].(float64)
		}
		require.Equal(t, 1.0, sum)
		e.noOutOfScopeNames(body)

		// 剛建立的批次：建立者本人讀得到，記錄為空
		code, body = e.get(e.h.GetBatch, "scoped", fmt.Sprintf("/api/v1/change-secret-batches/%d", fresh.ID), idp(fresh.ID))
		require.Equal(t, http.StatusOK, code, string(body))

		// 列表：含歷史批次與剛建立的批次，不含全範圍外的批次
		code, body = e.get(e.h.ListBatches, "scoped", "/api/v1/change-secret-batches", nil)
		require.Equal(t, http.StatusOK, code, string(body))
		var list struct {
			Data []map[string]any `json:"data"`
		}
		require.NoError(t, json.Unmarshal(body, &list))
		listed := map[uint]map[string]any{}
		for _, b := range list.Data {
			listed[uint(b["id"].(float64))] = b
		}
		require.Contains(t, listed, mixed.ID)
		require.Contains(t, listed, fresh.ID)
		require.NotContains(t, listed, outside.ID)
		require.Equal(t, float64(1), listed[mixed.ID]["target_count"])
		require.Equal(t, float64(1), listed[mixed.ID]["success_count"])
		e.noOutOfScopeNames(body)

		// 全範圍外批次的詳情與不存在 ID：逐欄相同
		c1, b1 := e.get(e.h.GetBatch, "scoped", fmt.Sprintf("/api/v1/change-secret-batches/%d", outside.ID), idp(outside.ID))
		c2, b2 := e.get(e.h.GetBatch, "scoped", "/api/v1/change-secret-batches/987658", idp(987658))
		require.Equal(t, http.StatusNotFound, c1, string(b1))
		require.Equal(t, c1, c2)
		require.JSONEq(t, string(b1), string(b2))

		// 全域主體：四個端點與未注入範圍判定的現行服務逐位元相同
		for _, id := range []uint{mixed.ID, outside.ID} {
			now := e.readEndpoints(e.h, "global", id)
			was := e.readEndpoints(e.legacy, "global", id)
			for i := range now {
				if i == 1 {
					// 目標列表帶 as_of（請求當下時刻），比對時去掉
					now[i], was[i] = dropAsOf(t, now[i]), dropAsOf(t, was[i])
				}
				require.Equal(t, string(was[i]), string(now[i]), "端點 %d", i)
			}
		}
	})

	// 目標列上的涵蓋計畫與適用天數只由檢視者可見的計畫彙總：資產集合跨到範圍外的計畫不可見，
	// 其名稱不出現、也不參與多計畫與最嚴天數的推導；全域主體與現行逐欄相同
	t.Run("targets_aggregate_visible_plans_only", func(t *testing.T) {
		mkPlan := func(name string, days int, assets ...string) {
			ids := make([]uint, 0, len(assets))
			for _, a := range assets {
				ids = append(ids, e.assets[a])
			}
			raw, err := json.Marshal(ids)
			require.NoError(t, err)
			require.NoError(t, e.db.Create(&model.ChangeSecretPlan{Name: name, AssetIDs: string(raw),
				Accounts: `["postgres"]`, Enabled: true, MaxAgeDays: days, TargetKind: model.PlanTargetAccount}).Error)
		}
		mkPlan("bs-plan-wide", 30, "bs-in-1", "bs-out-1")
		mkPlan("bs-plan-in", 60, "bs-in-1")

		code, body := e.get(e.h.BatchTargets, "scoped", "/api/v1/change-secret-batches/targets?username=postgres", nil)
		require.Equal(t, http.StatusOK, code, string(body))
		require.NotContains(t, string(body), "bs-plan-wide")
		var targets struct {
			Data []asset.BatchTarget `json:"data"`
		}
		require.NoError(t, json.Unmarshal(body, &targets))
		var row *asset.BatchTarget
		for i := range targets.Data {
			if targets.Data[i].AssetID == e.assets["bs-in-1"] {
				row = &targets.Data[i]
			}
		}
		require.NotNil(t, row)
		require.Equal(t, []string{"bs-plan-in"}, row.Plans)
		require.False(t, row.MultiPlan)
		require.Equal(t, 60, row.MaxAgeDays)
		require.Equal(t, asset.MaxAgeSourcePlanPrefix+"bs-plan-in", row.MaxAgeSource)

		// 全域主體：兩個計畫都計入，與未注入範圍判定的現行服務逐位元相同
		_, now := e.get(e.h.BatchTargets, "global", "/api/v1/change-secret-batches/targets?username=postgres", nil)
		_, was := e.get(e.legacy.BatchTargets, "global", "/api/v1/change-secret-batches/targets?username=postgres", nil)
		require.Equal(t, string(dropAsOf(t, was)), string(dropAsOf(t, now)))
		require.Contains(t, string(now), "bs-plan-wide")
	})

	// 兩交易競態：建立等在拓撲序列化鎖上，另一交易把目標移出範圍後提交，建立看到的是移出後的樹
	t.Run("race_moved_out_before_create", func(t *testing.T) {
		if e.db.Dialector.Name() != "postgres" {
			t.Skip("需要第二條連線（PostgreSQL）")
		}
		moved := e.assets["bs-in-2"]
		tx := e.db.Begin()
		require.NoError(t, authz.LockScopeTopologyTx(tx))
		require.NoError(t, tx.Model(&model.AssetNode{}).Where("asset_id = ?", moved).
			Update("node_id", e.nodes["bs-out"]).Error)
		type result struct {
			ids []uint
			err error
		}
		done := make(chan result, 1)
		go func() {
			_, ids, err := e.svc.Create(bsReq("postgres"), scoped, "bs-scoped")
			done <- result{ids, err}
		}()
		waiting := false
		for i := 0; i < 100 && !waiting; i++ {
			var n int64
			require.NoError(t, e.db.Raw("SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND NOT granted").
				Scan(&n).Error)
			waiting = n > 0
			if !waiting {
				time.Sleep(50 * time.Millisecond)
			}
		}
		require.True(t, waiting, "建立應等在拓撲序列化鎖上")
		fmt.Println("EVIDENCE batch_create_waiting_on_topology_lock=true")
		require.NoError(t, tx.Commit().Error)
		r := <-done
		require.NoError(t, r.err)
		require.Equal(t, []uint{e.assets["bs-in-1"]}, r.ids, "移出範圍的資產不入列")
		require.NoError(t, e.db.Model(&model.AssetNode{}).Where("asset_id = ?", moved).
			Update("node_id", e.nodes["bs-in"]).Error)
	})
}

// dropAsOf 去掉回應中的 as_of 欄（請求當下時刻），其餘原樣重新序列化
func dropAsOf(t *testing.T, body []byte) []byte {
	t.Helper()
	var m map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(body, &m))
	delete(m, "as_of")
	out, err := json.Marshal(m)
	require.NoError(t, err)
	return out
}

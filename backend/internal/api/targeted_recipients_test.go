package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/internal/modules/policy"
	"github.com/custodexa/backend/pkg/crypto"
)

// 定向通知的收件人判定：連線申請、破窗補審，以及待審單超過列表上限時的判定。
//
// 同一份 fixture 分開驗四件事：
//
//	(a) 候選人完備：每位通過待審（或待補審）過濾加單號的使用者都在候選人集合內；
//	(b) 業務資格：收件人集合等於預期，每位被排除的候選人都標註屬於哪一條排除或哪一條列明的差異；
//	(c) 端點守門：經真的路由（含 RequireApproverRole）呼叫待審清單端點，收件人的回應含該單；
//	    被排除者回 401／403、回應不含該單，或屬「已投完票」這一條列明的差異；
//	(d) 頁面可達：每位收件人對 /approvals 的入口規則放行。
//
// (a) 以服務的待審清單（與待審過濾同一份條件、不經端點守門）判斷「通過過濾」：fixture 的單數遠小於清單上限。

const tnSecret = "targeted-recipients-secret"

// 被排除者的標註（design 決策 2 的條件與決策 3 列明的差異）。
const (
	exclRequester       = "申請人（或破窗人）"
	exclExecutor        = "執行者"
	exclOwnAgentReq     = "申請人是該審核者擁有的 agent"
	exclOwnAgentExec    = "執行者是該審核者擁有的 agent"
	exclOutOfScope      = "範圍外"
	exclNotApprover     = "不是有效審核者"
	exclAgent           = "agent"
	exclDisabled        = "停用帳號"
	exclDeleted         = "已刪除帳號"
	exclVotedAll        = "已投完票（決策 3 第 1 點，列明的差異）"
	exclNotCandidateAny = "不在候選人集合"
)

type tnEnv struct {
	db       *gorm.DB
	svc      *authz.AccessRequestService
	policies *policy.SecurityPolicyService
	jwt      *crypto.JWTManager
	r        *gin.Engine
	ids      map[string]uint
	names    map[uint]string
	assets   map[string]uint
	nodes    map[string]uint
	now      time.Time
}

func setupTargetedEnv(t *testing.T) *tnEnv {
	t.Helper()
	gin.SetMode(gin.TestMode)
	// 具名的共用記憶體庫：破窗流程在交易內另以連線池檢查還原世代，連線池為 1 時會等待自己
	dsn := fmt.Sprintf("file:tn_%d?mode=memory&cache=shared", time.Now().UnixNano())
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(4)
	t.Cleanup(func() { _ = sqlDB.Close() })
	if err := migrateWithAuthz(db, &model.User{}, &model.Role{}, &model.UserGroup{}, &model.Asset{}, &model.AssetGroup{}, &model.AssetNode{},
		&model.AssetAuthorization{}, &model.AccessRequest{}, &model.AccessRequestItem{}, &model.AgentVisibilityExposure{},
		&model.AccessRequestApproval{}, &model.ApproverScope{}, &model.SecurityPolicy{}, &model.SecurityPolicyHistory{}, &model.AuditLog{},
		&model.NotificationChannel{}, &model.RolePermission{},
		&model.UserRole{}, &model.UserGroupMember{}, &model.UserGroupRole{}, &model.RoleBindingNode{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	oldDB := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = oldDB })

	policies := policy.NewSecurityPolicyService(db)
	accessPolicy := policy.NewAccessPolicyService(db, policies, authz.NewAssetAuthorizationService(db))
	svc := authz.NewAccessRequestService(db, policies, accessPolicy, nil, nil)
	h := NewAccessRequestHandler(svc, new(MockApproverScopeService), db)
	r := gin.New()
	h.RegisterRoutes(r.Group("/api/v1"), identity.NewAuthService(tnSecret, time.Minute))
	e := &tnEnv{db: db, svc: svc, policies: policies, jwt: crypto.NewJWTManager(tnSecret, time.Minute), r: r,
		ids: map[string]uint{}, names: map[uint]string{}, assets: map[string]uint{}, nodes: map[string]uint{}, now: time.Now()}
	e.seed(t)
	return e
}

func (e *tnEnv) user(t *testing.T, name string, mutate func(u *model.User), roles ...string) uint {
	t.Helper()
	u := &model.User{Username: name, Password: "x", Email: emailPtr(name + "@t.local"), Active: true, Kind: model.KindHuman}
	if mutate != nil {
		mutate(u)
	}
	active := u.Active
	u.Active = true
	if err := e.db.Create(u).Error; err != nil {
		t.Fatalf("seed user %s: %v", name, err)
	}
	if !active { // gorm 的 default:true 會把 false 視為零值，建立後另外寫入
		if err := e.db.Model(u).Update("active", false).Error; err != nil {
			t.Fatal(err)
		}
	}
	for _, role := range roles {
		grantLegacyRole(t, e.db, u.ID, role)
	}
	e.ids[name], e.names[u.ID] = u.ID, name
	return u.ID
}

func (e *tnEnv) scope(t *testing.T, s model.ApproverScope) {
	t.Helper()
	s.GrantedBy = 1
	if err := e.db.Create(&s).Error; err != nil {
		t.Fatalf("seed scope: %v", err)
	}
}

func (e *tnEnv) seed(t *testing.T) {
	t.Helper()
	approval := model.AccessPolicyApproval
	for _, name := range []string{"a1", "a2", "a3"} {
		a := model.Asset{Name: name, Protocol: model.ProtocolSSH, Host: "h", Port: 22, CreatedBy: 1, AccessPolicy: &approval}
		if err := e.db.Create(&a).Error; err != nil {
			t.Fatal(err)
		}
		e.assets[name] = a.ID
	}
	n0 := model.AssetGroup{Name: "n0"}
	if err := e.db.Create(&n0).Error; err != nil {
		t.Fatal(err)
	}
	n1 := model.AssetGroup{Name: "n1", ParentID: &n0.ID}
	if err := e.db.Create(&n1).Error; err != nil {
		t.Fatal(err)
	}
	e.nodes["n0"], e.nodes["n1"] = n0.ID, n1.ID
	if err := e.db.Create(&model.AssetNode{AssetID: e.assets["a2"], NodeID: n1.ID}).Error; err != nil {
		t.Fatal(err)
	}

	a1, a3 := e.assets["a1"], e.assets["a3"]
	approver := model.RoleApprover
	R := e.user(t, "requester", nil, approver)
	e.scope(t, model.ApproverScope{ApproverID: uptr(R), AssetID: uptr(a1)})
	for _, name := range []string{"asset", "executor", "agentowner", "execagentowner", "locked", "voted"} {
		id := e.user(t, name, nil, approver)
		e.scope(t, model.ApproverScope{ApproverID: uptr(id), AssetID: uptr(a1)})
	}
	subj := e.user(t, "subject", nil, approver)
	e.scope(t, model.ApproverScope{ApproverID: uptr(subj), SubjectUserID: uptr(R)})
	node := e.user(t, "node", nil, approver)
	e.scope(t, model.ApproverScope{ApproverID: uptr(node), AssetGroupID: uptr(n0.ID)})
	outside := e.user(t, "outside", nil, approver)
	e.scope(t, model.ApproverScope{ApproverID: uptr(outside), AssetID: uptr(a3)})
	// 經審核方群組取得範圍與審核資格（沒有 approver 角色）
	grp := e.user(t, "group", nil)
	g := model.UserGroup{Name: "approver-group"}
	if err := e.db.Create(&g).Error; err != nil {
		t.Fatal(err)
	}
	if err := e.db.Create(&model.UserGroupMember{UserGroupID: g.ID, UserID: grp}).Error; err != nil {
		t.Fatal(err)
	}
	e.scope(t, model.ApproverScope{ApproverGroupID: uptr(g.ID), AssetID: uptr(a1)})
	// 沒有 approver 角色、也不在審核方群組，但有直配範圍
	nr := e.user(t, "scopenorole", nil)
	e.scope(t, model.ApproverScope{ApproverID: uptr(nr), AssetID: uptr(a1)})
	e.user(t, "adminonly", nil, model.RoleAdmin)
	ag := e.user(t, "agent", func(u *model.User) { u.Kind = model.KindAgent; u.OwnerUserID = uptr(1) })
	e.scope(t, model.ApproverScope{ApproverID: uptr(ag), AssetID: uptr(a1)})
	dis := e.user(t, "disabled", func(u *model.User) { u.Active = false }, approver)
	e.scope(t, model.ApproverScope{ApproverID: uptr(dis), AssetID: uptr(a1)})
	// 停用時會推進憑證世代（帳號停用的既有路徑），停用前取得的 token 因此失效；停用的帳號也無法再登入
	if err := e.db.Model(&model.User{}).Where("id = ?", dis).Update("credential_epoch", 1).Error; err != nil {
		t.Fatal(err)
	}
	del := e.user(t, "deleted", nil, approver)
	e.scope(t, model.ApproverScope{ApproverID: uptr(del), AssetID: uptr(a1)})
	if err := e.db.Delete(&model.User{}, del).Error; err != nil {
		t.Fatal(err)
	}
	future := e.now.Add(time.Hour)
	if err := e.db.Model(&model.User{}).Where("id = ?", e.ids["locked"]).Update("locked_until", future).Error; err != nil {
		t.Fatal(err)
	}
	owner := e.ids["agentowner"]
	e.user(t, "ownedagent", func(u *model.User) { u.Kind = model.KindAgent; u.OwnerUserID = &owner })
	execOwner := e.ids["execagentowner"]
	e.user(t, "execagent", func(u *model.User) { u.Kind = model.KindAgent; u.OwnerUserID = &execOwner })
}

// request 直接寫一張待審申請與其項目；itemStatus 依資產給每一項的狀態。
func (e *tnEnv) request(t *testing.T, requester string, executor string, items map[string]model.AccessRequestStatus, created time.Time) uint {
	t.Helper()
	keys := make([]string, 0, len(items))
	for k := range items {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	req := model.AccessRequest{RequesterID: e.ids[requester], AssetID: e.assets[keys[0]], Reason: "maintenance",
		RequestedDurationMinutes: 60, Status: model.AccessRequestPending, Kind: model.AccessRequestKindNormal,
		PendingExpiresAt: e.now.Add(24 * time.Hour)}
	req.CreatedAt = created
	if executor != "" {
		id := e.ids[executor]
		req.ExecutorUserID = &id
	}
	if err := e.db.Create(&req).Error; err != nil {
		t.Fatalf("seed request: %v", err)
	}
	for _, k := range keys {
		item := model.AccessRequestItem{RequestID: req.ID, RequesterID: req.RequesterID, AssetID: e.assets[k], Status: items[k], PolicySnapshot: "{}"}
		if err := e.db.Create(&item).Error; err != nil {
			t.Fatalf("seed item: %v", err)
		}
	}
	return req.ID
}

func (e *tnEnv) vote(t *testing.T, requestID uint, asset, voter string) {
	t.Helper()
	var item model.AccessRequestItem
	if err := e.db.Where("request_id = ? AND asset_id = ?", requestID, e.assets[asset]).First(&item).Error; err != nil {
		t.Fatal(err)
	}
	if err := e.db.Create(&model.AccessRequestApproval{RequestID: requestID, ItemID: &item.ID, ApproverID: e.ids[voter]}).Error; err != nil {
		t.Fatal(err)
	}
}

func (e *tnEnv) namesOf(ids []uint) []string {
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		out = append(out, e.names[id])
	}
	sort.Strings(out)
	return out
}

func (e *tnEnv) token(t *testing.T, name string) string {
	t.Helper()
	tok, err := e.jwt.GenerateToken(e.ids[name], name, name+"@t.local", "user", crypto.AuthContext{})
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// listContains 以該使用者的身分呼叫清單端點，回傳狀態碼與回應是否含該單。
func (e *tnEnv) listContains(t *testing.T, path, name string, requestID uint) (int, bool) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("Authorization", "Bearer "+e.token(t, name))
	w := httptest.NewRecorder()
	e.r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		return w.Code, false
	}
	var body struct {
		Data []struct {
			ID uint `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("%s 回應不是 JSON: %s", path, w.Body.String())
	}
	for _, r := range body.Data {
		if r.ID == requestID {
			return w.Code, true
		}
	}
	return w.Code, false
}

// entryAllowed 使用者對某個頁面入口規則是否放行（以 /auth/me 投影同一組輸入計算）。
func (e *tnEnv) entryAllowed(t *testing.T, userID uint, path string) bool {
	t.Helper()
	p, err := authz.ResolveUserOn(e.db, userID, authz.TokenFacts{SubjectKind: model.KindHuman})
	if err != nil {
		t.Fatal(err)
	}
	isApprover, err := authz.NewAssetAuthorizationService(e.db).IsEffectiveApprover(userID)
	if err != nil {
		t.Fatal(err)
	}
	proj := authz.ProjectCapabilities(p, authz.ProjectionInputs{IsApprover: isApprover})
	have := map[string]bool{}
	for _, perm := range proj.Permissions {
		have[perm] = true
	}
	for _, rule := range authz.RouteEntryRules() {
		if rule.Path != path {
			continue
		}
		hits := 0
		for _, perm := range rule.Permissions {
			if have[perm] {
				hits++
			}
		}
		switch rule.Kind {
		case "any":
			return hits > 0
		case "all":
			return hits == len(rule.Permissions)
		default:
			t.Fatalf("入口規則 %s 的種類 %q 本測試未處理", path, rule.Kind)
		}
	}
	t.Fatalf("找不到入口規則 %s", path)
	return false
}

// candidateNames 審核者候選人（以判定函式對每位使用者都不成立時，空清單也要能被比較）。
var tnApproverFixtureUsers = []string{"requester", "asset", "executor", "agentowner", "execagentowner", "locked", "voted",
	"subject", "node", "outside", "group", "scopenorole", "adminonly", "agent", "disabled", "deleted", "ownedagent", "execagent"}

type tnCase struct {
	name       string
	requestID  uint
	recipients []string
	excluded   map[string]string // 候選人中被排除者 → 標註
}

// checkTargetedCase 對一張單驗 (a) 到 (d)。listPath 是待審或待補審清單端點；inFilter 判斷使用者是否通過過濾加單號。
func (e *tnEnv) checkTargetedCase(t *testing.T, c tnCase, got []uint, listPath, entryPath string, inFilter func(uint) bool) {
	t.Helper()
	candidates := map[string]bool{}
	var candIDs []uint
	if err := e.db.Raw(`SELECT approver_id AS id FROM approver_scopes WHERE deleted_at IS NULL AND approver_id IS NOT NULL
UNION SELECT gm.user_id AS id FROM user_group_members gm JOIN approver_scopes s ON s.approver_group_id = gm.user_group_id WHERE s.deleted_at IS NULL`).Scan(&candIDs).Error; err != nil {
		t.Fatal(err)
	}
	for _, id := range candIDs {
		candidates[e.names[id]] = true
	}
	// (a) 候選人完備
	for _, name := range tnApproverFixtureUsers {
		if inFilter(e.ids[name]) && !candidates[name] {
			t.Errorf("%s (a) %s 通過過濾加單號，但不在候選人集合內", c.name, name)
		}
	}
	// (b) 收件人集合
	want := append([]string{}, c.recipients...)
	sort.Strings(want)
	if gotNames := e.namesOf(got); strings.Join(gotNames, ",") != strings.Join(want, ",") {
		t.Errorf("%s (b) 收件人 = %v，want %v", c.name, gotNames, want)
	}
	isRecipient := map[string]bool{}
	for _, n := range want {
		isRecipient[n] = true
	}
	for name := range candidates {
		if !isRecipient[name] && c.excluded[name] == "" {
			t.Errorf("%s (b) 候選人 %s 被排除但沒有標註排除原因", c.name, name)
		}
	}
	// (c) 端點守門
	for _, name := range want {
		code, has := e.listContains(t, listPath, name, c.requestID)
		if code != http.StatusOK || !has {
			t.Errorf("%s (c) 收件人 %s 呼叫 %s 得 %d、含該單=%v，want 200 且含該單", c.name, name, listPath, code, has)
		}
	}
	for name, why := range c.excluded {
		code, has := e.listContains(t, listPath, name, c.requestID)
		switch {
		case why == exclVotedAll:
			// 列明的差異：他仍可在清單看到並拒絕，但通知只送還需要他投票的人
		case code == http.StatusForbidden || code == http.StatusUnauthorized:
		case code == http.StatusOK && !has:
		default:
			t.Errorf("%s (c) 被排除者 %s（%s）呼叫 %s 得 %d、含該單=%v", c.name, name, why, listPath, code, has)
		}
	}
	// (d) 頁面可達
	for _, name := range want {
		if !e.entryAllowed(t, e.ids[name], entryPath) {
			t.Errorf("%s (d) 收件人 %s 對 %s 的入口規則不放行", c.name, name, entryPath)
		}
	}
}

func (e *tnEnv) pendingFilter(t *testing.T, requestID uint) func(uint) bool {
	return func(userID uint) bool {
		reqs, err := e.svc.ListPending(userID, false, time.Now())
		if err != nil {
			t.Fatalf("ListPending: %v", err)
		}
		for _, r := range reqs {
			if r.ID == requestID {
				return true
			}
		}
		return false
	}
}

func (e *tnEnv) reviewFilter(t *testing.T, requestID uint) func(uint) bool {
	return func(userID uint) bool {
		reqs, err := e.svc.ListPendingReview(userID, false)
		if err != nil {
			t.Fatalf("ListPendingReview: %v", err)
		}
		for _, r := range reqs {
			if r.ID == requestID {
				return true
			}
		}
		return false
	}
}

// commonExcluded 每張單都相同的排除。
func commonExcluded(extra map[string]string) map[string]string {
	out := map[string]string{
		"scopenorole": exclNotApprover,
		"agent":       exclAgent,
		"disabled":    exclDisabled,
		"deleted":     exclDeleted,
	}
	for k, v := range extra {
		out[k] = v
	}
	return out
}

// TestTargetedAccessRequestRecipients 連線申請的收件人判定。
func TestTargetedAccessRequestRecipients(t *testing.T) {
	e := setupTargetedEnv(t)
	pending := model.AccessRequestPending
	created := e.now.Add(-time.Minute)
	req1 := e.request(t, "requester", "", map[string]model.AccessRequestStatus{"a1": pending, "a2": pending}, created)
	e.vote(t, req1, "a1", "voted")
	reqExec := e.request(t, "requester", "executor", map[string]model.AccessRequestStatus{"a1": pending}, created)
	reqAg := e.request(t, "ownedagent", "", map[string]model.AccessRequestStatus{"a1": pending}, created)
	reqExAg := e.request(t, "requester", "execagent", map[string]model.AccessRequestStatus{"a1": pending}, created)
	reqMulti := e.request(t, "requester", "", map[string]model.AccessRequestStatus{"a1": pending, "a3": pending}, created)

	cases := []tnCase{
		{"REQ1（兩項：直配資產與節點子樹）", req1,
			[]string{"asset", "subject", "node", "group", "executor", "agentowner", "execagentowner", "locked"},
			commonExcluded(map[string]string{"requester": exclRequester, "outside": exclOutOfScope, "voted": exclVotedAll})},
		{"執行者", reqExec,
			[]string{"asset", "subject", "group", "agentowner", "execagentowner", "locked", "voted"},
			commonExcluded(map[string]string{"requester": exclRequester, "executor": exclExecutor, "node": exclOutOfScope, "outside": exclOutOfScope})},
		{"申請人是審核者擁有的 agent", reqAg,
			[]string{"asset", "group", "executor", "execagentowner", "locked", "voted", "requester"},
			commonExcluded(map[string]string{"agentowner": exclOwnAgentReq, "subject": exclOutOfScope, "node": exclOutOfScope, "outside": exclOutOfScope})},
		{"執行者是審核者擁有的 agent", reqExAg,
			[]string{"asset", "subject", "group", "executor", "agentowner", "locked", "voted"},
			commonExcluded(map[string]string{"requester": exclRequester, "execagentowner": exclOwnAgentExec, "node": exclOutOfScope, "outside": exclOutOfScope})},
		{"多項申請只有一項在範圍內", reqMulti,
			[]string{"asset", "subject", "group", "executor", "agentowner", "execagentowner", "locked", "voted", "outside"},
			commonExcluded(map[string]string{"requester": exclRequester, "node": exclOutOfScope})},
	}
	for _, c := range cases {
		got, err := e.svc.TargetedAccessRequestRecipients(e.db, c.requestID, time.Now())
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		e.checkTargetedCase(t, c, got, "/api/v1/access-requests/pending", "/approvals", e.pendingFilter(t, c.requestID))
	}

	// (e) 鎖定但啟用的帳號在收件人內（上面每一張單都已斷言 locked 在收件人集合）；這裡另確認鎖定確實生效
	var locked model.User
	if err := e.db.First(&locked, e.ids["locked"]).Error; err != nil || locked.LockedUntil == nil || !locked.LockedUntil.After(time.Now()) {
		t.Fatalf("前提不成立：locked 帳號沒有被鎖定 %v", err)
	}
	// admin-only 不在候選人集合，也不是收件人
	if got, _ := e.svc.TargetedAccessRequestRecipients(e.db, req1, time.Now()); containsID(got, e.ids["adminonly"]) {
		t.Error("只有 admin 角色者成為收件人")
	}
}

// TestTargetedAccessRequestRecipientsAfterDecision 單已被決定、撤回或逾期後沒有收件人；收件人投完票後他被排除。
func TestTargetedAccessRequestRecipientsAfterDecision(t *testing.T) {
	e := setupTargetedEnv(t)
	pending := model.AccessRequestPending
	req := e.request(t, "requester", "", map[string]model.AccessRequestStatus{"a1": pending}, e.now)
	got, _ := e.svc.TargetedAccessRequestRecipients(e.db, req, time.Now())
	if !containsID(got, e.ids["asset"]) {
		t.Fatalf("前提不成立：asset 應是收件人，得 %v", e.namesOf(got))
	}
	e.vote(t, req, "a1", "asset")
	got, _ = e.svc.TargetedAccessRequestRecipients(e.db, req, time.Now())
	if containsID(got, e.ids["asset"]) {
		t.Error("投完票後仍是收件人")
	}
	for _, status := range []model.AccessRequestStatus{model.AccessRequestApproved, model.AccessRequestRejected, model.AccessRequestCancelled, model.AccessRequestExpired} {
		if err := e.db.Model(&model.AccessRequest{}).Where("id = ?", req).Update("status", status).Error; err != nil {
			t.Fatal(err)
		}
		if got, _ := e.svc.TargetedAccessRequestRecipients(e.db, req, time.Now()); len(got) != 0 {
			t.Errorf("狀態 %s 時仍有收件人 %v", status, e.namesOf(got))
		}
	}
	// 待審但已過待審期限
	if err := e.db.Model(&model.AccessRequest{}).Where("id = ?", req).Updates(map[string]any{"status": pending, "pending_expires_at": e.now.Add(-time.Minute)}).Error; err != nil {
		t.Fatal(err)
	}
	if got, _ := e.svc.TargetedAccessRequestRecipients(e.db, req, time.Now()); len(got) != 0 {
		t.Errorf("逾期的單仍有收件人 %v", e.namesOf(got))
	}
}

// TestTargetedAccessRequestRecipientBeyondListLimit 範圍內已有 200 張待審單時再建一張，收件人判定仍納入該審核者。
func TestTargetedAccessRequestRecipientBeyondListLimit(t *testing.T) {
	e := setupTargetedEnv(t)
	pending := model.AccessRequestPending
	base := e.now.Add(-time.Hour)
	for i := 0; i < 200; i++ {
		e.request(t, "requester", "", map[string]model.AccessRequestStatus{"a1": pending}, base.Add(time.Duration(i)*time.Second))
	}
	last := e.request(t, "requester", "", map[string]model.AccessRequestStatus{"a1": pending}, e.now)
	listed, err := e.svc.ListPending(e.ids["asset"], false, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != 200 {
		t.Fatalf("前提不成立：待審清單應被截在 200 筆，得 %d", len(listed))
	}
	for _, r := range listed {
		if r.ID == last {
			t.Fatal("前提不成立：第 201 張出現在待審清單內")
		}
	}
	got, err := e.svc.TargetedAccessRequestRecipients(e.db, last, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !containsID(got, e.ids["asset"]) {
		t.Errorf("第 201 張的收件人不含範圍內的審核者：%v", e.namesOf(got))
	}
	if code, has := e.listContains(t, "/api/v1/access-requests/pending", "asset", last); code != http.StatusOK || has {
		t.Errorf("前提不成立：端點應回 200 且不含第 201 張（直達會落到「找不到」的說明），得 %d %v", code, has)
	}
}

// breakGlass 以服務的破窗流程建單（建單即自動核准、補審待補審）。
func (e *tnEnv) breakGlass(t *testing.T, requester, asset string) uint {
	t.Helper()
	if _, err := e.policies.Update(policy.PolicyBreakGlassEnabled, "true", "admin"); err != nil {
		t.Fatal(err)
	}
	uid, aid := e.ids[requester], e.assets[asset]
	if err := e.db.Create(&model.AssetAuthorization{UserID: &uid, AssetID: &aid, Permission: model.PermissionConnect, GrantedBy: 1}).Error; err != nil {
		t.Fatal(err)
	}
	req, err := e.svc.BreakGlass(uid, requester, false, aid, "incident")
	if err != nil {
		t.Fatalf("BreakGlass: %v", err)
	}
	if req.Status != model.AccessRequestApproved || req.ReviewStatus != model.BreakGlassReviewPending {
		t.Fatalf("前提不成立：破窗單應即時核准且待補審，得 status=%s review=%s", req.Status, req.ReviewStatus)
	}
	return req.ID
}

// TestTargetedBreakGlassRecipients 破窗補審的收件人判定。
func TestTargetedBreakGlassRecipients(t *testing.T) {
	e := setupTargetedEnv(t)
	bg := e.breakGlass(t, "requester", "a1")
	want := []string{"asset", "subject", "group", "executor", "agentowner", "execagentowner", "locked", "voted"}
	c := tnCase{"破窗（建單即自動核准）", bg, want,
		commonExcluded(map[string]string{"requester": exclRequester, "node": exclOutOfScope, "outside": exclOutOfScope})}
	got, err := e.svc.TargetedBreakGlassRecipients(e.db, bg)
	if err != nil {
		t.Fatal(err)
	}
	e.checkTargetedCase(t, c, got, "/api/v1/access-requests/reviews/pending", "/approvals", e.reviewFilter(t, bg))

	// 臨時授權已到期、補審仍待補審時收件人不變
	past := time.Now().Add(-time.Minute)
	if err := e.db.Model(&model.AssetAuthorization{}).Where("id IN (SELECT authorization_id FROM access_request_items WHERE request_id = ? AND authorization_id IS NOT NULL)", bg).
		Update("date_expired", past).Error; err != nil {
		t.Fatal(err)
	}
	var expired int64
	e.db.Model(&model.AssetAuthorization{}).Where("date_expired IS NOT NULL AND date_expired < ?", time.Now()).Count(&expired)
	if expired == 0 {
		t.Fatal("前提不成立：破窗的臨時授權沒有被設成已到期")
	}
	again, err := e.svc.TargetedBreakGlassRecipients(e.db, bg)
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(e.namesOf(again)) != fmt.Sprint(e.namesOf(got)) {
		t.Errorf("臨時授權到期後收件人改變：%v → %v", e.namesOf(got), e.namesOf(again))
	}
	// 補審完成後收件人為空
	if _, err := e.svc.Review(e.ids["asset"], false, bg, model.BreakGlassDispositionConfirmed, "ok"); err != nil {
		t.Fatalf("Review: %v", err)
	}
	if after, _ := e.svc.TargetedBreakGlassRecipients(e.db, bg); len(after) != 0 {
		t.Errorf("補審完成後仍有收件人 %v", e.namesOf(after))
	}
}

func containsID(ids []uint, id uint) bool {
	for _, v := range ids {
		if v == id {
			return true
		}
	}
	return false
}

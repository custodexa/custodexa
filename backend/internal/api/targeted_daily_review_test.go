package api

import (
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/internal/modules/policy"
	"github.com/custodexa/backend/pkg/crypto"
)

// 每日簽核逾期提醒的定向收件人：能簽核（POST /daily-reviews）且能進入簽核頁
// （GET /daily-reviews/pending）的啟用 human；功能啟用；提醒所列的日子至少一天仍未簽。
//
//	(a) 候選人收窄：每位通過判定者都在 SQL 收窄後的候選人集合內；沒有任何角色指派的使用者不在集合內；
//	(b) 收件人集合等於預期，每位被排除者標註原因；
//	(c) 經真的路由（真 AuthMiddleware 與路由登錄）呼叫待簽清單端點與簽核端點：收件人皆不是 403
//	    （簽核端點以不會成立的請求本文呼叫）；被排除者對待簽清單端點回 401／403；
//	(d) 每位收件人對 /audit-logs 的入口規則放行。

const tdrSecret = "targeted-daily-review-secret"

type tdrEnv struct {
	db   *gorm.DB
	pol  *policy.SecurityPolicyService
	svc  *audit.DailyReviewService
	r    *gin.Engine
	jwt  *crypto.JWTManager
	ids  map[string]uint
	name map[uint]string
}

func setupTargetedDailyReviewEnv(t *testing.T) *tdrEnv {
	t.Helper()
	_, db, now := setupDailyReviewRouter(t)
	if err := db.AutoMigrate(&model.User{}, &model.RolePermission{}, &model.ApproverScope{}); err != nil {
		t.Fatal(err)
	}
	old := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = old })
	pol := policy.NewSecurityPolicyService(db)
	svc := audit.NewDailyReviewService(db, pol, nil)
	svc.SetClock(func() time.Time { return now })
	svc.SetSignerAccess(audit.DailyReviewSignerAccess{Candidates: authz.DailyReviewSignerCandidates, Allowed: authz.DailyReviewSignerAllowed})
	h := NewDailyReviewHandler(svc, nil)
	gin.SetMode(gin.TestMode)
	r := gin.New()
	h.RegisterRoutes(r.Group("/api/v1"), identity.NewAuthService(tdrSecret, time.Minute))
	e := &tdrEnv{db: db, pol: pol, svc: svc, r: r, jwt: crypto.NewJWTManager(tdrSecret, time.Minute), ids: map[string]uint{}, name: map[uint]string{}}
	e.seed(t)
	return e
}

func (e *tdrEnv) user(t *testing.T, name string, active bool) uint {
	t.Helper()
	u := &model.User{Username: name, Password: "x", Email: emailPtr(name + "@t.local"), Active: true, Kind: model.KindHuman}
	if err := e.db.Create(u).Error; err != nil {
		t.Fatal(err)
	}
	if !active {
		// 停用時會推進憑證世代（帳號停用的既有路徑），停用前取得的 token 因此失效
		if err := e.db.Model(u).Updates(map[string]any{"active": false, "credential_epoch": 1}).Error; err != nil {
			t.Fatal(err)
		}
	}
	e.ids[name], e.name[u.ID] = u.ID, name
	return u.ID
}

func (e *tdrEnv) customRole(t *testing.T, name string, perms ...authz.Permission) uint {
	t.Helper()
	role := &model.Role{Name: name, DefinitionVersion: 1}
	if err := e.db.Create(role).Error; err != nil {
		t.Fatal(err)
	}
	for _, p := range perms {
		if err := e.db.Create(&model.RolePermission{RoleID: role.ID, PermissionKey: string(p)}).Error; err != nil {
			t.Fatal(err)
		}
	}
	return role.ID
}

func (e *tdrEnv) assign(t *testing.T, userID, roleID uint) {
	t.Helper()
	if err := e.db.Create(&model.UserRole{UserID: userID, RoleID: roleID, ScopeKind: model.ScopeKindGlobal}).Error; err != nil {
		t.Fatal(err)
	}
}

func (e *tdrEnv) seed(t *testing.T) {
	t.Helper()
	grantLegacyRole(t, e.db, e.user(t, "superadmin", true), model.RoleAdmin)
	grantLegacyRole(t, e.db, e.user(t, "auditor", true), model.RoleAuditor)
	grantLegacyRole(t, e.db, e.user(t, "plainuser", true), model.RoleUser)
	both := e.customRole(t, "review-signer", authz.PermAuditView, authz.PermAlertManage)
	signOnly := e.customRole(t, "sign-only", authz.PermAlertManage)
	e.assign(t, e.user(t, "custom", true), both)
	e.assign(t, e.user(t, "signonly", true), signOnly)
	e.assign(t, e.user(t, "disabled", false), both)
	e.user(t, "norole", true)
	viaGroup := e.user(t, "viagroup", true)
	g := model.UserGroup{Name: "reviewers"}
	if err := e.db.Create(&g).Error; err != nil {
		t.Fatal(err)
	}
	if err := e.db.Create(&model.UserGroupMember{UserGroupID: g.ID, UserID: viaGroup}).Error; err != nil {
		t.Fatal(err)
	}
	if err := e.db.Create(&model.UserGroupRole{UserGroupID: g.ID, RoleID: both, ScopeKind: model.ScopeKindGlobal}).Error; err != nil {
		t.Fatal(err)
	}
}

func (e *tdrEnv) names(ids []uint) []string {
	out := []string{}
	for _, id := range ids {
		out = append(out, e.name[id])
	}
	sort.Strings(out)
	return out
}

func (e *tdrEnv) call(t *testing.T, name, method, path, body string) int {
	t.Helper()
	tok, err := e.jwt.GenerateToken(e.ids[name], name, name+"@t.local", "user", crypto.AuthContext{})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	e.r.ServeHTTP(w, req)
	return w.Code
}

var tdrParams = map[string]string{"pending_dates": "2026-10-08,2026-10-09"}

// TestTargetedDailyReviewRecipients 每日簽核逾期提醒的收件人判定，各情境見下方子測試。
func TestTargetedDailyReviewRecipients(t *testing.T) {
	e := setupTargetedDailyReviewEnv(t)
	got, err := e.svc.TargetedDailyReviewRecipients(e.db, tdrParams)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"auditor", "custom", "superadmin", "viagroup"}
	excluded := map[string]string{
		"signonly":  "只有簽核權、沒有檢視權（決策 3 第 2 點，列明的差異）",
		"plainuser": "沒有簽核權",
		"norole":    "沒有任何角色指派（一般使用者範本）",
		"disabled":  "停用帳號",
	}
	if strings.Join(e.names(got), ",") != strings.Join(want, ",") {
		t.Errorf("(b) 收件人 = %v，want %v", e.names(got), want)
	}
	for name := range e.ids {
		in := false
		for _, w := range want {
			in = in || w == name
		}
		if !in && excluded[name] == "" {
			t.Errorf("(b) %s 被排除但沒有標註原因", name)
		}
	}

	// (a) 候選人收窄
	candidates, err := authz.DailyReviewSignerCandidates(e.db)
	if err != nil {
		t.Fatal(err)
	}
	inCand := map[uint]bool{}
	for _, id := range candidates {
		inCand[id] = true
	}
	for name, id := range e.ids {
		needed, _, err := e.svc.TargetedDailyReviewVerdict(e.db, tdrParams, id)
		if err != nil {
			t.Fatal(err)
		}
		if needed && !inCand[id] {
			t.Errorf("(a) %s 通過判定但不在收窄後的候選人集合內", name)
		}
	}
	if inCand[e.ids["norole"]] {
		t.Error("(a) 沒有任何角色指派的使用者在候選人集合內")
	}
	if inCand[e.ids["disabled"]] {
		t.Error("(a) 停用帳號在候選人集合內")
	}

	// (c) 端點守門
	for _, name := range want {
		if code := e.call(t, name, http.MethodGet, "/api/v1/daily-reviews/pending", ""); code == http.StatusForbidden || code == http.StatusUnauthorized {
			t.Errorf("(c) 收件人 %s 呼叫待簽清單得 %d", name, code)
		}
		// 不會成立的請求本文：通過權限檢查後由處理器拒絕，所以不是 403
		if code := e.call(t, name, http.MethodPost, "/api/v1/daily-reviews", `{"review_date":"bogus"}`); code == http.StatusForbidden || code == http.StatusUnauthorized {
			t.Errorf("(c) 收件人 %s 呼叫簽核端點得 %d", name, code)
		}
	}
	for name, why := range excluded {
		code := e.call(t, name, http.MethodGet, "/api/v1/daily-reviews/pending", "")
		if code != http.StatusForbidden && code != http.StatusUnauthorized {
			t.Errorf("(c) 被排除者 %s（%s）呼叫待簽清單得 %d，want 401／403", name, why, code)
		}
	}
	if code := e.call(t, "signonly", http.MethodPost, "/api/v1/daily-reviews", `{"review_date":"bogus"}`); code == http.StatusForbidden {
		t.Error("前提不成立：只有簽核權者的簽核端點應放行權限檢查")
	}

	// (d) 頁面可達
	te := &tnEnv{db: e.db}
	for _, name := range want {
		if !te.entryAllowed(t, e.ids[name], "/audit-logs") {
			t.Errorf("(d) 收件人 %s 對 /audit-logs 的入口規則不放行", name)
		}
	}
	if te.entryAllowed(t, e.ids["signonly"], "/audit-logs") {
		t.Error("前提不成立：只有簽核權者不應能進入操作日誌頁")
	}
}

// TestTargetedDailyReviewNoRecipients 功能關閉、或提醒所列日子全部已簽時，收件人為空；所列日子已簽但出現新的未簽日也一樣。
func TestTargetedDailyReviewNoRecipients(t *testing.T) {
	e := setupTargetedDailyReviewEnv(t)
	got, _ := e.svc.TargetedDailyReviewRecipients(e.db, tdrParams)
	if len(got) == 0 {
		t.Fatal("前提不成立：應有收件人")
	}
	now := time.Now()
	for _, d := range []string{"2026-10-08", "2026-10-09"} {
		log := model.DailyReviewLog{ReviewDate: d, ReviewerID: e.ids["custom"], ReviewerName: "custom", SnapshotJSON: "{}",
			SignedAt: now, Timezone: "Asia/Taipei", WindowStart: now, WindowEnd: now, DueAt: now,
			Coverage: model.DailyReviewCoverageFullDay, SourceStatus: model.DailyReviewSourceComplete, EnabledBasis: model.DailyReviewBasisRecorded}
		if err := e.db.Create(&log).Error; err != nil {
			t.Fatal(err)
		}
		got, _ = e.svc.TargetedDailyReviewRecipients(e.db, tdrParams)
		if d == "2026-10-08" && len(got) == 0 {
			t.Error("所列兩天只簽了一天就沒有收件人")
		}
	}
	if got, _ = e.svc.TargetedDailyReviewRecipients(e.db, tdrParams); len(got) != 0 {
		t.Errorf("所列日子全部已簽時仍有收件人 %v（其他日子仍未簽不影響這則提醒）", e.names(got))
	}
	needed, eligible, _ := e.svc.TargetedDailyReviewVerdict(e.db, tdrParams, e.ids["custom"])
	if needed || !eligible {
		t.Errorf("所列日子都簽了：needed=%v eligible=%v，want false 與 true（事情已了結）", needed, eligible)
	}

	e2 := setupTargetedDailyReviewEnv(t)
	if _, err := e2.pol.Update(policy.PolicyDailyReviewEnabled, "false", "admin"); err != nil {
		t.Fatal(err)
	}
	if got, _ := e2.svc.TargetedDailyReviewRecipients(e2.db, tdrParams); len(got) != 0 {
		t.Errorf("功能關閉時仍有收件人 %v", e2.names(got))
	}
	if needed, _, _ := e2.svc.TargetedDailyReviewVerdict(e2.db, tdrParams, e2.ids["custom"]); needed {
		t.Error("功能關閉時重驗仍照送")
	}
	if _, eligible, _ := e2.svc.TargetedDailyReviewVerdict(e2.db, tdrParams, e2.ids["signonly"]); eligible {
		t.Error("只有簽核權者在重驗時被判為仍具資格")
	}
}

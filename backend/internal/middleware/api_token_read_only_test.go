package middleware

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/gin-gonic/gin"
)

// 授權角色的層級：認證時依路由性質決定計入哪些角色；全唯讀的 token 呼叫寫入路由在閘門以專屬機器碼拒絕。

const (
	readOnlyProbeRead   = "/api/v1/__levels/read"
	readOnlyProbeWrite  = "/api/v1/__levels/write"
	readOnlyProbeClosed = "/api/v1/__levels/closed"
)

// levelProbeDecider 三條探針路由的判定：讀（開放）、寫（開放）、不開放；其他查無。
func levelProbeDecider(method, path string) APITokenRouteVerdict {
	switch {
	case method == "GET" && path == readOnlyProbeRead:
		return APITokenRouteVerdict{Registered: true, Open: true, Nature: RouteNatureRead}
	case method == "POST" && path == readOnlyProbeWrite:
		return APITokenRouteVerdict{Registered: true, Open: true, Nature: RouteNatureWrite}
	case path == readOnlyProbeClosed:
		return APITokenRouteVerdict{Registered: true}
	}
	return APITokenRouteVerdict{}
}

// issueLeveled 以逐角色層級建立一把 token，回傳明文與識別。
func (f *apiTokenGateFixture) issueLeveled(t *testing.T, name string, roles ...identity.APITokenRoleGrant) (string, uint) {
	t.Helper()
	op := identity.Operator{UserID: f.owner.ID, Username: f.owner.Username,
		Principal: authz.NewPrincipal(f.owner.ID, authz.TokenFacts{SubjectKind: model.KindHuman}, nil)}
	created, err := f.tokens.Create(op, identity.CreateAPITokenInput{Name: name, Roles: roles, NeverExpires: true})
	if err != nil {
		t.Fatal(err)
	}
	return created.Token, created.View.ID
}

// levelRouter 審計 → agent 閘門 → API token 閘門 → 三條探針路由；reached 記錄處理函式是否執行。
func (f *apiTokenGateFixture) levelRouter(t *testing.T, observe func(*gin.Context), reached *int) *gin.Engine {
	t.Helper()
	if err := f.db.AutoMigrate(&model.AuditLog{}); err != nil {
		t.Fatal(err)
	}
	old := database.DB
	database.DB = f.db
	t.Cleanup(func() { database.DB = old })
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Next()
		if observe != nil {
			observe(c)
		}
	})
	r.Use(AuditLogMiddleware(newAnonAuditService()), AgentRouteAllowlist(f.auth), (&apiTokenGate{auth: f.auth, decide: levelProbeDecider}).Handle)
	h := func(c *gin.Context) {
		if reached != nil {
			*reached++
		}
		c.Status(200)
	}
	r.GET(readOnlyProbeRead, AuthMiddleware(f.auth), h)
	r.POST(readOnlyProbeWrite, AuthMiddleware(f.auth), h)
	r.POST(readOnlyProbeClosed, AuthMiddleware(f.auth), h)
	return r
}

// TestAPITokenGateCountsRolesByRouteNature 同一把混合層級的 token：讀取路由的請求主體計入全部授權角色，
// 寫入路由只計入讀寫的角色；唯讀角色的內建身分不出現在寫入請求的主體上。
func TestAPITokenGateCountsRolesByRouteNature(t *testing.T) {
	f := newAPITokenGateFixture(t)
	plain, _ := f.issueLeveled(t, "mixed",
		identity.APITokenRoleGrant{RoleID: f.ida.ID, Level: model.APITokenLevelReadWrite},
		identity.APITokenRoleGrant{RoleID: f.sec.ID, Level: model.APITokenLevelRead})
	var seen *gin.Context
	r := f.levelRouter(t, func(c *gin.Context) { seen = c }, nil)

	if w := bearerRequest(r, "GET", readOnlyProbeRead, plain); w.Code != 200 {
		t.Fatalf("read: %d %s", w.Code, w.Body)
	}
	p := authz.PrincipalFromContext(seen.Request.Context())
	if p == nil || p.Facts.RoleFilter == nil {
		t.Fatal("read: principal with role filter expected")
	}
	if got := p.Facts.RoleFilter.RoleIDs(); len(got) != 2 {
		t.Fatalf("read 應計入兩個授權角色：%v", got)
	}
	if !p.HasBuiltin(model.BuiltinSecurityAdmin) || !p.HasBuiltin(model.BuiltinIdentityAdmin) {
		t.Fatal("read 的主體應具兩個角色的身分")
	}

	if w := bearerRequest(r, "POST", readOnlyProbeWrite, plain); w.Code != 200 {
		t.Fatalf("write（混合層級不在閘門拒絕）: %d %s", w.Code, w.Body)
	}
	p = authz.PrincipalFromContext(seen.Request.Context())
	if p == nil || p.Facts.RoleFilter == nil {
		t.Fatal("write: principal with role filter expected")
	}
	if got := p.Facts.RoleFilter.RoleIDs(); len(got) != 1 || got[0] != f.ida.ID {
		t.Fatalf("write 只應計入讀寫的角色：%v", got)
	}
	if p.HasBuiltin(model.BuiltinSecurityAdmin) {
		t.Fatal("唯讀角色的內建身分不得出現在寫入請求的主體上")
	}
	if !p.HasBuiltin(model.BuiltinIdentityAdmin) {
		t.Fatal("讀寫角色的內建身分應保留")
	}
	if pr := PrincipalFrom(seen); pr == nil || pr.HasBuiltin(model.BuiltinSecurityAdmin) {
		t.Fatal("gin 脈絡的主體同樣只含讀寫的角色")
	}
}

// TestAPITokenGateReadOnlyOrderAndCode 判定順序：認證失敗 401；路由不開放回既有的 403；全唯讀的 token 呼叫
// 開放的寫入路由回 403 AUTH_API_TOKEN_READ_ONLY 且不進處理函式；讀取路由照常；混合層級與讀寫角色目前
// 不生效的 token 不在閘門拒絕；保存的層級不認得時視為唯讀。
func TestAPITokenGateReadOnlyOrderAndCode(t *testing.T) {
	f := newAPITokenGateFixture(t)
	readOnly, readOnlyID := f.issueLeveled(t, "read-only",
		identity.APITokenRoleGrant{RoleID: f.ida.ID, Level: model.APITokenLevelRead},
		identity.APITokenRoleGrant{RoleID: f.sec.ID, Level: model.APITokenLevelRead})
	mixed, _ := f.issueLeveled(t, "mixed",
		identity.APITokenRoleGrant{RoleID: f.ida.ID, Level: model.APITokenLevelRead},
		identity.APITokenRoleGrant{RoleID: f.sec.ID, Level: model.APITokenLevelReadWrite})
	reached := 0
	r := f.levelRouter(t, nil, &reached)

	expect := func(name, method, path, token string, code int, body string, wantReached bool) {
		t.Helper()
		before := reached
		w := bearerRequest(r, method, path, token)
		if w.Code != code || (body != "" && !strings.Contains(w.Body.String(), body)) {
			t.Fatalf("%s: %d %s（應為 %d %s）", name, w.Code, w.Body, code, body)
		}
		if got := reached > before; got != wantReached {
			t.Fatalf("%s: 處理函式執行=%v，應為 %v", name, got, wantReached)
		}
	}
	expect("invalid token on write route", "POST", readOnlyProbeWrite, identity.APITokenPrefix+"nope", 401, "AUTH_TOKEN_INVALID", false)
	expect("read-only on closed route", "POST", readOnlyProbeClosed, readOnly, 403, "AUTH_API_TOKEN_FORBIDDEN_ROUTE", false)
	expect("read-only on unknown route", "POST", "/api/v1/__levels/none", readOnly, 403, "AUTH_API_TOKEN_FORBIDDEN_ROUTE", false)
	expect("read-only on write route", "POST", readOnlyProbeWrite, readOnly, 403, "AUTH_API_TOKEN_READ_ONLY", false)
	expect("read-only on read route", "GET", readOnlyProbeRead, readOnly, 200, "", true)
	expect("mixed on write route", "POST", readOnlyProbeWrite, mixed, 200, "", true)
	expect("read_write on write route", "POST", readOnlyProbeWrite, f.plain, 200, "", true)

	// 讀寫角色從所屬帳號收回（不生效）：token 仍有讀寫的授權角色，閘門不拒絕，能力由之後的判定決定
	if err := f.db.Where("user_id = ? AND role_id = ?", f.owner.ID, f.sec.ID).Delete(&model.UserRole{}).Error; err != nil {
		t.Fatal(err)
	}
	expect("mixed with read_write role revoked", "POST", readOnlyProbeWrite, mixed, 200, "", true)

	// 保存的層級不是認得的值：視為唯讀
	if err := f.db.Model(&model.APITokenRole{}).Where("api_token_id = ?", readOnlyID).Update("level", "superuser").Error; err != nil {
		t.Fatal(err)
	}
	expect("unknown stored level", "POST", readOnlyProbeWrite, readOnly, 403, "AUTH_API_TOKEN_READ_ONLY", false)
	if err := f.db.Model(&model.APITokenRole{}).Where("api_token_id = ?", readOnlyID).Update("level", "").Error; err != nil {
		t.Fatal(err)
	}
	expect("empty stored level", "POST", readOnlyProbeWrite, readOnly, 403, "AUTH_API_TOKEN_READ_ONLY", false)
}

// TestAPITokenReadOnlyRejectionAuditedLikeForbiddenRoute 全唯讀的拒絕與路由不開放的拒絕：兩者都由稽核中介層
// 落地恰好一列拒絕的請求列，帶 token 識別與名稱、HTTP 403；details 各自帶機器可辨識的原因
// （denial＝api_token、basis＝forbidden_route／read_only），原因分類各得一個專屬碼；紀錄裡不出現 token 明文。
func TestAPITokenReadOnlyRejectionAuditedLikeForbiddenRoute(t *testing.T) {
	f := newAPITokenGateFixture(t)
	readOnly, readOnlyID := f.issueLeveled(t, "read-only",
		identity.APITokenRoleGrant{RoleID: f.ida.ID, Level: model.APITokenLevelRead})
	r := f.levelRouter(t, nil, nil)

	row := func(path string) model.AuditLog {
		t.Helper()
		before := f.maxAuditID(t)
		if w := bearerRequest(r, "POST", path, readOnly); w.Code != 403 {
			t.Fatalf("%s: %d %s", path, w.Code, w.Body)
		}
		rows := f.auditRowsSince(t, before)
		if len(rows) != 1 {
			t.Fatalf("%s: 應落地一列，得到 %d 列", path, len(rows))
		}
		return rows[0]
	}
	closed, unknown, readOnlyRow := row(readOnlyProbeClosed), row("/api/v1/__levels/none"), row(readOnlyProbeWrite)
	cases := []struct {
		name, basis, reason string
		got                 model.AuditLog
	}{
		{"forbidden route", "forbidden_route", "authz_api_token_forbidden_route", closed},
		{"unknown route", "forbidden_route", "authz_api_token_forbidden_route", unknown},
		{"read only", "read_only", "authz_api_token_read_only", readOnlyRow},
	}
	for _, tc := range cases {
		got := tc.got
		if got.APITokenID == nil || *got.APITokenID != readOnlyID || got.APITokenName == nil || *got.APITokenName != "read-only" {
			t.Fatalf("%s: 請求列應帶 token 標示：%v %v", tc.name, got.APITokenID, got.APITokenName)
		}
		if got.StatusCode != 403 || got.UserID != f.owner.ID || got.Status != model.StatusDenied {
			t.Fatalf("%s: status=%d user=%d audit_status=%s", tc.name, got.StatusCode, got.UserID, got.Status)
		}
		var details map[string]any
		if err := json.Unmarshal([]byte(got.Details), &details); err != nil {
			t.Fatalf("%s: details 應為 JSON 物件：%q", tc.name, got.Details)
		}
		if len(details) != 2 || details["denial"] != "api_token" || details["basis"] != tc.basis {
			t.Fatalf("%s: details 應只帶 denial=api_token 與 basis=%s：%q", tc.name, tc.basis, got.Details)
		}
		secret := strings.TrimPrefix(readOnly, identity.APITokenPrefix)
		for field, v := range map[string]string{"details": got.Details, "error_msg": got.ErrorMsg, "request_body": got.RequestBody, "path": got.Path} {
			if strings.Contains(v, secret) {
				t.Fatalf("%s: %s 帶出 token 明文", tc.name, field)
			}
		}
		if view := audit.NewAuditLogView(&got); view.ReasonCode != tc.reason || len(view.ReasonParams) != 0 {
			t.Fatalf("%s: 原因碼應為 %s，得到 %q %v", tc.name, tc.reason, view.ReasonCode, view.ReasonParams)
		}
	}
	if closed.Action != readOnlyRow.Action || closed.Resource != readOnlyRow.Resource {
		t.Fatalf("兩種拒絕的留痕形態不同：%s/%s vs %s/%s", closed.Action, closed.Resource,
			readOnlyRow.Action, readOnlyRow.Resource)
	}
}

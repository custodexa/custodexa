package api

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/pkg/crypto"
	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// 個人 API token 端點：回應形狀、明文只在建立回應、管理者端點的能力與受保護帳號規則、自我查驗只接受 token。

const apiTokenHandlerSecret = "api-token-handler-test"

type apiTokenHTTPEnv struct {
	db     *gorm.DB
	r      *gin.Engine
	roles  map[string]uint
	users  map[string]uint
	tokens *identity.APITokenService
	auth   *identity.AuthService
}

func newAPITokenHTTPEnv(t *testing.T) *apiTokenHTTPEnv {
	t.Helper()
	gin.SetMode(gin.TestMode)
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = sqlDB.Close() })
	seedAuthzState(t, db)
	require.NoError(t, db.AutoMigrate(&model.User{}, &model.RolePermission{}, &model.AuditLog{}, &model.APIToken{}, &model.APITokenRole{},
		&model.AssetGroup{}, &model.SystemAlertDetail{}, &model.SystemAlertOutbox{}, &model.SystemAlertSeverityOverride{},
		&model.NotificationChannel{}, &model.CommandAlert{}, &model.UserExternalIdentity{}, &model.OIDCProvider{}, &model.AssetAuthorization{}, &model.UserRoleMapping{}, &model.SecurityPolicy{}))
	e := &apiTokenHTTPEnv{db: db, roles: map[string]uint{}, users: map[string]uint{}}
	for _, name := range []string{"admin", "user"} {
		r := model.Role{Name: name}
		require.NoError(t, db.Create(&r).Error)
		e.roles[name] = r.ID
	}
	for _, seed := range []struct{ name, key string }{{"identity_admin", model.BuiltinIdentityAdmin}, {"security_admin", model.BuiltinSecurityAdmin}} {
		k := seed.key
		r := model.Role{Name: seed.name, BuiltinKey: &k, DefinitionVersion: 1}
		require.NoError(t, db.Create(&r).Error)
		e.roles[seed.name] = r.ID
	}
	for _, u := range []struct {
		name  string
		roles []string
	}{{"root", []string{"admin"}}, {"ida", []string{"identity_admin"}}, {"plain", []string{"user"}},
		{"owner", []string{"identity_admin"}}, {"sec", []string{"security_admin"}}} {
		row := model.User{Username: u.name, Password: "!", Kind: model.KindHuman, Active: true}
		require.NoError(t, db.Create(&row).Error)
		e.users[u.name] = row.ID
		for _, rn := range u.roles {
			require.NoError(t, db.Create(&model.UserRole{UserID: row.ID, RoleID: e.roles[rn], Source: model.RoleSourceManual, ScopeKind: model.ScopeKindGlobal}).Error)
		}
	}
	e.tokens = identity.NewAPITokenService(db, identity.NewAPITokenEventRecorder(audit.NewTxSink(), audit.NewSystemAlertSink(nil)))
	auth := identity.NewAuthService(apiTokenHandlerSecret, time.Hour)
	auth.SetEpochGateDB(db)
	e.auth = auth
	e.r = gin.New()
	e.r.Use(middleware.APITokenGate(auth))
	NewAPITokenHandler(e.tokens, nil).RegisterRoutes(e.r.Group("/api/v1"), auth)
	return e
}

func (e *apiTokenHTTPEnv) jwt(t *testing.T, name string) string {
	t.Helper()
	tok, err := crypto.NewJWTManager(apiTokenHandlerSecret, time.Hour).GenerateToken(e.users[name], name, "", model.RoleUser, crypto.AuthContext{})
	require.NoError(t, err)
	return tok
}

func (e *apiTokenHTTPEnv) do(method, path, bearer, body string) *httptest.ResponseRecorder {
	var req = httptest.NewRequest(method, path, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	w := httptest.NewRecorder()
	e.r.ServeHTTP(w, req)
	return w
}

// create 以登入工作階段替 name 建立一把 token，回傳識別與明文。
func (e *apiTokenHTTPEnv) create(t *testing.T, name, tokenName string, role string) (uint, string) {
	t.Helper()
	w := e.do("POST", "/api/v1/my/api-tokens", e.jwt(t, name),
		fmt.Sprintf(`{"name":%q,"role_ids":[%d],"never_expires":true}`, tokenName, e.roles[role]))
	require.Equal(t, 201, w.Code, w.Body.String())
	var got struct {
		ID    uint   `json:"id"`
		Token string `json:"token"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))
	return got.ID, got.Token
}

func (e *apiTokenHTTPEnv) digestOf(t *testing.T, id uint) string {
	t.Helper()
	var row model.APIToken
	require.NoError(t, e.db.First(&row, id).Error)
	return row.TokenHash
}

func TestAPITokenHandlerCreateResponseNoStore(t *testing.T) {
	e := newAPITokenHTTPEnv(t)
	w := e.do("POST", "/api/v1/my/api-tokens", e.jwt(t, "owner"),
		fmt.Sprintf(`{"name":"terraform","role_ids":[%d],"expires_at":%q}`, e.roles["identity_admin"], time.Now().Add(48*time.Hour).UTC().Format(time.RFC3339)))
	require.Equal(t, 201, w.Code, w.Body.String())
	assert.Equal(t, "no-store", w.Header().Get("Cache-Control"), "建立回應不得被快取")
	var got map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))
	plain, _ := got["token"].(string)
	assert.True(t, strings.HasPrefix(plain, identity.APITokenPrefix))
	id := uint(got["id"].(float64))
	assert.NotContains(t, w.Body.String(), e.digestOf(t, id), "建立回應不含雜湊")
	for _, k := range []string{"name", "status", "granted_roles", "privileged", "created_at", "expires_at", "last_used_at", "last_used_ip", "revoked_at", "revoked_by", "revoke_note"} {
		assert.Contains(t, got, k, "TokenView 欄位 %s", k)
	}
	// 兩者同時送出、角色不屬本人、名稱占用
	both := e.do("POST", "/api/v1/my/api-tokens", e.jwt(t, "owner"),
		fmt.Sprintf(`{"name":"x","role_ids":[%d],"expires_at":%q,"never_expires":true}`, e.roles["identity_admin"], time.Now().Add(time.Hour).UTC().Format(time.RFC3339)))
	assert.Equal(t, 400, both.Code)
	assert.Contains(t, both.Body.String(), "API_TOKEN_EXPIRY_INVALID")
	assert.Contains(t, both.Body.String(), "永不到期", "訊息涵蓋同時送出兩種到期的情形，不只說到期須在未來")
	dup := e.do("POST", "/api/v1/my/api-tokens", e.jwt(t, "owner"), fmt.Sprintf(`{"name":"terraform","role_ids":[%d],"never_expires":true}`, e.roles["identity_admin"]))
	assert.Equal(t, 409, dup.Code)
	notMine := e.do("POST", "/api/v1/my/api-tokens", e.jwt(t, "owner"), fmt.Sprintf(`{"name":"y","role_ids":[%d],"never_expires":true}`, e.roles["admin"]))
	assert.Equal(t, 400, notMine.Code)
	assert.Contains(t, notMine.Body.String(), "API_TOKEN_ROLE_NOT_GRANTABLE")
}

func TestAPITokenHandlerListAndVerifyOmitSecrets(t *testing.T) {
	e := newAPITokenHTTPEnv(t)
	require.NoError(t, e.db.Model(&model.User{}).Where("id = ?", e.users["owner"]).Update("allowed_cidrs", "0.0.0.0/0, ::/0").Error)
	id, plain := e.create(t, "owner", "tf", "identity_admin")
	digest := e.digestOf(t, id)

	list := e.do("GET", "/api/v1/my/api-tokens", e.jwt(t, "owner"), "")
	require.Equal(t, 200, list.Code, list.Body.String())
	assert.NotContains(t, list.Body.String(), plain, "清單不含明文")
	assert.NotContains(t, list.Body.String(), digest, "清單不含雜湊")
	var body struct {
		Data        []map[string]any `json:"data"`
		Eligibility struct {
			CanCreate      bool             `json:"can_create"`
			GrantableRoles []map[string]any `json:"grantable_roles"`
			AllowedCIDRs   []string         `json:"allowed_cidrs"`
		} `json:"eligibility"`
		Restore map[string]any `json:"restore"`
	}
	require.NoError(t, json.Unmarshal(list.Body.Bytes(), &body))
	require.Len(t, body.Data, 1)
	assert.True(t, body.Eligibility.CanCreate)
	assert.Equal(t, []string{"0.0.0.0/0", "::/0"}, body.Eligibility.AllowedCIDRs, "允許來源網段為陣列")
	assert.Contains(t, body.Restore, "invalidated_count")
	assert.Contains(t, body.Restore, "restored_at")

	verify := e.do("GET", "/api/v1/api-tokens/verify", plain, "")
	require.Equal(t, 200, verify.Code, verify.Body.String())
	assert.NotContains(t, verify.Body.String(), plain, "查驗回應不含明文")
	assert.NotContains(t, verify.Body.String(), digest, "查驗回應不含雜湊")
	var v struct {
		Valid bool `json:"valid"`
		Token struct {
			ID   uint   `json:"id"`
			Name string `json:"name"`
		} `json:"token"`
		User struct {
			ID uint `json:"id"`
		} `json:"user"`
		Granted   []map[string]any `json:"granted_roles"`
		Effective []map[string]any `json:"effective_roles"`
	}
	require.NoError(t, json.Unmarshal(verify.Body.Bytes(), &v))
	assert.True(t, v.Valid)
	assert.Equal(t, id, v.Token.ID)
	assert.Equal(t, "tf", v.Token.Name)
	assert.Equal(t, e.users["owner"], v.User.ID)
	assert.Len(t, v.Granted, 1)
	assert.Len(t, v.Effective, 1)

	// 人類工作階段呼叫自我查驗被拒；token 呼叫管理 token 的端點被路由範圍拒絕
	assert.Equal(t, 403, e.do("GET", "/api/v1/api-tokens/verify", e.jwt(t, "owner"), "").Code, "自我查驗只接受 API token")
	denied := e.do("GET", "/api/v1/my/api-tokens", plain, "")
	assert.Equal(t, 403, denied.Code)
	assert.Contains(t, denied.Body.String(), "AUTH_API_TOKEN_FORBIDDEN_ROUTE")
	assert.Equal(t, 403, e.do("POST", "/api/v1/my/api-tokens", plain, `{"name":"z","never_expires":true}`).Code)
}

func TestAPITokenHandlerAdminListRequiresAccountManagement(t *testing.T) {
	e := newAPITokenHTTPEnv(t)
	e.create(t, "owner", "tf", "identity_admin")
	path := fmt.Sprintf("/api/v1/users/%d/api-tokens", e.users["owner"])
	w := e.do("GET", path, e.jwt(t, "plain"), "")
	assert.Equal(t, 403, w.Code, "沒有帳號管理能力者讀他人清單被拒：%s", w.Body.String())
	ok := e.do("GET", path, e.jwt(t, "ida"), "")
	require.Equal(t, 200, ok.Code, ok.Body.String())
	var got struct {
		Data          []map[string]any `json:"data"`
		CanRevoke     bool             `json:"can_revoke"`
		Protected     bool             `json:"protected"`
		AccountActive bool             `json:"account_active"`
	}
	require.NoError(t, json.Unmarshal(ok.Body.Bytes(), &got))
	assert.Len(t, got.Data, 1)
	assert.True(t, got.CanRevoke)
	assert.False(t, got.Protected)
	assert.True(t, got.AccountActive)
	missing := e.do("GET", "/api/v1/users/99999/api-tokens", e.jwt(t, "ida"), "")
	assert.Equal(t, 404, missing.Code, "帳號不存在沿用使用者詳情的 404")
	// 受保護帳號：具帳號管理能力者可以查看，但不能撤銷
	e.create(t, "sec", "s", "security_admin")
	prot := e.do("GET", fmt.Sprintf("/api/v1/users/%d/api-tokens", e.users["sec"]), e.jwt(t, "ida"), "")
	require.Equal(t, 200, prot.Code)
	require.NoError(t, json.Unmarshal(prot.Body.Bytes(), &got))
	assert.True(t, got.Protected)
	assert.False(t, got.CanRevoke)
	superView := e.do("GET", fmt.Sprintf("/api/v1/users/%d/api-tokens", e.users["sec"]), e.jwt(t, "root"), "")
	require.NoError(t, json.Unmarshal(superView.Body.Bytes(), &got))
	assert.True(t, got.CanRevoke, "超級管理者可撤銷受保護帳號的 token")
}

func TestAPITokenHandlerRevokeEndpoints(t *testing.T) {
	e := newAPITokenHTTPEnv(t)
	ownerTok, _ := e.create(t, "owner", "a", "identity_admin")
	e.create(t, "owner", "b", "identity_admin")
	secTok, _ := e.create(t, "sec", "s", "security_admin")

	// 本人撤銷：不是自己的與不存在同為 404
	other := e.do("DELETE", fmt.Sprintf("/api/v1/my/api-tokens/%d", secTok), e.jwt(t, "owner"), "")
	assert.Equal(t, 404, other.Code)
	assert.Contains(t, other.Body.String(), "NOTFOUND_API_TOKEN")
	assert.Equal(t, 404, e.do("DELETE", "/api/v1/my/api-tokens/99999", e.jwt(t, "owner"), "").Code)
	assert.Equal(t, 204, e.do("DELETE", fmt.Sprintf("/api/v1/my/api-tokens/%d", ownerTok), e.jwt(t, "owner"), `{"note":"rotated"}`).Code)

	// 管理者撤銷受保護帳號的 token：非超級管理者被拒
	prot := e.do("DELETE", fmt.Sprintf("/api/v1/users/%d/api-tokens/%d", e.users["sec"], secTok), e.jwt(t, "ida"), "")
	assert.Equal(t, 403, prot.Code)
	assert.Contains(t, prot.Body.String(), "AUTH_PROTECTED_ACCOUNT_OPERATION")
	assert.Equal(t, 403, e.do("POST", fmt.Sprintf("/api/v1/users/%d/api-tokens/revoke-all", e.users["sec"]), e.jwt(t, "ida"), "").Code)
	assert.Equal(t, 403, e.do("POST", fmt.Sprintf("/api/v1/users/%d/api-tokens/revoke-all", e.users["owner"]), e.jwt(t, "plain"), "").Code,
		"沒有帳號管理能力者不能撤銷他人的 token")

	all := e.do("POST", fmt.Sprintf("/api/v1/users/%d/api-tokens/revoke-all", e.users["owner"]), e.jwt(t, "ida"), `{"note":"offboarding"}`)
	require.Equal(t, 200, all.Code, all.Body.String())
	assert.JSONEq(t, `{"revoked":1}`, all.Body.String(), "回本次實際撤銷的數量")
	assert.Equal(t, 204, e.do("DELETE", fmt.Sprintf("/api/v1/users/%d/api-tokens/%d", e.users["sec"], secTok), e.jwt(t, "root"), "").Code)
	assert.Equal(t, 404, e.do("DELETE", fmt.Sprintf("/api/v1/users/%d/api-tokens/%d", e.users["owner"], secTok), e.jwt(t, "root"), "").Code,
		"token 不屬於路徑上的帳號時為 404")
}

type emptyPreviewer struct{}

func (emptyPreviewer) Preview(authz.PreviewRequest) (authz.PreviewResult, error) {
	return authz.PreviewResult{Subjects: []authz.PreviewSubject{}}, nil
}

type previewTokenImpact struct {
	APITokens *identity.APITokenImpact `json:"api_tokens"`
}

// previewImpact 以超級管理者呼叫直接指派預覽：把 owner 的管理者指派集替換為 roles。
func (e *apiTokenHTTPEnv) previewImpact(t *testing.T, roles ...string) *identity.APITokenImpact {
	t.Helper()
	ids := make([]string, 0, len(roles))
	for _, r := range roles {
		ids = append(ids, fmt.Sprint(e.roles[r]))
	}
	w := e.do("POST", "/api/v1/role-assignment-previews", e.jwt(t, "root"),
		fmt.Sprintf(`{"kind":"direct_roles","user_id":%d,"role_ids":[%s]}`, e.users["owner"], strings.Join(ids, ",")))
	require.Equal(t, 200, w.Code, w.Body.String())
	var got previewTokenImpact
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))
	return got.APITokens
}

func newPreviewTokenEnv(t *testing.T) (*apiTokenHTTPEnv, uint) {
	t.Helper()
	e := newAPITokenHTTPEnv(t)
	NewRoleAssignmentPreviewHandler(emptyPreviewer{}).WithAPITokenImpact(e.tokens).RegisterRoutes(e.r.Group("/api/v1"), e.auth)
	require.NoError(t, e.db.Create(&model.UserRole{UserID: e.users["owner"], RoleID: e.roles["security_admin"], Source: model.RoleSourceManual, ScopeKind: model.ScopeKindGlobal}).Error)
	w := e.do("POST", "/api/v1/my/api-tokens", e.jwt(t, "owner"),
		fmt.Sprintf(`{"name":"both","role_ids":[%d,%d],"never_expires":true}`, e.roles["identity_admin"], e.roles["security_admin"]))
	require.Equal(t, 201, w.Code, w.Body.String())
	var got struct{ ID uint }
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))
	return e, got.ID
}

func TestRoleAssignmentPreviewAPITokenOneRoleRevoked(t *testing.T) {
	e, tokenID := newPreviewTokenEnv(t)
	impact := e.previewImpact(t, "identity_admin")
	require.NotNil(t, impact)
	assert.Equal(t, 1, impact.TotalUsable)
	require.Len(t, impact.Affected, 1)
	a := impact.Affected[0]
	assert.Equal(t, tokenID, a.ID)
	require.Len(t, a.LosesRoles, 1)
	assert.Equal(t, e.roles["security_admin"], a.LosesRoles[0].RoleID)
	require.Len(t, a.RemainingRoles, 1)
	assert.Equal(t, e.roles["identity_admin"], a.RemainingRoles[0].RoleID)
	assert.False(t, a.BecomesSuspended)
	assert.Zero(t, impact.SuspendedCount)
	assert.True(t, impact.EligibleAfter)
}

func TestRoleAssignmentPreviewAPITokenAllManagementRolesRevoked(t *testing.T) {
	e, _ := newPreviewTokenEnv(t)
	impact := e.previewImpact(t, "user")
	require.NotNil(t, impact)
	require.Len(t, impact.Affected, 1)
	assert.Len(t, impact.Affected[0].LosesRoles, 2)
	assert.Empty(t, impact.Affected[0].RemainingRoles)
	assert.True(t, impact.Affected[0].BecomesSuspended)
	assert.Equal(t, 1, impact.SuspendedCount)
	assert.False(t, impact.EligibleAfter, "收回全部管理類角色後沒有建立資格")
}

func TestRoleAssignmentPreviewAPITokenGroupSourceNotAffected(t *testing.T) {
	e, _ := newPreviewTokenEnv(t)
	g := model.UserGroup{Name: "sec-group"}
	require.NoError(t, e.db.Create(&g).Error)
	require.NoError(t, e.db.Create(&model.UserGroupMember{UserGroupID: g.ID, UserID: e.users["owner"], Manual: true}).Error)
	require.NoError(t, e.db.Create(&model.UserGroupRole{UserGroupID: g.ID, RoleID: e.roles["security_admin"], ScopeKind: model.ScopeKindGlobal, CreatedAt: time.Now()}).Error)
	impact := e.previewImpact(t, "identity_admin")
	require.NotNil(t, impact)
	assert.Equal(t, 1, impact.TotalUsable)
	assert.Empty(t, impact.Affected, "收回的角色另有群組來源時不列為受影響")
	assert.Zero(t, impact.SuspendedCount)
}

// dropOwnerDirectRole 模擬先前已收回 owner 的某個直接角色（token 仍授權該角色，只是不生效）。
func (e *apiTokenHTTPEnv) dropOwnerDirectRole(t *testing.T, role string) {
	t.Helper()
	require.NoError(t, e.db.Where("user_id = ? AND role_id = ?", e.users["owner"], e.roles[role]).Delete(&model.UserRole{}).Error)
}

func roleIDsOf(refs []identity.APITokenRoleRef) []uint {
	out := make([]uint, 0, len(refs))
	for _, r := range refs {
		out = append(out, r.RoleID)
	}
	return out
}

// 加回 token 被授權過的角色：該 token 列入受影響並指出恢復的角色；仍有其他生效角色，不算由暫停恢復。
func TestRoleAssignmentPreviewAPITokenRoleRegained(t *testing.T) {
	e, tokenID := newPreviewTokenEnv(t)
	e.dropOwnerDirectRole(t, "security_admin")
	impact := e.previewImpact(t, "identity_admin", "security_admin")
	require.NotNil(t, impact)
	require.Len(t, impact.Affected, 1, "加回被授權過的角色時不得說成 token 不受影響")
	a := impact.Affected[0]
	assert.Equal(t, tokenID, a.ID)
	assert.Empty(t, a.LosesRoles)
	assert.Equal(t, []uint{e.roles["security_admin"]}, roleIDsOf(a.RegainsRoles))
	assert.ElementsMatch(t, []uint{e.roles["identity_admin"], e.roles["security_admin"]}, roleIDsOf(a.RemainingRoles),
		"remaining_roles 是變更後生效的授權角色全集")
	assert.False(t, a.BecomesActive)
	assert.False(t, a.BecomesSuspended)
	assert.Zero(t, impact.SuspendedCount)
	assert.True(t, impact.EligibleAfter)
}

// 原本授權角色全部不生效而暫停的 token，因加回角色恢復可用。
func TestRoleAssignmentPreviewAPITokenSuspendedBecomesActive(t *testing.T) {
	e, tokenID := newPreviewTokenEnv(t)
	e.dropOwnerDirectRole(t, "security_admin")
	e.dropOwnerDirectRole(t, "identity_admin")
	impact := e.previewImpact(t, "identity_admin")
	require.NotNil(t, impact)
	assert.Equal(t, 1, impact.TotalUsable, "暫停中的 token 也算尚可使用")
	require.Len(t, impact.Affected, 1)
	a := impact.Affected[0]
	assert.Equal(t, tokenID, a.ID)
	assert.Equal(t, []uint{e.roles["identity_admin"]}, roleIDsOf(a.RegainsRoles))
	assert.Equal(t, []uint{e.roles["identity_admin"]}, roleIDsOf(a.RemainingRoles))
	assert.Empty(t, a.LosesRoles)
	assert.True(t, a.BecomesActive)
	assert.False(t, a.BecomesSuspended)
	assert.Zero(t, impact.SuspendedCount)
	assert.True(t, impact.EligibleAfter)
}

// 加回的角色原本就經群組有效：加上直接指派不改變 token 的有效角色，不列入。
func TestRoleAssignmentPreviewAPITokenRegainedViaGroupNotAffected(t *testing.T) {
	e, _ := newPreviewTokenEnv(t)
	e.dropOwnerDirectRole(t, "security_admin")
	g := model.UserGroup{Name: "sec-group"}
	require.NoError(t, e.db.Create(&g).Error)
	require.NoError(t, e.db.Create(&model.UserGroupMember{UserGroupID: g.ID, UserID: e.users["owner"], Manual: true}).Error)
	require.NoError(t, e.db.Create(&model.UserGroupRole{UserGroupID: g.ID, RoleID: e.roles["security_admin"], ScopeKind: model.ScopeKindGlobal, CreatedAt: time.Now()}).Error)
	impact := e.previewImpact(t, "identity_admin", "security_admin")
	require.NotNil(t, impact)
	assert.Empty(t, impact.Affected, "角色原本就經群組有效時，加上直接指派不算恢復")
}

// 同一次變更收回一個、加回另一個：同一把 token 同時有失去與恢復的角色。
func TestRoleAssignmentPreviewAPITokenLosesAndRegainsInOneChange(t *testing.T) {
	e, tokenID := newPreviewTokenEnv(t)
	e.dropOwnerDirectRole(t, "security_admin")
	impact := e.previewImpact(t, "security_admin")
	require.NotNil(t, impact)
	require.Len(t, impact.Affected, 1)
	a := impact.Affected[0]
	assert.Equal(t, tokenID, a.ID)
	assert.Equal(t, []uint{e.roles["identity_admin"]}, roleIDsOf(a.LosesRoles))
	assert.Equal(t, []uint{e.roles["security_admin"]}, roleIDsOf(a.RegainsRoles))
	assert.Equal(t, []uint{e.roles["security_admin"]}, roleIDsOf(a.RemainingRoles))
	assert.False(t, a.BecomesSuspended)
	assert.False(t, a.BecomesActive)
	assert.Zero(t, impact.SuspendedCount)
}

// 新增沒有任何 token 被授權的角色：token 不會取得它，不列入。
func TestRoleAssignmentPreviewAPITokenUngrantedRoleAddedNotAffected(t *testing.T) {
	e, _ := newPreviewTokenEnv(t)
	impact := e.previewImpact(t, "identity_admin", "security_admin", "admin")
	require.NotNil(t, impact)
	assert.Equal(t, 1, impact.TotalUsable)
	assert.Empty(t, impact.Affected, "token 不會因帳號新增角色而取得未被授權的角色")
	assert.Zero(t, impact.SuspendedCount)
}

func TestRoleAssignmentPreviewAPITokenOmittedWithoutTokens(t *testing.T) {
	e := newAPITokenHTTPEnv(t)
	NewRoleAssignmentPreviewHandler(emptyPreviewer{}).WithAPITokenImpact(e.tokens).RegisterRoutes(e.r.Group("/api/v1"), e.auth)
	w := e.do("POST", "/api/v1/role-assignment-previews", e.jwt(t, "root"),
		fmt.Sprintf(`{"kind":"direct_roles","user_id":%d,"role_ids":[%d]}`, e.users["owner"], e.roles["user"]))
	require.Equal(t, 200, w.Code, w.Body.String())
	assert.NotContains(t, w.Body.String(), "api_tokens", "帳號沒有尚可使用的 token 時回應形狀與修改前相同")
}

// TestRoleAssignmentPreviewAPITokenSummaryOmittedForTokenCaller 以 API token 呼叫預覽時不附對象帳號的 token 影響摘要
// （查看他人 token 的端點不對 token 開放）；同一請求以人類工作階段送出時照舊附上。
func TestRoleAssignmentPreviewAPITokenSummaryOmittedForTokenCaller(t *testing.T) {
	e, _ := newPreviewTokenEnv(t)
	w := e.do("POST", "/api/v1/my/api-tokens", e.jwt(t, "root"),
		fmt.Sprintf(`{"name":"root-tf","role_ids":[%d],"never_expires":true}`, e.roles["admin"]))
	require.Equal(t, 201, w.Code, w.Body.String())
	var created struct{ Token string }
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &created))
	require.NotEmpty(t, created.Token)

	body := fmt.Sprintf(`{"kind":"direct_roles","user_id":%d,"role_ids":[%d]}`, e.users["owner"], e.roles["identity_admin"])
	viaToken := e.do("POST", "/api/v1/role-assignment-previews", created.Token, body)
	require.Equal(t, 200, viaToken.Code, viaToken.Body.String())
	assert.NotContains(t, viaToken.Body.String(), "api_tokens", "token 呼叫不得取得對象帳號的 token 清單資訊")
	assert.NotContains(t, viaToken.Body.String(), `"both"`, "回應不含對象帳號的 token 名稱")

	viaSession := e.do("POST", "/api/v1/role-assignment-previews", e.jwt(t, "root"), body)
	require.Equal(t, 200, viaSession.Code, viaSession.Body.String())
	assert.Contains(t, viaSession.Body.String(), `"api_tokens"`, "人類工作階段照舊附上摘要")
	assert.Contains(t, viaSession.Body.String(), `"both"`)
}

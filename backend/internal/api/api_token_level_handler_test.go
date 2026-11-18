package api

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/custodexa/backend/internal/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// 授權角色的層級：建立請求的兩種寫法與驗證、清單／管理者檢視／建立回應／自我查驗帶層級與彙總、
// 角色變動預覽的受影響 token 帶層級。

type leveledRole struct {
	RoleID    uint   `json:"role_id"`
	Level     string `json:"level"`
	Effective bool   `json:"effective"`
}

type leveledView struct {
	ID           uint          `json:"id"`
	Access       string        `json:"access"`
	GrantedRoles []leveledRole `json:"granted_roles"`
	Token        string        `json:"token"`
	// CreatedBeforeLevels 指標：區分「鍵不存在」與「值為否」
	CreatedBeforeLevels *bool `json:"created_before_levels"`
}

func levelOf(roles []leveledRole, id uint) string {
	for _, r := range roles {
		if r.RoleID == id {
			return r.Level
		}
	}
	return "<missing>"
}

func (e *apiTokenHTTPEnv) grantOwnerSecurityAdmin(t *testing.T) {
	t.Helper()
	require.NoError(t, e.db.Create(&model.UserRole{UserID: e.users["owner"], RoleID: e.roles["security_admin"], Source: model.RoleSourceManual, ScopeKind: model.ScopeKindGlobal}).Error)
}

// TestAPITokenHandlerCreateWithLevels roles 寫法逐角色保存層級；role_ids 寫法各角色皆為讀寫；建立回應帶層級與彙總。
func TestAPITokenHandlerCreateWithLevels(t *testing.T) {
	e := newAPITokenHTTPEnv(t)
	e.grantOwnerSecurityAdmin(t)
	ida, sec := e.roles["identity_admin"], e.roles["security_admin"]

	w := e.do("POST", "/api/v1/my/api-tokens", e.jwt(t, "owner"),
		fmt.Sprintf(`{"name":"mixed","roles":[{"role_id":%d,"level":"read_write"},{"role_id":%d,"level":"read"}],"never_expires":true}`, ida, sec))
	require.Equal(t, 201, w.Code, w.Body.String())
	var mixed leveledView
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &mixed))
	assert.Equal(t, model.APITokenAccessMixed, mixed.Access)
	assert.Equal(t, model.APITokenLevelReadWrite, levelOf(mixed.GrantedRoles, ida))
	assert.Equal(t, model.APITokenLevelRead, levelOf(mixed.GrantedRoles, sec))
	var links []model.APITokenRole
	require.NoError(t, e.db.Where("api_token_id = ?", mixed.ID).Order("role_id").Find(&links).Error)
	require.Len(t, links, 2)
	for _, l := range links {
		want := model.APITokenLevelRead
		if l.RoleID == ida {
			want = model.APITokenLevelReadWrite
		}
		assert.Equal(t, want, l.Level, "保存的層級：角色 %d", l.RoleID)
	}

	w = e.do("POST", "/api/v1/my/api-tokens", e.jwt(t, "owner"),
		fmt.Sprintf(`{"name":"legacy","role_ids":[%d,%d],"never_expires":true}`, ida, sec))
	require.Equal(t, 201, w.Code, w.Body.String())
	var legacy leveledView
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &legacy))
	assert.Equal(t, model.APITokenAccessReadWrite, legacy.Access, "沿用 role_ids 的寫法等同各角色皆為讀寫")
	assert.Equal(t, model.APITokenLevelReadWrite, levelOf(legacy.GrantedRoles, ida))
	assert.Equal(t, model.APITokenLevelReadWrite, levelOf(legacy.GrantedRoles, sec))

	w = e.do("POST", "/api/v1/my/api-tokens", e.jwt(t, "owner"),
		fmt.Sprintf(`{"name":"ro","roles":[{"role_id":%d,"level":"read"}],"never_expires":true}`, ida))
	require.Equal(t, 201, w.Code, w.Body.String())
	var ro leveledView
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &ro))
	assert.Equal(t, model.APITokenAccessRead, ro.Access)
}

// TestAPITokenHandlerCreateLevelValidation 兩個鍵同時出現（含空陣列與 null）、同一角色出現兩次（不論層級）、
// 層級缺漏或不認得，皆回 400 且不建立；兩種寫法都沒有角色時沿用「至少要一個角色」。
func TestAPITokenHandlerCreateLevelValidation(t *testing.T) {
	e := newAPITokenHTTPEnv(t)
	e.grantOwnerSecurityAdmin(t)
	ida, sec := e.roles["identity_admin"], e.roles["security_admin"]
	cases := []struct {
		name, body, code string
	}{
		{"both keys", fmt.Sprintf(`{"name":"a","roles":[{"role_id":%d,"level":"read"}],"role_ids":[%d],"never_expires":true}`, ida, sec), "VALIDATION_BAD_PARAMS"},
		{"both keys, roles empty", fmt.Sprintf(`{"name":"a","roles":[],"role_ids":[%d],"never_expires":true}`, ida), "VALIDATION_BAD_PARAMS"},
		{"both keys, role_ids empty", fmt.Sprintf(`{"name":"a","roles":[{"role_id":%d,"level":"read"}],"role_ids":[],"never_expires":true}`, ida), "VALIDATION_BAD_PARAMS"},
		{"both keys, roles null", fmt.Sprintf(`{"name":"a","roles":null,"role_ids":[%d],"never_expires":true}`, ida), "VALIDATION_BAD_PARAMS"},
		{"both keys, role_ids in another case", fmt.Sprintf(`{"name":"a","roles":null,"ROLE_IDS":[%d],"never_expires":true}`, ida), "VALIDATION_BAD_PARAMS"},
		{"both keys, roles in another case", fmt.Sprintf(`{"name":"a","Roles":[{"role_id":%d,"level":"read"}],"role_ids":[%d],"never_expires":true}`, ida, sec), "VALIDATION_BAD_PARAMS"},
		{"both keys, role_ids null", fmt.Sprintf(`{"name":"a","roles":[{"role_id":%d,"level":"read"}],"role_ids":null,"never_expires":true}`, ida), "VALIDATION_BAD_PARAMS"},
		{"duplicate role same level", fmt.Sprintf(`{"name":"a","roles":[{"role_id":%d,"level":"read"},{"role_id":%d,"level":"read"}],"never_expires":true}`, ida, ida), "VALIDATION_BAD_PARAMS"},
		{"duplicate role different level", fmt.Sprintf(`{"name":"a","roles":[{"role_id":%d,"level":"read"},{"role_id":%d,"level":"read_write"}],"never_expires":true}`, ida, ida), "VALIDATION_BAD_PARAMS"},
		{"unknown level", fmt.Sprintf(`{"name":"a","roles":[{"role_id":%d,"level":"write"}],"never_expires":true}`, ida), "VALIDATION_BAD_PARAMS"},
		{"level case differs", fmt.Sprintf(`{"name":"a","roles":[{"role_id":%d,"level":"READ"}],"never_expires":true}`, ida), "VALIDATION_BAD_PARAMS"},
		{"level missing", fmt.Sprintf(`{"name":"a","roles":[{"role_id":%d}],"never_expires":true}`, ida), "VALIDATION_BAD_PARAMS"},
		{"roles empty", `{"name":"a","roles":[],"never_expires":true}`, "API_TOKEN_ROLE_REQUIRED"},
		{"roles null", `{"name":"a","roles":null,"never_expires":true}`, "API_TOKEN_ROLE_REQUIRED"},
		{"no roles at all", `{"name":"a","never_expires":true}`, "API_TOKEN_ROLE_REQUIRED"},
		{"role not grantable", fmt.Sprintf(`{"name":"a","roles":[{"role_id":%d,"level":"read"}],"never_expires":true}`, e.roles["admin"]), "API_TOKEN_ROLE_NOT_GRANTABLE"},
		{"role id zero", `{"name":"a","roles":[{"role_id":0,"level":"read"}],"never_expires":true}`, "API_TOKEN_ROLE_NOT_GRANTABLE"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := e.do("POST", "/api/v1/my/api-tokens", e.jwt(t, "owner"), c.body)
			assert.Equal(t, 400, w.Code, w.Body.String())
			assert.Contains(t, w.Body.String(), `"code":"`+c.code+`"`)
		})
	}
	var n int64
	require.NoError(t, e.db.Model(&model.APIToken{}).Count(&n).Error)
	assert.Zero(t, n, "被拒絕的請求不建立任何 token")
}

// TestAPITokenHandlerListsAndVerifyCarryLevels 本人清單、管理者檢視與自我查驗都帶每個角色的層級與彙總；
// 自我查驗的有效角色同樣帶層級。
func TestAPITokenHandlerListsAndVerifyCarryLevels(t *testing.T) {
	e := newAPITokenHTTPEnv(t)
	e.grantOwnerSecurityAdmin(t)
	ida, sec := e.roles["identity_admin"], e.roles["security_admin"]
	w := e.do("POST", "/api/v1/my/api-tokens", e.jwt(t, "owner"),
		fmt.Sprintf(`{"name":"mixed","roles":[{"role_id":%d,"level":"read_write"},{"role_id":%d,"level":"read"}],"never_expires":true}`, ida, sec))
	require.Equal(t, 201, w.Code, w.Body.String())
	var created leveledView
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &created))

	check := func(where string, v leveledView) {
		t.Helper()
		if assert.NotNil(t, v.CreatedBeforeLevels, where+"：應帶 created_before_levels") {
			assert.False(t, *v.CreatedBeforeLevels, where+"：本版建立的 token 不是升級前建立")
		}
		assert.Equal(t, model.APITokenAccessMixed, v.Access, where)
		assert.Equal(t, model.APITokenLevelReadWrite, levelOf(v.GrantedRoles, ida), where)
		assert.Equal(t, model.APITokenLevelRead, levelOf(v.GrantedRoles, sec), where)
	}
	var mine struct {
		Data []leveledView `json:"data"`
	}
	list := e.do("GET", "/api/v1/my/api-tokens", e.jwt(t, "owner"), "")
	require.Equal(t, 200, list.Code, list.Body.String())
	require.NoError(t, json.Unmarshal(list.Body.Bytes(), &mine))
	require.Len(t, mine.Data, 1)
	check("my list", mine.Data[0])

	var admin struct {
		Data []leveledView `json:"data"`
	}
	al := e.do("GET", fmt.Sprintf("/api/v1/users/%d/api-tokens", e.users["owner"]), e.jwt(t, "root"), "")
	require.Equal(t, 200, al.Code, al.Body.String())
	require.NoError(t, json.Unmarshal(al.Body.Bytes(), &admin))
	require.Len(t, admin.Data, 1)
	check("admin list", admin.Data[0])
	check("create response", created)

	// 升級前建立的 token（levels_recorded 為否）：清單與管理者檢視標示為升級前建立
	require.NoError(t, e.db.Model(&model.APIToken{}).Where("id = ?", created.ID).Update("levels_recorded", false).Error)
	for _, path := range []string{"/api/v1/my/api-tokens", fmt.Sprintf("/api/v1/users/%d/api-tokens", e.users["owner"])} {
		who := "owner"
		if path != "/api/v1/my/api-tokens" {
			who = "root"
		}
		var got struct {
			Data []leveledView `json:"data"`
		}
		r := e.do("GET", path, e.jwt(t, who), "")
		require.Equal(t, 200, r.Code, r.Body.String())
		require.NoError(t, json.Unmarshal(r.Body.Bytes(), &got))
		require.Len(t, got.Data, 1)
		if assert.NotNil(t, got.Data[0].CreatedBeforeLevels, path) {
			assert.True(t, *got.Data[0].CreatedBeforeLevels, path+"：升級前建立")
		}
	}
	require.NoError(t, e.db.Model(&model.APIToken{}).Where("id = ?", created.ID).Update("levels_recorded", true).Error)

	verify := e.do("GET", "/api/v1/api-tokens/verify", created.Token, "")
	require.Equal(t, 200, verify.Code, verify.Body.String())
	var v struct {
		Token struct {
			Access string `json:"access"`
		} `json:"token"`
		Granted   []leveledRole `json:"granted_roles"`
		Effective []leveledRole `json:"effective_roles"`
	}
	require.NoError(t, json.Unmarshal(verify.Body.Bytes(), &v))
	// 自我查驗不回報升級前建立的標記（設計只要求清單、管理者檢視與建立回應），這裡只比層級與彙總
	notBefore := false
	check("verify", leveledView{Access: v.Token.Access, GrantedRoles: v.Granted, CreatedBeforeLevels: &notBefore})
	require.Len(t, v.Effective, 2)
	assert.Equal(t, model.APITokenLevelRead, levelOf(v.Effective, sec), "有效角色同樣帶層級")

	// 可勾選的角色不是授權角色，不帶層級
	var elig struct {
		Eligibility struct {
			GrantableRoles []map[string]any `json:"grantable_roles"`
		} `json:"eligibility"`
	}
	require.NoError(t, json.Unmarshal(list.Body.Bytes(), &elig))
	require.NotEmpty(t, elig.Eligibility.GrantableRoles)
	for _, r := range elig.Eligibility.GrantableRoles {
		assert.NotContains(t, r, "level", "可勾選的角色不帶層級")
	}
}

// TestRoleAssignmentPreviewAPITokenImpactCarriesLevels 角色變動預覽中受影響的 token 帶相關授權角色的層級。
func TestRoleAssignmentPreviewAPITokenImpactCarriesLevels(t *testing.T) {
	e := newAPITokenHTTPEnv(t)
	NewRoleAssignmentPreviewHandler(emptyPreviewer{}).WithAPITokenImpact(e.tokens).RegisterRoutes(e.r.Group("/api/v1"), e.auth)
	e.grantOwnerSecurityAdmin(t)
	ida, sec := e.roles["identity_admin"], e.roles["security_admin"]
	w := e.do("POST", "/api/v1/my/api-tokens", e.jwt(t, "owner"),
		fmt.Sprintf(`{"name":"mixed","roles":[{"role_id":%d,"level":"read_write"},{"role_id":%d,"level":"read"}],"never_expires":true}`, ida, sec))
	require.Equal(t, 201, w.Code, w.Body.String())

	impact := e.previewImpact(t, "identity_admin")
	require.NotNil(t, impact)
	require.Len(t, impact.Affected, 1)
	a := impact.Affected[0]
	require.Len(t, a.LosesRoles, 1)
	assert.Equal(t, sec, a.LosesRoles[0].RoleID)
	assert.Equal(t, model.APITokenLevelRead, a.LosesRoles[0].Level, "失去的角色帶層級")
	require.Len(t, a.RemainingRoles, 1)
	assert.Equal(t, model.APITokenLevelReadWrite, a.RemainingRoles[0].Level, "保留的角色帶層級")
}

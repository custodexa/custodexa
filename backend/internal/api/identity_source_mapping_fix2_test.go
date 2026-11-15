package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/pkg/crypto"
	"github.com/gin-gonic/gin"
)

func TestFixSeg2MappingWarningHTTPShape(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, tc := range []struct {
		name    string
		err     error
		status  int
		code    string
		metaKey string
	}{
		{"source", &identity.MappingAckRequiredError{Warnings: []string{"MAPPING_SOURCE_ATTR_UNSET"}}, http.StatusUnprocessableEntity, "MAPPING_ACK_REQUIRED", "warnings"},
		{"usage", &identity.UserGroupMappingUsageAckError{UserGroupMappingUsage: identity.UserGroupMappingUsage{AssetAuthorizations: 3, ApproverScopes: 1, RequesterScopes: 2}}, http.StatusConflict, "MAPPING_USAGE_ACK_REQUIRED", "usage"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := gin.New()
			r.GET("/warning", func(c *gin.Context) { respondMappingError(c, model.RoleMappingChannelKindProvider, tc.err) })
			w := httptest.NewRecorder()
			r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/warning", nil))
			var body map[string]any
			if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if w.Code != tc.status || body["code"] != tc.code {
				t.Fatalf("HTTP %d body=%v", w.Code, body)
			}
			meta, ok := body["meta"].(map[string]any)
			if !ok || meta[tc.metaKey] == nil {
				t.Fatalf("警告資料不在 meta.%s: %v", tc.metaKey, body)
			}
		})
	}
}

func TestFixSeg2MappingRoutesRequireAdmin(t *testing.T) {
	gin.SetMode(gin.TestMode)
	installEpochGateDB(t, 1, 7)
	const secret = "mapping-fix2-gate"
	r := gin.New()
	NewIdentitySourceHandler(nil).RegisterRoutes(r.Group("/api/v1"), identity.NewAuthService(secret, time.Minute))
	path := "/api/v1/identity-sources/oidc/2/user-group-mappings"
	request := func(token string) int {
		req := httptest.NewRequest(http.MethodPost, path, nil)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w.Code
	}
	if code := request(""); code != http.StatusUnauthorized {
		t.Fatalf("未登入 HTTP %d", code)
	}
	token, err := crypto.NewJWTManager(secret, time.Minute).GenerateToken(7, "normaluser", "u@example.test", model.RoleUser, crypto.AuthContext{})
	if err != nil {
		t.Fatal(err)
	}
	if code := request(token); code != http.StatusForbidden {
		t.Fatalf("一般使用者 HTTP %d", code)
	}
}

// TestMappingContractErrorHTTPShape 重複的規則回 409 與專屬機器碼；查找參數不合法回 400。
// 兩者都不得落到 500 的預設分支。
func TestMappingContractErrorHTTPShape(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, kind := range []string{model.RoleMappingChannelKindProvider, model.RoleMappingChannelKindDirectory} {
		for _, tc := range []struct {
			name   string
			err    error
			status int
			code   string
		}{
			{"duplicate", identity.ErrMappingRuleExists, http.StatusConflict, "MAPPING_RULE_EXISTS"},
			{"lookup-param", identity.ErrMappingLookupParam, http.StatusBadRequest, "VALIDATION_BAD_PARAMS"},
			{"not-found", identity.ErrMappingRuleNotFound, http.StatusNotFound, "MAPPING_RULE_NOT_FOUND"},
			{"source-busy", identity.ErrLDAPDirectoryBusy, http.StatusConflict, "CONFLICT_LDAP_DIRECTORY_BUSY"},
		} {
			t.Run(kind+"/"+tc.name, func(t *testing.T) {
				r := gin.New()
				r.GET("/e", func(c *gin.Context) { respondMappingError(c, kind, tc.err) })
				w := httptest.NewRecorder()
				r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/e", nil))
				var body map[string]any
				if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
					t.Fatal(err)
				}
				if w.Code != tc.status || body["code"] != tc.code {
					t.Fatalf("HTTP %d body=%v", w.Code, body)
				}
			})
		}
	}
}

// TestMappingLookupParam 查找參數：沒帶、帶一次（含空字串）、同名重複三種情形。
// 重複時不取其中一個，交由呼叫端回 400：取哪一個都會讓結果隨參數順序改變。
func TestMappingLookupParam(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, tc := range []struct {
		query   string
		present bool
		value   string
		ok      bool
	}{
		{"", false, "", true},
		{"match_value=ops", true, "ops", true},
		{"match_value=", true, "", true},
		{"match_value=%20ops%20", true, " ops ", true},
		{"match_value=a&match_value=b", false, "", false},
		{"match_value=a&match_value=a", false, "", false},
		{"role=x", false, "", true},
	} {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Request = httptest.NewRequest(http.MethodGet, "/x?"+tc.query, nil)
		got, ok := lookupParam(c, "match_value")
		if ok != tc.ok || (got != nil) != tc.present || (got != nil && *got != tc.value) {
			t.Errorf("query %q: got=%v ok=%v", tc.query, got, ok)
		}
	}
}

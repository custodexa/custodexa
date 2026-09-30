package api

import (
	"testing"

	"github.com/gin-gonic/gin"
)

func TestIdentitySourceMappingRoutes(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	NewIdentitySourceHandler(nil).RegisterRoutes(router.Group("/api/v1"), nil)
	got := map[string]bool{}
	for _, route := range router.Routes() {
		got[route.Method+" "+route.Path] = true
	}
	for _, path := range []string{"mappings", "role-mappings", "user-group-mappings"} {
		for _, method := range []string{"GET", "POST"} {
			key := method + " /api/v1/identity-sources/:type/:sourceId/" + path
			if !got[key] {
				t.Errorf("missing %s", key)
			}
		}
		for _, method := range []string{"PUT", "DELETE"} {
			key := method + " /api/v1/identity-sources/:type/:sourceId/" + path + "/:ruleId"
			if !got[key] {
				t.Errorf("missing %s", key)
			}
		}
	}
	for _, key := range []string{
		"GET /api/v1/identity-sources/:type/:sourceId/user-group-usage/:userGroupId",
		"GET /api/v1/identity-sources/:type/:sourceId/external-groups",
		"PUT /api/v1/identity-sources/:type/:sourceId/external-groups/:externalGroupId",
	} {
		if !got[key] {
			t.Errorf("missing %s", key)
		}
	}
}

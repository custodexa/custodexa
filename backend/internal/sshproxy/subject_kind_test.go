package sshproxy

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/dbconsole"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/pkg/gatewayapi"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

// The harness authenticates a real agent bearer, then invokes the in-process
// issuer. It does not open an agent-facing connect-token HTTP route.
func TestSubjectKindRequestDeclarationCannotOverrideAgentCredential(t *testing.T) {
	h, db := setupGenerationTest(t)
	require.NoError(t, db.AutoMigrate(&model.AgentToken{}, &model.AlertRule{}))
	require.NoError(t, db.Model(&model.User{}).Where("id=1").Updates(map[string]any{"kind": model.KindAgent, "owner_user_id": 2}).Error)
	accountID := seedAccount(t, db, 1, "app", true)
	task, _ := seedEnvelope(t, db, model.AccountScope{"app"})
	require.NoError(t, db.Model(&model.AccessRequest{}).Where("id=?", task.ID).Updates(map[string]any{"requester_id": 2, "executor_user_id": 1}).Error)
	ownerID, assetID := uint(2), uint(1)
	require.NoError(t, db.Create(&model.AssetAuthorization{UserID: &ownerID, AssetID: &assetID, Permission: model.PermissionView, GrantedBy: ownerID}).Error)
	issued, err := identity.NewAgentTokenService(db, audit.NewTxSink()).Create(1,
		identity.CreateAgentTokenRequest{Name: "subject-conflict", ExpiresAt: time.Now().Add(time.Hour)}, gatewayapi.Actor{UserID: 2})
	require.NoError(t, err)
	h.AuthService.SetEpochGateDB(db)
	rule := model.AlertRule{Name: "agent-only", Pattern: `\bssh\b`, SubjectKind: model.KindAgent, Direction: model.DirectionInput, Action: "block", Severity: "high", Enabled: true}
	require.NoError(t, db.Create(&rule).Error)
	matcher := audit.NewAlertMatcher(db, nil)
	require.NoError(t, matcher.LoadRules())
	var grant gatewayapi.ConnectGrant
	router := gin.New()
	router.POST("/harness", middleware.AuthMiddleware(h.AuthService), func(c *gin.Context) {
		kind, known := middleware.GetPrincipalKind(c)
		require.True(t, known)
		require.Equal(t, model.KindAgent, kind)
		uid, ok := middleware.GetCurrentUserID(c)
		require.True(t, ok)
		var out *gatewayapi.Denial
		grant, out = h.IssueConnectGrant(c, gatewayapi.ConnectSubject{UserID: uid, ClientIP: c.ClientIP()}, nil)
		require.Nil(t, out)
		c.Status(http.StatusOK)
	})
	body := fmt.Sprintf(`{"asset_id":1,"account_id":%d,"access_request_id":%d,"subject_kind":"human"}`, accountID, task.ID)
	req := httptest.NewRequest(http.MethodPost, "/harness?subject_kind=human", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+issued.Token)
	req.Header.Set("X-Subject-Kind", "human")
	req.RemoteAddr = "127.0.0.1:1234"
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, model.KindAgent, grant.PrincipalKind)
	require.NotZero(t, grant.AgentTokenID)
	matched, blocked := matcher.ForSubject(grant.PrincipalKind).MatchBlock("ssh other-host", "ssh")
	require.True(t, blocked, "request-declared human must not bypass the agent rule")
	require.Equal(t, rule.ID, matched.ID)
}

func TestPrincipalKindGrantBindsConsoleSessionMatcher(t *testing.T) {
	h, db := setupGenerationTest(t)
	require.NoError(t, db.AutoMigrate(&model.AlertRule{}))
	agentRule := model.AlertRule{Name: "agent-only", Pattern: "SELECT", SubjectKind: model.KindAgent, Direction: model.DirectionInput, Action: "block", Severity: "high", Enabled: true}
	allRule := model.AlertRule{Name: "all-subjects", Pattern: "DROP", SubjectKind: model.AlertSubjectAll, Direction: model.DirectionInput, Action: "block", Severity: "high", Enabled: true}
	require.NoError(t, db.Create(&agentRule).Error)
	require.NoError(t, db.Create(&allRule).Error)
	matcher := audit.InitAlertMatcher(db, nil)
	t.Cleanup(func() { audit.InitAlertMatcher(nil, nil) })
	require.NoError(t, matcher.LoadRules())
	for _, kind := range []string{model.KindAgent, model.KindHuman, gatewayapi.PrincipalKindUnknown} {
		t.Run(kind, func(t *testing.T) {
			c := gateTestContext(http.MethodGet, "/db-console?subject_kind=human", nil)
			// The original request context may no longer describe the issuing
			// principal at redemption; only the authenticated grant is authoritative.
			c.Set("principal_kind", model.KindHuman)
			grant := gatewayapi.ConnectGrant{UserID: 1, AssetID: 1, PrincipalKind: kind}
			cs := h.newConsoleSession(c, nil, &model.Session{ID: 10, UserID: 1}, nil, dbconsole.ProtocolPostgres, grant, &consoleAuditContext{assetID: 1})
			require.NotNil(t, cs.matcher)
			require.NoError(t, cs.matcher.BlockerHealth())
			matched, blocked := cs.matcher.MatchBlock("SELECT 1", "postgres")
			require.Equal(t, kind == model.KindAgent, blocked)
			if blocked {
				require.Equal(t, agentRule.ID, matched.ID)
			}
			matched, blocked = cs.matcher.MatchBlock("DROP TABLE example", "postgres")
			require.True(t, blocked, "unknown provenance must still apply all rules")
			require.Equal(t, allRule.ID, matched.ID)
		})
	}
}

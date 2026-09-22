package agentmcp

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/proxy"
	"github.com/custodexa/backend/internal/sshproxy"
	"github.com/custodexa/backend/pkg/gatewayapi"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

func TestAgentOpenSessionGateSequence(t *testing.T) {
	for _, scenario := range []string{"authorization_revoked", "policy_tightened", "account_deleted"} {
		t.Run(scenario, func(t *testing.T) {
			f := newFixture(t)
			code := string(apierror.CodeAssetConnectDenied)
			switch scenario {
			case "authorization_revoked":
				require.NoError(t, f.db.Where("user_id=?", f.agent).Delete(&model.AssetAuthorization{}).Error)
			case "policy_tightened":
				code = string(apierror.CodeAuthSourceNotAllowed)
			case "account_deleted":
				require.NoError(t, f.db.Delete(&model.AssetAccount{}, f.account).Error)
				code = string(apierror.CodeAssetAccountNotFound)
			}
			f.authenticated(t, "198.51.100.9", func(c *gin.Context) {
				if scenario == "policy_tightened" {
					require.NoError(t, f.db.Model(&model.User{}).Where("id=?", f.agent).Update("allowed_cidrs", "192.0.2.0/24").Error)
				}
				conn, out := f.h.OpenSession(c, f.input())
				require.Nil(t, conn)
				require.NotNil(t, out)
				require.Equal(t, code, out.Decision.Code)
			})
			var count int64
			require.NoError(t, f.db.Model(&model.Session{}).Count(&count).Error)
			require.Zero(t, count)
			var rows []model.AuditLog
			require.NoError(t, f.db.Where("resource=? AND path=?", model.ResourceSession, "/api/v1/mcp").Find(&rows).Error)
			require.Len(t, rows, 1)
			require.Equal(t, code, rows[0].ErrorMsg)
			require.Contains(t, rows[0].Details, `"via":"mcp"`)
			require.Equal(t, "198.51.100.9", rows[0].ClientIP)
			require.Equal(t, f.agent, rows[0].UserID)
			require.NotNil(t, rows[0].AssetID)
			require.Equal(t, f.asset, *rows[0].AssetID)
		})
	}
}
func TestAgentRedeemSourceIPNotLoopback(t *testing.T) {
	f := newFixture(t)
	f.authenticated(t, "198.51.100.9", func(c *gin.Context) {
		require.NoError(t, f.db.Model(&model.User{}).Where("id=?", f.agent).Update("allowed_cidrs", "192.0.2.0/24").Error)
		conn, out := f.h.OpenSession(c, f.input())
		require.Nil(t, conn)
		require.NotNil(t, out)
		require.Equal(t, "source_not_allowed", out.Meta["reason"])
	})
	// Issue on an allowed address then redeem the same ordinary ticket on another
	// address: the redemption gate must reread the current caller, not the issuer.
	var ticket string
	f.authenticated(t, "192.0.2.8", func(c *gin.Context) {
		auth := middleware.GetAuthContext(c)
		grant, out := f.h.ssh.IssueConnectGrant(c, gatewayapi.ConnectSubject{UserID: f.agent, AuthMethod: auth.EffectiveMethod(), CredEpoch: auth.CredEpoch, ClientIP: "192.0.2.8"}, &sshproxy.ConnectTokenRequest{AssetID: f.asset, AccountID: f.account, AccessRequestID: f.task})
		require.Nil(t, out)
		var err error
		ticket, err = f.h.ssh.ConnectTokens.IssueConnectToken(c.Request.Context(), grant)
		require.NoError(t, err)
	})
	require.NoError(t, f.db.Model(&model.User{}).Where("id=?", f.agent).Update("allowed_cidrs", "").Error)
	f.authenticated(t, "198.51.100.9", func(c *gin.Context) {
		require.NoError(t, f.db.Model(&model.User{}).Where("id=?", f.agent).Update("allowed_cidrs", "192.0.2.0/24").Error)
		conn, out := f.h.ssh.OpenInProcess(c, ticket, false)
		require.Nil(t, conn)
		require.NotNil(t, out)
		require.Equal(t, "source_not_allowed", out.Outcome.Meta["reason"])
	})
	f.authenticated(t, "192.0.2.8", func(c *gin.Context) {
		conn, out := f.h.OpenSession(c, f.input())
		require.Nil(t, out)
		require.NotNil(t, conn)
		require.Equal(t, "192.0.2.8", conn.Session.ClientIP)
		require.NotNil(t, conn.Session.AgentTokenID)
		require.Equal(t, f.task, *conn.Session.AccessRequestID)
		// Observe the actual terminal bridge's connected frame; a synthetic session
		// row cannot satisfy this assertion. The target is the dev compose SSH server.
		frames := make(chan string, 1)
		go func() {
			_, raw, err := conn.Transport.ReadMessage()
			if err != nil {
				frames <- ""
				return
			}
			frames <- string(raw)
		}()
		select {
		case frame := <-frames:
			require.Contains(t, frame, `"type":"connected"`)
		case <-time.After(5 * time.Second):
			t.Fatal("no connected frame")
		}
		require.NoError(t, conn.Transport.Close())
		select {
		case <-conn.Done:
		case <-time.After(5 * time.Second):
			t.Fatal("session not settled")
		}
		var sess model.Session
		require.NoError(t, f.db.First(&sess, conn.Session.ID).Error)
		require.Equal(t, model.SessionStatusClosed, sess.Status)
		require.True(t, sess.HasRecording)
	})
}
func TestConnectTicketHasNoSourceAddress(t *testing.T) {
	typ := reflect.TypeOf(proxy.ConnectGrant{})
	expected := []string{"UserID", "AssetID", "AccountID", "AccessRequestID", "AgentTokenID", "PrincipalKind", "ProviderID", "AuthEpoch", "AuthMethod", "CredEpoch", "ExpiresAt"}
	var names []string
	for i := 0; i < typ.NumField(); i++ {
		names = append(names, typ.Field(i).Name)
	}
	require.ElementsMatch(t, expected, names)
	raw, err := json.Marshal(proxy.ConnectGrant{})
	require.NoError(t, err)
	require.NotContains(t, string(raw), "ClientIP")
}

func TestAgentOpenSessionGateSequenceRedeemRechecks(t *testing.T) {
	for _, scenario := range []string{"authorization_revoked", "policy_tightened", "account_deleted"} {
		t.Run(scenario, func(t *testing.T) {
			f := newFixture(t)
			f.authenticated(t, "198.51.100.9", func(c *gin.Context) {
				auth := middleware.GetAuthContext(c)
				grant, out := f.h.ssh.IssueConnectGrant(c, gatewayapi.ConnectSubject{UserID: f.agent, AuthMethod: auth.EffectiveMethod(), CredEpoch: auth.CredEpoch, ClientIP: "198.51.100.9"}, &sshproxy.ConnectTokenRequest{AssetID: f.asset, AccountID: f.account, AccessRequestID: f.task})
				require.Nil(t, out)
				ticket, err := f.h.ssh.ConnectTokens.IssueConnectToken(c.Request.Context(), grant)
				require.NoError(t, err)
				code := string(apierror.CodeAssetConnectDenied)
				switch scenario {
				case "authorization_revoked":
					require.NoError(t, f.db.Where("user_id=?", f.agent).Delete(&model.AssetAuthorization{}).Error)
				case "policy_tightened":
					require.NoError(t, f.db.Model(&model.User{}).Where("id=?", f.agent).Update("allowed_cidrs", "192.0.2.0/24").Error)
					code = string(apierror.CodeAuthSourceNotAllowed)
				case "account_deleted":
					require.NoError(t, f.db.Delete(&model.AssetAccount{}, f.account).Error)
					code = string(apierror.CodeAssetAccountNotFound)
				}
				request := c.Copy()
				request.Request = c.Request.Clone(c.Request.Context())
				u := *request.Request.URL
				request.Request.URL = &u
				u.RawQuery = "cols=80&rows=24"
				conn, failure := f.h.ssh.OpenInProcess(request, ticket, false)
				require.Nil(t, conn)
				require.NotNil(t, failure)
				require.Equal(t, code, failure.Outcome.Decision.Code)
				var count int64
				require.NoError(t, f.db.Model(&model.Session{}).Count(&count).Error)
				require.Zero(t, count)
				var rows []model.AuditLog
				require.NoError(t, f.db.Where("resource=? AND path=?", model.ResourceSession, "/api/v1/mcp").Find(&rows).Error)
				require.Len(t, rows, 1)
				require.Equal(t, code, rows[0].ErrorMsg)
				require.Equal(t, f.agent, rows[0].UserID)
				require.Equal(t, f.asset, *rows[0].AssetID)
			})
		})
	}
}

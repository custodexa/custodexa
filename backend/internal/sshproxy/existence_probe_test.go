package sshproxy

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/policy"
	"github.com/custodexa/backend/internal/modules/session"
	"github.com/custodexa/backend/pkg/gatewayapi"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"gorm.io/gorm"
)

func TestExistenceProbeConnectionResponses(t *testing.T) {
	request := func(h *Handler, method, path, body string, user uint, role string) *httptest.ResponseRecorder {
		r := gin.New()
		r.Use(func(c *gin.Context) { c.Set("userID", user); c.Set("role", role) })
		r.POST("/connect-tokens", h.HandleCreateConnectToken)
		r.POST("/transmission-consents", h.HandleCreateTransmissionConsent)
		r.GET("/ssh/sessions/:id/stats", h.HandleStats)
		r.POST("/sessions/:id/share", h.HandleCreateShare)
		r.DELETE("/sessions/:id/share", h.HandleRevokeShare)
		q := httptest.NewRequest(method, path, strings.NewReader(body))
		q.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, q)
		return w
	}
	pair := func(t *testing.T, missing, denied *httptest.ResponseRecorder, code, message string) {
		t.Helper()
		require.Equal(t, 404, missing.Code, missing.Body.String())
		require.Equal(t, missing.Code, denied.Code, "paired status: %s", denied.Body.String())
		require.JSONEq(t, fmt.Sprintf(`{"code":%q,"error":%q}`, code, message), missing.Body.String())
		require.Equal(t, missing.Body.String(), denied.Body.String(), "paired complete body")
		require.Equal(t, missing.Result().Header, denied.Result().Header, "paired complete headers")
	}

	for _, endpoint := range []struct{ name, path string }{{"connect_tokens", "/connect-tokens"}, {"transmission_consents", "/transmission-consents"}} {
		t.Run(endpoint.name, func(t *testing.T) {
			h, db := gateFixture(t)
			hidden := model.Asset{Name: "hidden", Protocol: "vnc", Host: "hidden", Port: 5900, CreatedBy: 2}
			require.NoError(t, db.Create(&hidden).Error)
			missing := request(h, "POST", endpoint.path, `{"asset_id":99999,"risk_keys":["vnc_unencrypted"]}`, 1, model.RoleUser)
			denied := request(h, "POST", endpoint.path, fmt.Sprintf(`{"asset_id":%d,"risk_keys":["vnc_unencrypted"]}`, hidden.ID), 1, model.RoleUser)
			pair(t, missing, denied, "NOTFOUND_ASSET", "資產不存在")
			for _, table := range []any{&model.Session{}, &model.TransmissionConsent{}} {
				var n int64
				require.NoError(t, db.Model(table).Count(&n).Error)
				require.Zero(t, n, "denied requests must have no resource side effects")
			}
		})
	}

	t.Run("connection_controls", func(t *testing.T) {
		h, db, policies := setupPolicyGateTest(t)
		seedGateFixture(t, db)
		setGroupPolicy(t, db, 1, model.AccessPolicyOpen)
		for _, actor := range []struct {
			id   uint
			role string
		}{{1, model.RoleUser}, {2, model.RoleAdmin}} {
			w := request(h, "POST", "/connect-tokens", `{"asset_id":1}`, actor.id, actor.role)
			require.Equal(t, 200, w.Code, w.Body.String())
		}
		pair(t, request(h, "POST", "/connect-tokens", `{"asset_id":99999}`, 3, model.RoleAuditor), request(h, "POST", "/connect-tokens", `{"asset_id":1}`, 3, model.RoleAuditor), "NOTFOUND_ASSET", "資產不存在")
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Request = httptest.NewRequest("POST", "/in-process", nil)
		_, out := h.IssueConnectGrant(c, gatewayapi.ConnectSubject{UserID: 3, ClaimedRole: model.RoleAuditor, ClientIP: "127.0.0.1"}, &ConnectTokenRequest{AssetID: 1})
		require.NotNil(t, out)
		require.Equal(t, 403, out.Status)
		require.Equal(t, "AUTH_ASSET_CONNECT_DENIED", out.Decision.Code)
		uid, aid := uint(3), uint(1)
		require.NoError(t, db.Create(&model.AssetAuthorization{UserID: &uid, AssetID: &aid, Permission: model.PermissionConnect, GrantedBy: 2}).Error)
		w := request(h, "POST", "/connect-tokens", `{"asset_id":1}`, 3, model.RoleAuditor)
		require.Equal(t, 200, w.Code, w.Body.String())
		for _, level := range []string{model.AccessPolicyReason, model.AccessPolicyApproval} {
			setGroupPolicy(t, db, 1, level)
			w = request(h, "POST", "/connect-tokens", `{"asset_id":1}`, 1, model.RoleUser)
			require.Equal(t, 403, w.Code, w.Body.String())
			require.Contains(t, w.Body.String(), level+"_required")
		}
		setGroupPolicy(t, db, 1, model.AccessPolicyOpen)
		require.NoError(t, db.Model(&model.Asset{}).Where("id=1").Update("protocol", "vnc").Error)
		_, err := policies.Update(policy.PolicyTransportVNCLevel, policy.TransportLevelWarn, "admin")
		require.NoError(t, err)
		h.TransmissionConsent = policy.NewTransmissionConsentService(db, policy.NewTransmissionPolicyService(policies, nil))
		w = request(h, "POST", "/connect-tokens", `{"asset_id":1}`, 1, model.RoleUser)
		require.Equal(t, 428, w.Code, w.Body.String())
		require.Contains(t, w.Body.String(), "vnc_unencrypted")
		w = request(h, "POST", "/transmission-consents", `{"asset_id":1,"risk_keys":["changed"]}`, 1, model.RoleUser)
		require.Equal(t, 409, w.Code, w.Body.String())
		for _, actor := range []struct {
			id   uint
			role string
		}{{1, model.RoleUser}, {2, model.RoleAdmin}, {3, model.RoleAuditor}} {
			w = request(h, "POST", "/transmission-consents", `{"asset_id":1,"risk_keys":["vnc_unencrypted"]}`, actor.id, actor.role)
			require.Equal(t, 200, w.Code, w.Body.String())
		}
		w = request(h, "POST", "/connect-tokens", `{"asset_id":1}`, 1, model.RoleUser)
		require.Equal(t, 200, w.Code, w.Body.String())
		require.NoError(t, db.Callback().Query().Before("gorm:query").Register("existence_permission_error", func(tx *gorm.DB) {
			if tx.Statement.Table == "asset_authorizations" {
				tx.AddError(errors.New("permission query unavailable"))
			}
		}))
		defer db.Callback().Query().Remove("existence_permission_error")
		for _, path := range []string{"/connect-tokens", "/transmission-consents"} {
			w = request(h, "POST", path, `{"asset_id":1,"risk_keys":["vnc_unencrypted"]}`, 1, model.RoleUser)
			require.Equal(t, 500, w.Code, w.Body.String())
			require.Contains(t, w.Body.String(), "INTERNAL_PERMISSION_CHECK")
		}
	})

	t.Run("sessions", func(t *testing.T) {
		h, db := gateFixture(t)
		h.SessionService = session.NewSessionService(nil)
		for _, s := range []model.Session{{ID: 1, SessionID: "probe-active", UserID: 1, Status: model.SessionStatusActive}, {ID: 2, SessionID: "probe-closed", UserID: 1, Status: model.SessionStatusClosed}} {
			require.NoError(t, db.Create(&s).Error)
		}
		// A local SSH endpoint serves actual stats channels for eligible actors.
		_, key, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		signer, err := ssh.NewSignerFromKey(key)
		require.NoError(t, err)
		cfg := &ssh.ServerConfig{NoClientAuth: true}
		cfg.AddHostKey(signer)
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		defer listener.Close()
		var collected atomic.Int32
		go func() {
			nc, err := listener.Accept()
			if err != nil {
				return
			}
			defer nc.Close()
			_ = nc.SetDeadline(time.Now().Add(15 * time.Second))
			conn, channels, requests, err := ssh.NewServerConn(nc, cfg)
			if err != nil {
				return
			}
			defer conn.Close()
			go ssh.DiscardRequests(requests)
			for incoming := range channels {
				ch, reqs, err := incoming.Accept()
				if err != nil {
					return
				}
				for req := range reqs {
					if req.Type == "exec" {
						collected.Add(1)
						_ = req.Reply(true, nil)
						_, _ = ch.Write([]byte(sampleStatsOutput))
						_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
						break
					}
					_ = req.Reply(false, nil)
				}
				_ = ch.Close()
			}
		}()
		client, err := ssh.Dial("tcp", listener.Addr().String(), &ssh.ClientConfig{User: "stats", HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 3 * time.Second})
		require.NoError(t, err)
		defer client.Close()
		h.statsClients.Store(uint(1), client)
		for _, endpoint := range []struct{ method, format string }{{"GET", "/ssh/sessions/%d/stats"}, {"POST", "/sessions/%d/share"}, {"DELETE", "/sessions/%d/share"}} {
			for _, shared := range []bool{false, true} {
				for _, id := range []uint{1, 2} {
					t.Run(fmt.Sprintf("%s_%s/shared=%v/id=%d", endpoint.method, endpoint.format, shared, id), func(t *testing.T) {
						h.Shares.Revoke(id)
						var code string
						if shared {
							code, _, err = h.Shares.Create(id, 1, time.Minute)
							require.NoError(t, err)
						}
						missing := request(h, endpoint.method, fmt.Sprintf(endpoint.format, 99999), `{}`, 4, model.RoleUser)
						denied := request(h, endpoint.method, fmt.Sprintf(endpoint.format, id), `{}`, 4, model.RoleUser)
						pair(t, missing, denied, "NOTFOUND_SESSION", "Session 不存在")
						require.Zero(t, collected.Load(), "unauthorized stats must not collect")
						if shared {
							actual, ok := h.Shares.Resolve(code)
							require.True(t, ok)
							require.Equal(t, id, actual)
						} else {
							require.Empty(t, h.Shares.bySess)
						}
						h.Shares.Revoke(id)
					})
				}
			}
		}
		for _, actor := range []struct {
			id   uint
			role string
		}{{1, model.RoleUser}, {2, model.RoleAdmin}, {3, model.RoleAuditor}} {
			w := request(h, "GET", "/ssh/sessions/1/stats", "", actor.id, actor.role)
			require.Equal(t, 200, w.Code, w.Body.String())
			require.Contains(t, w.Body.String(), `"hostname":"test-host"`)
			w = request(h, "GET", "/ssh/sessions/2/stats", "", actor.id, actor.role)
			require.Equal(t, 404, w.Code)
			require.Contains(t, w.Body.String(), "RULE_SESSION_NOT_ONLINE")
			if actor.id != 1 {
				for _, method := range []string{"POST", "DELETE"} {
					pair(t, request(h, method, "/sessions/99999/share", `{}`, actor.id, actor.role), request(h, method, "/sessions/1/share", `{}`, actor.id, actor.role), "NOTFOUND_SESSION", "Session 不存在")
				}
			}
		}
		var previous string
		for _, ttl := range []int{10, 1, 60} {
			w := request(h, "POST", "/sessions/1/share", fmt.Sprintf(`{"ttl_minutes":%d}`, ttl), 1, model.RoleUser)
			require.Equal(t, 200, w.Code, w.Body.String())
			var body struct {
				Code    string    `json:"code"`
				Expires time.Time `json:"expires_at"`
			}
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
			require.WithinDuration(t, time.Now().Add(time.Duration(ttl)*time.Minute), body.Expires, 2*time.Second)
			if previous != "" {
				_, ok := h.Shares.Resolve(previous)
				require.False(t, ok)
			}
			previous = body.Code
		}
		w := request(h, "DELETE", "/sessions/1/share", "", 1, model.RoleUser)
		require.Equal(t, 200, w.Code)
		require.JSONEq(t, `{"revoked":true}`, w.Body.String())
		w = request(h, "DELETE", "/sessions/1/share", "", 1, model.RoleUser)
		require.Equal(t, 404, w.Code)
		require.Contains(t, w.Body.String(), "NOTFOUND_SESSION_SHARE")
		w = request(h, "POST", "/sessions/2/share", `{}`, 1, model.RoleUser)
		require.Equal(t, 400, w.Code)
		require.Contains(t, w.Body.String(), "RULE_SESSION_SHARE_NOT_ACTIVE")
	})
}

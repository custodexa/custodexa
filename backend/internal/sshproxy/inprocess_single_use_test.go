package sshproxy

import (
	"context"
	"encoding/json"
	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/proxy"
	"github.com/custodexa/backend/pkg/crypto"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/require"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestConnectTokenSingleUseAcrossMCPAndWS(t *testing.T) {
	for _, first := range []string{"mcp", "websocket"} {
		t.Run(first+"_then_other", func(t *testing.T) {
			h, db := setupGenerationTest(t)
			sqlDB, err := db.DB()
			require.NoError(t, err)
			sqlDB.SetMaxOpenConns(1)
			prepareRedeemableAsset(t, h, db)
			h.Registry = proxy.NewConnectionRegistry()
			require.NoError(t, db.AutoMigrate(&model.SessionCommand{}, &model.AlertRule{}, &model.CommandAlert{}))
			matcher := audit.InitAlertMatcher(db, nil)
			require.NoError(t, matcher.LoadRules())
			t.Cleanup(func() { audit.InitAlertMatcher(nil, nil) })
			ticket := mustIssueWithAuth(t, h, crypto.AuthContext{})
			c := gateTestContext("POST", "/api/v1/mcp?cols=80&rows=24", nil)
			if first == "mcp" {
				conn, failure := h.OpenInProcess(c, ticket, false)
				require.Nil(t, failure)
				require.NotNil(t, conn)
				r := gin.New()
				r.GET("/ssh", h.HandleSSH)
				w := httptest.NewRecorder()
				r.ServeHTTP(w, httptest.NewRequest("GET", "/ssh?connect_token="+ticket+"&cols=80&rows=24", nil))
				require.Equal(t, 401, w.Code)
				var body map[string]any
				require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
				require.Equal(t, string(apierror.CodeConnectTokenInvalid), body["code"])
				conn.Transport.Close()
				select {
				case <-conn.Done:
				case <-time.After(3 * time.Second):
					t.Fatal("in-process session not settled")
				}
			} else {
				r := gin.New()
				r.GET("/ssh", h.HandleSSH)
				srv := httptest.NewServer(r)
				defer srv.Close()
				ws, resp, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http")+"/ssh?connect_token="+ticket+"&cols=80&rows=24", nil)
				require.NoError(t, err)
				require.Equal(t, 101, resp.StatusCode)
				require.NoError(t, ws.SetReadDeadline(time.Now().Add(3*time.Second)))
				var connected Message
				require.NoError(t, ws.ReadJSON(&connected))
				require.Equal(t, MsgConnected, connected.Type)
				conn, failure := h.OpenInProcess(c, ticket, false)
				require.Nil(t, conn)
				require.NotNil(t, failure)
				require.Equal(t, string(apierror.CodeConnectTokenInvalid), failure.Outcome.Decision.Code)
				require.NoError(t, ws.Close())
				require.Eventually(t, func() bool { sess := latestSession(t, db); return sess.Status == model.SessionStatusClosed }, 3*time.Second, 10*time.Millisecond)

			}
			_, ok := h.ConnectTokens.RedeemConnectToken(context.Background(), ticket)
			require.False(t, ok)
			var count int64
			require.NoError(t, db.Model(&model.Session{}).Count(&count).Error)
			require.EqualValues(t, 1, count)
		})
	}
}

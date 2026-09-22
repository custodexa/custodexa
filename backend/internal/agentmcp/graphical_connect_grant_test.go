package agentmcp

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/proxy"
	"github.com/custodexa/backend/pkg/crypto"
	"github.com/custodexa/backend/pkg/guacamole"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/require"
)

func TestGraphicalConnectGrantWithoutJWTInURL(t *testing.T) {
	f := newFixture(t)
	require.NoError(t, f.db.Model(&model.Asset{}).Where("id=?", f.asset).Update("protocol", model.ProtocolVNC).Error)
	require.NoError(t, f.db.Model(&model.Credential{}).Where("id=1").Update("protocol_family", model.ProtocolFamilyVNC).Error)
	human := uint(1)
	require.NoError(t, f.db.Create(&model.AssetAuthorization{UserID: &human, AssetID: &f.asset, Permission: model.PermissionConnect, GrantedBy: human, Accounts: model.AccountScope{"testuser"}}).Error)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()
	done := make(chan error, 1)
	go func() {
		peer, err := ln.Accept()
		if err != nil {
			done <- err
			return
		}
		defer peer.Close()
		_ = peer.SetDeadline(time.Now().Add(5 * time.Second))
		reader := bufio.NewReader(peer)
		selected, err := guacamole.ReadInstruction(reader)
		if err != nil {
			done <- err
			return
		}
		if selected.Opcode != "select" || len(selected.Args) != 1 || selected.Args[0] != "vnc" {
			done <- fmt.Errorf("unexpected select: %+v", selected)
			return
		}
		if _, err = fmt.Fprint(peer, "4.args,3.1.0,8.password;"); err != nil {
			done <- err
			return
		}
		for i := 0; i < 5; i++ {
			inst, err := guacamole.ReadInstruction(reader)
			if err != nil {
				done <- err
				return
			}
			if i == 4 && (inst.Opcode != "connect" || len(inst.Args) != 2 || inst.Args[1] != "testpass123") {
				done <- fmt.Errorf("credential did not reach guacd handshake")
				return
			}
		}
		if _, err = fmt.Fprint(peer, "5.ready,7.fixture;"); err != nil {
			done <- err
			return
		}
		// First real tunnel payload proves WebSocket upgrade and guacd forwarding.
		_, err = fmt.Fprint(peer, "4.sync,1.1;")
		if err != nil {
			done <- err
			return
		}
		_, err = guacamole.ReadInstruction(reader)
		done <- err
	}()
	h := proxy.NewConnectionHandler("127.0.0.1", ln.Addr().(*net.TCPAddr).Port, f.h.ssh.SessionService, f.h.ssh.AssetService, f.h.ssh.AuthService, f.h.ssh.AuthorizationService, f.h.ssh.AuditService, nil)
	h.Registry = f.h.ssh.Registry
	h.ConnectTokens = f.h.ssh.ConnectTokens
	h.AccessPolicy = f.h.ssh.AccessPolicy
	jwt, err := crypto.NewJWTManager("mcp-test-secret", time.Hour).GenerateToken(human, "mcp-owner", "", model.RoleUser, crypto.AuthContext{})
	require.NoError(t, err)
	router := gin.New()
	router.POST("/api/v1/connect-tokens", middleware.AuthMiddleware(f.h.ssh.AuthService), f.h.ssh.HandleCreateConnectToken)
	router.GET("/api/v1/connect", h.HandleConnect)
	srv := httptest.NewServer(router)
	defer srv.Close()
	raw, err := json.Marshal(map[string]any{"asset_id": f.asset, "account_id": f.account})
	require.NoError(t, err)
	req, err := http.NewRequest("POST", srv.URL+"/api/v1/connect-tokens", bytes.NewReader(raw))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	var issued map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&issued))
	resp.Body.Close()
	require.Equal(t, 200, resp.StatusCode, issued)
	ticket, ok := issued["connect_token"].(string)
	require.True(t, ok, issued)
	require.NotEmpty(t, ticket)
	require.NotEqual(t, jwt, ticket)
	target := "ws" + strings.TrimPrefix(srv.URL, "http") + "/api/v1/connect?connect_token=" + url.QueryEscape(ticket)
	parsed, err := url.Parse(target)
	require.NoError(t, err)
	require.Len(t, parsed.Query(), 1)
	require.Equal(t, ticket, parsed.Query().Get("connect_token"))
	require.NotContains(t, target, jwt)
	require.Empty(t, parsed.Query().Get("token"))
	require.Empty(t, parsed.Query().Get("jwt"))
	ws, resp, err := websocket.DefaultDialer.Dial(target, nil)
	require.NoError(t, err)
	defer ws.Close()
	require.Equal(t, 101, resp.StatusCode)
	require.NoError(t, ws.SetReadDeadline(time.Now().Add(3*time.Second)))
	_, data, err := ws.ReadMessage()
	require.NoError(t, err)
	require.Equal(t, "4.sync,1.1;", string(data))
	require.NoError(t, ws.WriteMessage(websocket.TextMessage, []byte("4.sync,1.1;")))
	require.NoError(t, <-done)
	ws.Close()
	var sess model.Session
	require.Eventually(t, func() bool { return f.db.First(&sess).Error == nil && sess.EndTime != nil }, 3*time.Second, 10*time.Millisecond)
	require.Equal(t, model.ProtocolVNC, sess.Protocol)
	require.Equal(t, human, sess.UserID)
	require.Equal(t, f.asset, *sess.AssetID)
	require.Equal(t, f.account, sess.AccountID)
	_, valid := h.ConnectTokens.RedeemConnectToken(req.Context(), ticket)
	require.False(t, valid, "successful connection consumed its one-use grant")
}
